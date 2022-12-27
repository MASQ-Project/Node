// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::big_int_processing::big_int_divider::UserDefinedFunctionError::InvalidInputValue;
use crate::accountant::gwei_to_wei;
use rusqlite::functions::{Context, FunctionFlags};
use rusqlite::Connection;
use rusqlite::Error::UserFunctionError;
use std::fmt::{Display, Formatter};

macro_rules! create_big_int_sqlite_fns {
    ($conn: expr, $($sqlite_fn_name: expr),+; $($intern_fn_name: ident),+) => {
        $(
            $conn.create_scalar_function::<_, i64>($sqlite_fn_name, 3, FunctionFlags::SQLITE_UTF8 | FunctionFlags::SQLITE_DETERMINISTIC,
                move |ctx| {
                    Ok(BigIntDivider::$intern_fn_name(common_arg_distillation(
                        ctx,
                        $sqlite_fn_name,
                    )?))
                }
            )?;
        )+
    }
}

pub struct BigIntDivider {}

impl BigIntDivider {
    pub fn deconstruct(num: i128) -> (i64, i64) {
        (
            Self::deconstruct_high_bytes(num),
            Self::deconstruct_low_bytes(num),
        )
    }

    fn deconstruct_high_bytes(num: i128) -> i64 {
        Self::deconstruct_range_check(num);
        (num >> 63) as i64
    }

    fn deconstruct_low_bytes(num: i128) -> i64 {
        (num & 0x7FFFFFFFFFFFFFFFi128) as i64
    }

    pub fn reconstitute(high_bytes: i64, low_bytes: i64) -> i128 {
        Self::forbidden_low_bytes_negativity_check(low_bytes);
        let low_bytes = low_bytes as i128;
        let high_bytes = high_bytes as i128;
        (high_bytes << 63) | low_bytes
    }

    fn deconstruct_range_check(num: i128) {
        let top_two_bits = num >> 126 & 0b11;
        if top_two_bits == 0b01 {
            panic!("Dividing big integer for special database storage: {:#X} is too big, maximally 0x3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF allowed",num)
        } else if top_two_bits == 0b10 {
            panic!("Dividing big integer for special database storage: {:#X} is too small, minimally 0xC0000000000000000000000000000000 allowed",num)
        }
    }

    fn forbidden_low_bytes_negativity_check(low_bytes: i64) {
        if low_bytes < 0 {
            panic!("Reconstituting big integer from special database storage: the second, lower integer {:#X} is signed despite the requirement to be all-time positive",low_bytes)
        }
    }

    pub fn register_big_int_deconstruction_for_sqlite_connection(
        conn: &Connection,
    ) -> rusqlite::Result<()> {
        Self::register_deconstruct_guts(conn, "slope_drop_high_bytes", "slope_drop_low_bytes")
    }

    fn register_deconstruct_guts(
        conn: &Connection,
        fn_name_1: &'static str,
        fn_name_2: &'static str,
    ) -> rusqlite::Result<()> {
        fn common_arg_distillation(
            rusqlite_fn_ctx: &Context,
            fn_name: &str,
        ) -> rusqlite::Result<i128> {
            const ERR_MSG_BEGINNINGS: [&str; 3] = ["First", "Second", "Third"];
            let error_msg = |msg: String| -> rusqlite::Error {
                UserFunctionError(Box::new(InvalidInputValue(fn_name.to_string(), msg)))
            };
            let get_i64_from_args = |arg_idx: usize| -> rusqlite::Result<i64> {
                let raw_value = rusqlite_fn_ctx.get_raw(arg_idx);
                raw_value.as_i64().map_err(|_| {
                    error_msg(format!(
                        "{} argument takes only i64, not: {:?}",
                        ERR_MSG_BEGINNINGS[arg_idx], raw_value
                    ))
                })
            };
            let start_point_to_decrease_from_gwei = get_i64_from_args(0)?;
            let slope = get_i64_from_args(1)?;
            let time_parameter = get_i64_from_args(2)?;
            match (slope.is_negative(), time_parameter.is_positive()) {
                (true, true) => Ok(gwei_to_wei::<i128, _>(start_point_to_decrease_from_gwei) + slope as i128 * time_parameter as i128),
                (false, _) => Err(error_msg(format!(
                    "Nonnegative slope {}; delinquency slope must be negative, since debts must become more delinquent over time.",
                    slope
                ))),
                _ => Err(error_msg(format!(
                    "Negative time parameter {}; debt age cannot go negative.",
                    time_parameter
                ))),
            }
        }

        create_big_int_sqlite_fns!(
            conn, fn_name_1, fn_name_2;
            deconstruct_high_bytes, deconstruct_low_bytes
        );
        Ok(())
    }
}

#[derive(Debug, PartialEq)]
enum UserDefinedFunctionError {
    InvalidInputValue(String, String),
}

impl std::error::Error for UserDefinedFunctionError {}

impl Display for UserDefinedFunctionError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            InvalidInputValue(fn_name, err_msg) => {
                write!(f, "Error from {}: {}", fn_name, err_msg)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accountant::big_int_processing::test_utils::restricted::create_new_empty_db;
    use rusqlite::Error::SqliteFailure;
    use rusqlite::ErrorCode;

    fn assert_reconstitution(as_two_integers: (i64, i64), expected_number: i128) {
        let result = BigIntDivider::reconstitute(as_two_integers.0, as_two_integers.1);

        assert_eq!(result, expected_number)
    }

    #[test]
    fn deconstruct_and_reconstitute_works_for_huge_number() {
        let tested_number = (0x3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFu128) as i128;

        let result = BigIntDivider::deconstruct(tested_number);

        assert_eq!(result, (i64::MAX, i64::MAX));

        assert_reconstitution(result, tested_number)
    }

    #[test]
    fn deconstruct_and_reconstitute_works_for_number_just_slightly_bigger_than_the_low_b_type_size()
    {
        let tested_number = i64::MAX as i128 + 1;

        let result = BigIntDivider::deconstruct(tested_number);

        assert_eq!(result, (1, 0));

        assert_reconstitution(result, tested_number)
    }

    #[test]
    fn help() {
        // let tested_number = i64::MAX as i128 + 1;
        //
        // let result = BigIntDivider::deconstruct(tested_number);
        //
        // assert_eq!(result, (1, 0));
        eprintln!("{}", BigIntDivider::reconstitute(0, i64::MAX));
        todo!("destroy me");
    }

    #[test]
    fn deconstruct_works_for_big_number() {
        let tested_number = i64::MAX as i128;
        let result = BigIntDivider::deconstruct(i64::MAX as i128);

        assert_eq!(result, (0, 9223372036854775807));

        assert_reconstitution(result, tested_number)
    }

    #[test]
    fn deconstruct_works_for_small_positive_number() {
        let tested_number = 1;
        let result = BigIntDivider::deconstruct(tested_number);

        assert_eq!(result, (0, 1));

        assert_reconstitution(result, tested_number)
    }

    #[test]
    fn deconstruct_works_for_zero() {
        let tested_number = 0;
        let result = BigIntDivider::deconstruct(tested_number);

        assert_eq!(result, (0, 0));

        assert_reconstitution(result, tested_number)
    }

    #[test]
    fn deconstruct_works_for_small_negative_number() {
        let tested_number = -1;
        let result = BigIntDivider::deconstruct(tested_number);

        assert_eq!(result, (-1, i64::MAX));

        assert_reconstitution(result, tested_number)
    }

    #[test]
    fn deconstruct_works_for_big_negative_number() {
        let tested_number = i64::MIN as i128;
        let result = BigIntDivider::deconstruct(tested_number);

        assert_eq!(result, (-1, 0));

        assert_reconstitution(result, tested_number)
    }

    #[test]
    fn deconstruct_and_reconstitute_works_for_number_just_slightly_smaller_than_the_low_b_type_size(
    ) {
        let tested_number = i64::MIN as i128 - 1;
        let result = BigIntDivider::deconstruct(tested_number);

        assert_eq!(result, (-2, 9223372036854775807));

        assert_reconstitution(result, tested_number)
    }

    #[test]
    fn deconstruct_works_for_huge_negative_number() {
        let tested_number = 0xC0000000000000000000000000000000u128 as i128;
        let result = BigIntDivider::deconstruct(tested_number);

        assert_eq!(result, (-9223372036854775808, 0));

        assert_reconstitution(result, tested_number)
    }

    #[test]
    #[should_panic(
        expected = "Dividing big integer for special database storage: 0x40000000000000000000000000000000 is too big, maximally 0x3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF allowed"
    )]
    fn deconstruct_has_its_limits_up() {
        let _ = BigIntDivider::deconstruct(0x3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF + 1);
    }

    #[test]
    #[should_panic(
        expected = "Dividing big integer for special database storage: 0xBFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF is too small, minimally 0xC0000000000000000000000000000000 allowed"
    )]
    fn deconstruct_has_its_limits_down() {
        let _ = BigIntDivider::deconstruct((0xC0000000000000000000000000000000u128 as i128) - 1);
    }

    #[test]
    #[should_panic(
        expected = "Reconstituting big integer from special database storage: the second, lower integer 0xFFFFFFFFFFFFFFFF is signed despite the requirement to be all-time positive"
    )]
    fn reconstitute_should_reject_lower_half_with_high_bit_set() {
        let _ = BigIntDivider::reconstitute(0, -1);
    }

    #[test]
    fn divided_integers_can_be_ordered() {
        let init = i64::MAX as i128 * 23;
        let numbers_ordered = vec![
            i64::MAX as i128 + 1,
            i64::MAX as i128,
            (i64::MAX - 1) as i128,
            7654,
            0,
            -4567,
            (i64::MIN + 1) as i128,
            i64::MIN as i128,
            i64::MIN as i128 - 1,
            i64::MIN as i128 * 32,
        ];

        let _ = numbers_ordered.into_iter().enumerate().fold(
            init,
            |previous_big_int, (idx, current_big_int): (usize, i128)| {
                let (previous_high_b, previous_low_b) = BigIntDivider::deconstruct(previous_big_int);
                let (current_high_b, current_low_b) = BigIntDivider::deconstruct(current_big_int);
                assert!(
                    (previous_high_b > current_high_b) || (previous_high_b == current_high_b && previous_low_b > current_low_b) ,
                    "previous_high_b: {}, current_high_b: {} and previous_low_b: {}, current_low_b: {} for {} and {} which is idx {}",
                    previous_high_b,
                    current_high_b,
                    previous_low_b,
                    current_low_b,
                    BigIntDivider::reconstitute(previous_high_b, previous_low_b),
                    BigIntDivider::reconstitute(current_high_b, current_low_b),
                    idx
                );
                current_big_int
            },
        );
    }

    fn create_test_table_and_run_register_deconstruction_for_sqlite_connection(
        test_name: &str,
    ) -> Connection {
        let conn = create_new_empty_db("big_int_db_processor", test_name);
        BigIntDivider::register_big_int_deconstruction_for_sqlite_connection(&conn).unwrap();
        conn.execute("create table test_table (computed_high_bytes int, computed_low_bytes int, database_parameter int not null)",[]).unwrap();
        conn
    }

    #[test]
    fn register_deconstruct_for_sqlite_connection_works() {
        let conn = create_test_table_and_run_register_deconstruction_for_sqlite_connection(
            "register_deconstruct_for_sqlite_connection_works",
        );

        let database_value_1: i64 = 12222;
        let database_value_2: i64 = 23333444;
        let database_value_3: i64 = 5555;
        let slope: i64 = -35_000_000;
        conn.execute(
            "insert into test_table (database_parameter) values (?),(?),(?)",
            &[&database_value_1, &database_value_2, &database_value_3],
        )
        .unwrap();
        let arbitrary_constant = 111222333444_i64;
        conn.execute(
            "update test_table set computed_high_bytes = slope_drop_high_bytes(:my_constant, :slope, database_parameter),\
        computed_low_bytes = slope_drop_low_bytes(:my_constant, :slope, database_parameter)",
            &[(":my_constant", &arbitrary_constant), (":slope", &slope)],
        )
            .unwrap();
        let mut stm = conn
            .prepare("select computed_high_bytes, computed_low_bytes from test_table")
            .unwrap();
        let computed_values = stm
            .query_map([], |row| {
                let high_bytes = row.get::<usize, i64>(0).unwrap();
                let low_bytes = row.get::<usize, i64>(1).unwrap();
                Ok((high_bytes, low_bytes))
            })
            .unwrap()
            .flatten()
            .collect::<Vec<_>>();
        assert_eq!(
            computed_values,
            vec![
                BigIntDivider::deconstruct(
                    gwei_to_wei::<i128, _>(arbitrary_constant) + (slope * database_value_1) as i128
                ),
                BigIntDivider::deconstruct(
                    gwei_to_wei::<i128, _>(arbitrary_constant) + (slope * database_value_2) as i128
                ),
                BigIntDivider::deconstruct(
                    gwei_to_wei::<i128, _>(arbitrary_constant) + (slope * database_value_3) as i128
                )
            ]
        );
    }

    #[test]
    fn user_defined_functions_error_implements_display() {
        assert_eq!(
            InvalidInputValue("CoolFn".to_string(), "error message".to_string()).to_string(),
            "Error from CoolFn: error message".to_string()
        )
    }

    #[test]
    fn register_deconstruct_for_sqlite_connection_returns_error_at_setting_the_first_function() {
        let conn = create_test_table_and_run_register_deconstruction_for_sqlite_connection(
            "register_deconstruct_for_sqlite_connection_returns_error_at_setting_the_first_function",
        );

        let result = conn
            .execute(
                "insert into test_table (computed_high_bytes) values (slope_drop_high_bytes('hello', -4005000000, 712))",
                [],
            )
            .unwrap_err();

        assert_eq!(
            result,
            SqliteFailure(
                rusqlite::ffi::Error {
                    code: ErrorCode::Unknown,
                    extended_code: 1
                },
                Some(
                    "Error from slope_drop_high_bytes: First argument takes only i64, not: Text([104, 101, 108, 108, 111])"
                        .to_string()
                )
            )
        )
    }

    #[test]
    fn register_deconstruct_for_sqlite_connection_returns_error_at_setting_the_second_function() {
        let conn = create_test_table_and_run_register_deconstruction_for_sqlite_connection(
            "register_deconstruct_for_sqlite_connection_returns_error_at_setting_the_second_function",
        );

        let result = conn
            .execute(
                "insert into test_table (computed_high_bytes) values (slope_drop_low_bytes('bye', -10000000000, 44233))",
                [],
            )
            .unwrap_err();

        assert_eq!(
            result,
            SqliteFailure(
                rusqlite::ffi::Error {
                    code: ErrorCode::Unknown,
                    extended_code: 1
                },
                Some(
                    "Error from slope_drop_low_bytes: First argument takes only i64, not: Text([98, 121, 101])".to_string()
                )
            )
        )
    }

    #[test]
    fn our_sqlite_functions_are_specialized_and_thus_should_not_take_positive_number_for_the_second_parameter(
    ) {
        let conn = create_test_table_and_run_register_deconstruction_for_sqlite_connection(
            "our_sqlite_functions_are_specialized_and_thus_should_not_take_positive_number_for_the_second_parameter"
        );
        let error_invoker = |bytes_type: &str| {
            let sql = format!(
                "insert into test_table (computed_{0}_bytes) values (slope_drop_{0}_bytes(45656, 5656, 11111))",
                bytes_type
            );
            conn.execute(&sql, []).unwrap_err()
        };

        let high_bytes_error = error_invoker("high");
        let low_bytes_error = error_invoker("low");

        assert_eq!(
            high_bytes_error,
            SqliteFailure(
                rusqlite::ffi::Error {
                    code: ErrorCode::Unknown,
                    extended_code: 1
                },
                Some(
                    "Error from slope_drop_high_bytes: Nonnegative slope 5656; delinquency \
                        slope must be negative, since debts must become more delinquent over time."
                        .to_string()
                )
            )
        );
        assert_eq!(
            low_bytes_error,
            SqliteFailure(
                rusqlite::ffi::Error {
                    code: ErrorCode::Unknown,
                    extended_code: 1
                },
                Some(
                    "Error from slope_drop_low_bytes: Nonnegative slope 5656; delinquency \
                       slope must be negative, since debts must become more delinquent over time."
                        .to_string()
                )
            )
        );
    }

    #[test]
    fn our_sqlite_functions_are_specialized_thus_should_not_take_negative_number_for_the_third_parameter(
    ) {
        let conn = create_test_table_and_run_register_deconstruction_for_sqlite_connection(
            "our_sqlite_functions_are_specialized_thus_should_not_take_negative_number_for_the_third_parameter"
        );
        let error_invoker = |bytes_type: &str| {
            let sql = format!(
                "insert into test_table (computed_{0}_bytes) values (slope_drop_{0}_bytes(45656, -500000, -11111))",
                bytes_type
            );
            conn.execute(&sql, []).unwrap_err()
        };

        let high_bytes_error = error_invoker("high");
        let low_bytes_error = error_invoker("low");

        assert_eq!(
            high_bytes_error,
            SqliteFailure(
                rusqlite::ffi::Error {
                    code: ErrorCode::Unknown,
                    extended_code: 1
                },
                Some(
                    "Error from slope_drop_high_bytes: Negative time parameter -11111; debt age cannot go negative."
                        .to_string()
                )
            )
        );
        assert_eq!(
            low_bytes_error,
            SqliteFailure(
                rusqlite::ffi::Error {
                    code: ErrorCode::Unknown,
                    extended_code: 1
                },
                Some(
                    "Error from slope_drop_low_bytes: Negative time parameter -11111; debt age cannot go negative."
                        .to_string()
                )
            )
        );
    }

    #[test]
    fn third_argument_error() {
        let conn = create_test_table_and_run_register_deconstruction_for_sqlite_connection(
            "third_argument_error",
        );

        let result = conn
            .execute(
                "insert into test_table (computed_high_bytes) values (slope_drop_low_bytes(15464646, 7866, 'time'))",
                [],
            )
            .unwrap_err();

        assert_eq!(
            result,
            SqliteFailure(
                rusqlite::ffi::Error{ code: ErrorCode::Unknown, extended_code: 1 },
                Some("Error from slope_drop_low_bytes: Third argument takes only i64, not: Text([116, 105, 109, 101])".to_string()
                ))
        )
    }

    #[test]
    fn first_fn_returns_internal_error_from_create_scalar_function() {
        let conn = create_test_table_and_run_register_deconstruction_for_sqlite_connection(
            "first_fn_returns_internal_error_from_create_scalar_function",
        );

        let result = BigIntDivider::register_deconstruct_guts(
            &conn,
            "badly\u{0000}named",
            "slope_drop_low_bytes",
        )
        .unwrap_err();

        //not asserting on the exact fit because the error
        //would involve some unstable code at reproducing it
        assert_eq!(
            result.to_string(),
            "nul byte found in provided data at position: 5".to_string()
        )
    }

    #[test]
    fn second_fn_returns_internal_error_from_create_scalar_function() {
        let conn = create_test_table_and_run_register_deconstruction_for_sqlite_connection(
            "second_fn_returns_internal_error_from_create_scalar_function",
        );

        let result = BigIntDivider::register_deconstruct_guts(
            &conn,
            "slope_drop_high_bytes",
            "also\u{0000}badlynamed",
        )
        .unwrap_err();

        //not asserting on the exact fit because the error
        //would involve some unstable code at reproducing it
        assert_eq!(
            result.to_string(),
            "nul byte found in provided data at position: 4".to_string()
        )
    }
}
