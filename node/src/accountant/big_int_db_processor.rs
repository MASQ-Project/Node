// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::big_int_db_processor::ByteOrder::{High, Low};
use crate::accountant::big_int_db_processor::UserDefinedFunctionError::InvalidInputValue;
use crate::accountant::big_int_db_processor::WeiChange::{Addition, Subtraction};
use crate::accountant::checked_conversion;
use crate::accountant::payable_dao::PayableDaoError;
use crate::accountant::receivable_dao::ReceivableDaoError;
use crate::database::connection_wrapper::ConnectionWrapper;
use crate::sub_lib::accountant::WEIS_OF_GWEI;
use crate::sub_lib::wallet::Wallet;
use itertools::Either;
use masq_lib::utils::ExpectValue;
use rusqlite::functions::{Context, FunctionFlags};
use rusqlite::Error::UserFunctionError;
use rusqlite::{Connection, Error, Statement, ToSql, Transaction};
use std::fmt::{Debug, Display, Formatter};
use std::iter::once;
use std::marker::PhantomData;
use std::ops::Neg;
use std::os::raw::c_int;

#[derive(Debug)]
pub struct BigIntDbProcessor<T: DAOTableIdentifier> {
    phantom: PhantomData<T>,
}

impl<T: DAOTableIdentifier> BigIntDbProcessor<T> {
    pub fn execute<'a>(
        &self,
        conn: Either<&dyn ConnectionWrapper, &Transaction>,
        config: BigIntSqlConfig<'a, T>,
    ) -> Result<(), BigIntDbError> {
        let main_sql = config.construct_main_sql();
        let mut stm = Self::prepare_statement(conn, &main_sql);
        let params = config
            .params
            .pure_rusqlite_params_uncorrected()
            .collect::<Vec<(&str, &dyn ToSql)>>();
        match stm.execute(params.as_slice()) {
            Ok(_) => Ok(()),
            //SQLITE_CONSTRAINT_DATATYPE (3091),
            //the moment of Sqlite trying to store the number as REAL in a strict INT column
            Err(Error::SqliteFailure(e, _)) if e.extended_code == c_int::from(3091) => {
                self.update_threatened_by_overflow(conn, config)
            }
            Err(e) => Err(BigIntDbError(format!(
                "Wei change: error after invalid {} command for {} of {} Wei to {} with error '{}'",
                config.determine_command(),
                T::table_name(),
                config.balance_change(),
                config.key_info().1,
                e
            ))),
        }
    }

    fn update_threatened_by_overflow<'a>(
        &self,
        conn: Either<&dyn ConnectionWrapper, &Transaction>,
        config: BigIntSqlConfig<'a, T>,
    ) -> Result<(), BigIntDbError> {
        let select_sql = config.select_sql();
        let mut select_stm = Self::prepare_statement(conn, &select_sql);
        match select_stm.query_row([], |row| {
            let low_bytes_result = row.get::<usize, i64>(0);
            match low_bytes_result {
                Ok(low_bytes) => {
                    let wei_change_params = &config.params.wei_change_params;
                    let high_bytes_correction = wei_change_params[0].1 + 1;
                    let low_bytes_correction = ((low_bytes as i128
                        + wei_change_params[1].1 as i128)
                        & 0x7FFFFFFFFFFFFFFF) as i64
                        - low_bytes;
                    let update_sql = config.prepare_update_sql();
                    let mut update_stm = Self::prepare_statement(conn, &update_sql);
                    let wei_update_array = [
                        (wei_change_params[0].0.as_str(), high_bytes_correction),
                        (wei_change_params[1].0.as_str(), low_bytes_correction),
                    ];
                    let params = config
                        .params
                        .pure_rusqlite_params_corrected(&wei_update_array)
                        .collect::<Vec<_>>();
                    match update_stm
                        .execute(&*params)
                        .expect("correction-for update sql has wrong logic")
                    {
                        1 => Ok(()),
                        x => unreachable!(
                            "This code was written to handle one changed row a time, not {}",
                            x
                        ),
                    }
                }
                Err(e) => Err(e),
            }
        }) {
            Ok(()) => Ok(()),
            Err(e) => Err(BigIntDbError(format!(
                "Updating balance for {} of {} Wei to {} with error '{}'",
                T::table_name(),
                config.balance_change(),
                config.key_info().1,
                e
            ))),
        }
    }
}

impl<T: DAOTableIdentifier> BigIntDbProcessor<T> {
    pub fn new() -> BigIntDbProcessor<T> {
        Self {
            phantom: Default::default(),
        }
    }
}

impl<T: DAOTableIdentifier> BigIntDbProcessor<T> {
    fn prepare_statement<'a>(
        form_of_conn: Either<&'a dyn ConnectionWrapper, &'a Transaction>,
        sql: &'a str,
    ) -> Statement<'a> {
        match form_of_conn {
            Either::Left(conn) => conn.prepare(sql),
            Either::Right(tx) => tx.prepare(sql),
        }
        .expect("internal rusqlite error")
    }
}

pub struct BigIntSqlConfig<'a, T> {
    main_sql: &'a str,
    update_clause_opt: Option<for<'b> fn(&'b str) -> String>,
    pub params: SQLParams<'a>,
    phantom: PhantomData<T>,
}

impl<'a, T: DAOTableIdentifier> BigIntSqlConfig<'a, T> {
    pub fn new(
        main_sql: &'a str,
        update_clause_opt: Option<for<'b> fn(&'b str) -> String>,
        params: SQLParams<'a>,
    ) -> BigIntSqlConfig<'a, T> {
        Self {
            main_sql,
            update_clause_opt,
            params,
            phantom: Default::default(),
        }
    }

    fn construct_main_sql(&self) -> String {
        format!(
            "{} {}",
            self.main_sql,
            if let Some(assembler) = self.update_clause_opt {
                assembler("")
            } else {
                String::new()
            }
        )
    }

    fn prepare_update_sql(&self) -> String {
        if let Some(assembler) = self.update_clause_opt {
            assembler(&T::table_name())
        } else {
            self.main_sql.to_string()
        }
    }

    fn select_sql(&self) -> String {
        let key_info = self.key_info();
        format!(
            "select {} from {} where {} = '{}'",
            &self.params.wei_change_params[1].0[1..],
            T::table_name(),
            self.params.table_key_name,
            key_info.1.to_string()
        )
    }

    fn key_info(&self) -> (&str, String) {
        let key_definition = self.params.params_except_wei_change[0];
        (key_definition.0, key_definition.1.to_string())
    }

    fn balance_change(&self) -> i128 {
        let wei_params = &self.params.wei_change_params;
        BigIntDivider::reconstitute(wei_params[0].1, wei_params[1].1)
    }

    fn determine_command(&self) -> String {
        let keyword = self
            .main_sql
            .chars()
            .skip_while(|char| char.is_whitespace())
            .take_while(|char| !char.is_whitespace())
            .collect::<String>();
        match (keyword.trim(), self.update_clause_opt.is_some()) {
            ("insert", true) => "upsert".to_string(),
            ("update", false) => keyword,
            _ => panic!(
                "broken code: unexpected or misplaced command \"{}\" in upsert",
                keyword
            ),
        }
    }
}

//to be able to display things that implement ToSql
pub trait ExtendedParamsMarker: ToSql + Display {}

macro_rules! impl_of_extended_params_marker{
    ($($implementer: ty),+) => {
        $(impl ExtendedParamsMarker for $implementer {})+
    }
}

impl_of_extended_params_marker!(i64, &str, Wallet);

#[derive(Default)]
pub struct SQLParamsBuilder<'a> {
    key_spec_opt: Option<(&'a str, &'a str, &'a dyn ExtendedParamsMarker)>,
    wei_change_spec_opt: Option<WeiChange>,
    other_params: Vec<(&'a str, &'a dyn ExtendedParamsMarker)>,
}

impl<'a> SQLParamsBuilder<'a> {
    pub fn key(
        mut self,
        table_param_name: &'a str,
        substitution_name: &'a str,
        value: &'a dyn ExtendedParamsMarker,
    ) -> Self {
        self.key_spec_opt = Some((table_param_name, substitution_name, value));
        self
    }

    pub fn wei_change(mut self, wei_change: WeiChange) -> Self {
        self.wei_change_spec_opt = Some(wei_change);
        self
    }

    pub fn other(mut self, params: Vec<(&'a str, &'a (dyn ExtendedParamsMarker + 'a))>) -> Self {
        self.other_params = params;
        self
    }

    pub fn build(self) -> SQLParams<'a> {
        let key_spec = self
            .key_spec_opt
            .unwrap_or_else(|| panic!("SQLparams cannot miss the component of a key"));
        let wei_change_spec = self
            .wei_change_spec_opt
            .unwrap_or_else(|| panic!("SQLparams cannot miss the component of Wei change"));
        let (wei_change_names, split_bytes) = Self::expand_wei_params(wei_change_spec);
        let params = once((key_spec.1, key_spec.2))
            .chain(self.other_params.into_iter())
            .collect();
        SQLParams {
            table_key_name: key_spec.0,
            wei_change_params: [
                (wei_change_names.0, split_bytes.0),
                (wei_change_names.1, split_bytes.1),
            ],
            params_except_wei_change: params,
        }
    }

    fn expand_wei_params(wei_change_spec: WeiChange) -> ((String, String), (i64, i64)) {
        let (name, num): (&'static str, i128) = match wei_change_spec {
            Addition(name, num) => (name, checked_conversion::<u128, i128>(num)),
            Subtraction(name, num) => (name, checked_conversion::<u128, i128>(num).neg()),
        };
        let (high_bytes, low_bytes) = BigIntDivider::deconstruct(num);
        let param_sub_name_for_high_bytes = Self::proper_wei_change_param_name(name, High);
        let param_sub_name_for_low_bytes = Self::proper_wei_change_param_name(name, Low);
        (
            (param_sub_name_for_high_bytes, param_sub_name_for_low_bytes),
            (high_bytes, low_bytes),
        )
    }

    fn proper_wei_change_param_name(base_word: &str, byte_order: ByteOrder) -> String {
        format!(":{}_{}_b", base_word, byte_order)
    }
}

enum ByteOrder {
    High,
    Low,
}

impl Display for ByteOrder {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            High => write!(f, "high"),
            Low => write!(f, "low"),
        }
    }
}

pub struct SQLParams<'a> {
    table_key_name: &'a str,
    wei_change_params: [(String, i64); 2],
    params_except_wei_change: Vec<(&'a str, &'a dyn ExtendedParamsMarker)>,
}

impl<'a> SQLParams<'a> {
    fn pure_rusqlite_params_uncorrected(&self) -> impl Iterator<Item = (&str, &dyn ToSql)> {
        self.pure_rusqlite_params(
            self.wei_change_params
                .iter()
                .map(|(name, value)| (name.as_str(), value as &dyn ToSql)),
        )
    }

    fn pure_rusqlite_params_corrected(
        &'a self,
        wei_change_params: &'a [(&'a str, i64); 2],
    ) -> impl Iterator<Item = (&str, &dyn ToSql)> {
        self.pure_rusqlite_params(
            wei_change_params
                .into_iter()
                .map(|(name, num)| (*name, num as &dyn ToSql)),
        )
    }

    fn pure_rusqlite_params(
        &'a self,
        wei_change_params: impl Iterator<Item = (&'a str, &'a dyn ToSql)>,
    ) -> impl Iterator<Item = (&'a str, &'a dyn ToSql)> {
        self.params_except_wei_change
            .iter()
            .map(|(name, value)| (*name, value as &dyn ToSql))
            .chain(wei_change_params)
    }
}

pub trait DAOTableIdentifier: Debug + Send {
    fn table_name() -> String;
}

#[derive(Debug, PartialEq, Clone)]
pub enum WeiChange {
    Addition(&'static str, u128),
    Subtraction(&'static str, u128),
}

#[derive(Debug, PartialEq)]
pub struct BigIntDbError(pub String);

macro_rules! insert_update_error_from {
    ($implementer: ident) => {
        impl From<BigIntDbError> for $implementer {
            fn from(iu_err: BigIntDbError) -> Self {
                $implementer::RusqliteError(iu_err.0)
            }
        }
    };
}

insert_update_error_from!(PayableDaoError);
insert_update_error_from!(ReceivableDaoError);

pub fn collect_and_sum_i128_values_from_table(
    conn: &dyn ConnectionWrapper,
    table: &str,
    parameter_name: &str,
) -> i128 {
    let select_stm = format!(
        "select {0}_high_b, {0}_low_b from {1}",
        parameter_name, table
    );
    conn.prepare(&select_stm)
        .expect("select stm error")
        .query_map([], |row| {
            Ok(BigIntDivider::reconstitute(
                row.get::<usize, i64>(0).expectv("high bytes"),
                row.get::<usize, i64>(1).expectv("low_bytes"),
            ))
        })
        .expect("select query failed")
        .flatten()
        .sum()
}

macro_rules! create_big_int_sqlite_fns {
    ($conn: expr, $flags: expr, $($sqlite_fn_name: expr),+; $($intern_fn_name: ident),+) => {
        $($conn.create_scalar_function::<_, i64>($sqlite_fn_name, 2, $flags, move |ctx| {
            Ok(BigIntDivider::$intern_fn_name(common_arg_distillation(
                ctx,
                $sqlite_fn_name,
            )?))
        })?;)+
    }
}

macro_rules! parse_fn_creation_args {
    ($ctx: expr, $fn_name: expr, $($idx: expr),+; $($parser: ident),+; $($err_msg: literal),+) => {
        ($($ctx.get_raw($idx)
            .$parser()
            .map_err(|_| invalid_input_error($fn_name, format!($err_msg, $ctx.get_raw($idx))))?
        ),+)
    };
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
        let high_bytes = (num >> 63) as i64;
        if num.is_positive() && (high_bytes.abs() as u64 & 0xC000000000000000u64) > 0 {
            panic!("Too big positive integer to be divided: {:#X}", num)
        }
        if num < -0x40000000000000000000000000000000 {
            panic!("Too big negative integer to be divided: -{:#X}", num)
        }
        high_bytes
    }

    fn deconstruct_low_bytes(num: i128) -> i64 {
        (num & 0x7FFFFFFFFFFFFFFFi128) as i64
    }

    pub fn reconstitute(high_bytes: i64, low_bytes: i64) -> i128 {
        let low_bytes = low_bytes as i128;
        let high_bytes = high_bytes as i128;
        (high_bytes << 63) | low_bytes
    }

    pub fn register_deconstruct_for_sqlite_connection(conn: &Connection) -> rusqlite::Result<()> {
        Self::guts_of_register_deconstruct(conn, "biginthigh", "bigintlow")
    }

    fn guts_of_register_deconstruct(
        conn: &Connection,
        fn_name_1: &'static str,
        fn_name_2: &'static str,
    ) -> rusqlite::Result<()> {
        fn invalid_input_error(fn_name: &str, message: String) -> Error {
            UserFunctionError(Box::new(InvalidInputValue(fn_name.to_string(), message)))
        }
        fn negativity_check_and_final_composition(
            fn_name: &str,
            tuple: (i64, f64),
        ) -> rusqlite::Result<i128> {
            let (point_to_decrease_from_gwei, decrease_wei) = tuple;
            if decrease_wei.is_sign_negative() {
                Ok(point_to_decrease_from_gwei as i128 * WEIS_OF_GWEI + decrease_wei as i128)
            } else {
                Err(invalid_input_error(
                    fn_name,
                    format!(
                        "None negative slope, while designed only for use with negative one: {}",
                        decrease_wei
                    ),
                ))
            }
        }
        fn common_arg_distillation(ctx: &Context, fn_name: &str) -> rusqlite::Result<i128> {
            negativity_check_and_final_composition(
                fn_name,
                parse_fn_creation_args!(
                    ctx, fn_name,
                    0, 1;
                    as_i64, as_f64;
                    "First argument takes only i64, not: {:?}",
                    "Second argument takes only a real number, not: {:?}"
                ),
            )
        }

        create_big_int_sqlite_fns!(
            conn,
            FunctionFlags::SQLITE_UTF8 | FunctionFlags::SQLITE_DETERMINISTIC,
            fn_name_1, fn_name_2;
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
    use crate::accountant::big_int_db_processor::WeiChange::Addition;
    use crate::database::connection_wrapper::{ConnectionWrapper, ConnectionWrapperReal};
    use crate::test_utils::make_wallet;
    use itertools::Either;
    use itertools::Either::Left;
    use masq_lib::test_utils::utils::ensure_node_home_directory_exists;
    use rusqlite::Error::SqliteFailure;
    use rusqlite::{Connection, ErrorCode, ToSql};

    #[derive(Debug)]
    struct DummyDao {}

    impl DAOTableIdentifier for DummyDao {
        fn table_name() -> String {
            String::from("test_table")
        }
    }

    #[test]
    fn conversion_from_insert_update_error_to_particular_payable_dao_error_works() {
        let subject = BigIntDbError(String::from("whatever"));

        let result: PayableDaoError = subject.into();

        assert_eq!(
            result,
            PayableDaoError::RusqliteError("whatever".to_string())
        )
    }

    #[test]
    fn conversion_from_insert_update_error_to_particular_receivable_dao_error_works() {
        let subject = BigIntDbError(String::from("whatever"));

        let result: ReceivableDaoError = subject.into();

        assert_eq!(
            result,
            ReceivableDaoError::RusqliteError("whatever".to_string())
        )
    }

    #[test]
    fn display_for_byte_order_works() {
        assert_eq!(High.to_string(), "high".to_string());
        assert_eq!(Low.to_string(), "low".to_string())
    }

    #[test]
    fn sql_params_builder_is_nicely_populated_inside_before_calling_build() {
        let subject = SQLParamsBuilder::default();

        let result = subject
            .wei_change(Addition("balance", 4546))
            .key("some_key", ":some_key", &"blah")
            .other(vec![("other_thing", &46565)]);

        assert_eq!(result.wei_change_spec_opt, Some(Addition("balance", 4546)));
        assert!(matches!(
            result.key_spec_opt,
            Some(("some_key", ":some_key", _))
        ));
        assert!(matches!(result.other_params[0], ("other_thing", _)));
        assert_eq!(result.other_params.len(), 1)
    }

    #[test]
    fn sql_params_builder_builds_correct_params() {
        let subject = SQLParamsBuilder::default();

        let result = subject
            .wei_change(Addition("balance", 115898))
            .key("some_key", ":some_key", &"blah")
            .other(vec![(":other_thing", &11111)])
            .build();

        assert_eq!(result.table_key_name, "some_key");
        assert_eq!(
            result.wei_change_params,
            [
                (":balance_high_b".to_string(), 0),
                (":balance_low_b".to_string(), 115898)
            ]
        );
        assert_eq!(result.params_except_wei_change[0].0, ":some_key");
        assert_eq!(
            result.params_except_wei_change[0].1.to_string(),
            "blah".to_string()
        );
        assert_eq!(result.params_except_wei_change[1].0, ":other_thing");
        assert_eq!(
            result.params_except_wei_change[1].1.to_string(),
            "11111".to_string()
        );
        assert_eq!(result.params_except_wei_change.len(), 2)
    }

    #[test]
    fn sql_params_builder_builds_correct_params_with_negative_wei_change() {
        let subject = SQLParamsBuilder::default();

        let result = subject
            .wei_change(Subtraction("balance", 454684))
            .key("some_key", ":some_key", &"wooow")
            .other(vec![(":other_thing", &46565)])
            .build();

        assert_eq!(result.table_key_name, "some_key");
        assert_eq!(
            result.wei_change_params,
            [
                (":balance_high_b".to_string(), -1),
                (":balance_low_b".to_string(), 9223372036854321124)
            ]
        );
        assert_eq!(result.params_except_wei_change[0].0, ":some_key");
        assert_eq!(
            result.params_except_wei_change[0].1.to_string(),
            "wooow".to_string()
        );
        assert_eq!(result.params_except_wei_change[1].0, ":other_thing");
        assert_eq!(
            result.params_except_wei_change[1].1.to_string(),
            "46565".to_string()
        );
        assert_eq!(result.params_except_wei_change.len(), 2)
    }

    #[test]
    #[should_panic(expected = "SQLparams cannot miss the component of a key")]
    fn sql_params_builder_cannot_be_built_without_key_spec() {
        let subject = SQLParamsBuilder::default();

        let _ = subject
            .wei_change(Addition("balance", 4546))
            .other(vec![("laughter", &"hahaha")])
            .build();
    }

    #[test]
    #[should_panic(expected = "SQLparams cannot miss the component of Wei change")]
    fn sql_params_builder_cannot_be_built_without_wei_change_spec() {
        let subject = SQLParamsBuilder::default();

        let _ = subject
            .key("wallet", ":wallet", &make_wallet("wallet"))
            .other(vec![("other_thing", &46565)])
            .build();
    }

    #[test]
    fn sql_params_builder_can_be_built_without_wei_change_spec() {
        let subject = SQLParamsBuilder::default();

        let _ = subject
            .wei_change(Addition("balance", 4546))
            .key("id", ":id", &45)
            .build();
    }

    fn make_empty_sql_params<'a>() -> SQLParams<'a> {
        SQLParams {
            table_key_name: "",
            wei_change_params: [("".to_string(), 0), ("".to_string(), 0)],
            params_except_wei_change: vec![],
        }
    }

    #[test]
    fn determine_command_works_for_upsert() {
        let subject: BigIntSqlConfig<'_, DummyDao> = BigIntSqlConfig {
            main_sql: "insert into table (a,b) values ('a','b')",
            update_clause_opt: Some(|table| format!("side clause {}", table)),
            params: make_empty_sql_params(),
            phantom: Default::default(),
        };

        let result = subject.determine_command();

        assert_eq!(result, "upsert".to_string())
    }

    #[test]
    fn determine_command_works_for_update() {
        let subject: BigIntSqlConfig<'_, DummyDao> = BigIntSqlConfig {
            main_sql: "update table set a='a',b='b' where a = 'e'",
            update_clause_opt: None,
            params: make_empty_sql_params(),
            phantom: Default::default(),
        };

        let result = subject.determine_command();

        assert_eq!(result, "update".to_string())
    }

    #[test]
    #[should_panic(expected = "broken code: unexpected or misplaced command \"some\" in upsert")]
    fn determine_command_panics_if_unknown_command_without_update_clause() {
        let subject: BigIntSqlConfig<'_, DummyDao> = BigIntSqlConfig {
            main_sql: "some other sql command",
            update_clause_opt: None,
            params: make_empty_sql_params(),
            phantom: Default::default(),
        };

        let _ = subject.determine_command();
    }

    #[test]
    #[should_panic(expected = "broken code: unexpected or misplaced command \"wow\" in upsert")]
    fn determine_command_panics_if_malformed_upsert() {
        let subject: BigIntSqlConfig<'_, DummyDao> = BigIntSqlConfig {
            main_sql: "wow sql command",
            update_clause_opt: Some(|table| format!("side clause {}", table)),
            params: make_empty_sql_params(),
            phantom: Default::default(),
        };

        let _ = subject.determine_command();
    }

    #[test]
    #[should_panic(expected = "broken code: unexpected or misplaced command \"update\" in upsert")]
    fn determine_command_panics_if_upsert_starting_with_update() {
        let subject: BigIntSqlConfig<'_, DummyDao> = BigIntSqlConfig {
            main_sql: "update sql command",
            update_clause_opt: Some(|table| format!("hawk clause {}", table)),
            params: make_empty_sql_params(),
            phantom: Default::default(),
        };

        let _ = subject.determine_command();
    }

    #[test]
    fn determine_command_allows_preceding_spaces() {
        let subject: BigIntSqlConfig<'_, DummyDao> = BigIntSqlConfig {
            main_sql: "  update into table (a,b) values ('a','b')",
            update_clause_opt: None,
            params: make_empty_sql_params(),
            phantom: Default::default(),
        };

        let result = subject.determine_command();

        assert_eq!(result, "update".to_string())
    }

    fn insert_single_record(conn: &dyn ConnectionWrapper, params: [&dyn ToSql; 3]) {
        conn.prepare(
            "insert into test_table (name,balance_high_b, balance_low_b) values (?, ?, ?)",
        )
        .unwrap()
        .execute(params.as_slice())
        .unwrap();
    }

    fn assert_on_whole_row(
        conn: &dyn ConnectionWrapper,
        expected_name: &str,
        init_record_opt: Option<(&str, i64, i64)>,
        overflow_expected: bool,
        wei_change: i128,
    ) {
        let previous_num = if let Some(values) = init_record_opt {
            BigIntDivider::reconstitute(values.1, values.2)
        } else {
            0
        };
        let expected_sum = previous_num + wei_change;
        conn.prepare("select * from test_table")
            .unwrap()
            .query_row([], |row| {
                let name = row.get::<usize, String>(0).unwrap();
                assert_eq!(name, expected_name.to_string());
                let high_bytes = row.get::<usize, i64>(1).unwrap();
                let low_bytes = row.get::<usize, i64>(2).unwrap();
                let wei_change_high_b_component = BigIntDivider::deconstruct(wei_change).0;
                if overflow_expected {
                    assert_eq!(
                        high_bytes,
                        if let Some(values) = init_record_opt {
                            values.1
                        } else {
                            0
                        } + wei_change_high_b_component
                            + 1
                    )
                }
                let single_numbered_balance = BigIntDivider::reconstitute(high_bytes, low_bytes);
                assert_eq!(single_numbered_balance, expected_sum);
                Ok(())
            })
            .unwrap();
    }

    fn precise_upsert_or_update_assertion(
        test_name: &str,
        main_sql: &str,
        update_clause_opt: Option<for<'a> fn(&'a str) -> String>,
        init_record_opt: Option<(&str, i64, i64)>,
        requested_wei_change: WeiChange,
        do_we_expect_overflow: bool,
    ) {
        let act = |conn: &mut dyn ConnectionWrapper, subject: &BigIntDbProcessor<DummyDao>| {
            subject.execute(
                Left(conn),
                BigIntSqlConfig::new(
                    main_sql,
                    update_clause_opt,
                    SQLParamsBuilder::default()
                        .key("name", ":name", &"Joe")
                        .wei_change(requested_wei_change.clone())
                        .build(),
                ),
            )
        };

        precise_upsert_or_update_assertion_test_environment(
            test_name,
            init_record_opt,
            &requested_wei_change,
            do_we_expect_overflow,
            act,
        )
    }

    fn precise_upsert_or_update_assertion_test_environment<F>(
        test_name: &str,
        init_record_opt: Option<(&str, i64, i64)>,
        requested_wei_change: &WeiChange,
        do_we_expect_overflow: bool,
        act: F,
    ) where
        F: Fn(
            &mut dyn ConnectionWrapper,
            &BigIntDbProcessor<DummyDao>,
        ) -> Result<(), BigIntDbError>,
    {
        let mut conn = initiate_simple_connection_and_test_table("big_int_db_processor", test_name);
        if let Some(values) = init_record_opt {
            insert_single_record(conn.as_ref(), [&values.0, &values.1, &values.2])
        };
        let subject = BigIntDbProcessor::<DummyDao>::new();

        let result = act(conn.as_mut(), &subject);

        assert_eq!(result, Ok(()));
        let wei_change = match requested_wei_change {
            Addition(_, num) => checked_conversion::<u128, i128>(*num),
            Subtraction(_, num) => checked_conversion::<u128, i128>(*num).neg(),
        };
        let wei_change_deconstructed = BigIntDivider::deconstruct(wei_change);
        let (_, low_bytes) = wei_change_deconstructed;
        let did_overflow_occurred = if let Some(values) = init_record_opt {
            values.2
        } else {
            0
        }
        .checked_add(low_bytes)
        .is_none();
        assert_eq!(
            did_overflow_occurred, do_we_expect_overflow,
            "we encountered overflow on low bytes thought hadn't been expected"
        );
        assert_on_whole_row(
            &*conn,
            "Joe",
            init_record_opt,
            do_we_expect_overflow,
            wei_change,
        )
    }

    fn create_new_empty_db(module: &str, test_name: &str) -> Connection {
        let home_dir = ensure_node_home_directory_exists(module, test_name);
        let db_path = home_dir.join("test_table.db");
        Connection::open(db_path.as_path()).unwrap()
    }

    fn initiate_simple_connection_and_test_table(
        module: &str,
        test_name: &str,
    ) -> Box<ConnectionWrapperReal> {
        let conn = create_new_empty_db(module, test_name);
        conn.execute(
            "create table test_table (name text primary key, balance_high_b integer not null, balance_low_b integer not null) strict",
            [],
        )
            .unwrap();
        Box::new(ConnectionWrapperReal::new(conn))
    }

    #[test]
    fn update_alone_in_its_pure_look_works_just_fine_for_addition() {
        precise_upsert_or_update_assertion(
            "update_alone_in_its_pure_look_works_just_fine_for_addition",
            "update test_table set balance_high_b = balance_high_b + :balance_high_b, balance_low_b = balance_low_b + :balance_low_b where name = :name",
            None,
            Some((&"Joe",47,598745133)),
            Addition("balance", 255),
            false);
    }

    #[test]
    fn update_alone_works_for_addition_with_overflow() {
        precise_upsert_or_update_assertion(
            "update_alone_works_for_addition_with_overflow",
            "update test_table set balance_high_b = balance_high_b + :balance_high_b, balance_low_b = balance_low_b + :balance_low_b where name = :name",
            None,
            Some((&"Joe",47,i64::MAX - 12)),
            Addition("balance", 25578),
            true);
    }

    #[test]
    //this and the opposite test (with just a small number subtracted) has an important implication: if we subtract small numbers we will very easily enter encounter an update with overflow,
    //on the contrary, if we subtract very big numbers the chance is the smallest. The reason is in representation of those small negative numbers being subtracted, their low bytes are codified
    //by a huge integer. This implies that often
    fn update_alone_in_its_pure_look_works_just_fine_for_subtraction() {
        precise_upsert_or_update_assertion(
            "update_alone_in_its_pure_look_works_just_fine_for_subtraction",
            "update test_table set balance_high_b = balance_high_b + :balance_high_b, balance_low_b = balance_low_b + :balance_low_b where name = :name",
            None,
            Some((&"Joe",2,33348987)),
            Subtraction("balance", (i64::MAX - 5) as u128),
            false);
    }

    #[test]
    //notice of that small amount subtracted and still causing overflow
    fn update_alone_works_for_subtraction_with_overflow() {
        precise_upsert_or_update_assertion(
            "update_alone_works_for_subtraction_with_overflow",
            "update test_table set balance_high_b = balance_high_b + :balance_high_b, balance_low_b = balance_low_b + :balance_low_b where name = :name",
            None,
            Some((&"Joe",2,100)),
            Subtraction("balance", (6) as u128),
        true);
    }

    #[test]
    fn early_return_for_successful_insert_works_for_addition() {
        precise_upsert_or_update_assertion(
            "early_return_for_successful_insert_works",
            "insert into test_table (name,balance_high_b,balance_low_b) values (:name,:balance_high_b,:balance_low_b)",
            None,
            None,
            Addition("balance", (i64::MAX - 58989) as u128), false);
    }

    #[test]
    fn early_return_for_successful_insert_works_for_subtraction() {
        precise_upsert_or_update_assertion(
            "early_return_for_successful_insert_works_for_subtraction",
            "insert into test_table (name,balance_high_b,balance_low_b) values (:name,:balance_high_b,:balance_low_b)",
            None,
            None,
            Subtraction("balance", 58989787), false);
    }

    #[test]
    fn insert_fails_simple_update_succeeds_for_addition() {
        precise_upsert_or_update_assertion(
            "insert_fails_simple_update_succeeds_for_addition",
            "insert into test_table (name, balance_high_b, balance_low_b) values (:name, :balance_high_b, :balance_low_b) on conflict (name) do",
            Some(|table_name |format!("update {} set balance_high_b = balance_high_b + :balance_high_b, balance_low_b = balance_low_b + :balance_low_b where name = :name",table_name)),
            Some((&"Joe", 60, 5555)),
            Addition("balance", 78985269), false);
    }

    #[test]
    fn insert_fails_simple_update_succeeds_for_subtraction() {
        precise_upsert_or_update_assertion(
            "insert_fails_simple_update_succeeds_for_subtraction",
            "insert into test_table (name, balance_high_b, balance_low_b) values (:name, :balance_high_b, :balance_low_b) on conflict (name) do",
            Some(|table_name |format!("update {} set balance_high_b = balance_high_b + :balance_high_b, balance_low_b = balance_low_b + :balance_low_b where name = :name",table_name)),
            Some((&"Joe", 89489612, 7841212)),
            Subtraction("balance", 789858784879), false);
    }

    #[test]
    fn insert_fails_update_succeeds_with_overflow_for_addition() {
        let enough_big_number = BigIntDivider::reconstitute(48795846111, i64::MAX - 48484);
        precise_upsert_or_update_assertion(
            "insert_fails_update_succeeds_with_overflow_for_addition",
            "insert into test_table (name, balance_high_b, balance_low_b) values (:name, :balance_high_b, :balance_low_b) on conflict (name) do",
            Some(|table_name |format!("update {} set balance_high_b = balance_high_b + :balance_high_b, balance_low_b = balance_low_b + :balance_low_b where name = :name",table_name)),
            Some((&"Joe", 60, 55554598)),
            Addition("balance", enough_big_number as u128), true);
    }

    #[test]
    fn insert_fails_update_succeeds_with_overflow_for_subtraction() {
        let enough_big_number = BigIntDivider::reconstitute(-48795846112, 9223372036854775797);
        precise_upsert_or_update_assertion(
            "insert_fails_update_succeeds_with_overflow_for_subtraction",
            "insert into test_table (name, balance_high_b, balance_low_b) values (:name, :balance_high_b, :balance_low_b) on conflict (name) do",
            Some(|table_name |format!("update {} set balance_high_b = balance_high_b + :balance_high_b, balance_low_b = balance_low_b + :balance_low_b where name = :name",table_name)),
            Some((&"Joe", -5, 2233333)),
            Subtraction("balance", enough_big_number.abs() as u128), true);
    }

    #[test]
    fn update_alone_works_also_for_transaction_instead_of_connection() {
        let wei_change = Addition("balance", 255);
        let act = |conn: &mut dyn ConnectionWrapper, subject: &BigIntDbProcessor<DummyDao>| {
            let tx = conn.transaction().unwrap();

            let result = subject.execute(
                Either::Right(&tx),
                BigIntSqlConfig::new(
                                "update test_table set balance_high_b = balance_high_b + :balance_high_b, balance_low_b = balance_low_b + :balance_low_b where name = :name",
                                None,
                                SQLParamsBuilder::default()
                                    .key("name", ":name", &"Joe")
                                    .wei_change(wei_change.clone())
                                    .build(),
                            ),
            );
            tx.commit().unwrap();
            result
        };

        precise_upsert_or_update_assertion_test_environment(
            "update_alone_works_also_for_transaction_instead_of_connection",
            Some((&"Joe", 47, 598745133)),
            &wei_change,
            false,
            act,
        )
    }

    #[test]
    fn select_stm_in_update_with_overflow_gets_also_well_along_numeric_key_value_and_different_table_and_substitution_param_name(
    ) {
        let conn = create_new_empty_db(
            "big_int_db_processor",
            "select_stm_in_update_with_overflow_gets_also_well_along_numeric_key_value_and_different_table_and_substitution_param_name"
        );
        let conn = ConnectionWrapperReal::new(conn);
        let mut stm = conn.prepare("create table test_table \
        (family_members_count int primary key, costs_per_month_per_district_high_b int not null, costs_per_month_per_district_low_b int not null)").unwrap();
        stm.execute([]).unwrap();
        let mut stm = conn.prepare("insert into test_table \
        (family_members_count, costs_per_month_per_district_high_b, costs_per_month_per_district_low_b) values (4,4578,5468956)").unwrap();
        stm.execute([]).unwrap();
        let balance_change = Addition("costs_per_month_per_district", 50000);
        let update_config = BigIntSqlConfig::new(
            "update test_table set costs_per_month_per_district_high_b = costs_per_month_per_district_high_b + :costs_per_month_per_district_high_b,\
             costs_per_month_per_district_low_b = costs_per_month_per_district_low_b + :costs_per_month_per_district_low_b where family_members_count = :members_count",
            None,
            SQLParamsBuilder::default()
                .wei_change(balance_change)
                .key("family_members_count", ":members_count", &4)
                .build(),
        );

        let result = BigIntDbProcessor::<DummyDao>::new()
            .update_threatened_by_overflow(Either::Left(&conn), update_config);

        assert_eq!(result, Ok(()));
        let (high_bytes_added, low_bytes_added) = BigIntDivider::deconstruct(50000);
        conn.prepare("select * from test_table")
            .unwrap()
            .query_row([], |row| {
                let member_count = row.get::<usize, i64>(0).unwrap();
                let high_bytes = row.get::<usize, i64>(1).unwrap();
                let low_bytes = row.get::<usize, i64>(2).unwrap();
                assert_eq!(member_count, 4);
                //the added 1 seems wrong, but we're exercising code intended
                //specially for dealing with overflow and the addition is automated (even though unreasonable in this case)
                assert_eq!(high_bytes, 4578 + high_bytes_added + 1);
                assert_eq!(low_bytes, 5468956 + low_bytes_added);
                Ok(())
            })
            .unwrap();
    }

    #[test]
    fn insert_failed_update_failed_too() {
        let conn = initiate_simple_connection_and_test_table(
            "big_int_db_processor",
            "insert_failed_update_failed_too",
        );
        insert_single_record(conn.as_ref(), [&"Joe", &60, &5555]);
        let subject = BigIntDbProcessor::<DummyDao>::new();
        let balance_change = Addition("balance", 5555);
        let config = BigIntSqlConfig::new(
            "insert into test_table (name, balance_high_b, balance_low_b) values (:name,:balance_high_b,:balance_low_b) on conflict (name) do",
            Some(|table_name|format!("update {} set balance_high_b = balance_high_b + :balance_high_b, balance_low_b = balance_low_b + :whatever where name = :name",table_name)),
                SQLParamsBuilder::default()
                    .key("name", ":name", &"Joe")
                    .wei_change(balance_change)
                    .build(),
            );

        let result = subject.execute(Left(conn.as_ref()), config);

        assert_eq!(
            result,
            Err(BigIntDbError(
                //sadly, I wasn't able to get a nicer error case with a more obvious relation to the tested requirements
                "Wei change: error after invalid upsert command for test_table of 5555 Wei to Joe with error 'NOT NULL constraint failed: test_table.balance_low_b'"
                    .to_string()
            ))
        );
    }

    #[test]
    fn insert_handles_unspecific_failures() {
        let conn = initiate_simple_connection_and_test_table(
            "big_int_db_processor",
            "insert_handles_unspecific_failures",
        );
        let subject = BigIntDbProcessor::<DummyDao>::new();
        let balance_change = Addition("balance", 4879898145125);
        let config = BigIntSqlConfig::new(
            "insert into test_table (name,balance_high_b,balance_low_b) values (:name,:balance_a,:balance_b) on conflict (name) do",
            Some(|table_name |format!("update {} set balance_high_b = balance_high_b + 5, balance_low_b = balance_low_b + 10 where name = :name",table_name)),
            SQLParamsBuilder::default()
                .key("name", ":name", &"Joe")
                .wei_change(balance_change)
                .build(),
        );

        let result = subject.execute(Left(conn.as_ref()), config);

        assert_eq!(
            result,
            Err(BigIntDbError(
                "Wei change: error after invalid upsert command for test_table of 4879898145125 \
                Wei to Joe with error 'Invalid parameter name: :balance_high_b'"
                    .to_string()
            ))
        );
    }

    #[test]
    fn update_with_overflow_handles_unspecific_error() {
        let conn = initiate_simple_connection_and_test_table(
            "big_int_db_processor",
            "update_with_overflow_handles_unspecific_error",
        );
        let balance_change = Addition("balance", 100);
        let update_config = BigIntSqlConfig::new(
            "this can be whatever because the test fails already on the select stm",
            None,
            SQLParamsBuilder::default()
                .wei_change(balance_change)
                .key("name", ":name", &"Joe")
                .build(),
        );

        let result = BigIntDbProcessor::<DummyDao>::new()
            .update_threatened_by_overflow(Either::Left(conn.as_ref()), update_config);

        //this kind of error is impossible in the real use case but is easiest regarding an arrangement of the test
        assert_eq!(result, Err(BigIntDbError("Updating balance for test_table of 100 Wei to Joe with error 'Query returned no rows'".to_string())));
    }

    #[test]
    #[should_panic(
        expected = "unreachable code: This code was written to handle one changed row a time, not 2"
    )]
    fn update_with_overflow_is_designed_to_handle_one_record_a_time() {
        let conn = initiate_simple_connection_and_test_table(
            "big_int_db_processor",
            "update_with_overflow_is_designed_to_handle_one_record_a_time",
        );
        insert_single_record(&*conn, [&"Joe", &60, &5555]);
        insert_single_record(&*conn, [&"Jodie", &77, &0]);
        let balance_change = Addition("balance", 100);
        let update_config = BigIntSqlConfig::new(
            "update test_table set balance_high_b = balance_high_b + :balance_high_b, balance_low_b = balance_low_b + :balance_low_b where name in(:name,'Jodie')",
            None,
            SQLParamsBuilder::default()
                .wei_change(balance_change)
                .key( "name", ":name",&"Joe")
                .build()
        );

        let _ = BigIntDbProcessor::<DummyDao>::new()
            .update_threatened_by_overflow(Either::Left(conn.as_ref()), update_config);
    }

    #[test]
    fn update_with_overflow_handles_error_from_executing_the_initial_select_stm() {
        let conn = initiate_simple_connection_and_test_table(
            "big_int_db_processor",
            "update_with_overflow_handles_error_from_executing_the_initial_select_stm",
        );
        conn.prepare("alter table test_table drop column balance_low_b")
            .unwrap()
            .execute([])
            .unwrap();
        conn.prepare("alter table test_table add column balance_low_b text")
            .unwrap()
            .execute([])
            .unwrap();
        insert_single_record(&*conn, [&"Joe", &60, &"bad type"]);
        let balance_change = Addition("balance", 100);
        let update_config = BigIntSqlConfig::new(
            "this can be whatever because the test fails already on the select stm",
            None,
            SQLParamsBuilder::default()
                .wei_change(balance_change)
                .key("name", ":name", &"Joe")
                .build(),
        );

        let result = BigIntDbProcessor::<DummyDao>::new()
            .update_threatened_by_overflow(Either::Left(conn.as_ref()), update_config);

        assert_eq!(
            result,
            Err(BigIntDbError(
                "Updating balance for test_table of 100 Wei to Joe with error \
        'Invalid column type Text at index: 0, name: balance_low_b'"
                    .to_string()
            ))
        );
    }

    #[test]
    fn deconstruct_works_for_small_number() {
        let result = BigIntDivider::deconstruct(45879);

        assert_eq!(result, (0, 45879))
    }

    #[test]
    fn deconstruct_works_for_big_number() {
        let result = BigIntDivider::deconstruct(i64::MAX as i128 + 33333);

        assert_eq!(result, (1, 33332))
    }

    #[test]
    fn deconstruct_works_for_huge_number() {
        let result = BigIntDivider::deconstruct(0x1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF);
        //this is the maximum: -42535295865117307932_921825928_971026431 Wei ... 42535295865117307932 MASQs
        //there are fewer than 1 billion of units available on the market

        assert_eq!(result, (4611686018427387903, i64::MAX))
    }

    #[test]
    #[should_panic(
        expected = "Too big positive integer to be divided: 0x20000000000000000000000000000000"
    )]
    fn deconstruct_has_its_limits_up() {
        let _ = BigIntDivider::deconstruct(0x1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF + 1);
    }

    #[test]
    fn deconstruct_works_for_zero_plus_one() {
        let result = BigIntDivider::deconstruct(1);

        assert_eq!(result, (0, 1))
    }

    #[test]
    fn deconstruct_works_for_zero() {
        let result = BigIntDivider::deconstruct(0);

        assert_eq!(result, (0, 0))
    }

    #[test]
    fn deconstruct_works_for_zero_minus_one() {
        let result = BigIntDivider::deconstruct(-1);

        assert_eq!(result, (-1, i64::MAX))
    }

    #[test]
    fn deconstruct_works_for_small_negative_number() {
        let result = BigIntDivider::deconstruct(-454887);

        assert_eq!(result, (-1, 9223372036854320921))
    }

    #[test]
    fn deconstruct_works_for_big_negative_number() {
        let result = BigIntDivider::deconstruct(i64::MIN as i128 - 4444);

        assert_eq!(result, (-2, 9223372036854771364))
    }

    #[test]
    fn deconstruct_works_for_huge_negative_number() {
        let result = BigIntDivider::deconstruct(-0x40000000000000000000000000000000);
        //this is the minimum: -85070591730234615865_843651857_942052864 Wei ... -85070591730234615865 MASQs
        //there are fewer than 1 billion of units available on the market

        assert_eq!(result, (-9223372036854775808, 0))
    }

    #[test]
    #[should_panic(
        expected = "Too big negative integer to be divided: -0xBFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
    )]
    fn deconstruct_has_its_limits_down() {
        let _ = BigIntDivider::deconstruct(-0x40000000000000000000000000000000 - 1);
        //at this number we lose the sign so it's the minimal possible value with which we can go down
    }

    #[test]
    fn reconstitute_works_for_small_number() {
        let result = BigIntDivider::reconstitute(0, 45879);

        assert_eq!(result, 45879)
    }

    #[test]
    fn reconstitute_works_for_big_number() {
        let result = BigIntDivider::reconstitute(1, 33332);

        assert_eq!(result, i64::MAX as i128 + 33333)
    }

    #[test]
    fn reconstitute_works_for_huge_number() {
        let result = BigIntDivider::reconstitute(2305843009213693951, i64::MAX);

        assert_eq!(result, 0x0FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF)
    }

    #[test]
    fn reconstitute_works_for_small_negative_number() {
        let result = BigIntDivider::reconstitute(-1, 9223372036854320921);

        assert_eq!(result, -454887)
    }

    #[test]
    fn reconstitute_works_for_big_negative_number() {
        let result = BigIntDivider::reconstitute(-2, 9223372036854771364);

        assert_eq!(result, i64::MIN as i128 - 4444)
    }

    #[test]
    fn reconstitute_works_for_huge_negative_number() {
        let result = BigIntDivider::reconstitute(-9223372036854775808, 0);

        assert_eq!(result, -0x40000000000000000000000000000000)
    }

    #[test]
    fn divided_integers_can_be_ordered() {
        let a = i64::MAX as i128 * 23;
        let b = i64::MAX as i128 + 1;
        let c = i64::MAX as i128;
        let d = (i64::MAX - 1) as i128;
        let e = 5432;
        let f = 0;
        let g = -4567;
        let h = (i64::MIN + 1) as i128;
        let i = i64::MIN as i128;
        let j = i64::MIN as i128 - 1;
        let k = i64::MIN as i128 * 32;
        let vec = vec![b, c, d, e, f, g, h, i, j, k];

        let _ = vec.into_iter().enumerate().fold(
            a,
            |previous, current: (usize, i128)| {
                let (previous_high_b, previous_low_b) = BigIntDivider::deconstruct(previous);
                let (current_high_b, current_low_b) = BigIntDivider::deconstruct(current.1);
                assert!(
                    (previous_high_b > current_high_b) || (previous_high_b == current_high_b && previous_low_b >= current_low_b) ,
                    "previous_high_b: {}, current_high_b: {} and previous_low_b: {}, current_low_b: {} for {} and {} which is idx {}",
                    previous_high_b,
                    current_high_b,
                    previous_low_b,
                    current_low_b,
                    BigIntDivider::reconstitute(previous_high_b, previous_low_b),
                    BigIntDivider::reconstitute(current_high_b, current_low_b),
                    current.0
                );
                current.1
            },
        );
    }

    fn create_test_table_and_run_register_deconstruct_for_sqlite_connection(
        test_name: &str,
    ) -> Connection {
        let conn = create_new_empty_db("big_int_db_processor", test_name);
        BigIntDivider::register_deconstruct_for_sqlite_connection(&conn).unwrap();
        conn.execute("create table test_table (computed_high_bytes int, computed_low_bytes int, database_parameter int not null)",[]).unwrap();
        conn
    }

    #[test]
    fn register_deconstruct_for_sqlite_connection_works() {
        let conn = create_test_table_and_run_register_deconstruct_for_sqlite_connection(
            "register_deconstruct_for_sqlite_connection_works",
        );

        let database_value_1: i64 = 12222;
        let database_value_2: i64 = 23333444;
        let database_value_3: i64 = 5555;
        conn.execute(
            "insert into test_table (database_parameter) values (?),(?),(?)",
            &[&database_value_1, &database_value_2, &database_value_3],
        )
        .unwrap();
        let arbitrary_constant = 111222333444_i64;
        conn.execute(
            "update test_table set \
        computed_high_bytes = biginthigh(:my_constant, -3.143 * database_parameter),\
        computed_low_bytes = bigintlow(:my_constant, -3.143 * database_parameter)",
            &[(":my_constant", &arbitrary_constant)],
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
                    arbitrary_constant as i128 * 1_000_000_000
                        + (-3.143 * database_value_1 as f64) as i128
                ),
                BigIntDivider::deconstruct(
                    arbitrary_constant as i128 * 1_000_000_000
                        + (-3.143 * database_value_2 as f64) as i128
                ),
                BigIntDivider::deconstruct(
                    arbitrary_constant as i128 * 1_000_000_000
                        + (-3.143 * database_value_3 as f64) as i128
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
        let conn = create_test_table_and_run_register_deconstruct_for_sqlite_connection(
            "register_deconstruct_for_sqlite_connection_returns_error_at_setting_the_first_function",
        );

        let result = conn
            .execute(
                "insert into test_table (computed_high_bytes) values (biginthigh('hello',-45.666))",
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
                    "Error from biginthigh: First argument takes only i64, not: Text([104, 101, 108, 108, 111])"
                        .to_string()
                )
            )
        )
    }

    #[test]
    fn register_deconstruct_for_sqlite_connection_returns_error_at_setting_the_second_function() {
        let conn = create_test_table_and_run_register_deconstruct_for_sqlite_connection(
            "register_deconstruct_for_sqlite_connection_returns_error_at_setting_the_second_function",
        );

        let result = conn
            .execute(
                "insert into test_table (computed_high_bytes) values (bigintlow('bye',-45.666))",
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
                    "Error from bigintlow: First argument takes only i64, not: Text([98, 121, 101])".to_string()
                )
            )
        )
    }

    #[test]
    fn our_sqlite_functions_are_specialized_and_thus_should_not_take_positive_number_for_the_second_parameter(
    ) {
        let conn = create_test_table_and_run_register_deconstruct_for_sqlite_connection(
            "our_sqlite_functions_are_specialized_and_thus_should_not_take_positive_number_for_the_second_parameter"
        );
        let error_invoker = |bytes_type: &str| {
            let sql = format!(
                "insert into test_table (computed_{0}_bytes) values (bigint{0}(45656,5656.23))",
                bytes_type
            );
            conn.execute(&sql, []).unwrap_err()
        };

        let high_bytes_error = error_invoker("high");
        let low_bytes_error = error_invoker("low");

        assert_eq!(high_bytes_error,
                   SqliteFailure(
                       rusqlite::ffi::Error{ code: ErrorCode::Unknown, extended_code: 1 },
                       Some("Error from biginthigh: None negative slope, while designed only for use with negative one: 5656.23".to_string())
                   )
        );
        assert_eq!(low_bytes_error,
                   SqliteFailure(
                       rusqlite::ffi::Error{ code: ErrorCode::Unknown, extended_code: 1 },
                       Some("Error from bigintlow: None negative slope, while designed only for use with negative one: 5656.23".to_string())
                   )
        );
    }

    #[test]
    fn other_than_real_num_argument_error() {
        let conn = create_test_table_and_run_register_deconstruct_for_sqlite_connection(
            "other_than_real_num_argument_error",
        );

        let result = conn
            .execute(
                "insert into test_table (computed_high_bytes) values (bigintlow(15464646,7866))",
                [],
            )
            .unwrap_err();

        assert_eq!(
            result,
            SqliteFailure(
                rusqlite::ffi::Error{ code: ErrorCode::Unknown, extended_code: 1 },
                Some("Error from bigintlow: Second argument takes only a real number, not: Integer(7866)".to_string()
            ))
        )
    }

    #[test]
    fn first_fn_returns_internal_error_from_create_scalar_function() {
        let conn = create_test_table_and_run_register_deconstruct_for_sqlite_connection(
            "first_fn_returns_internal_error_from_create_scalar_function",
        );

        let result =
            BigIntDivider::guts_of_register_deconstruct(&conn, "badly\u{0000}named", "bigintlow")
                .unwrap_err();

        //I couldn't assert on an exact fit because the error carries unstable code
        assert_eq!(
            result.to_string(),
            "nul byte found in provided data at position: 5".to_string()
        )
    }

    #[test]
    fn second_fn_returns_internal_error_from_create_scalar_function() {
        let conn = create_test_table_and_run_register_deconstruct_for_sqlite_connection(
            "second_fn_returns_internal_error_from_create_scalar_function",
        );

        let result = BigIntDivider::guts_of_register_deconstruct(
            &conn,
            "biginthigh",
            "also\u{0000}badlynamed",
        )
        .unwrap_err();

        //I couldn't assert on an exact fit because the error carries unstable code
        assert_eq!(
            result.to_string(),
            "nul byte found in provided data at position: 4".to_string()
        )
    }
}
