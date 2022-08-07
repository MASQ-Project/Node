// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::big_int_db_processor::ByteOrder::{High, Low};
use crate::accountant::big_int_db_processor::WeiChange::{Addition, Subtraction};
use crate::accountant::payable_dao::PayableDaoError;
use crate::accountant::receivable_dao::ReceivableDaoError;
use crate::accountant::{checked_conversion, politely_checked_conversion};
use crate::database::connection_wrapper::ConnectionWrapper;
use crate::sub_lib::wallet::Wallet;
use itertools::{chain, Either};
use masq_lib::utils::ExpectValue;
use nix::libc::iovec;
use rusqlite::types::ToSqlOutput;
use rusqlite::ErrorCode::ConstraintViolation;
use rusqlite::{params_from_iter, Error, Statement, ToSql, Transaction};
use std::fmt::{write, Debug, Display, Formatter};
use std::iter::{once, Chain, Map};
use std::marker::PhantomData;
use std::ops::Neg;
use std::os::raw::c_int;
use std::slice::Iter;

//TODO it doesn't have to be connected anymore...update and insert_update configs can stand separately
pub trait BigIntSQLProcessor<T: 'static + DAOTableIdentifier>: Send + Debug {
    fn execute<'a>(
        &self,
        conn: &dyn ConnectionWrapper,
        config: BigIntSqlConfig<'a, T>,
    ) -> Result<(), BigIntDbError>;

    fn update_threatened_by_overflow<'a>(
        &self,
        conn: Either<&dyn ConnectionWrapper, &Transaction>,
        config: BigIntSqlConfig<'a, T>,
    ) -> Result<(), BigIntDbError>;
}

#[derive(Debug)]
pub struct BigIntDbProcessorReal<T: Debug + DAOTableIdentifier + Send + 'static> {
    phantom: PhantomData<T>,
}

impl<T: DAOTableIdentifier + Debug + Send + 'static> BigIntSQLProcessor<T>
    for BigIntDbProcessorReal<T>
{
    fn execute<'a>(
        &self,
        conn: &dyn ConnectionWrapper,
        config: BigIntSqlConfig<'a, T>,
    ) -> Result<(), BigIntDbError> {
        let main_sql = config.construct_main_sql();
        let mut stm = conn.prepare(&main_sql).expect("internal rusqlite error");
        let params = config
            .params
            .pure_rusqlite_params_uncorrected()
            .collect::<Vec<(&str, &dyn ToSql)>>();
        match stm.execute(params.as_slice()) {
            Ok(_) => Ok(()),
            Err(e)
                if match e {
                    Error::SqliteFailure(e, _) => {
                        //SQLITE_CONSTRAINT_DATATYPE,
                        //the moment of Sqlite trying to store the number as REAL in a strict INT column
                        e.extended_code == c_int::from(3091)
                    }
                    _ => false,
                } =>
            {
                self.update_threatened_by_overflow(Either::Left(conn), config)
            }
            Err(e) => Err(BigIntDbError(format!(
                "Wei change: error after invalid {} command for {} of {} Wei to {} with error '{}'",
                config.determine_command(),
                T::table_name(),
                config.balance_change(), //TODO this is unnecessary? Can we have such a big number ..?
                config.key_info().1,
                e
            ))),
        }
    }

    fn update_threatened_by_overflow<'a>(
        &self,
        form_of_conn: Either<&dyn ConnectionWrapper, &Transaction>,
        config: BigIntSqlConfig<'a, T>,
    ) -> Result<(), BigIntDbError> {
        let select_sql = config.select_sql();
        let mut select_stm = Self::prepare_statement(form_of_conn, &select_sql);
        match select_stm.query_row([], |row| {
            let high_bytes_result = row.get::<usize,i64>(0);
            let low_bytes_result = row.get::<usize,i64>(1);
            match (high_bytes_result,low_bytes_result) {
                (Ok(high_bytes), Ok(low_bytes)) => {
                    let wei_change_params = &config.params.wei_change_params;
                    let high_bytes_correction = wei_change_params[0].1 + 1;
                    let low_bytes_correction = ((low_bytes as i128 + wei_change_params[1].1 as i128) & 0x7FFFFFFFFFFFFFFF) as i64 - low_bytes; //TODO test this thoroughly for negativeness
                    eprintln!("low bytes corrected {}", low_bytes_correction);
                    let update_sql = config.prepare_update_sql(form_of_conn);
                    let mut update_stm = Self::prepare_statement(form_of_conn,&update_sql);
                    let wei_update_array = [(wei_change_params[0].0.as_str(), high_bytes_correction),(wei_change_params[1].0.as_str(), low_bytes_correction)];
                    eprintln!("byte params corrected {:?}", wei_update_array);
                    let params = config.params.pure_rusqlite_params_corrected(&wei_update_array).collect::<Vec<_>>();
                    if update_stm.execute(&*params)
                        .expect("correction-for update sql has wrong logic") == 1 {
                        Ok(())
                    } else{
                        todo!()
                    }
                }
                (e1,e2) => todo!(), //Err(e),
            }
        }) {
            Ok(()) => Ok(()),
            Err(e) => todo!()
            //     Err(BlobInsertUpdateError(format!(
            //     "Updating balance for {} of {} Wei to {} with error '{}'",
            //     T::table_name(),
            //     balance_change,
            //     params.params[key_idx].1,
            //     e
            // ))),
        }
    }
}

impl<T: Debug + DAOTableIdentifier + Send> BigIntDbProcessorReal<T> {
    pub fn new() -> BigIntDbProcessorReal<T> {
        Self {
            phantom: Default::default(),
        }
    }
}

impl<T: Debug + DAOTableIdentifier + Send> BigIntDbProcessorReal<T> {
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

impl<'a, T: DAOTableIdentifier + Debug + Send + 'static> BigIntSqlConfig<'a, T> {
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
                todo!()
            }
        )
    }

    fn prepare_update_sql(
        &self,
        form_of_conn: Either<&'a dyn ConnectionWrapper, &'a Transaction>,
    ) -> String {
        if let Some(assembler) = self.update_clause_opt {
            assembler(&T::table_name())
        } else {
            todo!()
        }
    }

    fn select_sql(&self) -> String {
        let key_info = self.key_info();
        format!(
            "select {}, {} from {} where {} = '{}'",
            &self.params.wei_change_params[0].0[1..],
            &self.params.wei_change_params[1].0[1..],
            T::table_name(),
            &key_info.0[1..],
            key_info.1
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
        self.main_sql
            .chars()
            .skip_while(|char| char.is_whitespace())
            .take_while(|char| !char.is_whitespace())
            .collect()
    }

    #[cfg(test)]
    pub fn capture_sqls(&self) -> (String, String) {
        (self.construct_main_sql(), self.select_sql())
    }
}

pub trait ExtendedParamsMarker: ToSql + Display {}

//TODO delete this
macro_rules! blank_impl_of_extended_params_marker{
    ($($implementer: ty),+) => {
        $(impl ExtendedParamsMarker for $implementer {})+
    }
}

blank_impl_of_extended_params_marker!(i64, &str, Wallet);

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

    pub fn other(
        mut self,
        mut params: Vec<(&'a str, &'a (dyn ExtendedParamsMarker + 'a))>,
    ) -> Self {
        self.other_params = params;
        self
    }

    pub fn build(mut self) -> SQLParams<'a> {
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
        self.pure_rusqlite_params(Self::transform_wei_change_params(&self.wei_change_params))
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

    //TODO maybe inline these
    fn transform_wei_change_params(
        wei_change: &[(String, i64); 2],
    ) -> impl Iterator<Item = (&str, &dyn ToSql)> {
        wei_change
            .iter()
            .map(|(name, value)| (name.as_str(), value as &dyn ToSql))
    }
}

pub trait DAOTableIdentifier {
    fn table_name() -> String;
}

//TODO finalize this idea
#[derive(Debug, PartialEq)]
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

/////////////////////////////////////////////////////////////////////////////////////////////////

pub struct DatabaseBigIntegerHandler {}

impl DatabaseBigIntegerHandler {
    pub fn new() -> Self {
        todo!()
    }

    fn update(&self) -> Result<(), String> {
        todo!()
    }

    fn upsert(&self) -> Result<(), String> {
        todo!()
    }
}

pub struct BigIntDivider {}

impl BigIntDivider {
    pub fn new() -> Self {
        todo!()
    }

    //TODO maybe write this also for u128
    pub fn deconstruct(num: i128) -> (i64, i64) {
        let low_bits = (num & 0x7FFFFFFFFFFFFFFFi128) as i64;
        let high_bits = (num >> 63) as i64;
        if num.is_positive() && (high_bits.abs() as u64 & 0xC000000000000000u64) > 0 {
            panic!("Too big positive integer to be divided: {:#X}", num)
        }
        if num < -0x40000000000000000000000000000000 {
            panic!("Too big negative integer to be divided: -{:#X}", num)
        }
        (high_bits, low_bits)
    }

    //TODO maybe write this also for u128
    pub fn reconstitute(high_bytes: i64, low_bytes: i64) -> i128 {
        let low_bytes = low_bytes as i128;
        let high_bytes = high_bytes as i128;
        (high_bytes << 63) | low_bytes
    }

    pub fn reconstitute_unsigned(high_bytes: i64, low_bytes: i64) -> u128 {
        checked_conversion::<i128, u128>(Self::reconstitute(high_bytes, low_bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accountant::big_int_db_processor::WeiChange::Addition;
    use crate::accountant::payable_dao::PayableDaoReal;
    use crate::database::connection_wrapper::{ConnectionWrapper, ConnectionWrapperReal};
    use crate::database::db_initializer::{DbInitializer, DbInitializerReal};
    use crate::database::db_migrations::MigratorConfig;
    use crate::test_utils::make_wallet;
    use itertools::{Either, Itertools};
    use masq_lib::test_utils::utils::ensure_node_home_directory_exists;
    use rusqlite::types::ToSqlOutput;
    use rusqlite::{named_params, params, Connection, OpenFlags, ToSql};

    fn convert_params_to_debuggable_values<'a>(
        standard_params: Vec<(&'a str, &'a dyn ToSql)>,
    ) -> Vec<(&'a str, ToSqlOutput)> {
        let mut vec = standard_params
            .into_iter()
            .map(|(name, value)| (name, value.to_sql().unwrap()))
            .collect_vec();
        vec.sort_by(|(name_a, _), (name_b, _)| name_a.cmp(name_b));
        vec
    }

    #[derive(Debug)]
    struct DummyDao {}

    impl DAOTableIdentifier for DummyDao {
        fn table_name() -> String {
            String::from("test_table")
        }
    }
    //
    // #[test]
    // fn finalize_update_params_for_update_config_works() {
    //     let balance_change = BalanceChange::new_addition(5555);
    //     let subject = BigIntUpdateConfig {
    //         update_sql: "blah",
    //         params: SQLExtendedParams::new(vec![
    //             (":something", &152_i64),
    //             (":balance", &balance_change),
    //             (":something_else", &"foooo"),
    //         ]),
    //     };
    //
    //     finalize_update_params_assertion::<PayableDaoReal>(&subject)
    // }
    //
    // #[test]
    // fn finalize_update_params_for_insert_update_config_works() {
    //     let balance_change = BalanceChange::new_addition(5555);
    //     let subject = BigIntInsertUpdateConfig {
    //         insert_update_sql: "blah1",
    //         update_sql: "blah2",
    //         params: SQLExtendedParams::new(vec![
    //             (":something", &152_i64),
    //             (":balance", &balance_change),
    //             (":something_else", &"foooo"),
    //         ]),
    //     };
    //
    //     finalize_update_params_assertion::<PayableDaoReal>(&subject)
    // }
    //
    // fn finalize_update_params_assertion<'a, T: DAOTableIdentifier>(
    //     subject: &'a dyn UpdateConfiguration<'a, T>,
    // ) {
    //     let updated_balance = 456789;
    //     let balance_change = BalanceChange::new_addition(updated_balance as u128);
    //
    //     let result = subject.finalize_update_params(
    //         &updated_balance,
    //         subject.update_params().pure_rusqlite_params(),
    //     );
    //
    //     let expected_params: Vec<(&str, &dyn ToSql)> = vec![
    //         (":something", &152_i64),
    //         (":updated_balance", &balance_change),
    //         (":something_else", &"foooo"),
    //     ];
    //     let expected_assertable = convert_params_to_debuggable_values(expected_params);
    //     let result_assertable = convert_params_to_debuggable_values(result);
    //     assert_eq!(result_assertable, expected_assertable)
    // }

    // #[test]
    // fn fetch_balance_change_works() {
    //     let balance_change = WeiChange::new_addition(5021);
    //     let params = SQLParams(
    //         vec![
    //             (":something", &"yo-yo"),
    //             (":balance", &balance_change),
    //             (":something_else", &55_i64),
    //         ]);
    //
    //     let result = params.fetch_balance_change();
    //
    //     assert_eq!(result, 5021)
    // }

    // #[test]
    // fn fetch_key_works() {
    //     let wallet = make_wallet("blah");
    //     let key_holder = KeyHolder::new(&wallet, "wallet");
    //     let params = SQLParams(
    //         vec![
    //             (":something", &"yo-yo"),
    //             (":wonderful_wallet", &key_holder),
    //             (":something_else", &55_i64),
    //         ]
    //     );
    //
    //     let result = params.fetch_key_specification();
    //
    //     let (in_table_name, sql_param_name, idx) = result;
    //     assert_eq!(in_table_name, "wallet".to_string());
    //     assert_eq!(sql_param_name, ":wonderful_wallet".to_string());
    //     assert_eq!(idx, 1)
    // }

    // #[test]
    // #[should_panic(expected = "only one key parameter is allowed")]
    // fn we_support_only_one_key_a_time() {
    //     let wallet = make_wallet("blah");
    //     let key_holder_1 = KeyHolder::new(&wallet, "param_name");
    //     let key_holder_2 = KeyHolder::new(&66_i64, "param_name_2");
    //     let params = SQLParams(vec![
    //             (":something", &"yo-yo"),
    //             (":wonderful_wallet", &key_holder_1),
    //             (":something_else", &key_holder_2),
    //         ],
    //     );
    //
    //     let _ = params.fetch_key_specification();
    // }
    //
    // #[test]
    // #[should_panic(expected = "missing key parameter; broken")]
    // fn no_key_is_an_issue() {
    //     let wallet = make_wallet("abc");
    //     let subject = SQLParams(vec![
    //             (":something", &"yo-yo"),
    //             (":wonderful_wallet", &wallet),
    //             (":something_else", &699_i64),
    //         ]);
    //
    //     let _ = subject.fetch_key_specification();
    // }
    //
    // #[test]
    // #[should_panic(expected = "missing parameter of the change in balance; broken")]
    // fn no_balance_change_is_an_issue() {
    //     let subject = SQLParams(vec![
    //         (":something", &"yo-yo"),
    //         (":something_else", &55_i64)
    //     ]);
    //
    //     let _ = subject.fetch_balance_change();
    // }
    //
    // #[test]
    // #[should_panic(expected = "only one parameter of changed balance is allowed a time")]
    // fn we_support_only_one_change_balance_param() {
    //     let balance_change_1 = WeiChange { change: 458 };
    //     let balance_change_2 = WeiChange { change: -5000000 };
    //     let params = SQLParams(vec![
    //             (":something", &"yo-yo"),
    //             (":my_fortune", &balance_change_1),
    //             (":my_poverty", &balance_change_2),
    //         ]);
    //
    //     let _ = params.fetch_balance_change();
    // }

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

    // #[test]
    // fn display_for_balance_change_works() {
    //     let subtraction = WeiChange::new_subtraction(100, "balance");
    //     let addition = WeiChange::new_addition(50, "balance");
    //
    //     assert_eq!(subtraction.to_string(), "-100".to_string());
    //     assert_eq!(addition.to_string(), "50".to_string())
    // }
    //
    // #[test]
    // fn display_for_key_param_holder_works() {
    //     let wallet = make_wallet("booga");
    //     let key_holder_with_wallet = KeyHolder::new(&wallet, "wallet_address", ":wallet");
    //     let rowid = 56_i64;
    //     let key_holder_with_rowid = KeyHolder::new(&rowid, "pending_payable_rowid", ":rowid");
    //
    //     assert_eq!(key_holder_with_wallet.to_string(), wallet.to_string());
    //     assert_eq!(key_holder_with_rowid.to_string(), rowid.to_string())
    // }
    //
    // #[test]
    // fn to_sql_for_param_key_holder_works() {
    //     let value_1 = make_wallet("boooga");
    //     let value_2 = 235_i64;
    //     let key_holder_1 = KeyHolder::new(&value_1, "random_wallet", ":wallet");
    //     let key_holder_2 = KeyHolder::new(&value_2, "random_parameter", ":parameter");
    //
    //     let result_1 = key_holder_1.to_sql();
    //     let result_2 = key_holder_2.to_sql();
    //
    //     assert_eq!(result_1, value_1.to_sql());
    //     assert_eq!(result_2, value_2.to_sql())
    // }
    //
    // #[test]
    // fn get_key_for_non_key_params_is_always_none() {
    //     assert_eq!("blah".key_name_opt().is_none(), true);
    //     assert_eq!(make_wallet("some wallet").key_name_opt().is_none(), true);
    //     assert_eq!(56_i64.key_name_opt().is_none(), true)
    // }
    //
    // #[test]
    // fn getter_for_key_param_holder_returns_something_reasonable() {
    //     //notice that i64 alone returns None but inside this holder it is Some()...
    //     let key_object = KeyHolder::new(&8989_i64, "balance", ":balance").key_name_opt();
    //
    //     let in_table_param_name = key_object.unwrap();
    //     assert_eq!(in_table_param_name, "balance".to_string());
    // }

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
    fn determine_command_works_for_insert() {
        let subject: BigIntSqlConfig<'_, DummyDao> = BigIntSqlConfig {
            main_sql: "insert into table (a,b) values ('a','b')",
            update_clause_opt: None,
            params: make_empty_sql_params(),
            phantom: Default::default(),
        };

        let result = subject.determine_command();

        assert_eq!(result, "insert".to_string())
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
    fn determine_command_works_for_any_other_case() {
        let subject: BigIntSqlConfig<'_, DummyDao> = BigIntSqlConfig {
            main_sql: "other sql command",
            update_clause_opt: None,
            params: make_empty_sql_params(),
            phantom: Default::default(),
        };

        let result = subject.determine_command();

        assert_eq!(result, "other".to_string())
    }

    #[test]
    fn determine_command_allows_preceding_spaces() {
        let subject: BigIntSqlConfig<'_, DummyDao> = BigIntSqlConfig {
            main_sql: "  insert into table (a,b) values ('a','b')",
            update_clause_opt: None,
            params: make_empty_sql_params(),
            phantom: Default::default(),
        };

        let result = subject.determine_command();

        assert_eq!(result, "insert".to_string())
    }

    //TODO: update successful is missing

    #[test]
    fn update_handles_error_for_insert_update_config() {
        todo!("solve me ...by deleting???");
        // let wallet_address = "a11122";
        // let wallet_as_key = KeyParamHolder::new(&wallet_address, "wallet_address");
        // let conn = Connection::open_in_memory().unwrap();
        // conn.prepare(
        //     "create table payable
        //           ( wallet_address text primary key,
        //             balance blob not null,
        //             last_paid_timestamp integer not null,
        //             pending_payable_rowid integer null )",
        // )
        // .unwrap()
        // .execute([])
        // .unwrap();
        // let wrapped_conn = ConnectionWrapperReal::new(conn);
        // let balance_change = BalanceChange::new_addition(100);
        // let update_config = BigIntInsertUpdateConfig {
        //     insert_update_sql: "",
        //     params: SQLExtendedParams::new(vec![
        //         (":wallet", &wallet_as_key),
        //         (":balance", &balance_change),
        //     ]),
        // };
        //
        // let result = BlobInsertUpdateReal::<PayableDaoReal>::new()
        //     .update(Either::Left(&wrapped_conn), update_config);
        //
        // assert_eq!(result, Err(BlobInsertUpdateError("Updating balance for payable of 100 Wei to a11122 with error 'Query returned no rows'".to_string())));
    }

    #[test]
    fn update_handles_error_on_a_row_due_to_unfitting_data_types() {
        let wallet_address = "a11122";
        let path = ensure_node_home_directory_exists(
            "blob_utils",
            "update_handles_error_on_a_row_due_to_unfitting_data_types",
        );
        let conn = DbInitializerReal::default()
            .initialize(&path, true, MigratorConfig::test_default())
            .unwrap();
        let conn_ref = conn.as_ref();
        let params = named_params! {
            ":wallet":wallet_address,
            ":balance":"bubblebooo",
            ":last_time_stamp":"genesis",
            ":pending_payable_rowid":45_i64
        };
        let mut stm = conn.prepare("insert into payable (wallet_address, balance, last_paid_timestamp, pending_payable_rowid) values (:wallet,:balance,:last_time_stamp,:pending_payable_rowid)").unwrap();
        stm.execute(params).unwrap();
        let balance_change = Addition("balance", 100);
        let last_received_time_stamp_sec = 123_i64;
        let update_config = BigIntSqlConfig::new("update receivable set balance = :updated_balance, last_received_timestamp = :last_received where wallet_address = :wallet",
            None,
                                                 SQLParamsBuilder::default().other(vec![(":last_received", &last_received_time_stamp_sec)])
                .key( "wallet_address", ":wallet",&wallet_address).wei_change(balance_change).build());

        let result = BigIntDbProcessorReal::<PayableDaoReal>::new()
            .update_threatened_by_overflow(Either::Left(conn_ref), update_config);

        assert_eq!(result, Err(BigIntDbError("Updating balance for payable of 100 Wei to a11122 with error 'Invalid column type Text at index: 0, name: balance'".to_string())));
    }

    #[test]
    fn update_handles_error_of_bad_sql_params() {
        let wallet_address = "a11122";
        let path = ensure_node_home_directory_exists(
            "blob_utils",
            "update_handles_error_of_bad_sql_params",
        );
        let conn = DbInitializerReal::default()
            .initialize(&path, true, MigratorConfig::test_default())
            .unwrap();
        let conn_ref = conn.as_ref();
        let mut stm = conn_ref.prepare("insert into payable (wallet_address, balance_high_b, balance_low_b, last_paid_timestamp, pending_payable_rowid) values (?,?,?,strftime('%s','now'),null)").unwrap();
        stm.execute(params![wallet_address, 12, 45245]).unwrap();
        let balance_change = Addition("balance", 100);
        let last_received_time_stamp_sec = 123_i64;
        let update_config = BigIntSqlConfig::new("update receivable set balance = ?, last_received_timestamp = ? where wallet_address = ?",
            None,
            SQLParamsBuilder::default()
                        .other(vec![(":woodstock", &wallet_address), (":hendrix", &last_received_time_stamp_sec)])
                        .wei_change(balance_change) //:balance
                .key( "wallet_address", ":wallet",&wallet_address).build());

        let result = BigIntDbProcessorReal::<PayableDaoReal>::new()
            .update_threatened_by_overflow(Either::Left(conn_ref), update_config);

        assert_eq!(result, Err(BigIntDbError("Updating balance for payable of 100 Wei to a11122 with error 'Invalid parameter name: :woodstock'".to_string())));
    }

    #[test]
    fn update_changes_no_rows_err_detected() {
        let wallet_address = "a11122";
        let path =
            ensure_node_home_directory_exists("blob_utils", "update_changes_no_rows_err_detected");
        let conn = DbInitializerReal::default()
            .initialize(&path, true, MigratorConfig::test_default())
            .unwrap();
        let conn_ref = conn.as_ref();
        let balance_change = Addition("balance", 100);
        let update_config = BigIntSqlConfig::new(
            "update payable set balance = :balance where wallet_address = :wallet_address",
            None,
            SQLParamsBuilder::default()
                .key("wallet_address", ":wallet_address", &wallet_address)
                .wei_change(balance_change)
                .build(),
        );

        let result = BigIntDbProcessorReal::<PayableDaoReal>::new()
            .update_threatened_by_overflow(Either::Left(conn_ref), update_config);

        assert_eq!(result, Err(BigIntDbError(String::from("Updating balance for payable of 100 Wei to a11122 with error 'Query returned no rows'"))))
    }

    fn initiate_simple_connection_and_test_table(
        module: &str,
        test_name: &str,
        read_only_conn: bool,
    ) -> Box<ConnectionWrapperReal> {
        let home_dir = ensure_node_home_directory_exists(module, test_name);
        let db_path = home_dir.join("test_table.db");
        let conn = Connection::open(db_path.as_path()).unwrap();
        conn.execute(
            "create table test_table (name text primary key, balance_high_b integer not null, balance_low_b integer not null) strict",
            [],
        )
        .unwrap();
        let conn = if !read_only_conn {
            conn
        } else {
            drop(conn);
            Connection::open_with_flags(db_path.as_path(), OpenFlags::SQLITE_OPEN_READ_ONLY)
                .unwrap()
        };
        Box::new(ConnectionWrapperReal::new(conn))
    }

    #[test]
    fn upsert_early_return_for_successful_insert_works() {
        let conn = initiate_simple_connection_and_test_table(
            "blob_utils",
            "upsert_early_return_for_successful_insert_works",
            false,
        );
        let subject = BigIntDbProcessorReal::<DummyDao>::new();

        let result = subject.execute(conn.as_ref(), BigIntSqlConfig::new(
            "insert into test_table (name,balance_high_b,balance_low_b) values (:name,:balance_high_b,:balance_low_b)",
            None,
            SQLParamsBuilder::default()
                .key("name", ":name", &"Joe")
                .wei_change(Addition("balance", 255))
                .build(),
        ));

        assert_eq!(result, Ok(()));
        conn.prepare("select * from test_table")
            .unwrap()
            .query_row([], |_row| Ok(()))
            .unwrap();
    }

    #[test]
    fn upsert_insert_failed_update_succeeded() {
        let conn = initiate_simple_connection_and_test_table(
            "blob_utils",
            "upsert_insert_failed_update_succeeded",
            false,
        );
        conn.prepare(
            "insert into test_table (name,balance_high_b, balance_low_b) values ('Joe', ?, ?)",
        )
        .unwrap()
        .execute(&[&60, &5555])
        .unwrap();
        let subject = BigIntDbProcessorReal::<DummyDao>::new();
        let balance_change = Addition("balance", 5555);
        let config = BigIntSqlConfig::new(
            "insert into test_table (name, balance_high_b, balance_low_b) values (:name, :balance_high_b, :balance_low_b) on conflict (name) do",
            Some(|table_name |format!("update {} set balance_high_b = balance_high_b + :balance_high_b, balance_low_b = balance_low_b + :balance_low_b where name = :name",table_name)),
            SQLParamsBuilder::default()
                .key("name", ":name",&"Joe")
                .wei_change(balance_change)
                .build());

        let result = subject.execute(conn.as_ref(), config);

        assert_eq!(result, Ok(()));
        conn.prepare("select * from test_table")
            .unwrap()
            .query_row([], |row| {
                assert_eq!(row.get::<usize, String>(0).unwrap(), "Joe".to_string());
                assert_eq!(row.get::<usize, i64>(1).unwrap(), 60);
                assert_eq!(row.get::<usize, i64>(2).unwrap(), 11110);
                Ok(())
            })
            .unwrap();
    }

    #[test]
    fn upsert_insert_failed_update_failed_too() {
        todo!("do we really want a test like this?");
        let conn = initiate_simple_connection_and_test_table(
            "blob_utils",
            "upsert_insert_failed_update_failed_too",
            false,
        );
        conn.prepare(
            "insert into test_table (name,balance_high_b,balance_low_b) values ('Joe', ?, ?)",
        )
        .unwrap()
        //notice the type difference here and later
        .execute(&[&60, &5555])
        .unwrap();
        let subject = BigIntDbProcessorReal::<DummyDao>::new();
        let balance_change = Addition("balance", 5555);
        let config = BigIntSqlConfig::new(
            "insert into test_table (name, balance_high_b, balance_low_b) values (:name,:balance_high_b,:balance_low_b) on conflict (name) do",
            Some(|table_name|format!("update {} set balance_high_b = balance_high_b + :balance_high_b + where name = :name",table_name)),
                SQLParamsBuilder::default()
                    .key("name", ":name", &"Joe")
                    .wei_change(balance_change)
                    .build(),
            );

        let result = subject.execute(conn.as_ref(), config);

        assert_eq!(
            result,
            Err(BigIntDbError(
                "Updating balance for test_table of 5555 Wei to Joe with \
        error 'Invalid column type Integer at index: 0, name: balance'"
                    .to_string()
            ))
        );
    }

    #[test]
    fn upsert_insert_handles_unspecific_failures() {
        let conn = initiate_simple_connection_and_test_table(
            "blob_utils",
            "upsert_insert_handles_unspecific_failures",
            false,
        );
        let subject = BigIntDbProcessorReal::<DummyDao>::new();
        let balance_change = Addition("balance", 4879898145125);
        let config = BigIntSqlConfig::new(
            "insert into test_table (name,balance_high_b,balance_low_b) values (:name,:balance_a,:balance_b) on conflict (name) do",
            Some(|table_name |format!("update {} set balance_high_b = balance_high_b + 5, balance_low_b = balance_low_b + 10 where name = :name",table_name)),
            SQLParamsBuilder::default()
                    .key("name", ":name", &"Joe")
                    .wei_change(balance_change)
                    .build(),
            );

        let result = subject.execute(conn.as_ref(), config);

        assert_eq!(
            result,
            Err(BigIntDbError(
                "Wei change: error after invalid insert command for test_table of 4879898145125 \
                Wei to Joe with error 'Invalid parameter name: :balance_high_b'"
                    .to_string()
            ))
        );
    }

    #[test]
    fn upsert_insert_fails_and_update_overflows_in_low_bytes_but_is_handled() {
        let conn = initiate_simple_connection_and_test_table(
            "blob_utils",
            "upsert_insert_fails_and_update_overflows_but_is_handled",
            false,
        );
        conn.prepare(
            "insert into test_table (name,balance_high_b,balance_low_b) values ('Joe', ?, ?)",
        )
        .unwrap()
        .execute(&[&0, &(i64::MAX - 56)])
        .unwrap();
        let subject = BigIntDbProcessorReal::<DummyDao>::new();
        let balance_change = Addition("balance", 57 as u128);
        let config = BigIntSqlConfig::new(
            "insert into test_table (name,balance_high_b,balance_low_b) values (:name,:balance_high_b,:balance_low_b) on conflict (name) do",
            Some(|table_name|format!("update {} set balance_high_b = balance_high_b + :balance_high_b, balance_low_b = balance_low_b + :balance_low_b  where name = :name",table_name)),
                SQLParamsBuilder::default()
                    .key("name", ":name", &"Joe")
                    .wei_change(balance_change)
                    .build(),
            );

        let result = subject.execute(conn.as_ref(), config);

        assert_eq!(result, Ok(()));
        conn.prepare("select * from test_table")
            .unwrap()
            .query_row([], |row| {
                assert_eq!(row.get::<usize, String>(0).unwrap(), "Joe".to_string());
                let high_bytes = row.get::<usize, i64>(1).unwrap();
                let low_bytes = row.get::<usize, i64>(2).unwrap();
                assert_eq!(high_bytes, 1);
                assert_eq!(low_bytes, 0);
                let math_op_result = BigIntDivider::reconstitute(high_bytes, low_bytes);
                assert_eq!(math_op_result, i64::MAX as i128 + 1);
                Ok(())
            })
            .unwrap();
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
    //TODO kill this test later
    fn preparing_values_for_other_tests() {
        eprintln!(
            "{:?}",
            BigIntDivider::deconstruct(56784545484899 * 1000000000)
        );
        eprintln!("{:?}", BigIntDivider::deconstruct(-56784 * 1000000000));
        eprintln!("{:?}", BigIntDivider::deconstruct(9123 * 1000000000));
    }
}
