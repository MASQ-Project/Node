// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::payable_dao::PayableDaoError;
use crate::accountant::receivable_dao::ReceivableDaoError;
use crate::database::connection_wrapper::ConnectionWrapper;
use crate::sub_lib::accountant::SignConversionError;
use itertools::Either;
use masq_lib::utils::ExpectValue;
use rusqlite::ErrorCode::ConstraintViolation;
use rusqlite::{Error, Statement, ToSql, Transaction};
use std::any::Any;
use std::fmt::{Display, Formatter};

pub struct InsertUpdateConfig<'a> {
    pub insert_sql: &'a str,
    pub update_sql: &'a str,
    pub params: SQLExtParams<'a>,
    pub table: Table
}

pub struct InsertConfig<'a> {
    pub insert_sql: &'a str,
    pub params: &'a [(&'static str, &'a dyn ToSql)],
    pub table: Table,
}

pub struct UpdateConfig<'a> {
    pub update_sql: &'a str,
    pub params: SQLExtParams<'a>,
    pub table: Table
}

#[derive(PartialEq, Debug, Clone, Copy)]
pub enum Table {
    Payable,
    Receivable,
}

impl Display for Table {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Table::Payable => write!(f, "payable"),
            Table::Receivable => write!(f, "receivable"),
        }
    }
}

impl From<String> for PayableDaoError {
    fn from(_: String) -> Self {
        todo!()
    }
}

impl From<String> for ReceivableDaoError {
    fn from(_: String) -> Self {
        todo!()
    }
}

pub trait ExtendedParamsMarker: ToSql + Display {
    fn countable_as_any(&self) -> &dyn Any {
        intentionally_blank!()
    }
}
impl ExtendedParamsMarker for i128 {
    fn countable_as_any(&self) -> &dyn Any {
        self
    }
}
impl ExtendedParamsMarker for i64 {}
impl ExtendedParamsMarker for &str {}

pub struct SQLExtParams<'a> {
    params: Vec<(&'a str, &'a dyn ExtendedParamsMarker)>,
}

impl<'a> SQLExtParams<'a> {
    pub fn new(params: Vec<(&'a str, &'a (dyn ExtendedParamsMarker + 'a))>) -> Self {
        Self { params }
    }
    pub fn params(&self) -> &Vec<(&'a str, &'a (dyn ExtendedParamsMarker + 'a))> {
        &self.params
    }

    pub fn all_rusqlite_params(&'a self) -> Vec<(&'a str, &'a dyn ToSql)> {
        self.params
            .iter()
            .map(|(first, second)| (*first, second as &dyn ToSql))
            .collect()
    }
}

pub trait InsertUpdateCore {
    fn insert(
        &self,
        conn: &dyn ConnectionWrapper,
        config: &dyn InsertConfiguration,
    ) -> Result<(), Error>;
    fn update<'a>(
        &self,
        conn: Either<&dyn ConnectionWrapper, &Transaction>,
        config: &'a (dyn UpdateConfiguration<'a> + 'a),
    ) -> Result<(), String>;
    fn upsert<'a>(
        &self,
        conn: &dyn ConnectionWrapper,
        config: InsertUpdateConfig<'a>,
    ) -> Result<(), String>;
}

pub struct InsertUpdateCoreReal;

impl InsertUpdateCore for InsertUpdateCoreReal {
    fn insert(
        &self,
        conn: &dyn ConnectionWrapper,
        config: &dyn InsertConfiguration,
    ) -> Result<(), Error> {
        todo!()
    }

    fn update<'a>(
        &self,
        form_of_conn: Either<&dyn ConnectionWrapper, &Transaction>,
        config: &'a (dyn UpdateConfiguration<'a> + 'a),
    ) -> Result<(), String> {
        let present_state_query = config.select_sql();
        let mut statement = Self::prepare_statement(form_of_conn, present_state_query.as_str());
        let update_params = config.update_params().params();
        let (wallet, balance_change) = Self::fetch_fundamentals(update_params)?;
        match statement.query_row(&[(":wallet", &wallet)], |row| {
            let balance_result: rusqlite::Result<i128> = row.get(0);
            match balance_result {
                Ok(balance) => {
                    let updated_balance = balance + balance_change;
                    let params_to_update = config.update_params().all_rusqlite_params();
                    let update_params =
                        config.finalize_update_params(&updated_balance, params_to_update);
                    let update_query = config.update_sql();
                    let mut stm = Self::prepare_statement(form_of_conn, update_query);
                    stm.execute(&*update_params)
                }
                Err(e) => Err(e),
            }
        }) {
            Ok(_) => Ok(()),
            Err(e) => Err(format!(
                "Updating balance for {} of {} Wei to {}; failing on: '{}'",
                config.table(),
                balance_change,
                wallet,
                e
            )),
        }
    }

    fn upsert(
        &self,
        conn: &dyn ConnectionWrapper,
        config: InsertUpdateConfig,
    ) -> Result<(), String> {
        let params = config.params.all_rusqlite_params();
        let mut stm = conn
            .prepare(config.insert_sql)
            .expect("internal rusqlite error");
        match stm.execute(&*params) {
            Ok(_) => return Ok(()),
            Err(e)
                if {
                    match e {
                        Error::SqliteFailure(e, _) => match e.code {
                            ConstraintViolation => true,
                            _ => false,
                        },
                        _ => false,
                    }
                } =>
            {
                self.update(Either::Left(conn), &config)
            }
            Err(e) => {
                let params = config.params.params();
                let (wallet, amount) = Self::fetch_fundamentals(params)?;
                Err(format!(
                    "Updating balance after invalid insertion for {} of {} Wei to {}; failing on: '{}'",
                    config.table, amount, wallet, e
                ))
            }
        }
    }
}

pub trait FetchValue<'a> {
    fn fetch_balance_change(&'a self) -> Result<i128, String>;
    fn fetch_wallet(&'a self) -> Result<String, String>;
}

type ExtendedParamsVec<'a> = &'a Vec<(&'a str, &'a dyn ExtendedParamsMarker)>;

impl<'a> FetchValue<'a> for ExtendedParamsVec<'a> {
    fn fetch_balance_change(&'a self) -> Result<i128, String> {
        match self
            .iter()
            .find(|(param_name, _)| *param_name == ":balance")
        {
            Some((_, value)) => Ok(*value.countable_as_any().downcast_ref().expectv("i128")),
            None => Err("Missing parameter and value for the change in balance".to_string()),
        }
    }

    fn fetch_wallet(&'a self) -> Result<String, String> {
        match self.iter().find(|(param_name, _)| *param_name == ":wallet") {
            Some((_, value)) => Ok(value.to_string()),
            None => Err("Missing parameter and value for the wallet address".to_string()),
        }
    }
}

impl InsertUpdateCoreReal {
    fn fetch_fundamentals(params: ExtendedParamsVec<'_>) -> Result<(String, i128), String> {
        Ok((params.fetch_wallet()?, params.fetch_balance_change()?))
    }

    fn prepare_statement<'a>(
        form_of_conn: Either<&'a dyn ConnectionWrapper, &'a Transaction>,
        query: &'a str,
    ) -> Statement<'a> {
        match form_of_conn {
            Either::Left(conn) => conn.prepare(query),
            Either::Right(tx) => tx.prepare(query),
        }
        .expect("internal rusqlite error")
    }
}

pub trait InsertConfiguration<'a> {
    fn insert_sql(&self) -> &'a str;
    fn insert_params(&self) -> &'a [(&'static str, &'a dyn ToSql)];
}

impl<'a> InsertConfiguration<'a> for InsertUpdateConfig<'a> {
    fn insert_sql(&self) -> &'a str {
        todo!()
    }
    fn insert_params(&self) -> &'a [(&'static str, &'a dyn ToSql)] {
        todo!()
    }
}

pub trait UpdateConfiguration<'a> {
    fn table(&self) -> String;
    fn select_sql(&self) -> String;
    fn update_sql(&self) -> &'a str;
    fn update_params(&self) -> &SQLExtParams;
    fn finalize_update_params<'b>(
        &'a self,
        updated_balance: &'b i128,
        mut params_to_update: Vec<(&'b str, &'b dyn ToSql)>,
    ) -> Vec<(&'b str, &'b dyn ToSql)> {
        params_to_update.remove(
            params_to_update
                .iter()
                .position(|(name, _)| *name == ":balance")
                .expectv(":balance"),
        );
        params_to_update.insert(0, (":updated_balance", updated_balance));
        params_to_update
    }
}

impl<'a> UpdateConfiguration<'a> for InsertUpdateConfig<'a> {
    fn table(&self) -> String {
        self.table.to_string()
    }

    fn select_sql(&self) -> String {
        select_statement(&self.table)
    }

    fn update_sql(&self) -> &'a str {
        self.update_sql
    }

    fn update_params(&self) -> &SQLExtParams {
        &self.params
    }
}

impl<'a> UpdateConfiguration<'a> for UpdateConfig<'a> {
    fn table(&self) -> String {
        self.table.to_string()
    }

    fn select_sql(&self) -> String {
        select_statement(&self.table)
    }

    fn update_sql(&self) -> &'a str {
        self.update_sql
    }

    fn update_params(&self) -> &SQLExtParams {
        &self.params
    }
}

fn select_statement(table: &Table) -> String {
    format!(
        "select balance from {} where wallet_address = :wallet",
        table
    )
}

//update
pub fn update_receivable(
    transaction: &Transaction,
    core: &dyn InsertUpdateCore,
    wallet: &str,
    amount: i128,
    last_received_time_stamp: i64,
) -> Result<(), ReceivableDaoError> {
    Ok(core.update(Either::Right(transaction), &UpdateConfig {
        update_sql: "update receivable set balance = :updated_balance, last_received_timestamp = :last_received where wallet_address = :wallet",
        params: SQLExtParams::new(
   //         Table::Receivable,
            vec![
                (":wallet", &wallet),
                (":balance", &amount), //:balance is later recomputed into :updated_balance
                (":last_received", &last_received_time_stamp),
            ]),
        table: Table::Receivable
    })?)
}

//insert_update
pub fn upsert_receivable(
    conn: &dyn ConnectionWrapper,
    core: &dyn InsertUpdateCore,
    wallet: &str,
    amount: i128,
) -> Result<(), ReceivableDaoError> {
    Ok(core.upsert(conn,  InsertUpdateConfig{
        insert_sql: "insert into receivable (wallet_address, balance, last_received_timestamp) values (:wallet,:balance,strftime('%s','now'))",
        update_sql: "update receivable set balance = :updated_balance where wallet_address = :wallet",
        params: SQLExtParams::new(
            vec![
                (":wallet", &wallet),
                (":balance", &amount)
            ]),
        table: Table::Receivable,
    })?)
}

pub fn upsert_payable_on_new_accrual(
    conn: &dyn ConnectionWrapper,
    core: &dyn InsertUpdateCore,
    wallet: &str,
    amount: i128,
) -> Result<(), PayableDaoError> {
    Ok(core.upsert(conn, InsertUpdateConfig{
        insert_sql: "insert into payable (wallet_address, balance, last_paid_timestamp, pending_payment_transaction) values (:wallet,:balance,strftime('%s','now'),null)",
        update_sql: "update payable set balance = :updated_balance where wallet_address = :wallet",
        params: SQLExtParams::new(
            vec![
                (":wallet", &wallet),
                (":balance", &amount)
            ]),
        table: Table::Payable,
    })?)
}

//TODO this function may not need to be insert update but simply update
//TODO name change
pub fn upsert_payable_on_confirmation(
    conn: &dyn ConnectionWrapper,
    core: &dyn InsertUpdateCore,
    wallet: &str,
    amount: i128,
    last_paid_timestamp: i64,
    transaction_hash: &str,
) -> Result<(), PayableDaoError> {
    Ok(core.upsert(conn, InsertUpdateConfig{
        insert_sql: "insert into payable (balance, last_paid_timestamp, pending_payment_transaction, wallet_address) values (:balance, :last_paid, :transaction, :wallet)",
        update_sql: "update payable set balance = :updated_balance, last_paid_timestamp = :last_paid, pending_payment_transaction = :transaction where wallet_address = :wallet",
        params: SQLExtParams::new(
            vec![
                (":wallet", &wallet),
                (":balance", &amount),
                (":last_paid", &last_paid_timestamp),
                (":transaction", &transaction_hash),
            ]),
        table: Table::Payable,
    })?)
}

pub fn reverse_sign(amount: i128) -> Result<i128, SignConversionError> {
    amount.checked_abs().map(|val| -val).ok_or_else(|| {
        SignConversionError::I128(format!("Reversing the sign for value: {}", amount))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accountant::test_utils::InsertUpdateCoreMock;
    use crate::database::connection_wrapper::{ConnectionWrapper, ConnectionWrapperReal};
    use crate::database::db_initializer::{DbInitializer, DbInitializerReal};
    use crate::database::db_migrations::MigratorConfig;
    use itertools::{Either, Itertools};
    use masq_lib::test_utils::utils::ensure_node_home_directory_exists;
    use masq_lib::utils::array_of_borrows_to_vec;
    use rusqlite::types::ToSqlOutput;
    use rusqlite::{named_params, params, Connection, ToSql};
    use std::sync::{Arc, Mutex};
    use std::time::SystemTime;

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

    fn convert_to_all_string_values(str_args: Vec<(&str, &str)>) -> Vec<(String, String)> {
        str_args
            .into_iter()
            .map(|(a, b)| (a.to_string(), b.to_string()))
            .collect()
    }

    #[test]
    fn finalize_update_params_for_update_config_works() {
        let subject = UpdateConfig {
            update_sql: "blah",
            params: SQLExtParams::new(
                vec![
                    (":something", &152_i64),
                    (":balance", &5555_i128),
                    (":something_else", &"foooo"),
                ],
            ),
            table: Table::Payable,
        };

        finalize_update_params_assertion(&subject)
    }

    #[test]
    fn finalize_update_params_for_insert_update_config_works() {
        let subject = InsertUpdateConfig {
            insert_sql: "blah1",
            update_sql: "blah2",
            params: SQLExtParams::new(
                vec![
                    (":something", &152_i64),
                    (":balance", &5555_i128),
                    (":something_else", &"foooo"),
                ],
            ),
            table:Table::Payable,
        };

        finalize_update_params_assertion(&subject)
    }

    fn finalize_update_params_assertion<'a>(subject: &'a dyn UpdateConfiguration<'a>) {
        let updated_balance = 456789;

        let result = subject.finalize_update_params(
            &updated_balance,
            subject.update_params().all_rusqlite_params(),
        );

        let expected_params: Vec<(&str, &dyn ToSql)> = vec![
            (":something", &152_i64),
            (":updated_balance", &updated_balance),
            (":something_else", &"foooo"),
        ];
        let expected_assertable = convert_params_to_debuggable_values(expected_params);
        let result_assertable = convert_params_to_debuggable_values(result);
        assert_eq!(result_assertable, expected_assertable)
    }

    #[test]
    fn fetch_balance_change_works_for_err() {
        fetch_param_assertion(
            &|subject| subject.fetch_balance_change(),
            String::from("Missing parameter and value for the change in balance"),
        );
    }

    #[test]
    fn fetch_wallet_works_for_err() {
        fetch_param_assertion(
            &|subject| subject.fetch_wallet(),
            String::from("Missing parameter and value for the wallet address"),
        );
    }

    fn fetch_param_assertion<T>(
        act: &dyn Fn(ExtendedParamsVec) -> Result<T, String>,
        expected_err_msg: String,
    ) {
        let subject = &some_meaningless_params();

        let result = act(subject);

        let result = match result {
            Ok(_) => panic!("we expected Err but got Ok"),
            Err(e) => e,
        };
        assert_eq!(result, expected_err_msg)
    }

    fn some_meaningless_params<'a>() -> Vec<(&'a str, &'a dyn ExtendedParamsMarker)> {
        vec![(":something", &"yo-yo"), (":something_else", &55_i64)]
    }

    #[test]
    fn update_receivable_works_positive() {
        let wallet_address = "xyz123";
        let path = ensure_node_home_directory_exists(
            "dao_shared_methods",
            "update_receivable_works_positive",
        );
        let mut conn = DbInitializerReal::default()
            .initialize(&path, true, MigratorConfig::test_default())
            .unwrap();
        let conn_ref = conn.as_ref();
        insert_receivable_100_balance_100_last_time_stamp(conn_ref, wallet_address);
        let (balance, last_time_stamp) = read_row_receivable(conn_ref, wallet_address).unwrap();
        let tx = conn.transaction().unwrap();
        assert_eq!(balance, 100);
        assert_eq!(last_time_stamp, 100);
        let amount_wei = i128::MAX - 100;
        let last_received_time_stamp_sec = 4_545_789;

        let result = update_receivable(
            &tx,
            &InsertUpdateCoreReal,
            wallet_address,
            amount_wei,
            last_received_time_stamp_sec,
        );

        tx.commit().unwrap();
        assert_eq!(result, Ok(()));
        let (balance, last_time_stamp) =
            read_row_receivable(conn.as_ref(), wallet_address).unwrap();
        assert_eq!(balance, amount_wei + 100);
        assert_eq!(last_time_stamp, last_received_time_stamp_sec);
    }

    #[test]
    fn update_receivable_works_negative() {
        let wallet_address = "xyz178";
        let path = ensure_node_home_directory_exists(
            "dao_shared_methods",
            "update_receivable_works_negative",
        );
        let mut conn = DbInitializerReal::default()
            .initialize(&path, true, MigratorConfig::test_default())
            .unwrap();
        let conn_ref = conn.as_ref();
        insert_receivable_100_balance_100_last_time_stamp(conn_ref, wallet_address);
        let (balance, last_time_stamp) = read_row_receivable(conn_ref, wallet_address).unwrap();
        let tx = conn.transaction().unwrap();
        assert_eq!(balance, 100);
        assert_eq!(last_time_stamp, 100);
        let amount_wei = -345_125;
        let last_received_time_stamp_sec = 4_545_789;

        let result = update_receivable(
            &tx,
            &InsertUpdateCoreReal,
            wallet_address,
            amount_wei,
            last_received_time_stamp_sec,
        );

        tx.commit().unwrap();
        assert_eq!(result, Ok(()));
        let (balance, last_time_stamp) =
            read_row_receivable(conn.as_ref(), wallet_address).unwrap();
        assert_eq!(balance, -345_025);
        assert_eq!(last_time_stamp, last_received_time_stamp_sec);
    }

    #[test]
    fn insert_or_update_receivable_works_for_insert_positive() {
        let wallet_address = "xyz456";
        let path = ensure_node_home_directory_exists(
            "dao_shared_methods",
            "insert_or_update_receivable_works_for_insert_positive",
        );
        let conn = DbInitializerReal::default()
            .initialize(&path, true, MigratorConfig::test_default())
            .unwrap();
        let conn_ref = conn.as_ref();
        let err = read_row_receivable(conn_ref, wallet_address).unwrap_err();
        match err {
            rusqlite::Error::QueryReturnedNoRows => (),
            x => panic!("we expected 'query returned no rows' but got '{}'", x),
        }
        let amount_wei = i128::MAX;

        let result = upsert_receivable(conn_ref, &InsertUpdateCoreReal, wallet_address, amount_wei);

        assert_eq!(result, Ok(()));
        let (balance, last_timestamp) = read_row_receivable(conn_ref, wallet_address).unwrap();
        assert!(is_timely_around(last_timestamp));
        assert_eq!(balance, amount_wei)
    }

    #[test]
    fn insert_or_update_receivable_works_for_insert_negative() {
        let wallet_address = "xyz456";
        let path = ensure_node_home_directory_exists(
            "dao_shared_methods",
            "insert_or_update_receivable_works_for_insert_negative",
        );
        let conn = DbInitializerReal::default()
            .initialize(&path, true, MigratorConfig::test_default())
            .unwrap();
        let conn_ref = conn.as_ref();
        let err = read_row_receivable(conn_ref, wallet_address).unwrap_err();
        match err {
            rusqlite::Error::QueryReturnedNoRows => (),
            x => panic!("we expected 'query returned no rows' but got '{}'", x),
        }
        let amount_wei = -125_125;

        let result = upsert_receivable(conn_ref, &InsertUpdateCoreReal, wallet_address, amount_wei);

        assert_eq!(result, Ok(()));
        let (balance, last_timestamp) = read_row_receivable(conn_ref, wallet_address).unwrap();
        assert!(is_timely_around(last_timestamp));
        assert_eq!(balance, -125_125)
    }

    #[test]
    fn insert_or_update_receivable_works_for_update_positive() {
        let wallet_address = "xyz789";
        let path = ensure_node_home_directory_exists(
            "dao_shared_methods",
            "insert_or_update_receivable_works_for_update_positive",
        );
        let conn = DbInitializerReal::default()
            .initialize(&path, true, MigratorConfig::test_default())
            .unwrap();
        let conn_ref = conn.as_ref();
        insert_receivable_100_balance_100_last_time_stamp(conn_ref, wallet_address);
        let (balance, last_time_stamp) = read_row_receivable(conn_ref, wallet_address).unwrap();
        assert_eq!(balance, 100);
        assert_eq!(last_time_stamp, 100);
        let amount_wei = i128::MAX - 100;

        let result = upsert_receivable(conn_ref, &InsertUpdateCoreReal, wallet_address, amount_wei);

        assert_eq!(result, Ok(()));
        let (balance, last_timestamp) = read_row_receivable(conn_ref, wallet_address).unwrap();
        assert_eq!(last_timestamp, 100); //TODO this might be an old issue - do we really never want to update the timestamp? Can it ever disappear or the timestamp from the initial insertion persists forever?
        assert_eq!(balance, amount_wei + 100)
    }

    #[test]
    fn insert_or_update_receivable_works_for_update_negative() {
        let wallet_address = "xyz789";
        let path = ensure_node_home_directory_exists(
            "dao_shared_methods",
            "insert_or_update_receivable_works_for_update_negative",
        );
        let conn = DbInitializerReal::default()
            .initialize(&path, true, MigratorConfig::test_default())
            .unwrap();
        let conn_ref = conn.as_ref();
        insert_receivable_100_balance_100_last_time_stamp(conn_ref, wallet_address);
        let (balance, last_time_stamp) = read_row_receivable(conn_ref, wallet_address).unwrap();
        assert_eq!(balance, 100);
        assert_eq!(last_time_stamp, 100);
        let amount_wei = -123_100;

        let result = upsert_receivable(conn_ref, &InsertUpdateCoreReal, wallet_address, amount_wei);

        assert_eq!(result, Ok(()));
        let (balance, last_timestamp) = read_row_receivable(conn_ref, wallet_address).unwrap();
        assert_eq!(last_timestamp, 100); //TODO this might be an old issue - do we really never want to update the timestamp? Can it ever disappear or the timestamp from the initial insertion persists forever?
        assert_eq!(balance, -123_000)
    }

    #[test]
    fn insert_or_update_payable_works_for_insert_positive() {
        let wallet_address = "xyz2211";
        let path = ensure_node_home_directory_exists(
            "dao_shared_methods",
            "insert_or_update_payable_works_for_insert_positive",
        );
        let conn = DbInitializerReal::default()
            .initialize(&path, true, MigratorConfig::test_default())
            .unwrap();
        let conn_ref = conn.as_ref();
        let err = read_row_payable(conn_ref, wallet_address).unwrap_err();
        match err {
            rusqlite::Error::QueryReturnedNoRows => (),
            x => panic!("we expected 'query returned no rows' but got '{}'", x),
        }
        let amount_wei = i128::MAX;

        let result = upsert_payable_on_new_accrual(
            conn_ref,
            &InsertUpdateCoreReal,
            wallet_address,
            amount_wei,
        );

        assert_eq!(result, Ok(()));
        let (balance, last_timestamp, pending_transaction_hash) =
            read_row_payable(conn_ref, wallet_address).unwrap();
        assert!(is_timely_around(last_timestamp));
        assert_eq!(balance, amount_wei);
        assert_eq!(pending_transaction_hash, None)
    }

    #[test]
    fn insert_or_update_payable_works_for_insert_negative() {
        let wallet_address = "xyz2211";
        let path = ensure_node_home_directory_exists(
            "dao_shared_methods",
            "insert_or_update_payable_works_for_insert_negative",
        );
        let conn = DbInitializerReal::default()
            .initialize(&path, true, MigratorConfig::test_default())
            .unwrap();
        let conn_ref = conn.as_ref();
        let err = read_row_payable(conn_ref, wallet_address).unwrap_err();
        match err {
            rusqlite::Error::QueryReturnedNoRows => (),
            x => panic!("we expected 'query returned no rows' but got '{}'", x),
        }
        let amount_wei = -1_245_999;

        let result = upsert_payable_on_new_accrual(
            conn_ref,
            &InsertUpdateCoreReal,
            wallet_address,
            amount_wei,
        );

        assert_eq!(result, Ok(()));
        let (balance, last_timestamp, pending_transaction_hash) =
            read_row_payable(conn_ref, wallet_address).unwrap();
        assert!(is_timely_around(last_timestamp));
        assert_eq!(balance, -1_245_999);
        assert_eq!(pending_transaction_hash, None)
    }

    #[test]
    fn insert_or_update_payable_works_for_update_positive() {
        let wallet_address = "xyz78978";
        let path = ensure_node_home_directory_exists(
            "dao_shared_methods",
            "insert_or_update_payable_works_for_update_positive",
        );
        let conn = DbInitializerReal::default()
            .initialize(&path, true, MigratorConfig::test_default())
            .unwrap();
        let conn_ref = conn.as_ref();
        insert_payable_100_balance_100_last_time_stamp_transaction_hash_abc(
            conn_ref,
            wallet_address,
        );
        let (balance, last_time_stamp, pending_transaction_hash) =
            read_row_payable(conn_ref, wallet_address).unwrap();
        assert_eq!(balance, 100);
        assert_eq!(last_time_stamp, 100);
        assert_eq!(pending_transaction_hash, Some("abc".to_string()));
        let amount_wei = i128::MAX - 100;

        let result = upsert_payable_on_new_accrual(
            conn_ref,
            &InsertUpdateCoreReal,
            wallet_address,
            amount_wei,
        );

        assert_eq!(result, Ok(()));
        let (balance, last_timestamp, pending_transaction_hash) =
            read_row_payable(conn_ref, wallet_address).unwrap();
        assert_eq!(last_timestamp, 100); //TODO this might be an old issue - do we really never want to update the timestamp? Can it ever disappear or the timestamp from the initial insertion persists forever?
        assert_eq!(balance, amount_wei + 100);
        assert_eq!(pending_transaction_hash, Some("abc".to_string()))
    }

    #[test]
    fn insert_or_update_payable_works_for_update_negative() {
        let wallet_address = "xyz78978";
        let path = ensure_node_home_directory_exists(
            "dao_shared_methods",
            "insert_or_update_payable_works_for_update_negative",
        );
        let conn = DbInitializerReal::default()
            .initialize(&path, true, MigratorConfig::test_default())
            .unwrap();
        let conn_ref = conn.as_ref();
        insert_payable_100_balance_100_last_time_stamp_transaction_hash_abc(
            conn_ref,
            wallet_address,
        );
        let (balance, last_time_stamp, pending_transaction_hash) =
            read_row_payable(conn_ref, wallet_address).unwrap();
        assert_eq!(balance, 100);
        assert_eq!(last_time_stamp, 100);
        assert_eq!(pending_transaction_hash, Some("abc".to_string()));
        let amount_wei = -90_333;

        let result = upsert_payable_on_new_accrual(
            conn_ref,
            &InsertUpdateCoreReal,
            wallet_address,
            amount_wei,
        );

        assert_eq!(result, Ok(()));
        let (balance, last_timestamp, pending_transaction_hash) =
            read_row_payable(conn_ref, wallet_address).unwrap();
        assert_eq!(last_timestamp, 100); //TODO this might be an old issue - do we really never want to update the timestamp? Can it ever disappear or the timestamp from the initial insertion persists forever?
        assert_eq!(balance, -90_233);
        assert_eq!(pending_transaction_hash, Some("abc".to_string()))
    }

    #[test]
    fn insert_or_update_payable_for_our_payment_works_for_insert_positive() {
        let wallet_address = "xyz2211";
        let path = ensure_node_home_directory_exists(
            "dao_shared_methods",
            "insert_or_update_payable_for_our_payment_works_for_insert_positive",
        );
        let conn = DbInitializerReal::default()
            .initialize(&path, true, MigratorConfig::test_default())
            .unwrap();
        let conn_ref = conn.as_ref();
        let err = read_row_payable(conn_ref, wallet_address).unwrap_err();
        match err {
            rusqlite::Error::QueryReturnedNoRows => (),
            x => panic!("we expected 'query returned no rows' but got '{}'", x),
        }
        let amount_wei = i128::MAX;
        let last_paid_timestamp = 10_000_000;
        let transaction_hash = "ce5456ed";

        let result = upsert_payable_on_confirmation(
            conn_ref,
            &InsertUpdateCoreReal,
            wallet_address,
            amount_wei,
            last_paid_timestamp,
            transaction_hash,
        );

        assert_eq!(result, Ok(()));
        let (balance, last_timestamp, pending_transaction_hash) =
            read_row_payable(conn_ref, wallet_address).unwrap();
        assert_eq!(last_timestamp, last_paid_timestamp); //TODO this is going to produce troubles
        assert_eq!(balance, amount_wei);
        assert_eq!(pending_transaction_hash, Some(transaction_hash.to_string()))
    }

    #[test]
    fn insert_or_update_payable_for_our_payment_works_for_insert_negative() {
        let wallet_address = "xyz2211";
        let path = ensure_node_home_directory_exists(
            "dao_shared_methods",
            "insert_or_update_payable_for_our_payment_works_for_insert_negative",
        );
        let conn = DbInitializerReal::default()
            .initialize(&path, true, MigratorConfig::test_default())
            .unwrap();
        let conn_ref = conn.as_ref();
        let err = read_row_payable(conn_ref, wallet_address).unwrap_err();
        match err {
            rusqlite::Error::QueryReturnedNoRows => (),
            x => panic!("we expected 'query returned no rows' but got '{}'", x),
        }
        let amount_wei = -1_245_100;
        let last_paid_timestamp = 890_000_000;
        let transaction_hash = "ce5456ed";

        let result = upsert_payable_on_confirmation(
            conn_ref,
            &InsertUpdateCoreReal,
            wallet_address,
            amount_wei,
            last_paid_timestamp,
            transaction_hash,
        );

        assert_eq!(result, Ok(()));
        let (balance, last_timestamp, pending_transaction_hash) =
            read_row_payable(conn_ref, wallet_address).unwrap();
        assert_eq!(last_timestamp, last_paid_timestamp);
        assert_eq!(balance, -1_245_100);
        assert_eq!(pending_transaction_hash, Some(transaction_hash.to_string()))
    }

    #[test]
    fn insert_or_update_payable_for_our_payment_works_for_update_positive() {
        let wallet_address = "xyz7894";
        let path = ensure_node_home_directory_exists(
            "dao_shared_methods",
            "insert_or_update_payable_for_our_payment_works_for_update_positive",
        );
        let conn = DbInitializerReal::default()
            .initialize(&path, true, MigratorConfig::test_default())
            .unwrap();
        let conn_ref = conn.as_ref();
        insert_payable_100_balance_100_last_time_stamp_transaction_hash_abc(
            conn_ref,
            wallet_address,
        );
        let (balance, last_time_stamp, pending_transaction_hash) =
            read_row_payable(conn_ref, wallet_address).unwrap();
        assert_eq!(balance, 100);
        assert_eq!(last_time_stamp, 100);
        assert_eq!(pending_transaction_hash, Some("abc".to_string()));
        let amount_wei = i128::MAX - 100;
        let last_paid_timestamp = 5_000;
        let transaction_hash = "ed78acc54";

        let result = upsert_payable_on_confirmation(
            conn_ref,
            &InsertUpdateCoreReal,
            wallet_address,
            amount_wei,
            last_paid_timestamp,
            transaction_hash,
        );

        assert_eq!(result, Ok(()));
        let (balance, last_timestamp, pending_transaction_hash) =
            read_row_payable(conn_ref, wallet_address).unwrap();
        assert_eq!(last_timestamp, last_paid_timestamp);
        assert_eq!(balance, amount_wei + 100);
        assert_eq!(pending_transaction_hash, Some(transaction_hash.to_string()))
    }

    #[test]
    fn insert_or_update_payable_for_our_payment_works_for_update_negative() {
        let wallet_address = "xyz7894";
        let path = ensure_node_home_directory_exists(
            "dao_shared_methods",
            "insert_or_update_payable_for_our_payment_works_for_update_negative",
        );
        let conn = DbInitializerReal::default()
            .initialize(&path, true, MigratorConfig::test_default())
            .unwrap();
        let conn_ref = conn.as_ref();
        insert_payable_100_balance_100_last_time_stamp_transaction_hash_abc(
            conn_ref,
            wallet_address,
        );
        let (balance, last_time_stamp, pending_transaction_hash) =
            read_row_payable(conn_ref, wallet_address).unwrap();
        assert_eq!(balance, 100);
        assert_eq!(last_time_stamp, 100);
        assert_eq!(pending_transaction_hash, Some("abc".to_string()));
        let amount_wei = -45_000;
        let last_paid_timestamp = 5_000;
        let transaction_hash = "ed78acc54";

        let result = upsert_payable_on_confirmation(
            conn_ref,
            &InsertUpdateCoreReal,
            wallet_address,
            amount_wei,
            last_paid_timestamp,
            transaction_hash,
        );

        assert_eq!(result, Ok(()));
        let (balance, last_timestamp, pending_transaction_hash) =
            read_row_payable(conn_ref, wallet_address).unwrap();
        assert_eq!(last_timestamp, last_paid_timestamp);
        assert_eq!(balance, -44_900);
        assert_eq!(pending_transaction_hash, Some(transaction_hash.to_string()))
    }

    #[test]
    fn update_receivable_error_handling_and_params_assertion() {
        let insert_or_update_params_arc = Arc::new(Mutex::new(vec![]));
        let wallet_address = "xyz123";
        let conn = Connection::open_in_memory().unwrap();
        let mut wrapped_conn = ConnectionWrapperReal::new(conn);
        create_broken_receivable(&wrapped_conn);
        let supplied_amount_wei = 100;
        let last_received_time_stamp_sec = 123;
        let insert_update_core = InsertUpdateCoreMock::default()
            .update_params(&insert_or_update_params_arc)
            .update_result(Err("SomethingWrong".to_string()));
        let tx = wrapped_conn.transaction().unwrap();

        let result = update_receivable(
            &tx,
            &insert_update_core,
            wallet_address,
            supplied_amount_wei,
            last_received_time_stamp_sec,
        );

        assert_eq!(
            result,
            Err(ReceivableDaoError::RusqliteError(
                "SomethingWrong".to_string()
            ))
        );
        let mut insert_or_update_params = insert_or_update_params_arc.lock().unwrap();
        let (select_sql, update_sql, table, sql_param_names) = insert_or_update_params.remove(0);
        assert!(insert_or_update_params.is_empty());
        assert_eq!(
            select_sql,
            "select balance from receivable where wallet_address = :wallet"
        );
        assert_eq!(update_sql, "update receivable set balance = :updated_balance, last_received_timestamp = :last_received where wallet_address = :wallet");
        assert_eq!(table, Table::Receivable.to_string());
        assert_eq!(
            sql_param_names,
            array_of_borrows_to_vec(&[":wallet", ":balance", ":last_received"]) //TODO is this right?
        )
    }

    #[test]
    fn insert_or_update_receivable_error_handling_and_params_assertion() {
        let insert_or_update_params_arc = Arc::new(Mutex::new(vec![]));
        let wallet_address = "xyz123";
        let conn = Connection::open_in_memory().unwrap();
        let wrapped_conn = ConnectionWrapperReal::new(conn);
        create_broken_receivable(&wrapped_conn);
        let supplied_amount_wei = 100;
        let insert_update_core = InsertUpdateCoreMock::default()
            .upsert_params(&insert_or_update_params_arc)
            .upsert_results(Err("SomethingWrong".to_string()));

        let result = upsert_receivable(
            &wrapped_conn,
            &insert_update_core,
            wallet_address,
            supplied_amount_wei,
        );

        assert_eq!(
            result,
            Err(ReceivableDaoError::RusqliteError(
                "SomethingWrong".to_string()
            ))
        );
        let mut insert_or_update_params = insert_or_update_params_arc.lock().unwrap();
        let (update_sql, insert_sql, table, sql_param_names) = insert_or_update_params.remove(0);
        assert!(insert_or_update_params.is_empty());
        assert_eq!(
            update_sql,
            "update receivable set balance = :updated_balance where wallet_address = :wallet"
        );
        assert_eq!(insert_sql,"insert into receivable (wallet_address, balance, last_received_timestamp) values (:wallet,:balance,strftime('%s','now'))");
        assert_eq!(table, Table::Receivable);
        assert_eq!(
            sql_param_names,
            convert_to_all_string_values(vec![
                (":wallet", wallet_address),
                (":balance", &supplied_amount_wei.to_string())
            ])
        )
    }

    #[test]
    fn insert_or_update_payable_error_handling_and_params_assertion() {
        let insert_or_update_params_arc = Arc::new(Mutex::new(vec![]));
        let wallet_address = "xyz123";
        let conn = Connection::open_in_memory().unwrap();
        let wrapped_conn = ConnectionWrapperReal::new(conn);
        create_broken_payable(&wrapped_conn);
        let supplied_amount_wei = 100;
        let insert_update_core = InsertUpdateCoreMock::default()
            .upsert_params(&insert_or_update_params_arc)
            .upsert_results(Err("SomethingWrong".to_string()));

        let result = upsert_payable_on_new_accrual(
            &wrapped_conn,
            &insert_update_core,
            wallet_address,
            supplied_amount_wei,
        );

        assert_eq!(
            result,
            Err(PayableDaoError::RusqliteError("SomethingWrong".to_string()))
        );
        let mut insert_or_update_params = insert_or_update_params_arc.lock().unwrap();
        let (update_sql, insert_sql, table, sql_param_names) = insert_or_update_params.remove(0);
        assert!(insert_or_update_params.is_empty());
        assert_eq!(
            update_sql,
            "update payable set balance = :updated_balance where wallet_address = :wallet"
        );
        assert_eq!(insert_sql,"insert into payable (wallet_address, balance, last_paid_timestamp, pending_payment_transaction) values (:wallet,:balance,strftime('%s','now'),null)");
        assert_eq!(table, Table::Payable);
        assert_eq!(
            sql_param_names,
            convert_to_all_string_values(vec![
                (":wallet", wallet_address),
                (":balance", &supplied_amount_wei.to_string())
            ])
        )
    }

    #[test]
    fn insert_or_update_payable_for_our_payment_error_handling_and_params_assertion() {
        let insert_or_update_params_arc = Arc::new(Mutex::new(vec![]));
        let wallet_address = "xyz123";
        let conn = Connection::open_in_memory().unwrap();
        let wrapped_conn = ConnectionWrapperReal::new(conn);
        create_broken_payable(&wrapped_conn);
        let supplied_amount_wei = 100;
        let last_received_time_stamp_sec = 123;
        let tx_hash = "ab45cab45";
        let insert_update_core = InsertUpdateCoreMock::default()
            .upsert_params(&insert_or_update_params_arc)
            .upsert_results(Err("SomethingWrong".to_string()));

        let result = upsert_payable_on_confirmation(
            &wrapped_conn,
            &insert_update_core,
            wallet_address,
            supplied_amount_wei,
            last_received_time_stamp_sec,
            tx_hash,
        );

        assert_eq!(
            result,
            Err(PayableDaoError::RusqliteError("SomethingWrong".to_string()))
        );
        let mut insert_or_update_params = insert_or_update_params_arc.lock().unwrap();
        let (update_sql, insert_sql, table, sql_param_names) = insert_or_update_params.remove(0);
        assert!(insert_or_update_params.is_empty());
        assert_eq!(update_sql,"update payable set balance = :updated_balance, last_paid_timestamp = :last_paid, pending_payment_transaction = :transaction where wallet_address = :wallet");
        assert_eq!(insert_sql,"insert into payable (balance, last_paid_timestamp, pending_payment_transaction, wallet_address) values (:balance, :last_paid, :transaction, :wallet)");
        assert_eq!(table, Table::Payable);
        assert_eq!(
            sql_param_names,
            convert_to_all_string_values(vec![
                (":wallet", wallet_address),
                (":balance", &supplied_amount_wei.to_string()),
                (":last_paid", &last_received_time_stamp_sec.to_string()),
                (":transaction", tx_hash)
            ])
        )
    }

    #[test]
    fn update_handles_error_for_insert_update_config() {
        let wallet_address = "a11122";
        let conn = Connection::open_in_memory().unwrap();
        let wrapped_conn = ConnectionWrapperReal::new(conn);
        create_broken_payable(&wrapped_conn);
        let amount_wei = 100_i128;
        let update_config = InsertUpdateConfig {
            insert_sql: "",
            update_sql: "",
            params: SQLExtParams::new(
                vec![(":wallet", &wallet_address), (":balance", &amount_wei)],
            ),
            table:Table::Payable,
        };

        let result = InsertUpdateCoreReal.update(Either::Left(&wrapped_conn), &update_config);

        assert_eq!(result, Err("Updating balance for payable of 100 Wei to a11122; failing on: 'Query returned no rows'".to_string()));
    }

    #[test]
    fn update_handles_error_on_a_row_due_to_unfitting_data_types() {
        let wallet_address = "a11122";
        let path = ensure_node_home_directory_exists(
            "dao_shared_methods",
            "update_handles_error_on_a_row_due_to_unfitting_data_types",
        );
        let conn = DbInitializerReal::default()
            .initialize(&path, true, MigratorConfig::test_default())
            .unwrap();
        let conn_ref = conn.as_ref();
        insert_payable_balance_last_time_stamp_transaction_hash_with_bad_data_types(
            conn_ref,
            wallet_address,
        );
        let amount_wei = 100_i128;
        let last_received_time_stamp_sec = 123_i64;
        let update_config = UpdateConfig {
            update_sql: "update receivable set balance = :updated_balance, last_received_timestamp = :last_received where wallet_address = :wallet",
            params: SQLExtParams::new(vec![(":wallet", &wallet_address), (":balance", &amount_wei), (":last_received", &last_received_time_stamp_sec)]),
            table:Table::Payable,
        };

        let result = InsertUpdateCoreReal.update(Either::Left(conn_ref), &update_config);

        assert_eq!(result, Err("Updating balance for payable of 100 Wei to a11122; failing on: 'Invalid column type Text at index: 0, name: balance'".to_string()));
    }

    #[test]
    fn update_handles_error_on_a_row_due_to_bad_sql_params() {
        let wallet_address = "a11122";
        let path = ensure_node_home_directory_exists(
            "dao_shared_methods",
            "update_handles_error_on_a_row_due_to_bad_sql_params",
        );
        let conn = DbInitializerReal::default()
            .initialize(&path, true, MigratorConfig::test_default())
            .unwrap();
        let conn_ref = conn.as_ref();
        let mut stm = conn_ref.prepare("insert into payable (wallet_address, balance, last_paid_timestamp, pending_payment_transaction) values (?,?,strftime('%s','now'),null)").unwrap();
        stm.execute(params![wallet_address, 45245_i128]).unwrap();
        let amount_wei = 100_i128;
        let last_received_time_stamp_sec = 123_i64;
        let update_config = UpdateConfig {
            update_sql: "update receivable set balance = ?, last_received_timestamp = ? where wallet_address = ?",
            params: SQLExtParams::new( vec![(":woodstock", &wallet_address), (":hendrix", &last_received_time_stamp_sec), (":wallet", &wallet_address), (":balance", &amount_wei)]),
            table:Table::Payable,
        };

        let result = InsertUpdateCoreReal.update(Either::Left(conn_ref), &update_config);

        assert_eq!(result, Err("Updating balance for payable of 100 Wei to a11122; failing on: 'Invalid parameter name: :updated_balance'".to_string()));
    }

    #[test]
    fn reverse_sign_works_for_min_value() {
        let result = reverse_sign(i128::MIN);

        assert_eq!(
            result,
            Err(SignConversionError::I128(String::from(
                "Reversing the sign for value: -170141183460469231731687303715884105728"
            )))
        )
    }

    fn create_broken_receivable(conn: &dyn ConnectionWrapper) {
        let mut stm = conn
            .prepare(
                "create table receivable (
                wallet_address integer primary key,
                balance text null,
                last_received_timestamp integer not null
            )",
            )
            .unwrap();
        stm.execute([]).unwrap();
    }

    fn create_broken_payable(conn: &dyn ConnectionWrapper) {
        let mut stm = conn
            .prepare(
                "create table payable (
                wallet_address integer primary key,
                balance text not null,
                last_paid_timestamp integer not null,
                pending_payment_transaction integer null
            )",
            )
            .unwrap();
        stm.execute([]).unwrap();
    }

    fn insert_receivable_100_balance_100_last_time_stamp(
        conn: &dyn ConnectionWrapper,
        wallet: &str,
    ) {
        let params = named_params! {
            ":wallet":wallet,
            ":balance":100_i128,
            ":last_time_stamp":100_i64
        };
        let mut stm = conn.prepare("insert into receivable (wallet_address, balance, last_received_timestamp) values (:wallet,:balance,:last_time_stamp)").unwrap();
        stm.execute(params).unwrap();
    }

    fn insert_payable_100_balance_100_last_time_stamp_transaction_hash_abc(
        conn: &dyn ConnectionWrapper,
        wallet: &str,
    ) {
        let params = named_params! {
            ":wallet":wallet,
            ":balance":100_i128,
            ":last_time_stamp":100_i64,
            ":pending_payment_hash":"abc"
        };
        let mut stm = conn.prepare("insert into payable (wallet_address, balance, last_paid_timestamp, pending_payment_transaction) values (:wallet,:balance,:last_time_stamp,:pending_payment_hash)").unwrap();
        stm.execute(params).unwrap();
    }

    fn insert_payable_balance_last_time_stamp_transaction_hash_with_bad_data_types(
        conn: &dyn ConnectionWrapper,
        wallet: &str,
    ) {
        let params = named_params! {
            ":wallet":wallet,
            ":balance":"bubblebooo",
            ":last_time_stamp":"genesis",
            ":pending_payment_hash":45
        };
        let mut stm = conn.prepare("insert into payable (wallet_address, balance, last_paid_timestamp, pending_payment_transaction) values (:wallet,:balance,:last_time_stamp,:pending_payment_hash)").unwrap();
        stm.execute(params).unwrap();
    }

    fn read_row_receivable(
        conn: &dyn ConnectionWrapper,
        wallet_address: &str,
    ) -> rusqlite::Result<(i128, i64)> {
        let mut stm = conn
            .prepare(
                "select balance, last_received_timestamp from receivable where wallet_address = ?",
            )
            .unwrap();
        stm.query_row([wallet_address], |row| {
            let balance: rusqlite::Result<i128> = row.get(0);
            let last_received_timestamp = row.get(1);
            Ok((balance.unwrap(), last_received_timestamp.unwrap()))
        })
    }

    fn read_row_payable(
        conn: &dyn ConnectionWrapper,
        wallet_address: &str,
    ) -> rusqlite::Result<(i128, i64, Option<String>)> {
        let mut stm = conn.prepare("select balance, last_paid_timestamp, pending_payment_transaction from payable where wallet_address = ?").unwrap();
        stm.query_row([wallet_address], |row| {
            let balance: rusqlite::Result<i128> = row.get(0);
            let last_received_timestamp = row.get(1);
            let pending_transaction_hash: rusqlite::Result<Option<String>> = row.get(2);
            Ok((
                balance.unwrap(),
                last_received_timestamp.unwrap(),
                pending_transaction_hash.unwrap(),
            ))
        })
    }

    fn is_timely_around(time_stamp: i64) -> bool {
        let new_now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        (new_now - 3) < time_stamp && time_stamp <= new_now
    }
}
