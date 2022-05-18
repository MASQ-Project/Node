// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::payable_dao::PayableDaoError;
use crate::accountant::receivable_dao::ReceivableDaoError;
use crate::database::connection_wrapper::ConnectionWrapper;
use crate::sub_lib::accountant::SignConversionError;
use itertools::{Either, Itertools};
use masq_lib::utils::ExpectValue;
use rusqlite::ErrorCode::ConstraintViolation;
use rusqlite::{Error, Row, Statement, ToSql, Transaction};
use std::any::Any;
use std::cell::RefCell;
use std::fmt::{Display, Formatter};
use std::ops::Neg;
use rusqlite::types::ToSqlOutput;
use crate::accountant::checked_conversion;
use crate::sub_lib::wallet::Wallet;

pub trait InsertUpdateCore {
    fn update<'a>(
        &self,
        conn: Either<&dyn ConnectionWrapper, &Transaction>,
        config: &'a (dyn UpdateConfiguration<'a> + 'a),
    ) -> Result<(), InsertUpdateError>;
    fn upsert<'a>(
        &self,
        conn: &dyn ConnectionWrapper,
        config: InsertUpdateConfig<'a>,
    ) -> Result<(), InsertUpdateError>;
}

pub trait FetchValue<'a> {
    fn fetch_balance_change(&'a self) -> Result<i128, InsertUpdateError>;
    fn fetch_key(&'a self) -> Result<(String,Box<dyn ExtendedParamsMarker>), InsertUpdateError>;
}

type ExtendedParamsVec<'a> = &'a Vec<(&'a str, &'a dyn ExtendedParamsMarker)>;

pub trait ExtendedParamsMarker: ToSql + Display {
    fn countable_as_any(&self) -> &dyn Any {
        intentionally_blank!()
    }
    fn get_key(&self)->Option<Box<dyn ExtendedParamsMarker>>{
        todo!() //false
    }
}

pub struct InsertUpdateCoreReal;

impl InsertUpdateCore for InsertUpdateCoreReal {
    fn update<'a>(
        &self,
        form_of_conn: Either<&dyn ConnectionWrapper, &Transaction>,
        config: &'a (dyn UpdateConfiguration<'a> + 'a),
    ) -> Result<(), InsertUpdateError> {
        let present_state_query = config.select_sql();
        let mut statement = Self::prepare_statement(form_of_conn, present_state_query.as_str());
        let update_params = config.update_params().params();
        let ((key_name,key_value), balance_change) = Self::fetch_fundamentals(update_params)?;
        match statement.query_row(&[(&*key_name, &key_value as &dyn ToSql)], |row| {
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
            Err(e) => Err(InsertUpdateError(format!(
                "Updating balance for {} of {} Wei to {}; failing on: '{}'",
                config.table(),
                balance_change,
                key_value,
                e
            ))),
        }
    }

    fn upsert(
        &self,
        conn: &dyn ConnectionWrapper,
        config: InsertUpdateConfig,
    ) -> Result<(), InsertUpdateError> {
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
                let ((_,key_value), amount) = Self::fetch_fundamentals(params)?;
                Err(InsertUpdateError(format!(
                    "Updating balance after invalid insertion for {} of {} Wei to {}; failing on: '{}'",
                    config.table, amount, key_value, e
                )))
            }
        }
    }
}

impl InsertUpdateCoreReal {
    fn fetch_fundamentals(
        params: ExtendedParamsVec<'_>,
    ) -> Result<((String,Box<dyn ExtendedParamsMarker>), i128), InsertUpdateError> {
        Ok((params.fetch_key()?, params.fetch_balance_change()?))
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

pub struct InsertUpdateConfig<'a> {
    pub insert_sql: &'a str,
    pub update_sql: &'a str,
    pub params: SQLExtParams<'a>,
    pub table: Table,
}

pub struct UpdateConfig<'a> {
    pub update_sql: &'a str,
    pub params: SQLExtParams<'a>,
    pub table: Table,
}

//please don't implement for i128 instead use BalanceChange as intended
impl ExtendedParamsMarker for i64 {}
impl ExtendedParamsMarker for &str {}
impl ExtendedParamsMarker for Wallet{}
impl ExtendedParamsMarker for BalanceChange {
    fn countable_as_any(&self) -> &dyn Any {
        self
    }
}
impl ExtendedParamsMarker for ParamKeyWrapper {
    fn get_key(&self) -> Option<Box<dyn ExtendedParamsMarker>> {
        todo!()
    }
}

impl ToSql for BalanceChange {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
        todo!()
    }
}

impl Display for BalanceChange {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f,"{}",self.change)
    }
}

impl ToSql for ParamKeyWrapper {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
        todo!() //will be fun hahaha
    }
}

impl Display for ParamKeyWrapper {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f,"{}",self.param.borrow_mut().as_ref().expectv("inner ExtendedParamsMarker")) //TODO do we really need this?
    }
}

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

impl<'a> FetchValue<'a> for ExtendedParamsVec<'a> {
    fn fetch_balance_change(&'a self) -> Result<i128, InsertUpdateError> {
        match self
            .iter()
            .find(|(param_name, _)| *param_name == ":balance")
        {
            Some((_, value)) => Ok({
                let balance_change: &BalanceChange = value.countable_as_any().downcast_ref().expectv("BalanceChange");
                balance_change.change
            }),
            None => Err(InsertUpdateError(
                "Missing parameter and value for the change in balance".to_string(),
            )),
        }
    }

    fn fetch_key(&'a self) -> Result<(String, Box<dyn ExtendedParamsMarker>), InsertUpdateError> {
        match self.iter().fold(None,|acc: Option<Box<dyn ExtendedParamsMarker>>,(_,key_candidate )|
            match acc {
                Some(x) => todo!(),
                None => match key_candidate.get_key(){
                    Some(value) => todo!(), //value.get_key().expectv("key value")),
                    None => todo!(),
                }
            }){
            Some(x) => todo!(),
            None => todo!()
        }
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

pub fn get_unsized_128(row: &Row, index: usize) -> Result<u128, rusqlite::Error> {
    row.get::<usize, i128>(index).map(|val| val as u128)
}


#[derive(PartialEq, Debug)]
pub struct BalanceChange {
    change:i128
}

impl BalanceChange {
    pub fn new_addition(abs_change: u128)->Self{
        Self{change: checked_conversion::<u128,i128>(abs_change)}
    }
    pub fn new_subtraction(abs_change: u128)->Self{
        Self{change: checked_conversion::<u128,i128>(abs_change).neg()}
    }
}

pub struct ParamKeyWrapper{
    param: RefCell<Option<Box<dyn ExtendedParamsMarker>>>
}

impl ParamKeyWrapper {
    pub fn new(inner_value: Box<dyn ExtendedParamsMarker>)->Self{
        Self{ param: RefCell::new(Some(inner_value)) }
    }
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

#[derive(Debug, PartialEq)]
pub struct InsertUpdateError(pub String);

impl From<InsertUpdateError> for PayableDaoError {
    fn from(iu_err: InsertUpdateError) -> Self {
        PayableDaoError::RusqliteError(iu_err.0)
    }
}

impl From<InsertUpdateError> for ReceivableDaoError {
    fn from(iu_err: InsertUpdateError) -> Self {
        ReceivableDaoError::RusqliteError(iu_err.0)
    }
}

//TODO after you move the tests rename the modules of home dirs to the right ones

#[cfg(test)]
mod tests {
    use std::ops::Neg;
    use super::*;
    use crate::database::connection_wrapper::{ConnectionWrapper, ConnectionWrapperReal};
    use crate::database::db_initializer::{DbInitializer, DbInitializerReal};
    use crate::database::db_migrations::MigratorConfig;
    use itertools::{Either, Itertools};
    use masq_lib::test_utils::utils::ensure_node_home_directory_exists;
    use rusqlite::types::ToSqlOutput;
    use rusqlite::{named_params, params, Connection, ToSql};
    use crate::test_utils::make_wallet;

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

    #[test]
    fn finalize_update_params_for_update_config_works() {
        let balance_change = BalanceChange::new_addition(5555);
        let subject = UpdateConfig {
            update_sql: "blah",
            params: SQLExtParams::new(vec![
                (":something", &152_i64),
                (":balance", &balance_change),
                (":something_else", &"foooo"),
            ]),
            table: Table::Payable,
        };

        finalize_update_params_assertion(&subject)
    }

    #[test]
    fn finalize_update_params_for_insert_update_config_works() {
        let balance_change = BalanceChange::new_addition(5555);
        let subject = InsertUpdateConfig {
            insert_sql: "blah1",
            update_sql: "blah2",
            params: SQLExtParams::new(vec![
                (":something", &152_i64),
                (":balance",&balance_change),
                (":something_else", &"foooo"),
            ]),
            table: Table::Payable,
        };

        finalize_update_params_assertion(&subject)
    }

    fn finalize_update_params_assertion<'a>(subject: &'a dyn UpdateConfiguration<'a>) {
        let updated_balance = 456789;
        let balance_change = BalanceChange::new_addition(updated_balance as u128);

        let result = subject.finalize_update_params(
            &updated_balance,
            subject.update_params().all_rusqlite_params(),
        );

        let expected_params: Vec<(&str, &dyn ToSql)> = vec![
            (":something", &152_i64),
            (":updated_balance", &balance_change),
            (":something_else", &"foooo"),
        ];
        let expected_assertable = convert_params_to_debuggable_values(expected_params);
        let result_assertable = convert_params_to_debuggable_values(result);
        assert_eq!(result_assertable, expected_assertable)
    }

    #[test]
    fn fetch_balance_change_works() {
        let balance_change = BalanceChange::new_addition(5021);
        let params: ExtendedParamsVec =  &vec![(":something", &"yo-yo"), (":balance",&balance_change), (":something_else", &55_i64)];

        let result = params.fetch_balance_change();

        assert_eq!(result,Ok(5021))
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
            &|subject| subject.fetch_key(),
            String::from("Missing parameter and value for the wallet address"),
        );
    }

    fn fetch_param_assertion<T>(
        act: &dyn Fn(ExtendedParamsVec) -> Result<T, InsertUpdateError>,
        expected_err_msg: String,
    ) {
        let subject = &some_meaningless_params();

        let result = act(subject);

        let result = match result {
            Ok(_) => panic!("we expected Err but got Ok"),
            Err(e) => e,
        };
        assert_eq!(result.0, expected_err_msg)
    }

    fn some_meaningless_params<'a>() -> Vec<(&'a str, &'a dyn ExtendedParamsMarker)> {
        vec![(":something", &"yo-yo"), (":something_else", &55_i64)]
    }

    #[test]
    fn conversion_from_insert_update_error_to_particular_payable_dao_error_works() {
        let subject = InsertUpdateError(String::from("whatever"));

        let result: PayableDaoError = subject.into();

        assert_eq!(
            result,
            PayableDaoError::RusqliteError("whatever".to_string())
        )
    }

    #[test]
    fn conversion_from_insert_update_error_to_particular_receivable_dao_error_works() {
        let subject = InsertUpdateError(String::from("whatever"));

        let result: ReceivableDaoError = subject.into();

        assert_eq!(
            result,
            ReceivableDaoError::RusqliteError("whatever".to_string())
        )
    }

    #[test]
    fn constructor_for_balance_change_works_for_addition(){
        let addition = BalanceChange::new_addition(50);

        assert_eq!(addition, BalanceChange{change: 50_i128});
    }

    //loosing one unit but I can dare it, such an amount of our tokens doesn't exist
    #[test]
    fn constructor_for_balance_change_works_for_subtraction(){
        let subtraction = BalanceChange::new_subtraction(i128::MIN as u128 - 1);

        assert_eq!(subtraction, BalanceChange{change: i128::MIN + 1})
    }

    #[test]
    fn display_for_balance_change_works(){
        let subtraction = BalanceChange::new_subtraction(100);
        let addition = BalanceChange::new_addition(50);

        assert_eq!(subtraction.to_string(),"-100".to_string());
        assert_eq!(addition.to_string(),"50".to_string())
    }

    #[test]
    fn display_for_param_key_wrapper_works(){
        let wallet = make_wallet("booga");
        let key_wrapper_with_wallet = ParamKeyWrapper::new(Box::new(wallet.clone()));
        let rowid = 56_i64;
        let key_wrapper_with_rowid = ParamKeyWrapper::new(Box::new(rowid));

        assert_eq!(key_wrapper_with_wallet.to_string(),wallet.to_string());
        assert_eq!(key_wrapper_with_rowid.to_string(),rowid.to_string())
    }

    #[test]
    fn get_key_for_non_key_params_is_always_none(){
        todo!()
    }

    #[test]
    fn get_key_for_key_params_are_something(){
        todo!()
    }

    #[test]
    #[should_panic(expected="Overflow detected with 170141183460469231731687303715884105728: cannot be converted from u128 to i128")]
    fn balance_change_constructor_blows_up_on_overflow_in_addition(){
        let _ = BalanceChange::new_addition(i128::MAX as u128 + 1);
    }

    #[test]
    #[should_panic(expected="Overflow detected with 170141183460469231731687303715884105728: cannot be converted from u128 to i128")]
    fn balance_change_constructor_blows_up_on_overflow_in_subtraction(){
        let _ = BalanceChange::new_subtraction(i128::MIN as u128);
    }

    #[test]
    fn update_handles_error_for_insert_update_config() {
        let wallet_address = "a11122";
        let conn = Connection::open_in_memory().unwrap();
        let wrapped_conn = ConnectionWrapperReal::new(conn);
        create_broken_payable(&wrapped_conn);
        let balance_change = BalanceChange::new_addition(100);
        let update_config = InsertUpdateConfig {
            insert_sql: "",
            update_sql: "",
            params: SQLExtParams::new(vec![
                (":wallet", &wallet_address),
                (":balance", &balance_change),
            ]),
            table: Table::Payable,
        };

        let result = InsertUpdateCoreReal.update(Either::Left(&wrapped_conn), &update_config);

        assert_eq!(result, Err(InsertUpdateError("Updating balance for payable of 100 Wei to a11122; failing on: 'Query returned no rows'".to_string())));
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
        insert_payable_with_bad_data_types(conn_ref, wallet_address);
        let balance_change = BalanceChange::new_addition(100);
        let last_received_time_stamp_sec = 123_i64;
        let update_config = UpdateConfig {
            update_sql: "update receivable set balance = :updated_balance, last_received_timestamp = :last_received where wallet_address = :wallet",
            params: SQLExtParams::new(vec![(":wallet", &wallet_address), (":balance", &balance_change), (":last_received", &last_received_time_stamp_sec)]),
            table:Table::Payable,
        };

        let result = InsertUpdateCoreReal.update(Either::Left(conn_ref), &update_config);

        assert_eq!(result, Err(InsertUpdateError("Updating balance for payable of 100 Wei to a11122; failing on: 'Invalid column type Text at index: 0, name: balance'".to_string())));
    }

    #[test]
    fn update_handles_error_of_bad_sql_params() {
        let wallet_address = "a11122";
        let path = ensure_node_home_directory_exists(
            "dao_shared_methods",
            "update_handles_error_of_bad_sql_params",
        );
        let conn = DbInitializerReal::default()
            .initialize(&path, true, MigratorConfig::test_default())
            .unwrap();
        let conn_ref = conn.as_ref();
        let mut stm = conn_ref.prepare("insert into payable (wallet_address, balance, last_paid_timestamp, pending_payable_rowid) values (?,?,strftime('%s','now'),null)").unwrap();
        stm.execute(params![wallet_address, 45245_i128]).unwrap();
        let balance_change= BalanceChange::new_addition(100);
        let last_received_time_stamp_sec = 123_i64;
        let update_config = UpdateConfig {
            update_sql: "update receivable set balance = ?, last_received_timestamp = ? where wallet_address = ?",
            params: SQLExtParams::new( vec![(":woodstock", &wallet_address), (":hendrix", &last_received_time_stamp_sec), (":wallet", &wallet_address), (":balance", &balance_change)]),
            table:Table::Payable,
        };

        let result = InsertUpdateCoreReal.update(Either::Left(conn_ref), &update_config);

        assert_eq!(result, Err(InsertUpdateError("Updating balance for payable of 100 Wei to a11122; failing on: 'Invalid parameter name: :updated_balance'".to_string())));
    }

    //TODO are upsert detailed tests missing???

    fn insert_payable_with_bad_data_types(conn: &dyn ConnectionWrapper, wallet: &str) {
        let params = named_params! {
            ":wallet":wallet,
            ":balance":"bubblebooo",
            ":last_time_stamp":"genesis",
            ":pending_payable_rowid":45_i64
        };
        insert_into_payable(conn, params)
    }

    //TODO sometimes these utils are used just once, check it and maybe deutilize
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

    fn insert_into_payable(conn: &dyn ConnectionWrapper, params: &[(&str, &dyn ToSql)]) {
        let mut stm = conn.prepare("insert into payable (wallet_address, balance, last_paid_timestamp, pending_payable_rowid) values (:wallet,:balance,:last_time_stamp,:pending_payable_rowid)").unwrap();
        stm.execute(params).unwrap();
    }
}
