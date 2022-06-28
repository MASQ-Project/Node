// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
use crate::accountant::payable_dao::PayableAccount;
use crate::accountant::receivable_dao::ReceivableAccount;
use crate::accountant::{checked_conversion, sign_conversion};
use crate::database::connection_wrapper::ConnectionWrapper;
use crate::database::db_initializer::{connection_or_panic, DbInitializerReal};
use crate::database::db_migrations::MigratorConfig;
use masq_lib::messages::{UiPayableAccount, UiReceivableAccount};
use masq_lib::utils::ExpectValue;
use rusqlite::{params_from_iter, Row, ToSql};
use std::cell::RefCell;
use std::fmt::Display;
use std::path::{Path, PathBuf};
use std::time::Duration;
use std::time::SystemTime;

pub fn to_time_t(system_time: SystemTime) -> i64 {
    match system_time.duration_since(SystemTime::UNIX_EPOCH) {
        Err(e) => unimplemented!("{}", e),
        Ok(d) => sign_conversion::<u64, i64>(d.as_secs()).expect("MASQNode has expired"),
    }
}

pub fn now_time_t() -> i64 {
    to_time_t(SystemTime::now())
}

pub fn from_time_t(time_t: i64) -> SystemTime {
    let interval = Duration::from_secs(time_t as u64);
    SystemTime::UNIX_EPOCH + interval
}

pub struct DaoFactoryReal {
    pub data_directory: PathBuf,
    pub create_if_necessary: bool,
    pub migrator_config: RefCell<Option<MigratorConfig>>,
}

impl DaoFactoryReal {
    pub fn new(
        data_directory: &Path,
        create_if_necessary: bool,
        migrator_config: MigratorConfig,
    ) -> Self {
        Self {
            data_directory: data_directory.to_path_buf(),
            create_if_necessary,
            migrator_config: RefCell::new(Some(migrator_config)),
        }
    }

    pub fn make_connection(&self) -> Box<dyn ConnectionWrapper> {
        connection_or_panic(
            &DbInitializerReal::default(),
            &self.data_directory,
            self.create_if_necessary,
            self.migrator_config.take().expectv("MigratorConfig"),
        )
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum CustomQuery<N> {
    TopRecords(u16),
    RangeQuery {
        min_age: u64,
        max_age: u64,
        min_amount: N,
        max_amount: N,
    },
}

impl<N: Copy + Display> CustomQuery<N> {
    pub fn query<R, S, F1, F2>(
        self,
        conn: &dyn ConnectionWrapper,
        main_stm_assembler: F1,
        variant_range: &str,
        variant_top: &str,
        value_fetcher: F2,
    ) -> Option<Vec<R>>
    where
        F1: Fn(&str, &str) -> String,
        F2: Fn(&Row) -> rusqlite::Result<R>,
        S: TryFrom<N> + ToSql,
    {
        let (finalized_stm, params) = match self {
            Self::TopRecords(count) => (
                main_stm_assembler("", variant_top),
                vec![Box::new(count as i64) as Box<dyn ToSql>],
            ),
            Self::RangeQuery {
                min_age,
                max_age,
                min_amount,
                max_amount,
            } => {
                let now = to_time_t(SystemTime::now());
                let params: Vec<Box<dyn ToSql>> = vec![
                    Box::new(now - min_age as i64),
                    Box::new(now - max_age as i64),
                    Box::new(checked_conversion::<N, S>(min_amount)),
                    Box::new(checked_conversion::<N, S>(max_amount)),
                ];
                (main_stm_assembler(variant_range, ""), params)
            }
        };
        match conn
            .prepare(&finalized_stm)
            .expect("select statement is wrong")
            .query_map(
                params_from_iter(params.iter().map(|param| param.as_ref())),
                value_fetcher,
            ) {
            Ok(accounts) => {
                let vectored = accounts.flatten().collect::<Vec<R>>();
                if vectored.is_empty() {
                    None
                } else {
                    Some(vectored)
                }
            }
            Err(e) => panic!("database corrupt: {}", e),
        }
    }
}

pub fn remap_payable_accounts(accounts: Vec<PayableAccount>) -> Vec<UiPayableAccount> {
    accounts
        .into_iter()
        .map(|account| UiPayableAccount {
            wallet: account.wallet.to_string(),
            age: (to_time_t(SystemTime::now()) - to_time_t(account.last_paid_timestamp)) as u64,
            balance: account.balance,
            pending_payable_hash_opt: account
                .pending_payable_opt
                .map(|full_id| full_id.hash.to_string()),
        })
        .collect()
}

pub fn remap_receivable_accounts(accounts: Vec<ReceivableAccount>) -> Vec<UiReceivableAccount> {
    accounts
        .into_iter()
        .map(|account| UiReceivableAccount {
            wallet: account.wallet.to_string(),
            age: (to_time_t(SystemTime::now()) - to_time_t(account.last_received_timestamp)) as u64,
            balance: account.balance,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::connection_wrapper::ConnectionWrapperReal;
    use masq_lib::test_utils::utils::ensure_node_home_directory_exists;
    use rusqlite::{Connection, OpenFlags};
    use std::str::FromStr;

    #[test]
    #[should_panic(expected = "Failed to connect to database at \"nonexistent")]
    fn connection_panics_if_connection_cannot_be_made() {
        let subject = DaoFactoryReal::new(
            &PathBuf::from_str("nonexistent").unwrap(),
            false,
            MigratorConfig::test_default(),
        );

        let _ = subject.make_connection();
    }

    #[test]
    #[should_panic(
        expected = "database corrupt: Wrong number of parameters passed to query. Got 1, needed 0"
    )]
    fn erroneous_query_leads_to_panic() {
        let home_dir =
            ensure_node_home_directory_exists("dao_utils", "erroneous_query_leads_to_panic");
        let db_path = home_dir.join("test.db");
        let creation_conn = Connection::open(db_path.as_path()).unwrap();
        creation_conn
            .execute(
                "create table fruits (kind text primary key, price integer not null)",
                [],
            )
            .unwrap();
        let conn_read_only =
            Connection::open_with_flags(db_path, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
        let conn_wrapped = ConnectionWrapperReal::new(conn_read_only);
        let subject = CustomQuery::<u128>::TopRecords(12);

        let _ = subject.query::<_, i128, _, _>(
            &conn_wrapped,
            |_v1: &str, _v2: &str| "select kind, price from fruits".to_string(),
            "",
            "",
            |_row| Ok(()),
        );
    }
}
