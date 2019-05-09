// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use crate::database::dao_utils;
use crate::database::db_initializer::ConnectionWrapper;
use crate::sub_lib::wallet::Wallet;
use rusqlite::types::ToSql;
use rusqlite::OptionalExtension;
use std::fmt::Debug;
use std::time::SystemTime;

#[derive(Debug, PartialEq)]
pub struct ReceivableAccount {
    pub wallet_address: Wallet,
    pub balance: i64,
    pub last_received_timestamp: SystemTime,
}

pub trait ReceivableDao: Debug {
    fn more_money_receivable(&self, wallet_address: &Wallet, amount: u64);

    fn more_money_received(&self, wallet_address: &Wallet, amount: u64, timestamp: &SystemTime);

    fn account_status(&self, wallet_address: &Wallet) -> Option<ReceivableAccount>;

    fn receivables(&self) -> Vec<ReceivableAccount>;
}

#[derive(Debug)]
pub struct ReceivableDaoReal {
    conn: Box<ConnectionWrapper>,
}

impl ReceivableDao for ReceivableDaoReal {
    fn more_money_receivable(&self, wallet_address: &Wallet, amount: u64) {
        match self.try_update(wallet_address, amount) {
            Ok(true) => (),
            Ok(false) => match self.try_insert(wallet_address, amount) {
                Ok(_) => (),
                Err(e) => panic!("Database is corrupt: {}", e),
            },
            Err(e) => panic!("Database is corrupt: {}", e),
        };
    }

    fn more_money_received(&self, _wallet_address: &Wallet, _amount: u64, _timestamp: &SystemTime) {
        unimplemented!()
    }

    fn account_status(&self, wallet_address: &Wallet) -> Option<ReceivableAccount> {
        let mut stmt = self
            .conn
            .prepare(
                "select balance, last_received_timestamp from receivable where wallet_address = ?",
            )
            .expect("Internal error");
        match stmt
            .query_row(&[wallet_address.address.clone()], |row| {
                Ok((row.get_unwrap(0), row.get_unwrap(1)))
            })
            .optional()
        {
            Ok(Some((Some(balance), Some(timestamp)))) => Some(ReceivableAccount {
                wallet_address: wallet_address.clone(),
                balance,
                last_received_timestamp: dao_utils::from_time_t(timestamp),
            }),
            Ok(Some(e)) => panic!("Database is corrupt: {:?}", e),
            Ok(None) => None,
            Err(e) => panic!("Database is corrupt: {:?}", e),
        }
    }

    fn receivables(&self) -> Vec<ReceivableAccount> {
        let mut stmt = self
            .conn
            .prepare("select balance, last_received_timestamp, wallet_address from receivable")
            .expect("Internal error");

        stmt.query_map(&[] as &[&ToSql], |row| {
            Ok(ReceivableAccount {
                balance: row.get_unwrap(0),
                last_received_timestamp: dao_utils::from_time_t(row.get_unwrap(1)),
                wallet_address: Wallet::new(&row.get_unwrap::<usize, String>(2)),
            })
        })
        .expect("Database is corrupt")
        .map(|p| p.expect("Database is corrupt"))
        .collect()
    }
}

impl ReceivableDaoReal {
    pub fn new(conn: Box<ConnectionWrapper>) -> ReceivableDaoReal {
        ReceivableDaoReal { conn }
    }

    fn try_update(&self, wallet_address: &Wallet, amount: u64) -> Result<bool, String> {
        let mut stmt = self
            .conn
            .prepare("update receivable set balance = balance + ? where wallet_address = ?")
            .expect("Internal error");
        let params: &[&ToSql] = &[&(amount as i64), &wallet_address.address];
        match stmt.execute(params) {
            Ok(0) => Ok(false),
            Ok(_) => Ok(true),
            Err(e) => Err(format!("{}", e)),
        }
    }

    fn try_insert(&self, wallet_address: &Wallet, amount: u64) -> Result<(), String> {
        let timestamp = dao_utils::to_time_t(&SystemTime::now());
        let mut stmt = self.conn.prepare ("insert into receivable (wallet_address, balance, last_received_timestamp) values (?, ?, ?)").expect ("Internal error");
        let params: &[&ToSql] = &[
            &wallet_address.address,
            &(amount as i64),
            &(timestamp as i64),
        ];
        match stmt.execute(params) {
            Ok(_) => Ok(()),
            Err(e) => Err(format!("{}", e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::db_initializer;
    use crate::database::db_initializer::DbInitializer;
    use crate::database::db_initializer::DbInitializerReal;
    use crate::test_utils::test_utils::ensure_node_home_directory_exists;
    use rusqlite::NO_PARAMS;
    use rusqlite::{Connection, OpenFlags};

    #[test]
    fn more_money_receivable_works_for_new_address() {
        let home_dir = ensure_node_home_directory_exists(
            "accountant",
            "more_money_receivable_works_for_new_address",
        );
        let before = dao_utils::to_time_t(&SystemTime::now());
        let wallet = Wallet::new("booga");
        let status = {
            let subject =
                ReceivableDaoReal::new(DbInitializerReal::new().initialize(&home_dir).unwrap());

            subject.more_money_receivable(&wallet, 1234);
            subject.account_status(&wallet).unwrap()
        };

        let after = dao_utils::to_time_t(&SystemTime::now());
        assert_eq!(status.wallet_address, wallet);
        assert_eq!(status.balance, 1234);
        let timestamp = dao_utils::to_time_t(&status.last_received_timestamp);
        assert!(
            timestamp >= before,
            "{:?} should be on or after {:?}",
            timestamp,
            before
        );
        assert!(
            timestamp <= after,
            "{:?} should be on or before {:?}",
            timestamp,
            after
        );
    }

    #[test]
    fn more_money_receivable_works_for_existing_address() {
        let home_dir = ensure_node_home_directory_exists(
            "accountant",
            "more_money_receivable_works_for_existing_address",
        );
        let wallet = Wallet::new("booga");
        let subject = {
            let subject =
                ReceivableDaoReal::new(DbInitializerReal::new().initialize(&home_dir).unwrap());
            subject.more_money_receivable(&wallet, 1234);
            let mut flags = OpenFlags::empty();
            flags.insert(OpenFlags::SQLITE_OPEN_READ_WRITE);
            let conn =
                Connection::open_with_flags(&home_dir.join(db_initializer::DATABASE_FILE), flags)
                    .unwrap();
            conn.execute(
                "update receivable set last_received_timestamp = 0 where wallet_address = 'booga'",
                NO_PARAMS,
            )
            .unwrap();
            subject
        };

        let status = {
            subject.more_money_receivable(&wallet, 2345);
            subject.account_status(&wallet).unwrap()
        };

        assert_eq!(status.wallet_address, wallet);
        assert_eq!(status.balance, 3579);
        assert_eq!(status.last_received_timestamp, SystemTime::UNIX_EPOCH);
    }

    #[test]
    fn receivable_account_status_works_when_account_doesnt_exist() {
        let home_dir = ensure_node_home_directory_exists(
            "accountant",
            "receivable_account_status_works_when_account_doesnt_exist",
        );
        let wallet = Wallet::new("booga");
        let subject =
            ReceivableDaoReal::new(DbInitializerReal::new().initialize(&home_dir).unwrap());

        let result = subject.account_status(&wallet);

        assert_eq!(result, None);
    }

    #[test]
    fn receivables_fetches_all_receivable_accounts() {
        let home_dir = ensure_node_home_directory_exists(
            "accountant",
            "receivables_fetches_all_receivable_accounts",
        );
        let wallet1 = Wallet::new("wallet1");
        let wallet2 = Wallet::new("wallet2");
        let time_stub = SystemTime::now();

        let subject =
            ReceivableDaoReal::new(DbInitializerReal::new().initialize(&home_dir).unwrap());

        subject.more_money_receivable(&wallet1, 1234);
        subject.more_money_receivable(&wallet2, 2345);

        let accounts = subject
            .receivables()
            .into_iter()
            .map(|r| ReceivableAccount {
                last_received_timestamp: time_stub,
                ..r
            })
            .collect::<Vec<ReceivableAccount>>();

        assert_eq!(
            vec![
                ReceivableAccount {
                    wallet_address: wallet1,
                    balance: 1234,
                    last_received_timestamp: time_stub
                },
                ReceivableAccount {
                    wallet_address: wallet2,
                    balance: 2345,
                    last_received_timestamp: time_stub
                },
            ],
            accounts
        )
    }
}
