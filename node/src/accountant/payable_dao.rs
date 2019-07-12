// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use crate::database::dao_utils;
use crate::database::db_initializer::ConnectionWrapper;
use crate::sub_lib::wallet::Wallet;
use rusqlite::types::ToSql;
use rusqlite::{OptionalExtension, NO_PARAMS};
use std::fmt::Debug;
use std::time::SystemTime;

#[derive(Clone, Debug, PartialEq)]
pub struct PayableAccount {
    pub wallet: Wallet,
    pub balance: i64,
    pub last_paid_timestamp: SystemTime,
    pub pending_payment_transaction: Option<String>,
}

pub trait PayableDao: Debug + Send {
    fn more_money_payable(&self, wallet: &Wallet, amount: u64);

    fn payment_sent(&self, wallet: &Wallet, pending_payment_transaction: &str);

    fn payment_confirmed(
        &self,
        wallet: &Wallet,
        amount: u64,
        confirmation_noticed_timestamp: SystemTime,
    );

    fn account_status(&self, wallet: &Wallet) -> Option<PayableAccount>;

    fn non_pending_payables(&self) -> Vec<PayableAccount>;
}

#[derive(Debug)]
pub struct PayableDaoReal {
    conn: Box<ConnectionWrapper>,
}

impl PayableDao for PayableDaoReal {
    fn more_money_payable(&self, wallet: &Wallet, amount: u64) {
        match self.try_update(wallet, amount) {
            Ok(true) => (),
            Ok(false) => match self.try_insert(wallet, amount) {
                Ok(_) => (),
                Err(e) => panic!("Database is corrupt: {}", e),
            },
            Err(e) => panic!("Database is corrupt: {}", e),
        };
    }

    fn payment_sent(&self, _wallet: &Wallet, _pending_payment_transaction: &str) {
        unimplemented!()
    }

    fn payment_confirmed(
        &self,
        _wallet: &Wallet,
        _amount: u64,
        _confirmation_noticed_timestamp: SystemTime,
    ) {
        unimplemented!()
    }

    fn account_status(&self, wallet: &Wallet) -> Option<PayableAccount> {
        let mut stmt = self.conn
            .prepare("select balance, last_paid_timestamp, pending_payment_transaction from payable where wallet_address = ?")
            .expect("Internal error");
        match stmt
            .query_row(&[&wallet], |row| {
                let balance_result = row.get(0);
                let last_paid_timestamp_result = row.get(1);
                let pending_payment_transaction_result = row.get(2);
                match (
                    balance_result,
                    last_paid_timestamp_result,
                    pending_payment_transaction_result,
                ) {
                    (Ok(balance), Ok(last_paid_timestamp), Ok(pending_payment_transaction)) => {
                        Ok(PayableAccount {
                            wallet: wallet.clone(),
                            balance,
                            last_paid_timestamp: dao_utils::from_time_t(last_paid_timestamp),
                            pending_payment_transaction,
                        })
                    }
                    _ => panic!("Database is corrupt: PAYABLE table columns and/or types"),
                }
            })
            .optional()
        {
            Ok(value) => value,
            Err(e) => panic!("Database is corrupt: {:?}", e),
        }
    }

    fn non_pending_payables(&self) -> Vec<PayableAccount> {
        let mut stmt = self.conn
            .prepare("select balance, last_paid_timestamp, wallet_address from payable where pending_payment_transaction is null")
            .expect("Internal error");

        stmt.query_map(NO_PARAMS, |row| {
            let balance_result = row.get(0);
            let last_paid_timestamp_result = row.get(1);
            let wallet_result: Result<Wallet, rusqlite::Error> = row.get(2);
            match (balance_result, last_paid_timestamp_result, wallet_result) {
                (Ok(balance), Ok(last_paid_timestamp), Ok(wallet)) => Ok(PayableAccount {
                    wallet,
                    balance,
                    last_paid_timestamp: dao_utils::from_time_t(last_paid_timestamp),
                    pending_payment_transaction: None,
                }),
                _ => panic!("Database is corrupt: PAYABLE table columns and/or types"),
            }
        })
        .expect("Database is corrupt")
        .flat_map(|v| v)
        .collect()
    }
}

impl PayableDaoReal {
    pub fn new(conn: Box<ConnectionWrapper>) -> PayableDaoReal {
        PayableDaoReal { conn }
    }

    fn try_update(&self, wallet: &Wallet, amount: u64) -> Result<bool, String> {
        let mut stmt = self
            .conn
            .prepare("update payable set balance = balance + ? where wallet_address = ?")
            .expect("Internal error");
        let params: &[&dyn ToSql] = &[&(amount as i64), &wallet];
        match stmt.execute(params) {
            Ok(0) => Ok(false),
            Ok(_) => Ok(true),
            Err(e) => Err(format!("{}", e)),
        }
    }

    fn try_insert(&self, wallet: &Wallet, amount: u64) -> Result<(), String> {
        let timestamp = dao_utils::to_time_t(SystemTime::now());
        let mut stmt = self.conn
            .prepare("insert into payable (wallet_address, balance, last_paid_timestamp, pending_payment_transaction) values (?, ?, ?, null)")
            .expect("Internal error");
        let params: &[&dyn ToSql] = &[&wallet, &(amount as i64), &(timestamp as i64)];
        match stmt.execute(params) {
            Ok(_) => Ok(()),
            Err(e) => Err(format!("{}", e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::dao_utils::from_time_t;
    use crate::database::db_initializer;
    use crate::database::db_initializer::{DbInitializer, DbInitializerReal};
    use crate::test_utils::{ensure_node_home_directory_exists, make_wallet};
    use rusqlite::NO_PARAMS;
    use rusqlite::{Connection, OpenFlags};

    #[test]
    fn more_money_payable_works_for_new_address() {
        let home_dir = ensure_node_home_directory_exists(
            "accountant",
            "more_money_payable_works_for_new_address",
        );
        let before = dao_utils::to_time_t(SystemTime::now());
        let wallet = make_wallet("booga");
        let status = {
            let subject =
                PayableDaoReal::new(DbInitializerReal::new().initialize(&home_dir).unwrap());

            subject.more_money_payable(&wallet, 1234);
            subject.account_status(&wallet).unwrap()
        };

        let after = dao_utils::to_time_t(SystemTime::now());
        assert_eq!(status.wallet, wallet);
        assert_eq!(status.balance, 1234);
        let timestamp = dao_utils::to_time_t(status.last_paid_timestamp);
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
    fn more_money_payable_works_for_existing_address() {
        let home_dir = ensure_node_home_directory_exists(
            "accountant",
            "more_money_payable_works_for_existing_address",
        );
        let wallet = make_wallet("booga");
        let subject = {
            let subject =
                PayableDaoReal::new(DbInitializerReal::new().initialize(&home_dir).unwrap());
            subject.more_money_payable(&wallet, 1234);
            let mut flags = OpenFlags::empty();
            flags.insert(OpenFlags::SQLITE_OPEN_READ_WRITE);
            let conn =
                Connection::open_with_flags(&home_dir.join(db_initializer::DATABASE_FILE), flags)
                    .unwrap();
            conn.execute(
                "update payable set last_paid_timestamp = 0 where wallet_address = '0x000000000000000000000000000000626f6f6761'",
                NO_PARAMS,
            )
            .unwrap();
            subject
        };

        let status = {
            subject.more_money_payable(&wallet, 2345);
            subject.account_status(&wallet).unwrap()
        };

        assert_eq!(status.wallet, wallet);
        assert_eq!(status.balance, 3579);
        assert_eq!(status.last_paid_timestamp, SystemTime::UNIX_EPOCH);
    }

    #[test]
    fn payable_account_status_works_when_account_doesnt_exist() {
        let home_dir = ensure_node_home_directory_exists(
            "accountant",
            "payable_account_status_works_when_account_doesnt_exist",
        );
        let wallet = make_wallet("booga");
        let subject = PayableDaoReal::new(DbInitializerReal::new().initialize(&home_dir).unwrap());

        let result = subject.account_status(&wallet);

        assert_eq!(result, None);
    }

    #[test]
    fn non_pending_payables_should_return_an_empty_vec_when_the_database_is_empty() {
        let home_dir = ensure_node_home_directory_exists(
            "accountant",
            "non_pending_payables_should_return_an_empty_vec_when_the_database_is_empty",
        );

        let subject = PayableDaoReal::new(DbInitializerReal::new().initialize(&home_dir).unwrap());

        assert_eq!(subject.non_pending_payables(), vec![]);
    }

    #[test]
    fn non_pending_payables_should_return_payables_with_no_pending_transaction() {
        let home_dir = ensure_node_home_directory_exists(
            "accountant",
            "non_pending_payables_should_return_payables_with_no_pending_transaction",
        );

        let subject = PayableDaoReal::new(DbInitializerReal::new().initialize(&home_dir).unwrap());

        let mut flags = OpenFlags::empty();
        flags.insert(OpenFlags::SQLITE_OPEN_READ_WRITE);
        let conn =
            Connection::open_with_flags(&home_dir.join(db_initializer::DATABASE_FILE), flags)
                .unwrap();
        let insert = |wallet: &str, balance: i64, pending_payment_transaction: Option<&str>| {
            let params: &[&dyn ToSql] = &[&wallet, &balance, &0i64, &pending_payment_transaction];

            conn
                .prepare("insert into payable (wallet_address, balance, last_paid_timestamp, pending_payment_transaction) values (?, ?, ?, ?)")
                .unwrap()
                .execute(params)
                .unwrap();
        };

        insert(
            "0x0000000000000000000000000000000000666f6f",
            42,
            Some("0x155553215215"),
        );
        insert(
            "0x0000000000000000000000000000000000626172",
            24,
            Some("0x689477777623"),
        );
        insert("0x0000000000000000000000000000666f6f626172", 44, None);
        insert("0x0000000000000000000000000000626172666f6f", 22, None);

        let result = subject.non_pending_payables();

        assert_eq!(
            result,
            vec![
                PayableAccount {
                    wallet: make_wallet("foobar"),
                    balance: 44,
                    last_paid_timestamp: from_time_t(0),
                    pending_payment_transaction: None
                },
                PayableAccount {
                    wallet: make_wallet("barfoo"),
                    balance: 22,
                    last_paid_timestamp: from_time_t(0),
                    pending_payment_transaction: None
                },
            ]
        );
    }
}
