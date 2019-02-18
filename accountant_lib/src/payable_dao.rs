// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use crate::dao_utils;
use rusqlite::types::ToSql;
use rusqlite::Connection;
use rusqlite::OptionalExtension;
use std::fmt::Debug;
use std::time::SystemTime;
use sub_lib::wallet::Wallet;

#[derive(Debug, PartialEq)]
pub struct PayableAccount {
    pub wallet_address: Wallet,
    pub balance: i64,
    pub last_paid_timestamp: SystemTime,
    pub pending_payment_transaction: Option<String>,
}

pub trait PayableDao: Debug {
    fn more_money_payable(&self, wallet_address: &Wallet, amount: u64);

    fn payment_sent(&self, wallet_address: &Wallet, pending_payment_transaction: &str);

    fn payment_confirmed(
        &self,
        wallet_address: &Wallet,
        amount: u64,
        confirmation_noticed_timestamp: &SystemTime,
    );

    fn account_status(&self, wallet_address: &Wallet) -> Option<PayableAccount>;
}

#[derive(Debug)]
pub struct PayableDaoReal {
    conn: Connection,
}

impl PayableDao for PayableDaoReal {
    fn more_money_payable(&self, wallet_address: &Wallet, amount: u64) {
        match self.try_update(wallet_address, amount) {
            Ok(true) => (),
            Ok(false) => match self.try_insert(wallet_address, amount) {
                Ok(_) => (),
                Err(e) => panic!("Database is corrupt: {}", e),
            },
            Err(e) => panic!("Database is corrupt: {}", e),
        };
    }

    fn payment_sent(&self, _wallet_address: &Wallet, _pending_payment_transaction: &str) {
        unimplemented!()
    }

    fn payment_confirmed(
        &self,
        _wallet_address: &Wallet,
        _amount: u64,
        _confirmation_noticed_timestamp: &SystemTime,
    ) {
        unimplemented!()
    }

    fn account_status(&self, wallet_address: &Wallet) -> Option<PayableAccount> {
        let mut stmt = self.conn
            .prepare("select balance, last_paid_timestamp, pending_payment_transaction from payable where wallet_address = ?")
            .expect("Internal error");
        match stmt
            .query_row(&[wallet_address.address.clone()], |row| {
                (row.get(0), row.get(1), row.get(2))
            })
            .optional()
        {
            Ok(Some((Some(balance), Some(last_paid_timestamp), pending_payment_transaction))) => {
                Some(PayableAccount {
                    wallet_address: wallet_address.clone(),
                    balance,
                    last_paid_timestamp: dao_utils::from_time_t(last_paid_timestamp),
                    pending_payment_transaction,
                })
            }
            Ok(Some(e)) => panic!("Database is corrupt: {:?}", e),
            Ok(None) => None,
            Err(e) => panic!("Database is corrupt: {:?}", e),
        }
    }
}

impl PayableDaoReal {
    pub fn new(conn: Connection) -> PayableDaoReal {
        PayableDaoReal { conn }
    }

    fn try_update(&self, wallet_address: &Wallet, amount: u64) -> Result<bool, String> {
        let mut stmt = self
            .conn
            .prepare("update payable set balance = balance + ? where wallet_address = ?")
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
        let mut stmt = self.conn
            .prepare("insert into payable (wallet_address, balance, last_paid_timestamp, pending_payment_transaction) values (?, ?, ?, null)")
            .expect("Internal error");
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
    use crate::dao_utils;
    use crate::db_initializer;
    use crate::db_initializer::DbInitializer;
    use crate::db_initializer::DbInitializerReal;
    use crate::local_test_utils::ensure_node_home_directory_exists;
    use rusqlite::OpenFlags;
    use rusqlite::NO_PARAMS;

    #[test]
    fn more_money_payable_works_for_new_address() {
        let home_dir =
            ensure_node_home_directory_exists("more_money_payable_works_for_new_address");
        let before = dao_utils::to_time_t(&SystemTime::now());
        let wallet = Wallet::new("booga");
        let status = {
            let subject = DbInitializerReal::new()
                .initialize(&home_dir)
                .unwrap()
                .payable;

            subject.more_money_payable(&wallet, 1234);
            subject.account_status(&wallet).unwrap()
        };

        let after = dao_utils::to_time_t(&SystemTime::now());
        assert_eq!(status.wallet_address, wallet);
        assert_eq!(status.balance, 1234);
        let timestamp = dao_utils::to_time_t(&status.last_paid_timestamp);
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
        let home_dir =
            ensure_node_home_directory_exists("more_money_payable_works_for_existing_address");
        let wallet = Wallet::new("booga");
        let subject = {
            let subject = DbInitializerReal::new()
                .initialize(&home_dir)
                .unwrap()
                .payable;
            subject.more_money_payable(&wallet, 1234);
            let mut flags = OpenFlags::empty();
            flags.insert(OpenFlags::SQLITE_OPEN_READ_WRITE);
            let conn =
                Connection::open_with_flags(&home_dir.join(db_initializer::DATABASE_FILE), flags)
                    .unwrap();
            conn.execute(
                "update payable set last_paid_timestamp = 0 where wallet_address = 'booga'",
                NO_PARAMS,
            )
            .unwrap();
            subject
        };

        let status = {
            subject.more_money_payable(&wallet, 2345);
            subject.account_status(&wallet).unwrap()
        };

        assert_eq!(status.wallet_address, wallet);
        assert_eq!(status.balance, 3579);
        assert_eq!(status.last_paid_timestamp, SystemTime::UNIX_EPOCH);
    }

    #[test]
    fn payable_account_status_works_when_account_doesnt_exist() {
        let home_dir = ensure_node_home_directory_exists(
            "payable_account_status_works_when_account_doesnt_exist",
        );
        let wallet = Wallet::new("booga");
        let subject = DbInitializerReal::new()
            .initialize(&home_dir)
            .unwrap()
            .payable;

        let result = subject.account_status(&wallet);

        assert_eq!(result, None);
    }
}
