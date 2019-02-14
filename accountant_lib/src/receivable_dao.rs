use crate::dao_utils;
use rusqlite::types::ToSql;
use rusqlite::Connection;
use rusqlite::OptionalExtension;
use std::fmt::Debug;
use std::time::SystemTime;
use sub_lib::wallet::Wallet;

#[derive(Debug, PartialEq)]
pub struct Account {
    pub wallet_address: Wallet,
    pub balance: i64,
    pub last_received_timestamp: SystemTime,
}

pub trait ReceivableDao: Debug {
    fn more_money_owed(&self, wallet_address: &Wallet, amount: u64);

    fn more_money_received(&self, wallet_address: &Wallet, amount: u64, timestamp: &SystemTime);

    fn account_status(&self, wallet_address: &Wallet) -> Option<Account>;
}

#[derive(Debug)]
pub struct ReceivableDaoReal {
    conn: Connection,
}

impl ReceivableDao for ReceivableDaoReal {
    fn more_money_owed(&self, wallet_address: &Wallet, amount: u64) {
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

    fn account_status(&self, wallet_address: &Wallet) -> Option<Account> {
        let mut stmt = self
            .conn
            .prepare(
                "select balance, last_received_timestamp from receivable where wallet_address = ?",
            )
            .expect("Internal error");
        match stmt
            .query_row(&[wallet_address.address.clone()], |row| {
                (row.get(0), row.get(1))
            })
            .optional()
        {
            Ok(Some((Some(balance), Some(timestamp)))) => Some(Account {
                wallet_address: wallet_address.clone(),
                balance,
                last_received_timestamp: dao_utils::from_time_t(timestamp),
            }),
            Ok(Some(e)) => panic!("Database is corrupt: {:?}", e),
            Ok(None) => None,
            Err(e) => panic!("Database is corrupt: {:?}", e),
        }
    }
}

impl ReceivableDaoReal {
    pub fn new(conn: Connection) -> ReceivableDaoReal {
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
    use crate::accountant::tests::BASE_TEST_DIR;
    use crate::db_initializer;
    use crate::db_initializer::DbInitializer;
    use crate::db_initializer::DbInitializerReal;
    use rusqlite::OpenFlags;
    use rusqlite::NO_PARAMS;
    use std::fs;
    use std::path::PathBuf;

    #[test]
    fn more_money_owed_works_for_new_address() {
        let home_dir_string = format!(
            "{}/more_money_owed_works_for_new_address/home",
            BASE_TEST_DIR
        );
        let home_dir = PathBuf::from(home_dir_string.as_str());
        fs::remove_dir_all(&home_dir).is_ok();
        fs::create_dir_all(&home_dir).is_ok();
        let before = dao_utils::to_time_t(&SystemTime::now());
        let wallet = Wallet::new("booga");
        let status = {
            let subject = DbInitializerReal::new()
                .initialize(&home_dir)
                .unwrap()
                .receivable;

            subject.more_money_owed(&wallet, 1234);
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
    fn more_money_owed_works_for_existing_address() {
        let home_dir_string = format!(
            "{}/more_money_owed_works_for_existing_address/home",
            BASE_TEST_DIR
        );
        let home_dir = PathBuf::from(home_dir_string.as_str());
        fs::remove_dir_all(&home_dir).is_ok();
        fs::create_dir_all(&home_dir).is_ok();
        let wallet = Wallet::new("booga");
        let subject = {
            let subject = DbInitializerReal::new()
                .initialize(&home_dir)
                .unwrap()
                .receivable;
            subject.more_money_owed(&wallet, 1234);
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
            subject.more_money_owed(&wallet, 2345);
            subject.account_status(&wallet).unwrap()
        };

        assert_eq!(status.wallet_address, wallet);
        assert_eq!(status.balance, 3579);
        assert_eq!(status.last_received_timestamp, SystemTime::UNIX_EPOCH);
    }

    #[test]
    fn account_status_works_when_account_doesnt_exist() {
        let home_dir_string = format!(
            "{}/account_status_works_when_account_doesnt_exist/home",
            BASE_TEST_DIR
        );
        let home_dir = PathBuf::from(home_dir_string.as_str());
        fs::remove_dir_all(&home_dir).is_ok();
        fs::create_dir_all(&home_dir).is_ok();
        let wallet = Wallet::new("booga");
        let subject = DbInitializerReal::new()
            .initialize(&home_dir)
            .unwrap()
            .receivable;

        let result = subject.account_status(&wallet);

        assert_eq!(result, None);
    }
}
