// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use crate::database::dao_utils;
use crate::database::db_initializer::ConnectionWrapper;
use crate::sub_lib::wallet::Wallet;
use rusqlite::types::{ToSql, Type};
use rusqlite::{Error, OptionalExtension, NO_PARAMS};
use serde_json::{self, json};
use std::convert::TryFrom;
use std::fmt::Debug;
use std::time::SystemTime;
use web3::types::H256;

#[derive(Clone, Debug, PartialEq)]
pub struct PayableAccount {
    pub wallet: Wallet,
    pub balance: i64,
    pub last_paid_timestamp: SystemTime,
    pub pending_payment_transaction: Option<H256>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Payment {
    pub to: Wallet,
    pub amount: u64,
    pub timestamp: SystemTime,
    pub transaction: H256,
}

impl Payment {
    pub fn new(to: Wallet, amount: u64, transaction: H256) -> Self {
        Self {
            to,
            amount,
            timestamp: SystemTime::now(),
            transaction,
        }
    }
}

pub trait PayableDao: Debug + Send {
    fn more_money_payable(&self, wallet: &Wallet, amount: u64);

    fn payment_sent(&self, sent_payment: &Payment);

    fn payment_confirmed(
        &self,
        wallet: &Wallet,
        amount: u64,
        confirmation_noticed_timestamp: SystemTime,
        transaction_hash: H256,
    );

    fn account_status(&self, wallet: &Wallet) -> Option<PayableAccount>;

    fn non_pending_payables(&self) -> Vec<PayableAccount>;

    fn top_records(&self, minimum_amount: u64, maximum_age: u64) -> Vec<PayableAccount>;

    fn total(&self) -> u64;
}

#[derive(Debug)]
pub struct PayableDaoReal {
    conn: Box<dyn ConnectionWrapper>,
}

impl PayableDao for PayableDaoReal {
    fn more_money_payable(&self, wallet: &Wallet, amount: u64) {
        match self.try_increase_balance(wallet, amount) {
            Ok(_) => (),
            Err(e) => panic!("Database is corrupt: {}", e),
        };
    }

    fn payment_sent(&self, payment: &Payment) {
        match self.try_decrease_balance(
            &payment.to,
            payment.amount,
            payment.timestamp,
            payment.transaction,
        ) {
            Ok(_) => (),
            Err(e) => panic!("Database is corrupt: {}", e),
        }
    }

    fn payment_confirmed(
        &self,
        _wallet: &Wallet,
        _amount: u64,
        _confirmation_noticed_timestamp: SystemTime,
        _transaction_hash: H256,
    ) {
        unimplemented!("SC-925: TODO")
    }

    fn account_status(&self, wallet: &Wallet) -> Option<PayableAccount> {
        let mut stmt = self.conn
            .prepare("select balance, last_paid_timestamp, pending_payment_transaction from payable where wallet_address = ?")
            .expect("Internal error");
        match stmt
            .query_row(&[&wallet], |row| {
                let balance_result = row.get(0);
                let last_paid_timestamp_result = row.get(1);
                let pending_payment_transaction_result: Result<Option<String>, Error> = row.get(2);
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
                            pending_payment_transaction: match pending_payment_transaction {
                                Some(tx) => match serde_json::from_value(json!(tx)) {
                                    Ok(transaction) => Some(transaction),
                                    Err(e) => panic!("{:?}", e),
                                },
                                None => None,
                            },
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
        .flatten()
        .collect()
    }

    fn top_records(&self, minimum_amount: u64, maximum_age: u64) -> Vec<PayableAccount> {
        let min_amt = match i64::try_from(minimum_amount) {
            Ok(n) => n,
            Err(_) => 0x7FFF_FFFF_FFFF_FFFF,
        };
        let max_age = match i64::try_from(maximum_age) {
            Ok(n) => n,
            Err(_) => 0x7FFF_FFFF_FFFF_FFFF,
        };
        let min_timestamp = dao_utils::now_time_t() - max_age;
        let mut stmt = self
            .conn
            .prepare(
                r#"
                select
                    balance,
                    last_paid_timestamp,
                    wallet_address,
                    pending_payment_transaction
                from
                    payable
                where
                    balance >= ? and
                    last_paid_timestamp >= ?
                order by
                    balance desc,
                    last_paid_timestamp desc
            "#,
            )
            .expect("Internal error");
        let params: &[&dyn ToSql] = &[&min_amt, &min_timestamp];
        stmt.query_map(params, |row| {
            let balance_result = row.get(0);
            let last_paid_timestamp_result = row.get(1);
            let wallet_result: Result<Wallet, rusqlite::Error> = row.get(2);
            let pending_payment_transaction_result: Result<Option<String>, Error> = row.get(3);
            match (
                balance_result,
                last_paid_timestamp_result,
                wallet_result,
                pending_payment_transaction_result,
            ) {
                (
                    Ok(balance),
                    Ok(last_paid_timestamp),
                    Ok(wallet),
                    Ok(pending_payment_transaction),
                ) => Ok(PayableAccount {
                    wallet,
                    balance,
                    last_paid_timestamp: dao_utils::from_time_t(last_paid_timestamp),
                    pending_payment_transaction: match pending_payment_transaction {
                        Some(tx) => match serde_json::from_value(json!(tx)) {
                            Ok(transaction) => Some(transaction),
                            Err(e) => panic!("{:?}", e),
                        },
                        None => None,
                    },
                }),
                _ => panic!("Database is corrupt: PAYABLE table columns and/or types"),
            }
        })
        .expect("Database is corrupt")
        .flatten()
        .collect()
    }

    fn total(&self) -> u64 {
        let mut stmt = self
            .conn
            .prepare("select sum(balance) from payable")
            .expect("Internal error");
        match stmt.query_row(NO_PARAMS, |row| {
            let total_balance_result: Result<i64, rusqlite::Error> = row.get(0);
            match total_balance_result {
                Ok(total_balance) => Ok(total_balance as u64),
                Err(e)
                    if e == rusqlite::Error::InvalidColumnType(
                        0,
                        "sum(balance)".to_string(),
                        Type::Null,
                    ) =>
                {
                    Ok(0u64)
                }
                Err(e) => panic!(
                    "Database is corrupt: PAYABLE table columns and/or types: {:?}",
                    e
                ),
            }
        }) {
            Ok(value) => value,
            Err(e) => panic!("Database is corrupt: {:?}", e),
        }
    }
}

impl PayableDaoReal {
    pub fn new(conn: Box<dyn ConnectionWrapper>) -> PayableDaoReal {
        PayableDaoReal { conn }
    }

    fn try_increase_balance(&self, wallet: &Wallet, amount: u64) -> Result<bool, String> {
        let mut stmt = self
            .conn
            .prepare("insert into payable (wallet_address, balance, last_paid_timestamp, pending_payment_transaction) values (:address, :balance, strftime('%s','now'), null) on conflict (wallet_address) do update set balance = balance + :balance where wallet_address = :address")
            .expect("Internal error");
        let params: &[(&str, &dyn ToSql)] = &[
            (":address", &wallet),
            (
                ":balance",
                &i64::try_from(amount)
                    .unwrap_or_else(|_| panic!("Lost payable amount precision: {}", amount)),
            ),
        ];
        match stmt.execute_named(params) {
            Ok(0) => Ok(false),
            Ok(_) => Ok(true),
            Err(e) => Err(format!("{}", e)),
        }
    }

    fn try_decrease_balance(
        &self,
        wallet: &Wallet,
        amount: u64,
        last_paid_timestamp: SystemTime,
        transaction_hash: H256,
    ) -> Result<bool, String> {
        let mut stmt = self
            .conn
            .prepare("insert into payable (balance, last_paid_timestamp, pending_payment_transaction, wallet_address) values (0 - :balance, :last_paid, :transaction, :address) on conflict (wallet_address) do update set balance = balance - :balance, last_paid_timestamp = :last_paid, pending_payment_transaction = :transaction where wallet_address = :address")
            .expect("Internal error");
        let params: &[(&str, &dyn ToSql)] = &[
            (
                ":balance",
                &i64::try_from(amount)
                    .unwrap_or_else(|_| panic!("Lost payable amount precision: {}", amount)),
            ),
            (":last_paid", &dao_utils::to_time_t(last_paid_timestamp)),
            (":transaction", &format!("{:#x}", &transaction_hash)),
            (":address", &wallet),
        ];
        match stmt.execute_named(params) {
            Ok(0) => Ok(false),
            Ok(_) => Ok(true),
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
    use crate::test_utils::{make_wallet, DEFAULT_CHAIN_ID};
    use ethereum_types::BigEndianHash;
    use masq_lib::test_utils::utils::ensure_node_home_directory_exists;
    use rusqlite::{Connection, OpenFlags, NO_PARAMS};
    use std::str::FromStr;
    use web3::types::U256;

    #[test]
    fn more_money_payable_works_for_new_address() {
        let home_dir = ensure_node_home_directory_exists(
            "payable_dao",
            "more_money_payable_works_for_new_address",
        );
        let before = dao_utils::to_time_t(SystemTime::now());
        let wallet = make_wallet("booga");
        let status = {
            let subject = PayableDaoReal::new(
                DbInitializerReal::new()
                    .initialize(&home_dir, DEFAULT_CHAIN_ID, true)
                    .unwrap(),
            );

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
            "payable_dao",
            "more_money_payable_works_for_existing_address",
        );
        let wallet = make_wallet("booga");
        let subject = {
            let subject = PayableDaoReal::new(
                DbInitializerReal::new()
                    .initialize(&home_dir, DEFAULT_CHAIN_ID, true)
                    .unwrap(),
            );
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
    fn payment_sent_records_a_pending_transaction_for_a_new_address() {
        let home_dir = ensure_node_home_directory_exists(
            "payable_dao",
            "payment_sent_records_a_pending_transaction_for_a_new_address",
        );
        let wallet = make_wallet("booga");
        let subject = PayableDaoReal::new(
            DbInitializerReal::new()
                .initialize(&home_dir, DEFAULT_CHAIN_ID, true)
                .unwrap(),
        );
        let payment = Payment::new(wallet.clone(), 1, H256::from_uint(&U256::from(1)));

        let before_account_status = subject.account_status(&payment.to);
        assert!(before_account_status.is_none());

        subject.payment_sent(&payment);

        let after_account_status = subject.account_status(&payment.to).unwrap();

        assert_eq!(
            after_account_status.clone(),
            PayableAccount {
                wallet,
                balance: -1,
                last_paid_timestamp: after_account_status.last_paid_timestamp,
                pending_payment_transaction: Some(H256::from_uint(&U256::from(1))),
            }
        )
    }

    #[test]
    fn payment_sent_records_a_pending_transaction_for_an_existing_address() {
        let home_dir = ensure_node_home_directory_exists(
            "payable_dao",
            "payment_sent_records_a_pending_transaction_for_an_existing_address",
        );
        let wallet = make_wallet("booga");
        let subject = PayableDaoReal::new(
            DbInitializerReal::new()
                .initialize(&home_dir, DEFAULT_CHAIN_ID, true)
                .unwrap(),
        );
        let payment = Payment::new(wallet.clone(), 1, H256::from_uint(&U256::from(1)));

        let before_account_status = subject.account_status(&payment.to);
        assert!(before_account_status.is_none());
        subject.more_money_payable(&wallet, 1);
        subject.payment_sent(&payment);

        let after_account_status = subject.account_status(&payment.to).unwrap();

        assert_eq!(
            after_account_status.clone(),
            PayableAccount {
                wallet,
                balance: 0,
                last_paid_timestamp: after_account_status.last_paid_timestamp,
                pending_payment_transaction: Some(H256::from_uint(&U256::from(1))),
            }
        )
    }

    #[test]
    fn payable_account_status_works_when_account_doesnt_exist() {
        let home_dir = ensure_node_home_directory_exists(
            "payable_dao",
            "payable_account_status_works_when_account_doesnt_exist",
        );
        let wallet = make_wallet("booga");
        let subject = PayableDaoReal::new(
            DbInitializerReal::new()
                .initialize(&home_dir, DEFAULT_CHAIN_ID, true)
                .unwrap(),
        );

        let result = subject.account_status(&wallet);

        assert_eq!(result, None);
    }

    #[test]
    fn non_pending_payables_should_return_an_empty_vec_when_the_database_is_empty() {
        let home_dir = ensure_node_home_directory_exists(
            "payable_dao",
            "non_pending_payables_should_return_an_empty_vec_when_the_database_is_empty",
        );

        let subject = PayableDaoReal::new(
            DbInitializerReal::new()
                .initialize(&home_dir, DEFAULT_CHAIN_ID, true)
                .unwrap(),
        );

        assert_eq!(subject.non_pending_payables(), vec![]);
    }

    #[test]
    fn non_pending_payables_should_return_payables_with_no_pending_transaction() {
        let home_dir = ensure_node_home_directory_exists(
            "payable_dao",
            "non_pending_payables_should_return_payables_with_no_pending_transaction",
        );

        let subject = PayableDaoReal::new(
            DbInitializerReal::new()
                .initialize(&home_dir, DEFAULT_CHAIN_ID, true)
                .unwrap(),
        );

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

    #[test]
    #[should_panic(expected = "Lost payable amount precision: 18446744073709551615")]
    fn payable_amount_precision_loss_panics_on_insert() {
        let home_dir = ensure_node_home_directory_exists(
            "payable_dao",
            "payable_amount_precision_loss_panics_on_insert",
        );
        let subject = PayableDaoReal::new(
            DbInitializerReal::new()
                .initialize(&home_dir, DEFAULT_CHAIN_ID, true)
                .unwrap(),
        );
        subject.more_money_payable(&make_wallet("foobar"), std::u64::MAX);
    }

    #[test]
    #[should_panic(expected = "Lost payable amount precision: 18446744073709551615")]
    fn payable_amount_precision_loss_panics_on_update_balance() {
        let home_dir = ensure_node_home_directory_exists(
            "payable_dao",
            "payable_amount_precision_loss_panics_on_update_balance",
        );
        let subject = PayableDaoReal::new(
            DbInitializerReal::new()
                .initialize(&home_dir, DEFAULT_CHAIN_ID, true)
                .unwrap(),
        );
        subject.payment_sent(&Payment::new(
            make_wallet("foobar"),
            std::u64::MAX,
            H256::from_uint(&U256::from(123)),
        ));
    }

    #[test]
    fn top_records_and_total() {
        let home_dir = ensure_node_home_directory_exists("payable_dao", "top_records_and_total");
        let conn = DbInitializerReal::new()
            .initialize(&home_dir, DEFAULT_CHAIN_ID, true)
            .unwrap();
        let insert = |wallet: &str,
                      balance: i64,
                      timestamp: i64,
                      pending_payment_transaction: Option<&str>| {
            let params: &[&dyn ToSql] =
                &[&wallet, &balance, &timestamp, &pending_payment_transaction];
            conn
                .prepare("insert into payable (wallet_address, balance, last_paid_timestamp, pending_payment_transaction) values (?, ?, ?, ?)")
                .unwrap()
                .execute(params)
                .unwrap();
        };
        let timestamp1 = dao_utils::now_time_t() - 80_000;
        let timestamp2 = dao_utils::now_time_t() - 86_401;
        let timestamp3 = dao_utils::now_time_t() - 86_000;
        let timestamp4 = dao_utils::now_time_t() - 86_001;
        insert(
            "0x1111111111111111111111111111111111111111",
            999_999_999, // below minimum amount - reject
            timestamp1,  // below maximum age
            None,
        );
        insert(
            "0x2222222222222222222222222222222222222222",
            1_000_000_000, // minimum amount
            timestamp2,    // above maximum age - reject
            None,
        );
        insert(
            "0x3333333333333333333333333333333333333333",
            1_000_000_000, // minimum amount
            timestamp3,    // below maximum age
            None,
        );
        insert(
            "0x4444444444444444444444444444444444444444",
            1_000_000_001, // above minimum amount
            timestamp4,    // below maximum age
            Some("0x1111111122222222333333334444444455555555666666667777777788888888"),
        );

        let subject = PayableDaoReal::new(conn);

        let top_records = subject.top_records(1_000_000_000, 86400);
        let total = subject.total();

        assert_eq!(
            top_records,
            vec![
                PayableAccount {
                    wallet: Wallet::new("0x4444444444444444444444444444444444444444"),
                    balance: 1_000_000_001,
                    last_paid_timestamp: dao_utils::from_time_t(timestamp4),
                    pending_payment_transaction: Some(
                        H256::from_str(
                            "1111111122222222333333334444444455555555666666667777777788888888"
                        )
                        .unwrap()
                    )
                },
                PayableAccount {
                    wallet: Wallet::new("0x3333333333333333333333333333333333333333"),
                    balance: 1_000_000_000,
                    last_paid_timestamp: dao_utils::from_time_t(timestamp3),
                    pending_payment_transaction: None
                },
            ]
        );
        assert_eq!(total, 4_000_000_000)
    }

    #[test]
    fn correctly_totals_zero_records() {
        let home_dir =
            ensure_node_home_directory_exists("payable_dao", "correctly_totals_zero_records");
        let conn = DbInitializerReal::new()
            .initialize(&home_dir, DEFAULT_CHAIN_ID, true)
            .unwrap();
        let subject = PayableDaoReal::new(conn);

        let result = subject.total();

        assert_eq!(result, 0)
    }
}
