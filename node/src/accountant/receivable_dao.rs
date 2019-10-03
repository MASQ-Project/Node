// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use crate::accountant::PaymentCurves;
use crate::blockchain::blockchain_interface::Transaction;
use crate::database::dao_utils;
use crate::database::dao_utils::to_time_t;
use crate::database::db_initializer::ConnectionWrapper;
use crate::persistent_configuration::PersistentConfiguration;
use crate::sub_lib::logger::Logger;
use crate::sub_lib::wallet::Wallet;
use indoc::indoc;
use rusqlite::named_params;
use rusqlite::types::ToSql;
use rusqlite::{OptionalExtension, Row, NO_PARAMS};
use std::time::SystemTime;

#[derive(Debug, Clone, PartialEq)]
pub struct ReceivableAccount {
    pub wallet: Wallet,
    pub balance: i64,
    pub last_received_timestamp: SystemTime,
}

pub trait ReceivableDao: Send {
    fn more_money_receivable(&self, wallet: &Wallet, amount: u64);

    fn more_money_received(
        &mut self,
        persistent_configuration: &dyn PersistentConfiguration,
        transactions: Vec<Transaction>,
    );

    fn account_status(&self, wallet: &Wallet) -> Option<ReceivableAccount>;

    fn receivables(&self) -> Vec<ReceivableAccount>;

    fn new_delinquencies(
        &self,
        now: SystemTime,
        payment_curves: &PaymentCurves,
    ) -> Vec<ReceivableAccount>;

    fn paid_delinquencies(&self, payment_curves: &PaymentCurves) -> Vec<ReceivableAccount>;
}

pub struct ReceivableDaoReal {
    conn: Box<dyn ConnectionWrapper>,
    logger: Logger,
}

impl ReceivableDao for ReceivableDaoReal {
    fn more_money_receivable(&self, wallet: &Wallet, amount: u64) {
        match self.try_update(wallet, amount) {
            Ok(true) => (),
            Ok(false) => match self.try_insert(wallet, amount) {
                Ok(_) => (),
                Err(e) => {
                    fatal!(self.logger, "Couldn't insert; database is corrupt: {}", e);
                }
            },
            Err(e) => {
                fatal!(self.logger, "Couldn't update: database is corrupt: {}", e);
            }
        };
    }

    fn more_money_received(
        &mut self,
        persistent_configuration: &dyn PersistentConfiguration,
        payments: Vec<Transaction>,
    ) {
        self.try_multi_insert_payment(persistent_configuration, payments)
            .unwrap_or_else(|e| {
                warning!(self.logger, "Transaction failed, rolling back: {}", e);
            });
    }

    fn account_status(&self, wallet: &Wallet) -> Option<ReceivableAccount> {
        let mut stmt = self
            .conn
            .prepare(
                "select wallet_address, balance, last_received_timestamp from receivable where wallet_address = ?",
            )
            .expect("Internal error");
        match stmt.query_row(&[&wallet], Self::row_to_account).optional() {
            Ok(value) => value,
            Err(e) => panic!("Database is corrupt: {:?}", e),
        }
    }

    fn receivables(&self) -> Vec<ReceivableAccount> {
        let mut stmt = self
            .conn
            .prepare("select balance, last_received_timestamp, wallet_address from receivable")
            .expect("Internal error");

        stmt.query_map(NO_PARAMS, |row| {
            let balance_result = row.get(0);
            let last_received_timestamp_result = row.get(1);
            let wallet: Result<Wallet, rusqlite::Error> = row.get(2);
            match (balance_result, last_received_timestamp_result, wallet) {
                (Ok(balance), Ok(last_received_timestamp), Ok(wallet)) => Ok(ReceivableAccount {
                    wallet,
                    balance,
                    last_received_timestamp: dao_utils::from_time_t(last_received_timestamp),
                }),
                _ => panic!("Database is corrupt: RECEIVABLE table columns and/or types"),
            }
        })
        .expect("Database is corrupt")
        .flat_map(|p| p)
        .collect()
    }

    fn new_delinquencies(
        &self,
        system_now: SystemTime,
        payment_curves: &PaymentCurves,
    ) -> Vec<ReceivableAccount> {
        let now = to_time_t(system_now);
        let slope = (payment_curves.permanent_debt_allowed_gwub as f64
            - payment_curves.balance_to_decrease_from_gwub as f64)
            / (payment_curves.balance_decreases_for_sec as f64);
        let sql = indoc!(r"
            select r.wallet_address, r.balance, r.last_received_timestamp
            from receivable r left outer join banned b on r.wallet_address = b.wallet_address
            where
                r.last_received_timestamp < :sugg_and_grace
                and r.balance > :balance_to_decrease_from + :slope * (:sugg_and_grace - r.last_received_timestamp)
                and r.balance > :permanent_debt
                and b.wallet_address is null
        ");
        let mut stmt = self.conn.prepare(sql).expect("Couldn't prepare statement");
        stmt.query_map_named(
            named_params! {
                ":slope": slope,
                ":sugg_and_grace": payment_curves.sugg_and_grace(now),
                ":balance_to_decrease_from": payment_curves.balance_to_decrease_from_gwub,
                ":permanent_debt": payment_curves.permanent_debt_allowed_gwub,
            },
            Self::row_to_account,
        )
        .expect("Couldn't retrieve new delinquencies: database corruption")
        .flat_map(|v| v)
        .collect()
    }

    fn paid_delinquencies(&self, payment_curves: &PaymentCurves) -> Vec<ReceivableAccount> {
        let sql = indoc!(
            r"
            select r.wallet_address, r.balance, r.last_received_timestamp
            from receivable r inner join banned b on r.wallet_address = b.wallet_address
            where
                r.balance <= :unban_balance
        "
        );
        let mut stmt = self.conn.prepare(sql).expect("Couldn't prepare statement");
        stmt.query_map_named(
            named_params! {
                ":unban_balance": payment_curves.unban_when_balance_below_gwub,
            },
            Self::row_to_account,
        )
        .expect("Couldn't retrieve new delinquencies: database corruption")
        .flat_map(|v| v)
        .collect()
    }
}

impl ReceivableDaoReal {
    pub fn new(conn: Box<dyn ConnectionWrapper>) -> ReceivableDaoReal {
        ReceivableDaoReal {
            conn,
            logger: Logger::new("ReceivableDaoReal"),
        }
    }

    fn try_update(&self, wallet: &Wallet, amount: u64) -> Result<bool, String> {
        let mut stmt = self
            .conn
            .prepare("update receivable set balance = balance + ? where wallet_address = ?")
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
        let mut stmt = self.conn.prepare ("insert into receivable (wallet_address, balance, last_received_timestamp) values (?, ?, ?)").expect ("Internal error");
        let params: &[&dyn ToSql] = &[&wallet, &(amount as i64), &(timestamp as i64)];
        match stmt.execute(params) {
            Ok(_) => Ok(()),
            Err(e) => Err(format!("{}", e)),
        }
    }

    fn try_multi_insert_payment(
        &mut self,
        persistent_configuration: &dyn PersistentConfiguration,
        payments: Vec<Transaction>,
    ) -> Result<(), String> {
        let tx = match self.conn.transaction() {
            Ok(t) => t,
            Err(e) => return Err(e.to_string()),
        };

        let block_number = payments
            .iter()
            .map(|t| t.block_number)
            .max()
            .ok_or("no payments given")?;

        persistent_configuration.set_start_block_transactionally(&tx, block_number)?;

        {
            let mut stmt = tx.prepare("update receivable set balance = balance - ?, last_received_timestamp = ? where wallet_address = ?").expect("Internal error");
            for transaction in payments {
                let timestamp = dao_utils::now_time_t();
                let params: &[&dyn ToSql] = &[
                    &(transaction.gwei_amount as i64),
                    &(timestamp as i64),
                    &transaction.from,
                ];
                stmt.execute(params).map_err(|e| e.to_string())?;
            }
        }
        tx.commit().map_err(|e| e.to_string())
    }

    fn row_to_account(row: &Row) -> rusqlite::Result<ReceivableAccount> {
        let wallet: Result<Wallet, rusqlite::Error> = row.get(0);
        let balance_result = row.get(1);
        let last_received_timestamp_result = row.get(2);
        match (wallet, balance_result, last_received_timestamp_result) {
            (Ok(wallet), Ok(balance), Ok(last_received_timestamp)) => Ok(ReceivableAccount {
                wallet,
                balance,
                last_received_timestamp: dao_utils::from_time_t(last_received_timestamp),
            }),
            _ => panic!("Database is corrupt: RECEIVABLE table columns and/or types"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accountant::test_utils::make_receivable_account;
    use crate::config_dao::ConfigDaoReal;
    use crate::database::dao_utils::{from_time_t, now_time_t, to_time_t};
    use crate::database::db_initializer;
    use crate::database::db_initializer::test_utils::ConnectionWrapperMock;
    use crate::database::db_initializer::DbInitializer;
    use crate::database::db_initializer::DbInitializerReal;
    use crate::persistent_configuration::PersistentConfigurationReal;
    use crate::test_utils::logging::TestLogHandler;
    use crate::test_utils::persistent_configuration_mock::PersistentConfigurationMock;
    use crate::test_utils::{assert_contains, ensure_node_home_directory_exists, make_wallet};
    use crate::test_utils::{logging, DEFAULT_CHAIN_ID};
    use rusqlite::NO_PARAMS;
    use rusqlite::{Connection, Error, OpenFlags};

    #[test]
    fn more_money_receivable_works_for_new_address() {
        let home_dir = ensure_node_home_directory_exists(
            "accountant",
            "more_money_receivable_works_for_new_address",
        );
        let before = dao_utils::to_time_t(SystemTime::now());
        let wallet = make_wallet("booga");
        let status = {
            let subject = ReceivableDaoReal::new(
                DbInitializerReal::new()
                    .initialize(&home_dir, DEFAULT_CHAIN_ID)
                    .unwrap(),
            );

            subject.more_money_receivable(&wallet, 1234);
            subject.account_status(&wallet).unwrap()
        };

        let after = dao_utils::to_time_t(SystemTime::now());
        assert_eq!(status.wallet, wallet);
        assert_eq!(status.balance, 1234);
        let timestamp = dao_utils::to_time_t(status.last_received_timestamp);
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
        let wallet = make_wallet("booga");
        let subject = {
            let subject = ReceivableDaoReal::new(
                DbInitializerReal::new()
                    .initialize(&home_dir, DEFAULT_CHAIN_ID)
                    .unwrap(),
            );
            subject.more_money_receivable(&wallet, 1234);
            let mut flags = OpenFlags::empty();
            flags.insert(OpenFlags::SQLITE_OPEN_READ_WRITE);
            let conn =
                Connection::open_with_flags(&home_dir.join(db_initializer::DATABASE_FILE), flags)
                    .unwrap();
            conn.execute(
                "update receivable set last_received_timestamp = 0 where wallet_address = '0x000000000000000000000000000000626f6f6761'",
                NO_PARAMS,
            )
            .unwrap();
            subject
        };

        let status = {
            subject.more_money_receivable(&wallet, 2345);
            subject.account_status(&wallet).unwrap()
        };

        assert_eq!(status.wallet, wallet);
        assert_eq!(status.balance, 3579);
        assert_eq!(status.last_received_timestamp, SystemTime::UNIX_EPOCH);
    }

    #[test]
    fn more_money_received_works_for_existing_addresses() {
        let before = dao_utils::to_time_t(SystemTime::now());
        let home_dir = ensure_node_home_directory_exists(
            "accountant",
            "more_money_received_works_for_existing_address",
        );
        let debtor1 = make_wallet("debtor1");
        let debtor2 = make_wallet("debtor2");
        let mut subject = {
            let subject = ReceivableDaoReal::new(
                DbInitializerReal::new()
                    .initialize(&home_dir, DEFAULT_CHAIN_ID)
                    .unwrap(),
            );
            subject.more_money_receivable(&debtor1, 1234);
            subject.more_money_receivable(&debtor2, 2345);
            let mut flags = OpenFlags::empty();
            flags.insert(OpenFlags::SQLITE_OPEN_READ_WRITE);
            subject
        };

        let config_dao = ConfigDaoReal::new(
            DbInitializerReal::new()
                .initialize(&home_dir, DEFAULT_CHAIN_ID)
                .unwrap(),
        );
        let persistent_config: Box<dyn PersistentConfiguration> =
            Box::new(PersistentConfigurationReal::new(Box::new(config_dao)));

        let (status1, status2) = {
            let transactions = vec![
                Transaction {
                    from: debtor1.clone(),
                    gwei_amount: 1200u64,
                    block_number: 35u64,
                },
                Transaction {
                    from: debtor2.clone(),
                    gwei_amount: 2300u64,
                    block_number: 57u64,
                },
            ];

            subject.more_money_received(persistent_config.as_ref(), transactions);
            (
                subject.account_status(&debtor1).unwrap(),
                subject.account_status(&debtor2).unwrap(),
            )
        };

        assert_eq!(status1.wallet, debtor1);
        assert_eq!(status1.balance, 34);
        let timestamp1 = dao_utils::to_time_t(status1.last_received_timestamp);
        assert!(timestamp1 >= before);
        assert!(timestamp1 <= dao_utils::to_time_t(SystemTime::now()));

        assert_eq!(status2.wallet, debtor2);
        assert_eq!(status2.balance, 45);
        let timestamp2 = dao_utils::to_time_t(status2.last_received_timestamp);
        assert!(timestamp2 >= before);
        assert!(timestamp2 <= dao_utils::to_time_t(SystemTime::now()));

        let start_block = persistent_config.start_block();
        assert_eq!(57u64, start_block);
    }

    #[test]
    fn more_money_received_throws_away_payments_from_unknown_addresses() {
        let home_dir = ensure_node_home_directory_exists(
            "accountant",
            "more_money_received_throws_away_payments_from_unknown_addresses",
        );
        let debtor = make_wallet("unknown_wallet");
        let mut subject = ReceivableDaoReal::new(
            DbInitializerReal::new()
                .initialize(&home_dir, DEFAULT_CHAIN_ID)
                .unwrap(),
        );

        let config_dao = ConfigDaoReal::new(
            DbInitializerReal::new()
                .initialize(&home_dir, DEFAULT_CHAIN_ID)
                .unwrap(),
        );
        let persistent_config: Box<dyn PersistentConfiguration> =
            Box::new(PersistentConfigurationReal::new(Box::new(config_dao)));

        let status = {
            let transactions = vec![Transaction {
                from: debtor.clone(),
                gwei_amount: 2300u64,
                block_number: 33u64,
            }];
            subject.more_money_received(persistent_config.as_ref(), transactions);
            subject.account_status(&debtor)
        };

        assert!(status.is_none());
    }

    #[test]
    fn more_money_received_logs_when_transaction_fails() {
        logging::init_test_logging();

        let conn_mock =
            ConnectionWrapperMock::default().transaction_result(Err(Error::InvalidQuery));
        let mut receivable_dao = ReceivableDaoReal::new(Box::new(conn_mock));

        let persistent_configuration: Box<dyn PersistentConfiguration> =
            Box::new(PersistentConfigurationMock::new());

        receivable_dao.more_money_received(persistent_configuration.as_ref(), vec![]);

        TestLogHandler::new().exists_log_containing(&format!(
            "WARN: ReceivableDaoReal: Transaction failed, rolling back: {}",
            Error::InvalidQuery
        ));
    }

    #[test]
    fn more_money_received_logs_when_no_payment_are_given() {
        logging::init_test_logging();

        let home_dir = ensure_node_home_directory_exists(
            "accountant",
            "more_money_received_logs_when_no_payment_are_given",
        );

        let mut receivable_dao = ReceivableDaoReal::new(
            DbInitializerReal::new()
                .initialize(&home_dir, DEFAULT_CHAIN_ID)
                .unwrap(),
        );

        let persistent_configuration: Box<dyn PersistentConfiguration> =
            Box::new(PersistentConfigurationMock::new());

        receivable_dao.more_money_received(persistent_configuration.as_ref(), vec![]);

        TestLogHandler::new().exists_log_containing(
            "WARN: ReceivableDaoReal: Transaction failed, rolling back: no payments given",
        );
    }

    #[test]
    fn more_money_received_logs_when_start_block_cannot_be_updated() {
        logging::init_test_logging();

        let home_dir = ensure_node_home_directory_exists(
            "accountant",
            "more_money_received_logs_when_start_block_cannot_be_updated",
        );

        let mut receivable_dao = ReceivableDaoReal::new(
            DbInitializerReal::new()
                .initialize(&home_dir, DEFAULT_CHAIN_ID)
                .unwrap(),
        );

        let persistent_configuration_mock = PersistentConfigurationMock::new()
            .set_start_block_transactionally_result(Err("BOOM".to_string()));

        let payments = vec![Transaction {
            from: make_wallet("foobar"),
            gwei_amount: 2300u64,
            block_number: 33u64,
        }];

        let persistent_configuration: Box<dyn PersistentConfiguration> =
            Box::new(persistent_configuration_mock);

        receivable_dao.more_money_received(persistent_configuration.as_ref(), payments);

        TestLogHandler::new().exists_log_containing(
            r#"WARN: ReceivableDaoReal: Transaction failed, rolling back: BOOM"#,
        );
    }

    #[test]
    fn receivable_account_status_works_when_account_doesnt_exist() {
        let home_dir = ensure_node_home_directory_exists(
            "accountant",
            "receivable_account_status_works_when_account_doesnt_exist",
        );
        let wallet = make_wallet("booga");
        let subject = ReceivableDaoReal::new(
            DbInitializerReal::new()
                .initialize(&home_dir, DEFAULT_CHAIN_ID)
                .unwrap(),
        );

        let result = subject.account_status(&wallet);

        assert_eq!(result, None);
    }

    #[test]
    fn receivables_fetches_all_receivable_accounts() {
        let home_dir = ensure_node_home_directory_exists(
            "accountant",
            "receivables_fetches_all_receivable_accounts",
        );
        let wallet1 = make_wallet("wallet1");
        let wallet2 = make_wallet("wallet2");
        let time_stub = SystemTime::now();

        let subject = ReceivableDaoReal::new(
            DbInitializerReal::new()
                .initialize(&home_dir, DEFAULT_CHAIN_ID)
                .unwrap(),
        );

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
                    wallet: wallet1,
                    balance: 1234,
                    last_received_timestamp: time_stub
                },
                ReceivableAccount {
                    wallet: wallet2,
                    balance: 2345,
                    last_received_timestamp: time_stub
                },
            ],
            accounts
        )
    }

    #[test]
    fn new_delinquencies_unit_slope() {
        let pcs = PaymentCurves {
            payment_suggested_after_sec: 25,
            payment_grace_before_ban_sec: 50,
            permanent_debt_allowed_gwub: 100,
            balance_to_decrease_from_gwub: 200,
            balance_decreases_for_sec: 100,
            unban_when_balance_below_gwub: 0, // doesn't matter for this test
        };
        let now = now_time_t();
        let mut not_delinquent_inside_grace_period = make_receivable_account(1234, false);
        not_delinquent_inside_grace_period.balance = pcs.balance_to_decrease_from_gwub + 1;
        not_delinquent_inside_grace_period.last_received_timestamp =
            from_time_t(pcs.sugg_and_grace(now) + 2);
        let mut not_delinquent_after_grace_below_slope = make_receivable_account(2345, false);
        not_delinquent_after_grace_below_slope.balance = pcs.balance_to_decrease_from_gwub - 2;
        not_delinquent_after_grace_below_slope.last_received_timestamp =
            from_time_t(pcs.sugg_and_grace(now) - 1);
        let mut delinquent_above_slope_after_grace = make_receivable_account(3456, true);
        delinquent_above_slope_after_grace.balance = pcs.balance_to_decrease_from_gwub - 1;
        delinquent_above_slope_after_grace.last_received_timestamp =
            from_time_t(pcs.sugg_and_grace(now) - 2);
        let mut not_delinquent_below_slope_before_stop = make_receivable_account(4567, false);
        not_delinquent_below_slope_before_stop.balance = pcs.permanent_debt_allowed_gwub + 1;
        not_delinquent_below_slope_before_stop.last_received_timestamp =
            from_time_t(pcs.sugg_thru_decreasing(now) + 2);
        let mut delinquent_above_slope_before_stop = make_receivable_account(5678, true);
        delinquent_above_slope_before_stop.balance = pcs.permanent_debt_allowed_gwub + 2;
        delinquent_above_slope_before_stop.last_received_timestamp =
            from_time_t(pcs.sugg_thru_decreasing(now) + 1);
        let mut not_delinquent_above_slope_after_stop = make_receivable_account(6789, false);
        not_delinquent_above_slope_after_stop.balance = pcs.permanent_debt_allowed_gwub - 1;
        not_delinquent_above_slope_after_stop.last_received_timestamp =
            from_time_t(pcs.sugg_thru_decreasing(now) - 2);
        let home_dir = ensure_node_home_directory_exists("accountant", "new_delinquencies");
        let db_initializer = DbInitializerReal::new();
        let conn = db_initializer
            .initialize(&home_dir, DEFAULT_CHAIN_ID)
            .unwrap();
        add_receivable_account(&conn, &not_delinquent_inside_grace_period);
        add_receivable_account(&conn, &not_delinquent_after_grace_below_slope);
        add_receivable_account(&conn, &delinquent_above_slope_after_grace);
        add_receivable_account(&conn, &not_delinquent_below_slope_before_stop);
        add_receivable_account(&conn, &delinquent_above_slope_before_stop);
        add_receivable_account(&conn, &not_delinquent_above_slope_after_stop);
        let subject = ReceivableDaoReal::new(conn);

        let result = subject.new_delinquencies(from_time_t(now), &pcs);

        assert_contains(&result, &delinquent_above_slope_after_grace);
        assert_contains(&result, &delinquent_above_slope_before_stop);
        assert_eq!(2, result.len());
    }

    #[test]
    fn new_delinquencies_shallow_slope() {
        let pcs = PaymentCurves {
            payment_suggested_after_sec: 100,
            payment_grace_before_ban_sec: 100,
            permanent_debt_allowed_gwub: 100,
            balance_to_decrease_from_gwub: 110,
            balance_decreases_for_sec: 100,
            unban_when_balance_below_gwub: 0, // doesn't matter for this test
        };
        let now = now_time_t();
        let mut not_delinquent = make_receivable_account(1234, false);
        not_delinquent.balance = 105;
        not_delinquent.last_received_timestamp = from_time_t(pcs.sugg_and_grace(now) - 25);
        let mut delinquent = make_receivable_account(2345, true);
        delinquent.balance = 105;
        delinquent.last_received_timestamp = from_time_t(pcs.sugg_and_grace(now) - 75);
        let home_dir =
            ensure_node_home_directory_exists("accountant", "new_delinquencies_shallow_slope");
        let db_initializer = DbInitializerReal::new();
        let conn = db_initializer
            .initialize(&home_dir, DEFAULT_CHAIN_ID)
            .unwrap();
        add_receivable_account(&conn, &not_delinquent);
        add_receivable_account(&conn, &delinquent);
        let subject = ReceivableDaoReal::new(conn);

        let result = subject.new_delinquencies(from_time_t(now), &pcs);

        assert_contains(&result, &delinquent);
        assert_eq!(1, result.len());
    }

    #[test]
    fn new_delinquencies_steep_slope() {
        let pcs = PaymentCurves {
            payment_suggested_after_sec: 100,
            payment_grace_before_ban_sec: 100,
            permanent_debt_allowed_gwub: 100,
            balance_to_decrease_from_gwub: 1100,
            balance_decreases_for_sec: 100,
            unban_when_balance_below_gwub: 0, // doesn't matter for this test
        };
        let now = now_time_t();
        let mut not_delinquent = make_receivable_account(1234, false);
        not_delinquent.balance = 600;
        not_delinquent.last_received_timestamp = from_time_t(pcs.sugg_and_grace(now) - 25);
        let mut delinquent = make_receivable_account(2345, true);
        delinquent.balance = 600;
        delinquent.last_received_timestamp = from_time_t(pcs.sugg_and_grace(now) - 75);
        let home_dir =
            ensure_node_home_directory_exists("accountant", "new_delinquencies_steep_slope");
        let db_initializer = DbInitializerReal::new();
        let conn = db_initializer
            .initialize(&home_dir, DEFAULT_CHAIN_ID)
            .unwrap();
        add_receivable_account(&conn, &not_delinquent);
        add_receivable_account(&conn, &delinquent);
        let subject = ReceivableDaoReal::new(conn);

        let result = subject.new_delinquencies(from_time_t(now), &pcs);

        assert_contains(&result, &delinquent);
        assert_eq!(1, result.len());
    }

    #[test]
    fn new_delinquencies_does_not_find_existing_delinquencies() {
        let pcs = PaymentCurves {
            payment_suggested_after_sec: 25,
            payment_grace_before_ban_sec: 50,
            permanent_debt_allowed_gwub: 100,
            balance_to_decrease_from_gwub: 200,
            balance_decreases_for_sec: 100,
            unban_when_balance_below_gwub: 0, // doesn't matter for this test
        };
        let now = now_time_t();
        let mut existing_delinquency = make_receivable_account(1234, true);
        existing_delinquency.balance = 250;
        existing_delinquency.last_received_timestamp = from_time_t(pcs.sugg_and_grace(now) - 1);
        let mut new_delinquency = make_receivable_account(2345, true);
        new_delinquency.balance = 250;
        new_delinquency.last_received_timestamp = from_time_t(pcs.sugg_and_grace(now) - 1);

        let home_dir = ensure_node_home_directory_exists(
            "accountant",
            "new_delinquencies_does_not_find_existing_delinquencies",
        );
        let db_initializer = DbInitializerReal::new();
        let conn = db_initializer
            .initialize(&home_dir, DEFAULT_CHAIN_ID)
            .unwrap();
        add_receivable_account(&conn, &existing_delinquency);
        add_receivable_account(&conn, &new_delinquency);
        add_banned_account(&conn, &existing_delinquency);
        let subject = ReceivableDaoReal::new(conn);

        let result = subject.new_delinquencies(from_time_t(now), &pcs);

        assert_contains(&result, &new_delinquency);
        assert_eq!(1, result.len());
    }

    #[test]
    fn paid_delinquencies() {
        let pcs = PaymentCurves {
            payment_suggested_after_sec: 0,   // doesn't matter for this test
            payment_grace_before_ban_sec: 0,  // doesn't matter for this test
            permanent_debt_allowed_gwub: 0,   // doesn't matter for this test
            balance_to_decrease_from_gwub: 0, // doesn't matter for this test
            balance_decreases_for_sec: 0,     // doesn't matter for this test
            unban_when_balance_below_gwub: 50,
        };
        let mut paid_delinquent = make_receivable_account(1234, true);
        paid_delinquent.balance = 50;
        let mut unpaid_delinquent = make_receivable_account(2345, true);
        unpaid_delinquent.balance = 51;
        let home_dir = ensure_node_home_directory_exists("accountant", "paid_delinquencies");
        let db_initializer = DbInitializerReal::new();
        let conn = db_initializer
            .initialize(&home_dir, DEFAULT_CHAIN_ID)
            .unwrap();
        add_receivable_account(&conn, &paid_delinquent);
        add_receivable_account(&conn, &unpaid_delinquent);
        add_banned_account(&conn, &paid_delinquent);
        add_banned_account(&conn, &unpaid_delinquent);
        let subject = ReceivableDaoReal::new(conn);

        let result = subject.paid_delinquencies(&pcs);

        assert_contains(&result, &paid_delinquent);
        assert_eq!(1, result.len());
    }

    #[test]
    fn paid_delinquencies_does_not_find_existing_nondelinquencies() {
        let pcs = PaymentCurves {
            payment_suggested_after_sec: 0,   // doesn't matter for this test
            payment_grace_before_ban_sec: 0,  // doesn't matter for this test
            permanent_debt_allowed_gwub: 0,   // doesn't matter for this test
            balance_to_decrease_from_gwub: 0, // doesn't matter for this test
            balance_decreases_for_sec: 0,     // doesn't matter for this test
            unban_when_balance_below_gwub: 50,
        };
        let mut newly_non_delinquent = make_receivable_account(1234, false);
        newly_non_delinquent.balance = 25;
        let mut old_non_delinquent = make_receivable_account(2345, false);
        old_non_delinquent.balance = 25;

        let home_dir = ensure_node_home_directory_exists(
            "accountant",
            "paid_delinquencies_does_not_find_existing_nondelinquencies",
        );
        let db_initializer = DbInitializerReal::new();
        let conn = db_initializer
            .initialize(&home_dir, DEFAULT_CHAIN_ID)
            .unwrap();
        add_receivable_account(&conn, &newly_non_delinquent);
        add_receivable_account(&conn, &old_non_delinquent);
        add_banned_account(&conn, &newly_non_delinquent);
        let subject = ReceivableDaoReal::new(conn);

        let result = subject.paid_delinquencies(&pcs);

        assert_contains(&result, &newly_non_delinquent);
        assert_eq!(1, result.len());
    }

    fn add_receivable_account(conn: &Box<dyn ConnectionWrapper>, account: &ReceivableAccount) {
        let mut stmt = conn.prepare ("insert into receivable (wallet_address, balance, last_received_timestamp) values (?, ?, ?)").unwrap();
        let params: &[&dyn ToSql] = &[
            &account.wallet,
            &account.balance,
            &to_time_t(account.last_received_timestamp),
        ];
        stmt.execute(params).unwrap();
    }

    fn add_banned_account(conn: &Box<dyn ConnectionWrapper>, account: &ReceivableAccount) {
        let mut stmt = conn
            .prepare("insert into banned (wallet_address) values (?)")
            .unwrap();
        stmt.execute(&[&account.wallet]).unwrap();
    }
}
