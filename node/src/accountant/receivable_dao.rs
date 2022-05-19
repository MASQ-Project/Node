// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
use crate::accountant::dao_utils::Table::Receivable;
use crate::accountant::dao_utils::{
    BalanceChange, InsertUpdateConfig, InsertUpdateCore, InsertUpdateCoreReal, SQLExtParams,
    UpdateConfig,
};
use crate::accountant::{checked_conversion, unsigned_to_signed};
use crate::blockchain::blockchain_interface::PaidReceivable;
use crate::database::connection_wrapper::ConnectionWrapper;
use crate::database::dao_utils;
use crate::database::dao_utils::{now_time_t, to_time_t, DaoFactoryReal};
use crate::db_config::config_dao::{ConfigDaoWrite, ConfigDaoWriteableReal};
use crate::db_config::persistent_configuration::PersistentConfigError;
use crate::sub_lib::accountant::{PaymentThresholds, GWEI_TO_WEI};
use crate::sub_lib::wallet::Wallet;
use indoc::indoc;
use itertools::Either;
use masq_lib::logger::Logger;
use rusqlite::named_params;
use rusqlite::types::{ToSql, Type};
use rusqlite::{OptionalExtension, Row};
use std::time::SystemTime;

#[derive(Debug, PartialEq)]
pub enum ReceivableDaoError {
    SignConversion(u128),
    ConfigurationError(String),
    RusqliteError(String),
}

impl From<PersistentConfigError> for ReceivableDaoError {
    fn from(input: PersistentConfigError) -> Self {
        ReceivableDaoError::ConfigurationError(format!("{:?}", input))
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ReceivableAccount {
    pub wallet: Wallet,
    pub balance: i128,
    pub last_received_timestamp: SystemTime,
}

pub trait ReceivableDao: Send {
    fn more_money_receivable(
        &self,
        core: &dyn InsertUpdateCore,
        wallet: &Wallet,
        amount: u128,
    ) -> Result<(), ReceivableDaoError>;

    fn more_money_received(&mut self, transactions: Vec<PaidReceivable>);

    //TODO used just in tests to assert on other things
    fn account_status(&self, wallet: &Wallet) -> Option<ReceivableAccount>;

    //TODO never used
    fn receivables(&self) -> Vec<ReceivableAccount>;

    fn new_delinquencies(
        &self,
        now: SystemTime,
        payment_thresholds: &PaymentThresholds,
    ) -> Vec<ReceivableAccount>;

    fn paid_delinquencies(&self, payment_thresholds: &PaymentThresholds) -> Vec<ReceivableAccount>;

    //TODO never used
    fn top_records(&self, minimum_amount: u64, maximum_age: u64) -> Vec<ReceivableAccount>;

    fn total(&self) -> i128;
}

pub trait ReceivableDaoFactory {
    fn make(&self) -> Box<dyn ReceivableDao>;
}

impl ReceivableDaoFactory for DaoFactoryReal {
    fn make(&self) -> Box<dyn ReceivableDao> {
        Box::new(ReceivableDaoReal::new(self.make_connection()))
    }
}

pub struct ReceivableDaoReal {
    conn: Box<dyn ConnectionWrapper>,
    logger: Logger,
}

impl ReceivableDao for ReceivableDaoReal {
    //TODO: YES
    fn more_money_receivable(
        &self,
        core: &dyn InsertUpdateCore,
        wallet: &Wallet,
        amount: u128,
    ) -> Result<(), ReceivableDaoError> {
        Ok(core.upsert(&*self.conn,  InsertUpdateConfig{
            insert_sql: "insert into receivable (wallet_address, balance, last_received_timestamp) values (:wallet,:balance,strftime('%s','now'))",
            update_sql: "update receivable set balance = :updated_balance where wallet_address = :wallet",
            params: SQLExtParams::new(
                vec![
                    (":wallet", &&*wallet.to_string()),
                    (":balance", &BalanceChange::new_addition(amount))
                ]),
            table: Receivable,
        })?)
    }

    //TODO -- chop it, you can
    fn more_money_received(&mut self, payments: Vec<PaidReceivable>) {
        self.try_multi_insert_payment(&InsertUpdateCoreReal, &payments) //TODO check if it blows up if you change it to the mock version
            .unwrap_or_else(|e| {
                let mut report_lines =
                    vec![format!("{:10} {:42} {:18}", "Block #", "Wallet", "Amount")];
                let mut sum = 0u128;
                payments.iter().for_each(|t| {
                    report_lines.push(format!(
                        "{:10} {:42} {:18}",
                        t.block_number, t.from, t.wei_amount
                    ));
                    sum += t.wei_amount;
                });
                report_lines.push(format!("{:10} {:42} {:18}", "TOTAL", "", sum));
                let report = report_lines.join("\n");
                error!(
                    self.logger,
                    "Payment reception failed, rolling back: {:?}\n{}", e, report
                );
            })
    }

    //TODO: NO
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

    //TODO: NO
    fn receivables(&self) -> Vec<ReceivableAccount> {
        let mut stmt = self
            .conn
            .prepare("select balance, last_received_timestamp, wallet_address from receivable")
            .expect("Internal error");

        stmt.query_map([], |row| {
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
        .flatten()
        .collect()
    }

    //TODO: NO
    fn new_delinquencies(
        &self,
        system_now: SystemTime,
        payment_thresholds: &PaymentThresholds,
    ) -> Vec<ReceivableAccount> {
        let now = to_time_t(system_now);
        //TODO this slope is tilt in the wrong direction; a minus is absent there at the beginning
        let slope =
            (checked_conversion::<u64, i64>(payment_thresholds.permanent_debt_allowed_gwei)
                - checked_conversion::<u64, i64>(payment_thresholds.debt_threshold_gwei))
                / (checked_conversion::<u64, i64>(payment_thresholds.threshold_interval_sec));
        let sql = indoc!(
            r"
            select r.wallet_address, r.balance, r.last_received_timestamp
            from receivable r left outer join banned b on r.wallet_address = b.wallet_address
            where
                r.last_received_timestamp < :sugg_and_grace
                and r.balance > :balance_to_decrease_from + :slope * (:sugg_and_grace - r.last_received_timestamp)
                and r.balance > :permanent_debt
                and b.wallet_address is null
        "
        );
        let mut stmt = self.conn.prepare(sql).expect("Couldn't prepare statement");
        stmt.query_map(
            named_params! {
                ":slope": slope,
                ":sugg_and_grace": payment_thresholds.sugg_and_grace(now),
                ":balance_to_decrease_from": (payment_thresholds.debt_threshold_gwei as i128) * GWEI_TO_WEI,
                ":permanent_debt": (payment_thresholds.permanent_debt_allowed_gwei as i128) * GWEI_TO_WEI,
            },
            Self::row_to_account,
        )
        .expect("Couldn't retrieve new delinquencies: database corruption")
        .flatten()
        .collect()
    }

    //TODO: NO
    fn paid_delinquencies(&self, payment_thresholds: &PaymentThresholds) -> Vec<ReceivableAccount> {
        let sql = indoc!(
            r"
            select r.wallet_address, r.balance, r.last_received_timestamp
            from receivable r inner join banned b on r.wallet_address = b.wallet_address
            where
                r.balance <= :unban_balance
        "
        );
        let mut stmt = self.conn.prepare(sql).expect("Couldn't prepare statement");
        stmt.query_map(
            named_params! {
                ":unban_balance": (payment_thresholds.unban_below_gwei as i128) * GWEI_TO_WEI,
            },
            Self::row_to_account,
        )
        .expect("Couldn't retrieve new delinquencies: database corruption")
        .flatten()
        .collect()
    }

    //TODO: NO
    fn top_records(&self, minimum_amount: u64, maximum_age: u64) -> Vec<ReceivableAccount> {
        let min_amt =
            unsigned_to_signed::<u64, i64>(minimum_amount).unwrap_or(0x7FFF_FFFF_FFFF_FFFF);
        let max_age = unsigned_to_signed::<u64, i64>(maximum_age).unwrap_or(0x7FFF_FFFF_FFFF_FFFF);
        let min_timestamp = dao_utils::now_time_t() - max_age;
        let mut stmt = self
            .conn
            .prepare(
                r#"
                select
                    balance,
                    last_received_timestamp,
                    wallet_address
                from
                    receivable
                where
                    balance >= ? and
                    last_received_timestamp >= ?
                order by
                    balance desc,
                    last_received_timestamp desc
            "#,
            )
            .expect("Internal error");
        let params: &[&dyn ToSql] = &[&min_amt, &min_timestamp];
        stmt.query_map(params, |row| {
            let balance_result = row.get(0);
            let last_paid_timestamp_result = row.get(1);
            let wallet_result: Result<Wallet, rusqlite::Error> = row.get(2);
            match (balance_result, last_paid_timestamp_result, wallet_result) {
                (Ok(balance), Ok(last_paid_timestamp), Ok(wallet)) => Ok(ReceivableAccount {
                    wallet,
                    balance,
                    last_received_timestamp: dao_utils::from_time_t(last_paid_timestamp),
                }),
                _ => panic!("Database is corrupt: RECEIVABLE table columns and/or types"),
            }
        })
        .expect("Database is corrupt")
        .flatten()
        .collect()
    }

    //TODO: YES _ but different operations
    fn total(&self) -> i128 {
        let mut stmt = self
            .conn
            .prepare("select sum(balance) from receivable")
            .expect("Internal error");
        match stmt.query_row([], |row| {
            let total_balance_result: Result<i128, rusqlite::Error> = row.get(0);
            match total_balance_result {
                Ok(total_balance) => Ok(total_balance),
                Err(e)
                    if e == rusqlite::Error::InvalidColumnType(
                        0,
                        "sum(balance)".to_string(),
                        Type::Null,
                    ) =>
                {
                    Ok(0)
                }
                Err(e) => panic!(
                    "Database is corrupt: RECEIVABLE table columns and/or types: {:?}",
                    e
                ),
            }
        }) {
            Ok(value) => value,
            Err(e) => panic!("Database is corrupt: {:?}", e),
        }
    }
}

impl ReceivableDaoReal {
    pub fn new(conn: Box<dyn ConnectionWrapper>) -> ReceivableDaoReal {
        ReceivableDaoReal {
            conn,
            logger: Logger::new("ReceivableDaoReal"),
        }
    }

    //TODO: YES - direct replace
    fn try_multi_insert_payment(
        &mut self,
        core: &dyn InsertUpdateCore,
        payments: &[PaidReceivable],
    ) -> Result<(), ReceivableDaoError> {
        let tx = match self.conn.transaction() {
            Ok(t) => t,
            Err(e) => return Err(ReceivableDaoError::RusqliteError(e.to_string())),
        };

        let block_number = payments
            .iter()
            .map(|t| t.block_number)
            .max()
            .expect("we should have minimally one payment here");

        let mut writer = ConfigDaoWriteableReal::new(tx);
        match writer.set("start_block", Some(block_number.to_string())) {
            Ok(_) => (),
            Err(e) => return Err(ReceivableDaoError::RusqliteError(format!("{:?}", e))),
        }
        let tx = writer
            .extract()
            .expect("Transaction disappeared from writer");

        {
            for transaction in payments {
                core.update(Either::Right(&tx), &UpdateConfig {
                    update_sql: "update receivable set balance = :updated_balance, last_received_timestamp = :last_received where wallet_address = :wallet",
                    params: SQLExtParams::new(
                        vec![
                            (":wallet", &&*transaction.from.to_string()),
                            //:balance is later recomputed into :updated_balance
                            (":balance", &BalanceChange::new_subtraction(transaction.wei_amount)),
                            (":last_received", &now_time_t()),
                        ]),
                    table: Receivable
                })?
            }
        }
        match tx.commit() {
            // Error response is untested here, because without a mockable Transaction, it's untestable.
            Err(e) => Err(ReceivableDaoError::RusqliteError(format!("{:?}", e))),
            Ok(_) => Ok(()),
        }
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
    use crate::accountant::dao_utils::{InsertUpdateCoreReal, InsertUpdateError, Table};
    use crate::accountant::test_utils::{
        convert_to_all_string_values, make_receivable_account, InsertUpdateCoreMock,
    };
    use crate::database::dao_utils::{from_time_t, now_time_t, to_time_t};
    use crate::database::db_initializer;
    use crate::database::db_initializer::test_utils::ConnectionWrapperMock;
    use crate::database::db_initializer::DbInitializer;
    use crate::database::db_initializer::DbInitializerReal;
    use crate::database::db_migrations::MigratorConfig;
    use crate::db_config::config_dao::ConfigDaoReal;
    use crate::db_config::persistent_configuration::{
        PersistentConfigError, PersistentConfiguration, PersistentConfigurationReal,
    };
    use crate::test_utils::assert_contains;
    use crate::test_utils::make_wallet;
    use masq_lib::test_utils::logging::{init_test_logging, TestLogHandler};
    use masq_lib::test_utils::utils::ensure_node_home_directory_exists;
    use rusqlite::{Connection, Error, OpenFlags};
    use std::sync::{Arc, Mutex};

    #[test]
    fn conversion_from_pce_works() {
        let pce = PersistentConfigError::BadHexFormat("booga".to_string());

        let subject = ReceivableDaoError::from(pce);

        assert_eq!(
            subject,
            ReceivableDaoError::ConfigurationError("BadHexFormat(\"booga\")".to_string())
        );
    }

    #[test]
    fn try_multi_insert_payment_handles_error_of_number_sign_check() {
        let home_dir = ensure_node_home_directory_exists(
            "receivable_dao",
            "try_multi_insert_payment_handles_error_of_number_sign_check",
        );
        let mut subject = ReceivableDaoReal::new(
            DbInitializerReal::default()
                .initialize(&home_dir, true, MigratorConfig::test_default())
                .unwrap(),
        );
        let payments = vec![PaidReceivable {
            block_number: 42u64,
            from: make_wallet("some_address"),
            wei_amount: 18446744073709551615,
        }];

        let result = subject.try_multi_insert_payment(&InsertUpdateCoreReal, &payments.as_slice());

        assert_eq!(
            result,
            Err(ReceivableDaoError::SignConversion(18446744073709551615))
        )
    }

    #[test]
    fn try_multi_insert_payment_handles_error_setting_start_block() {
        let home_dir = ensure_node_home_directory_exists(
            "receivable_dao",
            "try_multi_insert_payment_handles_error_setting_start_block",
        );
        let conn = DbInitializerReal::default()
            .initialize(&home_dir, true, MigratorConfig::test_default())
            .unwrap();
        {
            let mut stmt = conn.prepare("drop table config").unwrap();
            stmt.execute([]).unwrap();
        }
        let mut subject = ReceivableDaoReal::new(conn);

        let payments = vec![PaidReceivable {
            block_number: 42u64,
            from: make_wallet("some_address"),
            wei_amount: 18446744073709551615,
        }];

        let result = subject.try_multi_insert_payment(&InsertUpdateCoreReal, &payments.as_slice());

        assert_eq!(
            result,
            Err(ReceivableDaoError::RusqliteError(
                "DatabaseError(\"no such table: config\")".to_string()
            ))
        )
    }

    #[test]
    #[should_panic(expected = "no such table: receivable")]
    fn try_multi_insert_payment_handles_error_adding_receivables() {
        let home_dir = ensure_node_home_directory_exists(
            "receivable_dao",
            "try_multi_insert_payment_handles_error_adding_receivables",
        );
        let conn = DbInitializerReal::default()
            .initialize(&home_dir, true, MigratorConfig::test_default())
            .unwrap();
        {
            let mut stmt = conn.prepare("drop table receivable").unwrap();
            stmt.execute([]).unwrap();
        }
        let mut subject = ReceivableDaoReal::new(conn);

        let payments = vec![PaidReceivable {
            block_number: 42u64,
            from: make_wallet("some_address"),
            wei_amount: 18446744073709551615,
        }];

        let _ = subject.try_multi_insert_payment(&InsertUpdateCoreReal, payments.as_slice());
    }

    #[test]
    fn more_money_receivable_works_for_new_address() {
        let home_dir = ensure_node_home_directory_exists(
            "receivable_dao",
            "more_money_receivable_works_for_new_address",
        );
        let before = dao_utils::to_time_t(SystemTime::now());
        let wallet = make_wallet("booga");
        let status = {
            let subject = ReceivableDaoReal::new(
                DbInitializerReal::default()
                    .initialize(&home_dir, true, MigratorConfig::test_default())
                    .unwrap(),
            );

            subject
                .more_money_receivable(&InsertUpdateCoreReal, &wallet, 1234)
                .unwrap();
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
            "receivable_dao",
            "more_money_receivable_works_for_existing_address",
        );
        let wallet = make_wallet("booga");
        let subject = {
            let subject = ReceivableDaoReal::new(
                DbInitializerReal::default()
                    .initialize(&home_dir, true, MigratorConfig::test_default())
                    .unwrap(),
            );
            subject
                .more_money_receivable(&InsertUpdateCoreReal, &wallet, 1234)
                .unwrap();
            let mut flags = OpenFlags::empty();
            flags.insert(OpenFlags::SQLITE_OPEN_READ_WRITE);
            let conn =
                Connection::open_with_flags(&home_dir.join(db_initializer::DATABASE_FILE), flags)
                    .unwrap();
            conn.execute(
                "update receivable set last_received_timestamp = 0 where wallet_address = '0x000000000000000000000000000000626f6f6761'",
                [],
            )
            .unwrap();
            subject
        };

        let status = {
            subject
                .more_money_receivable(&InsertUpdateCoreReal, &wallet, 2345)
                .unwrap();
            subject.account_status(&wallet).unwrap()
        };

        assert_eq!(status.wallet, wallet);
        assert_eq!(status.balance, 3579);
        assert_eq!(status.last_received_timestamp, SystemTime::UNIX_EPOCH);
    }

    #[test]
    fn more_money_receivable_works_for_overflow() {
        let home_dir = ensure_node_home_directory_exists(
            "receivable_dao",
            "more_money_receivable_works_for_overflow",
        );
        let subject = ReceivableDaoReal::new(
            DbInitializerReal::default()
                .initialize(&home_dir, true, MigratorConfig::test_default())
                .unwrap(),
        );

        let result =
            subject.more_money_receivable(&InsertUpdateCoreReal, &make_wallet("booga"), u128::MAX);

        assert_eq!(result, Err(ReceivableDaoError::SignConversion(u128::MAX)))
    }

    #[test]
    fn more_money_received_works_for_existing_addresses() {
        let before = dao_utils::to_time_t(SystemTime::now());
        let home_dir = ensure_node_home_directory_exists(
            "receivable_dao",
            "more_money_received_works_for_existing_address",
        );
        let debtor1 = make_wallet("debtor1");
        let debtor2 = make_wallet("debtor2");
        let mut subject = {
            let subject = ReceivableDaoReal::new(
                DbInitializerReal::default()
                    .initialize(&home_dir, true, MigratorConfig::test_default())
                    .unwrap(),
            );
            subject
                .more_money_receivable(&InsertUpdateCoreReal, &debtor1, 1234)
                .unwrap();
            subject
                .more_money_receivable(&InsertUpdateCoreReal, &debtor2, 2345)
                .unwrap();
            let mut flags = OpenFlags::empty();
            flags.insert(OpenFlags::SQLITE_OPEN_READ_WRITE);
            subject
        };

        let (status1, status2) = {
            let transactions = vec![
                PaidReceivable {
                    from: debtor1.clone(),
                    wei_amount: 1200_u128,
                    block_number: 35_u64,
                },
                PaidReceivable {
                    from: debtor2.clone(),
                    wei_amount: 2300_u128,
                    block_number: 57_u64,
                },
            ];

            subject.more_money_received(transactions);
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
        let config_dao = ConfigDaoReal::new(
            DbInitializerReal::default()
                .initialize(&home_dir, true, MigratorConfig::test_default())
                .unwrap(),
        );
        let persistent_config = PersistentConfigurationReal::new(Box::new(config_dao));
        let start_block = persistent_config.start_block().unwrap();
        assert_eq!(57u64, start_block);
    }

    #[test]
    fn more_money_received_throws_away_payments_from_unknown_addresses() {
        let home_dir = ensure_node_home_directory_exists(
            "receivable_dao",
            "more_money_received_throws_away_payments_from_unknown_addresses",
        );
        let debtor = make_wallet("unknown_wallet");
        let mut subject = ReceivableDaoReal::new(
            DbInitializerReal::default()
                .initialize(&home_dir, true, MigratorConfig::test_default())
                .unwrap(),
        );

        let status = {
            let transactions = vec![PaidReceivable {
                from: debtor.clone(),
                wei_amount: 2300_u128,
                block_number: 33_u64,
            }];
            subject.more_money_received(transactions);
            subject.account_status(&debtor)
        };

        assert!(status.is_none());
    }

    #[test]
    fn more_money_received_logs_when_transaction_fails() {
        init_test_logging();
        let conn_mock =
            ConnectionWrapperMock::default().transaction_result(Err(Error::InvalidQuery));
        let mut receivable_dao = ReceivableDaoReal::new(Box::new(conn_mock));
        let payments = vec![
            PaidReceivable {
                block_number: 1234567890,
                from: Wallet::new("0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
                wei_amount: 123456789123456789,
            },
            PaidReceivable {
                block_number: 2345678901,
                from: Wallet::new("0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"),
                wei_amount: 234567891234567891,
            },
            PaidReceivable {
                block_number: 3456789012,
                from: Wallet::new("0xCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"),
                wei_amount: 345678912345678912,
            },
        ];

        receivable_dao.more_money_received(payments);

        TestLogHandler::new().exists_log_containing(&format!(
            "ERROR: ReceivableDaoReal: Payment reception failed, rolling back: RusqliteError(\"Query is not read-only\")\n\
            Block #    Wallet                                     Amount            \n\
            1234567890 0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 123456789123456789\n\
            2345678901 0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb 234567891234567891\n\
            3456789012 0xcccccccccccccccccccccccccccccccccccccccc 345678912345678912\n\
            TOTAL                                                 703703592703703592"
        ));
    }

    #[test]
    fn receivable_account_status_works_when_account_doesnt_exist() {
        let home_dir = ensure_node_home_directory_exists(
            "receivable_dao",
            "receivable_account_status_works_when_account_doesnt_exist",
        );
        let wallet = make_wallet("booga");
        let subject = ReceivableDaoReal::new(
            DbInitializerReal::default()
                .initialize(&home_dir, true, MigratorConfig::test_default())
                .unwrap(),
        );

        let result = subject.account_status(&wallet);

        assert_eq!(result, None);
    }

    #[test]
    fn receivables_fetches_all_receivable_accounts() {
        let home_dir = ensure_node_home_directory_exists(
            "receivable_dao",
            "receivables_fetches_all_receivable_accounts",
        );
        let wallet1 = make_wallet("wallet1");
        let wallet2 = make_wallet("wallet2");
        let time_stub = SystemTime::now();
        let subject = ReceivableDaoReal::new(
            DbInitializerReal::default()
                .initialize(&home_dir, true, MigratorConfig::test_default())
                .unwrap(),
        );

        subject
            .more_money_receivable(&InsertUpdateCoreReal, &wallet1, 1234)
            .unwrap();
        subject
            .more_money_receivable(&InsertUpdateCoreReal, &wallet2, 2345)
            .unwrap();

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
        let pcs = PaymentThresholds {
            maturity_threshold_sec: 25,
            payment_grace_period_sec: 50,
            permanent_debt_allowed_gwei: 100,
            debt_threshold_gwei: 200,
            threshold_interval_sec: 100,
            unban_below_gwei: 0, // doesn't matter for this test
        };
        let now = now_time_t();
        let mut not_delinquent_inside_grace_period = make_receivable_account(1234, false);
        not_delinquent_inside_grace_period.balance =
            i128::try_from(pcs.debt_threshold_gwei + 1).unwrap();
        not_delinquent_inside_grace_period.last_received_timestamp =
            from_time_t(pcs.sugg_and_grace(now) + 2);
        let mut not_delinquent_after_grace_below_slope = make_receivable_account(2345, false);
        not_delinquent_after_grace_below_slope.balance =
            i128::try_from(pcs.debt_threshold_gwei - 2).unwrap();
        not_delinquent_after_grace_below_slope.last_received_timestamp =
            from_time_t(pcs.sugg_and_grace(now) - 1);
        let mut delinquent_above_slope_after_grace = make_receivable_account(3456, true);
        delinquent_above_slope_after_grace.balance =
            i128::try_from(pcs.debt_threshold_gwei - 1).unwrap();
        delinquent_above_slope_after_grace.last_received_timestamp =
            from_time_t(pcs.sugg_and_grace(now) - 2);
        let mut not_delinquent_below_slope_before_stop = make_receivable_account(4567, false);
        not_delinquent_below_slope_before_stop.balance =
            i128::try_from(pcs.permanent_debt_allowed_gwei + 1).unwrap();
        not_delinquent_below_slope_before_stop.last_received_timestamp =
            from_time_t(pcs.sugg_thru_decreasing(now) + 2);
        let mut delinquent_above_slope_before_stop = make_receivable_account(5678, true);
        delinquent_above_slope_before_stop.balance =
            i128::try_from(pcs.permanent_debt_allowed_gwei + 2).unwrap();
        delinquent_above_slope_before_stop.last_received_timestamp =
            from_time_t(pcs.sugg_thru_decreasing(now) + 1);
        let mut not_delinquent_above_slope_after_stop = make_receivable_account(6789, false);
        not_delinquent_above_slope_after_stop.balance =
            i128::try_from(pcs.permanent_debt_allowed_gwei - 1).unwrap();
        not_delinquent_above_slope_after_stop.last_received_timestamp =
            from_time_t(pcs.sugg_thru_decreasing(now) - 2);
        let home_dir = ensure_node_home_directory_exists("accountant", "new_delinquencies");
        let db_initializer = DbInitializerReal::default();
        let conn = db_initializer
            .initialize(&home_dir, true, MigratorConfig::test_default())
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
        let pcs = PaymentThresholds {
            maturity_threshold_sec: 100,
            payment_grace_period_sec: 100,
            permanent_debt_allowed_gwei: 100,
            debt_threshold_gwei: 110,
            threshold_interval_sec: 100,
            unban_below_gwei: 0, // doesn't matter for this test
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
        let db_initializer = DbInitializerReal::default();
        let conn = db_initializer
            .initialize(&home_dir, true, MigratorConfig::test_default())
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
        let pcs = PaymentThresholds {
            maturity_threshold_sec: 100,
            payment_grace_period_sec: 100,
            permanent_debt_allowed_gwei: 100,
            debt_threshold_gwei: 1100,
            threshold_interval_sec: 100,
            unban_below_gwei: 0, // doesn't matter for this test
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
        let db_initializer = DbInitializerReal::default();
        let conn = db_initializer
            .initialize(&home_dir, true, MigratorConfig::test_default())
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
        let pcs = PaymentThresholds {
            maturity_threshold_sec: 25,
            payment_grace_period_sec: 50,
            permanent_debt_allowed_gwei: 100,
            debt_threshold_gwei: 200,
            threshold_interval_sec: 100,
            unban_below_gwei: 0, // doesn't matter for this test
        };
        let now = now_time_t();
        let mut existing_delinquency = make_receivable_account(1234, true);
        existing_delinquency.balance = 250;
        existing_delinquency.last_received_timestamp = from_time_t(pcs.sugg_and_grace(now) - 1);
        let mut new_delinquency = make_receivable_account(2345, true);
        new_delinquency.balance = 250;
        new_delinquency.last_received_timestamp = from_time_t(pcs.sugg_and_grace(now) - 1);

        let home_dir = ensure_node_home_directory_exists(
            "receivable_dao",
            "new_delinquencies_does_not_find_existing_delinquencies",
        );
        let db_initializer = DbInitializerReal::default();
        let conn = db_initializer
            .initialize(&home_dir, true, MigratorConfig::test_default())
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
        let pcs = PaymentThresholds {
            maturity_threshold_sec: 0,
            payment_grace_period_sec: 0,
            permanent_debt_allowed_gwei: 0,
            debt_threshold_gwei: 0,
            threshold_interval_sec: 0,
            unban_below_gwei: 50,
        };
        let mut paid_delinquent = make_receivable_account(1234, true);
        paid_delinquent.balance = 50;
        let mut unpaid_delinquent = make_receivable_account(2345, true);
        unpaid_delinquent.balance = 51;
        let home_dir = ensure_node_home_directory_exists("accountant", "paid_delinquencies");
        let db_initializer = DbInitializerReal::default();
        let conn = db_initializer
            .initialize(&home_dir, true, MigratorConfig::test_default())
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
        let pcs = PaymentThresholds {
            maturity_threshold_sec: 0,
            payment_grace_period_sec: 0,
            permanent_debt_allowed_gwei: 0,
            debt_threshold_gwei: 0,
            threshold_interval_sec: 0,
            unban_below_gwei: 0,
        };
        let mut newly_non_delinquent = make_receivable_account(1234, false);
        newly_non_delinquent.balance = 25;
        let mut old_non_delinquent = make_receivable_account(2345, false);
        old_non_delinquent.balance = 25;

        let home_dir = ensure_node_home_directory_exists(
            "receivable_dao",
            "paid_delinquencies_does_not_find_existing_nondelinquencies",
        );
        let db_initializer = DbInitializerReal::default();
        let conn = db_initializer
            .initialize(&home_dir, true, MigratorConfig::test_default())
            .unwrap();
        add_receivable_account(&conn, &newly_non_delinquent);
        add_receivable_account(&conn, &old_non_delinquent);
        add_banned_account(&conn, &newly_non_delinquent);
        let subject = ReceivableDaoReal::new(conn);

        let result = subject.paid_delinquencies(&pcs);

        assert_contains(&result, &newly_non_delinquent);
        assert_eq!(1, result.len());
    }

    #[test]
    fn top_records_and_total() {
        let home_dir = ensure_node_home_directory_exists("receivable_dao", "top_records_and_total");
        let conn = DbInitializerReal::default()
            .initialize(&home_dir, true, MigratorConfig::test_default())
            .unwrap();
        let insert = |wallet: &str, balance: i64, timestamp: i64| {
            let params: &[&dyn ToSql] = &[&wallet, &balance, &timestamp];
            conn
                .prepare("insert into receivable (wallet_address, balance, last_received_timestamp) values (?, ?, ?)")
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
        );
        insert(
            "0x2222222222222222222222222222222222222222",
            1_000_000_000, // minimum amount
            timestamp2,    // above maximum age - reject
        );
        insert(
            "0x3333333333333333333333333333333333333333",
            1_000_000_000, // minimum amount
            timestamp3,    // below maximum age
        );
        insert(
            "0x4444444444444444444444444444444444444444",
            1_000_000_001, // above minimum amount
            timestamp4,    // below maximum age
        );
        let subject = ReceivableDaoReal::new(conn);

        let top_records = subject.top_records(1_000_000_000, 86400);
        let total = subject.total();

        assert_eq!(
            top_records,
            vec![
                ReceivableAccount {
                    wallet: Wallet::new("0x4444444444444444444444444444444444444444"),
                    balance: 1_000_000_001,
                    last_received_timestamp: dao_utils::from_time_t(timestamp4),
                },
                ReceivableAccount {
                    wallet: Wallet::new("0x3333333333333333333333333333333333333333"),
                    balance: 1_000_000_000,
                    last_received_timestamp: dao_utils::from_time_t(timestamp3),
                },
            ]
        );
        assert_eq!(total, 4_000_000_000)
    }

    #[test]
    fn correctly_totals_zero_records() {
        let home_dir =
            ensure_node_home_directory_exists("receivable_dao", "correctly_totals_zero_records");
        let conn = DbInitializerReal::default()
            .initialize(&home_dir, true, MigratorConfig::test_default())
            .unwrap();
        let subject = ReceivableDaoReal::new(conn);

        let result = subject.total();

        assert_eq!(result, 0)
    }

    // #[test]
    // fn insert_or_update_receivable_works_for_insert_positive() {
    //     let wallet_address = "xyz456";
    //     let path = ensure_node_home_directory_exists(
    //         "dao_shared_methods",
    //         "insert_or_update_receivable_works_for_insert_positive",
    //     );
    //     let conn_box = DbInitializerReal::default()
    //         .initialize(&path, true, MigratorConfig::test_default())
    //         .unwrap();
    //     let conn = conn_box.as_ref();
    //     let amount_wei = i128::MAX;
    //
    //     let result = upsert_receivable(conn, &InsertUpdateCoreReal, wallet_address, amount_wei);
    //
    //     assert_eq!(result, Ok(()));
    //     let (balance, last_timestamp) = read_row_receivable(conn, wallet_address).unwrap();
    //     assert!(is_timely_around(last_timestamp));
    //     assert_eq!(balance, amount_wei)
    // }
    //
    // #[test]
    // fn insert_or_update_receivable_works_for_update_positive() {
    //     let wallet_address = "xyz789";
    //     let path = ensure_node_home_directory_exists(
    //         "dao_shared_methods",
    //         "insert_or_update_receivable_works_for_update_positive",
    //     );
    //     let conn = DbInitializerReal::default()
    //         .initialize(&path, true, MigratorConfig::test_default())
    //         .unwrap();
    //     insert_receivable_100_balance_100_last_time_stamp(conn.as_ref(), wallet_address);
    //     let amount_wei = i128::MAX - 100;
    //
    //     let result = upsert_receivable(
    //         conn.as_ref(),
    //         &InsertUpdateCoreReal,
    //         wallet_address,
    //         amount_wei,
    //     );
    //
    //     assert_eq!(result, Ok(()));
    //     let (balance, last_timestamp) = read_row_receivable(conn.as_ref(), wallet_address).unwrap();
    //     assert_eq!(last_timestamp, 100); //TODO this might be an old issue - do we really never want to update the timestamp? Can it ever disappear or the timestamp from the initial insertion persists forever?
    //     assert_eq!(balance, amount_wei + 100)
    // }

    #[test]
    fn upsert_in_more_money_receivable_params_assertion() {
        let insert_or_update_params_arc = Arc::new(Mutex::new(vec![]));
        let wallet = make_wallet("xyz123");
        let amount = 100;
        let insert_update_core = InsertUpdateCoreMock::default()
            .upsert_params(&insert_or_update_params_arc)
            .upsert_results(Err(InsertUpdateError("SomethingWrong".to_string())));
        let subject = ReceivableDaoReal::new(Box::new(ConnectionWrapperMock::new()));

        let result = subject.more_money_receivable(&insert_update_core, &wallet, amount);

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
                (":wallet", &wallet.to_string()),
                (":balance", &amount.to_string())
            ])
        )
    }

    #[test]
    fn update_in_try_multi_insert_payment_params_assertion() {
        let insert_or_update_params_arc = Arc::new(Mutex::new(vec![]));
        let insert_update_core = InsertUpdateCoreMock::default()
            .update_params(&insert_or_update_params_arc)
            .update_result(Err(InsertUpdateError("SomethingWrong".to_string())));
        let mut subject = ReceivableDaoReal::new(Box::new(ConnectionWrapperMock::new()));
        let payments = vec![
            PaidReceivable {
                block_number: 42u64,
                from: make_wallet("some_address"),
                wei_amount: 18446744073709551615,
            },
            PaidReceivable {
                block_number: 60u64,
                from: make_wallet("other_address"),
                wei_amount: 444444555333337,
            },
        ];

        let result = subject.try_multi_insert_payment(&insert_update_core, &payments);

        assert_eq!(
            result,
            Err(ReceivableDaoError::RusqliteError(
                "SomethingWrong".to_string()
            ))
        );
        let mut insert_or_update_params = insert_or_update_params_arc.lock().unwrap();
        let (select_sql, update_sql, table, sql_param_names) =
            insert_or_update_params.pop().unwrap();
        assert_eq!(
            select_sql,
            "select balance from receivable where wallet_address = :wallet"
        );
        assert_eq!(update_sql, "update receivable set balance = :updated_balance, last_received_timestamp = :last_received where wallet_address = :wallet");
        assert_eq!(table, Table::Receivable.to_string());
        let sql_param_names_assertable: Vec<(String, String)> = sql_param_names
            .into_iter()
            .filter(|(param, _)| param.as_str() != ":last_received")
            .collect();
        assert_eq!(
            sql_param_names_assertable,
            convert_to_all_string_values(vec![
                (":wallet", &make_wallet("some_address").to_string()),
                (":balance", &18446744073709551615_i128.to_string()),
            ])
        );
        let (select_sql_2, update_sql_2, table_2, sql_param_names_2) =
            insert_or_update_params.pop().unwrap();
        assert_eq!(select_sql_2, select_sql);
        assert_eq!(update_sql_2, update_sql);
        assert_eq!(table_2, table);
        let sql_param_names_2_assertable: Vec<(String, String)> = sql_param_names_2
            .into_iter()
            .filter(|(param, _)| param.as_str() != ":last_received")
            .collect();
        assert_eq!(
            sql_param_names_2_assertable,
            convert_to_all_string_values(vec![
                (":wallet", &make_wallet("other_address").to_string()),
                (":balance", &444444555333337_i128.to_string()),
            ])
        );
        assert_eq!(insert_or_update_params.pop(), None)
    }

    // #[test]
    // fn update_receivable_works_positive() {
    //     let wallet_address = "xyz123";
    //     let path = ensure_node_home_directory_exists(
    //         "dao_shared_methods",
    //         "update_receivable_works_positive",
    //     );
    //     let mut conn = DbInitializerReal::default()
    //         .initialize(&path, true, MigratorConfig::test_default())
    //         .unwrap();
    //     insert_receivable_100_balance_100_last_time_stamp(conn.as_ref(), wallet_address);
    //     let tx = conn.transaction().unwrap();
    //     let amount_wei = i128::MAX - 100;
    //     let last_received_time_stamp_sec = 4_545_789;
    //
    //     let result = update_receivable(
    //         &tx,
    //         &InsertUpdateCoreReal,
    //         wallet_address,
    //         amount_wei,
    //         last_received_time_stamp_sec,
    //     );
    //
    //     tx.commit().unwrap();
    //     assert_eq!(result, Ok(()));
    //     let (balance, last_time_stamp) =
    //         read_row_receivable(conn.as_ref(), wallet_address).unwrap();
    //     assert_eq!(balance, amount_wei + 100);
    //     assert_eq!(last_time_stamp, last_received_time_stamp_sec);
    // }
    //
    // #[test]
    // fn update_receivable_works_negative() {
    //     let wallet_address = "xyz178";
    //     let path = ensure_node_home_directory_exists(
    //         "dao_shared_methods",
    //         "update_receivable_works_negative",
    //     );
    //     let mut conn = DbInitializerReal::default()
    //         .initialize(&path, true, MigratorConfig::test_default())
    //         .unwrap();
    //     insert_receivable_100_balance_100_last_time_stamp(conn.as_ref(), wallet_address);
    //     let tx = conn.transaction().unwrap();
    //     let amount_wei = -345_125;
    //     let last_received_time_stamp_sec = 4_545_789;
    //
    //     let result = update_receivable(
    //         &tx,
    //         &InsertUpdateCoreReal,
    //         wallet_address,
    //         amount_wei,
    //         last_received_time_stamp_sec,
    //     );
    //
    //     tx.commit().unwrap();
    //     assert_eq!(result, Ok(()));
    //     let (balance, last_time_stamp) =
    //         read_row_receivable(conn.as_ref(), wallet_address).unwrap();
    //     assert_eq!(balance, -345_025);
    //     assert_eq!(last_time_stamp, last_received_time_stamp_sec);
    // }

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
