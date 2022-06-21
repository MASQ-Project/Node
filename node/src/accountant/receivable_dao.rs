// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
use crate::accountant::blob_utils::Table::Receivable;
use crate::accountant::blob_utils::{
    collect_and_sum_i128_values_from_table, BalanceChange, InsertUpdateConfig, InsertUpdateCore,
    InsertUpdateCoreReal, ParamKeyHolder, SQLExtendedParams, Table, UpdateConfig,
};
use crate::accountant::receivable_dao::ReceivableDaoError::RusqliteError;
use crate::accountant::{checked_conversion, ThresholdUtils};
use crate::blockchain::blockchain_interface::BlockchainTransaction;
use crate::database::connection_wrapper::ConnectionWrapper;
use crate::database::dao_utils;
use crate::database::dao_utils::{now_time_t, to_time_t, DaoFactoryReal};
use crate::db_config::persistent_configuration::PersistentConfigError;
use crate::sub_lib::accountant::{PaymentThresholds, GWEI_TO_WEI};
use crate::sub_lib::wallet::Wallet;
use indoc::indoc;
use itertools::Either;
use masq_lib::logger::Logger;
use masq_lib::utils::plus;
use rusqlite::types::ToSql;
use rusqlite::{named_params, params_from_iter, Error};
use rusqlite::{OptionalExtension, Row};
use std::time::SystemTime;

#[derive(Debug, PartialEq)]
pub enum ReceivableDaoError {
    SignConversion(SignConversionError<u128>),
    ConfigurationError(String),
    RusqliteError(String),
}

#[derive(Debug, PartialEq)]
pub enum SignConversionError<T> {
    Msg(String),
    BadNum(T),
}

impl From<PersistentConfigError> for ReceivableDaoError {
    fn from(input: PersistentConfigError) -> Self {
        ReceivableDaoError::ConfigurationError(format!("{:?}", input))
    }
}

impl From<rusqlite::Error> for ReceivableDaoError {
    fn from(input: Error) -> Self {
        RusqliteError(format!("{:?}", input))
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
        wallet: &Wallet,
        amount: u128,
    ) -> Result<(), ReceivableDaoError>;

    fn more_money_received(&mut self, transactions: Vec<BlockchainTransaction>);

    //TODO never used -- remove and substitute with top records
    fn receivables(&self) -> Vec<ReceivableAccount>;

    fn new_delinquencies(
        &self,
        now: SystemTime,
        payment_thresholds: &PaymentThresholds,
    ) -> Vec<ReceivableAccount>;

    fn paid_delinquencies(&self, payment_thresholds: &PaymentThresholds) -> Vec<ReceivableAccount>;

    //TODO never used
    //fn top_records(&self, minimum_amount: u64, maximum_age: u64) -> Vec<ReceivableAccount>;

    fn total(&self) -> i128;

    #[cfg(test)]
    fn account_status(&self, wallet: &Wallet) -> Option<ReceivableAccount>;
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
    insert_update_core: Box<dyn InsertUpdateCore>,
    logger: Logger,
}

impl ReceivableDao for ReceivableDaoReal {
    fn more_money_receivable(
        &self,
        wallet: &Wallet,
        amount: u128,
    ) -> Result<(), ReceivableDaoError> {
        Ok(self.insert_update_core.upsert(&*self.conn,  InsertUpdateConfig{
            insert_sql: "insert into receivable (wallet_address, balance, last_received_timestamp) values (:wallet,:balance,strftime('%s','now'))",
            update_sql: "update receivable set balance = :updated_balance where wallet_address = :wallet",
            params: SQLExtendedParams::new(
                vec![
                    (":wallet", &ParamKeyHolder::new(wallet,"wallet_address")),
                    (":balance", &BalanceChange::new_addition(amount))
                ]),
            table: Receivable,
        })?)
    }

    //TODO -- chop it, you can do it
    fn more_money_received(&mut self, payments: Vec<BlockchainTransaction>) {
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

    //TODO: probably replace with 'top records' with proper range
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

    fn new_delinquencies(
        &self,
        system_now: SystemTime,
        payment_thresholds: &PaymentThresholds,
    ) -> Vec<ReceivableAccount> {
        self.mine_metadata_of_yet_unbanned(payment_thresholds, system_now);
        let sql = indoc!(
            r"
            select r.wallet_address, r.balance, r.last_received_timestamp
            from receivable r
            left outer join banned b on r.wallet_address = b.wallet_address
            inner join delinquency_metadata d on r.wallet_address = d.wallet_address
            where
                r.last_received_timestamp < :sugg_and_grace
                and r.balance > d.curve_point
                and b.wallet_address is null
        "
        );
        let findings = self
            .conn
            .prepare(sql)
            .expect("Couldn't prepare statement")
            .query_map(
                named_params! {
                    ":sugg_and_grace": payment_thresholds.sugg_and_grace(to_time_t(system_now)),
                },
                Self::row_to_account,
            )
            .expect("Couldn't retrieve new delinquencies: database corruption")
            .flatten()
            .collect();
        self.truncate_metadata_table();
        findings
    }

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
        let unban_balance = (payment_thresholds.unban_below_gwei as i128) * GWEI_TO_WEI;
        stmt.query_map(
            named_params! {
                ":unban_balance": unban_balance,
            },
            Self::row_to_account,
        )
        .expect("Couldn't retrieve new delinquencies: database corruption")
        .flatten()
        .collect()
    }

    // TODO: dead code
    // fn top_records(&self, minimum_amount: u64, maximum_age: u64) -> Vec<ReceivableAccount> {
    //     let min_amt =
    //         unsigned_to_signed::<u64, i64>(minimum_amount).unwrap_or(0x7FFF_FFFF_FFFF_FFFF);
    //     let max_age = unsigned_to_signed::<u64, i64>(maximum_age).unwrap_or(0x7FFF_FFFF_FFFF_FFFF);
    //     let min_timestamp = dao_utils::now_time_t() - max_age;
    //     let mut stmt = self
    //         .conn
    //         .prepare(
    //             r#"
    //             select
    //                 balance,
    //                 last_received_timestamp,
    //                 wallet_address
    //             from
    //                 receivable
    //             where
    //                 balance >= ? and
    //                 last_received_timestamp >= ?
    //             order by
    //                 balance desc,
    //                 last_received_timestamp desc
    //         "#,
    //         )
    //         .expect("Internal error");
    //     let params: &[&dyn ToSql] = &[&min_amt, &min_timestamp];
    //     stmt.query_map(params, |row| {
    //         let balance_result = row.get(0);
    //         let last_paid_timestamp_result = row.get(1);
    //         let wallet_result: Result<Wallet, rusqlite::Error> = row.get(2);
    //         match (balance_result, last_paid_timestamp_result, wallet_result) {
    //             (Ok(balance), Ok(last_paid_timestamp), Ok(wallet)) => Ok(ReceivableAccount {
    //                 wallet,
    //                 balance,
    //                 last_received_timestamp: dao_utils::from_time_t(last_paid_timestamp),
    //             }),
    //             _ => panic!("Database is corrupt: RECEIVABLE table columns and/or types"),
    //         }
    //     })
    //     .expect("Database is corrupt")
    //     .flatten()
    //     .collect()
    // }

    fn total(&self) -> i128 {
        collect_and_sum_i128_values_from_table(self.conn.as_ref(), Table::Receivable, "balance")
    }

    #[cfg(test)]
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
}

impl ReceivableDaoReal {
    pub fn new(conn: Box<dyn ConnectionWrapper>) -> ReceivableDaoReal {
        ReceivableDaoReal {
            conn,
            insert_update_core: Box::new(InsertUpdateCoreReal),
            logger: Logger::new("ReceivableDaoReal"),
        }
    }

    fn mine_metadata_of_yet_unbanned(
        &self,
        payment_thresholds: &PaymentThresholds,
        system_now: SystemTime,
    ) {
        let sql = indoc!(
            r"
            create temp table if not exists delinquency_metadata(
                wallet_address text not null,
                curve_point blob not null
            )"
        );
        self.conn
            .prepare(sql)
            .expect("internal error")
            .execute([])
            .expect("creation of a temporary table failed");
        let mut select_stm = self
            .conn
            .prepare(indoc!(
                r"
                select r.wallet_address, r.last_received_timestamp from receivable r
                left outer join banned b on r.wallet_address = b.wallet_address
                where b.wallet_address is null"
            ))
            .expect("internal error");
        let found_data = select_stm
            .query_map([], |row| {
                let wallet_address: rusqlite::Result<String> = row.get(0);
                let timestamp: rusqlite::Result<i64> = row.get(1);
                match (wallet_address, timestamp) {
                    (Ok(wallet_address), Ok(timestamp)) => Ok((
                        wallet_address,
                        Self::delinquency_curve_height_detection(
                            payment_thresholds,
                            to_time_t(system_now),
                            timestamp,
                        ),
                    )),
                    _ => unimplemented!(),
                }
            })
            .expect("internal error")
            .flatten()
            .collect::<Vec<(String, i128)>>();
        let serial_params = Self::serialize_sql_params(found_data);
        let sql = Self::prepare_multi_insert_statement(serial_params.len() / 2);
        let mut stm = self.conn.prepare(&sql).expect("bad multi insert statement");
        stm.execute(params_from_iter(
            serial_params.iter().map(|param| param.as_ref()),
        ))
        .expect("insert operation failed");
    }

    pub fn delinquency_curve_height_detection(
        payment_thresholds: &PaymentThresholds,
        now: i64,
        timestamp: i64,
    ) -> i128 {
        let time = payment_thresholds.grace(now) - timestamp;
        let time = if time.is_negative() { 0 } else { time };
        ThresholdUtils::calculate_sloped_threshold_by_time(
            payment_thresholds,
            checked_conversion::<i64, u64>(time),
        ) as i128
            * GWEI_TO_WEI
    }

    fn prepare_multi_insert_statement(row_count: usize) -> String {
        let mut flexible_part = "(?, ?),".repeat(row_count);
        flexible_part.pop();
        format!(
            "insert into delinquency_metadata (wallet_address,curve_point) values {}",
            flexible_part
        )
    }

    fn serialize_sql_params(pairs: Vec<(String, i128)>) -> Vec<Box<dyn ToSql>> {
        pairs.into_iter().fold(vec![], |acc, (wallet, point)| {
            plus(plus(acc, Box::new(wallet)), Box::new(point))
        })
    }

    fn truncate_metadata_table(&self) {
        //'To truncate a table in SQLite, you just need to execute a DELETE statement without a WHERE clause'
        let _ = self
            .conn
            .prepare("delete from delinquency_metadata")
            .expect("internal error")
            .execute([])
            .expect("internal error");
    }

    fn try_multi_insert_payment(
        &mut self,
        core: &dyn InsertUpdateCore,
        payments: &[BlockchainTransaction],
    ) -> Result<(), ReceivableDaoError> {
        let xactn = self.conn.transaction()?;
        {
            for transaction in payments {
                core.update(Either::Right(&xactn), &UpdateConfig {
                    update_sql: "update receivable set balance = :updated_balance, last_received_timestamp = :last_received where wallet_address = :wallet",
                    params: SQLExtendedParams::new(
                        vec![
                            (":wallet", &ParamKeyHolder::new(&transaction.from,"wallet_address")),
                            //:balance is later recomputed into :updated_balance
                            (":balance", &BalanceChange::polite_new_subtraction(transaction.wei_amount).map_err(|e|ReceivableDaoError::SignConversion(SignConversionError::Msg(e)))?),
                            (":last_received", &now_time_t()),
                        ]),
                    table: Receivable
                })?
            }
        }
        match xactn.commit() {
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
    use crate::accountant::blob_utils::{InsertUpdateCoreReal, InsertUpdateError, Table};
    use crate::accountant::test_utils::{
        assert_on_sloped_segment_of_payment_thresholds_and_its_proper_alignment,
        convert_to_all_string_values, make_receivable_account, InsertUpdateCoreMock,
    };
    use crate::database::dao_utils::{from_time_t, now_time_t, to_time_t};
    use crate::database::db_initializer;
    use crate::database::db_initializer::test_utils::ConnectionWrapperMock;
    use crate::database::db_initializer::DbInitializer;
    use crate::database::db_initializer::DbInitializerReal;
    use crate::database::db_migrations::MigratorConfig;
    use crate::db_config::persistent_configuration::PersistentConfigError;
    use crate::test_utils::assert_contains;
    use crate::test_utils::make_wallet;
    use masq_lib::test_utils::logging::{init_test_logging, TestLogHandler};
    use masq_lib::test_utils::utils::ensure_node_home_directory_exists;
    use rusqlite::{Connection, OpenFlags};
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
        let payments = vec![BlockchainTransaction {
            block_number: 42u64,
            from: make_wallet("some_address"),
            wei_amount: u128::MAX,
        }];

        let result = subject.try_multi_insert_payment(&InsertUpdateCoreReal, &payments.as_slice());

        assert_eq!(
            result,
            Err(ReceivableDaoError::SignConversion(
                SignConversionError::Msg("Overflow detected with 340282366920938463463374607431768211455: cannot be converted from u128 to i128".to_string())
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

        let payments = vec![BlockchainTransaction {
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

            subject.more_money_receivable(&wallet, 1234).unwrap();
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
            subject.more_money_receivable(&wallet, 1234).unwrap();
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
            subject.more_money_receivable(&wallet, 2345).unwrap();
            subject.account_status(&wallet).unwrap()
        };

        assert_eq!(status.wallet, wallet);
        assert_eq!(status.balance, 3579);
        assert_eq!(status.last_received_timestamp, SystemTime::UNIX_EPOCH);
    }

    #[test]
    #[should_panic(
        expected = "Overflow detected with 340282366920938463463374607431768211455: cannot be converted from u128 to i128"
    )]
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

        let _ = subject.more_money_receivable(&make_wallet("booga"), u128::MAX);
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
            subject.more_money_receivable(&debtor1, 1234).unwrap();
            subject.more_money_receivable(&debtor2, 2345).unwrap();
            let mut flags = OpenFlags::empty();
            flags.insert(OpenFlags::SQLITE_OPEN_READ_WRITE);
            subject
        };

        let (status1, status2) = {
            let transactions = vec![
                BlockchainTransaction {
                    from: debtor1.clone(),
                    wei_amount: 1200_u128,
                    block_number: 35_u64,
                },
                BlockchainTransaction {
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
            let transactions = vec![BlockchainTransaction {
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
    fn more_money_received_logs_when_try_multi_insert_payment_fails() {
        init_test_logging();

        let home_dir = ensure_node_home_directory_exists(
            "receivable_dao",
            "more_money_received_logs_when_try_multi_insert_payment_fails",
        );
        let mut subject = ReceivableDaoReal::new(
            DbInitializerReal::default()
                .initialize(&home_dir, true, MigratorConfig::test_default())
                .unwrap(),
        );
        // Sabotage the database so there'll be an error
        {
            let mut conn = DbInitializerReal::default()
                .initialize(&home_dir, false, MigratorConfig::test_default())
                .unwrap();
            let xactn = conn.transaction().unwrap();
            xactn
                .prepare("drop table receivable")
                .unwrap()
                .execute([])
                .unwrap();
            xactn.commit().unwrap();
        }

        let payments = vec![
            BlockchainTransaction {
                block_number: 1234567890,
                from: Wallet::new("0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
                wei_amount: 123456789123456789,
            },
            BlockchainTransaction {
                block_number: 2345678901,
                from: Wallet::new("0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"),
                wei_amount: 234567891234567891,
            },
            BlockchainTransaction {
                block_number: 3456789012,
                from: Wallet::new("0xCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"),
                wei_amount: 345678912345678912,
            },
        ];

        subject.more_money_received(payments);

        TestLogHandler::new().exists_log_containing(&format!(
            "ERROR: ReceivableDaoReal: Payment reception failed, rolling back: \
            RusqliteError(\"Updating balance for receivable of -123456789123456789 Wei to 0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa with error 'no such table: receivable'\")\n\
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

        subject.more_money_receivable(&wallet1, 1234).unwrap();
        subject.more_money_receivable(&wallet2, 2345).unwrap();

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
    fn delinquency_high_detection_goes_along_a_proper_line() {
        let payment_thresholds = PaymentThresholds {
            maturity_threshold_sec: 333,
            payment_grace_period_sec: 444,
            permanent_debt_allowed_gwei: 1456,
            debt_threshold_gwei: 9876,
            threshold_interval_sec: 1111111,
            unban_below_gwei: 0,
        };
        let now = to_time_t(SystemTime::now());
        let higher_corner_timestamp = (now
            - ThresholdUtils::convert(
                payment_thresholds.maturity_threshold_sec
                    + payment_thresholds.payment_grace_period_sec,
            )) as u64;
        let middle_point_timestamp = (now
            - ThresholdUtils::convert(
                payment_thresholds.maturity_threshold_sec
                    + payment_thresholds.payment_grace_period_sec
                    + payment_thresholds.threshold_interval_sec / 2,
            )) as u64;
        let lower_corner_timestamp = (now
            - ThresholdUtils::convert(
                payment_thresholds.maturity_threshold_sec
                    + payment_thresholds.payment_grace_period_sec
                    + payment_thresholds.threshold_interval_sec,
            )) as u64;
        let tested_fn = |payment_thresholds: &PaymentThresholds, time| {
            ReceivableDaoReal::delinquency_curve_height_detection(
                payment_thresholds,
                now,
                time as i64,
            )
        };

        assert_on_sloped_segment_of_payment_thresholds_and_its_proper_alignment(
            tested_fn,
            payment_thresholds,
            higher_corner_timestamp,
            middle_point_timestamp,
            lower_corner_timestamp,
        )
    }

    #[test]
    fn despite_not_much_realistic_timestamp_gap_smaller_than_grace_period_can_never_blow_up() {
        let payment_thresholds = PaymentThresholds {
            maturity_threshold_sec: 25,
            payment_grace_period_sec: 50,
            permanent_debt_allowed_gwei: 100,
            debt_threshold_gwei: 200,
            threshold_interval_sec: 100,
            unban_below_gwei: 0,
        };
        let now = to_time_t(SystemTime::now());
        let timestamp = now - 11;

        let result = ReceivableDaoReal::delinquency_curve_height_detection(
            &payment_thresholds,
            now,
            timestamp,
        );

        assert_eq!(
            result,
            payment_thresholds.debt_threshold_gwei as i128 * GWEI_TO_WEI
        )
    }

    #[test]
    fn mine_curve_heights_on_temp_table_for_potential_new_delinquencies() {
        let payment_thresholds = PaymentThresholds {
            maturity_threshold_sec: 25,
            payment_grace_period_sec: 50,
            permanent_debt_allowed_gwei: 100,
            debt_threshold_gwei: 200,
            threshold_interval_sec: 100,
            unban_below_gwei: 0,
        };
        let home_dir = ensure_node_home_directory_exists(
            "accountant",
            "mine_curve_heights_on_temp_table_for_potential_new_delinquencies",
        );
        let conn = DbInitializerReal::default()
            .initialize(&home_dir, true, MigratorConfig::test_default())
            .unwrap();
        let wallet_banned = make_wallet("wallet_banned");
        let wallet_1 = make_wallet("wallet_1");
        let wallet_2 = make_wallet("wallet_2");
        let unbanned_account_1_timestamp = from_time_t(to_time_t(SystemTime::now()) - 1000);
        let unbanned_account_2_timestamp = SystemTime::now();
        let banned_account = ReceivableAccount {
            wallet: wallet_banned,
            balance: 80057,
            last_received_timestamp: from_time_t(16_554_000_000),
        };
        let unbanned_account_1 = ReceivableAccount {
            wallet: wallet_1.clone(),
            balance: 8500,
            last_received_timestamp: unbanned_account_1_timestamp,
        };
        let unbanned_account_2 = ReceivableAccount {
            wallet: wallet_2.clone(),
            balance: 30,
            last_received_timestamp: unbanned_account_2_timestamp,
        };
        add_receivable_account(&conn, &banned_account);
        add_banned_account(&conn, &banned_account);
        add_receivable_account(&conn, &unbanned_account_1);
        add_receivable_account(&conn, &unbanned_account_2);
        let subject = ReceivableDaoReal::new(conn);

        subject.mine_metadata_of_yet_unbanned(&payment_thresholds, SystemTime::now());

        let now = now_time_t();
        let captured = capture_rows(subject.conn.as_ref(), "delinquency_metadata");
        let expected_point_height_for_unbanned_1 =
            ReceivableDaoReal::delinquency_curve_height_detection(
                &payment_thresholds,
                now,
                to_time_t(unbanned_account_1_timestamp),
            );
        let expected_point_height_for_unbanned_2 =
            ReceivableDaoReal::delinquency_curve_height_detection(
                &payment_thresholds,
                now,
                to_time_t(unbanned_account_2_timestamp),
            );
        assert_eq!(
            captured,
            vec![
                (wallet_1.to_string(), expected_point_height_for_unbanned_1),
                (wallet_2.to_string(), expected_point_height_for_unbanned_2)
            ]
        );
    }

    fn capture_rows(conn: &dyn ConnectionWrapper, table: &str) -> Vec<(String, i128)> {
        let mut stm = conn.prepare(&format!("select * from {}", table)).unwrap();

        stm.query_map([], |row| {
            let wallet: String = row.get(0).unwrap();
            let curve_value: i128 = row.get(1).unwrap();
            Ok((wallet, curve_value))
        })
        .unwrap()
        .flat_map(|val| val)
        .collect::<Vec<(String, i128)>>()
    }

    #[test]
    fn new_delinquencies_unit_slope() {
        fn wei_conversion(gwei: u64) -> i128 {
            i128::try_from(gwei).unwrap() * GWEI_TO_WEI
        }
        let pcs = PaymentThresholds {
            maturity_threshold_sec: 25,
            payment_grace_period_sec: 50,
            permanent_debt_allowed_gwei: 100,
            debt_threshold_gwei: 200,
            threshold_interval_sec: 100,
            unban_below_gwei: 0,
        };
        let now = now_time_t();
        let mut not_delinquent_inside_grace_period = make_receivable_account(1234, false);
        not_delinquent_inside_grace_period.balance = wei_conversion(pcs.debt_threshold_gwei + 1);
        not_delinquent_inside_grace_period.last_received_timestamp =
            from_time_t(pcs.sugg_and_grace(now) + 2);
        let mut not_delinquent_after_grace_below_slope = make_receivable_account(2345, false);
        not_delinquent_after_grace_below_slope.balance =
            wei_conversion(pcs.debt_threshold_gwei - 2);
        not_delinquent_after_grace_below_slope.last_received_timestamp =
            from_time_t(pcs.sugg_and_grace(now) - 1);
        let mut delinquent_above_slope_after_grace = make_receivable_account(3456, true);
        delinquent_above_slope_after_grace.balance = wei_conversion(pcs.debt_threshold_gwei - 1);
        delinquent_above_slope_after_grace.last_received_timestamp =
            from_time_t(pcs.sugg_and_grace(now) - 2);
        let mut not_delinquent_below_slope_before_stop = make_receivable_account(4567, false);
        not_delinquent_below_slope_before_stop.balance =
            wei_conversion(pcs.permanent_debt_allowed_gwei + 1);
        not_delinquent_below_slope_before_stop.last_received_timestamp =
            from_time_t(pcs.sugg_thru_decreasing(now) + 2);
        let mut delinquent_above_slope_before_stop = make_receivable_account(5678, true);
        delinquent_above_slope_before_stop.balance =
            wei_conversion(pcs.permanent_debt_allowed_gwei + 2);
        delinquent_above_slope_before_stop.last_received_timestamp =
            from_time_t(pcs.sugg_thru_decreasing(now) + 1);
        let mut not_delinquent_above_slope_after_stop = make_receivable_account(6789, false);
        not_delinquent_above_slope_after_stop.balance =
            wei_conversion(pcs.permanent_debt_allowed_gwei - 1);
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
            unban_below_gwei: 0,
        };
        let now = now_time_t();
        let mut not_delinquent = make_receivable_account(1234, false);
        not_delinquent.balance = 105 * GWEI_TO_WEI;
        not_delinquent.last_received_timestamp = from_time_t(pcs.sugg_and_grace(now) - 25);
        let mut delinquent = make_receivable_account(2345, true);
        delinquent.balance = 105 * GWEI_TO_WEI;
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
            unban_below_gwei: 0,
        };
        let now = now_time_t();
        let mut not_delinquent = make_receivable_account(1234, false);
        not_delinquent.balance = 600 * GWEI_TO_WEI;
        not_delinquent.last_received_timestamp = from_time_t(pcs.sugg_and_grace(now) - 25);
        let mut delinquent = make_receivable_account(2345, true);
        delinquent.balance = 600 * GWEI_TO_WEI;
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
            unban_below_gwei: 0,
        };
        let now = now_time_t();
        let mut existing_delinquency = make_receivable_account(1234, true);
        existing_delinquency.balance = 250 * GWEI_TO_WEI;
        existing_delinquency.last_received_timestamp = from_time_t(pcs.sugg_and_grace(now) - 1);
        let mut new_delinquency = make_receivable_account(2345, true);
        new_delinquency.balance = 250 * GWEI_TO_WEI;
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
    fn metadata_gets_gone_after_the_procedure_of_new_delinquencies() {
        let pcs = PaymentThresholds {
            maturity_threshold_sec: 25,
            payment_grace_period_sec: 50,
            permanent_debt_allowed_gwei: 100,
            debt_threshold_gwei: 200,
            threshold_interval_sec: 100,
            unban_below_gwei: 0,
        };
        let now = now_time_t();
        let home_dir = ensure_node_home_directory_exists(
            "receivable_dao",
            "metadata_gets_gone_after_the_procedure_of_new_delinquencies",
        );
        let db_initializer = DbInitializerReal::default();
        let conn = db_initializer
            .initialize(&home_dir, true, MigratorConfig::test_default())
            .unwrap();
        add_receivable_account(&conn, &make_receivable_account(1234, true));
        add_receivable_account(&conn, &make_receivable_account(5678, true));
        add_receivable_account(&conn, &make_receivable_account(9012, true));
        let subject = ReceivableDaoReal::new(conn);

        let result = subject.new_delinquencies(from_time_t(now), &pcs);

        assert!(!result.is_empty());
        let mut stm = subject
            .conn
            .prepare("select * from delinquency_metadata")
            .unwrap();
        let error = stm.query_row([], |_row| Ok(())).unwrap_err();
        assert_eq!(error, Error::QueryReturnedNoRows)
    }

    #[test]
    fn temporary_metadata_table_gets_gone_after_disconnection<'a: 'b, 'b>() {
        let payment_thresholds = PaymentThresholds {
            maturity_threshold_sec: 25,
            payment_grace_period_sec: 50,
            permanent_debt_allowed_gwei: 100,
            debt_threshold_gwei: 200,
            threshold_interval_sec: 100,
            unban_below_gwei: 0,
        };
        let now = now_time_t();
        let home_dir = ensure_node_home_directory_exists(
            "receivable_dao",
            "temporary_metadata_table_gets_gone_after_disconnection",
        );
        let db_initializer = DbInitializerReal::default();
        let conn = db_initializer
            .initialize(&home_dir, true, MigratorConfig::test_default())
            .unwrap();
        add_receivable_account(&conn, &make_receivable_account(1234, true));
        add_receivable_account(&conn, &make_receivable_account(5678, true));
        let subject = ReceivableDaoReal::new(conn);
        let _ = subject.new_delinquencies(from_time_t(now), &payment_thresholds);
        let assertion_sql = "select * from delinquency_metadata";
        subject.conn.prepare(assertion_sql).unwrap();

        drop(subject);

        let new_connection = db_initializer
            .initialize(&home_dir, false, MigratorConfig::test_default())
            .unwrap();
        let error = new_connection.prepare(assertion_sql).unwrap_err();
        match error {
            Error::SqliteFailure(_, Some(msg)) => {
                assert_eq!(msg, "no such table: delinquency_metadata".to_string())
            }
            x => panic!("we expected 'no such table error' but received: {}", x),
        }
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
        paid_delinquent.balance = 50_000_000_000;
        let mut unpaid_delinquent = make_receivable_account(2345, true);
        unpaid_delinquent.balance = 50_000_000_001;
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
            unban_below_gwei: 50,
        };
        let mut newly_non_delinquent = make_receivable_account(1234, false);
        newly_non_delinquent.balance = 25_000_000_000;
        let mut old_non_delinquent = make_receivable_account(2345, false);
        old_non_delinquent.balance = 25_000_000_000;

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
        todo!("decide how to see to the top records query")
        // let home_dir = ensure_node_home_directory_exists("receivable_dao", "top_records_and_total");
        // let conn = DbInitializerReal::default()
        //     .initialize(&home_dir, true, MigratorConfig::test_default())
        //     .unwrap();
        // let insert = |wallet: &str, balance: i64, timestamp: i64| {
        //     let params: &[&dyn ToSql] = &[&wallet, &balance, &timestamp];
        //     conn
        //         .prepare("insert into receivable (wallet_address, balance, last_received_timestamp) values (?, ?, ?)")
        //         .unwrap()
        //         .execute(params)
        //         .unwrap();
        // };
        // let timestamp1 = dao_utils::now_time_t() - 80_000;
        // let timestamp2 = dao_utils::now_time_t() - 86_401;
        // let timestamp3 = dao_utils::now_time_t() - 86_000;
        // let timestamp4 = dao_utils::now_time_t() - 86_001;
        // insert(
        //     "0x1111111111111111111111111111111111111111",
        //     999_999_999, // below minimum amount - reject
        //     timestamp1,  // below maximum age
        // );
        // insert(
        //     "0x2222222222222222222222222222222222222222",
        //     1_000_000_000, // minimum amount
        //     timestamp2,    // above maximum age - reject
        // );
        // insert(
        //     "0x3333333333333333333333333333333333333333",
        //     1_000_000_000, // minimum amount
        //     timestamp3,    // below maximum age
        // );
        // insert(
        //     "0x4444444444444444444444444444444444444444",
        //     1_000_000_001, // above minimum amount
        //     timestamp4,    // below maximum age
        // );
        // let subject = ReceivableDaoReal::new(conn);
        //
        // let top_records = subject.top_records(1_000_000_000, 86400);
        // let total = subject.total();
        //
        // assert_eq!(
        //     top_records,
        //     vec![
        //         ReceivableAccount {
        //             wallet: Wallet::new("0x4444444444444444444444444444444444444444"),
        //             balance: 1_000_000_001,
        //             last_received_timestamp: dao_utils::from_time_t(timestamp4),
        //         },
        //         ReceivableAccount {
        //             wallet: Wallet::new("0x3333333333333333333333333333333333333333"),
        //             balance: 1_000_000_000,
        //             last_received_timestamp: dao_utils::from_time_t(timestamp3),
        //         },
        //     ]
        // );
        // assert_eq!(total, 4_000_000_000)
    }

    #[test]
    fn total_works() {
        let home_dir = ensure_node_home_directory_exists("receivable_dao", "total_works");
        let conn = DbInitializerReal::default()
            .initialize(&home_dir, true, MigratorConfig::test_default())
            .unwrap();
        let insert = |wallet: &str, balance: i128, timestamp: i64| {
            let params: &[&dyn ToSql] = &[&wallet, &balance, &timestamp];
            conn
                .prepare("insert into receivable (wallet_address, balance, last_received_timestamp) values (?, ?, ?)")
                .unwrap()
                .execute(params)
                .unwrap();
        };
        let timestamp = dao_utils::now_time_t();
        insert(
            "0x1111111111111111111111111111111111111111",
            999_999_800,
            timestamp - 1000,
        );
        insert(
            "0x2222222222222222222222222222222222222222",
            1_000_000_070,
            timestamp - 3333,
        );
        insert(
            "0x3333333333333333333333333333333333333333",
            1_000_000_130,
            timestamp - 4567,
        );
        let subject = ReceivableDaoReal::new(conn);

        let total = subject.total();

        assert_eq!(total, 3_000_000_000)
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

    #[test]
    fn upsert_in_more_money_receivable_params_assertion() {
        let insert_or_update_params_arc = Arc::new(Mutex::new(vec![]));
        let wallet = make_wallet("xyz123");
        let amount = 100;
        let insert_update_core = InsertUpdateCoreMock::default()
            .upsert_params(&insert_or_update_params_arc)
            .upsert_results(Err(InsertUpdateError("SomethingWrong".to_string())));
        let conn = ConnectionWrapperMock::new();
        let conn_id_stamp = conn.set_arbitrary_id_stamp();
        let mut subject = ReceivableDaoReal::new(Box::new(conn));
        subject.insert_update_core = Box::new(insert_update_core);

        let result = subject.more_money_receivable(&wallet, amount);

        assert_eq!(
            result,
            Err(ReceivableDaoError::RusqliteError(
                "SomethingWrong".to_string()
            ))
        );
        let mut insert_or_update_params = insert_or_update_params_arc.lock().unwrap();
        let (captured_conn_id_stamp, update_sql, insert_sql, table, sql_param_names) =
            insert_or_update_params.remove(0);
        assert_eq!(captured_conn_id_stamp, conn_id_stamp);
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
    fn update_in_try_multi_insert_payment_returns_early_error_with_params_assertion() {
        let home = ensure_node_home_directory_exists(
            "receivable_dao",
            "update_in_try_multi_insert_payment_returns_early_error_with_params_assertion",
        );
        let conn = DbInitializerReal::default()
            .initialize(&home, true, MigratorConfig::test_default())
            .unwrap();
        let insert_or_update_params_arc = Arc::new(Mutex::new(vec![]));
        let insert_update_core = InsertUpdateCoreMock::default()
            .update_params(&insert_or_update_params_arc)
            .update_result(Err(InsertUpdateError("SomethingWrong".to_string())));
        let mut subject = ReceivableDaoReal::new(conn);
        let payments = vec![
            BlockchainTransaction {
                block_number: 42u64,
                from: make_wallet("some_address"),
                wei_amount: 18446744073709551615,
            },
            BlockchainTransaction {
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
        let (captured_conn_id_stamp_opt, select_sql, update_sql, table, sql_param_names) =
            insert_or_update_params.pop().unwrap();
        assert_eq!(captured_conn_id_stamp_opt, None); //implication: operation over sqlite transaction
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
                (":balance", &(-18446744073709551615_i128).to_string()),
            ])
        );
        assert_eq!(insert_or_update_params.pop(), None)
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
