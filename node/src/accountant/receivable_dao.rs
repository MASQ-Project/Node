// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
use crate::accountant::big_int_db_processor::WeiChange::{Addition, Subtraction};
use crate::accountant::big_int_db_processor::{
    collect_and_sum_i128_values_from_table, BigIntDbProcessor, BigIntDivider, BigIntSqlConfig,
    SQLParamsBuilder, TableNameDAO,
};
use crate::accountant::dao_utils;
use crate::accountant::dao_utils::{
    to_time_t, AssemblerFeeder, CustomQuery, DaoFactoryReal, RangeStmConfig, TopStmConfig,
    VigilantFlatten,
};
use crate::accountant::receivable_dao::ReceivableDaoError::RusqliteError;
use crate::accountant::{checked_conversion, ThresholdUtils};
use crate::blockchain::blockchain_interface::BlockchainTransaction;
use crate::database::connection_wrapper::ConnectionWrapper;
use crate::database::db_initializer::{connection_or_panic, DbInitializerReal};
use crate::db_config::persistent_configuration::PersistentConfigError;
use crate::sub_lib::accountant::{PaymentThresholds, WEIS_OF_GWEI};
use crate::sub_lib::wallet::Wallet;
use indoc::indoc;
use itertools::Either;
use itertools::Either::Left;
use masq_lib::logger::Logger;
use masq_lib::utils::{plus, ExpectValue};
use rusqlite::OptionalExtension;
use rusqlite::Row;
use rusqlite::{named_params, Error};
#[cfg(test)]
use std::any::Any;
use std::time::SystemTime;

#[derive(Debug, PartialEq, Eq)]
pub enum ReceivableDaoError {
    SignConversion(SignConversionError<u128>),
    ConfigurationError(String),
    RusqliteError(String),
}

#[derive(Debug, PartialEq, Eq)]
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceivableAccount {
    pub wallet: Wallet,
    pub balance_wei: i128,
    pub last_received_timestamp: SystemTime,
}

pub trait ReceivableDao: Send {
    fn more_money_receivable(
        &self,
        now: SystemTime,
        wallet: &Wallet,
        amount: u128,
    ) -> Result<(), ReceivableDaoError>;

    fn more_money_received(&mut self, now: SystemTime, transactions: Vec<BlockchainTransaction>);

    fn new_delinquencies(
        &self,
        now: SystemTime,
        payment_thresholds: &PaymentThresholds,
    ) -> Vec<ReceivableAccount>;

    fn paid_delinquencies(&self, payment_thresholds: &PaymentThresholds) -> Vec<ReceivableAccount>;

    fn custom_query(&self, custom_query: CustomQuery<i64>) -> Option<Vec<ReceivableAccount>>;

    fn total(&self) -> i128;

    //test only intended method but because of share with multi-node tests conditional compilation is disallowed
    fn account_status(&self, wallet: &Wallet) -> Option<ReceivableAccount>;

    as_any_dcl!();
}

pub trait ReceivableDaoFactory {
    fn make(&self) -> Box<dyn ReceivableDao>;
}

impl ReceivableDaoFactory for DaoFactoryReal {
    fn make(&self) -> Box<dyn ReceivableDao> {
        let init_config = self
            .init_config
            .take()
            .expectv("init config")
            .add_special_conn_setup(
                BigIntDivider::register_big_int_deconstruction_for_sqlite_connection,
            );
        Box::new(ReceivableDaoReal::new(connection_or_panic(
            &DbInitializerReal::default(),
            self.data_directory.as_path(),
            self.create_if_necessary,
            init_config,
        )))
    }
}

#[derive(Debug)]
pub struct ReceivableDaoReal {
    conn: Box<dyn ConnectionWrapper>,
    big_int_db_processor: BigIntDbProcessor<Self>,
    logger: Logger,
}

impl ReceivableDao for ReceivableDaoReal {
    fn more_money_receivable(
        &self,
        timestamp: SystemTime,
        wallet: &Wallet,
        amount: u128,
    ) -> Result<(), ReceivableDaoError> {
        Ok(self.big_int_db_processor.execute(Left(self.conn.as_ref()), BigIntSqlConfig::new(
               "insert into receivable (wallet_address, balance_high_b, balance_low_b, last_received_timestamp) values (:wallet, :balance_high_b, :balance_low_b, :last_received) on conflict (wallet_address) do \
               update set balance_high_b = balance_high_b + :balance_high_b, balance_low_b = balance_low_b + :balance_low_b",
            "update receivable set balance_high_b = :balance_high_b, balance_low_b = :balance_low_b",
            SQLParamsBuilder::default()
                        .key(  "wallet_address",":wallet",wallet)
                        .wei_change(Addition("balance",amount))
                        .other(vec![(":last_received",&to_time_t(timestamp))])
                        .build()
        ))?)
    }

    fn more_money_received(&mut self, timestamp: SystemTime, payments: Vec<BlockchainTransaction>) {
        self.try_multi_insert_payment(timestamp, &payments)
            .unwrap_or_else(|e| self.more_money_received_pretty_error_log(&payments, e))
    }

    fn new_delinquencies(
        &self,
        system_now: SystemTime,
        payment_thresholds: &PaymentThresholds,
    ) -> Vec<ReceivableAccount> {
        let slope = ThresholdUtils::slope(payment_thresholds, true);
        let (permanent_debt_allowed_high_b, permanent_debt_allowed_low_b) =
            BigIntDivider::deconstruct(
                checked_conversion::<u64, i128>(payment_thresholds.permanent_debt_allowed_gwei)
                    * WEIS_OF_GWEI,
            );
        let sql = indoc!(
            r"
                select r.wallet_address, r.balance_high_b, r.balance_low_b, r.last_received_timestamp
                from receivable r
                left outer join banned b on r.wallet_address = b.wallet_address
                where
                    r.last_received_timestamp < :sugg_and_grace
                    and ((r.balance_high_b > biginthigh(:debt_threshold, :slope * (:sugg_and_grace - r.last_received_timestamp)))
                        or ((r.balance_high_b = biginthigh(:debt_threshold, :slope * (:sugg_and_grace - r.last_received_timestamp)))
                        and (r.balance_low_b > bigintlow(:debt_threshold, :slope * (:sugg_and_grace - r.last_received_timestamp)))))
                    and ((r.balance_high_b > :permanent_debt_allowed_high_b) or ((r.balance_high_b = 0) and (r.balance_low_b > :permanent_debt_allowed_low_b)))
                    and b.wallet_address is null
            "
        );
        self.conn
            .prepare(sql)
            .expect("Couldn't prepare statement")
            .query_map(
                named_params! {
                    ":debt_threshold": checked_conversion::<u64,i64>(payment_thresholds.debt_threshold_gwei),
                    ":slope": slope,
                    ":sugg_and_grace": payment_thresholds.sugg_and_grace(to_time_t(system_now)),
                    ":permanent_debt_allowed_high_b": permanent_debt_allowed_high_b,
                    ":permanent_debt_allowed_low_b": permanent_debt_allowed_low_b
                },
                Self::form_receivable_account,
            )
            .expect("Couldn't retrieve new delinquencies: database corruption")
            .vigilant_flatten()
            .collect()
    }

    fn paid_delinquencies(&self, payment_thresholds: &PaymentThresholds) -> Vec<ReceivableAccount> {
        let sql = indoc!(
            r"
            select r.wallet_address, r.balance_high_b, r.balance_low_b, r.last_received_timestamp
            from receivable r inner join banned b on r.wallet_address = b.wallet_address
            where
                (r.balance_high_b < :unban_balance_high_b) or ((balance_high_b = :unban_balance_high_b) and (balance_low_b <= :unban_balance_low_b))
        "
        );
        let mut stmt = self.conn.prepare(sql).expect("Couldn't prepare statement");
        let (unban_balance_high_b, unban_balance_low_b) = BigIntDivider::deconstruct(
            (payment_thresholds.unban_below_gwei as i128) * WEIS_OF_GWEI,
        );
        stmt.query_map(
            named_params! {
                ":unban_balance_high_b": unban_balance_high_b,
                ":unban_balance_low_b": unban_balance_low_b
            },
            Self::form_receivable_account,
        )
        .expect("Couldn't retrieve new delinquencies: database corruption")
        .vigilant_flatten()
        .collect()
    }

    fn custom_query(&self, custom_query: CustomQuery<i64>) -> Option<Vec<ReceivableAccount>> {
        let variant_top = TopStmConfig{
            limit_clause: "limit :limit_count",
            gwei_min_resolution_clause: "where (balance_high_b > 0) or ((balance_high_b = 0) and (balance_low_b >= 1000000000))",
            age_param_name: "last_received_timestamp asc",
        };
        let variant_range = RangeStmConfig {
            where_clause: "where ((last_received_timestamp <= :max_timestamp) and (last_received_timestamp >= :min_timestamp)) \
            and ((balance_high_b > :min_balance_high_b) or ((balance_high_b = :min_balance_high_b) and (balance_low_b >= :min_balance_low_b))) \
            and ((balance_high_b < :max_balance_high_b) or ((balance_high_b = :max_balance_high_b) and (balance_low_b <= :max_balance_low_b)))",
            gwei_min_resolution_clause: "and (((balance_high_b > 0) or ((balance_high_b = 0) and (balance_low_b >= 1000000000))) \
            or ((balance_high_b < -1) or ((balance_high_b = -1) and (balance_low_b <= 9223372035854775807))))", //i64::MAX - 1*10^9
            secondary_order_param: "last_received_timestamp asc"
        };

        custom_query.query::<_, i64, _, _>(
            self.conn.as_ref(),
            Self::stm_assembler_of_receivable_cq,
            variant_top,
            variant_range,
            Self::form_receivable_account,
        )
    }

    fn total(&self) -> i128 {
        collect_and_sum_i128_values_from_table(self.conn.as_ref(), &Self::table_name(), "balance")
    }

    fn account_status(&self, wallet: &Wallet) -> Option<ReceivableAccount> {
        let mut stmt = self
            .conn
            .prepare(
                "select wallet_address, balance_high_b, balance_low_b, last_received_timestamp from receivable where wallet_address = ?",
            )
            .expect("Internal error");
        match stmt
            .query_row(&[&wallet], Self::form_receivable_account)
            .optional()
        {
            Ok(value) => value,
            Err(e) => panic!("Database is corrupt: {:?}", e),
        }
    }

    as_any_impl!();
}

impl ReceivableDaoReal {
    pub fn new(conn: Box<dyn ConnectionWrapper>) -> ReceivableDaoReal {
        ReceivableDaoReal {
            conn,
            big_int_db_processor: BigIntDbProcessor::default(),
            logger: Logger::new("ReceivableDaoReal"),
        }
    }

    fn try_multi_insert_payment(
        &mut self,
        timestamp: SystemTime,
        payments: &[BlockchainTransaction],
    ) -> Result<(), ReceivableDaoError> {
        let xactn = self.conn.transaction()?;
        {
            for transaction in payments {
                self.big_int_db_processor.execute(Either::Right(&xactn), BigIntSqlConfig::new(
                    "update receivable set balance_high_b = balance_high_b + :balance_high_b, balance_low_b = balance_low_b + :balance_low_b, last_received_timestamp = :last_received where wallet_address = :wallet",
                    "update receivable set balance_high_b = :balance_high_b, balance_low_b = :balance_low_b, last_received_timestamp = :last_received where wallet_address = :wallet",
                    SQLParamsBuilder::default()
                                .key( "wallet_address", ":wallet",&transaction.from)
                                .wei_change(Subtraction("balance",transaction.wei_amount))
                                .other(vec![(":last_received", &to_time_t(timestamp))])
                                .build()
                    ))?
            }
        }
        match xactn.commit() {
            // Error response is untested here, because without a mockable Transaction, it's untestable.
            Err(e) => Err(ReceivableDaoError::RusqliteError(format!("{:?}", e))),
            Ok(_) => Ok(()),
        }
    }

    fn form_receivable_account(row: &Row) -> rusqlite::Result<ReceivableAccount> {
        let wallet: Result<Wallet, Error> = row.get(0);
        let balance_high_b_result = row.get(1);
        let balance_low_b_result = row.get(2);
        let last_received_timestamp_result = row.get(3);
        match (
            wallet,
            balance_high_b_result,
            balance_low_b_result,
            last_received_timestamp_result,
        ) {
            (Ok(wallet), Ok(high_bytes), Ok(low_bytes), Ok(last_received_timestamp)) => {
                Ok(ReceivableAccount {
                    wallet,
                    balance_wei: BigIntDivider::reconstitute(high_bytes, low_bytes),
                    last_received_timestamp: dao_utils::from_time_t(last_received_timestamp),
                })
            }
            e => panic!(
                "Database is corrupt: RECEIVABLE table columns and/or types: {:?}",
                e
            ),
        }
    }

    fn stm_assembler_of_receivable_cq(feeder: AssemblerFeeder) -> String {
        format!(
            "select
                 wallet_address,
                 balance_high_b,
                 balance_low_b,
                 last_received_timestamp
             from
                 receivable
             {} {}
             order by
                 {},
                 {}
             {}",
            feeder.main_where_clause,
            feeder.where_clause_extension,
            feeder.order_by_first_param,
            feeder.order_by_second_param,
            feeder.limit_clause
        )
    }

    fn more_money_received_pretty_error_log(
        &self,
        payments: &[BlockchainTransaction],
        error: ReceivableDaoError,
    ) {
        fn finalize_report(data: (Vec<String>, u128)) -> String {
            let (report_lines, sum) = data;
            plus(report_lines, format!("{:10} {:42} {:18}", "TOTAL", "", sum)).join("\n")
        }
        fn record_one_more_transaction(
            acc: (Vec<String>, u128),
            bc_tx: &BlockchainTransaction,
        ) -> (Vec<String>, u128) {
            let lines_adjusted = plus(
                acc.0,
                format!(
                    "{:10} {:42} {:18}",
                    bc_tx.block_number, bc_tx.from, bc_tx.wei_amount
                ),
            );
            let sum_so_far = acc.1 + bc_tx.wei_amount;
            (lines_adjusted, sum_so_far)
        }
        let init = (
            vec![format!("{:10} {:42} {:18}", "Block #", "Wallet", "Amount")],
            0_u128,
        );
        let aggregated = payments.iter().fold(init, record_one_more_transaction);
        error!(
            self.logger,
            "Payment reception failed, rolling back: {:?}\n{}",
            error,
            finalize_report(aggregated)
        );
    }
}

impl TableNameDAO for ReceivableDaoReal {
    fn table_name() -> String {
        String::from("receivable")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accountant::dao_utils::{from_time_t, now_time_t, to_time_t};
    use crate::accountant::test_utils::{
        assert_database_blows_up_on_an_unexpected_error, make_receivable_account,
    };
    use crate::database::db_initializer::DbInitializerReal;
    use crate::database::db_initializer::{DbInitializationConfig, DbInitializer};
    use crate::database::db_migrations::ExternalData;
    use crate::db_config::persistent_configuration::PersistentConfigError;
    use crate::test_utils::assert_contains;
    use crate::test_utils::make_wallet;
    use masq_lib::messages::TopRecordsOrdering::{Age, Balance};
    use masq_lib::test_utils::logging::{init_test_logging, TestLogHandler};
    use masq_lib::test_utils::utils::ensure_node_home_directory_exists;
    use masq_lib::utils::NeighborhoodModeLight;
    use rusqlite::ToSql;
    use std::path::Path;

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
    fn factory_produces_connection_that_is_familiar_with_our_defined_sqlite_functions() {
        let home_dir = ensure_node_home_directory_exists(
            "receivable_dao",
            "factory_produces_connection_that_is_familiar_with_our_defined_sqlite_functions",
        );
        DbInitializerReal::default()
            .initialize(
                &home_dir,
                true,
                DbInitializationConfig::create_or_migrate(ExternalData {
                    chain: Default::default(),
                    neighborhood_mode: NeighborhoodModeLight::Standard,
                    db_password_opt: None,
                }),
            )
            .unwrap();
        let subject = DaoFactoryReal::new(
            &home_dir,
            false,
            DbInitializationConfig::panic_on_migration(),
        );

        let receivable_dao = subject.make();

        let definite_dao = receivable_dao
            .as_any()
            .downcast_ref::<ReceivableDaoReal>()
            .unwrap();
        definite_dao
            .conn
            .prepare("select biginthigh(4578745,89.7888)")
            .unwrap();
        definite_dao
            .conn
            .prepare("select bigintlow(787845,7878.0056)")
            .unwrap();
        //we didn't blow up, all is good
    }

    #[test]
    #[should_panic(
        expected = "Overflow detected with 340282366920938463463374607431768211455: cannot be converted from u128 to i128"
    )]
    fn try_multi_insert_payment_handles_error_of_number_sign_check() {
        let home_dir = ensure_node_home_directory_exists(
            "receivable_dao",
            "try_multi_insert_payment_handles_error_of_number_sign_check",
        );
        let mut subject = ReceivableDaoReal::new(
            DbInitializerReal::default()
                .initialize(&home_dir, true, DbInitializationConfig::test_default())
                .unwrap(),
        );
        let payments = vec![BlockchainTransaction {
            block_number: 42u64,
            from: make_wallet("some_address"),
            wei_amount: u128::MAX,
        }];

        let _ = subject.try_multi_insert_payment(SystemTime::now(), &payments.as_slice());
    }

    #[test]
    #[should_panic(expected = "no such table: receivable")]
    fn try_multi_insert_payment_handles_error_adding_receivables() {
        let home_dir = ensure_node_home_directory_exists(
            "receivable_dao",
            "try_multi_insert_payment_handles_error_adding_receivables",
        );
        let conn = DbInitializerReal::default()
            .initialize(&home_dir, true, DbInitializationConfig::test_default())
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

        let _ = subject.try_multi_insert_payment(SystemTime::now(), payments.as_slice());
    }

    #[test]
    fn more_money_receivable_works_for_new_address() {
        let home_dir = ensure_node_home_directory_exists(
            "receivable_dao",
            "more_money_receivable_works_for_new_address",
        );
        let now = SystemTime::now();
        let wallet = make_wallet("booga");
        let subject = ReceivableDaoReal::new(
            DbInitializerReal::default()
                .initialize(&home_dir, true, DbInitializationConfig::test_default())
                .unwrap(),
        );

        subject.more_money_receivable(now, &wallet, 1234).unwrap();

        let status = subject.account_status(&wallet).unwrap();
        assert_eq!(status.wallet, wallet);
        assert_eq!(status.balance_wei, 1234);
        assert_eq!(to_time_t(status.last_received_timestamp), to_time_t(now));
    }

    #[test]
    fn more_money_receivable_works_for_existing_address() {
        let home_dir = ensure_node_home_directory_exists(
            "receivable_dao",
            "more_money_receivable_works_for_existing_address",
        );
        let wallet = make_wallet("booga");
        let subject = ReceivableDaoReal::new(
            DbInitializerReal::default()
                .initialize(&home_dir, true, DbInitializationConfig::test_default())
                .unwrap(),
        );
        let now = SystemTime::now();
        subject.more_money_receivable(now, &wallet, 1234).unwrap();

        subject
            .more_money_receivable(SystemTime::UNIX_EPOCH, &wallet, 2345)
            .unwrap();

        let status = subject.account_status(&wallet).unwrap();
        assert_eq!(status.wallet, wallet);
        assert_eq!(status.balance_wei, 3579);
        assert_eq!(to_time_t(status.last_received_timestamp), to_time_t(now));
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
                .initialize(&home_dir, true, DbInitializationConfig::test_default())
                .unwrap(),
        );

        let _ = subject.more_money_receivable(SystemTime::now(), &make_wallet("booga"), u128::MAX);
    }

    #[test]
    fn more_money_received_works_for_existing_addresses() {
        let home_dir = ensure_node_home_directory_exists(
            "receivable_dao",
            "more_money_received_works_for_existing_address",
        );
        let debtor1 = make_wallet("debtor1");
        let debtor2 = make_wallet("debtor2");
        let now = SystemTime::now();
        let mut subject = {
            let subject = ReceivableDaoReal::new(
                DbInitializerReal::default()
                    .initialize(&home_dir, true, DbInitializationConfig::test_default())
                    .unwrap(),
            );
            subject.more_money_receivable(now, &debtor1, 1234).unwrap();
            subject.more_money_receivable(now, &debtor2, 2345).unwrap();
            subject
        };
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

        subject.more_money_received(now, transactions);

        let status1 = subject.account_status(&debtor1).unwrap();
        assert_eq!(status1.wallet, debtor1);
        assert_eq!(status1.balance_wei, 34);
        assert_eq!(to_time_t(status1.last_received_timestamp), to_time_t(now));
        let status2 = subject.account_status(&debtor2).unwrap();
        assert_eq!(status2.wallet, debtor2);
        assert_eq!(status2.balance_wei, 45);
        assert_eq!(to_time_t(status2.last_received_timestamp), to_time_t(now));
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
                .initialize(&home_dir, true, DbInitializationConfig::test_default())
                .unwrap(),
        );
        let transactions = vec![BlockchainTransaction {
            from: debtor.clone(),
            wei_amount: 2300_u128,
            block_number: 33_u64,
        }];

        subject.more_money_received(SystemTime::now(), transactions);

        let status = subject.account_status(&debtor);
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
                .initialize(&home_dir, true, DbInitializationConfig::test_default())
                .unwrap(),
        );
        // Sabotage the database so there'll be an error
        {
            let mut conn = DbInitializerReal::default()
                .initialize(&home_dir, false, DbInitializationConfig::test_default())
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

        subject.more_money_received(SystemTime::now(), payments);

        TestLogHandler::new().exists_log_containing(&format!(
            "ERROR: ReceivableDaoReal: Payment reception failed, rolling back: \
            RusqliteError(\"Wei change: error after invalid update command for receivable of -123456789123456789 Wei to 0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa with error 'no such table: receivable'\")\n\
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
                .initialize(&home_dir, true, DbInitializationConfig::test_default())
                .unwrap(),
        );

        let result = subject.account_status(&wallet);

        assert_eq!(result, None);
    }

    fn make_connection_with_our_defined_sqlite_functions(
        home_dir: &Path,
    ) -> Box<dyn ConnectionWrapper> {
        let init_config = DbInitializationConfig::test_default().add_special_conn_setup(
            BigIntDivider::register_big_int_deconstruction_for_sqlite_connection,
        );
        DbInitializerReal::default()
            .initialize(home_dir, true, init_config)
            .unwrap()
    }

    #[test]
    fn new_delinquencies_unit_slope() {
        fn wei_conversion(gwei: u64) -> i128 {
            i128::try_from(gwei).unwrap() * WEIS_OF_GWEI
        }
        let payment_thresholds = PaymentThresholds {
            maturity_threshold_sec: 25,
            payment_grace_period_sec: 50,
            permanent_debt_allowed_gwei: 100,
            debt_threshold_gwei: 200,
            threshold_interval_sec: 100,
            unban_below_gwei: 0,
        };
        let now = now_time_t();
        let mut not_delinquent_inside_grace_period = make_receivable_account(1234, false);
        not_delinquent_inside_grace_period.balance_wei =
            wei_conversion(payment_thresholds.debt_threshold_gwei + 1);
        not_delinquent_inside_grace_period.last_received_timestamp =
            from_time_t(payment_thresholds.sugg_and_grace(now) + 2);
        let mut not_delinquent_after_grace_below_slope = make_receivable_account(2345, false);
        not_delinquent_after_grace_below_slope.balance_wei =
            wei_conversion(payment_thresholds.debt_threshold_gwei - 2);
        not_delinquent_after_grace_below_slope.last_received_timestamp =
            from_time_t(payment_thresholds.sugg_and_grace(now) - 1);
        let mut delinquent_above_slope_after_grace = make_receivable_account(3456, true);
        delinquent_above_slope_after_grace.balance_wei =
            wei_conversion(payment_thresholds.debt_threshold_gwei - 1);
        delinquent_above_slope_after_grace.last_received_timestamp =
            from_time_t(payment_thresholds.sugg_and_grace(now) - 2);
        let mut not_delinquent_below_slope_before_stop = make_receivable_account(4567, false);
        not_delinquent_below_slope_before_stop.balance_wei =
            wei_conversion(payment_thresholds.permanent_debt_allowed_gwei + 1);
        not_delinquent_below_slope_before_stop.last_received_timestamp =
            from_time_t(payment_thresholds.sugg_thru_decreasing(now) + 2);
        let mut delinquent_above_slope_before_stop = make_receivable_account(5678, true);
        delinquent_above_slope_before_stop.balance_wei =
            wei_conversion(payment_thresholds.permanent_debt_allowed_gwei + 2);
        delinquent_above_slope_before_stop.last_received_timestamp =
            from_time_t(payment_thresholds.sugg_thru_decreasing(now) + 1);
        let mut not_delinquent_above_slope_after_stop = make_receivable_account(6789, false);
        not_delinquent_above_slope_after_stop.balance_wei =
            wei_conversion(payment_thresholds.permanent_debt_allowed_gwei - 1);
        not_delinquent_above_slope_after_stop.last_received_timestamp =
            from_time_t(payment_thresholds.sugg_thru_decreasing(now) - 2);
        let home_dir = ensure_node_home_directory_exists("accountant", "new_delinquencies");
        let conn = make_connection_with_our_defined_sqlite_functions(&home_dir);
        add_receivable_account(&conn, &not_delinquent_inside_grace_period);
        add_receivable_account(&conn, &not_delinquent_after_grace_below_slope);
        add_receivable_account(&conn, &delinquent_above_slope_after_grace);
        add_receivable_account(&conn, &not_delinquent_below_slope_before_stop);
        add_receivable_account(&conn, &delinquent_above_slope_before_stop);
        add_receivable_account(&conn, &not_delinquent_above_slope_after_stop);
        let subject = ReceivableDaoReal::new(conn);

        let result = subject.new_delinquencies(from_time_t(now), &payment_thresholds);

        assert_contains(&result, &delinquent_above_slope_after_grace);
        assert_contains(&result, &delinquent_above_slope_before_stop);
        assert_eq!(2, result.len());
    }

    #[test]
    fn new_delinquencies_shallow_slope() {
        let payment_thresholds = PaymentThresholds {
            maturity_threshold_sec: 100,
            payment_grace_period_sec: 100,
            permanent_debt_allowed_gwei: 100,
            debt_threshold_gwei: 110,
            threshold_interval_sec: 100,
            unban_below_gwei: 0,
        };
        let now = now_time_t();
        let mut not_delinquent = make_receivable_account(1234, false);
        not_delinquent.balance_wei = 105 * WEIS_OF_GWEI;
        not_delinquent.last_received_timestamp =
            from_time_t(payment_thresholds.sugg_and_grace(now) - 25);
        let mut delinquent = make_receivable_account(2345, true);
        delinquent.balance_wei = 105 * WEIS_OF_GWEI;
        delinquent.last_received_timestamp =
            from_time_t(payment_thresholds.sugg_and_grace(now) - 75);
        let home_dir =
            ensure_node_home_directory_exists("accountant", "new_delinquencies_shallow_slope");
        let conn = make_connection_with_our_defined_sqlite_functions(&home_dir);
        add_receivable_account(&conn, &not_delinquent);
        add_receivable_account(&conn, &delinquent);
        let subject = ReceivableDaoReal::new(conn);

        let result = subject.new_delinquencies(from_time_t(now), &payment_thresholds);

        assert_contains(&result, &delinquent);
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn new_delinquencies_steep_slope() {
        let payment_thresholds = PaymentThresholds {
            maturity_threshold_sec: 100,
            payment_grace_period_sec: 100,
            permanent_debt_allowed_gwei: 100,
            debt_threshold_gwei: 1100,
            threshold_interval_sec: 100,
            unban_below_gwei: 0,
        };
        let now = now_time_t();
        let mut not_delinquent = make_receivable_account(1234, false);
        not_delinquent.balance_wei = 600 * WEIS_OF_GWEI;
        not_delinquent.last_received_timestamp =
            from_time_t(payment_thresholds.sugg_and_grace(now) - 25);
        let mut delinquent = make_receivable_account(2345, true);
        delinquent.balance_wei = 600 * WEIS_OF_GWEI;
        delinquent.last_received_timestamp =
            from_time_t(payment_thresholds.sugg_and_grace(now) - 75);
        let home_dir =
            ensure_node_home_directory_exists("accountant", "new_delinquencies_steep_slope");
        let conn = make_connection_with_our_defined_sqlite_functions(&home_dir);
        add_receivable_account(&conn, &not_delinquent);
        add_receivable_account(&conn, &delinquent);
        let subject = ReceivableDaoReal::new(conn);

        let result = subject.new_delinquencies(from_time_t(now), &payment_thresholds);

        assert_contains(&result, &delinquent);
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn new_delinquencies_does_not_find_existing_delinquencies() {
        let payment_thresholds = PaymentThresholds {
            maturity_threshold_sec: 25,
            payment_grace_period_sec: 50,
            permanent_debt_allowed_gwei: 100,
            debt_threshold_gwei: 200,
            threshold_interval_sec: 100,
            unban_below_gwei: 0,
        };
        let now = now_time_t();
        let mut existing_delinquency = make_receivable_account(1234, true);
        existing_delinquency.balance_wei = 250 * WEIS_OF_GWEI;
        existing_delinquency.last_received_timestamp =
            from_time_t(payment_thresholds.sugg_and_grace(now) - 1);
        let mut new_delinquency = make_receivable_account(2345, true);
        new_delinquency.balance_wei = 250 * WEIS_OF_GWEI;
        new_delinquency.last_received_timestamp =
            from_time_t(payment_thresholds.sugg_and_grace(now) - 1);
        let home_dir = ensure_node_home_directory_exists(
            "receivable_dao",
            "new_delinquencies_does_not_find_existing_delinquencies",
        );
        let conn = make_connection_with_our_defined_sqlite_functions(&home_dir);
        add_receivable_account(&conn, &existing_delinquency);
        add_receivable_account(&conn, &new_delinquency);
        add_banned_account(&conn, &existing_delinquency);
        let subject = ReceivableDaoReal::new(conn);

        let result = subject.new_delinquencies(from_time_t(now), &payment_thresholds);

        assert_contains(&result, &new_delinquency);
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn new_delinquencies_works_for_still_empty_tables() {
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
            "new_delinquencies_work_for_still_empty_tables",
        );
        let conn = make_connection_with_our_defined_sqlite_functions(&home_dir);
        let subject = ReceivableDaoReal::new(conn);

        let result = subject.new_delinquencies(from_time_t(now), &payment_thresholds);

        assert!(result.is_empty())
    }

    #[test]
    fn new_delinquencies_handles_too_young_debts_causing_slope_parameter_to_be_negative() {
        //would happen if sugg_and_grace involve more time than the age of the debt
        let home_dir = ensure_node_home_directory_exists(
            "receivable_dao",
            "new_delinquencies_handles_too_young_debts_causing_slope_parameter_to_be_negative",
        );
        let payment_thresholds = PaymentThresholds {
            maturity_threshold_sec: 25,
            payment_grace_period_sec: 50,
            permanent_debt_allowed_gwei: 100,
            debt_threshold_gwei: 200,
            threshold_interval_sec: 100,
            unban_below_gwei: 0,
        };
        let now = to_time_t(SystemTime::now());
        let sugg_and_grace = payment_thresholds.sugg_and_grace(now);
        let too_young_new_delinquency = ReceivableAccount {
            wallet: make_wallet("abc123"),
            balance_wei: 123_456_789_101_112,
            last_received_timestamp: from_time_t(sugg_and_grace + 1),
        };
        let ok_new_delinquency = ReceivableAccount {
            wallet: make_wallet("aaa999"),
            balance_wei: 123_456_789_101_112,
            last_received_timestamp: from_time_t(sugg_and_grace - 1),
        };
        let conn = make_connection_with_our_defined_sqlite_functions(&home_dir);
        add_receivable_account(&conn, &too_young_new_delinquency);
        add_receivable_account(&conn, &ok_new_delinquency.clone());
        let subject = ReceivableDaoReal::new(conn);

        let result = subject.new_delinquencies(from_time_t(now), &payment_thresholds);

        assert_eq!(result, vec![ok_new_delinquency])
    }

    #[test]
    fn paid_delinquencies() {
        let payment_thresholds = PaymentThresholds {
            maturity_threshold_sec: 0,
            payment_grace_period_sec: 0,
            permanent_debt_allowed_gwei: 0,
            debt_threshold_gwei: 0,
            threshold_interval_sec: 0,
            unban_below_gwei: 50,
        };
        let mut paid_delinquent = make_receivable_account(1234, true);
        paid_delinquent.balance_wei = 50_000_000_000;
        let mut unpaid_delinquent = make_receivable_account(2345, true);
        unpaid_delinquent.balance_wei = 50_000_000_001;
        let home_dir = ensure_node_home_directory_exists("accountant", "paid_delinquencies");
        let db_initializer = DbInitializerReal::default();
        let conn = db_initializer
            .initialize(&home_dir, true, DbInitializationConfig::test_default())
            .unwrap();
        add_receivable_account(&conn, &paid_delinquent);
        add_receivable_account(&conn, &unpaid_delinquent);
        add_banned_account(&conn, &paid_delinquent);
        add_banned_account(&conn, &unpaid_delinquent);
        let subject = ReceivableDaoReal::new(conn);

        let result = subject.paid_delinquencies(&payment_thresholds);

        assert_contains(&result, &paid_delinquent);
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn paid_delinquencies_does_not_find_existing_nondelinquencies() {
        let payment_thresholds = PaymentThresholds {
            maturity_threshold_sec: 0,
            payment_grace_period_sec: 0,
            permanent_debt_allowed_gwei: 0,
            debt_threshold_gwei: 0,
            threshold_interval_sec: 0,
            unban_below_gwei: 50,
        };
        let mut newly_non_delinquent = make_receivable_account(1234, false);
        newly_non_delinquent.balance_wei = 25_000_000_000;
        let mut old_non_delinquent = make_receivable_account(2345, false);
        old_non_delinquent.balance_wei = 25_000_000_000;

        let home_dir = ensure_node_home_directory_exists(
            "receivable_dao",
            "paid_delinquencies_does_not_find_existing_nondelinquencies",
        );
        let db_initializer = DbInitializerReal::default();
        let conn = db_initializer
            .initialize(&home_dir, true, DbInitializationConfig::test_default())
            .unwrap();
        add_receivable_account(&conn, &newly_non_delinquent);
        add_receivable_account(&conn, &old_non_delinquent);
        add_banned_account(&conn, &newly_non_delinquent);
        let subject = ReceivableDaoReal::new(conn);

        let result = subject.paid_delinquencies(&payment_thresholds);

        assert_contains(&result, &newly_non_delinquent);
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn custom_query_handles_empty_table_in_top_records_mode() {
        let main_test_setup = |_insert: &dyn Fn(&str, i128, i64)| {};
        let subject = custom_query_test_body_for_receivable(
            "custom_query_handles_empty_table_in_top_records_mode",
            main_test_setup,
        );

        let result = subject.custom_query(CustomQuery::TopRecords {
            count: 6,
            ordered_by: Balance,
        });

        assert_eq!(result, None)
    }

    fn common_setup_of_accounts_for_tests_of_top_records(
        now: i64,
    ) -> Box<dyn Fn(&dyn Fn(&str, i128, i64))> {
        let timestamp1 = now - 86_480;
        let timestamp2 = now - 222_000;
        let timestamp3 = now - 100_000;
        let timestamp4 = now - 86_000;
        let timestamp5 = now - 86_111;
        let timestamp6 = timestamp1;
        Box::new(move |insert: &dyn Fn(&str, i128, i64)| {
            insert(
                "0x1111111111111111111111111111111111111111",
                1_000_000_001,
                timestamp1,
            );
            insert(
                "0x2222222222222222222222222222222222222222",
                1_000_000_001,
                timestamp2,
            );
            insert(
                "0x3333333333333333333333333333333333333333",
                920_655_455,
                timestamp3,
            );
            insert(
                "0x4444444444444444444444444444444444444444",
                990_000_000, //below 1 Gwei
                timestamp4,
            );
            insert(
                "0x5555555555555555555555555555555555555555",
                1_000_000_000,
                timestamp5,
            );
            insert(
                "0x6666666666666666666666666666666666666666",
                32_000_000_200,
                timestamp6,
            )
        })
    }

    #[test]
    fn custom_query_in_top_records_mode_default_ordering() {
        //Accounts of balances smaller than one gwei don't qualify.
        //Two accounts differ only in debt's age but not balance which allows to check doubled ordering,
        //here by balance and then by age.
        let now = now_time_t();
        let main_test_setup = common_setup_of_accounts_for_tests_of_top_records(now);
        let subject = custom_query_test_body_for_receivable(
            "custom_query_in_top_records_mode_default_ordering",
            main_test_setup,
        );

        let result = subject
            .custom_query(CustomQuery::TopRecords {
                count: 3,
                ordered_by: Balance,
            })
            .unwrap();

        assert_eq!(
            result,
            vec![
                ReceivableAccount {
                    wallet: Wallet::new("0x6666666666666666666666666666666666666666"),
                    balance_wei: 32_000_000_200,
                    last_received_timestamp: from_time_t(now - 86_480),
                },
                ReceivableAccount {
                    wallet: Wallet::new("0x2222222222222222222222222222222222222222"),
                    balance_wei: 1_000_000_001,
                    last_received_timestamp: from_time_t(now - 222_000),
                },
                ReceivableAccount {
                    wallet: Wallet::new("0x1111111111111111111111111111111111111111"),
                    balance_wei: 1_000_000_001,
                    last_received_timestamp: from_time_t(now - 86_480),
                },
            ]
        );
    }

    #[test]
    fn custom_query_in_top_records_mode_ordered_by_age() {
        //Accounts of balances smaller than one gwei don't qualify.
        //Two accounts differ only in balance but not the debt's age which allows to check doubled ordering,
        //here by age and then by balance.
        let now = now_time_t();
        let main_test_setup = common_setup_of_accounts_for_tests_of_top_records(now);
        let subject = custom_query_test_body_for_receivable(
            "custom_query_in_top_records_mode_ordered_by_age",
            main_test_setup,
        );

        let result = subject
            .custom_query(CustomQuery::TopRecords {
                count: 3,
                ordered_by: Age,
            })
            .unwrap();

        assert_eq!(
            result,
            vec![
                ReceivableAccount {
                    wallet: Wallet::new("0x2222222222222222222222222222222222222222"),
                    balance_wei: 1_000_000_001,
                    last_received_timestamp: from_time_t(now - 222_000),
                },
                ReceivableAccount {
                    wallet: Wallet::new("0x6666666666666666666666666666666666666666"),
                    balance_wei: 32_000_000_200,
                    last_received_timestamp: from_time_t(now - 86_480),
                },
                ReceivableAccount {
                    wallet: Wallet::new("0x1111111111111111111111111111111111111111"),
                    balance_wei: 1_000_000_001,
                    last_received_timestamp: from_time_t(now - 86_480),
                },
            ]
        );
    }

    #[test]
    fn custom_query_handles_empty_table_in_range_mode() {
        let main_test_setup = |_insert: &dyn Fn(&str, i128, i64)| {};
        let subject = custom_query_test_body_for_receivable(
            "custom_query_handles_empty_table_in_range_mode",
            main_test_setup,
        );

        let result = subject.custom_query(CustomQuery::RangeQuery {
            min_age_s: 20000,
            max_age_s: 200000,
            min_amount_gwei: 500000000,
            max_amount_gwei: 3500000000,
            timestamp: SystemTime::now(),
        });

        assert_eq!(result, None)
    }

    #[test]
    fn custom_query_in_range_mode() {
        //Two accounts differ only in debt's age but not balance which allows to check doubled ordering,
        //by balance and then by age.
        let now = now_time_t();
        let timestamp1 = now - 99_001;
        let timestamp2 = now - 86_401;
        let timestamp3 = now - 70_000;
        let timestamp4 = now - 69_000;
        let timestamp5 = now - 86_000;
        let timestamp6 = now - 66_244;
        let timestamp7 = now - 59_999;
        let main_test_setup = |insert: &dyn Fn(&str, i128, i64)| {
            insert(
                "0x1111111111111111111111111111111111111111",
                999_454_656 * WEIS_OF_GWEI,
                timestamp1, //too old
            );
            insert(
                "0x2222222222222222222222222222222222222222",
                -560_001 * WEIS_OF_GWEI, //too small
                timestamp2,
            );
            insert(
                "0x3333333333333333333333333333333333333333",
                1_000_000_230 * WEIS_OF_GWEI,
                timestamp3,
            );
            insert(
                "0x4444444444444444444444444444444444444444",
                1_100_000_001 * WEIS_OF_GWEI, //too big
                timestamp4,
            );
            insert(
                "0x5555555555555555555555555555555555555555",
                1_000_000_230 * WEIS_OF_GWEI,
                timestamp5,
            );
            insert(
                "0x6666666666666666666666666666666666666666",
                1_050_444_230 * WEIS_OF_GWEI,
                timestamp6,
            );
            insert(
                "0x7777777777777777777777777777777777777777",
                900_000_000 * WEIS_OF_GWEI,
                timestamp7, //too young
            );
        };
        let subject =
            custom_query_test_body_for_receivable("custom_query_in_range_mode", main_test_setup);

        let result = subject
            .custom_query(CustomQuery::RangeQuery {
                min_age_s: 60000,
                max_age_s: 99000,
                min_amount_gwei: -560000,
                max_amount_gwei: 1_100_000_000,
                timestamp: from_time_t(now),
            })
            .unwrap();

        assert_eq!(
            result,
            vec![
                ReceivableAccount {
                    wallet: Wallet::new("0x6666666666666666666666666666666666666666"),
                    balance_wei: 1_050_444_230_000_000_000,
                    last_received_timestamp: from_time_t(timestamp6),
                },
                ReceivableAccount {
                    wallet: Wallet::new("0x5555555555555555555555555555555555555555"),
                    balance_wei: 1_000_000_230_000_000_000,
                    last_received_timestamp: from_time_t(timestamp5),
                },
                ReceivableAccount {
                    wallet: Wallet::new("0x3333333333333333333333333333333333333333"),
                    balance_wei: 1_000_000_230_000_000_000,
                    last_received_timestamp: from_time_t(timestamp3),
                }
            ]
        );
    }

    #[test]
    fn range_query_does_not_display_values_from_below_1_gwei() {
        let timestamp1 = now_time_t() - 5000;
        let timestamp2 = now_time_t() - 3232;
        let main_setup = |insert: &dyn Fn(&str, i128, i64)| {
            insert(
                "0x1111111111111111111111111111111111111111",
                999_999_999, //smaller than 1 Gwei
                now_time_t() - 11_001,
            );
            insert(
                "0x2222222222222222222222222222222222222222",
                -999_999_999, //smaller than -1 Gwei
                now_time_t() - 5_606,
            );
            insert(
                "0x3333333333333333333333333333333333333333",
                30_000_300_000,
                timestamp1,
            );
            insert(
                "0x4444444444444444444444444444444444444444",
                -2_000_300_000,
                timestamp2,
            );
        };
        let subject = custom_query_test_body_for_receivable(
            "range_query_does_not_display_values_from_below_1_gwei",
            main_setup,
        );

        let result = subject
            .custom_query(CustomQuery::RangeQuery {
                min_age_s: 0,
                max_age_s: 200000,
                min_amount_gwei: i64::MIN,
                max_amount_gwei: 35_000_000_000,
                timestamp: SystemTime::now(),
            })
            .unwrap();

        assert_eq!(
            result,
            vec![
                ReceivableAccount {
                    wallet: Wallet::new("0x3333333333333333333333333333333333333333"),
                    balance_wei: 30_000_300_000,
                    last_received_timestamp: from_time_t(timestamp1),
                },
                ReceivableAccount {
                    wallet: Wallet::new("0x4444444444444444444444444444444444444444"),
                    balance_wei: -2_000_300_000,
                    last_received_timestamp: from_time_t(timestamp2),
                }
            ]
        )
    }

    #[test]
    fn total_works() {
        let home_dir = ensure_node_home_directory_exists("receivable_dao", "total_works");
        let conn = DbInitializerReal::default()
            .initialize(&home_dir, true, DbInitializationConfig::test_default())
            .unwrap();

        let insert = |wallet: &str, balance: i128, timestamp: i64| {
            let (high_bytes, low_bytes) = BigIntDivider::deconstruct(balance);
            let params: &[&dyn ToSql] = &[&wallet, &high_bytes, &low_bytes, &timestamp];
            conn
                .prepare("insert into receivable (wallet_address, balance_high_b, balance_low_b, last_received_timestamp) values (?, ?, ?, ?)")
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
            .initialize(&home_dir, true, DbInitializationConfig::test_default())
            .unwrap();
        let subject = ReceivableDaoReal::new(conn);

        let result = subject.total();

        assert_eq!(result, 0)
    }

    #[test]
    #[should_panic(
        expected = "Database is corrupt: RECEIVABLE table columns and/or types: (Err(FromSqlConversionFailure(0, Text, InvalidAddress)), Err(InvalidColumnIndex(1))"
    )]
    fn form_receivable_account_panics_on_database_error() {
        assert_database_blows_up_on_an_unexpected_error(ReceivableDaoReal::form_receivable_account);
    }

    #[test]
    fn receivable_dao_implements_dao_table_identifier() {
        assert_eq!(ReceivableDaoReal::table_name(), "receivable")
    }

    fn add_receivable_account(conn: &Box<dyn ConnectionWrapper>, account: &ReceivableAccount) {
        let mut stmt = conn.prepare ("insert into receivable (wallet_address, balance_high_b, balance_low_b, last_received_timestamp) values (?, ?, ?, ?)").unwrap();
        let (high_bytes, low_bytes) = BigIntDivider::deconstruct(account.balance_wei);
        let params: &[&dyn ToSql] = &[
            &account.wallet,
            &high_bytes,
            &low_bytes,
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

    fn custom_query_test_body_for_receivable<F>(
        test_name: &str,
        main_test_setup: F,
    ) -> ReceivableDaoReal
    where
        F: Fn(&dyn Fn(&str, i128, i64)),
    {
        let conn = DbInitializerReal::default()
            .initialize(
                &ensure_node_home_directory_exists("receivable_dao", test_name),
                true,
                DbInitializationConfig::test_default(),
            )
            .unwrap();
        let insert = |wallet: &str, balance: i128, timestamp: i64| {
            let (high_bytes, low_bytes) = BigIntDivider::deconstruct(balance);
            let params: &[&dyn ToSql] = &[&wallet, &high_bytes, &low_bytes, &timestamp];
            conn
                .prepare("insert into receivable (wallet_address, balance_high_b, balance_low_b, last_received_timestamp) values (?, ?, ?, ?)")
                .unwrap()
                .execute(params)
                .unwrap();
        };
        main_test_setup(&insert);
        ReceivableDaoReal::new(conn)
    }
}
