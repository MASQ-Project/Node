// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::{unsigned_to_signed, PendingPayableId};
use crate::blockchain::blockchain_bridge::PendingPayableFingerprint;
use crate::database::connection_wrapper::ConnectionWrapper;
use crate::database::dao_utils;
use crate::database::dao_utils::{multi_row_update_rows_changed, to_time_t, DaoFactoryReal};
use crate::sub_lib::wallet::Wallet;
use itertools::Itertools;
use masq_lib::utils::ExpectValue;
use rusqlite::types::{ToSql, Type};
use rusqlite::{Error, Row};
use std::fmt::Debug;
use std::str::FromStr;
use std::time::SystemTime;
use web3::types::H256;

#[derive(Debug, PartialEq, Eq)]
pub enum PayableDaoError {
    SignConversion(u64),
    RusqliteError(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PayableAccount {
    pub wallet: Wallet,
    pub balance: i64,
    pub last_paid_timestamp: SystemTime,
    pub pending_payable_opt: Option<PendingPayableId>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingPayable {
    pub recipient_wallet: Wallet,
    pub hash: H256,
}

impl PendingPayable {
    pub fn new(to: Wallet, txn: H256) -> Self {
        Self {
            recipient_wallet: to,
            hash: txn,
        }
    }
}

pub trait PayableDao: Debug + Send {
    fn more_money_payable(
        &self,
        now: SystemTime,
        wallet: &Wallet,
        amount: u64,
    ) -> Result<(), PayableDaoError>;

    fn mark_pending_payables_rowids(
        &self,
        wallets_and_rowids: &[(&Wallet, u64)],
    ) -> Result<(), PayableDaoError>;

    fn transactions_confirmed(
        &self,
        actual_payments: &[PendingPayableFingerprint],
    ) -> Result<(), PayableDaoError>;

    fn non_pending_payables(&self) -> Vec<PayableAccount>;

    fn top_records(&self, minimum_amount: u64, maximum_age: u64) -> Vec<PayableAccount>;

    fn total(&self) -> u64;
}

pub trait PayableDaoFactory {
    fn make(&self) -> Box<dyn PayableDao>;
}

impl PayableDaoFactory for DaoFactoryReal {
    fn make(&self) -> Box<dyn PayableDao> {
        Box::new(PayableDaoReal::new(self.make_connection()))
    }
}

#[derive(Debug)]
pub struct PayableDaoReal {
    conn: Box<dyn ConnectionWrapper>,
}

impl PayableDao for PayableDaoReal {
    fn more_money_payable(
        &self,
        timestamp: SystemTime,
        wallet: &Wallet,
        amount: u64,
    ) -> Result<(), PayableDaoError> {
        let signed_amount = unsigned_to_signed(amount).map_err(PayableDaoError::SignConversion)?;
        match self.try_increase_balance(timestamp, wallet, signed_amount) {
            Ok(_) => Ok(()),
            Err(e) => panic!(
                "Database is corrupt: {}; processing payable for {}",
                e, wallet
            ),
        }
    }

    fn mark_pending_payables_rowids(
        &self,
        wallets_and_rowids: &[(&Wallet, u64)],
    ) -> Result<(), PayableDaoError> {
        const COMMA_SEPARATOR: &str = ", ";
        fn collect_feedback(row: &Row) -> Result<Option<()>, rusqlite::Error> {
            row.get::<usize, Option<u64>>(0)
                .map(|id_opt| id_opt.map(|_| ()))
        }
        fn error_extension_about_not_null_ids(
            conn: &dyn ConnectionWrapper,
            wallets_and_rowids: &[(&Wallet, u64)],
        ) -> String {
            let sql = format!(
                "select wallet_address from payable where pending_payable_rowid not in ({}) and wallet_address in ({})",
                wallets_and_rowids.iter().map(|(_, rowid)|rowid.to_string()).join(COMMA_SEPARATOR),
                 comma_separated_wallets(wallets_and_rowids,"'")
            );
            let failing_wallets = conn
                .prepare(&sql)
                .expect("select failed")
                .query_map([], |row| row.get::<usize, String>(0))
                .expect("no args but yet binding failed")
                .flatten() //TODO use vigilant flatten
                .join(COMMA_SEPARATOR);
            if failing_wallets.is_empty() {
                failing_wallets
            } else {
                format!(" Accounts for wallets ({}) had contained rowids when we tried to update them with new ones. \
                 All such columns should be emptied beforehand at the confirmation of the earlier transactions. \
                 A malformed, repeated payment is suspected", failing_wallets)
            }
        }
        fn comma_separated_wallets(
            wallets_and_rowids: &[(&Wallet, u64)],
            quoting_mark: &str,
        ) -> String {
            wallets_and_rowids
                .iter()
                .map(|(wallet, _)| format!("{quoting_mark}{wallet}{quoting_mark}"))
                .join(COMMA_SEPARATOR)
        }
        fn resolve_success_or_failure(
            conn: &dyn ConnectionWrapper,
            wallets_and_rowids: &[(&Wallet, u64)],
            returning_clause_feedback: Result<
                impl Iterator<Item = Result<Option<()>, rusqlite::Error>>,
                rusqlite::Error,
            >,
        ) -> Result<(), PayableDaoError> {
            fn rows_changed_counter(takes: Vec<Option<()>>) -> usize {
                takes.iter().flatten().count()
            }
            match multi_row_update_rows_changed(returning_clause_feedback, rows_changed_counter) {
                Ok(rows_affected) => match rows_affected {
                    num if num == wallets_and_rowids.len() => Ok(()),
                    num => panic!(
                        "Marking pending payable rowid for wallets {} affected {} rows but expected {}.{}",
                        comma_separated_wallets(wallets_and_rowids,""),
                        num,
                        wallets_and_rowids.len(),
                        error_extension_about_not_null_ids(conn, wallets_and_rowids)
                    ),
                },
                Err(e) => Err(PayableDaoError::RusqliteError(e.to_string())),
            }
        }

        let sql = {
            let when_clauses_for_case_stm = wallets_and_rowids
                .iter()
                .map(|(wallet, rowid)| format!("when wallet_address = '{}' then {}", wallet, rowid))
                .join("\n");
            format!(
                "update payable set pending_payable_rowid = case {} end \
             where pending_payable_rowid is null
             returning pending_payable_rowid",
                when_clauses_for_case_stm
            )
        };
        let mut stm = self.conn.prepare(&sql).expect("Internal Error");
        let returning_clause_feedback = stm.query_map([], collect_feedback);
        resolve_success_or_failure(&*self.conn, wallets_and_rowids, returning_clause_feedback)
    }

    fn transactions_confirmed(
        &self,
        fingerprints: &[PendingPayableFingerprint],
    ) -> Result<(), PayableDaoError> {
        fingerprints.iter().try_for_each(|fgp| {
            let amount = unsigned_to_signed(fgp.amount).map_err(PayableDaoError::SignConversion)?;

            self.try_decrease_balance(fgp.rowid, amount, fgp.timestamp)
                .map_err(PayableDaoError::RusqliteError)
        })
    }

    fn non_pending_payables(&self) -> Vec<PayableAccount> {
        let mut stmt = self.conn
            .prepare("select wallet_address, balance, last_paid_timestamp from payable where pending_payable_rowid is null")
            .expect("Internal error");

        stmt.query_map([], |row| {
            let wallet_result: Result<Wallet, Error> = row.get(0);
            let balance_result = row.get(1);
            let last_paid_timestamp_result = row.get(2);
            match (wallet_result, balance_result, last_paid_timestamp_result) {
                (Ok(wallet), Ok(balance), Ok(last_paid_timestamp)) => Ok(PayableAccount {
                    wallet,
                    balance,
                    last_paid_timestamp: dao_utils::from_time_t(last_paid_timestamp),
                    pending_payable_opt: None,
                }),
                _ => panic!("Database is corrupt: PAYABLE table columns and/or types"),
            }
        })
        .expect("Database is corrupt")
        .flatten()
        .collect()
    }

    fn top_records(&self, minimum_amount: u64, maximum_age: u64) -> Vec<PayableAccount> {
        let min_amt = unsigned_to_signed(minimum_amount).unwrap_or(0x7FFF_FFFF_FFFF_FFFF);
        let max_age = unsigned_to_signed(maximum_age).unwrap_or(0x7FFF_FFFF_FFFF_FFFF);
        let min_timestamp = dao_utils::now_time_t() - max_age;
        let mut stmt = self
            .conn
            .prepare(
                r#"
                select
                    balance,
                    last_paid_timestamp,
                    wallet_address,
                    pending_payable_rowid,
                    pending_payable.transaction_hash
                from
                    payable
                left join pending_payable on
                    pending_payable.rowid = payable.pending_payable_rowid
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
            let wallet_result: Result<Wallet, Error> = row.get(2);
            let pending_payable_rowid_result_opt: Result<Option<u64>, Error> = row.get(3);
            let pending_payable_hash_result_opt: Result<Option<String>, Error> = row.get(4);
            match (
                wallet_result,
                balance_result,
                last_paid_timestamp_result,
                pending_payable_rowid_result_opt,
                pending_payable_hash_result_opt,
            ) {
                (
                    Ok(wallet),
                    Ok(balance),
                    Ok(last_paid_timestamp),
                    Ok(pending_payable_rowid_opt),
                    Ok(pending_payable_hash_opt),
                ) => Ok(PayableAccount {
                    wallet,
                    balance,
                    last_paid_timestamp: dao_utils::from_time_t(last_paid_timestamp),
                    pending_payable_opt: pending_payable_rowid_opt.map(|rowid| PendingPayableId {
                        rowid,
                        hash: pending_payable_hash_opt
                            .map(|s| H256::from_str(&s[2..]).expectv("string tx hash"))
                            .expectv("tx hash"),
                    }),
                }),
                x => panic!(
                    "Database is corrupt: PAYABLE table columns and/or types {:?}",
                    x
                ),
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
        match stmt.query_row([], |row| {
            let total_balance_result: Result<u64, Error> = row.get(0);
            match total_balance_result {
                Ok(total_balance) => Ok(total_balance),
                Err(e)
                    if e == Error::InvalidColumnType(0, "sum(balance)".to_string(), Type::Null) =>
                {
                    Ok(0)
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

    fn try_increase_balance(
        &self,
        timestamp: SystemTime,
        wallet: &Wallet,
        amount: i64,
    ) -> Result<bool, String> {
        let mut stmt = self
            .conn
            .prepare("insert into payable (wallet_address, balance, last_paid_timestamp, pending_payable_rowid) values (:address, :balance, :timestamp, null) on conflict (wallet_address) do update set balance = balance + :balance where wallet_address = :address")
            .expect("Internal error");
        let params: &[(&str, &dyn ToSql)] = &[
            (":address", &wallet),
            (":balance", &amount),
            (":timestamp", &to_time_t(timestamp)),
        ];
        match stmt.execute(params) {
            Ok(0) => Ok(false),
            Ok(_) => Ok(true),
            Err(e) => Err(format!("{}", e)),
        }
    }

    fn try_decrease_balance(
        &self,
        rowid: u64,
        amount: i64,
        last_paid_timestamp: SystemTime,
    ) -> Result<(), String> {
        let mut stmt = self
            .conn
            .prepare("update payable set balance = balance - :balance, last_paid_timestamp = :last_paid, pending_payable_rowid = null where pending_payable_rowid = :referential_rowid")
            .expect("Internal error");
        let params: &[(&str, &dyn ToSql)] = &[
            (":balance", &amount),
            (":last_paid", &dao_utils::to_time_t(last_paid_timestamp)),
            (
                ":referential_rowid",
                &i64::try_from(rowid).expect("SQLite was wrong when choosing the rowid"),
            ),
        ];
        match stmt.execute(params) {
            Ok(1) => Ok(()),
            Ok(num) => panic!(
                "Trying to decrease balance for rowid {}: {} rows changed instead of 1",
                rowid, num
            ),
            Err(e) => Err(format!("{}", e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accountant::test_utils::{account_status, make_pending_payable_fingerprint};
    use crate::blockchain::test_utils::make_tx_hash;
    use crate::database::connection_wrapper::ConnectionWrapperReal;
    use crate::database::dao_utils::{from_time_t, to_time_t};
    use crate::database::db_initializer::{DbInitializer, DbInitializerReal, DATABASE_FILE};
    use crate::database::db_migrations::MigratorConfig;
    use crate::test_utils::make_wallet;
    use masq_lib::test_utils::utils::ensure_node_home_directory_exists;
    use rusqlite::Connection as RusqliteConnection;
    use rusqlite::{Connection, OpenFlags};
    use std::ops::RangeInclusive;
    use std::path::Path;
    use std::time::Duration;

    #[test]
    #[should_panic(
        expected = "Trying to decrease balance for rowid 45: 0 rows changed instead of 1"
    )]
    fn try_decrease_balance_changed_no_rows() {
        let home_dir = ensure_node_home_directory_exists(
            "payable_dao",
            "try_decrease_balance_changed_no_rows",
        );
        let wrapped_conn = DbInitializerReal::default()
            .initialize(&home_dir, true, MigratorConfig::test_default())
            .unwrap();
        let subject = PayableDaoReal::new(wrapped_conn);

        let _ = subject.try_decrease_balance(45, 1111, SystemTime::now());
    }

    #[test]
    fn more_money_payable_works_for_new_address() {
        let home_dir = ensure_node_home_directory_exists(
            "payable_dao",
            "more_money_payable_works_for_new_address",
        );
        let now = SystemTime::now();
        let wallet = make_wallet("booga");
        let status = {
            let boxed_conn = DbInitializerReal::default()
                .initialize(&home_dir, true, MigratorConfig::test_default())
                .unwrap();
            let subject = PayableDaoReal::new(boxed_conn);
            let secondary_conn = Connection::open(home_dir.join(DATABASE_FILE)).unwrap();

            subject.more_money_payable(now, &wallet, 1234).unwrap();

            account_status(&secondary_conn, &wallet).unwrap()
        };

        assert_eq!(status.wallet, wallet);
        assert_eq!(status.balance, 1234);
        assert_eq!(to_time_t(status.last_paid_timestamp), to_time_t(now));
    }

    #[test]
    fn more_money_payable_works_for_existing_address() {
        let home_dir = ensure_node_home_directory_exists(
            "payable_dao",
            "more_money_payable_works_for_existing_address",
        );
        let wallet = make_wallet("booga");
        let now = SystemTime::now();
        let boxed_conn = DbInitializerReal::default()
            .initialize(&home_dir, true, MigratorConfig::test_default())
            .unwrap();
        let secondary_conn = Connection::open(home_dir.join(DATABASE_FILE)).unwrap();
        let subject = PayableDaoReal::new(boxed_conn);
        subject.more_money_payable(now, &wallet, 1234).unwrap();

        let status = {
            subject
                .more_money_payable(SystemTime::UNIX_EPOCH, &wallet, 2345)
                .unwrap();

            account_status(&secondary_conn, &wallet).unwrap()
        };

        assert_eq!(status.wallet, wallet);
        assert_eq!(status.balance, 3579);
        assert_eq!(to_time_t(status.last_paid_timestamp), to_time_t(now));
    }

    #[test]
    fn more_money_payable_works_for_overflow() {
        let home_dir = ensure_node_home_directory_exists(
            "payable_dao",
            "more_money_payable_works_for_overflow",
        );
        let wallet = make_wallet("booga");
        let subject = PayableDaoReal::new(
            DbInitializerReal::default()
                .initialize(&home_dir, true, MigratorConfig::test_default())
                .unwrap(),
        );

        let result = subject.more_money_payable(SystemTime::now(), &wallet, u64::MAX);

        assert_eq!(result, Err(PayableDaoError::SignConversion(u64::MAX)));
    }

    #[test]
    fn mark_pending_payables_marks_pending_transactions_for_new_addresses() {
        //the extra unchanged record checks the safety of right count of changed rows;
        //experienced serious troubles in the past
        let home_dir = ensure_node_home_directory_exists(
            "payable_dao",
            "mark_pending_payables_marks_pending_transactions_for_new_addresses",
        );
        let wallet_1 = make_wallet("booga");
        let pending_payable_rowid_1 = 656;
        let wallet_2 = make_wallet("bagaboo");
        let pending_payable_rowid_2 = 657;
        let boxed_conn = DbInitializerReal::default()
            .initialize(&home_dir, true, MigratorConfig::test_default())
            .unwrap();
        let secondary_conn = Connection::open(home_dir.join(DATABASE_FILE)).unwrap();
        {
            let insert = "insert into payable (wallet_address, balance, \
             last_paid_timestamp) values (?, ?, ?), (?, ?, ?), (?, ?, ?)";
            let mut stm = boxed_conn.prepare(insert).unwrap();
            let params: &[&dyn ToSql] = &[
                &make_wallet("wallet"),
                &12345,
                &149_000_000,
                &wallet_1,
                &5000,
                &150_000_000,
                &wallet_2,
                &6789,
                &151_000_000,
            ];
            stm.execute(params).unwrap();
        }
        let subject = PayableDaoReal::new(boxed_conn);

        subject
            .mark_pending_payables_rowids(&[
                (&wallet_1, pending_payable_rowid_1),
                (&wallet_2, pending_payable_rowid_2),
            ])
            .unwrap();

        let account_statuses = [&wallet_1, &wallet_2]
            .iter()
            .map(|wallet| account_status(&secondary_conn, wallet).unwrap())
            .collect::<Vec<PayableAccount>>();
        assert_eq!(
            account_statuses,
            vec![
                PayableAccount {
                    wallet: wallet_1,
                    balance: 5000,
                    last_paid_timestamp: from_time_t(150_000_000),
                    pending_payable_opt: Some(PendingPayableId {
                        rowid: pending_payable_rowid_1,
                        hash: Default::default()
                    }),
                },
                //notice the hashes are garbage, but generated by a test method not knowing doing better
                PayableAccount {
                    wallet: wallet_2,
                    balance: 6789,
                    last_paid_timestamp: from_time_t(151_000_000),
                    pending_payable_opt: Some(PendingPayableId {
                        rowid: pending_payable_rowid_2,
                        hash: Default::default()
                    })
                }
            ]
        )
    }

    fn run_performance_test_for_mark_pending_payable_rowids(
        test_name: &str,
        range_of_attempts: RangeInclusive<usize>,
    ) -> (Duration, Duration) {
        /*
           The case statement used in the multi record SQL forces us into going through all records; it seems like a good idea to test the performance;
           We're going to compare an amount of time needed for updates done via
           a) separate db calls
           b) a single db call using a case statement
        */
        fn make_str_wallet_from_idx(idx: usize) -> String {
            format!("0x{:0>40}", idx)
        }
        fn create_initial_state_records(
            conn: &dyn ConnectionWrapper,
            range_of_attempts: RangeInclusive<usize>,
        ) {
            let set_of_values = range_of_attempts
                .map(|idx| format!("('{}', 1000, 12345, null)", make_str_wallet_from_idx(idx)))
                .join(", ");
            let sql = format!("insert into payable (wallet_address, balance, last_paid_timestamp, pending_payable_rowid) values {}", set_of_values);
            let _ = conn.prepare(&sql).unwrap().execute([]).unwrap();
        }
        fn assert_task_has_been_done_completely(
            conn: &dyn ConnectionWrapper,
            range_of_attempts: RangeInclusive<usize>,
        ) {
            let sql = "select wallet_address, pending_payable_rowid from payable where pending_payable_rowid not null";
            let updated_wallets_and_rowids = conn
                .prepare(sql)
                .unwrap()
                .query_map([], |row| {
                    Ok((
                        row.get::<usize, String>(0).unwrap(),
                        row.get::<usize, Option<i64>>(1).unwrap().unwrap(),
                    ))
                })
                .unwrap()
                .flatten()
                .collect::<Vec<(String, i64)>>();
            let odd_idx_iterator = range_of_attempts.into_iter().step_by(2);
            assert_eq!(
                updated_wallets_and_rowids.len(),
                odd_idx_iterator.clone().count()
            );
            assert!(!updated_wallets_and_rowids.is_empty());
            updated_wallets_and_rowids
                .into_iter()
                .zip(odd_idx_iterator)
                .for_each(|((wallet, rowid), idx)| {
                    assert_eq!(rowid as usize, idx);
                    assert_eq!(wallet, make_str_wallet_from_idx(idx));
                })
        }

        let test_home_folder = ensure_node_home_directory_exists("payable_dao", test_name);
        let db_for_separate_calls = DbInitializerReal::default()
            .initialize(
                test_home_folder.join("separate_calls").as_path(),
                true,
                MigratorConfig::test_default(),
            )
            .unwrap();
        create_initial_state_records(db_for_separate_calls.as_ref(), range_of_attempts.clone());
        let update_call = |idx: usize| {
            let _ = db_for_separate_calls
                .prepare("update payable set pending_payable_rowid = ? where wallet_address = ?")
                .unwrap()
                .execute(&[&idx as &dyn ToSql, &make_str_wallet_from_idx(idx)])
                .unwrap();
        };
        let separate_calls_start = SystemTime::now();

        range_of_attempts.clone().for_each(|attempt| {
            if attempt % 2 != 0 {
                update_call(attempt)
            }
        });

        let separate_calls_end = SystemTime::now();
        assert_task_has_been_done_completely(
            db_for_separate_calls.as_ref(),
            range_of_attempts.clone(),
        );
        let separate_calls_attempt_duration = separate_calls_end
            .duration_since(separate_calls_start)
            .unwrap();
        ////////////////////////////////////////////////////////////////////////////
        let single_call_path = test_home_folder.join("single_call");
        let db_for_single_call = DbInitializerReal::default()
            .initialize(
                single_call_path.as_path(),
                true,
                MigratorConfig::test_default(),
            )
            .unwrap();
        create_initial_state_records(db_for_single_call.as_ref(), range_of_attempts.clone());
        let dao = PayableDaoReal::new(db_for_single_call);
        let generated_owned_args = range_of_attempts
            .clone()
            .flat_map(|idx| {
                if idx % 2 != 0 {
                    Some((
                        Wallet::from_str(&make_str_wallet_from_idx(idx)).unwrap(),
                        idx as u64,
                    ))
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        let args = generated_owned_args
            .iter()
            .map(|(wallet, id)| (wallet, *id))
            .collect::<Vec<(&Wallet, u64)>>();
        let single_call_start = SystemTime::now();

        dao.mark_pending_payables_rowids(&args).unwrap();

        let single_call_end = SystemTime::now();
        let conn = Connection::open(single_call_path.join(DATABASE_FILE)).unwrap();
        let wrapped_conn = ConnectionWrapperReal::new(conn);
        assert_task_has_been_done_completely(&wrapped_conn, range_of_attempts.clone());
        let single_call_attempt_duration =
            single_call_end.duration_since(single_call_start).unwrap();
        (
            single_call_attempt_duration,
            separate_calls_attempt_duration,
        )
    }

    #[test]
    fn performance_test_for_mark_pending_payable_rowids_with_five_updates() {
        //processing every odd item in the range
        let tested_range_of_cumulative_updates = 1..=9;
        let (single_call_attempt_duration, separate_calls_attempt_duration) =
            run_performance_test_for_mark_pending_payable_rowids(
                "performance_test_for_mark_pending_payable_rowids_with_multiple_updates",
                tested_range_of_cumulative_updates,
            );
        assert!(single_call_attempt_duration * 220 < separate_calls_attempt_duration * 100,
                "With multi-update machinery: {} μs, with a very simple call: {} μs; where the former is {} μs with 220 % correction",
                single_call_attempt_duration.as_micros(),
                separate_calls_attempt_duration.as_micros(),
                ((single_call_attempt_duration * 220) / 100).as_micros()
        )
        //I've also often seen 350 % or even 400 % better performance but 220 % is safe for CI and CPU timing.
        //The disregarded benefit is though that the first scenario requires just a single call and so with the threads synchronization
        //done by the database manager
    }

    #[test]
    fn performance_test_for_mark_pending_payable_rowids_on_just_one_update() {
        let tested_range_of_cumulative_updates = 1..=1;
        let (single_call_attempt_duration, separate_calls_attempt_duration) =
            run_performance_test_for_mark_pending_payable_rowids(
                "performance_test_for_mark_pending_payable_rowids_on_just_one_update",
                tested_range_of_cumulative_updates,
            );
        assert!(single_call_attempt_duration * 100 < separate_calls_attempt_duration * 115,
            "With multi-update machinery: {} μs, with a very simple call: {} μs; where the letter is {} μs with 15% correction",
            single_call_attempt_duration.as_micros(),
            separate_calls_attempt_duration.as_micros(),
                ((separate_calls_attempt_duration * 115) / 100).as_micros()
        )
        //I've seen only 10% or even less correction to work just okay and frequently.
    }

    #[test]
    #[should_panic(
        expected = "Marking pending payable rowid for wallets 0x000000000000000000000000000000626f6f6761 affected 0 rows but expected 1"
    )]
    fn mark_pending_payables_rowids_returned_different_row_count_than_expected_when_no_fingerprint_id_assigned_at_the_moment(
    ) {
        let home_dir = ensure_node_home_directory_exists(
            "payable_dao",
            "mark_pending_payables_rowids_returned_different_row_count_than_expected_when_no_fingerprint_id_assigned_at_the_moment",
        );
        let wallet = make_wallet("booga");
        let rowid = 656;
        let conn = DbInitializerReal::default()
            .initialize(&home_dir, true, MigratorConfig::test_default())
            .unwrap();
        let subject = PayableDaoReal::new(conn);

        let _ = subject.mark_pending_payables_rowids(&[(&wallet, rowid)]);
    }

    #[test]
    #[should_panic(
        expected = "Marking pending payable rowid for wallets 0x000000000000000000000000000000686f6f6761, \
         0x000000000000000000000000000000626f6f6761, 0x00000000000000000000626f6f6761686f6f6761 affected 1 rows but expected 3. \
         Accounts for wallets (0x000000000000000000000000000000626f6f6761, 0x00000000000000000000626f6f6761686f6f6761) had contained \
          rowids when we tried to update them with new ones. All such columns should be emptied beforehand at the confirmation of the \
           earlier transactions. A malformed, repeated payment is suspected"
    )]
    fn mark_pending_payables_rowids_refuses_to_overwrite_existing_marked_rowids() {
        let home_dir = ensure_node_home_directory_exists(
            "payable_dao",
            "mark_pending_payables_rowids_refuses_to_overwrite_existing_marked_rowids",
        );
        let wallet_1 = make_wallet("hooga");
        let rowid_1 = 550;
        let wallet_2 = make_wallet("booga");
        let rowid_2 = 555;
        let wallet_3 = make_wallet("boogahooga");
        let rowid_3 = 558;
        let conn = DbInitializerReal::default()
            .initialize(&home_dir, true, MigratorConfig::test_default())
            .unwrap();
        create_payable_account_with_pending_payment(
            &*conn,
            &wallet_1,
            12345,
            from_time_t(1_000_000_000),
            0,
        );
        conn.prepare("update payable set pending_payable_rowid = null where wallet_address = ?")
            .unwrap()
            .execute(&[&wallet_1])
            .unwrap();
        create_payable_account_with_pending_payment(
            &*conn,
            &wallet_2,
            23456,
            from_time_t(1_000_000_111),
            540,
        );
        create_payable_account_with_pending_payment(
            &*conn,
            &wallet_3,
            34567,
            from_time_t(1_000_000_222),
            541,
        );
        let subject = PayableDaoReal::new(conn);

        let _ = subject.mark_pending_payables_rowids(&[
            (&wallet_1, rowid_1),
            (&wallet_2, rowid_2),
            (&wallet_3, rowid_3),
        ]);
    }

    #[test]
    fn mark_pending_payables_rowids_handles_general_sql_error() {
        let home_dir = ensure_node_home_directory_exists(
            "payable_dao",
            "mark_pending_payables_rowids_handles_general_sql_error",
        );
        let wallet = make_wallet("booga");
        let rowid = 656;
        let conn = how_to_trick_rusqlite_for_an_error(&home_dir);
        let conn_wrapped = ConnectionWrapperReal::new(conn);
        let subject = PayableDaoReal::new(Box::new(conn_wrapped));

        let result = subject.mark_pending_payables_rowids(&[(&wallet, rowid)]);

        assert_eq!(
            result,
            Err(PayableDaoError::RusqliteError(
                "attempt to write a readonly database".to_string()
            ))
        )
    }

    fn create_payable_account_with_pending_payment(
        conn: &dyn ConnectionWrapper,
        recipient_wallet: &Wallet,
        amount: i64,
        timestamp: SystemTime,
        rowid: u64,
    ) {
        let mut stm1 = conn
            .prepare(
                "insert into payable (wallet_address, balance, \
         last_paid_timestamp, pending_payable_rowid) values (?,?,?,?)",
            )
            .unwrap();
        let params: &[&dyn ToSql] = &[
            &recipient_wallet,
            &amount,
            &to_time_t(timestamp),
            &unsigned_to_signed(rowid).unwrap(),
        ];
        let row_changed = stm1.execute(params).unwrap();
        assert_eq!(row_changed, 1);
    }

    struct TestSetupValuesHolder {
        fingerprint_1: PendingPayableFingerprint,
        fingerprint_2: PendingPayableFingerprint,
        wallet_1: Wallet,
        wallet_2: Wallet,
        starting_amount_1: i64,
        starting_amount_2: i64,
    }

    fn make_fingerprint_pair_and_insert_initial_payable_records(
        conn: &dyn ConnectionWrapper,
    ) -> TestSetupValuesHolder {
        let hash_1 = make_tx_hash(12345);
        let rowid_1 = 789;
        let previous_timestamp_1 = from_time_t(190_000_000);
        let new_payable_timestamp_1 = from_time_t(199_000_000);
        let starting_amount_1 = 10000;
        let payment_1 = 6666;
        let wallet_1 = make_wallet("bobble");
        let hash_2 = make_tx_hash(54321);
        let rowid_2 = 792;
        let previous_timestamp_2 = from_time_t(187_100_000);
        let new_payable_timestamp_2 = from_time_t(191_333_000);
        let starting_amount_2 = 200;
        let payment_2 = 20000000;
        let wallet_2 = make_wallet("booble bobble");
        {
            create_payable_account_with_pending_payment(
                conn,
                &wallet_1,
                starting_amount_1,
                previous_timestamp_1,
                rowid_1,
            );
            create_payable_account_with_pending_payment(
                conn,
                &wallet_2,
                starting_amount_2,
                previous_timestamp_2,
                rowid_2,
            )
        }
        let fingerprint_1 = PendingPayableFingerprint {
            rowid: rowid_1,
            timestamp: new_payable_timestamp_1,
            hash: hash_1,
            attempt: 1,
            amount: payment_1 as u64,
            process_error: None,
        };
        let fingerprint_2 = PendingPayableFingerprint {
            rowid: rowid_2,
            timestamp: new_payable_timestamp_2,
            hash: hash_2,
            attempt: 1,
            amount: payment_2 as u64,
            process_error: None,
        };
        TestSetupValuesHolder {
            fingerprint_1,
            fingerprint_2,
            wallet_1,
            wallet_2,
            starting_amount_1,
            starting_amount_2,
        }
    }

    #[test]
    fn transaction_confirmed_works() {
        let home_dir =
            ensure_node_home_directory_exists("payable_dao", "transaction_confirmed_works");
        let boxed_conn = DbInitializerReal::default()
            .initialize(&home_dir, true, MigratorConfig::test_default())
            .unwrap();
        let setup_holder =
            make_fingerprint_pair_and_insert_initial_payable_records(boxed_conn.as_ref());
        let subject = PayableDaoReal::new(boxed_conn);
        let expected_account_1 = PayableAccount {
            wallet: setup_holder.wallet_1.clone(),
            balance: setup_holder.starting_amount_1 - setup_holder.fingerprint_1.amount as i64,
            last_paid_timestamp: setup_holder.fingerprint_1.timestamp,
            pending_payable_opt: None,
        };
        let expected_account_2 = PayableAccount {
            wallet: setup_holder.wallet_2.clone(),
            balance: setup_holder.starting_amount_2 - setup_holder.fingerprint_2.amount as i64,
            last_paid_timestamp: setup_holder.fingerprint_2.timestamp,
            pending_payable_opt: None,
        };

        let result = subject
            .transactions_confirmed(&[setup_holder.fingerprint_1, setup_holder.fingerprint_2]);

        assert_eq!(result, Ok(()));
        let secondary_conn = Connection::open(home_dir.join(DATABASE_FILE)).unwrap();
        let account_1_opt = account_status(&secondary_conn, &setup_holder.wallet_1);
        assert_eq!(account_1_opt, Some(expected_account_1));
        let account_2_opt = account_status(&secondary_conn, &setup_holder.wallet_2);
        assert_eq!(account_2_opt, Some(expected_account_2))
    }

    #[test]
    fn transaction_confirmed_works_for_generic_sql_error() {
        let home_dir = ensure_node_home_directory_exists(
            "payable_dao",
            "transaction_confirmed_works_for_generic_sql_error",
        );
        let conn = how_to_trick_rusqlite_for_an_error(&home_dir);
        let conn_wrapped = ConnectionWrapperReal::new(conn);
        let mut pending_payable_fingerprint = make_pending_payable_fingerprint();
        let hash = make_tx_hash(12345);
        let rowid = 789;
        pending_payable_fingerprint.hash = hash;
        pending_payable_fingerprint.rowid = rowid;
        let subject = PayableDaoReal::new(Box::new(conn_wrapped));

        let result = subject.transactions_confirmed(&[pending_payable_fingerprint]);

        assert_eq!(
            result,
            Err(PayableDaoError::RusqliteError(
                "attempt to write a readonly database".to_string()
            ))
        )
    }

    #[test]
    fn transaction_confirmed_works_for_overflow_from_amount_stored_in_pending_payable_fingerprint()
    {
        let home_dir = ensure_node_home_directory_exists(
            "payable_dao",
            "transaction_confirmed_works_for_overflow_from_amount_stored_in_pending_payable_fingerprint",
        );
        let subject = PayableDaoReal::new(
            DbInitializerReal::default()
                .initialize(&home_dir, true, MigratorConfig::test_default())
                .unwrap(),
        );
        let mut pending_payable_fingerprint = make_pending_payable_fingerprint();
        let hash = make_tx_hash(12345);
        let rowid = 789;
        pending_payable_fingerprint.hash = hash;
        pending_payable_fingerprint.rowid = rowid;
        pending_payable_fingerprint.amount = u64::MAX;
        //The overflow occurs before we start modifying the payable account so I decided not to create an example in the database

        let result = subject.transactions_confirmed(&[pending_payable_fingerprint]);

        assert_eq!(result, Err(PayableDaoError::SignConversion(u64::MAX)))
    }

    #[test]
    fn transaction_confirmed_returns_error_from_another_cycle_which_happens_to_fail() {
        let home_dir = ensure_node_home_directory_exists(
            "payable_dao",
            "transaction_confirmed_returns_error_from_another_cycle_which_happens_to_fail",
        );
        let conn = DbInitializerReal::default()
            .initialize(&home_dir, true, MigratorConfig::test_default())
            .unwrap();
        let setup_holder = make_fingerprint_pair_and_insert_initial_payable_records(conn.as_ref());
        let subject = PayableDaoReal::new(conn);
        let expected_account_1 = PayableAccount {
            wallet: setup_holder.wallet_1.clone(),
            balance: setup_holder.starting_amount_1 - setup_holder.fingerprint_1.amount as i64,
            last_paid_timestamp: setup_holder.fingerprint_1.timestamp,
            pending_payable_opt: None,
        };
        let new_payment_timestamp_2 = setup_holder.fingerprint_2.timestamp;
        let mut fingerprint_2 = setup_holder.fingerprint_2;
        fingerprint_2.amount = u64::MAX;

        let result = subject.transactions_confirmed(&[setup_holder.fingerprint_1, fingerprint_2]);

        assert_eq!(result, Err(PayableDaoError::SignConversion(u64::MAX)));
        let secondary_conn = Connection::open(home_dir.join(DATABASE_FILE)).unwrap();
        let account_1_opt = account_status(&secondary_conn, &setup_holder.wallet_1);
        assert_eq!(account_1_opt, Some(expected_account_1));
        let account_2_opt = account_status(&secondary_conn, &setup_holder.wallet_2);
        assert_eq!(
            account_2_opt,
            Some(PayableAccount {
                wallet: setup_holder.wallet_2,
                balance: setup_holder.starting_amount_2,
                last_paid_timestamp: from_time_t(187_100_000),
                pending_payable_opt: Some(PendingPayableId {
                    rowid: 792,
                    hash: H256::default()
                })
            })
        );
        //negation
        assert_ne!(new_payment_timestamp_2, from_time_t(187_100_000))
    }

    fn how_to_trick_rusqlite_for_an_error(path: &Path) -> Connection {
        let db_path = path.join("experiment.db");
        let conn = RusqliteConnection::open_with_flags(&db_path, OpenFlags::default()).unwrap();
        {
            let mut stm = conn
                .prepare(
                    "\
                create table payable (\
                    wallet_address text primary key,
                    balance integer not null,
                    last_paid_timestamp integer not null,
                    pending_payable_rowid integer null)\
                    ",
                )
                .unwrap();
            stm.execute([]).unwrap();
        }
        conn.close().unwrap();
        let conn = RusqliteConnection::open_with_flags(&db_path, OpenFlags::SQLITE_OPEN_READ_ONLY)
            .unwrap();
        conn
    }

    #[test]
    fn non_pending_payables_should_return_an_empty_vec_when_the_database_is_empty() {
        let home_dir = ensure_node_home_directory_exists(
            "payable_dao",
            "non_pending_payables_should_return_an_empty_vec_when_the_database_is_empty",
        );

        let subject = PayableDaoReal::new(
            DbInitializerReal::default()
                .initialize(&home_dir, true, MigratorConfig::test_default())
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
            DbInitializerReal::default()
                .initialize(&home_dir, true, MigratorConfig::test_default())
                .unwrap(),
        );
        let mut flags = OpenFlags::empty();
        flags.insert(OpenFlags::SQLITE_OPEN_READ_WRITE);
        let conn = Connection::open_with_flags(&home_dir.join(DATABASE_FILE), flags).unwrap();
        let insert = |wallet: &str, balance: i64, pending_payable_rowid: Option<i64>| {
            let params: &[&dyn ToSql] = &[&wallet, &balance, &0i64, &pending_payable_rowid];

            conn
                .prepare("insert into payable (wallet_address, balance, last_paid_timestamp, pending_payable_rowid) values (?, ?, ?, ?)")
                .unwrap()
                .execute(params)
                .unwrap();
        };
        insert("0x0000000000000000000000000000000000666f6f", 42, Some(15));
        insert("0x0000000000000000000000000000000000626172", 24, Some(16));
        insert(&make_wallet("foobar").to_string(), 44, None);
        insert(&make_wallet("barfoo").to_string(), 22, None);

        let result = subject.non_pending_payables();

        assert_eq!(
            result,
            vec![
                PayableAccount {
                    wallet: make_wallet("foobar"),
                    balance: 44,
                    last_paid_timestamp: from_time_t(0),
                    pending_payable_opt: None
                },
                PayableAccount {
                    wallet: make_wallet("barfoo"),
                    balance: 22,
                    last_paid_timestamp: from_time_t(0),
                    pending_payable_opt: None
                },
            ]
        );
    }

    #[test]
    fn payable_amount_errors_on_insert_when_out_of_range() {
        let home_dir = ensure_node_home_directory_exists(
            "payable_dao",
            "payable_amount_precision_loss_panics_on_insert",
        );
        let subject = PayableDaoReal::new(
            DbInitializerReal::default()
                .initialize(&home_dir, true, MigratorConfig::test_default())
                .unwrap(),
        );

        let result =
            subject.more_money_payable(SystemTime::now(), &make_wallet("foobar"), u64::MAX);

        assert_eq!(result, Err(PayableDaoError::SignConversion(u64::MAX)))
    }

    #[test]
    fn top_records_and_total() {
        let home_dir = ensure_node_home_directory_exists("payable_dao", "top_records_and_total");
        let conn = DbInitializerReal::default()
            .initialize(&home_dir, true, MigratorConfig::test_default())
            .unwrap();
        let insert = |wallet: &str,
                      balance: i64,
                      timestamp: i64,
                      pending_payable_rowid: Option<i64>| {
            let params: &[&dyn ToSql] = &[&wallet, &balance, &timestamp, &pending_payable_rowid];
            conn
                .prepare("insert into payable (wallet_address, balance, last_paid_timestamp, pending_payable_rowid) values (?, ?, ?, ?)")
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
            Some(1),
        );
        let params: &[&dyn ToSql] = &[
            &String::from("0xabc4546cce78230a2312e12f3acb78747340456fe5237896666100143abcd223"),
            &40,
            &177777777,
            &1,
        ];
        conn
            .prepare("insert into pending_payable (transaction_hash,amount,payable_timestamp,attempt) values (?,?,?,?)")
            .unwrap()
            .execute(params)
            .unwrap();

        let subject = PayableDaoReal::new(conn);

        let top_records = subject.top_records(1_000_000_000, 86400);
        let total = subject.total();
        assert_eq!(
            top_records,
            vec![
                PayableAccount {
                    wallet: Wallet::new("0x4444444444444444444444444444444444444444"),
                    balance: 1_000_000_001,
                    last_paid_timestamp: from_time_t(timestamp4),
                    pending_payable_opt: Some(PendingPayableId {
                        rowid: 1,
                        hash: H256::from_str(
                            "abc4546cce78230a2312e12f3acb78747340456fe5237896666100143abcd223"
                        )
                        .unwrap()
                    })
                },
                PayableAccount {
                    wallet: Wallet::new("0x3333333333333333333333333333333333333333"),
                    balance: 1_000_000_000,
                    last_paid_timestamp: from_time_t(timestamp3),
                    pending_payable_opt: None
                },
            ]
        );
        assert_eq!(total, 4_000_000_000)
    }

    #[test]
    fn correctly_totals_zero_records() {
        let home_dir =
            ensure_node_home_directory_exists("payable_dao", "correctly_totals_zero_records");
        let conn = DbInitializerReal::default()
            .initialize(&home_dir, true, MigratorConfig::test_default())
            .unwrap();
        let subject = PayableDaoReal::new(conn);

        let result = subject.total();

        assert_eq!(result, 0)
    }
}
