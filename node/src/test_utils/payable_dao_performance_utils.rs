// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

#[cfg(any(test, not(feature = "no_test_share")))]
pub mod shared_test_environment {
    use crate::database::connection_wrapper::ConnectionWrapper;
    use crate::sub_lib::wallet::Wallet;
    use crate::test_utils::payable_dao_performance_utils::test_environment::{
        assert_zig_zag_task_has_been_done_completely, basic_body_for_performance_test,
        create_initial_state_records, make_str_wallet_from_idx, update_call,
    };
    use std::ops::RangeInclusive;
    use std::str::FromStr;
    use std::time::Duration;

    pub fn specialized_body_for_zig_zag_test(
        test_name: &str,
        range_of_attempts: RangeInclusive<usize>,
    ) -> (Duration, Duration) {
        let separate_calls_logic =
            |conn: &dyn ConnectionWrapper, range_of_attempts: &RangeInclusive<usize>| {
                range_of_attempts.clone().for_each(|attempt| {
                    if attempt % 2 != 0 {
                        update_call(attempt, conn)
                    }
                })
            };
        let provided_owned_args = |range_of_attempts: &RangeInclusive<usize>| {
            range_of_attempts
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
                .collect::<Vec<_>>()
        };
        basic_body_for_performance_test(
            test_name,
            range_of_attempts,
            create_initial_state_records,
            separate_calls_logic,
            provided_owned_args,
            assert_zig_zag_task_has_been_done_completely,
        )
    }
}

#[cfg(any(test, not(feature = "no_test_share")))]
pub mod test_environment {
    use crate::accountant::payable_dao::{PayableDao, PayableDaoReal};
    use crate::database::connection_wrapper::{ConnectionWrapper, ConnectionWrapperReal};
    use crate::database::db_initializer::{
        DbInitializationConfig, DbInitializer, DbInitializerReal, DATABASE_FILE,
    };
    use crate::sub_lib::wallet::Wallet;
    use itertools::Itertools;
    use masq_lib::test_utils::utils::ensure_node_home_directory_exists;
    use rusqlite::{Connection, ToSql};
    use std::ops::RangeInclusive;
    use std::str::FromStr;
    use std::time::{Duration, SystemTime};

    pub(super) fn make_str_wallet_from_idx(idx: usize) -> String {
        format!("0x{:0>40}", idx)
    }

    pub(super) fn create_initial_state_records(
        conn: &dyn ConnectionWrapper,
        range_of_attempts: &RangeInclusive<usize>,
    ) {
        let set_of_values = range_of_attempts
            .clone()
            .map(|idx| {
                format!(
                    "('{}', 0, 1000, 12345, null)",
                    make_str_wallet_from_idx(idx)
                )
            })
            .join(", ");
        let sql = format!(
            "insert into payable (wallet_address, balance_high_b, \
         balance_low_b, last_paid_timestamp, pending_payable_rowid) values {}",
            set_of_values
        );
        let _ = conn.prepare(&sql).unwrap().execute([]).unwrap();
    }

    fn assert_count_and_return_all_updated_rows(
        conn: &dyn ConnectionWrapper,
        range_of_attempts: &RangeInclusive<usize>,
    ) -> Vec<(String, i64)> {
        let sql_count = "select count(*) from payable";
        let count_found = conn
            .prepare(sql_count)
            .unwrap()
            .query_row([], |row| row.get::<usize, usize>(0))
            .unwrap();
        assert_eq!(
            count_found,
            range_of_attempts.end() - range_of_attempts.start() + 1
        );
        let sql = "select wallet_address, pending_payable_rowid from payable where pending_payable_rowid not null";
        conn.prepare(sql)
            .unwrap()
            .query_map([], |row| {
                Ok((
                    row.get::<usize, String>(0).unwrap(),
                    row.get::<usize, Option<i64>>(1).unwrap().unwrap(),
                ))
            })
            .unwrap()
            .flatten()
            .collect()
    }

    pub(super) fn assert_zig_zag_task_has_been_done_completely(
        conn: &dyn ConnectionWrapper,
        range_of_attempts: &RangeInclusive<usize>,
    ) {
        let updated_wallets_and_rowids =
            assert_count_and_return_all_updated_rows(conn, range_of_attempts);
        let odd_idx_iterator = range_of_attempts.clone().into_iter().step_by(2);
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

    fn assert_long_traverse_task_has_been_done_completely(
        conn: &dyn ConnectionWrapper,
        range_of_attempts: &RangeInclusive<usize>,
    ) {
        let updated_wallets_and_rowids =
            assert_count_and_return_all_updated_rows(conn, range_of_attempts);
        let just_corner_records_idx = [range_of_attempts.start(), range_of_attempts.end()];
        assert_eq!(updated_wallets_and_rowids.len(), 2);
        updated_wallets_and_rowids
            .into_iter()
            .zip(just_corner_records_idx)
            .for_each(|((wallet, rowid), idx)| {
                assert_eq!(rowid as usize, *idx);
                assert_eq!(wallet, make_str_wallet_from_idx(*idx));
            })
    }

    pub(super) fn update_call(idx: usize, conn: &dyn ConnectionWrapper) {
        let rows_changed = conn
            .prepare("update payable set pending_payable_rowid = ? where wallet_address = ?")
            .unwrap()
            .execute(&[&idx as &dyn ToSql, &make_str_wallet_from_idx(idx)])
            .unwrap();
        assert_eq!(rows_changed, 1)
    }

    pub(super) fn basic_body_for_performance_test<F1, F2>(
        test_name: &str,
        range_of_attempts: RangeInclusive<usize>,
        create_initial_records: fn(&dyn ConnectionWrapper, &RangeInclusive<usize>),
        attempt_logic_for_separate_call: F1,
        provide_args_for_multi_update_records: F2,
        assert_all_updates_done_correctly: fn(&dyn ConnectionWrapper, &RangeInclusive<usize>),
    ) -> (Duration, Duration)
    where
        F1: FnOnce(&dyn ConnectionWrapper, &RangeInclusive<usize>),
        F2: FnOnce(&RangeInclusive<usize>) -> Vec<(Wallet, u64)>,
    {
        let test_home_folder = ensure_node_home_directory_exists("payable_dao", test_name);
        let db_for_separate_calls = DbInitializerReal::default()
            .initialize(
                test_home_folder.join("separate_calls").as_path(),
                DbInitializationConfig::test_default(),
            )
            .unwrap();
        create_initial_records(db_for_separate_calls.as_ref(), &range_of_attempts);
        let separate_calls_start = SystemTime::now();

        attempt_logic_for_separate_call(db_for_separate_calls.as_ref(), &range_of_attempts);

        let separate_calls_end = SystemTime::now();
        assert_all_updates_done_correctly(db_for_separate_calls.as_ref(), &range_of_attempts);
        let separate_calls_attempt_duration = separate_calls_end
            .duration_since(separate_calls_start)
            .unwrap();
        ////     THE SECOND PART    ////
        let single_call_path = test_home_folder.join("single_call");
        let db_for_single_call = DbInitializerReal::default()
            .initialize(
                single_call_path.as_path(),
                DbInitializationConfig::test_default(),
            )
            .unwrap();
        create_initial_records(db_for_single_call.as_ref(), &range_of_attempts);
        let dao = PayableDaoReal::new(db_for_single_call);
        let provided_owned_args = provide_args_for_multi_update_records(&range_of_attempts);
        let args = provided_owned_args
            .iter()
            .map(|(wallet, id)| (wallet, *id))
            .collect::<Vec<(&Wallet, u64)>>();
        let single_call_start = SystemTime::now();

        dao.mark_pending_payables_rowids(&args).unwrap();

        let single_call_end = SystemTime::now();
        let conn = Connection::open(single_call_path.join(DATABASE_FILE)).unwrap();
        let helper_conn = ConnectionWrapperReal::new(conn);
        assert_all_updates_done_correctly(&helper_conn, &range_of_attempts);
        let single_call_attempt_duration =
            single_call_end.duration_since(single_call_start).unwrap();
        (
            single_call_attempt_duration,
            separate_calls_attempt_duration,
        )
    }

    pub fn specialized_body_for_long_traverse_test(
        test_name: &str,
        full_range_of_records: RangeInclusive<usize>,
        only_updated_records: [usize; 2],
    ) -> (Duration, Duration) {
        let separate_calls_logic =
            |conn: &dyn ConnectionWrapper, _range_of_attempts: &RangeInclusive<usize>| {
                only_updated_records
                    .into_iter()
                    .for_each(|attempt| update_call(attempt, conn))
            };
        let provided_owned_args = |_range_of_attempts: &RangeInclusive<usize>| {
            only_updated_records
                .into_iter()
                .map(|idx| {
                    (
                        Wallet::from_str(&make_str_wallet_from_idx(idx)).unwrap(),
                        idx as u64,
                    )
                })
                .collect::<Vec<(Wallet, u64)>>()
        };

        basic_body_for_performance_test(
            test_name,
            full_range_of_records,
            create_initial_state_records,
            separate_calls_logic,
            provided_owned_args,
            assert_long_traverse_task_has_been_done_completely,
        )
    }
}
