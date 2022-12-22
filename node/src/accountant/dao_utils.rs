// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::big_int_processing::big_int_divider::BigIntDivider;
use crate::accountant::payable_dao::PayableAccount;
use crate::accountant::receivable_dao::ReceivableAccount;
use crate::accountant::{checked_conversion, sign_conversion};
use crate::database::connection_wrapper::ConnectionWrapper;
use crate::database::db_initializer::{
    connection_or_panic, DbInitializationConfig, DbInitializerReal,
};
use masq_lib::constants::WEIS_OF_GWEI;
use masq_lib::messages::{
    RangeQuery, TopRecordsConfig, TopRecordsOrdering, UiPayableAccount, UiReceivableAccount,
};
use masq_lib::utils::{ExpectValue, plus};
use rusqlite::{Row, ToSql};
use std::cell::RefCell;
use std::fmt::{Debug, Display};
use std::iter::FlatMap;
use std::path::{Path, PathBuf};
use std::time::Duration;
use std::time::SystemTime;

pub fn to_time_t(system_time: SystemTime) -> i64 {
    match system_time.duration_since(SystemTime::UNIX_EPOCH) {
        Ok(d) => sign_conversion::<u64, i64>(d.as_secs()).expect("MASQNode has expired"),
        Err(e) => panic!(
            "Must be wrong, moment way far in the past: {:?}, {}",
            system_time, e
        ),
    }
}

pub fn now_time_t() -> i64 {
    to_time_t(SystemTime::now())
}

pub fn from_time_t(time_t: i64) -> SystemTime {
    let interval = Duration::from_secs(time_t as u64);
    SystemTime::UNIX_EPOCH + interval
}

pub struct DaoFactoryReal {
    pub data_directory: PathBuf,
    pub init_config: RefCell<Option<DbInitializationConfig>>,
}

impl DaoFactoryReal {
    pub fn new(data_directory: &Path, init_config: DbInitializationConfig) -> Self {
        Self {
            data_directory: data_directory.to_path_buf(),
            init_config: RefCell::new(Some(init_config)),
        }
    }

    pub fn make_connection(&self) -> Box<dyn ConnectionWrapper> {
        connection_or_panic(
            &DbInitializerReal::default(),
            &self.data_directory,
            self.init_config.take().expectv("Db init config"),
        )
    }
}

impl<T> From<TopRecordsConfig> for CustomQuery<T> {
    fn from(config: TopRecordsConfig) -> Self {
        CustomQuery::TopRecords {
            count: config.count,
            ordered_by: config.ordered_by,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CustomQuery<N> {
    TopRecords {
        count: u16,
        ordered_by: TopRecordsOrdering,
    },
    RangeQuery {
        min_age_s: u64,
        max_age_s: u64,
        min_amount_gwei: N,
        max_amount_gwei: N,
        timestamp: SystemTime,
    },
}

type RusqliteParamsWithOwnedToSql = Vec<(&'static str, Box<dyn ToSql>)>;

pub struct TopStmConfig {
    pub limit_clause: &'static str,
    pub gwei_min_resolution_clause: &'static str,
    pub age_ordering_clause: &'static str,
}

pub struct RangeStmConfig {
    pub where_clause: &'static str,
    pub gwei_min_resolution_clause: &'static str,
    pub secondary_order_param: &'static str,
}

pub struct AssemblerFeeder {
    pub main_where_clause: &'static str,
    pub where_clause_extension: &'static str,
    pub order_by_first_param: &'static str,
    pub order_by_second_param: &'static str,
    pub limit_clause: &'static str,
}

//be aware that balances smaller than one gwei won't be shown,
//if there aren't any bigger ones the function returns None
impl<N: Copy + Display> CustomQuery<N> {
    pub fn query<R, S, F1, F2>(
        self,
        conn: &dyn ConnectionWrapper,
        stm_assembler: F1,
        variant_top: TopStmConfig,
        variant_range: RangeStmConfig,
        value_fetcher: F2,
    ) -> Option<Vec<R>>
    where
        F1: Fn(AssemblerFeeder) -> String,
        F2: Fn(&Row) -> rusqlite::Result<R>,
        S: TryFrom<N>,
        i128: From<N>,
    {
        let (finalized_stm, params): (String, RusqliteParamsWithOwnedToSql) = match self {
            Self::TopRecords { count, ordered_by } => {
                let (order_by_first_param, order_by_second_param) =
                    Self::ordering(ordered_by, variant_top.age_ordering_clause);
                (
                    stm_assembler(AssemblerFeeder {
                        main_where_clause: variant_top.gwei_min_resolution_clause,
                        where_clause_extension: "",
                        order_by_first_param,
                        order_by_second_param,
                        limit_clause: variant_top.limit_clause,
                    }),
                    vec![(":limit_count", Box::new(count as i64))],
                )
            }
            Self::RangeQuery {
                min_age_s: min_age,
                max_age_s: max_age,
                min_amount_gwei: min_amount,
                max_amount_gwei: max_amount,
                timestamp,
            } => (
                stm_assembler(AssemblerFeeder {
                    main_where_clause: variant_range.where_clause,
                    where_clause_extension: variant_range.gwei_min_resolution_clause,
                    order_by_first_param: "balance_high_b desc, balance_low_b desc",
                    order_by_second_param: variant_range.secondary_order_param,
                    limit_clause: "",
                }),
                Self::set_age_constraints(min_age, max_age, timestamp)
                    .into_iter()
                    .chain(Self::set_wei_constraints(min_amount, max_amount))
                    .collect::<Vec<(&str, Box<dyn ToSql>)>>(),
            ),
        };
        let accounts = Self::execute_query(conn, &finalized_stm, params, value_fetcher);
        (!accounts.is_empty()).then_some(accounts)
    }

    fn execute_query<'a, R, F1>(
        conn: &'a dyn ConnectionWrapper,
        stm: &'a str,
        params: RusqliteParamsWithOwnedToSql,
        value_fetcher: F1,
    ) -> Vec<R>
    where
        F1: Fn(&Row) -> rusqlite::Result<R>,
    {
        conn.prepare(stm)
            .expect("select statement is wrong")
            .query_map(
                params
                    .iter()
                    .map(|(param_name, value)| (*param_name, value.as_ref()))
                    .collect::<Vec<_>>()
                    .as_slice(),
                value_fetcher,
            )
            .unwrap_or_else(|e| panic!("database corrupt: {}", e))
            .vigilant_flatten()
            .collect::<Vec<R>>()
    }

    fn set_age_constraints(
        min_age: u64,
        max_age: u64,
        timestamp: SystemTime,
    ) -> RusqliteParamsWithOwnedToSql {
        let now = to_time_t(timestamp);
        let age_to_time_t = |age_limit| now - checked_conversion::<u64, i64>(age_limit);
        vec![
            (":min_timestamp", Box::new(age_to_time_t(max_age))),
            (":max_timestamp", Box::new(age_to_time_t(min_age))),
        ]
    }

    fn set_wei_constraints(min_amount: N, max_amount: N) -> RusqliteParamsWithOwnedToSql
    where
        i128: From<N>,
    {
        [
            (":min_balance_high_b", ":min_balance_low_b"),
            (":max_balance_high_b", ":max_balance_low_b"),
        ]
        .into_iter()
        .zip([min_amount, max_amount].into_iter())
        .flat_map(|(param_names, gwei_num)| {
            let wei_num = i128::from(gwei_num) * WEIS_OF_GWEI;
            let big_int_divided = BigIntDivider::deconstruct(wei_num);
            Self::balance_constraint_as_integer_pair(param_names, big_int_divided)
        })
        .collect()
    }

    fn balance_constraint_as_integer_pair<'a>(
        param_names: (&'a str, &'a str),
        big_int_divided: (i64, i64),
    ) -> Vec<(&'a str, Box<dyn ToSql>)> {
        let (high_bytes_param_name, low_bytes_param_name) = param_names;
        let (high_bytes_value, low_bytes_value) = big_int_divided;
        vec![
            (high_bytes_param_name, Box::new(high_bytes_value)),
            (low_bytes_param_name, Box::new(low_bytes_value)),
        ]
    }

    fn ordering(
        ordering: TopRecordsOrdering,
        age_param: &'static str,
    ) -> (&'static str, &'static str) {
        match ordering {
            TopRecordsOrdering::Age => (age_param, "balance_high_b desc, balance_low_b desc"),
            TopRecordsOrdering::Balance => ("balance_high_b desc, balance_low_b desc", age_param),
        }
    }
}

impl<T: Copy> From<&RangeQuery<T>> for CustomQuery<T> {
    fn from(user_input: &RangeQuery<T>) -> Self {
        Self::RangeQuery {
            min_age_s: user_input.min_age_s,
            max_age_s: user_input.max_age_s,
            min_amount_gwei: user_input.min_amount_gwei,
            max_amount_gwei: user_input.max_amount_gwei,
            timestamp: SystemTime::now(),
        }
    }
}

pub fn remap_payable_accounts(accounts: Vec<PayableAccount>) -> Vec<UiPayableAccount> {
    accounts
        .into_iter()
        .map(|account| UiPayableAccount {
            wallet: account.wallet.to_string(),
            age_s: to_age(account.last_paid_timestamp),
            balance_gwei: {
                let gwei = (account.balance_wei / (WEIS_OF_GWEI as u128)) as u64;
                if gwei > 0 {
                    gwei
                } else {
                    panic!(
                        "Broken code: PayableAccount with less than 1 gwei passed through db query \
                         constraints; wallet: {}, balance: {}",
                        account.wallet, account.balance_wei
                    )
                }
            },
            pending_payable_hash_opt: account
                .pending_payable_opt
                .map(|full_id| full_id.hash.to_string()),
        })
        .collect()
}

pub fn remap_receivable_accounts(accounts: Vec<ReceivableAccount>) -> Vec<UiReceivableAccount> {
    accounts
        .into_iter()
        .map(|account| UiReceivableAccount {
            wallet: account.wallet.to_string(),
            age_s: to_age(account.last_received_timestamp),
            balance_gwei:{
                let gwei =  (account.balance_wei / (WEIS_OF_GWEI as i128)) as i64;
                if gwei != 0 {gwei} else {panic!("Broken code: ReceivableAccount with balance \
                 between {} and 0 gwei passed through db query constraints; wallet: {}, balance: {}",
                        if account.balance_wei.is_positive() {"1"}else{"-1"},
                        account.wallet,
                        account.balance_wei
            )}
          },
        })
        .collect()
}

fn to_age(timestamp: SystemTime) -> u64 {
    (to_time_t(SystemTime::now()) - to_time_t(timestamp)) as u64
}

#[allow(clippy::type_complexity)]
pub trait VigilantRusqliteFlatten {
    fn vigilant_flatten<R>(
        self,
    ) -> FlatMap<Self, rusqlite::Result<R>, fn(rusqlite::Result<R>) -> rusqlite::Result<R>>
    where
        Self: Iterator<Item = rusqlite::Result<R>> + Sized,
    {
        self.flat_map(|item: rusqlite::Result<R>| {
            item.map_err(|err| {
                panic!(
                    "discovered an error from a preceding operation when flattening produced \
                     Result structures: {:?}",
                    err
                )
            })
        })
    }
}

impl<T: Iterator<Item = rusqlite::Result<R>>, R> VigilantRusqliteFlatten for T {}

pub fn sum_i128_values_from_table(
    conn: &dyn ConnectionWrapper,
    table: &str,
    param_name: &str,
    value_completer: fn(usize, &Row) -> rusqlite::Result<i128>,
) -> i128 {
    let mut row_number = 0;
    let select_stm = format!("select {param_name}_high_b, {param_name}_low_b from {table}");
    conn.prepare(&select_stm)
        .expect("select stm error")
        .query_map([], |row| {
            row_number += 1;
            value_completer(row_number, row)
        })
        .expect("select query failed")
        .vigilant_flatten()
        .sum()
}

pub fn multi_row_update_rows_changed<T: Debug>(
    results: Result<impl Iterator<Item = Result<T, rusqlite::Error>>, rusqlite::Error>,
    rows_changed_counter: fn(Vec<T>) -> usize,
) -> Result<usize, rusqlite::Error> {
    let (oks, mut errs): (Vec<_>, Vec<_>) =
        results
            .expect("query failed on binding")
            .fold((vec![], vec![]), |acc, current| {
                if let Ok(val) = current {
                    (plus(acc.0, val), acc.1)
                } else {
                    (acc.0, plus(acc.1, current.expect_err("we saw it was err")))
                }
            });
    if errs.is_empty() {
        if !oks.is_empty() {
            Ok(rows_changed_counter(oks))
        } else {
            Ok(0)
        }
    } else if errs.len() == 1 {
        Err(errs.remove(0))
    } else {
        panic!(
            "broken code: we expect to get maximally a single error but got: {:?}",
            errs
        )
    }
}

#[cfg(test)]
mod tests {
    use std::option::IntoIter;
    use std::str::FromStr;
    use super::*;
    use crate::database::connection_wrapper::ConnectionWrapperReal;
    use crate::test_utils::make_wallet;
    use masq_lib::messages::TopRecordsOrdering::Balance;
    use masq_lib::test_utils::utils::ensure_node_home_directory_exists;
    use rusqlite::types::{ToSqlOutput, Value};
    use rusqlite::{Connection, OpenFlags};
    use std::time::UNIX_EPOCH;

    #[test]
    fn set_age_constraints_works() {
        let min_age = 5555;
        let max_age = 10000;
        let now = SystemTime::now();

        let result = CustomQuery::<i64>::set_age_constraints(min_age, max_age, now);

        assert_eq!(result.len(), 2);
        let param_pair_1 = &result[0];
        let param_pair_2 = &result[1];
        assert_eq!(param_pair_1.0, ":min_timestamp");
        assert_eq!(param_pair_2.0, ":max_timestamp");
        let get_assigned_value = |value| match value {
            ToSqlOutput::Owned(Value::Integer(num)) => num,
            x => panic!("we expected integer and got this: {:?}", x),
        };
        let assigned_value_1 = get_assigned_value(param_pair_1.1.to_sql().unwrap());
        let assigned_value_2 = get_assigned_value(param_pair_2.1.to_sql().unwrap());
        assert_eq!(assigned_value_1, to_time_t(now) - 10000);
        assert_eq!(assigned_value_2, to_time_t(now) - 5555)
    }

    #[test]
    #[should_panic(expected = "database corrupt: Invalid parameter name: :limit_count")]
    fn erroneous_query_leads_to_panic() {
        let home_dir =
            ensure_node_home_directory_exists("dao_utils", "erroneous_query_leads_to_panic");
        let db_path = home_dir.join("test.db");
        let creation_conn = Connection::open(db_path.as_path()).unwrap();
        creation_conn
            .execute(
                "create table fruits (kind text primary key, price integer not null)",
                [],
            )
            .unwrap();
        let conn_read_only =
            Connection::open_with_flags(db_path, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
        let conn_wrapped = ConnectionWrapperReal::new(conn_read_only);
        let subject = CustomQuery::<u64>::TopRecords {
            count: 12,
            ordered_by: Balance,
        };

        let _ = subject.query::<_, i64, _, _>(
            &conn_wrapped,
            |_feeder: AssemblerFeeder| "select kind, price from fruits".to_string(),
            TopStmConfig {
                limit_clause: "",
                gwei_min_resolution_clause: "",
                age_ordering_clause: "",
            },
            RangeStmConfig {
                where_clause: "",
                gwei_min_resolution_clause: "",
                secondary_order_param: "",
            },
            |_row| Ok(()),
        );
    }

    #[test]
    #[should_panic(
        expected = "Broken code: PayableAccount with less than 1 gwei passed through db query constraints; \
         wallet: 0x0000000000000000000000000061633336363563, balance: 565122333"
    )]
    fn remap_payable_accounts_getting_record_below_one_gwei_means_broken_database_query() {
        let accounts = vec![
            PayableAccount {
                wallet: make_wallet("abc123"),
                balance_wei: 4_888_123_457,
                last_paid_timestamp: SystemTime::now(),
                pending_payable_opt: None,
            },
            PayableAccount {
                wallet: make_wallet("ac3665c"),
                balance_wei: 565_122_333,
                last_paid_timestamp: SystemTime::now(),
                pending_payable_opt: None,
            },
        ];
        remap_payable_accounts(accounts);
    }

    #[test]
    #[should_panic(
        expected = "Broken code: ReceivableAccount with balance between 1 and 0 gwei passed through db query \
         constraints; wallet: 0x0000000000000000000000000061633336363563, balance: 300122333"
    )]
    fn remap_receivable_accounts_getting_record_between_one_and_zero_gwei_means_broken_database_query(
    ) {
        let accounts = vec![
            ReceivableAccount {
                wallet: make_wallet("ac45123"),
                balance_wei: 4_888_123_457,
                last_received_timestamp: SystemTime::now(),
            },
            ReceivableAccount {
                wallet: make_wallet("ac3665c"),
                balance_wei: 300_122_333,
                last_received_timestamp: SystemTime::now(),
            },
        ];
        remap_receivable_accounts(accounts);
    }

    #[test]
    #[should_panic(
        expected = "Broken code: ReceivableAccount with balance between -1 and 0 gwei passed through db query \
         constraints; wallet: 0x0000000000000000000000000061633336363563, balance: -290122333"
    )]
    fn remap_receivable_accounts_getting_record_between_minus_one_and_zero_gwei_means_broken_database_query(
    ) {
        let accounts = vec![
            ReceivableAccount {
                wallet: make_wallet("ac45123"),
                balance_wei: -4_000_123_457,
                last_received_timestamp: SystemTime::now(),
            },
            ReceivableAccount {
                wallet: make_wallet("ac3665c"),
                balance_wei: -290_122_333,
                last_received_timestamp: SystemTime::now(),
            },
        ];
        remap_receivable_accounts(accounts);
    }

    #[test]
    fn custom_query_from_range_query_works() {
        let subject = RangeQuery {
            min_age_s: 12,
            max_age_s: 55,
            min_amount_gwei: 89_i64,
            max_amount_gwei: 12222,
        };
        let before = SystemTime::now();

        let result: CustomQuery<i64> = (&subject).into();

        let after = SystemTime::now();
        if let CustomQuery::RangeQuery {
            min_age_s,
            max_age_s,
            min_amount_gwei,
            max_amount_gwei,
            timestamp,
        } = result
        {
            assert_eq!(min_age_s, 12);
            assert_eq!(max_age_s, 55);
            assert_eq!(min_amount_gwei, 89);
            assert_eq!(max_amount_gwei, 12222);
            assert!(before <= timestamp && timestamp <= after)
        } else {
            panic!("we expected range query but got something else")
        }
    }

    #[test]
    #[should_panic(expected = "Must be wrong, moment way far in the past")]
    fn to_time_t_does_not_like_time_traveling() {
        let far_far_before = UNIX_EPOCH.checked_sub(Duration::from_secs(1)).unwrap();

        let _ = to_time_t(far_far_before);
    }

    #[test]
    fn vigilant_flatten_can_flatten() {
        let collection = vec![Ok(56_u16), Ok(0), Ok(6789)];
        let iterator = collection.into_iter();

        let result = iterator.vigilant_flatten().collect::<Vec<_>>();

        assert_eq!(result, vec![56, 0, 6789])
    }

    #[test]
    #[should_panic(
        expected = "discovered an error from a preceding operation when flattening produced Result structures: QueryReturnedNoRows"
    )]
    fn vigilant_flatten_discovers_error() {
        let collection = vec![
            Ok(56_u16),
            Err(rusqlite::Error::QueryReturnedNoRows),
            Err(rusqlite::Error::UnwindingPanic),
        ];
        let iterator = collection.into_iter();

        let _ = iterator.vigilant_flatten().collect::<Vec<_>>();
    }

    #[test]
    #[should_panic(expected = "Failed to connect to database at \"nonexistent")]
    fn connection_panics_if_connection_cannot_be_made() {
        let subject = DaoFactoryReal::new(
            &PathBuf::from_str("nonexistent").unwrap(),
            DbInitializationConfig::test_default(),
        );

        let _ = subject.make_connection();
    }

    #[test]
    fn multi_update_rows_changed_returns_the_number() {
        let random_collection_of_changed_data = vec![Ok(5_i64), Ok(111), Ok(4321)];
        let iterator = random_collection_of_changed_data.into_iter();
        let result = multi_row_update_rows_changed(Ok(iterator), |ok_vec| ok_vec.len());

        assert_eq!(result, Ok(3))
    }

    #[test]
    fn multi_update_rows_changed_suspects_0_if_nothing_changed() {
        let random_collection_of_changed_data: Vec<Result<i64, _>> = vec![];
        let iterator = random_collection_of_changed_data.into_iter();

        let result = multi_row_update_rows_changed(Ok(iterator), |ok_vec| ok_vec.len());

        assert_eq!(result, Ok(0))
    }

    #[test]
    fn multi_update_rows_changed_returns_the_error() {
        //it's important to note that the real situation can only be a single error, not more errors
        let random_collection_of_changed_data: Vec<Result<i64, _>> =
            vec![Err(rusqlite::Error::QueryReturnedNoRows)];
        let iterator = random_collection_of_changed_data.into_iter();

        let result = multi_row_update_rows_changed(Ok(iterator), |ok_vec| ok_vec.len());

        assert_eq!(result, Err(rusqlite::Error::QueryReturnedNoRows))
    }

    #[test]
    #[should_panic(
    expected = "broken code: we expect to get maximally a single error but got: [QueryReturnedNoRows, InvalidQuery]"
    )]
    fn more_than_one_error_is_considered_a_malformation() {
        //it's important to note that the real situation can only be a single error, not more errors
        let random_collection_of_changed_data: Vec<Result<i64, _>> = vec![
            Err(rusqlite::Error::QueryReturnedNoRows),
            Err(rusqlite::Error::InvalidQuery),
        ];
        let iterator = random_collection_of_changed_data.into_iter();

        let _ = multi_row_update_rows_changed(Ok(iterator), |ok_vec| ok_vec.len());
    }

    #[test]
    #[should_panic(expected = "query failed on binding: InvalidParameterName(\"blah\")")]
    fn the_first_contact_rusqlite_error_just_panics_as_it_belongs_with_the_querys_args_binding() {
        let _ = multi_row_update_rows_changed(
            Err::<IntoIter<Result<i64, rusqlite::Error>>, _>(
                rusqlite::Error::InvalidParameterName("blah".to_string()),
            ),
            |ok_vec: Vec<i64>| ok_vec.len(),
        );
    }
}
