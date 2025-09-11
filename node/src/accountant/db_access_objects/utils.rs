// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::db_access_objects::failed_payable_dao::FailedTx;
use crate::accountant::db_access_objects::payable_dao::PayableAccount;
use crate::accountant::db_access_objects::receivable_dao::ReceivableAccount;
use crate::accountant::db_big_integer::big_int_divider::BigIntDivider;
use crate::accountant::{checked_conversion, gwei_to_wei, sign_conversion};
use crate::database::db_initializer::{
    connection_or_panic, DbInitializationConfig, DbInitializerReal,
};
use crate::database::rusqlite_wrappers::ConnectionWrapper;
use crate::sub_lib::accountant::PaymentThresholds;
use ethereum_types::H256;
use masq_lib::constants::WEIS_IN_GWEI;
use masq_lib::messages::{
    RangeQuery, TopRecordsConfig, TopRecordsOrdering, UiPayableAccount, UiReceivableAccount,
};
use rusqlite::{Row, Statement, ToSql};
use std::collections::HashMap;
use std::fmt::{Debug, Display};
use std::iter::FlatMap;
use std::path::{Path, PathBuf};
use std::string::ToString;
use std::time::Duration;
use std::time::SystemTime;

pub type TxHash = H256;
pub type RowId = u64;
pub type TxIdentifiers = HashMap<TxHash, RowId>;

pub fn to_unix_timestamp(system_time: SystemTime) -> i64 {
    match system_time.duration_since(SystemTime::UNIX_EPOCH) {
        Ok(d) => sign_conversion::<u64, i64>(d.as_secs()).expect("MASQNode has expired"),
        Err(e) => panic!(
            "Must be wrong, moment way far in the past: {:?}, {}",
            system_time, e
        ),
    }
}

pub fn current_unix_timestamp() -> i64 {
    to_unix_timestamp(SystemTime::now())
}

pub fn from_unix_timestamp(unix_timestamp: i64) -> SystemTime {
    let interval = Duration::from_secs(unix_timestamp as u64);
    SystemTime::UNIX_EPOCH + interval
}

pub fn sql_values_of_failed_tx(failed_tx: &FailedTx) -> String {
    let amount_checked = checked_conversion::<u128, i128>(failed_tx.amount);
    let gas_price_wei_checked = checked_conversion::<u128, i128>(failed_tx.gas_price_wei);
    let (amount_high_b, amount_low_b) = BigIntDivider::deconstruct(amount_checked);
    let (gas_price_wei_high_b, gas_price_wei_low_b) =
        BigIntDivider::deconstruct(gas_price_wei_checked);
    format!(
        "('{:?}', '{:?}', {}, {}, {}, {}, {}, {}, '{}', '{}')",
        failed_tx.hash,
        failed_tx.receiver_address,
        amount_high_b,
        amount_low_b,
        failed_tx.timestamp,
        gas_price_wei_high_b,
        gas_price_wei_low_b,
        failed_tx.nonce,
        failed_tx.reason,
        failed_tx.status
    )
}

pub struct DaoFactoryReal {
    pub data_directory: PathBuf,
    pub init_config: DbInitializationConfig,
}

impl DaoFactoryReal {
    pub fn new(data_directory: &Path, init_config: DbInitializationConfig) -> Self {
        Self {
            data_directory: data_directory.to_path_buf(),
            init_config,
        }
    }

    pub fn make_connection(&self) -> Box<dyn ConnectionWrapper> {
        connection_or_panic(
            &DbInitializerReal::default(),
            &self.data_directory,
            self.init_config.clone(),
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
        let now = to_unix_timestamp(timestamp);
        let age_to_unix_timestamp = |age_limit| now - checked_conversion::<u64, i64>(age_limit);
        vec![
            (":min_timestamp", Box::new(age_to_unix_timestamp(max_age))),
            (":max_timestamp", Box::new(age_to_unix_timestamp(min_age))),
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
            let wei_num = i128::from(gwei_num) * WEIS_IN_GWEI;
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
                let gwei = (account.balance_wei / (WEIS_IN_GWEI as u128)) as u64;
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
                let gwei =  (account.balance_wei / (WEIS_IN_GWEI as i128)) as i64;
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
    (to_unix_timestamp(SystemTime::now()) - to_unix_timestamp(timestamp)) as u64
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

pub fn update_rows_and_return_valid_count(
    update_returning_stm: &mut Statement,
    update_row_validator: fn(&Row) -> rusqlite::Result<bool>,
) -> Result<usize, Vec<rusqlite::Error>> {
    let init: (usize, Vec<rusqlite::Error>) = (0, vec![]);
    let validator_outputs = update_returning_stm.query_map([], update_row_validator);
    let (valid_rows_count, errs) = validator_outputs
        .expect("query failed on params binding")
        .fold(init, |(oks, mut errs), validator_output| {
            if let Ok(updated_row_is_valid) = validator_output {
                if updated_row_is_valid {
                    (oks + 1, errs)
                } else {
                    (oks, errs)
                }
            } else {
                errs.push(validator_output.expect_err("was seen as err"));
                (oks, errs)
            }
        });
    match errs.as_slice() {
        [] => Ok(valid_rows_count),
        _ => Err(errs),
    }
}

pub struct ThresholdUtils {}

impl ThresholdUtils {
    pub fn slope(payment_thresholds: &PaymentThresholds) -> i128 {
        /*
        Slope is an integer, rather than a float, to improve performance. Since there are
        computations that divide by the slope, it cannot be allowed to be zero; but since it's
        an integer, it can't get any closer to zero than -1.

        If the numerator of this computation is less than the denominator, the slope will be
        calculated as 0; therefore, .permanent_debt_allowed_gwei must be less than
        .debt_threshold_gwei, so that the numerator will be no greater than -10^9 (-gwei_to_wei(1)),
        and the denominator must be less than or equal to 10^9.

        These restrictions do not seem over-strict, since having .permanent_debt_allowed greater
        than or equal to .debt_threshold_gwei would result in chaos, and setting
        .threshold_interval_sec over 10^9 would mean continuing to declare debts delinquent after
        more than 31 years.

        If payment_thresholds are ever configurable by the user, these validations should be done
        on the values before they are accepted.
        */

        (gwei_to_wei::<i128, u64>(payment_thresholds.permanent_debt_allowed_gwei)
            - gwei_to_wei::<i128, u64>(payment_thresholds.debt_threshold_gwei))
            / payment_thresholds.threshold_interval_sec as i128
    }

    pub fn calculate_finite_debt_limit_by_age(
        payment_thresholds: &PaymentThresholds,
        debt_age_s: u64,
    ) -> u128 {
        if Self::qualifies_for_permanent_debt_limit(debt_age_s, payment_thresholds) {
            return gwei_to_wei(payment_thresholds.permanent_debt_allowed_gwei);
        };
        let m = ThresholdUtils::slope(payment_thresholds);
        let b = ThresholdUtils::compute_theoretical_interception_with_y_axis(
            m,
            payment_thresholds.maturity_threshold_sec as i128,
            gwei_to_wei(payment_thresholds.debt_threshold_gwei),
        );
        let y = m * debt_age_s as i128 + b;
        y as u128
    }

    fn compute_theoretical_interception_with_y_axis(
        m: i128, //is negative
        maturity_threshold_sec: i128,
        debt_threshold_wei: i128,
    ) -> i128 {
        debt_threshold_wei - (maturity_threshold_sec * m)
    }

    fn qualifies_for_permanent_debt_limit(
        debt_age_s: u64,
        payment_thresholds: &PaymentThresholds,
    ) -> bool {
        debt_age_s
            > (payment_thresholds.maturity_threshold_sec
                + payment_thresholds.threshold_interval_sec)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::rusqlite_wrappers::ConnectionWrapperReal;
    use crate::sub_lib::accountant::DEFAULT_PAYMENT_THRESHOLDS;
    use crate::test_utils::make_wallet;
    use itertools::Itertools;
    use masq_lib::constants::MASQ_TOTAL_SUPPLY;
    use masq_lib::messages::TopRecordsOrdering::Balance;
    use masq_lib::test_utils::utils::ensure_node_home_directory_exists;
    use rusqlite::types::{ToSqlOutput, Value};
    use rusqlite::{Connection, OpenFlags};
    use std::collections::HashMap;
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
        assert_eq!(assigned_value_1, to_unix_timestamp(now) - 10000);
        assert_eq!(assigned_value_2, to_unix_timestamp(now) - 5555)
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
    fn to_unix_timestamp_does_not_like_time_traveling() {
        let far_far_before = UNIX_EPOCH.checked_sub(Duration::from_secs(1)).unwrap();

        let _ = to_unix_timestamp(far_far_before);
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

    fn gap_tester(payment_thresholds: &PaymentThresholds) -> (u64, u64) {
        let mut counts_of_unique_elements: HashMap<u64, usize> = HashMap::new();
        (1_u64..20)
            .map(|to_add| {
                ThresholdUtils::calculate_finite_debt_limit_by_age(
                    &payment_thresholds,
                    1500 + to_add,
                ) as u64
            })
            .for_each(|point_height| {
                counts_of_unique_elements
                    .entry(point_height)
                    .and_modify(|q| *q += 1)
                    .or_insert(1);
            });

        let mut heights_and_counts = counts_of_unique_elements.drain().collect::<Vec<_>>();
        heights_and_counts.sort_by_key(|(height, _)| (u64::MAX - height));
        let mut counts_of_groups_of_the_same_size: HashMap<usize, (u64, usize)> = HashMap::new();
        let mut previous_height =
            ThresholdUtils::calculate_finite_debt_limit_by_age(&payment_thresholds, 1500) as u64;
        heights_and_counts
            .into_iter()
            .for_each(|(point_height, unique_count)| {
                let height_change = if point_height <= previous_height {
                    previous_height - point_height
                } else {
                    panic!("unexpected trend; previously: {previous_height}, now: {point_height}")
                };
                counts_of_groups_of_the_same_size
                    .entry(unique_count)
                    .and_modify(|(_height_change, occurrence_so_far)| *occurrence_so_far += 1)
                    .or_insert((height_change, 1));
                previous_height = point_height;
            });

        let mut sortable = counts_of_groups_of_the_same_size
            .drain()
            .collect::<Vec<_>>();
        sortable.sort_by_key(|(_key, (_height_change, occurrence))| *occurrence);

        let (number_of_seconds_detected, (height_change, occurrence)) =
            sortable.last().expect("no values to analyze");
        //checking if the sample of undistorted results (consist size groups) has enough weight compared to 20 tries from the beginning
        if number_of_seconds_detected * occurrence >= 15 {
            (*number_of_seconds_detected as u64, *height_change)
        } else {
            panic!("couldn't provide a relevant amount of data for the analysis")
        }
    }

    fn assert_on_height_granularity_with_advancing_time(
        description_of_given_pt: &str,
        payment_thresholds: &PaymentThresholds,
        expected_height_change_wei: u64,
    ) {
        let (seconds_needed_for_smallest_change_in_height, absolute_height_change_wei) =
            gap_tester(&payment_thresholds);

        assert_eq!(
            seconds_needed_for_smallest_change_in_height,
            1,
            "while testing {} we expected that these thresholds: {:?} will require only 1 s until \
             we see the height change but computed {} s instead",
            description_of_given_pt,
            payment_thresholds,
            seconds_needed_for_smallest_change_in_height
        );
        assert_eq!(
            absolute_height_change_wei,
            expected_height_change_wei,
            "while testing {} we expected that these thresholds: {:?} will cause a height change \
             of {} wei as a result of advancement in time by {} s but the true result is {}",
            description_of_given_pt,
            payment_thresholds,
            expected_height_change_wei,
            seconds_needed_for_smallest_change_in_height,
            absolute_height_change_wei
        )
    }

    #[test]
    fn testing_granularity_calculate_sloped_threshold_by_time() {
        let payment_thresholds = PaymentThresholds {
            maturity_threshold_sec: 1000,
            payment_grace_period_sec: 0,
            permanent_debt_allowed_gwei: 100,
            debt_threshold_gwei: 10_000,
            threshold_interval_sec: 10_000,
            unban_below_gwei: 100,
        };

        assert_on_height_granularity_with_advancing_time(
            "135° slope",
            &payment_thresholds,
            990_000_000,
        );

        let payment_thresholds = PaymentThresholds {
            maturity_threshold_sec: 1000,
            payment_grace_period_sec: 0,
            permanent_debt_allowed_gwei: 100,
            debt_threshold_gwei: 3_420,
            threshold_interval_sec: 10_000,
            unban_below_gwei: 100,
        };

        assert_on_height_granularity_with_advancing_time(
            "160° slope",
            &payment_thresholds,
            332_000_000,
        );

        let payment_thresholds = PaymentThresholds {
            maturity_threshold_sec: 1000,
            payment_grace_period_sec: 0,
            permanent_debt_allowed_gwei: 100,
            debt_threshold_gwei: 875,
            threshold_interval_sec: 10_000,
            unban_below_gwei: 100,
        };

        assert_on_height_granularity_with_advancing_time(
            "175° slope",
            &payment_thresholds,
            77_500_000,
        );
    }

    #[test]
    fn checking_chosen_values_for_the_payment_thresholds_defaults_on_height_values_granularity() {
        let payment_thresholds = *DEFAULT_PAYMENT_THRESHOLDS;

        assert_on_height_granularity_with_advancing_time(
            "default thresholds",
            &payment_thresholds,
            23_148_148_148_148,
        );
    }

    #[test]
    fn slope_has_loose_enough_limitations_to_allow_work_with_number_bigger_than_masq_token_max_supply(
    ) {
        //max masq token supply by August 2022: 37,500,000
        let payment_thresholds = PaymentThresholds {
            maturity_threshold_sec: 20,
            payment_grace_period_sec: 33,
            permanent_debt_allowed_gwei: 1,
            debt_threshold_gwei: MASQ_TOTAL_SUPPLY * WEIS_IN_GWEI as u64,
            threshold_interval_sec: 1,
            unban_below_gwei: 0,
        };

        let slope = ThresholdUtils::slope(&payment_thresholds);

        assert_eq!(slope, -37499999999999999000000000);
        let check = {
            let y_interception = ThresholdUtils::compute_theoretical_interception_with_y_axis(
                slope,
                payment_thresholds.maturity_threshold_sec as i128,
                gwei_to_wei(payment_thresholds.debt_threshold_gwei),
            );
            slope * (payment_thresholds.maturity_threshold_sec + 1) as i128 + y_interception
        };
        assert_eq!(check, WEIS_IN_GWEI)
    }

    #[test]
    fn slope_after_its_end_turns_into_permanent_debt_allowed() {
        let payment_thresholds = PaymentThresholds {
            maturity_threshold_sec: 1000,
            payment_grace_period_sec: 444,
            permanent_debt_allowed_gwei: 44,
            debt_threshold_gwei: 8888,
            threshold_interval_sec: 11111,
            unban_below_gwei: 0,
        };

        let right_at_the_end = ThresholdUtils::calculate_finite_debt_limit_by_age(
            &payment_thresholds,
            payment_thresholds.maturity_threshold_sec
                + payment_thresholds.threshold_interval_sec
                + 1,
        );
        let a_certain_distance_further = ThresholdUtils::calculate_finite_debt_limit_by_age(
            &payment_thresholds,
            payment_thresholds.maturity_threshold_sec
                + payment_thresholds.threshold_interval_sec
                + 1234,
        );

        assert_eq!(
            right_at_the_end,
            gwei_to_wei(payment_thresholds.permanent_debt_allowed_gwei)
        );
        assert_eq!(
            a_certain_distance_further,
            gwei_to_wei(payment_thresholds.permanent_debt_allowed_gwei)
        )
    }

    #[test]
    #[should_panic(
        expected = "Couldn't initialize database due to \"Nonexistent\" at \"generated/test\
        /dao_utils/make_connection_panics_if_connection_cannot_be_made/home"
    )]
    fn make_connection_panics_if_connection_cannot_be_made() {
        let data_dir = ensure_node_home_directory_exists(
            "dao_utils",
            "make_connection_panics_if_connection_cannot_be_made",
        );
        let subject = DaoFactoryReal::new(
            &data_dir.join("nonexistent_db"),
            DbInitializationConfig::panic_on_migration(),
        );

        let _ = subject.make_connection();
    }

    fn create_table_with_text_id_and_single_numeric_column(
        conn: &Connection,
        init_data: &[(&str, i64)],
    ) {
        conn.execute("create table example (name text, num integer)", [])
            .unwrap();
        if !init_data.is_empty() {
            let sequence_of_values_for_inserted_rows = init_data
                .iter()
                .map(|(name, num)| format!("({}, {})", name, num))
                .join(", ");
            let rows_added = conn
                .execute(
                    &format!(
                        "insert into example (name, num) values {}",
                        sequence_of_values_for_inserted_rows
                    ),
                    [],
                )
                .unwrap();
            assert_eq!(rows_added, init_data.len())
        }
    }

    const UPDATE_STM_WITH_RETURNING: &str = "update example set num = num + 2 returning num";

    #[test]
    fn update_rows_and_return_their_count_returns_all_satisfying_results() {
        let conn = Connection::open_in_memory().unwrap();
        create_table_with_text_id_and_single_numeric_column(
            &conn,
            &vec![("'A'", 12), ("'B'", 23), ("'C'", 34)],
        );
        let mut returning_update_stm = conn.prepare(UPDATE_STM_WITH_RETURNING).unwrap();
        let function_to_validate_row_value = |row: &Row| row.get::<usize, i64>(0).map(|_num| true);

        let result = update_rows_and_return_valid_count(
            &mut returning_update_stm,
            function_to_validate_row_value,
        );

        assert_eq!(result, Ok(3))
    }

    #[test]
    fn update_rows_and_return_their_count_allows_use_of_predicate() {
        let conn = Connection::open_in_memory().unwrap();
        create_table_with_text_id_and_single_numeric_column(
            &conn,
            &vec![("'A'", 12), ("'B'", -56), ("'C'", 34)],
        );
        let mut returning_update_stm = conn.prepare(UPDATE_STM_WITH_RETURNING).unwrap();
        let function_to_validate_row_value =
            |row: &Row| row.get::<usize, i64>(0).map(|num| num > 0);

        let result = update_rows_and_return_valid_count(
            &mut returning_update_stm,
            function_to_validate_row_value,
        );

        assert_eq!(result, Ok(2))
    }

    #[test]
    fn update_rows_and_return_their_count_suspects_0_if_nothing_to_change() {
        let conn = Connection::open_in_memory().unwrap();
        create_table_with_text_id_and_single_numeric_column(&conn, &vec![]);
        let mut returning_update_stm = conn.prepare(UPDATE_STM_WITH_RETURNING).unwrap();
        let function_to_validate_row_value = |row: &Row| row.get::<usize, i64>(0).map(|_num| true);

        let result = update_rows_and_return_valid_count(
            &mut returning_update_stm,
            function_to_validate_row_value,
        );

        assert_eq!(result, Ok(0))
    }

    #[test]
    fn update_rows_and_return_their_count_returns_all_errors() {
        let conn = Connection::open_in_memory().unwrap();
        create_table_with_text_id_and_single_numeric_column(&conn, &vec![("'A'", 12), ("'B'", 23)]);
        let mut returning_update_stm = conn.prepare(UPDATE_STM_WITH_RETURNING).unwrap();
        let function_to_validate_row_value = |_row: &Row| Err(rusqlite::Error::InvalidQuery);

        let result = update_rows_and_return_valid_count(
            &mut returning_update_stm,
            function_to_validate_row_value,
        );

        assert_eq!(
            result,
            Err(vec![
                rusqlite::Error::InvalidQuery,
                rusqlite::Error::InvalidQuery
            ])
        )
    }

    #[test]
    #[should_panic(expected = "query failed on params binding: InvalidParameterCount(0, 1)")]
    fn update_rows_and_return_valid_count_cannot_tolerate_parameterized_statement() {
        let conn = Connection::open_in_memory().unwrap();
        create_table_with_text_id_and_single_numeric_column(&conn, &vec![("'A'", 12), ("'B'", 23)]);
        let mut returning_update_stm = conn
            .prepare("update example set num = num + 2 where name = ? returning num")
            .unwrap();
        let function_to_validate_row_value =
            |row: &Row| row.get::<usize, String>(0).map(|_num| true);

        let _ = update_rows_and_return_valid_count(
            &mut returning_update_stm,
            function_to_validate_row_value,
        );
    }
}
