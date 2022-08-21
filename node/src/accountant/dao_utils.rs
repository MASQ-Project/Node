// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
use crate::accountant::big_int_db_processor::BigIntDivider;
use crate::accountant::payable_dao::PayableAccount;
use crate::accountant::receivable_dao::ReceivableAccount;
use crate::accountant::{checked_conversion, sign_conversion};
use crate::database::connection_wrapper::ConnectionWrapper;
use crate::database::db_initializer::{
    connection_or_panic, DbInitializationConfig, DbInitializerReal,
};
use crate::sub_lib::accountant::WEIS_OF_GWEI;
use masq_lib::messages::{
    RangeQuery, TopRecordsConfig, TopRecordsOrdering, UiPayableAccount, UiReceivableAccount,
};
use masq_lib::utils::ExpectValue;
use rusqlite::{Row, ToSql};
use std::cell::RefCell;
use std::fmt::Display;
use std::path::{Path, PathBuf};
use std::time::Duration;
use std::time::SystemTime;

pub fn to_time_t(system_time: SystemTime) -> i64 {
    match system_time.duration_since(SystemTime::UNIX_EPOCH) {
        Err(e) => unimplemented!("{}", e),
        Ok(d) => sign_conversion::<u64, i64>(d.as_secs()).expect("MASQNode has expired"),
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
    pub create_if_necessary: bool,
    pub init_config: RefCell<Option<DbInitializationConfig>>,
}

impl DaoFactoryReal {
    pub fn new(
        data_directory: &Path,
        create_if_necessary: bool,
        init_config: DbInitializationConfig,
    ) -> Self {
        Self {
            data_directory: data_directory.to_path_buf(),
            create_if_necessary,
            init_config: RefCell::new(Some(init_config)),
        }
    }

    pub fn make_connection(&self) -> Box<dyn ConnectionWrapper> {
        connection_or_panic(
            &DbInitializerReal::default(),
            &self.data_directory,
            self.create_if_necessary,
            self.init_config.take().expectv("MigratorConfig"),
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

#[derive(Debug, Clone, PartialEq)]
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
    limit_clause: &'static str,
    gwei_min_resolution_clause: &'static str,
    age_param: &'static str,
}

impl TopStmConfig {
    pub fn new(age_param: &'static str) -> Self {
        Self {
            limit_clause: "limit :limit_count",
            gwei_min_resolution_clause: "where (balance_high_b > 0) or ((balance_high_b = 0) and (balance_low_b >= 1000000000))",
            age_param,
        }
    }
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
                    Self::ordering(ordered_by, variant_top.age_param);
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
                Self::set_up_age_constrains(min_age, max_age, timestamp)
                    .into_iter()
                    .chain(Self::set_up_wei_constrains(vec![min_amount, max_amount]))
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
                &*params
                    .iter()
                    .map(|(param_name, value)| (*param_name, value.as_ref()))
                    .collect::<Vec<_>>(),
                value_fetcher,
            )
            .unwrap_or_else(|e| panic!("database corrupt: {}", e))
            .flatten()
            .collect::<Vec<R>>()
    }

    fn set_up_age_constrains(
        min_age: u64,
        max_age: u64,
        timestamp: SystemTime,
    ) -> RusqliteParamsWithOwnedToSql {
        let now = to_time_t(timestamp);
        let to_time_t = |limit| now - checked_conversion::<u64, i64>(limit);
        vec![
            (":min_timestamp", Box::new(to_time_t(max_age))),
            (":max_timestamp", Box::new(to_time_t(min_age))),
        ]
    }

    fn set_up_wei_constrains(two_num_limits: Vec<N>) -> RusqliteParamsWithOwnedToSql
    where
        i128: From<N>,
    {
        [
            (":min_balance_high_b", ":min_balance_low_b"),
            (":max_balance_high_b", ":max_balance_low_b"),
        ]
        .into_iter()
        .zip(two_num_limits.into_iter())
        .flat_map(|(param_names, gwei_num)| {
            let wei_num = i128::from(gwei_num) * WEIS_OF_GWEI;
            let (high_bytes, low_bytes) = BigIntDivider::deconstruct(wei_num);
            vec![
                (param_names.0, Box::new(high_bytes) as Box<dyn ToSql>),
                (param_names.1, Box::new(low_bytes)),
            ]
        })
        .collect()
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
                if gwei > 0 { gwei } else { panic!("Broken code: PayableAccount with less than 1 Gwei passed through db query constrains; wallet: {}, balance: {}", account.wallet, account.balance_wei) }
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
                if gwei != 0 {gwei} else {panic!("Broken code: ReceivableAccount with balance between {} and 0 Gwei passed through db query constrains; wallet: {}, balance: {}",
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::connection_wrapper::ConnectionWrapperReal;
    use crate::test_utils::make_wallet;
    use masq_lib::messages::TopRecordsOrdering::Balance;
    use masq_lib::test_utils::utils::ensure_node_home_directory_exists;
    use rusqlite::types::{ToSqlOutput, Value};
    use rusqlite::{Connection, OpenFlags};
    use std::str::FromStr;

    #[test]
    #[should_panic(expected = "Failed to connect to database at \"nonexistent")]
    fn connection_panics_if_connection_cannot_be_made() {
        let subject = DaoFactoryReal::new(
            &PathBuf::from_str("nonexistent").unwrap(),
            false,
            DbInitializationConfig::test_default(),
        );

        let _ = subject.make_connection();
    }

    #[test]
    fn set_up_age_constrains_works() {
        let min_age = 5555;
        let max_age = 10000;
        let now = SystemTime::now();

        let result = CustomQuery::<i64>::set_up_age_constrains(min_age, max_age, now);

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
                age_param: "",
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
        expected = "Broken code: PayableAccount with less than 1 Gwei passed through db query constrains; \
         wallet: 0x0000000000000000000000000061633336363563, balance: 565122333"
    )]
    fn remap_payable_accounts_getting_record_below_one_gwei_means_broken_database_query() {
        let accounts = vec![
            PayableAccount {
                wallet: make_wallet("abc123"),
                balance_wei: 4_888_123_457,
                last_paid_timestamp: SystemTime::now(), //unimportant
                pending_payable_opt: None,
            },
            PayableAccount {
                wallet: make_wallet("ac3665c"),
                balance_wei: 565_122_333,
                last_paid_timestamp: SystemTime::now(), //unimportant
                pending_payable_opt: None,
            },
        ];
        remap_payable_accounts(accounts);
    }

    #[test]
    #[should_panic(
        expected = "Broken code: ReceivableAccount with balance between 1 and 0 Gwei passed through db query \
         constrains; wallet: 0x0000000000000000000000000061633336363563, balance: 300122333"
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
        expected = "Broken code: ReceivableAccount with balance between -1 and 0 Gwei passed through db query \
         constrains; wallet: 0x0000000000000000000000000061633336363563, balance: -290122333"
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
}
