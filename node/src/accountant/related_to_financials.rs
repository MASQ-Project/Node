// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::dao_utils::CustomQuery;
use crate::accountant::Accountant;
use masq_lib::constants::VALUE_EXCEEDS_ALLOWED_LIMIT;
use masq_lib::ui_gateway::MessageBody;
use std::fmt::{Debug, Display};

//there are two fundamental components making the macros powerful:
//a) see the procedural paste! macro (an external library) allowing to assemble valid idents (e. g. field or function names) from
// both in-place-defined and with-args-supplied literals
//b) repetition $(expression),+ in between round brackets producing a tuple that is later deconstructed in order to get the computed values out of it.

#[macro_export]
macro_rules! process_individual_range_queries {
    ($self: expr, $financials_request: expr, $context_id: expr, $($table_name: literal),+) => {
        Ok(match $financials_request.custom_queries_opt.as_ref(){
            Some(specs) => {
                let (payable_opt, receivable_opt) =

                ($(paste! {
                    if let Some(query_specs) = specs.[<$table_name _opt>].as_ref() {
                        let query = CustomQuery::from(query_specs);
                        check_query_is_within_tech_limits(&query, $table_name, $context_id)?;
                        $self.[<request_ $table_name _accounts_by_specific_mode>](
                            query
                        )
                    } else {
                        None
                    }
                }),+);

                Some(
                    QueryResults {
                        payable_opt,
                        receivable_opt,
                    }
                )
            }
            None => None}
        )
    };
}

#[macro_export]
macro_rules! process_top_records_query {
    ($self: expr, $financials_request: expr, $($table_name: literal),+) => {
        $financials_request.top_records_opt.map(|config|{
            let (payable, receivable) =

            ($(paste! {
                $self.[<request_ $table_name _accounts_by_specific_mode>](config.into())
               .unwrap_or_default()
            }),+);

            QueryResults{
                payable_opt: Some(payable),
                receivable_opt: Some(receivable)
            }
        })
    };
}

fn fits_in_0_to_i64max_for_u64<T>(num: &T) -> bool
where
    T: Ord + Copy + TryFrom<u64>,
    u64: TryFrom<T>,
    <T as TryFrom<u64>>::Error: Debug,
{
    match u64::try_from(*num) {
        Ok(u64_num) => u64_num <= i64::MAX as u64,
        Err(_) => {
            let zero_as_t: T = 0_u64.try_into().expect("should be fine");
            if num < &zero_as_t {
                true
            } else {
                unreachable!("only u64 and i64 values are expected")
            }
        }
    }
}

pub fn check_query_is_within_tech_limits<T>(
    query: &CustomQuery<T>,
    table: &str,
    context_id: u64,
) -> Result<(), MessageBody>
where
    T: Ord + Copy + Display + TryFrom<u64>,
    u64: TryFrom<T>,
    <u64 as TryFrom<T>>::Error: Debug,
    <T as TryFrom<u64>>::Error: Debug,
{
    let err = |param_name, num: &dyn Display| {
        Err(Accountant::financials_bad_news(
            VALUE_EXCEEDS_ALLOWED_LIMIT,
            &format!(
                "Range query for {}: {} requested too big. Should be less than or equal to {}, not: {}",
                table,
                param_name,
                i64::MAX,
                num
            ),
            context_id,
        ))
    };
    if let CustomQuery::RangeQuery {
        min_age_s,
        max_age_s,
        min_amount_gwei,
        max_amount_gwei,
        ..
    } = query
    {
        match (
            min_age_s <= &(i64::MAX as u64),
            max_age_s <= &(i64::MAX as u64),
            fits_in_0_to_i64max_for_u64(min_amount_gwei),
            fits_in_0_to_i64max_for_u64(max_amount_gwei),
        ) {
            (false, ..) => err("Min age", min_age_s),
            (_, false, ..) => err("Max age", max_age_s),
            (_, _, false, _) => err("Min amount", min_amount_gwei),
            (_, _, _, false) => err("Max amount", max_amount_gwei),
            _ => Ok(()),
        }
    } else {
        panic!("Broken code: only range query belongs in here")
    }
}

#[cfg(test)]
mod tests {
    use crate::accountant::dao_utils::CustomQuery;
    use crate::accountant::related_to_financials::{
        check_query_is_within_tech_limits, fits_in_0_to_i64max_for_u64,
    };
    use crate::accountant::Accountant;
    use masq_lib::constants::VALUE_EXCEEDS_ALLOWED_LIMIT;
    use masq_lib::messages::TopRecordsOrdering::Age;
    use std::fmt::{Debug, Display};
    use std::time::SystemTime;

    fn assert_excessive_values_in_check_query_is_within_tech_limits<T>(
        query: CustomQuery<T>,
        err_msg: &str,
    ) where
        T: Ord + Copy + Display + TryFrom<u64>,
        u64: TryFrom<T>,
        <u64 as TryFrom<T>>::Error: Debug,
        <T as TryFrom<u64>>::Error: Debug,
    {
        let result = check_query_is_within_tech_limits(&query, "payable", 1234);

        assert_eq!(
            result,
            Err(Accountant::financials_bad_news(
                VALUE_EXCEEDS_ALLOWED_LIMIT,
                err_msg,
                1234
            ))
        )
    }

    #[test]
    fn check_query_is_within_tech_limits_catches_error_at_age_min() {
        let query = CustomQuery::RangeQuery {
            min_age_s: i64::MAX as u64 + 1,
            max_age_s: 4000000,
            min_amount_gwei: 55,
            max_amount_gwei: 6666,
            timestamp: SystemTime::now(),
        };

        assert_excessive_values_in_check_query_is_within_tech_limits(
            query,
            "Range query for payable: Min age requested \
         too big. Should be less than or equal to 9223372036854775807, not: 9223372036854775808",
        )
    }

    #[test]
    fn check_query_is_within_tech_limits_catches_error_at_age_max() {
        let query = CustomQuery::RangeQuery {
            min_age_s: 32656,
            max_age_s: i64::MAX as u64 + 1,
            min_amount_gwei: 55,
            max_amount_gwei: 6666,
            timestamp: SystemTime::now(),
        };

        assert_excessive_values_in_check_query_is_within_tech_limits(
            query,
            "Range query for payable: Max age requested \
         too big. Should be less than or equal to 9223372036854775807, not: 9223372036854775808",
        )
    }

    #[test]
    fn check_query_is_within_tech_limits_catches_error_at_amount_min() {
        let query = CustomQuery::RangeQuery {
            min_age_s: 32656,
            max_age_s: 4545555,
            min_amount_gwei: i64::MAX as u64 + 1,
            max_amount_gwei: 6666,
            timestamp: SystemTime::now(),
        };

        assert_excessive_values_in_check_query_is_within_tech_limits(
            query,
            "Range query for payable: Min amount requested \
         too big. Should be less than or equal to 9223372036854775807, not: 9223372036854775808",
        )
    }

    #[test]
    fn check_query_is_within_tech_limits_catches_error_at_amount_max() {
        let query = CustomQuery::RangeQuery {
            min_age_s: 32656,
            max_age_s: 4545555,
            min_amount_gwei: 144,
            max_amount_gwei: i64::MAX as u64 + 1,
            timestamp: SystemTime::now(),
        };

        assert_excessive_values_in_check_query_is_within_tech_limits(
            query,
            "Range query for payable: Max amount requested \
         too big. Should be less than or equal to 9223372036854775807, not: 9223372036854775808",
        )
    }

    #[test]
    fn check_query_is_within_tech_limits_works_for_smaller_or_equal_values_than_max_limit() {
        [i64::MAX as u64, (i64::MAX - 1) as u64, 1]
            .into_iter()
            .for_each(|val| {
                let query = CustomQuery::RangeQuery {
                    min_age_s: val,
                    max_age_s: val,
                    min_amount_gwei: val,
                    max_amount_gwei: val,
                    timestamp: SystemTime::now(),
                };
                let result = check_query_is_within_tech_limits(&query, "payable", 1234);
                assert_eq!(result, Ok(()))
            })
    }

    #[test]
    fn check_query_is_within_tech_limits_works_for_negative_values() {
        let query = CustomQuery::RangeQuery {
            min_age_s: 32656,
            max_age_s: 4545555,
            min_amount_gwei: -500000,
            max_amount_gwei: -500,
            timestamp: SystemTime::now(),
        };

        let result = check_query_is_within_tech_limits(&query, "receivable", 789);

        assert_eq!(result, Ok(()))
    }

    #[test]
    #[should_panic(expected = "entered unreachable code: only u64 and i64 values are expected")]
    fn compare_amount_param_unreachable_condition() {
        let _ = fits_in_0_to_i64max_for_u64(&u128::MAX);
    }

    #[test]
    #[should_panic(expected = "Broken code: only range query belongs in here")]
    fn check_query_is_within_tech_limits_blows_up_on_unexpected_query_type() {
        let query = CustomQuery::<i64>::TopRecords {
            count: 123,
            ordered_by: Age,
        };

        let _ = check_query_is_within_tech_limits(&query, "payable", 1234);
    }
}
