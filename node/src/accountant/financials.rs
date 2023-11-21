// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use std::fmt::Debug;

const OPCODE_FINANCIALS: &str = "financials";

fn fits_in_0_to_i64max_for_u64<N>(num: &N) -> bool
where
    N: Ord + Copy + TryFrom<u64>,
    u64: TryFrom<N>,
    <N as TryFrom<u64>>::Error: Debug,
{
    match u64::try_from(*num) {
        Ok(u64_num) => u64_num <= i64::MAX as u64,
        Err(_) => {
            let zero_as_t: N = 0_u64.try_into().expect("should be fine");
            if num < &zero_as_t {
                true
            } else {
                unreachable!("only u64 and i64 values are expected")
            }
        }
    }
}

pub(in crate::accountant) mod visibility_restricted_module {
    use crate::accountant::db_access_objects::utils::CustomQuery;
    use crate::accountant::financials::{fits_in_0_to_i64max_for_u64, OPCODE_FINANCIALS};
    use masq_lib::constants::{
        REQUEST_WITH_MUTUALLY_EXCLUSIVE_PARAMS, REQUEST_WITH_NO_VALUES, VALUE_EXCEEDS_ALLOWED_LIMIT,
    };
    use masq_lib::messages::UiFinancialsRequest;
    use masq_lib::ui_gateway::{MessageBody, MessagePath};
    use std::fmt::{Debug, Display};

    pub fn check_query_is_within_tech_limits<N>(
        query: &CustomQuery<N>,
        table: &str,
        context_id: u64,
    ) -> Result<(), MessageBody>
    where
        N: Ord + Copy + Display + TryFrom<u64>,
        u64: TryFrom<N>,
        <u64 as TryFrom<N>>::Error: Debug,
        <N as TryFrom<u64>>::Error: Debug,
    {
        let err = |param_name, num: &dyn Display| {
            Err(MessageBody {
                opcode: OPCODE_FINANCIALS.to_string(),
                path: MessagePath::Conversation(context_id),
                payload: Err((VALUE_EXCEEDS_ALLOWED_LIMIT, format!(
                    "Range query for {}: {} requested too big. Should be less than or equal to {}, not: {}",
                    table,
                    param_name,
                    i64::MAX,
                    num
                )))
            })
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

    pub fn financials_entry_check(
        msg: &UiFinancialsRequest,
        context_id: u64,
    ) -> Result<(), MessageBody> {
        if !msg.stats_required && msg.top_records_opt.is_none() && msg.custom_queries_opt.is_none()
        {
            Err(MessageBody {
                opcode: OPCODE_FINANCIALS.to_string(),
                path: MessagePath::Conversation(context_id),
                payload: Err((
                    REQUEST_WITH_NO_VALUES,
                    "Empty requests with missing queries not to be processed".to_string(),
                )),
            })
        } else if msg.top_records_opt.is_some() && msg.custom_queries_opt.is_some() {
            Err(MessageBody {
                opcode: OPCODE_FINANCIALS.to_string(),
                path: MessagePath::Conversation(context_id),
                payload: Err((REQUEST_WITH_MUTUALLY_EXCLUSIVE_PARAMS, "Requesting top records and the more customized subset of records is not allowed both at the same time".to_string())),
            })
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::visibility_restricted_module::check_query_is_within_tech_limits;
    use crate::accountant::db_access_objects::utils::CustomQuery;
    use crate::accountant::financials::fits_in_0_to_i64max_for_u64;
    use masq_lib::constants::VALUE_EXCEEDS_ALLOWED_LIMIT;
    use masq_lib::messages::TopRecordsOrdering::Age;
    use masq_lib::ui_gateway::{MessageBody, MessagePath};
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
            Err(MessageBody {
                opcode: "financials".to_string(),
                path: MessagePath::Conversation(1234),
                payload: Err((VALUE_EXCEEDS_ALLOWED_LIMIT, err_msg.to_string())),
            })
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
