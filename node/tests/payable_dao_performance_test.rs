// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use masq_lib::test_utils::utils::is_running_under_github_actions;
use node_lib::test_utils::payable_dao_performance_utils::shared_test_environment::specialized_body_for_zig_zag_test;
use std::cmp;

#[test]
fn progressive_efficiency_of_mark_pending_payable_rowids_integration() {
    //from more than one update done at a time, not even does the performance of this solution hinder us,
    //it is significantly beneficial with each additional updated record
    fn perform_with_counts_of_updates(ending_range_num: usize) -> (u64, u64) {
        let tested_range_of_cumulative_updates = 1..=ending_range_num;
        let (single_call_attempt_duration, separate_calls_attempt_duration) =
            specialized_body_for_zig_zag_test(
                "performance_test_for_mark_pending_payable_rowids_with_low_counts",
                tested_range_of_cumulative_updates,
            );
        (
            single_call_attempt_duration.as_micros() as u64,
            separate_calls_attempt_duration.as_micros() as u64,
        )
    }

    let times_of_single_and_separate_calls = (1_usize..7)
        .step_by(2)
        .into_iter()
        .map(perform_with_counts_of_updates)
        .collect::<Vec<(u64, u64)>>();

    let (single_call_sum_of_time, separate_calls_sum_of_time) =
        times_of_single_and_separate_calls.iter().fold(
            (0_u64, 0_u64),
            |(sum_single, sum_separate), (time_from_single_call, time_from_separate_calls)| {
                (
                    sum_single + *time_from_single_call,
                    sum_separate + *time_from_separate_calls,
                )
            },
        );
    let single_call_average_time =
        single_call_sum_of_time / times_of_single_and_separate_calls.len() as u64;
    let separate_calls_average_time =
        separate_calls_sum_of_time / times_of_single_and_separate_calls.len() as u64;
    let (sum_quadratic_diff_single, sum_quadratic_diff_separate) =
        times_of_single_and_separate_calls.iter().fold(
            (0_u64, 0_u64),
            |(sum_quadratic_diff_single, sum_quadratic_diff_separate),
             (time_from_single_call, time_from_separate_calls)| {
                fn add_quadratic_difference(acc_sum: u64, time_current: u64, mean: u64) -> u64 {
                    acc_sum + (time_current as i64 - mean as i64).pow(2) as u64
                }
                (
                    add_quadratic_difference(
                        sum_quadratic_diff_single,
                        *time_from_single_call,
                        single_call_average_time,
                    ),
                    add_quadratic_difference(
                        sum_quadratic_diff_separate,
                        *time_from_separate_calls,
                        separate_calls_average_time,
                    ),
                )
            },
        );

    //TODO in Actions...
    // single call: 858
    // separate call: 1124   ...ration 0
    // and then
    // single call: 1791
    // separate call: 1139   ...ration 2
    // _____

    //MacOs
    //1.
    //single: 1617
    //separate: 1385
    //2.
    //single: 4980
    //separate: 8536

    //ubuntu
    //1.
    //single: 2110,
    //separate: 1754,
    //2.
    //single: 1665,
    //separate: 2802

    // Win
    // _____
    // single call: 31097
    // separate call: 76185

    let first_cpu_coefficient = if is_running_under_github_actions() {
        25
    } else {
        15
    };
    assert!(single_one < separate_one * first_cpu_coefficient / 10);
    let ratio_one = (single_one * 100) / separate_one;
    let ratio_two = (single_two * 100) / separate_two;
    eprintln!("ration 1: {}, ratio 2: {}", ratio_one, ratio_two);
    eprintln!(
        "github ratio 1: {}, ratio 2: {}",
        (858 * 100) / 1124,
        (1791 * 100) / 1139
    );
    assert!(ratio_one > ratio_two * 10 / 14)
    //these values in the assertions have got a safety margin; the performance is averagely much better
    //but there are spikes occasionally that would crash the test
}
