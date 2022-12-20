// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use node_lib::test_utils::payable_dao_performance_utils::shared_test_environment::specialized_body_for_zig_zag_test;

#[test]
fn progressive_efficiency_of_mark_pending_payable_rowids_integration() {
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

    let times_of_single_and_separate_calls = (1_usize..=7)
        .step_by(2)
        .into_iter()
        .map(perform_with_counts_of_updates)
        .collect::<Vec<(u64, u64)>>();

    let (standard_deviation_single, standard_deviation_separate) = {
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
        let standard_deviation = |sum_of_quadratic_differences| {
            ((sum_of_quadratic_differences / times_of_single_and_separate_calls.len() as u64)
                as f64)
                .sqrt()
        };
        (
            standard_deviation(sum_quadratic_diff_single),
            standard_deviation(sum_quadratic_diff_separate),
        )
    };
    eprintln!("times {:?}", times_of_single_and_separate_calls);
    eprintln!("single sd  = {}", standard_deviation_single);
    eprintln!("separate sd = {}", standard_deviation_separate);
    assert!(
        standard_deviation_single < 200.0,
        "sd for single call was {}",
        standard_deviation_single
    );
    assert!(
        standard_deviation_single * 100.0 < standard_deviation_separate,
        "sd of the single call {}, sd of the separate calls {}, multiplied {}",
        standard_deviation_single,
        standard_deviation_separate,
        standard_deviation_single * 100.0
    );
    let first_for_single = times_of_single_and_separate_calls[0].0;
    let first_for_separate = times_of_single_and_separate_calls[0].1;
    assert!(
        (first_for_separate <= (first_for_single) * 13 / 10)
            && (((first_for_single) * 7) / 10 <= first_for_separate)
    );
    times_of_single_and_separate_calls
        .iter()
        .skip(1)
        .enumerate()
        .for_each(
            |(attempt_number, (single_attempt_time_needed, separate_attempt_time_needed))| {
                let lap_coefficient = {
                    let base = (attempt_number as u64 + 2) * 10;
                    base - ((2 * base) / 10)
                };
                assert!(
                    (*single_attempt_time_needed * lap_coefficient) / 10 < *separate_attempt_time_needed,
                    "the expected difference given by coefficient {} / 10 wasn't met; time for single \
                     {} and time for separate {}",
                    lap_coefficient,
                    single_attempt_time_needed,
                    separate_attempt_time_needed
                )
            },
        );

    //TODO remove this
    //
    // in Actions...
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
}
