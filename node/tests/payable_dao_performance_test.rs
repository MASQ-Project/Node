// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use linreg;
use node_lib::test_utils::payable_dao_performance_utils::shared_test_environment::specialized_body_for_zig_zag_test;

#[test]
fn progressive_efficiency_of_mark_pending_payable_rowids_integration() {
    fn perform_one_round_with_particular_count_of_updates(ending_range_num: usize) -> (u32, u32) {
        let this_attempt_range = 1..=ending_range_num;
        let (single_call_attempt_duration, separate_calls_attempt_duration) =
            specialized_body_for_zig_zag_test(
                &format!(
                    "progressive_efficiency_of_mark_pending_payable_rowids_integration_{}",
                    ending_range_num
                ),
                this_attempt_range,
            );
        (
            single_call_attempt_duration.as_micros() as u32,
            separate_calls_attempt_duration.as_micros() as u32,
        )
    }

    let range_definition = (1_usize..=7).step_by(2);
    let discrete_counts = range_definition
        .clone()
        .map(|count| count as u32)
        .collect::<Vec<u32>>();

    let (time_laps_of_single_calls, time_laps_of_separate_calls): (Vec<u32>, Vec<u32>) =
        range_definition
            .into_iter()
            .map(perform_one_round_with_particular_count_of_updates)
            .unzip();

    let lin_regression_for_single: (f64, _) =
        linreg::linear_regression(&discrete_counts, &time_laps_of_single_calls).unwrap();
    let (slope_for_single, _) = lin_regression_for_single;
    let lin_regression_for_separate: (f64, _) =
        linreg::linear_regression(&discrete_counts, &time_laps_of_separate_calls).unwrap();
    let (slope_for_separate, _) = lin_regression_for_separate;
    let debug_helper = || {
        format!(
            "single call time laps: {:?}, slope for single: {}, \
         separate calls time laps {:?}, slope for separate: {}",
            time_laps_of_single_calls,
            slope_for_single,
            time_laps_of_separate_calls,
            slope_for_separate
        )
    };
    assert!(
        slope_for_single * 80.0 < slope_for_separate,
        "{}",
        debug_helper()
    );
    let first_for_single = time_laps_of_single_calls[0];
    let first_for_separate = time_laps_of_separate_calls[0];
    assert!(
        (first_for_separate <= (first_for_single) * 8 / 5)
            && (((first_for_single) * 2) / 5 <= first_for_separate),
        "{}",
        debug_helper()
    );
    //Linux
    //times [(1309, 1010), (1631, 1799), (1986, 7660), (1561, 3803)]

    //MacOs
    //times [(1233, 944), (1008, 1980), (1000, 2904), (1062, 3787)]

    //Windows
    //times [(1803, 1617), (6853, 5272), (1906, 6876), (2683, 7531)]
}
