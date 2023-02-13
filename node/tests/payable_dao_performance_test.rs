// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use linreg;
use node_lib::test_utils::payable_dao_performance_utils::shared_test_environment::specialized_body_for_zig_zag_test;

#[test]
#[not(feature = occasional_tests)]
fn progressive_efficiency_of_mark_pending_payable_rowids_integration() {
    //this test is supposed to prove that our multirow update statement beats separate sql calls;
    //tested for 1, 2, 3, 4, 5 updates;
    //before each round a full database of records is created;
    //every second number in the ruling range means a single updated row;
    //the gaps between are simply untouched rows
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

    let range_definition = (1_usize..=9).step_by(2);
    let discrete_counts = range_definition
        .clone()
        .map(|count| count as u32)
        .collect::<Vec<u32>>();
    let (time_laps_of_single_calls, time_laps_of_separate_calls): (Vec<u32>, Vec<u32>) =
        range_definition
            .into_iter()
            .map(perform_one_round_with_particular_count_of_updates)
            .unzip();
    //excluding the first attempt with a single update that usually distorts the dataset by an accidental jump up
    let make_regression_array = |time_laps: &[u32]| -> Vec<(u32, u32)> {
        discrete_counts
            .iter()
            .zip(time_laps.iter())
            .skip(1)
            .map(|(a, b)| (*a, *b))
            .collect()
    };
    let regression_array_for_single = make_regression_array(&time_laps_of_single_calls);
    let regression_array_for_separate = make_regression_array(&time_laps_of_separate_calls);
    let lin_regression_for_single: (f64, _) =
        linreg::linear_regression_of(&regression_array_for_single).unwrap();
    let (slope_for_single, _) = lin_regression_for_single;
    let lin_regression_for_separate: (f64, _) =
        linreg::linear_regression_of(&regression_array_for_separate).unwrap();
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
    //All the coefficients are underestimated to enable this test also for slow Actions.
    //For example for the slope, a decent machine handles a multiple of 60.
    assert!(
        slope_for_single * 17.0 < slope_for_separate,
        "failing at slope check: {}",
        debug_helper()
    );
    let first_for_single = time_laps_of_single_calls[0];
    let first_for_separate = time_laps_of_separate_calls[0];
    assert!(
        first_for_single <= (first_for_separate * 5) / 2,
        "failing at first attempts comparison: {}",
        debug_helper()
    );
    let last_for_separate = *(time_laps_of_separate_calls.last().unwrap());
    //this coefficient is low / it can be 5 for a decent machine
    assert!(
        (first_for_separate * 22) / 10 <= last_for_separate,
        "failing at first and last comparison for separate calls: {}",
        debug_helper()
    );
}
