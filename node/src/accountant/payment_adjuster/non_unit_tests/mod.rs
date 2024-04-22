// Copyright (c) 2024, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::db_access_objects::payable_dao::PayableAccount;
use crate::accountant::db_access_objects::utils::{from_time_t, to_time_t};
use crate::accountant::payment_adjuster::miscellaneous::helper_functions::sum_as;
use crate::accountant::payment_adjuster::test_utils::PRESERVED_TEST_PAYMENT_THRESHOLDS;
use crate::accountant::payment_adjuster::{
    Adjustment, AdjustmentAnalysis, PaymentAdjuster, PaymentAdjusterError, PaymentAdjusterReal,
};
use crate::accountant::scanners::mid_scan_msg_handling::payable_scanner::test_utils::BlockchainAgentMock;
use crate::accountant::scanners::mid_scan_msg_handling::payable_scanner::PreparedAdjustment;
use crate::accountant::test_utils::try_making_guaranteed_qualified_payables;
use crate::accountant::AnalyzedPayableAccount;
use crate::sub_lib::blockchain_bridge::OutboundPaymentsInstructions;
use crate::sub_lib::wallet::Wallet;
use crate::test_utils::make_wallet;
use itertools::{Either, Itertools};
use masq_lib::test_utils::utils::ensure_node_home_directory_exists;
use masq_lib::utils::convert_collection;
use rand;
use rand::rngs::ThreadRng;
use rand::{thread_rng, Rng};
use std::fs::File;
use std::io::Write;
use std::time::SystemTime;
use thousands::Separable;
use web3::types::U256;

#[test]
#[ignore]
fn loading_test_with_randomized_params() {
    // This test needs to be understood as a generator of extensive amount of scenarios that
    // the PaymentAdjuster might come to be asked to resolve while there are quite many combinations
    // that a human has a hard time with to imagine, now we ought to think that some of them might
    // be corner cases that there wasn't awareness of when it was being designed. Therefore, the main
    // purpose of this test is to prove that out of a huge number of tries the PaymentAdjuster always
    // comes along fairly well, especially, that it cannot kill the Node by an accidental panic or
    // that it can live up to its original purpose and the vast majority of the attempted adjustments
    // end up with reasonable results. That said, a smaller amount of these attempts are expected
    // to be vain because of some chance always be there that with a given combination of payables
    // the algorithm will go step by step eliminating completely all accounts. There's hardly a way
    // for the adjustment procedure as it proceeds now to anticipate if this is going to happen.
    let now = SystemTime::now();
    let mut gn = thread_rng();
    let mut subject = PaymentAdjusterReal::new();
    let number_of_requested_scenarios = 500;
    let scenarios = generate_scenarios(&mut gn, now, number_of_requested_scenarios);
    let test_overall_output_collector = TestOverallOutputCollector::default();

    struct FirstStageOutput {
        test_overall_output_collector: TestOverallOutputCollector,
        allowed_scenarios: Vec<PreparedAdjustment>,
    }

    let init = FirstStageOutput {
        test_overall_output_collector,
        allowed_scenarios: vec![],
    };
    let first_stage_output = scenarios
        .into_iter()
        .fold(init, |mut output_collector, scenario| {
            // We watch only the service fee balance check, transaction fee can be added, but it
            // doesn't interact with the potential error 'AllAccountsEliminated' whose occurrence
            // rate is interesting compared to how many times the initial check lets the adjustment
            // procedure go on
            let qualified_payables = scenario
                .adjustment_analysis
                .accounts
                .iter()
                .map(|account| account.qualified_as.clone())
                .collect();
            let initial_check_result =
                subject.search_for_indispensable_adjustment(qualified_payables, &*scenario.agent);
            let allowed_scenario_opt = match initial_check_result {
                Ok(check_factual_output) => {
                    match check_factual_output {
                        Either::Left(_) => panic!(
                            "Wrong test setup. This test is designed to generate scenarios with \
                            balances always insufficient in some way!"
                        ),
                        Either::Right(_) => (),
                    };
                    Some(scenario)
                }
                Err(
                    PaymentAdjusterError::NotEnoughServiceFeeBalanceEvenForTheSmallestTransaction {
                        ..
                    },
                ) => {
                    output_collector
                        .test_overall_output_collector
                        .scenarios_denied_before_adjustment_started += 1;
                    None
                }
                _e => Some(scenario),
            };

            match allowed_scenario_opt {
                Some(scenario) => output_collector.allowed_scenarios.push(scenario),
                None => (),
            }

            output_collector
        });

    let second_stage_scenarios = first_stage_output.allowed_scenarios;
    let test_overall_output_collector = first_stage_output.test_overall_output_collector;
    let scenario_adjustment_results = second_stage_scenarios
        .into_iter()
        .map(|prepared_adjustment| {
            let account_infos =
                preserve_account_infos(&prepared_adjustment.adjustment_analysis.accounts, now);
            let required_adjustment = prepared_adjustment.adjustment_analysis.adjustment.clone();
            let cw_service_fee_balance_minor =
                prepared_adjustment.agent.service_fee_balance_minor();

            let payment_adjuster_result = subject.adjust_payments(prepared_adjustment, now);

            administrate_single_scenario_result(
                payment_adjuster_result,
                account_infos,
                required_adjustment,
                cw_service_fee_balance_minor,
            )
        })
        .collect();

    render_results_to_file_and_attempt_basic_assertions(
        scenario_adjustment_results,
        number_of_requested_scenarios,
        test_overall_output_collector,
    )
}

fn generate_scenarios(
    gn: &mut ThreadRng,
    now: SystemTime,
    number_of_scenarios: usize,
) -> Vec<PreparedAdjustment> {
    (0..number_of_scenarios)
        .flat_map(|_| try_making_single_valid_scenario(gn, now))
        .collect()
}

fn try_making_single_valid_scenario(
    gn: &mut ThreadRng,
    now: SystemTime,
) -> Option<PreparedAdjustment> {
    let (cw_service_fee_balance, payables) = make_payables(gn, now);
    let payables_len = payables.len();
    let qualified_payables = try_making_guaranteed_qualified_payables(
        payables,
        &PRESERVED_TEST_PAYMENT_THRESHOLDS,
        now,
        false,
    );
    if payables_len != qualified_payables.len() {
        return None;
    }
    let analyzed_accounts: Vec<AnalyzedPayableAccount> = convert_collection(qualified_payables);
    let agent = make_agent(cw_service_fee_balance);
    let adjustment = make_adjustment(gn, analyzed_accounts.len());
    Some(PreparedAdjustment::new(
        Box::new(agent),
        None,
        AdjustmentAnalysis::new(adjustment, analyzed_accounts),
    ))
}

fn make_payables(gn: &mut ThreadRng, now: SystemTime) -> (u128, Vec<PayableAccount>) {
    let accounts_count = generate_non_zero_usize(gn, 20) + 1;
    let accounts = (0..accounts_count)
        .map(|idx| {
            let wallet = make_wallet(&format!("wallet{}", idx));
            let debt_age = 2000 + generate_non_zero_usize(gn, 200000);
            let service_fee_balance_minor = {
                let mut generate_u128 = || -> u128 { gn.gen_range(1_000_000_000..2_000_000_000) };
                let parameter_a = generate_u128();
                let parameter_b = generate_u128();
                parameter_a * parameter_b
            };
            let last_paid_timestamp = from_time_t(to_time_t(now) - debt_age as i64);
            PayableAccount {
                wallet,
                balance_wei: service_fee_balance_minor,
                last_paid_timestamp,
                pending_payable_opt: None,
            }
        })
        .collect::<Vec<_>>();
    let balance_average = {
        let sum: u128 = sum_as(&accounts, |account| account.balance_wei);
        sum / accounts_count as u128
    };
    let cw_service_fee_balance_minor = {
        let max_pieces = accounts_count * 6;
        let number_of_pieces = generate_usize(gn, max_pieces - 2) as u128 + 2;
        balance_average / 6 * number_of_pieces
    };
    (cw_service_fee_balance_minor, accounts)
}

fn make_agent(cw_service_fee_balance: u128) -> BlockchainAgentMock {
    BlockchainAgentMock::default()
        // We don't care about this check in this test
        .transaction_fee_balance_minor_result(U256::from(u128::MAX))
        // ...as well as we don't here
        .estimated_transaction_fee_per_transaction_minor_result(1)
        // Used in the entry check
        .service_fee_balance_minor_result(cw_service_fee_balance)
        // For evaluation preparations in the test
        .service_fee_balance_minor_result(cw_service_fee_balance)
        // For PaymentAdjuster itself
        .service_fee_balance_minor_result(cw_service_fee_balance)
}

fn make_adjustment(gn: &mut ThreadRng, accounts_count: usize) -> Adjustment {
    let also_by_transaction_fee = generate_boolean(gn);
    if also_by_transaction_fee && accounts_count > 2 {
        let affordable_transaction_count =
            u16::try_from(generate_non_zero_usize(gn, accounts_count)).unwrap();
        Adjustment::TransactionFeeInPriority {
            affordable_transaction_count,
        }
    } else {
        Adjustment::ByServiceFee
    }
}

fn administrate_single_scenario_result(
    payment_adjuster_result: Result<OutboundPaymentsInstructions, PaymentAdjusterError>,
    account_infos: Vec<AccountInfo>,
    required_adjustment: Adjustment,
    cw_service_fee_balance_minor: u128,
) -> ScenarioResult {
    let common = CommonScenarioInfo {
        cw_service_fee_balance_minor,
        required_adjustment,
    };
    let reinterpreted_result = match payment_adjuster_result {
        Ok(outbound_payment_instructions) => {
            let mut adjusted_accounts = outbound_payment_instructions.affordable_accounts;
            let portion_of_cw_cumulatively_used_percents = {
                let used_absolute: u128 = sum_as(&adjusted_accounts, |account| account.balance_wei);
                ((100 * used_absolute) / common.cw_service_fee_balance_minor) as u8
            };
            let adjusted_accounts =
                interpretable_account_resolutions(account_infos, &mut adjusted_accounts);
            let (partially_sorted_interpretable_adjustments, were_no_accounts_eliminated) =
                sort_interpretable_adjustments(adjusted_accounts);
            Ok(SuccessfulAdjustment {
                common,
                portion_of_cw_cumulatively_used_percents,
                partially_sorted_interpretable_adjustments,
                were_no_accounts_eliminated,
            })
        }
        Err(adjuster_error) => Err(FailedAdjustment {
            common,
            account_infos,
            adjuster_error,
        }),
    };

    ScenarioResult::new(reinterpreted_result)
}

fn interpretable_account_resolutions(
    account_infos: Vec<AccountInfo>,
    adjusted_accounts: &mut Vec<PayableAccount>,
) -> Vec<InterpretableAdjustmentResult> {
    account_infos
        .into_iter()
        .map(|account_info| {
            prepare_interpretable_account_resolution(account_info, adjusted_accounts)
        })
        .collect()
}

struct ScenarioResult {
    result: Result<SuccessfulAdjustment, FailedAdjustment>,
}

impl ScenarioResult {
    fn new(result: Result<SuccessfulAdjustment, FailedAdjustment>) -> Self {
        Self { result }
    }
}

struct SuccessfulAdjustment {
    common: CommonScenarioInfo,
    portion_of_cw_cumulatively_used_percents: u8,
    partially_sorted_interpretable_adjustments: Vec<InterpretableAdjustmentResult>,
    were_no_accounts_eliminated: bool,
}

struct FailedAdjustment {
    common: CommonScenarioInfo,
    account_infos: Vec<AccountInfo>,
    adjuster_error: PaymentAdjusterError,
}

fn preserve_account_infos(
    accounts: &[AnalyzedPayableAccount],
    now: SystemTime,
) -> Vec<AccountInfo> {
    accounts
        .iter()
        .map(|account| AccountInfo {
            wallet: account.qualified_as.bare_account.wallet.clone(),
            initially_requested_service_fee_minor: account.qualified_as.bare_account.balance_wei,
            debt_age_s: now
                .duration_since(account.qualified_as.bare_account.last_paid_timestamp)
                .unwrap()
                .as_secs(),
        })
        .collect()
}

fn render_results_to_file_and_attempt_basic_assertions(
    scenario_results: Vec<ScenarioResult>,
    number_of_requested_scenarios: usize,
    overall_output_collector: TestOverallOutputCollector,
) {
    let file_dir = ensure_node_home_directory_exists("payment_adjuster", "tests");
    let mut file = File::create(file_dir.join("loading_test_output.txt")).unwrap();
    introduction(&mut file);
    let test_overall_output_collector =
        scenario_results
            .into_iter()
            .fold(overall_output_collector, |acc, scenario_result| {
                do_final_processing_of_single_scenario(&mut file, acc, scenario_result)
            });
    let total_scenarios_evaluated = test_overall_output_collector
        .scenarios_denied_before_adjustment_started
        + test_overall_output_collector.oks
        + test_overall_output_collector.all_accounts_eliminated
        + test_overall_output_collector.insufficient_service_fee_balance;
    write_brief_test_summary_into_file(
        &mut file,
        &test_overall_output_collector,
        number_of_requested_scenarios,
        total_scenarios_evaluated,
    );

    assert_eq!(
        total_scenarios_evaluated, number_of_requested_scenarios,
        "Evaluated scenarios count ({}) != requested scenarios count ({})",
        total_scenarios_evaluated, number_of_requested_scenarios
    );
    // The next assertions depend heavily on the setup for the scenario generator!!
    // It rather indicates how well the setting is so that you can adjust it eventually,
    // to see more relevant results
    let entry_check_pass_rate = 100
        - ((test_overall_output_collector.scenarios_denied_before_adjustment_started * 100)
            / total_scenarios_evaluated);
    let required_pass_rate = 80;
    assert!(
        entry_check_pass_rate >= required_pass_rate,
        "Not at least {}% from {} the scenarios \
    generated for this test allows PaymentAdjuster to continue doing its job and ends too early. \
    Instead only {}%. Setup of the test might be needed",
        required_pass_rate,
        total_scenarios_evaluated,
        entry_check_pass_rate
    );
    let ok_adjustment_percentage = (test_overall_output_collector.oks * 100)
        / (total_scenarios_evaluated
            - test_overall_output_collector.scenarios_denied_before_adjustment_started);
    let required_success_rate = 70;
    assert!(
        ok_adjustment_percentage >= required_success_rate,
        "Not at least {}% from {} adjustment procedures from PaymentAdjuster runs finished with success, only {}%",
        required_success_rate,
        total_scenarios_evaluated,
        ok_adjustment_percentage
    );
}

fn introduction(file: &mut File) {
    write_thick_dividing_line(file);
    write_thick_dividing_line(file);
    file.write(b"A short summary can be found at the tail\n")
        .unwrap();
    write_thick_dividing_line(file);
    write_thick_dividing_line(file)
}

fn write_brief_test_summary_into_file(
    file: &mut File,
    overall_output_collector: &TestOverallOutputCollector,
    number_of_requested_scenarios: usize,
    total_of_scenarios_evaluated: usize,
) {
    write_thick_dividing_line(file);
    file.write_fmt(format_args!(
        "\n\
         Scenarios\n\
         Requested:............................. {}\n\
         Actually evaluated:.................... {}\n\n\
         Successful:............................ {}\n\
         Successes with no accounts eliminated:. {}\n\n\
         Transaction fee / mixed adjustments:... {}\n\
         Bills fulfillment distribution:\n\
         {}\n\n\
         Plain service fee adjustments:......... {}\n\
         Bills fulfillment distribution:\n\
         {}\n\n\
         Unsuccessful\n\
         Caught by the entry check:............. {}\n\
         With 'AllAccountsEliminated':.......... {}\n\
         With late insufficient balance errors:. {}",
        number_of_requested_scenarios,
        total_of_scenarios_evaluated,
        overall_output_collector.oks,
        overall_output_collector.with_no_accounts_eliminated,
        overall_output_collector
            .fulfillment_distribution_for_transaction_fee_adjustments
            .total_scenarios(),
        overall_output_collector
            .fulfillment_distribution_for_transaction_fee_adjustments
            .render_in_two_lines(),
        overall_output_collector
            .fulfillment_distribution_for_service_fee_adjustments
            .total_scenarios(),
        overall_output_collector
            .fulfillment_distribution_for_service_fee_adjustments
            .render_in_two_lines(),
        overall_output_collector.scenarios_denied_before_adjustment_started,
        overall_output_collector.all_accounts_eliminated,
        overall_output_collector.insufficient_service_fee_balance
    ))
    .unwrap()
}

fn do_final_processing_of_single_scenario(
    file: &mut File,
    mut test_overall_output: TestOverallOutputCollector,
    scenario: ScenarioResult,
) -> TestOverallOutputCollector {
    match scenario.result {
        Ok(positive) => {
            if positive.were_no_accounts_eliminated {
                test_overall_output.with_no_accounts_eliminated += 1
            }
            if matches!(
                positive.common.required_adjustment,
                Adjustment::TransactionFeeInPriority { .. }
            ) {
                test_overall_output
                    .fulfillment_distribution_for_transaction_fee_adjustments
                    .collected_fulfillment_percentages
                    .push(positive.portion_of_cw_cumulatively_used_percents)
            }
            if positive.common.required_adjustment == Adjustment::ByServiceFee {
                test_overall_output
                    .fulfillment_distribution_for_service_fee_adjustments
                    .collected_fulfillment_percentages
                    .push(positive.portion_of_cw_cumulatively_used_percents)
            }
            render_positive_scenario(file, positive);
            test_overall_output.oks += 1;
            test_overall_output
        }
        Err(negative) => {
            match negative.adjuster_error {
                PaymentAdjusterError::NotEnoughTransactionFeeBalanceForSingleTx { .. } => {
                    panic!("impossible in this kind of test without the tx fee initial check")
                }
                PaymentAdjusterError::NotEnoughServiceFeeBalanceEvenForTheSmallestTransaction {
                    ..
                } => test_overall_output.insufficient_service_fee_balance += 1,
                PaymentAdjusterError::AllAccountsEliminated => {
                    test_overall_output.all_accounts_eliminated += 1
                }
            }
            render_negative_scenario(file, negative);
            test_overall_output
        }
    }
}

fn render_scenario_header(
    file: &mut File,
    cw_service_fee_balance_minor: u128,
    portion_of_cw_used_percents: u8,
    required_adjustment: Adjustment,
) {
    file.write_fmt(format_args!(
        "CW service fee balance: {} wei\n\
         Portion of CW balance used: {}%\n\
         Maximal txt count due to CW txt fee balance: {}\n",
        cw_service_fee_balance_minor.separate_with_commas(),
        portion_of_cw_used_percents,
        resolve_affordable_transaction_count(required_adjustment)
    ))
    .unwrap();
}
fn render_positive_scenario(file: &mut File, result: SuccessfulAdjustment) {
    write_thick_dividing_line(file);
    render_scenario_header(
        file,
        result.common.cw_service_fee_balance_minor,
        result.portion_of_cw_cumulatively_used_percents,
        result.common.required_adjustment,
    );
    write_thin_dividing_line(file);
    let adjusted_accounts = result.partially_sorted_interpretable_adjustments;
    adjusted_accounts.into_iter().for_each(|account| {
        single_account_output(
            file,
            account.initial_balance,
            account.debt_age_s,
            account.bills_coverage_in_percentage_opt,
        )
    })
}

const BALANCE_COLUMN_WIDTH: usize = 30;
const AGE_COLUMN_WIDTH: usize = 7;

fn single_account_output(
    file: &mut File,
    balance_minor: u128,
    age_s: u64,
    bill_coverage_in_percentage_opt: Option<u8>,
) {
    let _ = file
        .write_fmt(format_args!(
            "{:>balance_width$} wei | {:>age_width$} s | {}\n",
            balance_minor.separate_with_commas(),
            age_s.separate_with_commas(),
            resolve_account_ending_status_graphically(bill_coverage_in_percentage_opt),
            balance_width = BALANCE_COLUMN_WIDTH,
            age_width = AGE_COLUMN_WIDTH
        ))
        .unwrap();
}

fn resolve_account_ending_status_graphically(
    bill_coverage_in_percentage_opt: Option<u8>,
) -> String {
    match bill_coverage_in_percentage_opt {
        Some(percentage) => format!("{} %", percentage),
        None => "X".to_string(),
    }
}

fn render_negative_scenario(file: &mut File, negative_result: FailedAdjustment) {
    write_thick_dividing_line(file);
    render_scenario_header(
        file,
        negative_result.common.cw_service_fee_balance_minor,
        0,
        negative_result.common.required_adjustment,
    );
    write_thin_dividing_line(file);
    negative_result.account_infos.iter().for_each(|account| {
        single_account_output(
            file,
            account.initially_requested_service_fee_minor,
            account.debt_age_s,
            None,
        )
    });
    write_thin_dividing_line(file);
    write_error(file, negative_result.adjuster_error)
}

fn write_error(file: &mut File, error: PaymentAdjusterError) {
    file.write_fmt(format_args!(
        "Scenario resulted in a failure: {:?}\n",
        error
    ))
    .unwrap()
}

fn resolve_affordable_transaction_count(adjustment: Adjustment) -> String {
    match adjustment {
        Adjustment::ByServiceFee => "Unlimited".to_string(),
        Adjustment::TransactionFeeInPriority {
            affordable_transaction_count,
        } => affordable_transaction_count.to_string(),
    }
}

fn write_thick_dividing_line(file: &mut File) {
    write_ln_made_of(file, '=')
}

fn write_thin_dividing_line(file: &mut File) {
    write_ln_made_of(file, '_')
}

fn write_ln_made_of(file: &mut File, char: char) {
    let _ = file
        .write_fmt(format_args!("{}\n", char.to_string().repeat(100)))
        .unwrap();
}

fn prepare_interpretable_account_resolution(
    account_info: AccountInfo,
    resulted_affordable_accounts: &mut Vec<PayableAccount>,
) -> InterpretableAdjustmentResult {
    let adjusted_account_idx_opt = resulted_affordable_accounts
        .iter()
        .position(|account| account.wallet == account_info.wallet);
    let bills_coverage_in_percentage_opt = match adjusted_account_idx_opt {
        Some(idx) => {
            let adjusted_account = resulted_affordable_accounts.remove(idx);
            let bill_coverage_in_percentage = u8::try_from(
                (adjusted_account.balance_wei * 100)
                    / account_info.initially_requested_service_fee_minor,
            )
            .unwrap();
            Some(bill_coverage_in_percentage)
        }
        None => None,
    };
    InterpretableAdjustmentResult {
        initial_balance: account_info.initially_requested_service_fee_minor,
        debt_age_s: account_info.debt_age_s,
        bills_coverage_in_percentage_opt,
    }
}

fn sort_interpretable_adjustments(
    interpretable_adjustments: Vec<InterpretableAdjustmentResult>,
) -> (Vec<InterpretableAdjustmentResult>, bool) {
    let (finished, eliminated): (
        Vec<InterpretableAdjustmentResult>,
        Vec<InterpretableAdjustmentResult>,
    ) = interpretable_adjustments
        .into_iter()
        .partition(|adjustment| adjustment.bills_coverage_in_percentage_opt.is_some());
    let were_no_accounts_eliminated = eliminated.is_empty();
    let finished_sorted = finished.into_iter().sorted_by(|result_a, result_b| {
        Ord::cmp(
            &result_b.bills_coverage_in_percentage_opt.unwrap(),
            &result_a.bills_coverage_in_percentage_opt.unwrap(),
        )
    });
    let eliminated_sorted = eliminated.into_iter().sorted_by(|result_a, result_b| {
        Ord::cmp(&result_b.initial_balance, &result_a.initial_balance)
    });
    let all_results = finished_sorted.chain(eliminated_sorted).collect();
    (all_results, were_no_accounts_eliminated)
}

fn generate_usize_guts(gn: &mut ThreadRng, low: usize, up_to: usize) -> usize {
    gn.gen_range(low..up_to)
}

fn generate_non_zero_usize(gn: &mut ThreadRng, up_to: usize) -> usize {
    generate_usize_guts(gn, 1, up_to)
}

fn generate_usize(gn: &mut ThreadRng, up_to: usize) -> usize {
    generate_usize_guts(gn, 0, up_to)
}

fn generate_boolean(gn: &mut ThreadRng) -> bool {
    gn.gen()
}

#[derive(Default)]
struct TestOverallOutputCollector {
    // First stage: entry check
    // ____________________________________
    scenarios_denied_before_adjustment_started: usize,
    // Second stage: proper adjustments
    // ____________________________________
    oks: usize,
    with_no_accounts_eliminated: usize,
    fulfillment_distribution_for_transaction_fee_adjustments: PercentageFulfillmentDistribution,
    fulfillment_distribution_for_service_fee_adjustments: PercentageFulfillmentDistribution,
    // Errors
    all_accounts_eliminated: usize,
    insufficient_service_fee_balance: usize,
}

#[derive(Default)]
struct PercentageFulfillmentDistribution {
    collected_fulfillment_percentages: Vec<u8>,
}

impl PercentageFulfillmentDistribution {
    fn render_in_two_lines(&self) -> String {
        #[derive(Default)]
        struct Ranges {
            from_0_to_10: usize,
            from_10_to_20: usize,
            from_20_to_30: usize,
            from_30_to_40: usize,
            from_40_to_50: usize,
            from_50_to_60: usize,
            from_60_to_70: usize,
            from_70_to_80: usize,
            from_80_to_90: usize,
            from_90_to_100: usize,
        }

        let full_count = self.collected_fulfillment_percentages.len();
        let ranges_populated = self.collected_fulfillment_percentages.iter().fold(
            Ranges::default(),
            |mut ranges, current| {
                match current {
                    0..=9 => ranges.from_0_to_10 += 1,
                    10..=19 => ranges.from_10_to_20 += 1,
                    20..=29 => ranges.from_20_to_30 += 1,
                    30..=39 => ranges.from_30_to_40 += 1,
                    40..=49 => ranges.from_40_to_50 += 1,
                    50..=59 => ranges.from_50_to_60 += 1,
                    60..=69 => ranges.from_60_to_70 += 1,
                    70..=79 => ranges.from_70_to_80 += 1,
                    80..=89 => ranges.from_80_to_90 += 1,
                    90..=100 => ranges.from_90_to_100 += 1,
                    _ => panic!("Shouldn't happen"),
                }
                ranges
            },
        );
        let digits = 6.max(full_count.to_string().len());
        format!(
            "Percentage ranges\n\
        {:^digits$}|{:^digits$}|{:^digits$}|{:^digits$}|{:^digits$}|\
        {:^digits$}|{:^digits$}|{:^digits$}|{:^digits$}|{:^digits$}\n\
        {:^digits$}|{:^digits$}|{:^digits$}|{:^digits$}|{:^digits$}|\
        {:^digits$}|{:^digits$}|{:^digits$}|{:^digits$}|{:^digits$}",
            "0-9",
            "10-19",
            "20-29",
            "30-39",
            "40-49",
            "50-59",
            "60-69",
            "70-79",
            "80-89",
            "90-100",
            ranges_populated.from_0_to_10,
            ranges_populated.from_10_to_20,
            ranges_populated.from_20_to_30,
            ranges_populated.from_30_to_40,
            ranges_populated.from_40_to_50,
            ranges_populated.from_50_to_60,
            ranges_populated.from_60_to_70,
            ranges_populated.from_70_to_80,
            ranges_populated.from_80_to_90,
            ranges_populated.from_90_to_100
        )
    }

    fn total_scenarios(&self) -> usize {
        self.collected_fulfillment_percentages.len()
    }
}

struct CommonScenarioInfo {
    cw_service_fee_balance_minor: u128,
    required_adjustment: Adjustment,
}

struct InterpretableAdjustmentResult {
    initial_balance: u128,
    debt_age_s: u64,
    // Account was eliminated from payment if None
    bills_coverage_in_percentage_opt: Option<u8>,
}

struct AccountInfo {
    wallet: Wallet,
    initially_requested_service_fee_minor: u128,
    debt_age_s: u64,
}
