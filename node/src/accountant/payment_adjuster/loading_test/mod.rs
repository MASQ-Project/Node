// Copyright (c) 2024, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

#![cfg(feature = "occasional_test")]

use crate::accountant::db_access_objects::payable_dao::PayableAccount;
use crate::accountant::db_access_objects::utils::{from_time_t, to_time_t};
use crate::accountant::payment_adjuster::miscellaneous::helper_functions::sum_as;
use crate::accountant::payment_adjuster::{
    Adjustment, PaymentAdjuster, PaymentAdjusterError, PaymentAdjusterReal,
};
use crate::accountant::scanners::mid_scan_msg_handling::payable_scanner::test_utils::BlockchainAgentMock;
use crate::accountant::scanners::mid_scan_msg_handling::payable_scanner::OrderedAdjustment;
use crate::sub_lib::blockchain_bridge::OutboundPaymentsInstructions;
use crate::sub_lib::wallet::Wallet;
use crate::test_utils::make_wallet;
use itertools::Itertools;
use masq_lib::test_utils::utils::ensure_node_home_directory_exists;
use rand;
use rand::rngs::ThreadRng;
use rand::{thread_rng, Rng};
use std::fs::File;
use std::io::Write;
use std::time::SystemTime;
use thousands::Separable;
use web3::types::U256;

#[test]
fn loading_test_with_randomized_params() {
    // This test needs to be understood as a generator of extensive amount of scenarios that
    // the PaymentAdjuster might come to be asked to resolve while there are quite many combinations
    // that a human has a hard time with to imagine, now we ought to think that some of them might
    // be corner cases that there wasn't awareness of when it was being designed. Therefore, the main
    // purpose of this test is to prove that out of a huge number of tries the PaymentAdjuster always
    // comes along fairly well, especially, that it cannot kill the Node by an accidental panic or
    // that it can live up to its original purpose and vast majority of the attempted adjustments
    // end up with reasonable results. That said, a smaller amount of these attempts are expected
    // to be vain because of some chance always be there that with a given combination of payables
    // the algorithm will go step by step eliminating completely all accounts. There's hardly
    // a way for the adjustment procedure as it proceeds now to anticipate if this is going to happen.
    let now = SystemTime::now();
    let mut gn = thread_rng();
    let mut subject = PaymentAdjusterReal::new();
    let number_of_requested_scenarios = 500;
    let scenarios = generate_scenarios(&mut gn, now, number_of_requested_scenarios);
    let test_overall_output_collector = TestOverallOutputCollector::default();

    struct FirstStageOutput {
        test_overall_output_collector: TestOverallOutputCollector,
        allowed_scenarios: Vec<OrderedAdjustment>,
    }

    let init = FirstStageOutput {
        test_overall_output_collector,
        allowed_scenarios: vec![],
    };
    let first_stage_output = scenarios
        .into_iter()
        .fold(init, |mut output_collector, scenario|{
            // We watch only the service fee balance check, transaction fee can be added but it doesn't
            // interact with the potential error 'AllAccountsEliminated' whose occurrence rate is interesting
            // compared to the number of cases the initial check let the adjustment procedure go on
            let initial_check_result = subject.search_for_indispensable_adjustment(&scenario.qualified_payables, &*scenario.agent);
            let allowed_scenario_opt = match initial_check_result{
                Ok(adjustment_opt) => {match adjustment_opt{
                    None => panic!("Wrong test setup. This test is designed to generate scenarios with balances always insufficient in some way!"),
                    Some(_) => ()
                };
                Some(scenario)}
                Err(PaymentAdjusterError::NotEnoughServiceFeeBalanceEvenForTheSmallestTransaction {..}) => {
                    output_collector.test_overall_output_collector.scenarios_eliminated_before_adjustment_started += 1;
                    None
                }
                _e => Some(scenario)
            };

            match allowed_scenario_opt{
                Some(scenario) => output_collector.allowed_scenarios.push(scenario),
                None => ()
            }

            output_collector
        });

    let second_stage_scenarios = first_stage_output.allowed_scenarios;
    let test_overall_output_collector = first_stage_output.test_overall_output_collector;
    let scenario_adjustment_results = second_stage_scenarios
        .into_iter()
        .map(|required_adjustment| {
            let account_infos =
                preserve_account_infos(&required_adjustment.qualified_payables, now);
            let required_adjustment = required_adjustment.adjustment.clone();
            let cw_service_fee_balance_minor =
                required_adjustment.agent.service_fee_balance_minor();

            let payment_adjuster_result = subject.adjust_payments(required_adjustment, now);

            prepare_single_scenario_result(
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
) -> Vec<OrderedAdjustment> {
    (0..number_of_scenarios)
        .map(|_| make_single_scenario(gn, now))
        .collect()
}

fn make_single_scenario(gn: &mut ThreadRng, now: SystemTime) -> OrderedAdjustment {
    let (cw_service_fee_balance, qualified_payables) = make_qualified_payables(gn, now);
    let agent = make_agent(cw_service_fee_balance);
    let adjustment = make_adjustment(gn, qualified_payables.len());
    OrderedAdjustment::new(qualified_payables, Box::new(agent), None, adjustment)
}

fn make_qualified_payables(gn: &mut ThreadRng, now: SystemTime) -> (u128, Vec<PayableAccount>) {
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
    let cw_service_fee_balance_minor =
        balance_average * (generate_usize(gn, accounts_count - 1) as u128 + 1);
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

fn prepare_single_scenario_result(
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
            let adjusted_accounts = account_infos
                .into_iter()
                .map(|account_info| {
                    prepare_interpretable_account_resolution(account_info, &mut adjusted_accounts)
                })
                .collect();
            let sorted_interpretable_adjustments =
                sort_interpretable_adjustments(adjusted_accounts);
            Ok(SuccessfulAdjustment {
                common,
                partially_sorted_interpretable_adjustments: sorted_interpretable_adjustments,
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
    partially_sorted_interpretable_adjustments: Vec<InterpretableAdjustmentResult>,
}

struct FailedAdjustment {
    common: CommonScenarioInfo,
    account_infos: Vec<AccountInfo>,
    adjuster_error: PaymentAdjusterError,
}

fn preserve_account_infos(accounts: &[PayableAccount], now: SystemTime) -> Vec<AccountInfo> {
    accounts
        .iter()
        .map(|account| AccountInfo {
            wallet: account.wallet.clone(),
            initially_requested_service_fee_minor: account.balance_wei,
            debt_age_s: now
                .duration_since(account.last_paid_timestamp)
                .unwrap()
                .as_secs(),
        })
        .collect()
}

fn render_results_to_file_and_attempt_basic_assertions(
    scenario_results: Vec<ScenarioResult>,
    number_of_requested_scenarios: usize,
    test_overall_output_collector: TestOverallOutputCollector,
) {
    let file_dir = ensure_node_home_directory_exists("payment_adjuster", "loading_test");
    let mut file = File::create(file_dir.join("loading_test_output.txt")).unwrap();
    introduction(&mut file);
    let test_overall_output_collector = scenario_results
        .into_iter()
        .fold(test_overall_output_collector, |acc, scenario_result| {
            process_single_scenario(&mut file, acc, scenario_result)
        });
    let total_scenarios_evaluated = test_overall_output_collector
        .scenarios_eliminated_before_adjustment_started
        + test_overall_output_collector.oks
        + test_overall_output_collector.all_accounts_eliminated
        + test_overall_output_collector.insufficient_service_fee_balance;
    write_in_test_overall_output_to_file(
        &mut file,
        &test_overall_output_collector,
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
        - ((test_overall_output_collector.scenarios_eliminated_before_adjustment_started * 100)
            / total_scenarios_evaluated);
    let required_pass_rate = 80;
    assert!(entry_check_pass_rate >= required_pass_rate, "Not at least {}% from {} the scenarios generated for this test allows PaymentAdjuster to continue doing its job and ends too early. Instead only {}%. Setup of the test might be needed",required_pass_rate, total_scenarios_evaluated, entry_check_pass_rate);
    let ok_adjustment_percentage = (test_overall_output_collector.oks * 100)
        / (total_scenarios_evaluated
            - test_overall_output_collector.scenarios_eliminated_before_adjustment_started);
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
    file.write(b"For a brief overview of this formatted test output look at the end\n")
        .unwrap();
    write_thick_dividing_line(file);
    write_thick_dividing_line(file)
}

fn write_in_test_overall_output_to_file(
    file: &mut File,
    test_overall_output_collector: &TestOverallOutputCollector,
    total_of_scenarios_eliminated: usize,
) {
    write_thick_dividing_line(file);
    file.write_fmt(format_args!(
        "Total scenarios generated: {}\n\
         Scenarios caught by the entry check: {}\n\
         Ok scenarios: {}\n\
         Scenarios with 'AllAccountsEliminated': {}\n\
         Scenarios with late insufficient balance errors: {}",
        total_of_scenarios_eliminated,
        test_overall_output_collector.scenarios_eliminated_before_adjustment_started,
        test_overall_output_collector.oks,
        test_overall_output_collector.all_accounts_eliminated,
        test_overall_output_collector.insufficient_service_fee_balance
    ))
    .unwrap()
}

fn process_single_scenario(
    file: &mut File,
    mut test_overall_output: TestOverallOutputCollector,
    scenario: ScenarioResult,
) -> TestOverallOutputCollector {
    match scenario.result {
        Ok(positive) => {
            render_positive_scenario(file, positive);
            test_overall_output.oks += 1;
            test_overall_output
        }
        Err(negative) => {
            match negative.adjuster_error {
                PaymentAdjusterError::NotEnoughTransactionFeeBalanceForSingleTx { .. } => {
                    panic!("impossible in this kind of test without the initial check")
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
    required_adjustment: Adjustment,
) {
    file.write_fmt(format_args!(
        "CW service fee balance: {} wei\n\
         Maximal txt count due to CW txt fee balance: {}\n",
        cw_service_fee_balance_minor.separate_with_commas(),
        resolve_affordable_transaction_count(required_adjustment)
    ))
    .unwrap();
}
fn render_positive_scenario(file: &mut File, result: SuccessfulAdjustment) {
    write_thick_dividing_line(file);
    render_scenario_header(
        file,
        result.common.cw_service_fee_balance_minor,
        result.common.required_adjustment,
    );
    write_thin_dividing_line(file);
    let adjusted_accounts = result.partially_sorted_interpretable_adjustments;
    adjusted_accounts.into_iter().for_each(|account| {
        single_account_output(
            file,
            account.initial_balance,
            account.debt_age_s,
            account.bill_coverage_in_percentage_opt,
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
    let bill_coverage_in_percentage_opt = match adjusted_account_idx_opt {
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
        bill_coverage_in_percentage_opt,
    }
}

fn sort_interpretable_adjustments(
    interpretable_adjustments: Vec<InterpretableAdjustmentResult>,
) -> Vec<InterpretableAdjustmentResult> {
    let (finished, eliminated): (
        Vec<InterpretableAdjustmentResult>,
        Vec<InterpretableAdjustmentResult>,
    ) = interpretable_adjustments
        .into_iter()
        .partition(|adjustment| adjustment.bill_coverage_in_percentage_opt.is_some());
    let finished_sorted = finished.into_iter().sorted_by(|result_a, result_b| {
        Ord::cmp(
            &result_b.bill_coverage_in_percentage_opt.unwrap(),
            &result_a.bill_coverage_in_percentage_opt.unwrap(),
        )
    });
    let eliminated_sorted = eliminated.into_iter().sorted_by(|result_a, result_b| {
        Ord::cmp(&result_b.initial_balance, &result_a.initial_balance)
    });
    finished_sorted.chain(eliminated_sorted).collect()
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
    scenarios_eliminated_before_adjustment_started: usize,
    // Second stage: proper adjustment
    // ____________________________________
    oks: usize,
    // Errors
    all_accounts_eliminated: usize,
    insufficient_service_fee_balance: usize,
}

struct CommonScenarioInfo {
    cw_service_fee_balance_minor: u128,
    required_adjustment: Adjustment,
}

struct InterpretableAdjustmentResult {
    initial_balance: u128,
    debt_age_s: u64,
    // Account was eliminated from payment if None
    bill_coverage_in_percentage_opt: Option<u8>,
}

struct AccountInfo {
    wallet: Wallet,
    initially_requested_service_fee_minor: u128,
    debt_age_s: u64,
}
