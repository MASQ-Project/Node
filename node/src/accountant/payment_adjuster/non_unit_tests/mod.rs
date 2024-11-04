// Copyright (c) 2024, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

#![cfg(test)]

use crate::accountant::db_access_objects::payable_dao::PayableAccount;
use crate::accountant::db_access_objects::utils::{from_time_t, to_time_t};
use crate::accountant::payment_adjuster::miscellaneous::helper_functions::sum_as;
use crate::accountant::payment_adjuster::preparatory_analyser::accounts_abstraction::BalanceProvidingAccount;
use crate::accountant::payment_adjuster::test_utils::PRESERVED_TEST_PAYMENT_THRESHOLDS;
use crate::accountant::payment_adjuster::{
    Adjustment, AdjustmentAnalysisReport, PaymentAdjuster, PaymentAdjusterError,
    PaymentAdjusterReal,
};
use crate::accountant::scanners::mid_scan_msg_handling::payable_scanner::test_utils::BlockchainAgentMock;
use crate::accountant::scanners::mid_scan_msg_handling::payable_scanner::PreparedAdjustment;
use crate::accountant::scanners::scanners_utils::payable_scanner_utils::{
    PayableInspector, PayableThresholdsGaugeReal,
};
use crate::accountant::test_utils::{
    make_single_qualified_payable_opt, try_making_guaranteed_qualified_payables,
};
use crate::accountant::{AnalyzedPayableAccount, QualifiedPayableAccount};
use crate::sub_lib::accountant::PaymentThresholds;
use crate::sub_lib::blockchain_bridge::OutboundPaymentsInstructions;
use crate::sub_lib::wallet::Wallet;
use crate::test_utils::make_wallet;
use itertools::{Either, Itertools};
use masq_lib::percentage::PurePercentage;
use masq_lib::test_utils::utils::ensure_node_home_directory_exists;
use masq_lib::utils::convert_collection;
use rand;
use rand::distributions::uniform::SampleUniform;
use rand::rngs::ThreadRng;
use rand::{thread_rng, Rng};
use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use std::time::SystemTime;
use thousands::Separable;
use web3::types::U256;

#[test]
// TODO If an option for "occasional tests" is added, this is a good adept
#[ignore]
fn loading_test_with_randomized_params() {
    // This is a fuzz test, a generator of possibly an overwhelming amount of scenarios that could
    // get the PaymentAdjuster to be asked to sort them out even in real situations while there
    // might be many and many combinations that a human is having a hard time just imagining; of
    // them some might be corner cases whose threatening wasn't known when this was being designed.
    // This test is to prove that even a huge number of runs, with hopefully highly variable inputs,
    // will not shoot the PaymentAdjuster down and the Node with it; on the contrary, it should
    // be able to give reasonable results and live up to its original purpose of adjustments.

    // Part of the requested count is rejected before the test begins as there are generated
    // scenarios with such parameters that don't fit to a variety of conditions. It's easier to keep
    // it this way than setting up an algorithm with enough "tamed" randomness. Other bunch of them
    // will likely be marked as legitimate errors that the PaymentAdjuster can detect.
    // When the test reaches its end, a text file is filled in with some key figures of the performed
    // exercises and finally also an overall summary with useful statistics that can serve to
    // evaluate the actual behavior against the desired.

    // If you are new to this algorithm, there might be results (maybe rare, but absolutely valid
    // and wanted, and so deserving some interest) that can have one puzzled, though.

    // The example further below presents a tricky-to-understand output belonging to one set of
    // payables. See those percentages. They may not excel at explaining themselves when it comes to
    // their inconsistent proportionality towards the balances. These percents represent a payment
    // coverage of the initial debts. But why don't they correspond with ascending balances? There's
    // a principle to equip accounts low balances with the biggest weights. True. However, it doesn't
    // need to be reflected so clearly, though. The adjustment depends heavily on a so-called
    // "disqualification limit". Besides other purposes, this value affects that the payment won't
    // require the entire amount but only its portion. That inherently will do for the payer to stay
    // unbanned. In bulky accounts, this until-some-time forgiven portion stands only as a fraction
    // of a whole. Small accounts, however, if it can be applied (as opposed to the account having
    // to be excluded) might get shrunk a lot, and therefore many percents are to be reported as
    // missing. This is what the numbers like 99% and 90% illustrates. That said, the letter account
    // comes across as it should take precedence for its expectedly larger weight, and gain at the
    // expanse of the other, but the percents speak otherwise. Yet, it's correct. The interpretation
    // is the key. (Caution: this test displays its output with those accounts sorted).

    // CW service fee balance: 32,041,461,894,055,482 wei
    // Portion of CW balance used: 100%
    // Maximal txt count due to CW txt fee balance: UNLIMITED
    // Used PaymentThresholds: DEFAULTED
    // 2000000|1000|1000|1000000|500000|1000000
    // _____________________________________________________________________________________________
    //   1,988,742,049,305,843 wei |  236,766 s | 100 %
    //  21,971,010,542,100,729 wei |  472,884 s | 99 %                         # # # # # # # #
    //   4,726,030,753,976,563 wei |  395,377 s | 95 %                         # # # # # # # #
    //   3,995,577,830,314,875 wei |  313,396 s | 90 %                         # # # # # # # #
    // 129,594,971,536,673,815 wei |  343,511 s | X

    // In the code, we select and pale up accounts so that the picked balance isn't the full range,
    // but still enough. The disqualification limit draws the cut. Only if the wallet isn't all
    // dried up, after the accounts to keep are determined, while iterated over again, accounts
    // sorted by descending weights are given more of it one by one, the maximum they can absorb,
    // until there is still something to spend.

    let now = SystemTime::now();
    let mut gn = thread_rng();
    let mut subject = PaymentAdjusterReal::new();
    let number_of_requested_scenarios = 2000;
    let scenarios = generate_scenarios(&mut gn, now, number_of_requested_scenarios);
    let invalidly_generated_scenarios = number_of_requested_scenarios - scenarios.len();
    let test_overall_output_collector =
        TestOverallOutputCollector::new(invalidly_generated_scenarios);

    struct FirstStageOutput {
        test_overall_output_collector: TestOverallOutputCollector,
        allowed_scenarios: Vec<PreparedAdjustmentAndThresholds>,
    }

    let init = FirstStageOutput {
        test_overall_output_collector,
        allowed_scenarios: vec![],
    };
    let first_stage_output = scenarios
        .into_iter()
        .fold(init, |mut output_collector, scenario| {
            // We care only about the service fee balance check, parameters for transaction fee can
            // be worked into the scenarios later.
            let qualified_payables = scenario
                .prepared_adjustment
                .adjustment_analysis
                .accounts
                .iter()
                .map(|account| account.qualified_as.clone())
                .collect();
            let initial_check_result = subject
                .consider_adjustment(qualified_payables, &*scenario.prepared_adjustment.agent);
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
                Err(_) => {
                    output_collector
                        .test_overall_output_collector
                        .scenarios_denied_before_adjustment_started += 1;
                    None
                }
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
        .map(|scenario| {
            let prepared_adjustment = scenario.prepared_adjustment;
            let account_infos =
                preserve_account_infos(&prepared_adjustment.adjustment_analysis.accounts, now);
            let required_adjustment = prepared_adjustment.adjustment_analysis.adjustment.clone();
            let cw_service_fee_balance_minor =
                prepared_adjustment.agent.service_fee_balance_minor();

            let payment_adjuster_result = subject.adjust_payments(prepared_adjustment, now);

            administrate_single_scenario_result(
                payment_adjuster_result,
                account_infos,
                scenario.used_thresholds,
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
) -> Vec<PreparedAdjustmentAndThresholds> {
    (0..number_of_scenarios)
        .flat_map(|_| try_making_single_valid_scenario(gn, now))
        .collect()
}

fn try_making_single_valid_scenario(
    gn: &mut ThreadRng,
    now: SystemTime,
) -> Option<PreparedAdjustmentAndThresholds> {
    let accounts_count = generate_non_zero_usize(gn, 25) + 1;
    let thresholds_to_be_used = choose_thresholds(gn, accounts_count);
    let (cw_service_fee_balance, qualified_payables, wallet_and_thresholds_pairs) =
        try_generating_qualified_payables_and_cw_balance(
            gn,
            &thresholds_to_be_used,
            accounts_count,
            now,
        )?;
    let used_thresholds =
        thresholds_to_be_used.fix_individual_thresholds_if_needed(wallet_and_thresholds_pairs);
    let analyzed_accounts: Vec<AnalyzedPayableAccount> = convert_collection(qualified_payables);
    let agent = make_agent(cw_service_fee_balance);
    let adjustment = make_adjustment(gn, analyzed_accounts.len());
    let prepared_adjustment = PreparedAdjustment::new(
        Box::new(agent),
        None,
        AdjustmentAnalysisReport::new(adjustment, analyzed_accounts),
    );
    Some(PreparedAdjustmentAndThresholds {
        prepared_adjustment,
        used_thresholds,
    })
}

fn make_payable_account(
    idx: usize,
    thresholds: &PaymentThresholds,
    now: SystemTime,
    gn: &mut ThreadRng,
) -> PayableAccount {
    // Why is this construction so complicated? Well, I wanted to get the test showing partially
    // fulfilling adjustments where the final accounts can be paid enough but still not all up to
    // their formerly claimed balance. It turned out it is very difficult to achieve with the use of
    // randomized ranges, I couldn't really come up with parameters that would promise this condition.
    // I ended up experimenting and looking for an algorithm that would make the parameters as random
    // as possible because the generator alone is not much good at it, using gradually, but
    // individually generated parameters that I put together for better chances of randomness. Many
    // produced accounts will not make it through into the actual test, filtered out when attempted
    // to be converted into a proper QualifiedPayableAccount. This isn't optimal, sure, but it allows
    // to observe some of those partial adjustments, however, with rather a low rate of occurrence
    // among those all attempts of acceptable scenarios.
    let wallet = make_wallet(&format!("wallet{}", idx));
    let mut generate_age_segment = || {
        generate_non_zero_usize(
            gn,
            (thresholds.maturity_threshold_sec + thresholds.threshold_interval_sec) as usize,
        ) / 2
    };
    let debt_age = generate_age_segment() + generate_age_segment();
    let service_fee_balance_minor = {
        let mut generate_u128 = || generate_non_zero_usize(gn, 100) as u128;
        let parameter_a = generate_u128();
        let parameter_b = generate_u128();
        let parameter_c = generate_u128();
        let parameter_d = generate_u128();
        let parameter_e = generate_u128();
        let parameter_f = generate_u128();
        let mut use_variable_exponent = |parameter: u128, up_to: usize| {
            parameter.pow(generate_non_zero_usize(gn, up_to) as u32)
        };
        let a_b_c_d_e = parameter_a
            * use_variable_exponent(parameter_b, 2)
            * use_variable_exponent(parameter_c, 3)
            * use_variable_exponent(parameter_d, 4)
            * use_variable_exponent(parameter_e, 5);
        let addition = (0..6).fold(a_b_c_d_e, |so_far, subtrahend| {
            if so_far != a_b_c_d_e {
                so_far
            } else {
                if let Some(num) =
                    a_b_c_d_e.checked_sub(use_variable_exponent(parameter_f, 6 - subtrahend))
                {
                    num
                } else {
                    so_far
                }
            }
        });

        thresholds.permanent_debt_allowed_gwei as u128 + addition
    };
    let last_paid_timestamp = from_time_t(to_time_t(now) - debt_age as i64);
    PayableAccount {
        wallet,
        balance_wei: service_fee_balance_minor,
        last_paid_timestamp,
        pending_payable_opt: None,
    }
}

fn try_generating_qualified_payables_and_cw_balance(
    gn: &mut ThreadRng,
    thresholds_to_be_used: &AppliedThresholds,
    accounts_count: usize,
    now: SystemTime,
) -> Option<(
    u128,
    Vec<QualifiedPayableAccount>,
    Vec<(Wallet, PaymentThresholds)>,
)> {
    let payables = make_payables_according_to_thresholds_setup(
        gn,
        &thresholds_to_be_used,
        accounts_count,
        now,
    );

    let (qualified_payables, wallet_and_thresholds_pairs) =
        try_make_qualified_payables_by_applied_thresholds(payables, &thresholds_to_be_used, now);

    let balance_average = {
        let sum: u128 = sum_as(&qualified_payables, |account| {
            account.initial_balance_minor()
        });
        sum / accounts_count as u128
    };
    let cw_service_fee_balance_minor = {
        let multiplier = 1000;
        let max_pieces = accounts_count * multiplier;
        let number_of_pieces = generate_usize(gn, max_pieces - 2) as u128 + 2;
        balance_average / multiplier as u128 * number_of_pieces
    };
    let required_service_fee_total: u128 = sum_as(&qualified_payables, |account| {
        account.initial_balance_minor()
    });
    if required_service_fee_total <= cw_service_fee_balance_minor {
        None
    } else {
        Some((
            cw_service_fee_balance_minor,
            qualified_payables,
            wallet_and_thresholds_pairs,
        ))
    }
}

fn make_payables_according_to_thresholds_setup(
    gn: &mut ThreadRng,
    thresholds_to_be_used: &AppliedThresholds,
    accounts_count: usize,
    now: SystemTime,
) -> Vec<PayableAccount> {
    match thresholds_to_be_used {
        AppliedThresholds::Defaulted => make_payables_with_common_thresholds(
            gn,
            &PRESERVED_TEST_PAYMENT_THRESHOLDS,
            accounts_count,
            now,
        ),
        AppliedThresholds::SingleButRandomized { common_thresholds } => {
            make_payables_with_common_thresholds(gn, common_thresholds, accounts_count, now)
        }
        AppliedThresholds::RandomizedForEachAccount {
            individual_thresholds,
        } => {
            let vec_of_thresholds = individual_thresholds
                .thresholds
                .as_ref()
                .left()
                .expect("should be Vec at this stage");
            assert_eq!(vec_of_thresholds.len(), accounts_count);
            make_payables_with_individual_thresholds(gn, vec_of_thresholds, now)
        }
    }
}

fn make_payables_with_common_thresholds(
    gn: &mut ThreadRng,
    common_thresholds: &PaymentThresholds,
    accounts_count: usize,
    now: SystemTime,
) -> Vec<PayableAccount> {
    (0..accounts_count)
        .map(|idx| make_payable_account(idx, common_thresholds, now, gn))
        .collect::<Vec<_>>()
}

fn make_payables_with_individual_thresholds(
    gn: &mut ThreadRng,
    individual_thresholds: &[PaymentThresholds],
    now: SystemTime,
) -> Vec<PayableAccount> {
    individual_thresholds
        .iter()
        .enumerate()
        .map(|(idx, thresholds)| make_payable_account(idx, thresholds, now, gn))
        .collect()
}

fn choose_thresholds(gn: &mut ThreadRng, accounts_count: usize) -> AppliedThresholds {
    let be_defaulted = generate_boolean(gn);
    if be_defaulted {
        AppliedThresholds::Defaulted
    } else {
        let be_common_for_all = generate_boolean(gn);
        if be_common_for_all {
            AppliedThresholds::SingleButRandomized {
                common_thresholds: return_single_randomized_thresholds(gn),
            }
        } else {
            let thresholds_set = (0..accounts_count)
                .map(|_| return_single_randomized_thresholds(gn))
                .collect();
            let individual_thresholds = IndividualThresholds {
                thresholds: Either::Left(thresholds_set),
            };
            AppliedThresholds::RandomizedForEachAccount {
                individual_thresholds,
            }
        }
    }
}

fn return_single_randomized_thresholds(gn: &mut ThreadRng) -> PaymentThresholds {
    let permanent_debt_allowed_gwei = generate_range(gn, 100, 1_000_000_000);
    let debt_threshold_gwei =
        permanent_debt_allowed_gwei + generate_range(gn, 10_000, 10_000_000_000);
    let maturity_threshold_sec = generate_range(gn, 100, 10_000);
    let threshold_interval_sec = generate_range(gn, 1000, 100_000);
    let unban_below_gwei = permanent_debt_allowed_gwei;
    PaymentThresholds {
        debt_threshold_gwei,
        maturity_threshold_sec,
        payment_grace_period_sec: 0,
        permanent_debt_allowed_gwei,
        threshold_interval_sec,
        unban_below_gwei,
    }
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
        .agreed_transaction_fee_margin_result(PurePercentage::try_from(15).unwrap())
}

fn make_adjustment(gn: &mut ThreadRng, accounts_count: usize) -> Adjustment {
    let also_by_transaction_fee = generate_boolean(gn);
    if also_by_transaction_fee && accounts_count > 2 {
        let affordable_transaction_count =
            u16::try_from(generate_non_zero_usize(gn, accounts_count)).unwrap();
        Adjustment::BeginByTransactionFee {
            affordable_transaction_count,
        }
    } else {
        Adjustment::ByServiceFee
    }
}

fn administrate_single_scenario_result(
    payment_adjuster_result: Result<OutboundPaymentsInstructions, PaymentAdjusterError>,
    account_infos: Vec<AccountInfo>,
    used_thresholds: AppliedThresholds,
    required_adjustment: Adjustment,
    cw_service_fee_balance_minor: u128,
) -> ScenarioResult {
    let common = CommonScenarioInfo {
        cw_service_fee_balance_minor,
        required_adjustment,
        used_thresholds,
    };
    let reinterpreted_result = match payment_adjuster_result {
        Ok(outbound_payment_instructions) => {
            let mut adjusted_accounts = outbound_payment_instructions.affordable_accounts;
            let portion_of_cw_cumulatively_used_percents = {
                let used_absolute: u128 = sum_as(&adjusted_accounts, |account| account.balance_wei);
                ((100 * used_absolute) / common.cw_service_fee_balance_minor) as u8
            };
            let adjusted_accounts =
                interpretable_adjustment_results(account_infos, &mut adjusted_accounts);
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

fn interpretable_adjustment_results(
    account_infos: Vec<AccountInfo>,
    adjusted_accounts: &mut Vec<PayableAccount>,
) -> Vec<InterpretableAdjustmentResult> {
    account_infos
        .into_iter()
        .map(|account_info| {
            prepare_interpretable_adjustment_result(account_info, adjusted_accounts)
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
        + test_overall_output_collector.late_immoderately_insufficient_service_fee_balance;
    write_brief_test_summary_into_file(
        &mut file,
        &test_overall_output_collector,
        number_of_requested_scenarios,
        total_scenarios_evaluated,
    );
    let total_scenarios_handled_including_invalid_ones =
        total_scenarios_evaluated + test_overall_output_collector.invalidly_generated_scenarios;
    assert_eq!(
        total_scenarios_handled_including_invalid_ones, number_of_requested_scenarios,
        "All handled scenarios including those invalid ones ({}) != requested scenarios count ({})",
        total_scenarios_handled_including_invalid_ones, number_of_requested_scenarios
    );
    // Only some of the generated scenarios are acceptable, don't be surprised by the waste. That's
    // anticipated given the nature of the generator and the requirements on the payable accounts
    // so that they are picked up and let in the PaymentAdjuster. We'll be better off truly faithful
    // to the use case and the expected conditions. Therefore, we insist on making "guaranteed"
    // QualifiedPayableAccounts out of PayableAccount which is where we take the losses.
    let entry_check_pass_rate = 100
        - ((test_overall_output_collector.scenarios_denied_before_adjustment_started * 100)
            / total_scenarios_evaluated);
    let required_pass_rate = 50;
    assert!(
        entry_check_pass_rate >= required_pass_rate,
        "Not at least {}% from those {} scenarios \
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
    let page_width = PAGE_WIDTH;
    file.write_fmt(format_args!(
        "{:^page_width$}\n",
        "A short summary can be found at the tail"
    ))
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
         With late insufficient balance errors:. {}\n\n\
         Legend\n\
         Partially adjusted accounts mark:...... {}",
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
        overall_output_collector.late_immoderately_insufficient_service_fee_balance,
        NON_EXHAUSTED_ACCOUNT_MARKER
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
                Adjustment::BeginByTransactionFee { .. }
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
                PaymentAdjusterError::EarlyNotEnoughFeeForSingleTransaction { .. } => {
                    panic!("Such errors should be already filtered out")
                }
                PaymentAdjusterError::LateNotEnoughFeeForSingleTransaction { .. } => {
                    test_overall_output.late_immoderately_insufficient_service_fee_balance += 1
                }
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
    scenario_common: &CommonScenarioInfo,
    portion_of_cw_used_percents: u8,
) {
    write_thick_dividing_line(file);
    file.write_fmt(format_args!(
        "CW service fee balance: {} wei\n\
         Portion of CW balance used: {}%\n\
         Maximal txt count due to CW txt fee balance: {}\n\
         Used PaymentThresholds: {}\n",
        scenario_common
            .cw_service_fee_balance_minor
            .separate_with_commas(),
        portion_of_cw_used_percents,
        resolve_affordable_transaction_count(&scenario_common.required_adjustment),
        resolve_comment_on_thresholds(&scenario_common.used_thresholds)
    ))
    .unwrap();
}

fn resolve_comment_on_thresholds(applied_thresholds: &AppliedThresholds) -> String {
    match applied_thresholds {
        AppliedThresholds::Defaulted | AppliedThresholds::SingleButRandomized { .. } => {
            if let AppliedThresholds::SingleButRandomized { common_thresholds } = applied_thresholds
            {
                format!("SHARED BUT CUSTOM\n{}", common_thresholds)
            } else {
                format!("DEFAULTED\n{}", PRESERVED_TEST_PAYMENT_THRESHOLDS)
            }
        }
        AppliedThresholds::RandomizedForEachAccount { .. } => "INDIVIDUAL".to_string(),
    }
}

fn render_positive_scenario(file: &mut File, result: SuccessfulAdjustment) {
    render_scenario_header(
        file,
        &result.common,
        result.portion_of_cw_cumulatively_used_percents,
    );
    write_thin_dividing_line(file);

    let adjusted_accounts = result.partially_sorted_interpretable_adjustments;

    render_accounts(
        file,
        &adjusted_accounts,
        &result.common.used_thresholds,
        |file, account, individual_thresholds_opt| {
            single_account_output(
                file,
                account.info.initially_requested_service_fee_minor,
                account.info.debt_age_s,
                individual_thresholds_opt,
                account.bills_coverage_in_percentage_opt,
            )
        },
    )
}

fn render_accounts<A, F>(
    file: &mut File,
    accounts: &[A],
    used_thresholds: &AppliedThresholds,
    mut render_account: F,
) where
    A: AccountWithWallet,
    F: FnMut(&mut File, &A, Option<&PaymentThresholds>),
{
    let set_of_individual_thresholds_opt = if let AppliedThresholds::RandomizedForEachAccount {
        individual_thresholds,
    } = used_thresholds
    {
        Some(individual_thresholds.thresholds.as_ref().right().unwrap())
    } else {
        None
    };
    accounts
        .iter()
        .map(|account| {
            (
                account,
                set_of_individual_thresholds_opt.map(|thresholds| {
                    thresholds
                        .get(&account.wallet())
                        .expect("Original thresholds missing")
                }),
            )
        })
        .for_each(|(account, individual_thresholds_opt)| {
            render_account(file, account, individual_thresholds_opt)
        });
    file.write(b"\n").unwrap();
}

trait AccountWithWallet {
    fn wallet(&self) -> &Wallet;
}

const FIRST_COLUMN_WIDTH: usize = 50;
const AGE_COLUMN_WIDTH: usize = 8;

const STARTING_GAP: usize = 6;

fn single_account_output(
    file: &mut File,
    balance_minor: u128,
    age_s: u64,
    individual_thresholds_opt: Option<&PaymentThresholds>,
    bill_coverage_in_percentage_opt: Option<u8>,
) {
    let first_column_width = FIRST_COLUMN_WIDTH;
    let age_width = AGE_COLUMN_WIDTH;
    let starting_gap = STARTING_GAP;
    let _ = file
        .write_fmt(format_args!(
            "{}{:<starting_gap$}{:>first_column_width$} wei | {:>age_width$} s | {}\n",
            individual_thresholds_opt
                .map(|thresholds| format!(
                    "{:<starting_gap$}This account thresholds: {:>first_column_width$}\n",
                    "", thresholds
                ))
                .unwrap_or("".to_string()),
            "",
            balance_minor.separate_with_commas(),
            age_s.separate_with_commas(),
            resolve_account_ending_status_graphically(bill_coverage_in_percentage_opt),
        ))
        .unwrap();
}

const NON_EXHAUSTED_ACCOUNT_MARKER: &str = "# # # # # # # #";

fn resolve_account_ending_status_graphically(
    bill_coverage_in_percentage_opt: Option<u8>,
) -> String {
    match bill_coverage_in_percentage_opt {
        Some(percentage) => {
            let highlighting = if percentage != 100 {
                NON_EXHAUSTED_ACCOUNT_MARKER
            } else {
                ""
            };
            format!("{} %{:>shift$}", percentage, highlighting, shift = 40)
        }
        None => "X".to_string(),
    }
}

fn render_negative_scenario(file: &mut File, negative_result: FailedAdjustment) {
    render_scenario_header(file, &negative_result.common, 0);
    write_thin_dividing_line(file);
    render_accounts(
        file,
        &negative_result.account_infos,
        &negative_result.common.used_thresholds,
        |file, account, individual_thresholds_opt| {
            single_account_output(
                file,
                account.initially_requested_service_fee_minor,
                account.debt_age_s,
                individual_thresholds_opt,
                None,
            )
        },
    );
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

fn resolve_affordable_transaction_count(adjustment: &Adjustment) -> String {
    match adjustment {
        Adjustment::ByServiceFee => "UNLIMITED".to_string(),
        Adjustment::BeginByTransactionFee {
            affordable_transaction_count,
        } => affordable_transaction_count.to_string(),
    }
}

fn write_thick_dividing_line(file: &mut dyn Write) {
    write_ln_made_of(file, '=')
}

fn write_thin_dividing_line(file: &mut dyn Write) {
    write_ln_made_of(file, '_')
}

const PAGE_WIDTH: usize = 120;

fn write_ln_made_of(file: &mut dyn Write, char: char) {
    let _ = file
        .write_fmt(format_args!("{}\n", char.to_string().repeat(PAGE_WIDTH)))
        .unwrap();
}

fn prepare_interpretable_adjustment_result(
    account_info: AccountInfo,
    resulted_affordable_accounts: &mut Vec<PayableAccount>,
) -> InterpretableAdjustmentResult {
    let adjusted_account_idx_opt = resulted_affordable_accounts
        .iter()
        .position(|account| account.wallet == account_info.wallet);
    let bills_coverage_in_percentage_opt = match adjusted_account_idx_opt {
        Some(idx) => {
            let adjusted_account = resulted_affordable_accounts.remove(idx);
            assert_eq!(adjusted_account.wallet, account_info.wallet);
            let bill_coverage_in_percentage = {
                let percentage = (adjusted_account.balance_wei * 100)
                    / account_info.initially_requested_service_fee_minor;
                u8::try_from(percentage).unwrap()
            };
            Some(bill_coverage_in_percentage)
        }
        None => None,
    };
    InterpretableAdjustmentResult {
        info: AccountInfo {
            wallet: account_info.wallet,
            debt_age_s: account_info.debt_age_s,
            initially_requested_service_fee_minor: account_info
                .initially_requested_service_fee_minor,
        },

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
            &(
                result_b.bills_coverage_in_percentage_opt,
                result_a.info.initially_requested_service_fee_minor,
            ),
            &(
                result_a.bills_coverage_in_percentage_opt,
                result_b.info.initially_requested_service_fee_minor,
            ),
        )
    });
    let eliminated_sorted = eliminated.into_iter().sorted_by(|result_a, result_b| {
        Ord::cmp(
            &result_a.info.initially_requested_service_fee_minor,
            &result_b.info.initially_requested_service_fee_minor,
        )
    });
    let all_results = finished_sorted.chain(eliminated_sorted).collect();
    (all_results, were_no_accounts_eliminated)
}

fn generate_range<T>(gn: &mut ThreadRng, low: T, up_to: T) -> T
where
    T: SampleUniform + PartialOrd,
{
    gn.gen_range(low..up_to)
}

fn generate_non_zero_usize(gn: &mut ThreadRng, up_to: usize) -> usize {
    generate_range(gn, 1, up_to)
}

fn generate_usize(gn: &mut ThreadRng, up_to: usize) -> usize {
    generate_range(gn, 0, up_to)
}

fn generate_boolean(gn: &mut ThreadRng) -> bool {
    gn.gen()
}

struct TestOverallOutputCollector {
    invalidly_generated_scenarios: usize,
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
    late_immoderately_insufficient_service_fee_balance: usize,
}

impl TestOverallOutputCollector {
    fn new(invalidly_generated_scenarios: usize) -> Self {
        Self {
            invalidly_generated_scenarios,
            scenarios_denied_before_adjustment_started: 0,
            oks: 0,
            with_no_accounts_eliminated: 0,
            fulfillment_distribution_for_transaction_fee_adjustments: Default::default(),
            fulfillment_distribution_for_service_fee_adjustments: Default::default(),
            all_accounts_eliminated: 0,
            late_immoderately_insufficient_service_fee_balance: 0,
        }
    }
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

struct PreparedAdjustmentAndThresholds {
    prepared_adjustment: PreparedAdjustment,
    used_thresholds: AppliedThresholds,
}

struct CommonScenarioInfo {
    cw_service_fee_balance_minor: u128,
    required_adjustment: Adjustment,
    used_thresholds: AppliedThresholds,
}
struct InterpretableAdjustmentResult {
    info: AccountInfo,
    // Account was eliminated from payment if None
    bills_coverage_in_percentage_opt: Option<u8>,
}

impl AccountWithWallet for InterpretableAdjustmentResult {
    fn wallet(&self) -> &Wallet {
        &self.info.wallet
    }
}

struct AccountInfo {
    wallet: Wallet,
    initially_requested_service_fee_minor: u128,
    debt_age_s: u64,
}

impl AccountWithWallet for AccountInfo {
    fn wallet(&self) -> &Wallet {
        &self.wallet
    }
}

enum AppliedThresholds {
    Defaulted,
    SingleButRandomized {
        common_thresholds: PaymentThresholds,
    },
    RandomizedForEachAccount {
        individual_thresholds: IndividualThresholds,
    },
}

impl AppliedThresholds {
    fn fix_individual_thresholds_if_needed(
        self,
        wallet_and_thresholds_pairs: Vec<(Wallet, PaymentThresholds)>,
    ) -> Self {
        match self {
            AppliedThresholds::RandomizedForEachAccount { .. } => {
                assert!(
                    !wallet_and_thresholds_pairs.is_empty(),
                    "Pairs should be missing by now"
                );
                let hash_map = HashMap::from_iter(wallet_and_thresholds_pairs);
                let individual_thresholds = IndividualThresholds {
                    thresholds: Either::Right(hash_map),
                };
                AppliedThresholds::RandomizedForEachAccount {
                    individual_thresholds,
                }
            }
            x => x,
        }
    }
}

struct IndividualThresholds {
    thresholds: Either<Vec<PaymentThresholds>, HashMap<Wallet, PaymentThresholds>>,
}

fn try_make_qualified_payables_by_applied_thresholds(
    payable_accounts: Vec<PayableAccount>,
    applied_thresholds: &AppliedThresholds,
    now: SystemTime,
) -> (
    Vec<QualifiedPayableAccount>,
    Vec<(Wallet, PaymentThresholds)>,
) {
    let payment_inspector = PayableInspector::new(Box::new(PayableThresholdsGaugeReal::default()));
    match applied_thresholds {
        AppliedThresholds::Defaulted => (
            try_making_guaranteed_qualified_payables(
                payable_accounts,
                &PRESERVED_TEST_PAYMENT_THRESHOLDS,
                now,
                false,
            ),
            vec![],
        ),
        AppliedThresholds::SingleButRandomized { common_thresholds } => (
            try_making_guaranteed_qualified_payables(
                payable_accounts,
                common_thresholds,
                now,
                false,
            ),
            vec![],
        ),
        AppliedThresholds::RandomizedForEachAccount {
            individual_thresholds,
        } => {
            let vec_of_thresholds = individual_thresholds
                .thresholds
                .as_ref()
                .left()
                .expect("should be Vec at this stage");
            assert_eq!(
                payable_accounts.len(),
                vec_of_thresholds.len(),
                "The number of generated \
            payables {} differs from their sets of thresholds {}, but one should've been derived \
            from the other",
                payable_accounts.len(),
                vec_of_thresholds.len()
            );
            let zipped = payable_accounts.into_iter().zip(vec_of_thresholds.iter());
            zipped.fold(
                (vec![], vec![]),
                |(mut qualified_payables, mut wallet_thresholds_pairs),
                 (payable, its_thresholds)| match make_single_qualified_payable_opt(
                    payable,
                    &payment_inspector,
                    &its_thresholds,
                    false,
                    now,
                ) {
                    Some(qualified_payable) => {
                        let wallet = qualified_payable.bare_account.wallet.clone();
                        qualified_payables.push(qualified_payable);
                        wallet_thresholds_pairs.push((wallet, *its_thresholds));
                        (qualified_payables, wallet_thresholds_pairs)
                    }
                    None => (qualified_payables, wallet_thresholds_pairs),
                },
            )
        }
    }
}
