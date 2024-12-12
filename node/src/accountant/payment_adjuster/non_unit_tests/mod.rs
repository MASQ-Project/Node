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
    make_single_qualified_payable_opt, try_to_make_guaranteed_qualified_payables,
};
use crate::accountant::{AnalyzedPayableAccount, QualifiedPayableAccount};
use crate::blockchain::blockchain_interface::blockchain_interface_web3::TRANSACTION_FEE_MARGIN;
use crate::sub_lib::accountant::PaymentThresholds;
use crate::sub_lib::blockchain_bridge::OutboundPaymentsInstructions;
use crate::sub_lib::wallet::Wallet;
use crate::test_utils::make_wallet;
use itertools::{Either, Itertools};
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
//#[ignore]
fn loading_test_with_randomized_params() {
    // This is a fuzz test. It generates possibly an overwhelming amount of scenarios that
    // the PaymentAdjuster could be given sort them out, as realistic as it can get, while its
    // nature of randomness offers chances to have a dense range of combinations that a human fails
    // to even try imagining. The hypothesis is that some of those might be corner cases whose
    // trickiness wasn't recognized when the functionality was still at design. This test is to
    // prove that despite highly variable input over a lot of attempts, the PaymentAdjuster can do
    // its job reliably and won't endanger the Node. Also, it is important that it should give
    // reasonable payment adjustments.

    // We can consider the test having an exo-parameter. It's the count of scenarios to be generated.
    // This number must be thought of just as a rough parameter, because many of those attempted
    // scenarios, loosely randomized, will be rejected in the setup stage.

    // The rejection happens before the actual test unwinds as there will always be scenarios with
    // attributes that don't fit to a variety of conditions which needs to be insisted on. Those are
    // that the accounts under each scenario can hold that they are legitimately qualified payables
    // as those to be passed on to the payment adjuster in the real world. It goes much easier if
    // we allow this always implied waste than trying to invent an algorithm whose randomness would
    // be exercised within strictly controlled boundaries.

    // Some other are lost quite early as legitimate errors that the PaymentAdjuster can detect,
    // which would prevent finishing the search for given scenario.

    // When the test reaches its end, it produces important output in a text file, located:
    // node/generated/test/payment_adjuster/tests/home/loading_test_output.txt

    // This file begins with some key figures of those exercises just run, which is followed by
    // a summary loaded with statistics that can serve well on inspection of the actual behavior
    // against the desired.

    // If you are new to this algorithm, there might be results (maybe rare, but absolutely valid
    // and wanted) that can keep one puzzled.

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
                scenario.applied_thresholds,
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

    let (cw_service_fee_balance, qualified_payables, applied_thresholds) =
        try_generating_qualified_payables_and_cw_balance(gn, accounts_count, now)?;

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
        applied_thresholds,
    })
}

fn make_payable_account(
    wallet: Wallet,
    thresholds: &PaymentThresholds,
    now: SystemTime,
    gn: &mut ThreadRng,
) -> PayableAccount {
    let debt_age = generate_debt_age(gn, thresholds);
    let service_fee_balance_minor =
        generate_highly_randomized_payable_account_balance(gn, thresholds);
    let last_paid_timestamp = from_time_t(to_time_t(now) - debt_age as i64);
    PayableAccount {
        wallet,
        balance_wei: service_fee_balance_minor,
        last_paid_timestamp,
        pending_payable_opt: None,
    }
}

fn generate_debt_age(gn: &mut ThreadRng, thresholds: &PaymentThresholds) -> u64 {
    generate_range(
        gn,
        thresholds.maturity_threshold_sec,
        thresholds.maturity_threshold_sec + thresholds.threshold_interval_sec,
    ) / 2
}

fn generate_highly_randomized_payable_account_balance(
    gn: &mut ThreadRng,
    thresholds: &PaymentThresholds,
) -> u128 {
    // This seems overcomplicated, damn. As a result of simple intentions though. I wanted to ensure
    // occurrence of accounts with balances having different magnitudes in the frame of a single
    // scenario. This was crucial to me so much that I was ready to write even this piece of code
    // a bit crazy by look.
    // This setup worked well to stress the randomness I needed, a lot more significant compared to
    // what the naked number generator can put for you. Using some nesting, it broke the rigid
    // pattern and gave an existence to accounts with diverse balances.
    let mut generate_u128 = || generate_non_zero_usize(gn, 100) as u128;

    let parameter_a = generate_u128();
    let parameter_b = generate_u128();
    let parameter_c = generate_u128();
    let parameter_d = generate_u128();
    let parameter_e = generate_u128();
    let parameter_f = generate_u128();

    let mut use_variable_exponent =
        |parameter: u128, up_to: usize| parameter.pow(generate_non_zero_usize(gn, up_to) as u32);

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
}

fn try_make_qualified_payables_by_applied_thresholds(
    payable_accounts: Vec<PayableAccount>,
    applied_thresholds: &AppliedThresholds,
    now: SystemTime,
) -> Vec<QualifiedPayableAccount> {
    let payment_inspector = PayableInspector::new(Box::new(PayableThresholdsGaugeReal::default()));
    match applied_thresholds {
        AppliedThresholds::Defaulted => try_to_make_guaranteed_qualified_payables(
            payable_accounts,
            &PRESERVED_TEST_PAYMENT_THRESHOLDS,
            now,
            false,
        ),
        AppliedThresholds::CommonButRandomized { common_thresholds } => {
            try_to_make_guaranteed_qualified_payables(
                payable_accounts,
                common_thresholds,
                now,
                false,
            )
        }
        AppliedThresholds::RandomizedForEachAccount {
            individual_thresholds,
        } => {
            let vec_of_thresholds = individual_thresholds.values().collect_vec();
            let zipped = payable_accounts.into_iter().zip(vec_of_thresholds.iter());
            zipped
                .flat_map(|(qualified_payable, thresholds)| {
                    make_single_qualified_payable_opt(
                        qualified_payable,
                        &payment_inspector,
                        &thresholds,
                        false,
                        now,
                    )
                })
                .collect()
        }
    }
}

fn try_generating_qualified_payables_and_cw_balance(
    gn: &mut ThreadRng,
    accounts_count: usize,
    now: SystemTime,
) -> Option<(u128, Vec<QualifiedPayableAccount>, AppliedThresholds)> {
    let (payables, applied_thresholds) =
        make_payables_according_to_thresholds_setup(gn, accounts_count, now);

    let qualified_payables =
        try_make_qualified_payables_by_applied_thresholds(payables, &applied_thresholds, now);

    let cw_service_fee_balance_minor =
        pick_appropriate_cw_service_fee_balance(gn, &qualified_payables, accounts_count);

    let required_service_fee_total: u128 = sum_as(&qualified_payables, |account| {
        account.initial_balance_minor()
    });
    if required_service_fee_total <= cw_service_fee_balance_minor {
        None
    } else {
        Some((
            cw_service_fee_balance_minor,
            qualified_payables,
            applied_thresholds,
        ))
    }
}

fn pick_appropriate_cw_service_fee_balance(
    gn: &mut ThreadRng,
    qualified_payables: &[QualifiedPayableAccount],
    accounts_count: usize,
) -> u128 {
    // Value picked empirically
    const COEFFICIENT: usize = 1000;
    let balance_average = sum_as(qualified_payables, |account| {
        account.initial_balance_minor()
    }) / accounts_count as u128;
    let max_pieces = accounts_count * COEFFICIENT;
    let number_of_pieces = generate_usize(gn, max_pieces - 2) as u128 + 2;
    balance_average / COEFFICIENT as u128 * number_of_pieces
}

fn make_payables_according_to_thresholds_setup(
    gn: &mut ThreadRng,
    accounts_count: usize,
    now: SystemTime,
) -> (Vec<PayableAccount>, AppliedThresholds) {
    let wallets = prepare_account_wallets(accounts_count);

    let nominated_thresholds = choose_thresholds(gn, &wallets);

    let payables = match &nominated_thresholds {
        AppliedThresholds::Defaulted => make_payables_with_common_thresholds(
            gn,
            wallets,
            &PRESERVED_TEST_PAYMENT_THRESHOLDS,
            now,
        ),
        AppliedThresholds::CommonButRandomized { common_thresholds } => {
            make_payables_with_common_thresholds(gn, wallets, common_thresholds, now)
        }
        AppliedThresholds::RandomizedForEachAccount {
            individual_thresholds,
        } => make_payables_with_individual_thresholds(gn, &individual_thresholds, now),
    };

    (payables, nominated_thresholds)
}

fn prepare_account_wallets(accounts_count: usize) -> Vec<Wallet> {
    (0..accounts_count)
        .map(|idx| make_wallet(&format!("wallet{}", idx)))
        .collect()
}

fn choose_thresholds(gn: &mut ThreadRng, prepared_wallets: &[Wallet]) -> AppliedThresholds {
    let be_defaulted = generate_boolean(gn);
    if be_defaulted {
        AppliedThresholds::Defaulted
    } else {
        let be_same_for_all_accounts = generate_boolean(gn);
        if be_same_for_all_accounts {
            AppliedThresholds::CommonButRandomized {
                common_thresholds: return_single_randomized_thresholds(gn),
            }
        } else {
            let individual_thresholds = prepared_wallets
                .iter()
                .map(|wallet| (wallet.clone(), return_single_randomized_thresholds(gn)))
                .collect::<HashMap<Wallet, PaymentThresholds>>();
            AppliedThresholds::RandomizedForEachAccount {
                individual_thresholds,
            }
        }
    }
}

fn make_payables_with_common_thresholds(
    gn: &mut ThreadRng,
    prepared_wallets: Vec<Wallet>,
    common_thresholds: &PaymentThresholds,
    now: SystemTime,
) -> Vec<PayableAccount> {
    prepared_wallets
        .into_iter()
        .map(|wallet| make_payable_account(wallet, common_thresholds, now, gn))
        .collect()
}

fn make_payables_with_individual_thresholds(
    gn: &mut ThreadRng,
    wallets_and_thresholds: &HashMap<Wallet, PaymentThresholds>,
    now: SystemTime,
) -> Vec<PayableAccount> {
    wallets_and_thresholds
        .iter()
        .map(|(wallet, thresholds)| make_payable_account(wallet.clone(), thresholds, now, gn))
        .collect()
}

fn return_single_randomized_thresholds(gn: &mut ThreadRng) -> PaymentThresholds {
    let permanent_debt_allowed_gwei = generate_range(gn, 100, 1_000_000_000);
    let debt_threshold_gwei =
        permanent_debt_allowed_gwei + generate_range(gn, 10_000, 10_000_000_000);
    PaymentThresholds {
        debt_threshold_gwei,
        maturity_threshold_sec: generate_range(gn, 100, 10_000),
        payment_grace_period_sec: 0,
        permanent_debt_allowed_gwei,
        threshold_interval_sec: generate_range(gn, 1000, 100_000),
        unban_below_gwei: permanent_debt_allowed_gwei,
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
        .gas_price_margin_result(TRANSACTION_FEE_MARGIN.clone())
}

fn make_adjustment(gn: &mut ThreadRng, accounts_count: usize) -> Adjustment {
    let also_by_transaction_fee = generate_boolean(gn);
    if also_by_transaction_fee && accounts_count > 2 {
        let transaction_count_limit =
            u16::try_from(generate_non_zero_usize(gn, accounts_count)).unwrap();
        Adjustment::BeginByTransactionFee {
            transaction_count_limit,
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
    output_collector: TestOverallOutputCollector,
) {
    let file_dir = ensure_node_home_directory_exists("payment_adjuster", "tests");
    let mut file = File::create(file_dir.join("loading_test_output.txt")).unwrap();
    introduction(&mut file);
    let output_collector =
        scenario_results
            .into_iter()
            .fold(output_collector, |acc, scenario_result| {
                do_final_processing_of_single_scenario(&mut file, acc, scenario_result)
            });
    let total_scenarios_evaluated = output_collector.scenarios_denied_before_adjustment_started
        + output_collector.oks
        + output_collector.all_accounts_eliminated
        + output_collector.late_immoderately_insufficient_service_fee_balance;
    write_brief_test_summary_into_file(
        &mut file,
        &output_collector,
        number_of_requested_scenarios,
        total_scenarios_evaluated,
    );
    let total_scenarios_handled_including_invalid_ones =
        total_scenarios_evaluated + output_collector.invalidly_generated_scenarios;
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
        - ((output_collector.scenarios_denied_before_adjustment_started * 100)
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
    let ok_adjustment_percentage = (output_collector.oks * 100)
        / (total_scenarios_evaluated - output_collector.scenarios_denied_before_adjustment_started);
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
         With 'RecursionDrainedAllAccounts':.......... {}\n\
         With late insufficient balance errors:. {}\n\n\
         Legend\n\
         Adjusted balances are highlighted by \
         this mark by the side:................. {}",
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
                PaymentAdjusterError::RecursionDrainedAllAccounts => {
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
        AppliedThresholds::Defaulted | AppliedThresholds::CommonButRandomized { .. } => {
            if let AppliedThresholds::CommonButRandomized { common_thresholds } = applied_thresholds
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

fn render_accounts<Account, F>(
    file: &mut File,
    accounts: &[Account],
    used_thresholds: &AppliedThresholds,
    mut render_account: F,
) where
    Account: AccountWithWallet,
    F: FnMut(&mut File, &Account, Option<&PaymentThresholds>),
{
    let individual_thresholds_opt = if let AppliedThresholds::RandomizedForEachAccount {
        individual_thresholds,
    } = used_thresholds
    {
        Some(individual_thresholds)
    } else {
        None
    };

    accounts
        .iter()
        .map(|account| {
            (
                account,
                fetch_individual_thresholds_for_account_if_appropriate(
                    individual_thresholds_opt,
                    account,
                ),
            )
        })
        .for_each(|(account, individual_thresholds_opt)| {
            render_account(file, account, individual_thresholds_opt)
        });

    file.write(b"\n").unwrap();
}

fn fetch_individual_thresholds_for_account_if_appropriate<'a, Account>(
    individual_thresholds_opt: Option<&'a HashMap<Wallet, PaymentThresholds>>,
    account: &'a Account,
) -> Option<&'a PaymentThresholds>
where
    Account: AccountWithWallet,
{
    individual_thresholds_opt.map(|wallets_and_thresholds| {
        wallets_and_thresholds
            .get(&account.wallet())
            .expect("Original thresholds missing")
    })
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
            transaction_count_limit,
        } => transaction_count_limit.to_string(),
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
    applied_thresholds: AppliedThresholds,
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
    CommonButRandomized {
        common_thresholds: PaymentThresholds,
    },
    RandomizedForEachAccount {
        individual_thresholds: HashMap<Wallet, PaymentThresholds>,
    },
}
