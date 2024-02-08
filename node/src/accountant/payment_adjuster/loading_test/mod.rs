// Copyright (c) 2024, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

#![cfg(test)]

use crate::accountant::db_access_objects::payable_dao::PayableAccount;
use crate::accountant::db_access_objects::utils::{from_time_t, to_time_t};
use crate::accountant::payment_adjuster::{
    Adjustment, PaymentAdjuster, PaymentAdjusterError, PaymentAdjusterReal,
};
use crate::accountant::scanners::mid_scan_msg_handling::payable_scanner::test_utils::BlockchainAgentMock;
use crate::accountant::scanners::mid_scan_msg_handling::payable_scanner::PreparedAdjustment;
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

#[test]
fn loading_test_with_randomized_params() {
    let now = SystemTime::now();
    let mut gn = thread_rng();
    let mut subject = PaymentAdjusterReal::new();

    let scenarios = generate_scenarios(&mut gn, now, 100);

    let scenario_results = scenarios
        .into_iter()
        .map(|prepared_adjustment| {
            let account_infos =
                suck_off_account_infos(&prepared_adjustment.qualified_payables, now);
            let required_adjustment = prepared_adjustment.adjustment.clone();
            let cw_service_fee_balance_minor =
                prepared_adjustment.agent.service_fee_balance_minor();

            let payment_adjuster_result = subject.adjust_payments(prepared_adjustment, now);

            prepare_single_scenario_result(
                payment_adjuster_result,
                account_infos,
                required_adjustment,
                cw_service_fee_balance_minor,
            )
        })
        .collect();

    render_results(scenario_results)
}

fn generate_scenarios(
    gn: &mut ThreadRng,
    now: SystemTime,
    number_of_scenarios: usize,
) -> Vec<PreparedAdjustment> {
    (0..number_of_scenarios)
        .map(|_| make_single_scenario(gn, now))
        .collect()
}

fn make_single_scenario(gn: &mut ThreadRng, now: SystemTime) -> PreparedAdjustment {
    let cw_service_fee_balance = {
        let base = generate_non_zero_usize(gn, usize::MAX) as u128;
        base * generate_non_zero_usize(gn, 1000) as u128
    };
    let qualified_payables = make_qualified_payables(gn, now, cw_service_fee_balance);
    let agent = make_agent(cw_service_fee_balance);
    let adjustment = make_adjustment(gn, qualified_payables.len());
    PreparedAdjustment::new(qualified_payables, Box::new(agent), None, adjustment)
}

fn make_qualified_payables(
    gn: &mut ThreadRng,
    now: SystemTime,
    cw_service_fee_balance: u128,
) -> Vec<PayableAccount> {
    let accounts_count = generate_non_zero_usize(gn, 20) + 1;
    let average_portion = cw_service_fee_balance / accounts_count as u128;
    (0..accounts_count)
        .map(|idx| {
            let wallet = make_wallet(&format!("wallet{}", idx));
            let debt_age = 2000 + generate_non_zero_usize(gn, 200000);
            let balance_wei =
                average_portion + average_portion / 100 * generate_non_zero_usize(gn, 1000) as u128;
            PayableAccount {
                wallet,
                balance_wei,
                last_paid_timestamp: from_time_t(to_time_t(now) - debt_age as i64),
                pending_payable_opt: None,
            }
        })
        .collect()
}

fn make_agent(cw_service_fee_balance: u128) -> BlockchainAgentMock {
    BlockchainAgentMock::default()
        // For scenario evaluation
        .service_fee_balance_minor_result(cw_service_fee_balance)
        // For PaymentAdjuster itself
        .service_fee_balance_minor_result(cw_service_fee_balance)
}

fn make_adjustment(gn: &mut ThreadRng, accounts_count: usize) -> Adjustment {
    let also_by_transaction_fee = generate_boolean(gn);
    if also_by_transaction_fee && accounts_count > 2 {
        let can_afford = generate_non_zero_usize(gn, accounts_count);
        Adjustment::TransactionFeeInPriority {
            affordable_transaction_count: u16::try_from(can_afford).unwrap(),
        }
    } else {
        Adjustment::ByServiceFee
    }
}

fn prepare_single_scenario_result(
    result: Result<OutboundPaymentsInstructions, PaymentAdjusterError>,
    account_infos: Vec<AccountInfo>,
    required_adjustment: Adjustment,
    cw_service_fee_balance_minor: u128,
) -> ScenarioResult {
    let common = CommonScenarioInfo {
        cw_service_fee_balance_minor,
        required_adjustment,
    };
    let result = match result {
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
                sorted_interpretable_adjustments,
            })
        }
        Err(adjuster_error) => Err(FailedAdjustment {
            common,
            account_infos,
            adjuster_error,
        }),
    };

    ScenarioResult::new(result)
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
    sorted_interpretable_adjustments: Vec<InterpretableAdjustmentResult>,
}

struct FailedAdjustment {
    common: CommonScenarioInfo,
    account_infos: Vec<AccountInfo>,
    adjuster_error: PaymentAdjusterError,
}

fn suck_off_account_infos(accounts: &[PayableAccount], now: SystemTime) -> Vec<AccountInfo> {
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

fn render_results(scenario_results: Vec<ScenarioResult>) {
    let file_dir = ensure_node_home_directory_exists("payment_adjuster", "loading_test");
    let mut file = File::create(file_dir.join("loading_test_output.txt")).unwrap();
    scenario_results
        .into_iter()
        .for_each(|scenario_result| render_single_scenario(&mut file, scenario_result))
}

fn render_single_scenario(file: &mut File, scenario: ScenarioResult) {
    match scenario.result {
        Ok(positive) => render_positive_scenario(file, positive),
        Err(negative) => render_negative_scenario(file, negative),
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
    let adjusted_accounts = result.sorted_interpretable_adjustments;
    adjusted_accounts.into_iter().for_each(|account| {
        single_account_liner(
            file,
            account.initial_balance,
            account.debt_age_s,
            account.bill_coverage_in_percentage_opt,
        )
    })
}

const BALANCE_COLUMN_WIDTH: usize = 30;
const AGE_COLUMN_WIDTH: usize = 7;

fn single_account_liner(
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

fn render_negative_scenario(file: &mut File, negative_result: FailedAdjustment) {
    write_thick_dividing_line(file);
    render_scenario_header(
        file,
        negative_result.common.cw_service_fee_balance_minor,
        negative_result.common.required_adjustment,
    );
    write_thin_dividing_line(file);
    negative_result.account_infos.iter().for_each(|account| {
        single_account_liner(
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

fn generate_usize_guts(gn: &mut ThreadRng, low: usize, up_to: usize) -> usize {
    gn.gen_range(low..up_to)
}

fn generate_non_zero_usize(gn: &mut ThreadRng, up_to: usize) -> usize {
    generate_usize_guts(gn, 1, up_to)
}

fn generate_boolean(gn: &mut ThreadRng) -> bool {
    gn.gen()
}

// struct ResultTypesCounter {
//     oks: usize,
//     all_accounts_eliminated: usize,
//     other_errors: usize,
// }

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
