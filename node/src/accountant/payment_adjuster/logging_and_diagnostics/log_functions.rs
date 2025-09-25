// Copyright (c) 2023, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::db_access_objects::payable_dao::PayableAccount;
use crate::accountant::payment_adjuster::disqualification_arbiter::DisqualificationSuspectedAccount;
use itertools::Itertools;
use masq_lib::constants::WALLET_ADDRESS_LENGTH;
use masq_lib::logger::Logger;
use std::collections::HashMap;
use std::ops::Not;
use thousands::Separable;
use web3::types::{Address, U256};

const REFILL_RECOMMENDATION: &str = "\
Please be aware that abandoning your debts is going to result in delinquency bans. To consume \
services without limitations, you will need to place more funds into your consuming wallet.";
pub const LATER_DETECTED_SERVICE_FEE_SEVERE_SCARCITY: &str = "\
Passed successfully adjustment by transaction fee, then rechecked the service fee balance to be \
applied on the adjusted set, but discovered a shortage of MASQ not to suffice even for a single \
transaction. Operation is aborting.";

const EMPTY_STR: &str = "";

pub fn accounts_before_and_after_debug(
    original_account_balances_mapped: HashMap<Address, u128>,
    adjusted_accounts: &[PayableAccount],
) -> String {
    let excluded_wallets_and_balances =
        preprocess_excluded_accounts(&original_account_balances_mapped, adjusted_accounts);
    let excluded_accounts_summary_opt = excluded_wallets_and_balances.is_empty().not().then(|| {
        write_title_and_summary(
            &excluded_accounts_title(),
            &format_summary_for_excluded_accounts(&excluded_wallets_and_balances),
        )
    });
    let included_accounts_summary = write_title_and_summary(
        &included_accounts_title(),
        &format_summary_for_included_accounts(&original_account_balances_mapped, adjusted_accounts),
    );
    concatenate_summaries(included_accounts_summary, excluded_accounts_summary_opt)
}

fn included_accounts_title() -> String {
    format!(
        "{:<length$} {}\n\
         \n\
         {:<length$} {}\n\
         {:<length$} {}",
        "Payable Account",
        "Balance Wei",
        EMPTY_STR,
        "Original",
        EMPTY_STR,
        "Adjusted",
        length = WALLET_ADDRESS_LENGTH
    )
}

fn format_summary_for_included_accounts(
    original_account_balances_mapped: &HashMap<Address, u128>,
    adjusted_accounts: &[PayableAccount],
) -> String {
    adjusted_accounts
        .iter()
        .sorted_by(|account_a, account_b| {
            // Sorting in descending order
            Ord::cmp(&account_b.balance_wei, &account_a.balance_wei)
        })
        .map(|account| format_single_included_account(account, original_account_balances_mapped))
        .join("\n")
}

fn format_single_included_account(
    processed_account: &PayableAccount,
    original_account_balances_mapped: &HashMap<Address, u128>,
) -> String {
    let original_balance = original_account_balances_mapped
        .get(&processed_account.wallet.address())
        .expect("The hashmap should contain every wallet");

    format!(
        "{} {}\n{:^length$} {}",
        processed_account.wallet,
        original_balance.separate_with_commas(),
        EMPTY_STR,
        processed_account.balance_wei.separate_with_commas(),
        length = WALLET_ADDRESS_LENGTH
    )
}

fn excluded_accounts_title() -> String {
    format!(
        "{:<length$} Original",
        "Ruled Out Accounts",
        length = WALLET_ADDRESS_LENGTH
    )
}

fn preprocess_excluded_accounts(
    original_account_balances_mapped: &HashMap<Address, u128>,
    adjusted_accounts: &[PayableAccount],
) -> Vec<(Address, u128)> {
    let adjusted_accounts_wallets: Vec<Address> = adjusted_accounts
        .iter()
        .map(|account| account.wallet.address())
        .collect();
    original_account_balances_mapped
        .iter()
        .fold(vec![], |mut acc, (wallet, original_balance)| {
            if !adjusted_accounts_wallets.contains(wallet) {
                acc.push((*wallet, *original_balance));
            }
            acc
        })
}

fn format_summary_for_excluded_accounts(excluded: &[(Address, u128)]) -> String {
    excluded
        .iter()
        .sorted_by(|(_, balance_account_a), (_, balance_account_b)| {
            Ord::cmp(&balance_account_b, &balance_account_a)
        })
        .map(|(wallet, original_balance)| {
            format!("{:?} {}", wallet, original_balance.separate_with_commas())
        })
        .join("\n")
}

fn write_title_and_summary(title: &str, summary: &str) -> String {
    format!("\n{}\n\n{}", title, summary)
}

fn concatenate_summaries(
    adjusted_accounts_summary: String,
    excluded_accounts_summary_opt: Option<String>,
) -> String {
    vec![
        Some(adjusted_accounts_summary),
        excluded_accounts_summary_opt,
    ]
    .into_iter()
    .flatten()
    .join("\n")
}

pub fn info_log_for_disqualified_account(
    logger: &Logger,
    account: &DisqualificationSuspectedAccount,
) {
    info!(
        logger,
        "Ready payment to {:?} was eliminated to spare MASQ for those higher prioritized. {} wei \
        owed at the moment.",
        account.wallet,
        account.initial_account_balance_minor.separate_with_commas(),
    )
}

pub fn log_adjustment_by_service_fee_is_required(
    logger: &Logger,
    payables_sum: u128,
    cw_service_fee_balance: u128,
) {
    warning!(
        logger,
        "Mature payables amount to {} MASQ wei while the consuming wallet holds only {} wei. \
        Adjustment in their count or balances is necessary.",
        payables_sum.separate_with_commas(),
        cw_service_fee_balance.separate_with_commas()
    );
    info!(logger, "{}", REFILL_RECOMMENDATION)
}

pub fn log_insufficient_transaction_fee_balance(
    logger: &Logger,
    requested_tx_count: u16,
    feasible_tx_count: u16,
    txn_fee_required_per_txn_minor: u128,
    transaction_fee_minor: U256,
) {
    warning!(
        logger,
        "Transaction fee balance of {} wei cannot cover the anticipated {} wei for {} \
        transactions. Maximal count is set to {}. Adjustment must be performed.",
        transaction_fee_minor.separate_with_commas(),
        (requested_tx_count as u128 * txn_fee_required_per_txn_minor).separate_with_commas(),
        requested_tx_count,
        feasible_tx_count
    );
    info!(logger, "{}", REFILL_RECOMMENDATION)
}

pub fn log_transaction_fee_adjustment_ok_but_by_service_fee_undoable(logger: &Logger) {
    error!(logger, "{}", LATER_DETECTED_SERVICE_FEE_SEVERE_SCARCITY)
}

#[cfg(test)]
mod tests {
    use crate::accountant::payment_adjuster::logging_and_diagnostics::log_functions::{
        LATER_DETECTED_SERVICE_FEE_SEVERE_SCARCITY, REFILL_RECOMMENDATION,
    };

    #[test]
    fn constants_are_correct() {
        assert_eq!(
            REFILL_RECOMMENDATION,
            "Please be aware that abandoning your debts is going to result in delinquency bans. \
            To consume services without limitations, you will need to place more funds into \
            your consuming wallet."
        );
        assert_eq!(
            LATER_DETECTED_SERVICE_FEE_SEVERE_SCARCITY,
            "Passed successfully adjustment by transaction fee, then rechecked the service fee \
            balance to be applied on the adjusted set, but discovered a shortage of \
            MASQ not to suffice even for a single transaction. Operation is aborting."
        )
    }
}
