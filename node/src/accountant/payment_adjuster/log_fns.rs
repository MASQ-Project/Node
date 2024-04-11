// Copyright (c) 2023, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::db_access_objects::payable_dao::PayableAccount;
use crate::accountant::payment_adjuster::disqualification_arbiter::DisqualificationSuspectedAccount;
use crate::masq_lib::utils::ExpectValue;
use crate::sub_lib::wallet::Wallet;
use itertools::Itertools;
use masq_lib::constants::WALLET_ADDRESS_LENGTH;
use masq_lib::logger::Logger;
use std::collections::HashMap;
use std::iter::once;
use std::ops::Not;
use thousands::Separable;
use web3::types::U256;

const REFILL_RECOMMENDATION: &str = "\
Please be aware that abandoning your debts is going to result in delinquency bans. In order to \
consume services without limitations, you will need to place more funds into your consuming wallet.";
const LATER_DETECTED_SERVICE_FEE_SEVERE_SCARCITY: &str = "\
Passed successfully adjustment by transaction fee, but by a second look, noticing of critical \
shortage of MASQ balance. Operation will abort.";

const BLANK_SPACE: &str = "";

pub fn format_brief_adjustment_summary(
    original_account_balances_mapped: HashMap<Wallet, u128>,
    adjusted_accounts: &[PayableAccount],
) -> String {
    fn format_summary_for_included_accounts(
        original_account_balances_mapped: &HashMap<Wallet, u128>,
        adjusted_accounts: &[PayableAccount],
    ) -> String {
        adjusted_accounts
            .iter()
            .sorted_by(|account_a, account_b| {
                Ord::cmp(&account_b.balance_wei, &account_a.balance_wei)
            })
            .map(|account| {
                format!(
                    "{} {}\n{:^length$} {}",
                    account.wallet,
                    original_account_balances_mapped
                        .get(&account.wallet)
                        .expectv("initial balance")
                        .separate_with_commas(),
                    BLANK_SPACE,
                    account.balance_wei.separate_with_commas(),
                    length = WALLET_ADDRESS_LENGTH
                )
            })
            .join("\n")
    }
    fn format_summary_for_excluded_accounts(excluded: &[(&Wallet, u128)]) -> String {
        let title = once(format!(
            "\n{:<length$} Original\n",
            "Ruled Out Accounts",
            length = WALLET_ADDRESS_LENGTH
        ));
        let list = excluded
            .iter()
            .sorted_by(|(_, balance_account_a), (_, balance_account_b)| {
                Ord::cmp(&balance_account_b, &balance_account_a)
            })
            .map(|(wallet, original_balance)| {
                format!("{} {}", wallet, original_balance.separate_with_commas())
            });
        title.chain(list).join("\n")
    }

    let adjusted_accounts_wallets: Vec<&Wallet> = adjusted_accounts
        .iter()
        .map(|account| &account.wallet)
        .collect();
    let excluded: Vec<(&Wallet, u128)> = original_account_balances_mapped.iter().fold(
        vec![],
        |mut acc, (wallet, original_balance)| {
            if !adjusted_accounts_wallets.contains(&wallet) {
                acc.push((wallet, *original_balance));
            }
            acc
        },
    );
    let adjusted_accounts_summary =
        format_summary_for_included_accounts(&original_account_balances_mapped, adjusted_accounts);
    let excluded_accounts_summary_opt = excluded
        .is_empty()
        .not()
        .then(|| format_summary_for_excluded_accounts(&excluded));
    vec![
        Some(adjusted_accounts_summary),
        excluded_accounts_summary_opt,
    ]
    .into_iter()
    .flatten()
    .join("\n")
}

pub fn accounts_before_and_after_debug(
    original_account_balances_mapped: HashMap<Wallet, u128>,
    adjusted_accounts: &[PayableAccount],
) -> String {
    format!(
        "\n\
            {:<length$} {}\n\
            \n\
            {:<length$} {}\n\
            {:<length$} {}\n\
            \n\
            {}",
        "Payable Account",
        "Balance Wei",
        BLANK_SPACE,
        "Original",
        BLANK_SPACE,
        "Adjusted",
        format_brief_adjustment_summary(original_account_balances_mapped, adjusted_accounts),
        length = WALLET_ADDRESS_LENGTH
    )
}

pub fn info_log_for_disqualified_account(
    logger: &Logger,
    account: &DisqualificationSuspectedAccount,
) {
    info!(
        logger,
        "Shortage of MASQ in your consuming wallet will impact payable {}, ruled out from this \
        round of payments. The proposed adjustment {} wei was below the disqualification limit \
        {} wei",
        account.wallet,
        account
            .proposed_adjusted_balance_minor
            .separate_with_commas(),
        account.disqualification_edge.separate_with_commas()
    )
}

pub fn log_adjustment_by_service_fee_is_required(
    logger: &Logger,
    payables_sum: u128,
    cw_service_fee_balance: u128,
) {
    warning!(
        logger,
        "Total of {} wei in MASQ was ordered while the consuming wallet held only {} wei of \
        the MASQ token. Adjustment in their count or the amounts is required.",
        payables_sum.separate_with_commas(),
        cw_service_fee_balance.separate_with_commas()
    );
    info!(logger, "{}", REFILL_RECOMMENDATION)
}

pub fn log_insufficient_transaction_fee_balance(
    logger: &Logger,
    required_transactions_count: u16,
    transaction_fee_minor: U256,
    limiting_count: u16,
) {
    warning!(
        logger,
        "Transaction fee amount {} wei from your wallet will not cover anticipated \
        fees to send {} transactions. Maximum is {}. The payments count needs to be \
        adjusted.",
        transaction_fee_minor.separate_with_commas(),
        required_transactions_count,
        limiting_count
    );
    info!(logger, "{}", REFILL_RECOMMENDATION)
}

pub fn log_transaction_fee_adjustment_ok_but_by_service_fee_undoable(logger: &Logger) {
    error!(logger, "{}", LATER_DETECTED_SERVICE_FEE_SEVERE_SCARCITY)
}

#[cfg(test)]
mod tests {
    use crate::accountant::payment_adjuster::disqualification_arbiter::DisqualificationSuspectedAccount;
    use crate::accountant::payment_adjuster::log_fns::{
        info_log_for_disqualified_account, LATER_DETECTED_SERVICE_FEE_SEVERE_SCARCITY,
        REFILL_RECOMMENDATION,
    };
    use crate::test_utils::make_wallet;
    use masq_lib::logger::Logger;
    use masq_lib::test_utils::logging::{init_test_logging, TestLogHandler};

    #[test]
    fn constants_are_correct() {
        assert_eq!(
            REFILL_RECOMMENDATION,
            "Please be aware that abandoning your debts is going to result in delinquency bans. In \
            order to consume services without limitations, you will need to place more funds into \
            your consuming wallet."
        );
        assert_eq!(
            LATER_DETECTED_SERVICE_FEE_SEVERE_SCARCITY,
            "Passed successfully adjustment by transaction fee, but by a second look, noticing of \
            critical shortage of MASQ balance. Operation will abort."
        )
    }

    #[test]
    fn disqualification_log_properly_formatted() {
        init_test_logging();
        let test_name = "disqualification_log_properly_formatted";
        let logger = Logger::new(test_name);
        let wallet = make_wallet("aaa");
        let disqualified_account = DisqualificationSuspectedAccount {
            wallet: &wallet,
            weight: 0,
            proposed_adjusted_balance_minor: 1_555_666_777,
            disqualification_edge: 2_000_000_000,
        };

        info_log_for_disqualified_account(&logger, &disqualified_account);

        TestLogHandler::new().exists_log_containing(&format!(
            "INFO: {}: Shortage of MASQ \
        in your consuming wallet will impact payable 0x0000000000000000000000000000000000616161, \
        ruled out from this round of payments. The proposed adjustment 1,555,666,777 wei was \
        below the disqualification limit 2,000,000,000 wei",
            test_name
        ));
    }
}
