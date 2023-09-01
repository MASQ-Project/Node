// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::database_access_objects::payable_dao::PayableAccount;
use crate::accountant::payment_adjuster::miscellaneous::helper_functions::ACCOUNT_INSIGNIFICANCE_BY_PERCENTAGE;
use crate::accountant::payment_adjuster::{AnalysisError, PaymentAdjusterError};
use crate::masq_lib::utils::ExpectValue;
use itertools::Itertools;

pub struct MasqAdjustmentPossibilityVerifier {}

impl MasqAdjustmentPossibilityVerifier {
    pub fn verify_adjustment_possibility(
        &self,
        accounts: &[&PayableAccount],
        cw_masq_balance_minor: u128,
    ) -> Result<(), PaymentAdjusterError> {
        // The reasoning is that the real adjustment algorithm will proceed by eliminating the biggest
        // account in each iteration, reaching out the smallest one eventually; if the smallest one
        // reduced by the disqualification margin turned out possible to be paid by the available
        // balance, we can state the Node is going to perform at least one blockchain transaction

        let sorted = accounts
            .iter()
            .sorted_by(|account_b, account_a| {
                Ord::cmp(&account_b.balance_wei, &account_a.balance_wei)
            })
            .collect::<Vec<_>>();
        let smallest_account = sorted.first().expectv("qualified payable account");

        if (smallest_account.balance_wei * ACCOUNT_INSIGNIFICANCE_BY_PERCENTAGE.multiplier)
            / ACCOUNT_INSIGNIFICANCE_BY_PERCENTAGE.divisor
            <= cw_masq_balance_minor
        {
            Ok(())
        } else {
            Err(PaymentAdjusterError::AnalysisError(
                AnalysisError::RiskOfWastedAdjustmentWithAllAccountsEventuallyEliminated {
                    number_of_accounts: accounts.len(),
                    cw_masq_balance_minor,
                },
            ))
        }
    }

    fn calculate_breaking_line(account_balance: u128) -> u128 {
        (ACCOUNT_INSIGNIFICANCE_BY_PERCENTAGE.multiplier * account_balance)
            / ACCOUNT_INSIGNIFICANCE_BY_PERCENTAGE.divisor
    }
}

#[cfg(test)]
mod tests {
    use crate::accountant::database_access_objects::payable_dao::PayableAccount;
    use crate::accountant::payment_adjuster::miscellaneous::helper_functions::ACCOUNT_INSIGNIFICANCE_BY_PERCENTAGE;
    use crate::accountant::payment_adjuster::verifier::MasqAdjustmentPossibilityVerifier;
    use crate::accountant::payment_adjuster::{AnalysisError, PaymentAdjusterError};
    use crate::accountant::test_utils::make_payable_account;

    #[test]
    fn calculate_breaking_line_works() {
        let mut account = make_payable_account(111);
        account.balance_wei = 300_000_000;

        let result =
            MasqAdjustmentPossibilityVerifier::calculate_breaking_line(account.balance_wei);

        assert_eq!(
            result,
            (ACCOUNT_INSIGNIFICANCE_BY_PERCENTAGE.multiplier * account.balance_wei)
                / ACCOUNT_INSIGNIFICANCE_BY_PERCENTAGE.divisor
        )
    }

    fn test_body_for_adjustment_possibility_nearly_rejected(
        original_accounts: Vec<PayableAccount>,
        cw_masq_balance: u128,
    ) {
        let accounts_in_expected_format =
            original_accounts.iter().collect::<Vec<&PayableAccount>>();
        let subject = MasqAdjustmentPossibilityVerifier {};

        let result =
            subject.verify_adjustment_possibility(&accounts_in_expected_format, cw_masq_balance);

        assert_eq!(result, Ok(()))
    }

    #[test]
    fn adjustment_possibility_nearly_rejected_when_cw_balance_one_more() {
        let mut account_1 = make_payable_account(111);
        account_1.balance_wei = 2_000_000_000;
        let mut account_2 = make_payable_account(333);
        account_2.balance_wei = 1_000_000_000;
        let cw_masq_balance =
            MasqAdjustmentPossibilityVerifier::calculate_breaking_line(account_2.balance_wei) + 1;
        let original_accounts = vec![account_1, account_2];

        test_body_for_adjustment_possibility_nearly_rejected(original_accounts, cw_masq_balance)
    }

    #[test]
    fn adjustment_possibility_nearly_rejected_when_cw_balance_equal() {
        let mut account_1 = make_payable_account(111);
        account_1.balance_wei = 2_000_000_000;
        let mut account_2 = make_payable_account(333);
        account_2.balance_wei = 1_000_000_000;
        let cw_masq_balance =
            MasqAdjustmentPossibilityVerifier::calculate_breaking_line(account_2.balance_wei);
        let original_accounts = vec![account_1, account_2];

        test_body_for_adjustment_possibility_nearly_rejected(original_accounts, cw_masq_balance)
    }

    #[test]
    fn adjustment_possibility_err_from_insufficient_balance_for_at_least_single_account_adjustment()
    {
        let mut account_1 = make_payable_account(111);
        account_1.balance_wei = 2_000_000_000;
        let mut account_2 = make_payable_account(222);
        account_2.balance_wei = 2_000_000_002;
        let mut account_3 = make_payable_account(333);
        account_3.balance_wei = 1_000_000_002;
        let cw_masq_balance =
            MasqAdjustmentPossibilityVerifier::calculate_breaking_line(account_3.balance_wei) - 1;
        let original_accounts = vec![account_1, account_2, account_3];
        let accounts_in_expected_format =
            original_accounts.iter().collect::<Vec<&PayableAccount>>();
        let subject = MasqAdjustmentPossibilityVerifier {};

        let result =
            subject.verify_adjustment_possibility(&accounts_in_expected_format, cw_masq_balance);

        assert_eq!(
            result,
            Err(PaymentAdjusterError::AnalysisError(
                AnalysisError::RiskOfWastedAdjustmentWithAllAccountsEventuallyEliminated {
                    number_of_accounts: 3,
                    cw_masq_balance_minor: cw_masq_balance
                }
            ))
        )
    }
}
