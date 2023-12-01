// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::db_access_objects::payable_dao::PayableAccount;
use crate::accountant::payment_adjuster::miscellaneous::helper_functions::{
    calculate_disqualification_edge, sum_as,
};
use crate::accountant::payment_adjuster::PaymentAdjusterError;
use itertools::Itertools;

pub struct MasqAdjustmentPossibilityVerifier {}

impl MasqAdjustmentPossibilityVerifier {
    pub fn verify_adjustment_possibility(
        &self,
        accounts: &[&PayableAccount],
        cw_service_fee_balance_minor: u128,
    ) -> Result<(), PaymentAdjusterError> {
        // The idea stands as the adjustment algorithm will have to proceed in each iteration by
        // eliminating the biggest account there as it always finds an account to disqualify,
        // reaching out the smallest one eventually; if the smallest one reduced by
        // the disqualification margin turns out to be still possibly paid out we can be sure
        // that this Node is going to realize at least one blockchain transaction
        let sorted = accounts
            .iter()
            .sorted_by(|account_a, account_b| {
                Ord::cmp(&account_a.balance_wei, &account_b.balance_wei)
            })
            .collect::<Vec<_>>();
        let smallest_account = sorted.first().expect("should be one at minimum");

        if calculate_disqualification_edge(smallest_account.balance_wei)
            <= cw_service_fee_balance_minor
        {
            Ok(())
        } else {
            let total_amount_demanded_minor = sum_as(accounts, |account| account.balance_wei);
            Err(
                PaymentAdjusterError::RiskOfWastefulAdjustmentWithAllAccountsEventuallyEliminated {
                    number_of_accounts: accounts.len(),
                    total_amount_demanded_minor,
                    cw_service_fee_balance_minor,
                },
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::accountant::db_access_objects::payable_dao::PayableAccount;
    use crate::accountant::payment_adjuster::miscellaneous::helper_functions::calculate_disqualification_edge;
    use crate::accountant::payment_adjuster::possibility_verifier::MasqAdjustmentPossibilityVerifier;
    use crate::accountant::payment_adjuster::PaymentAdjusterError;
    use crate::accountant::test_utils::make_payable_account;

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
        let cw_masq_balance = calculate_disqualification_edge(account_2.balance_wei) + 1;
        let original_accounts = vec![account_1, account_2];

        test_body_for_adjustment_possibility_nearly_rejected(original_accounts, cw_masq_balance)
    }

    #[test]
    fn adjustment_possibility_nearly_rejected_when_cw_balance_equal() {
        let mut account_1 = make_payable_account(111);
        account_1.balance_wei = 2_000_000_000;
        let mut account_2 = make_payable_account(333);
        account_2.balance_wei = 1_000_000_000;
        let cw_masq_balance = calculate_disqualification_edge(account_2.balance_wei);
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
        let cw_masq_balance = calculate_disqualification_edge(account_3.balance_wei) - 1;
        let original_accounts = vec![account_1, account_2, account_3];
        let accounts_in_expected_format =
            original_accounts.iter().collect::<Vec<&PayableAccount>>();
        let subject = MasqAdjustmentPossibilityVerifier {};

        let result =
            subject.verify_adjustment_possibility(&accounts_in_expected_format, cw_masq_balance);

        assert_eq!(
            result,
            Err(
                PaymentAdjusterError::RiskOfWastefulAdjustmentWithAllAccountsEventuallyEliminated {
                    number_of_accounts: 3,
                    total_amount_demanded_minor: 2_000_000_000 + 2_000_000_002 + 1_000_000_002,
                    cw_service_fee_balance_minor: cw_masq_balance
                }
            )
        )
    }
}
