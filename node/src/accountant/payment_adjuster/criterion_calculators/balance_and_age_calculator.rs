// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::payment_adjuster::criterion_calculators::CriterionCalculator;
use crate::accountant::payment_adjuster::inner::PaymentAdjusterInner;
use crate::accountant::QualifiedPayableAccount;

#[derive(Default)]
pub struct BalanceAndAgeCriterionCalculator {}

impl CriterionCalculator for BalanceAndAgeCriterionCalculator {
    fn calculate(
        &self,
        account: &QualifiedPayableAccount,
        context: &dyn PaymentAdjusterInner,
    ) -> u128 {
        let largest = context.largest_exceeding_balance_recently_qualified();

        let this_account =
            account.bare_account.balance_wei - account.payment_threshold_intercept_minor;
        let diff = largest - this_account;

        // We invert the magnitude for smaller debts
        largest + diff
    }

    fn parameter_name(&self) -> &'static str {
        "BALANCE AND AGE"
    }
}

#[cfg(test)]
mod tests {
    use crate::accountant::payment_adjuster::criterion_calculators::balance_and_age_calculator::BalanceAndAgeCriterionCalculator;
    use crate::accountant::payment_adjuster::criterion_calculators::CriterionCalculator;
    use crate::accountant::payment_adjuster::inner::PaymentAdjusterInnerReal;
    use crate::accountant::payment_adjuster::miscellaneous::helper_functions::find_largest_exceeding_balance;
    use crate::accountant::payment_adjuster::test_utils::multiple_by_billion;
    use crate::accountant::test_utils::make_non_guaranteed_qualified_payable;
    use std::time::SystemTime;

    #[test]
    fn calculator_knows_its_name() {
        let subject = BalanceAndAgeCriterionCalculator::default();

        let result = subject.parameter_name();

        assert_eq!(result, "BALANCE AND AGE")
    }

    #[test]
    fn balance_and_age_criterion_calculator_works() {
        let now = SystemTime::now();
        let qualified_accounts = [50, 100, 2_222]
            .into_iter()
            .enumerate()
            .map(|(idx, n)| {
                let mut basic_q_payable = make_non_guaranteed_qualified_payable(idx as u64);
                basic_q_payable.bare_account.balance_wei = multiple_by_billion(n);
                basic_q_payable.payment_threshold_intercept_minor =
                    (multiple_by_billion(2) / 5) * 3;
                basic_q_payable
            })
            .collect::<Vec<_>>();
        let largest_exceeding_balance = find_largest_exceeding_balance(&qualified_accounts);
        let payment_adjuster_inner =
            PaymentAdjusterInnerReal::new(now, None, 123456789, largest_exceeding_balance);
        let subject = BalanceAndAgeCriterionCalculator::default();

        let computed_criteria = qualified_accounts
            .iter()
            .map(|qualified_account| subject.calculate(qualified_account, &payment_adjuster_inner))
            .collect::<Vec<_>>();

        let zipped = qualified_accounts
            .into_iter()
            .zip(computed_criteria.into_iter());
        zipped.into_iter().for_each(|(account, actual_criterion)| {
            let expected_criterion = {
                let exceeding_balance_on_this_account =
                    account.bare_account.balance_wei - account.payment_threshold_intercept_minor;
                let diff = largest_exceeding_balance - exceeding_balance_on_this_account;
                largest_exceeding_balance + diff
            };
            assert_eq!(actual_criterion, expected_criterion)
        })
    }
}
