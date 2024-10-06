// Copyright (c) 2023, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::payment_adjuster::criterion_calculators::CriterionCalculator;
use crate::accountant::payment_adjuster::inner::PaymentAdjusterInner;
use crate::accountant::QualifiedPayableAccount;

#[derive(Default)]
pub struct BalanceCriterionCalculator {}

impl CriterionCalculator for BalanceCriterionCalculator {
    fn calculate(
        &self,
        account: &QualifiedPayableAccount,
        context: &dyn PaymentAdjusterInner,
    ) -> u128 {
        let largest = context.largest_exceeding_balance_recently_qualified();

        let this_account =
            account.bare_account.balance_wei - account.payment_threshold_intercept_minor;
        let diff = largest - this_account;

        // We invert the magnitude of smaller debts, so they weight the most
        largest + diff
    }

    fn parameter_name(&self) -> &'static str {
        "BALANCE"
    }
}

#[cfg(test)]
mod tests {
    use crate::accountant::payment_adjuster::criterion_calculators::balance_calculator::BalanceCriterionCalculator;
    use crate::accountant::payment_adjuster::criterion_calculators::CriterionCalculator;
    use crate::accountant::payment_adjuster::inner::PaymentAdjusterInnerReal;
    use crate::accountant::payment_adjuster::miscellaneous::helper_functions::find_largest_exceeding_balance;
    use crate::accountant::payment_adjuster::test_utils::multiple_by_billion;
    use crate::accountant::test_utils::make_meaningless_analyzed_account;
    use std::time::SystemTime;

    #[test]
    fn calculator_knows_its_name() {
        let subject = BalanceCriterionCalculator::default();

        let result = subject.parameter_name();

        assert_eq!(result, "BALANCE")
    }

    #[test]
    fn balance_criterion_calculator_works() {
        let now = SystemTime::now();
        let analyzed_accounts = [50, 100, 2_222]
            .into_iter()
            .enumerate()
            .map(|(idx, n)| {
                let mut basic_analyzed_payable = make_meaningless_analyzed_account(idx as u64);
                basic_analyzed_payable.qualified_as.bare_account.balance_wei =
                    multiple_by_billion(n);
                basic_analyzed_payable
                    .qualified_as
                    .payment_threshold_intercept_minor = multiple_by_billion(2) * (idx as u128 + 1);
                basic_analyzed_payable
            })
            .collect::<Vec<_>>();
        let largest_exceeding_balance = find_largest_exceeding_balance(&analyzed_accounts);
        let payment_adjuster_inner =
            PaymentAdjusterInnerReal::new(now, None, 123456789, largest_exceeding_balance);
        let subject = BalanceCriterionCalculator::default();

        let computed_criteria = analyzed_accounts
            .iter()
            .map(|analyzed_account| {
                subject.calculate(&analyzed_account.qualified_as, &payment_adjuster_inner)
            })
            .collect::<Vec<_>>();

        let expected_values = vec![4_384_000_000_000, 4_336_000_000_000, 2_216_000_000_000];
        computed_criteria
            .into_iter()
            .zip(expected_values.into_iter())
            .for_each(|(actual_criterion, expected_criterion)| {
                assert_eq!(actual_criterion, expected_criterion)
            })
    }
}
