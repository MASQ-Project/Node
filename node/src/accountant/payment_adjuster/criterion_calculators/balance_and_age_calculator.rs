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
        let now = context.now();
        let debt_age_s = now
            .duration_since(account.payable.last_paid_timestamp)
            .expect("time traveller")
            .as_secs();
        (account.payable.balance_wei - account.payment_threshold_intercept_minor
            + debt_age_s as u128)
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
        let qualified_accounts = [0, 10, 22]
            .into_iter()
            .map(|n| make_non_guaranteed_qualified_payable(n))
            .collect::<Vec<_>>();
        let payment_adjuster_inner = PaymentAdjusterInnerReal::new(now, None, 123456789);
        let subject = BalanceAndAgeCriterionCalculator::default();

        let computed_criteria = qualified_accounts
            .iter()
            .map(|qualified_account| subject.calculate(qualified_account, &payment_adjuster_inner))
            .collect::<Vec<_>>();

        let zipped = qualified_accounts
            .into_iter()
            .zip(computed_criteria.into_iter());
        zipped.into_iter().for_each(|(account, actual_criterion)| {
            let debt_age_s = now
                .duration_since(account.payable.last_paid_timestamp)
                .unwrap()
                .as_secs();
            let expected_criterion = account.payable.balance_wei
                - account.payment_threshold_intercept_minor
                + debt_age_s as u128;
            assert_eq!(actual_criterion, expected_criterion)
        })
    }
}
