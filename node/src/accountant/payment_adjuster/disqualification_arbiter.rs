// Copyright (c) 2024, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::payment_adjuster::logging_and_diagnostics::diagnostics::ordinary_diagnostic_functions::{
    account_nominated_for_disqualification_diagnostics,
    try_finding_an_account_to_disqualify_diagnostics,
};
use crate::accountant::payment_adjuster::logging_and_diagnostics::log_functions::info_log_for_disqualified_account;
use crate::accountant::payment_adjuster::miscellaneous::data_structures::UnconfirmedAdjustment;
use crate::accountant::QualifiedPayableAccount;
use crate::sub_lib::wallet::Wallet;
use masq_lib::logger::Logger;
use std::cmp::Ordering;

pub struct DisqualificationArbiter {
    disqualification_gauge: Box<dyn DisqualificationGauge>,
}

impl Default for DisqualificationArbiter {
    fn default() -> Self {
        Self::new(Box::new(DisqualificationGaugeReal::default()))
    }
}

impl DisqualificationArbiter {
    pub fn new(disqualification_gauge: Box<dyn DisqualificationGauge>) -> Self {
        Self {
            disqualification_gauge,
        }
    }

    pub fn calculate_disqualification_edge(
        &self,
        qualified_payable: &QualifiedPayableAccount,
    ) -> u128 {
        let balance = qualified_payable.bare_account.balance_wei;
        let intercept = qualified_payable.payment_threshold_intercept_minor;
        let permanent_debt_allowed = qualified_payable
            .creditor_thresholds
            .permanent_debt_allowed_minor;

        self.disqualification_gauge
            .determine_limit(balance, intercept, permanent_debt_allowed)
    }

    pub fn find_an_account_to_disqualify_in_this_iteration(
        &self,
        unconfirmed_adjustments: &[UnconfirmedAdjustment],
        logger: &Logger,
    ) -> Wallet {
        let disqualification_suspected_accounts =
            Self::list_accounts_nominated_for_disqualification(unconfirmed_adjustments);

        let account_to_disqualify =
            Self::find_account_with_smallest_weight(&disqualification_suspected_accounts);

        let wallet = account_to_disqualify.wallet.clone();

        try_finding_an_account_to_disqualify_diagnostics(
            &disqualification_suspected_accounts,
            &wallet,
        );

        debug!(
            logger,
            "Found accounts {:?} applying for disqualification",
            disqualification_suspected_accounts,
        );

        info_log_for_disqualified_account(logger, account_to_disqualify);

        wallet
    }

    fn list_accounts_nominated_for_disqualification(
        unconfirmed_adjustments: &[UnconfirmedAdjustment],
    ) -> Vec<DisqualificationSuspectedAccount> {
        unconfirmed_adjustments
            .iter()
            .flat_map(|adjustment_info| {
                let disqualification_limit = adjustment_info.disqualification_limit_minor();
                let proposed_adjusted_balance = adjustment_info.proposed_adjusted_balance_minor;

                if proposed_adjusted_balance < disqualification_limit {
                    account_nominated_for_disqualification_diagnostics(
                        adjustment_info,
                        proposed_adjusted_balance,
                        disqualification_limit,
                    );

                    let suspected_account: DisqualificationSuspectedAccount =
                        adjustment_info.into();

                    Some(suspected_account)
                } else {
                    None
                }
            })
            .collect()
    }

    fn find_account_with_smallest_weight<'accounts>(
        accounts: &'accounts [DisqualificationSuspectedAccount],
    ) -> &'accounts DisqualificationSuspectedAccount<'accounts> {
        let first_account = accounts.first().expect("collection was empty");
        accounts.iter().fold(
            first_account,
            |with_smallest_weight_so_far, current| match Ord::cmp(
                &current.weight,
                &with_smallest_weight_so_far.weight,
            ) {
                Ordering::Less => current,
                Ordering::Greater => with_smallest_weight_so_far,
                Ordering::Equal => with_smallest_weight_so_far,
            },
        )
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct DisqualificationSuspectedAccount<'account> {
    pub wallet: &'account Wallet,
    pub weight: u128,
    // The rest is for an INFO log
    pub proposed_adjusted_balance_minor: u128,
    pub disqualification_limit_minor: u128,
}

impl<'unconfirmed_accounts> From<&'unconfirmed_accounts UnconfirmedAdjustment>
    for DisqualificationSuspectedAccount<'unconfirmed_accounts>
{
    fn from(unconfirmed_account: &'unconfirmed_accounts UnconfirmedAdjustment) -> Self {
        DisqualificationSuspectedAccount {
            wallet: unconfirmed_account.wallet(),
            weight: unconfirmed_account.weighted_account.weight,
            proposed_adjusted_balance_minor: unconfirmed_account.proposed_adjusted_balance_minor,
            disqualification_limit_minor: unconfirmed_account.disqualification_limit_minor(),
        }
    }
}

pub trait DisqualificationGauge {
    fn determine_limit(
        &self,
        account_balance_wei: u128,
        threshold_intercept_wei: u128,
        permanent_debt_allowed_wei: u128,
    ) -> u128;
}

#[derive(Default)]
pub struct DisqualificationGaugeReal {}

impl DisqualificationGauge for DisqualificationGaugeReal {
    fn determine_limit(
        &self,
        account_balance_minor: u128,
        threshold_intercept_minor: u128,
        permanent_debt_allowed_minor: u128,
    ) -> u128 {
        if threshold_intercept_minor == permanent_debt_allowed_minor {
            return account_balance_minor;
        }
        let exceeding_debt_part = account_balance_minor - threshold_intercept_minor;
        if DisqualificationGaugeReal::qualifies_for_double_margin(
            account_balance_minor,
            threshold_intercept_minor,
            permanent_debt_allowed_minor,
        ) {
            exceeding_debt_part + 2 * permanent_debt_allowed_minor
        } else {
            exceeding_debt_part + permanent_debt_allowed_minor
        }
    }
}

impl DisqualificationGaugeReal {
    const FIRST_CONDITION_COEFFICIENT: u128 = 2;
    const SECOND_CONDITION_COEFFICIENT: u128 = 2;
    fn qualifies_for_double_margin(
        account_balance_minor: u128,
        threshold_intercept_minor: u128,
        permanent_debt_allowed_minor: u128,
    ) -> bool {
        let exceeding_threshold = account_balance_minor - threshold_intercept_minor;
        let considered_forgiven = threshold_intercept_minor - permanent_debt_allowed_minor;
        let minimal_payment_accepted = exceeding_threshold + permanent_debt_allowed_minor;

        let first_condition =
            minimal_payment_accepted >= Self::FIRST_CONDITION_COEFFICIENT * considered_forgiven;

        let second_condition = considered_forgiven
            >= Self::SECOND_CONDITION_COEFFICIENT * permanent_debt_allowed_minor;

        first_condition && second_condition
    }
}

#[cfg(test)]
mod tests {
    use crate::accountant::db_access_objects::payable_dao::PayableAccount;
    use crate::accountant::db_access_objects::utils::from_time_t;
    use crate::accountant::payment_adjuster::disqualification_arbiter::{
        DisqualificationArbiter, DisqualificationGauge, DisqualificationGaugeReal,
        DisqualificationSuspectedAccount,
    };
    use crate::accountant::payment_adjuster::miscellaneous::data_structures::UnconfirmedAdjustment;
    use crate::accountant::payment_adjuster::miscellaneous::helper_functions::find_largest_exceeding_balance;
    use crate::accountant::payment_adjuster::service_fee_adjuster::AdjustmentComputer;
    use crate::accountant::payment_adjuster::test_utils::{
        make_initialized_subject, make_non_guaranteed_unconfirmed_adjustment,
    };
    use crate::accountant::test_utils::make_guaranteed_qualified_payables;
    use crate::sub_lib::accountant::PaymentThresholds;
    use crate::test_utils::make_wallet;
    use masq_lib::logger::Logger;
    use masq_lib::utils::convert_collection;
    use std::time::SystemTime;

    #[test]
    fn constants_are_correct() {
        assert_eq!(DisqualificationGaugeReal::FIRST_CONDITION_COEFFICIENT, 2);
        assert_eq!(DisqualificationGaugeReal::SECOND_CONDITION_COEFFICIENT, 2)
    }

    #[test]
    fn qualifies_for_double_margin_granted_on_both_conditions_returning_equals() {
        let account_balance_minor = 6_000_000_000;
        let threshold_intercept_minor = 3_000_000_000;
        let permanent_debt_allowed_minor = 1_000_000_000;

        let result = DisqualificationGaugeReal::qualifies_for_double_margin(
            account_balance_minor,
            threshold_intercept_minor,
            permanent_debt_allowed_minor,
        );

        assert_eq!(result, true)
    }

    #[test]
    fn qualifies_for_double_margin_granted_on_first_condition_bigger_second_equal() {
        let account_balance_minor = 6_000_000_001;
        let threshold_intercept_minor = 3_000_000_000;
        let permanent_debt_allowed_minor = 1_000_000_000;

        let result = DisqualificationGaugeReal::qualifies_for_double_margin(
            account_balance_minor,
            threshold_intercept_minor,
            permanent_debt_allowed_minor,
        );

        assert_eq!(result, true)
    }

    #[test]
    fn qualifies_for_double_margin_granted_on_first_condition_equal_second_bigger() {
        let account_balance_minor = 6_000_000_003;
        let threshold_intercept_minor = 3_000_000_001;
        let permanent_debt_allowed_minor = 1_000_000_000;

        let result = DisqualificationGaugeReal::qualifies_for_double_margin(
            account_balance_minor,
            threshold_intercept_minor,
            permanent_debt_allowed_minor,
        );

        assert_eq!(result, true)
    }

    #[test]
    fn qualifies_for_double_margin_granted_on_both_conditions_returning_bigger() {
        let account_balance_minor = 6_000_000_004;
        let threshold_intercept_minor = 3_000_000_001;
        let permanent_debt_allowed_minor = 1_000_000_000;

        let result = DisqualificationGaugeReal::qualifies_for_double_margin(
            account_balance_minor,
            threshold_intercept_minor,
            permanent_debt_allowed_minor,
        );

        assert_eq!(result, true)
    }

    #[test]
    fn qualifies_for_double_margin_declined_on_first_condition() {
        let account_balance_minor = 5_999_999_999;
        let threshold_intercept_minor = 3_000_000_000;
        let permanent_debt_allowed_minor = 1_000_000_000;

        let result = DisqualificationGaugeReal::qualifies_for_double_margin(
            account_balance_minor,
            threshold_intercept_minor,
            permanent_debt_allowed_minor,
        );

        assert_eq!(result, false)
    }

    #[test]
    fn qualifies_for_double_margin_declined_on_second_condition() {
        let account_balance_minor = 6_000_000_000;
        let threshold_intercept_minor = 2_999_999_999;
        let permanent_debt_allowed_minor = 1_000_000_000;

        let result = DisqualificationGaugeReal::qualifies_for_double_margin(
            account_balance_minor,
            threshold_intercept_minor,
            permanent_debt_allowed_minor,
        );

        assert_eq!(result, false)
    }

    #[test]
    fn calculate_disqualification_edge_in_the_horizontal_thresholds_area() {
        let balance_minor = 30_000_000_000;
        let threshold_intercept_minor = 4_000_000_000;
        let permanent_debt_allowed_minor = 4_000_000_000;
        let subject = DisqualificationGaugeReal::default();

        let result = subject.determine_limit(
            balance_minor,
            threshold_intercept_minor,
            permanent_debt_allowed_minor,
        );

        assert_eq!(result, 30_000_000_000)
    }

    #[test]
    fn calculate_disqualification_edge_in_the_tilted_thresholds_area_with_normal_margin() {
        let balance_minor = 6_000_000_000;
        let threshold_intercept_minor = 4_000_000_000;
        let permanent_debt_allowed_minor = 1_000_000_000;
        let subject = DisqualificationGaugeReal::default();

        let result = subject.determine_limit(
            balance_minor,
            threshold_intercept_minor,
            permanent_debt_allowed_minor,
        );

        assert_eq!(result, (6_000_000_000 - 4_000_000_000) + 1_000_000_000)
    }

    #[test]
    fn calculate_disqualification_edge_in_the_tilted_thresholds_area_with_double_margin() {
        let balance_minor = 30_000_000_000;
        let threshold_intercept_minor = 4_000_000_000;
        let permanent_debt_allowed_minor = 1_000_000_000;
        let subject = DisqualificationGaugeReal::default();

        let result = subject.determine_limit(
            balance_minor,
            threshold_intercept_minor,
            permanent_debt_allowed_minor,
        );

        assert_eq!(
            result,
            (30_000_000_000 - 4_000_000_000) + (2 * 1_000_000_000)
        )
    }

    #[test]
    fn list_accounts_nominated_for_disqualification_ignores_adjustment_even_to_the_dsq_limit() {
        let mut account = make_non_guaranteed_unconfirmed_adjustment(444);
        account.proposed_adjusted_balance_minor = 1_000_000_000;
        account
            .weighted_account
            .analyzed_account
            .disqualification_limit_minor = 1_000_000_000;
        let accounts = vec![account];

        let result =
            DisqualificationArbiter::list_accounts_nominated_for_disqualification(&accounts);

        assert!(result.is_empty())
    }

    #[test]
    fn find_account_with_smallest_weight_works_for_unequal_weights() {
        let adjustments = make_unconfirmed_adjustments(vec![1004, 1000, 1002, 1001]);
        let dsq_suspected_accounts = make_dsq_suspected_accounts(&adjustments);

        let result =
            DisqualificationArbiter::find_account_with_smallest_weight(&dsq_suspected_accounts);

        let expected_result = &dsq_suspected_accounts[1];
        assert_eq!(result, expected_result)
    }

    #[test]
    fn find_account_with_smallest_weight_for_equal_weights_chooses_the_first_of_the_same_size() {
        let adjustments = make_unconfirmed_adjustments(vec![1111, 1113, 1111]);
        let dsq_suspected_accounts = make_dsq_suspected_accounts(&adjustments);

        let result =
            DisqualificationArbiter::find_account_with_smallest_weight(&dsq_suspected_accounts);

        let expected_result = &dsq_suspected_accounts[0];
        assert_eq!(result, expected_result)
    }

    #[test]
    fn only_account_with_the_smallest_weight_will_be_disqualified_in_single_iteration() {
        let test_name =
            "only_account_with_the_smallest_weight_will_be_disqualified_in_single_iteration";
        let now = SystemTime::now();
        let cw_service_fee_balance_minor = 200_000_000_000;
        let mut payment_thresholds = PaymentThresholds::default();
        payment_thresholds.permanent_debt_allowed_gwei = 10;
        payment_thresholds.maturity_threshold_sec = 1_000;
        payment_thresholds.threshold_interval_sec = 10_000;
        let logger = Logger::new(test_name);
        let wallet_1 = make_wallet("abc");
        let common_timestamp = from_time_t(
            (payment_thresholds.maturity_threshold_sec
                + payment_thresholds.threshold_interval_sec
                + 1) as i64,
        );
        let account_1 = PayableAccount {
            wallet: wallet_1.clone(),
            balance_wei: 120_000_000_000 + 1,
            last_paid_timestamp: common_timestamp,
            pending_payable_opt: None,
        };
        let wallet_2 = make_wallet("def");
        let account_2 = PayableAccount {
            wallet: wallet_2.clone(),
            balance_wei: 120_000_000_000,
            last_paid_timestamp: common_timestamp,
            pending_payable_opt: None,
        };
        let wallet_3 = make_wallet("ghi");
        // This account has the largest exceeding balance and therefore has the smallest weight
        let account_3 = PayableAccount {
            wallet: wallet_3.clone(),
            balance_wei: 120_000_000_000 + 2,
            last_paid_timestamp: common_timestamp,
            pending_payable_opt: None,
        };
        let wallet_4 = make_wallet("jkl");
        let account_4 = PayableAccount {
            wallet: wallet_4.clone(),
            balance_wei: 120_000_000_000 - 1,
            last_paid_timestamp: common_timestamp,
            pending_payable_opt: None,
        };
        let accounts = vec![account_1, account_2, account_3, account_4];
        let qualified_payables =
            make_guaranteed_qualified_payables(accounts, &payment_thresholds, now);
        let analyzed_accounts = convert_collection(qualified_payables);
        let largest_exceeding_balance = find_largest_exceeding_balance(&analyzed_accounts);
        let payment_adjuster = make_initialized_subject(
            Some(now),
            Some(cw_service_fee_balance_minor),
            None,
            Some(largest_exceeding_balance),
            None,
        );
        let weights_and_accounts = payment_adjuster.calculate_weights(analyzed_accounts);
        let subject = DisqualificationArbiter::default();
        let unconfirmed_adjustments = AdjustmentComputer::default()
            .compute_unconfirmed_adjustments(weights_and_accounts, cw_service_fee_balance_minor);

        let result = subject
            .find_an_account_to_disqualify_in_this_iteration(&unconfirmed_adjustments, &logger);

        unconfirmed_adjustments.iter().for_each(|payable| {
            // Condition of disqualification at the horizontal threshold
            assert!(payable.proposed_adjusted_balance_minor < 120_000_000_000)
        });
        assert_eq!(result, wallet_3);
    }

    fn make_unconfirmed_adjustments(weights: Vec<u128>) -> Vec<UnconfirmedAdjustment> {
        weights
            .into_iter()
            .enumerate()
            .map(|(idx, weight)| {
                let mut account = make_non_guaranteed_unconfirmed_adjustment(idx as u64);
                account.weighted_account.weight = weight;
                account
            })
            .collect()
    }

    fn make_dsq_suspected_accounts(
        accounts_and_dsq_edges: &[UnconfirmedAdjustment],
    ) -> Vec<DisqualificationSuspectedAccount> {
        let with_referred_accounts: Vec<&UnconfirmedAdjustment> =
            accounts_and_dsq_edges.iter().collect();
        convert_collection(with_referred_accounts)
    }
}
