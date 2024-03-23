// Copyright (c) 2024, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::payment_adjuster::diagnostics::ordinary_diagnostic_functions::{
    account_nominated_for_disqualification_diagnostics,
    try_finding_an_account_to_disqualify_diagnostics,
};
use crate::accountant::payment_adjuster::log_fns::info_log_for_disqualified_account;
use crate::accountant::payment_adjuster::miscellaneous::data_structures::{
    AdjustedAccountBeforeFinalization, UnconfirmedAdjustment,
};
use crate::accountant::QualifiedPayableAccount;
use crate::sub_lib::wallet::Wallet;
use masq_lib::logger::Logger;
use std::cmp::Ordering;

pub struct DisqualificationArbiter {
    disqualification_gauge: Box<dyn DisqualificationGauge>,
}

impl DisqualificationArbiter {
    pub fn new(dsq_edge_detector: Box<dyn DisqualificationGauge>) -> Self {
        todo!()
    }
    pub fn try_finding_an_account_to_disqualify_in_this_iteration(
        &self,
        unconfirmed_adjustments: &[UnconfirmedAdjustment],
        logger: &Logger,
    ) -> Option<Wallet> {
        let disqualification_suspected_accounts =
            self.list_accounts_nominated_for_disqualification(unconfirmed_adjustments);

        if !disqualification_suspected_accounts.is_empty() {
            let account_to_disqualify =
                Self::find_account_with_smallest_weight(&disqualification_suspected_accounts);

            let wallet = account_to_disqualify
                .original_qualified_account
                .payable
                .wallet
                .clone();

            try_finding_an_account_to_disqualify_diagnostics(
                &disqualification_suspected_accounts,
                &wallet,
            );

            debug!(
                logger,
                "Found accounts {:?} whose proposed adjusted balances didn't get above the limit \
            for disqualification. Chose the least desirable disqualified account as the one \
            with the biggest balance, which is {}. To be thrown away in this iteration.",
                disqualification_suspected_accounts,
                wallet
            );

            info_log_for_disqualified_account(logger, account_to_disqualify);

            Some(wallet)
        } else {
            None
        }
    }

    pub fn calculate_disqualification_edge(
        &self,
        qualified_payable_account: &QualifiedPayableAccount,
    ) -> u128 {
        todo!()
    }

    fn list_accounts_nominated_for_disqualification(
        &self,
        unconfirmed_adjustments: &[UnconfirmedAdjustment],
    ) -> Vec<&UnconfirmedAdjustment> {
        unconfirmed_adjustments
            .iter()
            .flat_map(|adjustment_info| {
                let disqualification_edge = self.calculate_disqualification_edge(
                    &adjustment_info
                        .non_finalized_account
                        .original_qualified_account,
                );
                let proposed_adjusted_balance = adjustment_info
                    .non_finalized_account
                    .proposed_adjusted_balance;

                if proposed_adjusted_balance <= disqualification_edge {
                    account_nominated_for_disqualification_diagnostics(
                        adjustment_info,
                        proposed_adjusted_balance,
                        disqualification_edge,
                    );

                    Some(adjustment_info)
                } else {
                    None
                }
            })
            .collect()
    }

    fn find_account_with_smallest_weight<'a>(
        accounts: &'a [&'a UnconfirmedAdjustment],
    ) -> &'a AdjustedAccountBeforeFinalization {
        let first_account = &accounts.first().expect("collection was empty");
        &accounts
            .iter()
            .fold(
                **first_account,
                |with_smallest_weight_so_far, current| match Ord::cmp(
                    &current.weight,
                    &with_smallest_weight_so_far.weight,
                ) {
                    Ordering::Less => current,
                    Ordering::Greater => with_smallest_weight_so_far,
                    Ordering::Equal => with_smallest_weight_so_far,
                },
            )
            .non_finalized_account
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
        account_balance_wei: u128,
        threshold_intercept_wei: u128,
        permanent_debt_allowed_wei: u128,
    ) -> u128 {
        todo!()
    }
}

impl DisqualificationGaugeReal {
    fn qualifies_for_double_margin(
        account_balance_wei: u128,
        threshold_intercept_wei: u128,
        permanent_debt_allowed_wei: u128,
    ) -> bool {
        let exceeding_part = account_balance_wei - threshold_intercept_wei;
        let considered_forgiven = threshold_intercept_wei - permanent_debt_allowed_wei;
        let extra_condition: bool = if considered_forgiven == 2 * permanent_debt_allowed_wei {
            todo!()
        } else if considered_forgiven < 2 * permanent_debt_allowed_wei {
            todo!()
        } else {
            todo!()
        };
        if exceeding_part > 2 * considered_forgiven && extra_condition {
            todo!()
        } else if exceeding_part == 2 * considered_forgiven && extra_condition {
            todo!()
        } else {
            todo!()
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::accountant::db_access_objects::payable_dao::PayableAccount;
    use crate::accountant::payment_adjuster::disqualification_arbiter::{
        DisqualificationArbiter, DisqualificationGauge, DisqualificationGaugeReal,
    };
    use crate::accountant::payment_adjuster::miscellaneous::data_structures::{
        AdjustedAccountBeforeFinalization, UnconfirmedAdjustment, WeightedAccount,
    };
    use crate::accountant::payment_adjuster::miscellaneous::helper_functions::{
        weights_total, EXCESSIVE_DEBT_PART_INSIGNIFICANCE_RATIO,
    };
    use crate::accountant::payment_adjuster::test_utils::{
        make_initialized_subject, DisqualificationGaugeMock, PRESERVED_TEST_PAYMENT_THRESHOLDS,
    };
    use crate::accountant::test_utils::{
        make_guaranteed_qualified_payables, make_non_guaranteed_qualified_payable,
        make_payable_account,
    };
    use crate::accountant::QualifiedPayableAccount;
    use crate::test_utils::make_wallet;
    use masq_lib::logger::Logger;
    use std::time::{Duration, SystemTime};

    #[test]
    fn qualifies_for_double_margin_granted_on_both_conditions_returning_equals() {
        let account_balance_wei = 6_000_000_000;
        let permanent_debt_allowed_wei = 1_000_000_000;
        let threshold_intercept_wei = 3_000_000_000;

        let result = DisqualificationGaugeReal::qualifies_for_double_margin(
            account_balance_wei,
            permanent_debt_allowed_wei,
            threshold_intercept_wei,
        );

        assert_eq!(result, true)
    }

    #[test]
    fn qualifies_for_double_margin_granted_on_first_condition_bigger_second_equal() {
        let account_balance_wei = 6_000_000_001;
        let permanent_debt_allowed_wei = 1_000_000_000;
        let threshold_intercept_wei = 3_000_000_000;

        let result = DisqualificationGaugeReal::qualifies_for_double_margin(
            account_balance_wei,
            permanent_debt_allowed_wei,
            threshold_intercept_wei,
        );

        assert_eq!(result, true)
    }

    #[test]
    fn qualifies_for_double_margin_granted_on_first_condition_equal_second_bigger() {
        let account_balance_wei = 6_000_000_002;
        let permanent_debt_allowed_wei = 1_000_000_000;
        let threshold_intercept_wei = 3_000_000_001;

        let result = DisqualificationGaugeReal::qualifies_for_double_margin(
            account_balance_wei,
            permanent_debt_allowed_wei,
            threshold_intercept_wei,
        );

        assert_eq!(result, true)
    }

    fn qualifies_for_double_margin_granted_on_both_conditions_returning_bigger() {
        let account_balance_wei = 6_000_000_003;
        let permanent_debt_allowed_wei = 1_000_000_000;
        let threshold_intercept_wei = 3_000_000_001;

        let result = DisqualificationGaugeReal::qualifies_for_double_margin(
            account_balance_wei,
            permanent_debt_allowed_wei,
            threshold_intercept_wei,
        );

        assert_eq!(result, true)
    }

    fn qualifies_for_double_margin_declined_on_first_condition() {
        let account_balance_wei = 5_999_999_999;
        let permanent_debt_allowed_wei = 1_000_000_000;
        let threshold_intercept_wei = 3_000_000_000;

        let result = DisqualificationGaugeReal::qualifies_for_double_margin(
            account_balance_wei,
            permanent_debt_allowed_wei,
            threshold_intercept_wei,
        );

        assert_eq!(result, false)
    }

    fn qualifies_for_double_margin_declined_on_second_condition() {
        let account_balance_wei = 6_000_000_000;
        let permanent_debt_allowed_wei = 1_000_000_000;
        let threshold_intercept_wei = 2_999_999_999;

        let result = DisqualificationGaugeReal::qualifies_for_double_margin(
            account_balance_wei,
            permanent_debt_allowed_wei,
            threshold_intercept_wei,
        );

        assert_eq!(result, false)
    }

    #[test]
    fn calculate_disqualification_edge_in_the_horizontal_thresholds_area() {
        let balance_wei = 30_000_000_000;
        let threshold_intercept_wei = 4_000_000_000;
        let permanent_debt_allowed_wei = 4_000_000_000;
        let subject = DisqualificationGaugeReal::default();

        todo!("finish the setup when pda can be added");
        let result = subject.determine_limit(
            balance_wei,
            threshold_intercept_wei,
            permanent_debt_allowed_wei,
        );

        assert_eq!(result, 30_000_000_000)
    }

    #[test]
    fn calculate_disqualification_edge_in_the_tilted_thresholds_area_with_normal_margin() {
        let balance_wei = 6_000_000_000;
        let threshold_intercept_wei = 4_000_000_000;
        let permanent_debt_allowed_wei = 1_000_000_000;
        let subject = DisqualificationGaugeReal::default();

        todo!("finish the setup when pda can be added");
        let result = subject.determine_limit(
            balance_wei,
            threshold_intercept_wei,
            permanent_debt_allowed_wei,
        );

        assert_eq!(result, (30_000_000_000 - 4_000_000_000) + 1_000_000_000)
    }

    #[test]
    fn calculate_disqualification_edge_in_the_tilted_thresholds_area_with_double_margin() {
        let balance_wei = 30_000_000_000;
        let threshold_intercept_wei = 4_000_000_000;
        let permanent_debt_allowed_wei = 1_000_000_000;
        let subject = DisqualificationGaugeReal::default();

        todo!("finish the setup when pda can be added");
        let result = subject.determine_limit(
            balance_wei,
            threshold_intercept_wei,
            permanent_debt_allowed_wei,
        );

        assert_eq!(
            result,
            (30_000_000_000 - 4_000_000_000) + (2 * 1_000_000_000)
        )
    }

    #[test]
    fn list_accounts_nominated_for_disqualification_uses_the_right_manifest_const() {
        todo!("do I still want this test??");
        let account_balance = 1_000_000;
        let garbage_weight = 22222222; // It plays no role
        let garbage_thresholds_intercept = 456789; // Also no role
        let prepare_account = |n: u64| {
            let mut account = make_payable_account(n);
            account.balance_wei = account_balance;
            account
        };
        let payable_account_1 = prepare_account(1);
        let payable_account_2 = prepare_account(2);
        let payable_account_3 = prepare_account(3);
        let edge: u128 = todo!();
        let proposed_ok_balance = edge + 1;
        let unconfirmed_adjustment_1 = UnconfirmedAdjustment::new(
            WeightedAccount::new(
                QualifiedPayableAccount::new(payable_account_1, garbage_thresholds_intercept),
                garbage_weight,
            ),
            proposed_ok_balance,
        );
        let proposed_bad_balance_because_equal = edge;
        let unconfirmed_adjustment_2 = UnconfirmedAdjustment::new(
            WeightedAccount::new(
                QualifiedPayableAccount::new(payable_account_2, garbage_thresholds_intercept),
                garbage_weight,
            ),
            proposed_bad_balance_because_equal,
        );
        let proposed_bad_balance_because_smaller = edge - 1;
        let unconfirmed_adjustment_3 = UnconfirmedAdjustment::new(
            WeightedAccount::new(
                QualifiedPayableAccount::new(payable_account_3, garbage_thresholds_intercept),
                garbage_weight,
            ),
            proposed_bad_balance_because_smaller,
        );
        let unconfirmed_adjustments = vec![
            unconfirmed_adjustment_1,
            unconfirmed_adjustment_2.clone(),
            unconfirmed_adjustment_3.clone(),
        ];
        let subject = DisqualificationArbiter::new(Box::new(DisqualificationGaugeReal::default()));

        let result = subject.list_accounts_nominated_for_disqualification(&unconfirmed_adjustments);

        let expected_disqualified_accounts =
            vec![&unconfirmed_adjustment_2, &unconfirmed_adjustment_3];
        assert_eq!(result, expected_disqualified_accounts)
    }

    #[test]
    fn find_account_with_smallest_weight_works_for_unequal_weights() {
        let idx_of_expected_result = 1;
        let (adjustments, expected_result) =
            make_unconfirmed_adjustments_and_select_expected_account_returned_in_the_test(
                vec![1004, 1000, 1002, 1001],
                idx_of_expected_result,
            );
        let referenced_unconfirmed_adjustments = by_reference(&adjustments);

        let result = DisqualificationArbiter::find_account_with_smallest_weight(
            &referenced_unconfirmed_adjustments,
        );

        assert_eq!(result, &expected_result)
    }

    #[test]
    fn find_account_with_smallest_weight_for_equal_weights_chooses_the_first_of_the_same_size() {
        let idx_of_expected_result = 0;
        let (adjustments, expected_result) =
            make_unconfirmed_adjustments_and_select_expected_account_returned_in_the_test(
                vec![1111, 1113, 1111],
                idx_of_expected_result,
            );
        let referenced_non_finalized_accounts = by_reference(&adjustments);

        let result = DisqualificationArbiter::find_account_with_smallest_weight(
            &referenced_non_finalized_accounts,
        );

        assert_eq!(result, &expected_result)
    }

    fn by_reference(adjusted_accounts: &[UnconfirmedAdjustment]) -> Vec<&UnconfirmedAdjustment> {
        adjusted_accounts.iter().collect()
    }

    #[test]
    fn only_account_with_the_smallest_weight_will_be_disqualified_in_single_iteration() {
        let test_name =
            "only_account_with_the_smallest_weight_will_be_disqualified_in_single_iteration";
        let now = SystemTime::now();
        let cw_masq_balance = 200_000_000_000;
        let logger = Logger::new(test_name);
        let subject = make_initialized_subject(now, Some(cw_masq_balance), None);
        // None of these accounts would be outside the definition for disqualification
        // even if any of them would be gifted by the complete balance from the cw
        let wallet_1 = make_wallet("abc");
        let account_1 = PayableAccount {
            wallet: wallet_1.clone(),
            balance_wei: 120_000_000_001,
            last_paid_timestamp: now.checked_sub(Duration::from_secs(1_000_000)).unwrap(),
            pending_payable_opt: None,
        };
        let wallet_2 = make_wallet("def");
        let account_2 = PayableAccount {
            wallet: wallet_2.clone(),
            balance_wei: 120_000_000_000,
            last_paid_timestamp: now.checked_sub(Duration::from_secs(1_000_000)).unwrap(),
            pending_payable_opt: None,
        };
        let wallet_3 = make_wallet("ghi");
        let account_3 = PayableAccount {
            wallet: wallet_3.clone(),
            balance_wei: 119_999_999_999,
            last_paid_timestamp: now.checked_sub(Duration::from_secs(999_999)).unwrap(),
            pending_payable_opt: None,
        };
        let wallet_4 = make_wallet("jkl");
        let account_4 = PayableAccount {
            wallet: wallet_4.clone(),
            balance_wei: 120_000_000_000,
            last_paid_timestamp: now.checked_sub(Duration::from_secs(999_999)).unwrap(),
            pending_payable_opt: None,
        };
        let accounts = vec![account_1, account_2, account_3, account_4];
        let qualified_payables =
            make_guaranteed_qualified_payables(accounts, &PRESERVED_TEST_PAYMENT_THRESHOLDS, now);
        let weights_and_accounts = subject.calculate_weights_for_accounts(qualified_payables);
        let weights_total = weights_total(&weights_and_accounts);
        let unconfirmed_adjustments =
            subject.compute_unconfirmed_adjustments(weights_and_accounts, weights_total);
        let disqualification_gauge = DisqualificationGaugeMock::default();
        let subject = DisqualificationArbiter::new(Box::new(disqualification_gauge));

        let result =
            DisqualificationArbiter::try_finding_an_account_to_disqualify_in_this_iteration(
                &unconfirmed_adjustments,
                &logger,
            );

        assert_eq!(result, Some(wallet_3));
    }

    fn make_unconfirmed_adjustments_and_select_expected_account_returned_in_the_test(
        weights: Vec<u128>,
        idx_of_expected_result: usize,
    ) -> (
        Vec<UnconfirmedAdjustment>,
        AdjustedAccountBeforeFinalization,
    ) {
        let init: (
            Vec<UnconfirmedAdjustment>,
            Option<AdjustedAccountBeforeFinalization>,
        ) = (vec![], None);
        let (adjustments, expected_result_opt) = weights.into_iter().enumerate().fold(
            init,
            |(mut adjustments_so_far, expected_result_opt_so_far), (actual_idx, weight)| {
                let original_account = make_payable_account(actual_idx as u64);
                let garbage_intercept = 2_000_000_000; // Unimportant for the tests this is used in;
                let qualified_account = QualifiedPayableAccount {
                    payable: original_account,
                    payment_threshold_intercept: garbage_intercept,
                };
                let garbage_proposed_balance = 1_000_000_000; // Same here
                let new_adjustment_to_be_added = UnconfirmedAdjustment::new(
                    WeightedAccount::new(qualified_account, weight),
                    garbage_proposed_balance,
                );
                let expected_result_opt = if expected_result_opt_so_far.is_none()
                    && actual_idx == idx_of_expected_result
                {
                    Some(new_adjustment_to_be_added.non_finalized_account.clone())
                } else {
                    expected_result_opt_so_far
                };
                adjustments_so_far.push(new_adjustment_to_be_added);
                (adjustments_so_far, expected_result_opt)
            },
        );
        (adjustments, expected_result_opt.unwrap())
    }
}
