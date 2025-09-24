// Copyright (c) 2024, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use web3::types::Address;
use crate::accountant::payment_adjuster::logging_and_diagnostics::diagnostics::ordinary_diagnostic_functions::{
    account_nominated_for_disqualification_diagnostics,
    try_finding_an_account_to_disqualify_diagnostics,
};
use crate::accountant::payment_adjuster::logging_and_diagnostics::log_functions::info_log_for_disqualified_account;
use crate::accountant::payment_adjuster::miscellaneous::data_structures::UnconfirmedAdjustment;
use crate::accountant::QualifiedPayableAccount;
use masq_lib::logger::Logger;

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
    ) -> Address {
        let disqualification_suspected_accounts =
            Self::list_accounts_nominated_for_disqualification(unconfirmed_adjustments);

        let account_to_disqualify =
            Self::find_account_with_smallest_weight(&disqualification_suspected_accounts);

        let wallet = account_to_disqualify.wallet;

        try_finding_an_account_to_disqualify_diagnostics(
            &disqualification_suspected_accounts,
            wallet,
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

    fn find_account_with_smallest_weight(
        accounts: &[DisqualificationSuspectedAccount],
    ) -> &DisqualificationSuspectedAccount {
        accounts
            .iter()
            .min_by_key(|account| account.weight)
            .expect("an empty collection of accounts")
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct DisqualificationSuspectedAccount {
    pub wallet: Address,
    pub weight: u128,
    // The rest serves diagnostics and logging
    pub proposed_adjusted_balance_minor: u128,
    pub disqualification_limit_minor: u128,
    pub initial_account_balance_minor: u128,
}

impl<'unconfirmed_accounts> From<&'unconfirmed_accounts UnconfirmedAdjustment>
    for DisqualificationSuspectedAccount
{
    fn from(unconfirmed_account: &'unconfirmed_accounts UnconfirmedAdjustment) -> Self {
        DisqualificationSuspectedAccount {
            wallet: unconfirmed_account.wallet(),
            weight: unconfirmed_account.weighed_account.weight,
            proposed_adjusted_balance_minor: unconfirmed_account.proposed_adjusted_balance_minor,
            disqualification_limit_minor: unconfirmed_account.disqualification_limit_minor(),
            initial_account_balance_minor: unconfirmed_account.initial_balance_minor(),
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
        // This signs that the debt lies in the horizontal area of the payment thresholds, and thus
        // should be paid in the whole size.
        if threshold_intercept_minor == permanent_debt_allowed_minor {
            return account_balance_minor;
        }
        Self::determine_adequate_minimal_payment(
            account_balance_minor,
            threshold_intercept_minor,
            permanent_debt_allowed_minor,
        )
    }
}

impl DisqualificationGaugeReal {
    const FIRST_QUALIFICATION_CONDITION_COEFFICIENT: u128 = 2;
    const SECOND_QUALIFICATION_CONDITION_COEFFICIENT: u128 = 2;
    const MULTIPLIER_FOR_THICKER_MARGIN: u128 = 2;

    fn qualifies_for_thicker_margin(
        account_balance_minor: u128,
        threshold_intercept_minor: u128,
        permanent_debt_allowed_minor: u128,
    ) -> bool {
        let exceeding_threshold = account_balance_minor - threshold_intercept_minor;
        let considered_forgiven = threshold_intercept_minor - permanent_debt_allowed_minor;
        let minimal_acceptable_payment = exceeding_threshold + permanent_debt_allowed_minor;

        let is_debt_growing_fast = minimal_acceptable_payment
            >= Self::FIRST_QUALIFICATION_CONDITION_COEFFICIENT * considered_forgiven;

        let situated_on_the_left_half_of_the_slope = considered_forgiven
            >= Self::SECOND_QUALIFICATION_CONDITION_COEFFICIENT * permanent_debt_allowed_minor;

        is_debt_growing_fast && situated_on_the_left_half_of_the_slope
    }

    fn determine_adequate_minimal_payment(
        account_balance_minor: u128,
        threshold_intercept_minor: u128,
        permanent_debt_allowed_minor: u128,
    ) -> u128 {
        let debt_part_over_the_threshold = account_balance_minor - threshold_intercept_minor;
        if DisqualificationGaugeReal::qualifies_for_thicker_margin(
            account_balance_minor,
            threshold_intercept_minor,
            permanent_debt_allowed_minor,
        ) {
            debt_part_over_the_threshold
                + Self::MULTIPLIER_FOR_THICKER_MARGIN * permanent_debt_allowed_minor
        } else {
            debt_part_over_the_threshold + permanent_debt_allowed_minor
        }
    }

    //       This schema shows the conditions used to determine the disqualification limit
    //                          (or minimal acceptable payment)
    //
    //  Y axis - debt size
    //
    //  |
    //  |         A +
    //  |           |     P   -----------+
    //  |           |     P              |
    //  |           |     P              |
    //  |           |     P              |
    //  |         B |  P  P   -----+     |
    //  |           +  P  P        |     |
    //  |           |\ P  P        X     Y
    //  |           | \P  P        |     |
    //  |           |  P  P   -----+     |
    //  |         B'+  P\ P              |
    //  |           |\ P \P              |
    //  |           | \P  P   -----+-----+
    //  |           |  U  P\
    //  |         B"+  U\ P \
    //  |            \ U \P  +C
    //  |             \U  P  |\
    //  |              U  P\ | \
    //  |              U\ P \|  \  P                 P
    //  |              U \P  +C' \ P                 P
    //  |              U  U  |\   \P                 P
    //  |              U  U\ | \   P                 P
    //  |              U  U \|  \  P\                P
    //  |              U  U  +C" \ P \               P
    //  |              U  U   \   \P  \              P
    //  |              U  U    \   U   \ D           P       E
    //  |              U  U     \  U\   +------------P--------+
    //  |              U  U      \ U \  |            P
    //  |              U  U       \U  \ |            P
    //  |              U  U        U   \|D'          P       E'
    //  +---------------------------+---+---------------------+   X axis - time
    //                 3  4        2                 1
    //
    //  This diagram presents computation of the disqualification limit which differs by four cases.
    //  The debt portion illustrated with the use of the letter 'P' stands for the actual limit.
    //  That is the minimum amount we consider effective to keep us away from a ban for delinquent
    //  debtors. Beyond that mark, if the debt is bigger, it completes the column with 'U's. This
    //  part can be forgiven for the time being, until more funds is supplied for the consuming
    //  wallet.
    //
    //  Points A, B, D, E make up a simple outline of possible payment thresholds. These are
    //  fundamental statements: The x-axis distance between B and D is "threshold_interval_sec".
    //  From B vertically down to the x-axis, it amounts to "debt_threshold_gwei". D is as far
    //  from D' as the size of the "permanent_debt_allowed_gwei" parameter. A few other line
    //  segments in the diagram are also derived from this last mentioned measurement, like B - B'
    //  and B' - B".
    //
    //  1. This debt is ordered entire strictly as well as any other one situated between D and E.
    //     (Note that the E isn't a real point, the axis goes endless this direction).
    //  2. Since we are earlier in the time with debt, a different rule is applied. The limit is
    //     formed as the part above the threshold, plus an equivalent of the D - D' distance.
    //     It's notable that we are evaluating a debt older than the timestamp which would appear
    //     on the x-axis if we prolonged the C - C" line towards it.
    //  3. Now we are before that timestamp, however the surplussing debt portion X isn't
    //     significant enough yet. Therefore the same rule as at No. 2 is applied also here.
    //  4. This time we hold the condition for the age not reaching the decisive timestamp and
    //     the debt becomes sizable, measured as Y, which indicates that it might be linked to
    //     a Node that we've used extensively (or even that we're using right now). We then prefer
    //     to increase the margin added to the above-threshold amount, and so we double it.
    //     If true to the reality, the diagram would have to run much further upwards. That's
    //     because the condition to consider a debt's size significant says that the part under
    //     the threshold must be twice (or more) smaller than that above it (Y).
    //
}

#[cfg(test)]
mod tests {
    use crate::accountant::payment_adjuster::disqualification_arbiter::{
        DisqualificationArbiter, DisqualificationGauge, DisqualificationGaugeReal,
        DisqualificationSuspectedAccount,
    };
    use crate::accountant::payment_adjuster::miscellaneous::data_structures::UnconfirmedAdjustment;
    use crate::accountant::payment_adjuster::test_utils::local_utils::{
        make_meaningless_weighed_account, make_meaningless_unconfirmed_adjustment,
    };
    use itertools::Itertools;
    use masq_lib::logger::Logger;
    use masq_lib::utils::convert_collection;

    #[test]
    fn constants_are_correct() {
        assert_eq!(
            DisqualificationGaugeReal::FIRST_QUALIFICATION_CONDITION_COEFFICIENT,
            2
        );
        assert_eq!(
            DisqualificationGaugeReal::SECOND_QUALIFICATION_CONDITION_COEFFICIENT,
            2
        );
        assert_eq!(DisqualificationGaugeReal::MULTIPLIER_FOR_THICKER_MARGIN, 2)
    }

    #[test]
    fn qualifies_for_thicker_margin_granted_on_both_conditions_returning_equals() {
        let account_balance_minor = 6_000_000_000;
        let threshold_intercept_minor = 3_000_000_000;
        let permanent_debt_allowed_minor = 1_000_000_000;

        let result = DisqualificationGaugeReal::qualifies_for_thicker_margin(
            account_balance_minor,
            threshold_intercept_minor,
            permanent_debt_allowed_minor,
        );

        assert_eq!(result, true)
    }

    #[test]
    fn qualifies_for_thicker_margin_granted_on_first_condition_bigger_second_equal() {
        let account_balance_minor = 6_000_000_001;
        let threshold_intercept_minor = 3_000_000_000;
        let permanent_debt_allowed_minor = 1_000_000_000;

        let result = DisqualificationGaugeReal::qualifies_for_thicker_margin(
            account_balance_minor,
            threshold_intercept_minor,
            permanent_debt_allowed_minor,
        );

        assert_eq!(result, true)
    }

    #[test]
    fn qualifies_for_thicker_margin_granted_on_first_condition_equal_second_bigger() {
        let account_balance_minor = 6_000_000_003;
        let threshold_intercept_minor = 3_000_000_001;
        let permanent_debt_allowed_minor = 1_000_000_000;

        let result = DisqualificationGaugeReal::qualifies_for_thicker_margin(
            account_balance_minor,
            threshold_intercept_minor,
            permanent_debt_allowed_minor,
        );

        assert_eq!(result, true)
    }

    #[test]
    fn qualifies_for_thicker_margin_granted_on_both_conditions_returning_bigger() {
        let account_balance_minor = 6_000_000_004;
        let threshold_intercept_minor = 3_000_000_001;
        let permanent_debt_allowed_minor = 1_000_000_000;

        let result = DisqualificationGaugeReal::qualifies_for_thicker_margin(
            account_balance_minor,
            threshold_intercept_minor,
            permanent_debt_allowed_minor,
        );

        assert_eq!(result, true)
    }

    #[test]
    fn qualifies_for_thicker_margin_declined_on_first_condition() {
        let account_balance_minor = 5_999_999_999;
        let threshold_intercept_minor = 3_000_000_000;
        let permanent_debt_allowed_minor = 1_000_000_000;

        let result = DisqualificationGaugeReal::qualifies_for_thicker_margin(
            account_balance_minor,
            threshold_intercept_minor,
            permanent_debt_allowed_minor,
        );

        assert_eq!(result, false)
    }

    #[test]
    fn qualifies_for_thicker_margin_declined_on_second_condition() {
        let account_balance_minor = 6_000_000_000;
        let threshold_intercept_minor = 2_999_999_999;
        let permanent_debt_allowed_minor = 1_000_000_000;

        let result = DisqualificationGaugeReal::qualifies_for_thicker_margin(
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
        let mut account = make_meaningless_unconfirmed_adjustment(444);
        account.proposed_adjusted_balance_minor = 1_000_000_000;
        account
            .weighed_account
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
        let mut account_1 = make_meaningless_weighed_account(123);
        account_1.analyzed_account.disqualification_limit_minor = 1_000_000;
        account_1.weight = 1000;
        let mut account_2 = make_meaningless_weighed_account(456);
        account_2.analyzed_account.disqualification_limit_minor = 1_000_000;
        account_2.weight = 1002;
        let mut account_3 = make_meaningless_weighed_account(789);
        account_3.analyzed_account.disqualification_limit_minor = 1_000_000;
        account_3.weight = 999;
        let wallet_3 = account_3
            .analyzed_account
            .qualified_as
            .bare_account
            .wallet
            .address();
        let mut account_4 = make_meaningless_weighed_account(012);
        account_4.analyzed_account.disqualification_limit_minor = 1_000_000;
        account_4.weight = 1001;
        // Notice that each proposed adjustment is below 1_000_000 which makes it clear all these
        // accounts are nominated for disqualification, only one can be picked though
        let seeds = vec![
            (account_1, 900_000),
            (account_2, 920_000),
            (account_3, 910_000),
            (account_4, 930_000),
        ];
        let unconfirmed_adjustments = seeds
            .into_iter()
            .map(
                |(weighed_account, proposed_adjusted_balance_minor)| UnconfirmedAdjustment {
                    weighed_account,
                    proposed_adjusted_balance_minor,
                },
            )
            .collect_vec();
        let subject = DisqualificationArbiter::default();

        let result = subject.find_an_account_to_disqualify_in_this_iteration(
            &unconfirmed_adjustments,
            &Logger::new("test"),
        );

        assert_eq!(result, wallet_3);
    }

    fn make_unconfirmed_adjustments(weights: Vec<u128>) -> Vec<UnconfirmedAdjustment> {
        weights
            .into_iter()
            .enumerate()
            .map(|(idx, weight)| {
                let mut account = make_meaningless_unconfirmed_adjustment(idx as u64);
                account.weighed_account.weight = weight;
                account
            })
            .collect()
    }

    fn make_dsq_suspected_accounts(
        accounts: &[UnconfirmedAdjustment],
    ) -> Vec<DisqualificationSuspectedAccount> {
        let with_referred_accounts: Vec<&UnconfirmedAdjustment> = accounts.iter().collect();
        convert_collection(with_referred_accounts)
    }
}
