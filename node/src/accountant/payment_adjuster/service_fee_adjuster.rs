// Copyright (c) 2024, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::payment_adjuster::miscellaneous::data_structures::{
    AdjustmentIterationResult, UnconfirmedAdjustment, WeightedPayable,
};
use masq_lib::logger::Logger;

pub trait ServiceFeeAdjuster {
    fn perform_adjustment_by_service_fee(
        &self,
        weighted_accounts: Vec<WeightedPayable>,
        unallocated_cw_service_fee_balance_minor: u128,
        logger: &Logger,
    ) -> AdjustmentIterationResult;
}

pub struct ServiceFeeAdjusterReal {
    adjustment_computer: AdjustmentComputer,
}

impl ServiceFeeAdjuster for ServiceFeeAdjusterReal {
    fn perform_adjustment_by_service_fee(
        &self,
        weighted_accounts: Vec<WeightedPayable>,
        cw_service_fee_balance_minor: u128,
        logger: &Logger,
    ) -> AdjustmentIterationResult {
        todo!()
    }
}

impl Default for ServiceFeeAdjusterReal {
    fn default() -> Self {
        Self::new()
    }
}

impl ServiceFeeAdjusterReal {
    fn new() -> Self {
        Self {
            adjustment_computer: Default::default(),
        }
    }
}

#[derive(Default)]
pub struct AdjustmentComputer {}

impl AdjustmentComputer {
    pub fn compute_unconfirmed_adjustments(
        &self,
        weighted_accounts: Vec<WeightedPayable>,
        unallocated_cw_service_fee_balance_minor: u128,
    ) -> Vec<UnconfirmedAdjustment> {
        todo!()
    }
}

// fn perform_adjustment_by_service_fee(
//     &self,
//     weighted_accounts: Vec<WeightedPayable>,
// ) -> AdjustmentIterationResult {
//     let non_finalized_adjusted_accounts =
//         self.compute_unconfirmed_adjustments(weighted_accounts);
//
//     let still_unchecked_for_disqualified =
//         match self.handle_possibly_outweighed_accounts(non_finalized_adjusted_accounts) {
//             Either::Left(first_check_passing_accounts) => first_check_passing_accounts,
//             Either::Right(with_some_outweighed) => return with_some_outweighed,
//         };
//
//     let verified_accounts = match self
//         .consider_account_disqualification(still_unchecked_for_disqualified, &self.logger)
//     {
//         Either::Left(verified_accounts) => verified_accounts,
//         Either::Right(with_some_disqualified) => return with_some_disqualified,
//     };
//
//     AdjustmentIterationResult::AllAccountsProcessed(verified_accounts)
// }

// TODO Should this become a helper? ...with which I can catch mid-results and assert on them?
//
// fn compute_unconfirmed_adjustments(
//     &self,
//     weighted_accounts: Vec<WeightedPayable>,
// ) -> Vec<UnconfirmedAdjustment> {
//     let weights_total = weights_total(&weighted_accounts);
//     let largest_weight = find_largest_weight(&weighted_accounts);
//     let cw_service_fee_balance = self.inner.unallocated_cw_service_fee_balance_minor();
//
//     let multiplication_coefficient = compute_mul_coefficient_preventing_fractional_numbers(
//         cw_service_fee_balance,
//         largest_weight,
//     );
//
//     let proportional_cw_balance_fragment = Self::compute_proportional_cw_fragment(
//         cw_service_fee_balance,
//         weights_total,
//         multiplication_coefficient,
//     );
//     let compute_proposed_adjusted_balance =
//         |weight: u128| weight * proportional_cw_balance_fragment / multiplication_coefficient;
//
//     weighted_accounts
//         .into_iter()
//         .map(|weighted_account| {
//             let proposed_adjusted_balance =
//                 compute_proposed_adjusted_balance(weighted_account.weight);
//
//             proposed_adjusted_balance_diagnostics(
//                 &weighted_account.qualified_account,
//                 proposed_adjusted_balance,
//             );
//
//             UnconfirmedAdjustment::new(weighted_account, proposed_adjusted_balance)
//         })
//         .collect()
// }
