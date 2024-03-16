// Copyright (c) 2023, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::QualifiedPayableAccount;

#[derive(Clone)]
pub struct WeightedAccount {
    pub qualified_account: QualifiedPayableAccount,
    pub weight: u128,
}

impl WeightedAccount {
    pub fn new(qualified_account: QualifiedPayableAccount, weight: u128) -> Self {
        Self {
            qualified_account,
            weight,
        }
    }
}

#[derive(Debug)]
pub enum AdjustmentIterationResult {
    AllAccountsProcessed(Vec<AdjustedAccountBeforeFinalization>),
    SpecialTreatmentRequired {
        case: RequiredSpecialTreatment,
        remaining_undecided_accounts: Vec<QualifiedPayableAccount>,
    },
}

pub struct RecursionResults {
    pub here_decided_accounts: Vec<AdjustedAccountBeforeFinalization>,
    pub downstream_decided_accounts: Vec<AdjustedAccountBeforeFinalization>,
}

impl RecursionResults {
    pub fn new(
        here_decided_accounts: Vec<AdjustedAccountBeforeFinalization>,
        downstream_decided_accounts: Vec<AdjustedAccountBeforeFinalization>,
    ) -> Self {
        Self {
            here_decided_accounts,
            downstream_decided_accounts,
        }
    }

    pub fn merge_results_from_recursion(self) -> Vec<AdjustedAccountBeforeFinalization> {
        self.here_decided_accounts
            .into_iter()
            .chain(self.downstream_decided_accounts.into_iter())
            .collect()
    }
}

#[derive(Debug)]
pub enum RequiredSpecialTreatment {
    TreatInsignificantAccount,
    TreatOutweighedAccounts(Vec<AdjustedAccountBeforeFinalization>),
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct AdjustedAccountBeforeFinalization {
    pub original_qualified_account: QualifiedPayableAccount,
    pub proposed_adjusted_balance: u128,
}

impl AdjustedAccountBeforeFinalization {
    pub fn new(original_account: QualifiedPayableAccount, proposed_adjusted_balance: u128) -> Self {
        Self {
            original_qualified_account: original_account,
            proposed_adjusted_balance,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct UnconfirmedAdjustment {
    pub non_finalized_account: AdjustedAccountBeforeFinalization,
    pub weight: u128,
}

impl UnconfirmedAdjustment {
    pub fn new(weighted_account: WeightedAccount, proposed_adjusted_balance: u128) -> Self {
        Self {
            non_finalized_account: AdjustedAccountBeforeFinalization::new(
                weighted_account.qualified_account,
                proposed_adjusted_balance,
            ),
            weight: weighted_account.weight,
        }
    }
}

pub struct NonFinalizedAdjustmentWithResolution {
    pub non_finalized_adjustment: AdjustedAccountBeforeFinalization,
    pub adjustment_resolution: AdjustmentResolution,
}

impl NonFinalizedAdjustmentWithResolution {
    pub fn new(
        non_finalized_adjustment: AdjustedAccountBeforeFinalization,
        adjustment_resolution: AdjustmentResolution,
    ) -> Self {
        Self {
            non_finalized_adjustment,
            adjustment_resolution,
        }
    }
}

#[derive(Clone, Copy)]
pub enum AdjustmentResolution {
    Finalize,
    Revert,
}

// Sets the minimal percentage of the original balance that must be proposed after the adjustment
// or the account will be eliminated for insignificance
#[derive(Debug, PartialEq, Eq)]
pub struct PercentageAccountInsignificance {
    // Using integers means we have to represent accurate percentage
    // as set of two constants
    pub multiplier: u128,
    pub divisor: u128,
}

pub struct TransactionCountsWithin16bits {
    pub affordable: u16,
    pub required: u16,
}

impl TransactionCountsWithin16bits {
    pub fn new(max_possible_tx_count: u128, number_of_accounts: usize) -> Self {
        TransactionCountsWithin16bits {
            affordable: u16::try_from(max_possible_tx_count).unwrap_or(u16::MAX),
            required: u16::try_from(number_of_accounts).unwrap_or(u16::MAX),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::accountant::payment_adjuster::miscellaneous::data_structures::{
        AdjustedAccountBeforeFinalization, RecursionResults, TransactionCountsWithin16bits,
    };
    use crate::accountant::test_utils::make_non_guaranteed_qualified_payable;

    #[test]
    fn merging_results_from_recursion_works() {
        let non_finalized_account_1 = AdjustedAccountBeforeFinalization {
            original_qualified_account: make_non_guaranteed_qualified_payable(111),
            proposed_adjusted_balance: 1234,
        };
        let non_finalized_account_2 = AdjustedAccountBeforeFinalization {
            original_qualified_account: make_non_guaranteed_qualified_payable(222),
            proposed_adjusted_balance: 5555,
        };
        let non_finalized_account_3 = AdjustedAccountBeforeFinalization {
            original_qualified_account: make_non_guaranteed_qualified_payable(333),
            proposed_adjusted_balance: 6789,
        };
        let subject = RecursionResults {
            here_decided_accounts: vec![non_finalized_account_1.clone()],
            downstream_decided_accounts: vec![
                non_finalized_account_2.clone(),
                non_finalized_account_3.clone(),
            ],
        };

        let result = subject.merge_results_from_recursion();

        assert_eq!(
            result,
            vec![
                non_finalized_account_1,
                non_finalized_account_2,
                non_finalized_account_3
            ]
        )
    }

    #[test]
    fn there_is_u16_ceiling_for_possible_tx_count() {
        let result = [-3_i8, -1, 0, 1, 10]
            .into_iter()
            .map(|correction| plus_minus_correction_of_u16_max(correction) as u128)
            .map(|max_possible_tx_count| {
                let detected_tx_counts =
                    TransactionCountsWithin16bits::new(max_possible_tx_count, 123);
                detected_tx_counts.affordable
            })
            .collect::<Vec<_>>();

        assert_eq!(
            result,
            vec![u16::MAX - 3, u16::MAX - 1, u16::MAX, u16::MAX, u16::MAX]
        )
    }

    #[test]
    fn there_is_u16_ceiling_for_required_number_of_accounts() {
        let result = [-9_i8, -1, 0, 1, 5]
            .into_iter()
            .map(|correction| plus_minus_correction_of_u16_max(correction))
            .map(|required_tx_count_usize| {
                let detected_tx_counts =
                    TransactionCountsWithin16bits::new(123, required_tx_count_usize);
                detected_tx_counts.required
            })
            .collect::<Vec<_>>();

        assert_eq!(
            result,
            vec![u16::MAX - 9, u16::MAX - 1, u16::MAX, u16::MAX, u16::MAX]
        )
    }

    fn plus_minus_correction_of_u16_max(correction: i8) -> usize {
        if correction < 0 {
            (u16::MAX - correction.abs() as u16) as usize
        } else {
            u16::MAX as usize + correction as usize
        }
    }
}
