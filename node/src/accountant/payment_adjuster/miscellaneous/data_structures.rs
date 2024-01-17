// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::db_access_objects::payable_dao::PayableAccount;

#[derive(Debug)]
pub enum AdjustmentIterationResult {
    AllAccountsProcessedSmoothly(Vec<AdjustedAccountBeforeFinalization>),
    SpecialTreatmentNeeded {
        case: AfterAdjustmentSpecialTreatment,
        remaining: Vec<PayableAccount>,
    },
}

pub struct GraduallyFormedResult{
    pub here_decided_accounts: Vec<AdjustedAccountBeforeFinalization>,
    pub downstream_decided_accounts: Vec<AdjustedAccountBeforeFinalization>
}

impl GraduallyFormedResult{
    pub fn new(here_decided_accounts: Vec<AdjustedAccountBeforeFinalization>, downstream_decided_accounts: Vec<AdjustedAccountBeforeFinalization>)->Self{
        Self{ here_decided_accounts, downstream_decided_accounts }
    }
}

#[derive(Debug)]
pub enum AfterAdjustmentSpecialTreatment {
    TreatInsignificantAccount,
    TreatOutweighedAccounts(Vec<AdjustedAccountBeforeFinalization>),
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct AdjustedAccountBeforeFinalization {
    pub original_account: PayableAccount,
    pub proposed_adjusted_balance: u128,
}

impl AdjustedAccountBeforeFinalization {
    pub fn new(original_account: PayableAccount, proposed_adjusted_balance: u128) -> Self {
        Self {
            original_account,
            proposed_adjusted_balance,
        }
    }
}

#[derive(Clone, Copy)]
pub enum ProposedAdjustmentResolution {
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
    use crate::accountant::payment_adjuster::miscellaneous::data_structures::TransactionCountsWithin16bits;

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
