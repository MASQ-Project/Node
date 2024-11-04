// Copyright (c) 2023, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::db_access_objects::payable_dao::PayableAccount;
use crate::accountant::AnalyzedPayableAccount;
use crate::sub_lib::wallet::Wallet;
use web3::types::U256;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WeightedPayable {
    pub analyzed_account: AnalyzedPayableAccount,
    pub weight: u128,
}

impl WeightedPayable {
    pub fn new(analyzed_account: AnalyzedPayableAccount, weight: u128) -> Self {
        Self {
            analyzed_account,
            weight,
        }
    }

    pub fn wallet(&self) -> &Wallet {
        &self.analyzed_account.qualified_as.bare_account.wallet
    }

    pub fn initial_balance_minor(&self) -> u128 {
        self.analyzed_account.qualified_as.bare_account.balance_wei
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct AdjustmentIterationResult {
    pub decided_accounts: Vec<AdjustedAccountBeforeFinalization>,
    pub remaining_undecided_accounts: Vec<WeightedPayable>,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct AdjustedAccountBeforeFinalization {
    pub original_account: PayableAccount,
    pub weight: u128,
    pub proposed_adjusted_balance_minor: u128,
}

impl AdjustedAccountBeforeFinalization {
    pub fn new(
        original_account: PayableAccount,
        weight: u128,
        proposed_adjusted_balance_minor: u128,
    ) -> Self {
        Self {
            original_account,
            weight,
            proposed_adjusted_balance_minor,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct UnconfirmedAdjustment {
    pub weighted_account: WeightedPayable,
    pub proposed_adjusted_balance_minor: u128,
}

impl UnconfirmedAdjustment {
    pub fn new(weighted_account: WeightedPayable, proposed_adjusted_balance_minor: u128) -> Self {
        Self {
            weighted_account,
            proposed_adjusted_balance_minor,
        }
    }

    pub fn wallet(&self) -> &Wallet {
        self.weighted_account.wallet()
    }

    pub fn initial_balance_minor(&self) -> u128 {
        self.weighted_account.initial_balance_minor()
    }

    pub fn disqualification_limit_minor(&self) -> u128 {
        self.weighted_account
            .analyzed_account
            .disqualification_limit_minor
    }
}

pub struct AffordableAndRequiredTxCounts {
    pub affordable: u16,
    pub required: u16,
}

impl AffordableAndRequiredTxCounts {
    pub fn new(max_possible_tx_count: U256, number_of_accounts: usize) -> Self {
        AffordableAndRequiredTxCounts {
            affordable: u16::try_from(max_possible_tx_count).unwrap_or(u16::MAX),
            required: u16::try_from(number_of_accounts).unwrap_or(u16::MAX),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::accountant::payment_adjuster::miscellaneous::data_structures::AffordableAndRequiredTxCounts;
    use ethereum_types::U256;

    #[test]
    fn there_is_u16_ceiling_for_possible_tx_count() {
        let corrections_from_u16_max = [-3_i8, -1, 0, 1, 10];
        let prepared_input_numbers = corrections_from_u16_max
            .into_iter()
            .map(plus_minus_correction_for_u16_max)
            .map(U256::from);
        let result = prepared_input_numbers
            .map(|max_possible_tx_count| {
                let detected_tx_counts =
                    AffordableAndRequiredTxCounts::new(max_possible_tx_count, 123);
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
        let corrections_from_u16_max = [-9_i8, -1, 0, 1, 5];
        let right_input_numbers = corrections_from_u16_max
            .into_iter()
            .map(plus_minus_correction_for_u16_max);
        let result = right_input_numbers
            .map(|required_tx_count_usize| {
                let detected_tx_counts =
                    AffordableAndRequiredTxCounts::new(U256::from(123), required_tx_count_usize);
                detected_tx_counts.required
            })
            .collect::<Vec<_>>();

        assert_eq!(
            result,
            vec![u16::MAX - 9, u16::MAX - 1, u16::MAX, u16::MAX, u16::MAX]
        )
    }

    fn plus_minus_correction_for_u16_max(correction: i8) -> usize {
        if correction < 0 {
            (u16::MAX - correction.abs() as u16) as usize
        } else {
            u16::MAX as usize + correction as usize
        }
    }
}
