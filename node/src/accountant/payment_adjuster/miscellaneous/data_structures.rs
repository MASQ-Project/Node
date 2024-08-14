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

    pub fn balance_minor(&self) -> u128 {
        self.analyzed_account.qualified_as.bare_account.balance_wei
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct AdjustmentIterationResult {
    pub decided_accounts: DecidedAccounts,
    pub remaining_undecided_accounts: Vec<WeightedPayable>,
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

#[derive(Debug, PartialEq, Eq)]
pub enum DecidedAccounts {
    LowGainingAccountEliminated,
    SomeAccountsProcessed(Vec<AdjustedAccountBeforeFinalization>),
}

impl From<DecidedAccounts> for Vec<AdjustedAccountBeforeFinalization> {
    fn from(decided_accounts: DecidedAccounts) -> Self {
        match decided_accounts {
            DecidedAccounts::LowGainingAccountEliminated => vec![],
            DecidedAccounts::SomeAccountsProcessed(accounts) => accounts,
        }
    }
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

    pub fn balance_minor(&self) -> u128 {
        self.weighted_account.balance_minor()
    }

    pub fn disqualification_limit_minor(&self) -> u128 {
        self.weighted_account
            .analyzed_account
            .disqualification_limit_minor
    }
}

pub struct TransactionCountsBy16bits {
    pub affordable: u16,
    pub required: u16,
}

impl TransactionCountsBy16bits {
    pub fn new(max_possible_tx_count: U256, number_of_accounts: usize) -> Self {
        TransactionCountsBy16bits {
            affordable: u16::try_from(max_possible_tx_count).unwrap_or(u16::MAX),
            required: u16::try_from(number_of_accounts).unwrap_or(u16::MAX),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::accountant::payment_adjuster::miscellaneous::data_structures::{
        AdjustedAccountBeforeFinalization, RecursionResults, TransactionCountsBy16bits,
    };
    use crate::accountant::test_utils::make_payable_account;
    use ethereum_types::U256;

    #[test]
    fn merging_results_from_recursion_works() {
        let non_finalized_account_1 =
            AdjustedAccountBeforeFinalization::new(make_payable_account(111), 12345, 1234);
        let non_finalized_account_2 =
            AdjustedAccountBeforeFinalization::new(make_payable_account(222), 543, 5555);
        let non_finalized_account_3 =
            AdjustedAccountBeforeFinalization::new(make_payable_account(333), 789987, 6789);
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
        let corrections_from_u16_max = [-3_i8, -1, 0, 1, 10];
        let result = corrections_from_u16_max
            .into_iter()
            .map(plus_minus_correction_for_u16_max)
            .map(U256::from)
            .map(|max_possible_tx_count| {
                let detected_tx_counts = TransactionCountsBy16bits::new(max_possible_tx_count, 123);
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
        let result = corrections_from_u16_max
            .into_iter()
            .map(plus_minus_correction_for_u16_max)
            .map(|required_tx_count_usize| {
                let detected_tx_counts =
                    TransactionCountsBy16bits::new(U256::from(123), required_tx_count_usize);
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
