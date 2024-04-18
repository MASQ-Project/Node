// Copyright (c) 2023, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::db_access_objects::payable_dao::PayableAccount;
use crate::accountant::payment_adjuster::miscellaneous::helper_functions::sum_as;
use crate::accountant::payment_adjuster::preparatory_analyser::BalanceProvidingAccount;
use crate::accountant::{AnalyzedPayableAccount, QualifiedPayableAccount};
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

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct AdjustedAccountBeforeFinalization {
    pub original_account: PayableAccount,
    pub proposed_adjusted_balance_minor: u128,
}

impl AdjustedAccountBeforeFinalization {
    pub fn new(original_account: PayableAccount, proposed_adjusted_balance_minor: u128) -> Self {
        Self {
            original_account,
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
        &self.weighted_account.wallet()
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

#[derive(Debug)]
pub enum TransactionFeePastActionsContext {
    TransactionFeeCheckDone {
        limitation_opt: Option<TransactionFeeLimitation>,
    },
    TransactionFeeAccountsDumped {
        past_txs_count: usize,
        past_sum_of_service_fee_balances: u128,
    },
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct TransactionFeeLimitation {
    pub count_limit: u16,
    pub available_balance: u128,
    pub sum_of_transaction_fee_balances: u128,
}

impl TransactionFeePastActionsContext {
    pub fn accounts_dumped_context(whole_set_of_analyzed_accounts: &[WeightedPayable]) -> Self {
        let past_txs_count = whole_set_of_analyzed_accounts.len();
        let past_sum_of_service_fee_balances: u128 =
            sum_as(whole_set_of_analyzed_accounts, |account| {
                account.balance_minor()
            });
        Self::TransactionFeeAccountsDumped {
            past_txs_count,
            past_sum_of_service_fee_balances,
        }
    }

    pub fn check_done_context(limitation_opt: Option<TransactionFeeLimitation>) -> Self {
        Self::TransactionFeeCheckDone { limitation_opt }
    }
}

#[cfg(test)]
mod tests {
    use crate::accountant::payment_adjuster::miscellaneous::data_structures::{
        AdjustedAccountBeforeFinalization, RecursionResults, TransactionCountsBy16bits,
        TransactionFeePastActionsContext,
    };
    use crate::accountant::payment_adjuster::test_utils::make_weighed_account;
    use crate::accountant::test_utils::make_payable_account;
    use ethereum_types::U256;

    #[test]
    fn merging_results_from_recursion_works() {
        let non_finalized_account_1 = AdjustedAccountBeforeFinalization {
            original_account: make_payable_account(111),
            proposed_adjusted_balance_minor: 1234,
        };
        let non_finalized_account_2 = AdjustedAccountBeforeFinalization {
            original_account: make_payable_account(222),
            proposed_adjusted_balance_minor: 5555,
        };
        let non_finalized_account_3 = AdjustedAccountBeforeFinalization {
            original_account: make_payable_account(333),
            proposed_adjusted_balance_minor: 6789,
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

    #[test]
    fn construction_of_error_context_with_accounts_dumped_works() {
        let mut account_1 = make_weighed_account(123);
        account_1
            .analyzed_account
            .qualified_as
            .bare_account
            .balance_wei = 1234567;
        let mut account_2 = make_weighed_account(345);
        account_2
            .analyzed_account
            .qualified_as
            .bare_account
            .balance_wei = 999888777;
        let weighted_accounts = vec![account_1, account_2];

        let dump_performed =
            TransactionFeePastActionsContext::accounts_dumped_context(&weighted_accounts);

        match dump_performed {
            TransactionFeePastActionsContext::TransactionFeeAccountsDumped {
                past_txs_count: txs_count,
                past_sum_of_service_fee_balances: sum_of_transaction_fee_balances,
            } => {
                assert_eq!(txs_count, 2);
                assert_eq!(sum_of_transaction_fee_balances, 1234567 + 999888777)
            }
            x => panic!("We expected version for accounts dump but got: {:?}", x),
        }
    }
}
