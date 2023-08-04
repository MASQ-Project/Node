// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::database_access_objects::payable_dao::PayableAccount;
use crate::sub_lib::wallet::Wallet;

#[derive(Debug)]
pub enum AccountsRecreationResult {
    AllAccountsCleanlyProcessed(Vec<AdjustedAccountBeforeFinalization>),
    InsignificantAccounts {
        disqualified: DisqualifiedPayableAccount,
        remaining: Vec<PayableAccount>,
    },
    OutweighedAccounts {
        outweighed: Vec<AdjustedAccountBeforeFinalization>,
        remaining: Vec<PayableAccount>,
    },
}

#[derive(Debug)]
pub struct AdjustmentIterationSummary {
    pub decided_accounts: Vec<AdjustedAccountBeforeFinalization>,
    pub remaining_accounts: Vec<PayableAccount>,
    pub disqualified_account_opt: Option<DisqualifiedPayableAccount>,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct AdjustedAccountBeforeFinalization {
    pub original_account: PayableAccount,
    pub proposed_adjusted_balance: u128,
    pub criteria_sum: u128,
}

impl AdjustedAccountBeforeFinalization {
    pub fn new(
        original_account: PayableAccount,
        proposed_adjusted_balance: u128,
        criteria_sum: u128,
    ) -> Self {
        Self {
            original_account,
            proposed_adjusted_balance,
            criteria_sum,
        }
    }

    pub fn finalize_collection_of_self(
        account_infos: Vec<Self>,
        resolution: ResolutionAfterFullyDetermined,
    ) -> Vec<PayableAccount> {
        account_infos
            .into_iter()
            .map(|account_info| PayableAccount::from((account_info, resolution)))
            .collect()
    }
}

#[derive(Clone, Copy)]
pub enum ResolutionAfterFullyDetermined {
    Finalize,
    Revert,
}

#[derive(Debug, PartialEq, Eq)]
pub struct DisqualifiedPayableAccount {
    pub wallet: Wallet,
    pub proposed_adjusted_balance: u128,
    pub original_balance: u128,
}

impl DisqualifiedPayableAccount {
    pub fn new(wallet: Wallet, original_balance: u128, proposed_adjusted_balance: u128) -> Self {
        Self {
            wallet,
            proposed_adjusted_balance,
            original_balance,
        }
    }
}
