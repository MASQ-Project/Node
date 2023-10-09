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
