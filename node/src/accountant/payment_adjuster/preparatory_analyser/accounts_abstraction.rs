// Copyright (c) 2024, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::payment_adjuster::miscellaneous::data_structures::WeighedPayable;
use crate::accountant::{AnalyzedPayableAccount, QualifiedPayableAccount};

pub trait BalanceProvidingAccount {
    fn initial_balance_minor(&self) -> u128;
}

impl BalanceProvidingAccount for WeighedPayable {
    fn initial_balance_minor(&self) -> u128 {
        self.analyzed_account.initial_balance_minor()
    }
}

impl BalanceProvidingAccount for AnalyzedPayableAccount {
    fn initial_balance_minor(&self) -> u128 {
        self.qualified_as.initial_balance_minor()
    }
}

impl BalanceProvidingAccount for QualifiedPayableAccount {
    fn initial_balance_minor(&self) -> u128 {
        self.bare_account.balance_wei
    }
}

pub trait DisqualificationLimitProvidingAccount {
    fn disqualification_limit(&self) -> u128;
}

impl DisqualificationLimitProvidingAccount for WeighedPayable {
    fn disqualification_limit(&self) -> u128 {
        self.analyzed_account.disqualification_limit()
    }
}

impl DisqualificationLimitProvidingAccount for AnalyzedPayableAccount {
    fn disqualification_limit(&self) -> u128 {
        self.disqualification_limit_minor
    }
}
