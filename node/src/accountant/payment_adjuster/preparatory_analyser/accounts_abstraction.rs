use crate::accountant::payment_adjuster::disqualification_arbiter::DisqualificationArbiter;
use crate::accountant::payment_adjuster::miscellaneous::data_structures::WeightedPayable;
use crate::accountant::{AnalyzedPayableAccount, QualifiedPayableAccount};

pub trait DisqualificationAnalysableAccount<Product>: BalanceProvidingAccount
where
    Product: BalanceProvidingAccount + DisqualificationLimitProvidingAccount,
{
    fn prepare_analyzable_account(
        self,
        disqualification_arbiter: &DisqualificationArbiter,
    ) -> Product;
}

pub trait BalanceProvidingAccount {
    fn balance_minor(&self) -> u128;
}

pub trait DisqualificationLimitProvidingAccount {
    fn disqualification_limit(&self) -> u128;
}

impl DisqualificationAnalysableAccount<WeightedPayable> for WeightedPayable {
    fn prepare_analyzable_account(
        self,
        _disqualification_arbiter: &DisqualificationArbiter,
    ) -> WeightedPayable {
        self
    }
}

impl BalanceProvidingAccount for WeightedPayable {
    fn balance_minor(&self) -> u128 {
        self.analyzed_account.balance_minor()
    }
}

impl DisqualificationLimitProvidingAccount for WeightedPayable {
    fn disqualification_limit(&self) -> u128 {
        self.analyzed_account.disqualification_limit()
    }
}

impl DisqualificationLimitProvidingAccount for AnalyzedPayableAccount {
    fn disqualification_limit(&self) -> u128 {
        self.disqualification_limit_minor
    }
}

impl BalanceProvidingAccount for AnalyzedPayableAccount {
    fn balance_minor(&self) -> u128 {
        self.qualified_as.balance_minor()
    }
}

impl DisqualificationAnalysableAccount<AnalyzedPayableAccount> for QualifiedPayableAccount {
    fn prepare_analyzable_account(
        self,
        disqualification_arbiter: &DisqualificationArbiter,
    ) -> AnalyzedPayableAccount {
        let dsq_limit = disqualification_arbiter.calculate_disqualification_edge(&self);
        AnalyzedPayableAccount::new(self, dsq_limit)
    }
}

impl BalanceProvidingAccount for QualifiedPayableAccount {
    fn balance_minor(&self) -> u128 {
        self.bare_account.balance_wei
    }
}
