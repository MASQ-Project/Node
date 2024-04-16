// Copyright (c) 2024, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::db_access_objects::payable_dao::PayableAccount;
use crate::accountant::payment_adjuster::miscellaneous::data_structures::{
    AdjustedAccountBeforeFinalization, UnconfirmedAdjustment, WeightedPayable,
};
use crate::accountant::QualifiedPayableAccount;

// If passing along without PA just to BlockchainBridge
impl From<QualifiedPayableAccount> for PayableAccount {
    fn from(qualified_payable: QualifiedPayableAccount) -> Self {
        qualified_payable.bare_account
    }
}

// After transaction fee adjustment while no need to go off with the other fee, and so we want to
// drop the weights etc.
impl From<WeightedPayable> for PayableAccount {
    fn from(weighted_account: WeightedPayable) -> Self {
        todo!()
    }
}

impl From<AdjustedAccountBeforeFinalization> for PayableAccount {
    fn from(non_finalized_adjustment: AdjustedAccountBeforeFinalization) -> Self {
        let mut account = non_finalized_adjustment.original_account;
        account.balance_wei = non_finalized_adjustment.proposed_adjusted_balance_minor;
        account
    }
}

// Preparing "remaining, unresolved accounts" for another iteration that always begins with
// WeightedPayable types
impl From<UnconfirmedAdjustment> for WeightedPayable {
    fn from(unconfirmed_adjustment: UnconfirmedAdjustment) -> Self {
        unconfirmed_adjustment.weighted_account
    }
}

// Used after the unconfirmed adjustment pass through all confirmations
impl From<UnconfirmedAdjustment> for AdjustedAccountBeforeFinalization {
    fn from(unconfirmed_adjustment: UnconfirmedAdjustment) -> Self {
        let proposed_adjusted_balance_minor =
            unconfirmed_adjustment.proposed_adjusted_balance_minor;
        let original_account = unconfirmed_adjustment
            .weighted_account
            .analyzed_account
            .qualified_as
            .bare_account;

        AdjustedAccountBeforeFinalization::new(original_account, proposed_adjusted_balance_minor)
    }
}

// This is used when we detect that the upcoming iterations begins with a surplus in the remaining
// unallocated CW service fee, and therefore we grant the remaining accounts with the full balance
// they requested
impl From<WeightedPayable> for AdjustedAccountBeforeFinalization {
    fn from(weighted_account: WeightedPayable) -> Self {
        let proposed_adjusted_balance_minor = weighted_account.balance_minor();
        let original_account = weighted_account.analyzed_account.qualified_as.bare_account;

        AdjustedAccountBeforeFinalization::new(original_account, proposed_adjusted_balance_minor)
    }
}

#[cfg(test)]
mod tests {
    use crate::accountant::db_access_objects::payable_dao::PayableAccount;
    use crate::accountant::payment_adjuster::miscellaneous::data_structures::{
        AdjustedAccountBeforeFinalization, UnconfirmedAdjustment, WeightedPayable,
    };
    use crate::accountant::test_utils::{
        make_non_guaranteed_qualified_payable, make_payable_account,
    };
    use crate::accountant::{AnalyzedPayableAccount, CreditorThresholds, QualifiedPayableAccount};

    #[test]
    fn conversion_between_non_finalized_account_and_payable_account_is_implemented() {
        let mut original_payable_account = make_payable_account(123);
        original_payable_account.balance_wei = 200_000_000;
        let non_finalized_account =
            AdjustedAccountBeforeFinalization::new(original_payable_account.clone(), 123_456_789);

        let result = PayableAccount::from(non_finalized_account);

        original_payable_account.balance_wei = 123_456_789;
        assert_eq!(result, original_payable_account)
    }

    fn prepare_weighted_account(payable_account: PayableAccount) -> WeightedPayable {
        let garbage_disqualification_limit = 333_333_333;
        let garbage_weight = 777_777_777;
        let mut analyzed_account = AnalyzedPayableAccount::new(
            make_non_guaranteed_qualified_payable(111),
            garbage_disqualification_limit,
        );
        analyzed_account.qualified_as.bare_account = payable_account;
        WeightedPayable::new(analyzed_account, garbage_weight)
    }
    #[test]
    fn conversion_between_weighted_payable_and_non_finalized_account_is_implemented() {
        let mut original_payable_account = make_payable_account(123);
        original_payable_account.balance_wei = 200_000_000;
        let weighted_account = prepare_weighted_account(original_payable_account.clone());

        let result = AdjustedAccountBeforeFinalization::from(weighted_account);

        let expected_result =
            AdjustedAccountBeforeFinalization::new(original_payable_account, 200_000_000);
        assert_eq!(result, expected_result)
    }

    #[test]
    fn conversion_between_unconfirmed_adjustment_and_non_finalized_account_is_implemented() {
        let mut original_payable_account = make_payable_account(123);
        original_payable_account.balance_wei = 200_000_000;
        let weighted_account = prepare_weighted_account(original_payable_account.clone());
        let unconfirmed_adjustment =
            UnconfirmedAdjustment::new(weighted_account, 111_222_333);

        let result = AdjustedAccountBeforeFinalization::from(unconfirmed_adjustment);

        let expected_result =
            AdjustedAccountBeforeFinalization::new(original_payable_account, 111_222_333);
        assert_eq!(result, expected_result)
    }
}
