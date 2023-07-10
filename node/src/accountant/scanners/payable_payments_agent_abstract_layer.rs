// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

#[cfg(test)]
use crate::arbitrary_id_stamp_in_trait;
use crate::db_config::persistent_configuration::{PersistentConfigError, PersistentConfiguration};
use crate::sub_lib::blockchain_bridge::ConsumingWalletBalances;
#[cfg(test)]
use crate::test_utils::unshared_test_utils::arbitrary_id_stamp::ArbitraryIdStamp;
use std::fmt::{Debug, Formatter};
use web3::types::U256;

// Table of chains by
//
// a) adoption of the fee market (variations on "gas price")
// b) customizable limit of allowed computation ("gas limit")
//
// CHAINS                    a)  |  b)
//-------------------------------+------
// Ethereum                 yes  |  yes
// Polygon                  yes  |  yes
// Qtum                     yes  |  yes
// NEO                      yes  |  no*
// Cardano                  no   |  yes
// Bitcoin                  yes  |  no

//* defaulted limit

pub trait PayablePaymentsAgent: Send {
    // the nature of a method of this kind lies in the possibility of the need to
    // refuse the consultant's  and leave the parameter out for uselessness
    // e.g. Cardano does not require user's own choice of fee size
    fn deliberate_required_fee_per_computed_unit(
        &mut self,
        consultant: &dyn PersistentConfiguration,
    ) -> Result<(), PersistentConfigError>;
    fn set_up_pending_transaction_id(&mut self, id: U256);
    fn set_up_consuming_wallet_balances(&mut self, balances: ConsumingWalletBalances);
    fn estimated_transaction_fee_total(&self, number_of_transactions: usize) -> u128;
    fn consuming_wallet_balances(&self) -> Option<ConsumingWalletBalances>;
    fn required_fee_per_computed_unit(&self) -> Option<u64>;
    fn pending_transaction_id(&self) -> Option<U256>;
    // this method has the taste of a hack but the concept can be powerful: if the implementor itself
    // takes Debug we can easily make a string representation and return it; because of the nature
    // of the received human readable decoded chars put together we can operate with kind of generics
    // at the return; that means that, with quite low struggle, we've bypassed the pitfalls from the
    // Debug (and PartialEq) implementing objects considered as automatically trait object unsafe.
    // This attempt to break it has a huge benefit: we can go ahead and compare the Debug output to
    // verify differences or equality between the instances, including having a way to see
    // the differences if they don't match
    fn debug(&self) -> String;
    fn duplicate(&self) -> Box<dyn PayablePaymentsAgent>;

    #[cfg(test)]
    arbitrary_id_stamp_in_trait!();
}

impl PartialEq for Box<dyn PayablePaymentsAgent> {
    fn eq(&self, other: &Self) -> bool {
        self.debug() == other.debug()
    }
}

impl Debug for Box<dyn PayablePaymentsAgent> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Trait object of: {}", self.debug())
    }
}

impl Clone for Box<dyn PayablePaymentsAgent> {
    fn clone(&self) -> Self {
        self.duplicate()
    }
}

#[cfg(test)]
mod tests {
    use crate::accountant::scanners::payable_payments_agent_abstract_layer::PayablePaymentsAgent;
    use crate::accountant::scanners::payable_payments_agent_web3::PayablePaymentsAgentWeb3;
    use crate::accountant::test_utils::{
        assert_on_cloneable_agent_objects, PayablePaymentsAgentMock,
    };
    use crate::test_utils::unshared_test_utils::arbitrary_id_stamp::ArbitraryIdStamp;
    use web3::types::U256;

    #[test]
    fn trait_object_like_payable_payments_agent_implements_partial_eq() {
        let mut agent_a =
            Box::new(PayablePaymentsAgentWeb3::new(45678)) as Box<dyn PayablePaymentsAgent>;
        let agent_b =
            Box::new(PayablePaymentsAgentWeb3::new(78910)) as Box<dyn PayablePaymentsAgent>;
        let mut agent_c =
            Box::new(PayablePaymentsAgentWeb3::new(45678)) as Box<dyn PayablePaymentsAgent>;
        let id_stamp_1 = ArbitraryIdStamp::new();
        let id_stamp_2 = ArbitraryIdStamp::new();
        let agent_d =
            Box::new(PayablePaymentsAgentMock::default().set_arbitrary_id_stamp(id_stamp_1))
                as Box<dyn PayablePaymentsAgent>;
        let agent_e =
            Box::new(PayablePaymentsAgentMock::default().set_arbitrary_id_stamp(id_stamp_1))
                as Box<dyn PayablePaymentsAgent>;
        let agent_f =
            Box::new(PayablePaymentsAgentMock::default().set_arbitrary_id_stamp(id_stamp_2))
                as Box<dyn PayablePaymentsAgent>;

        assert_ne!(&agent_a, &agent_b);
        assert_eq!(&agent_a, &agent_c);
        assert_ne!(&agent_b, &agent_d);
        assert_eq!(&agent_d, &agent_e);
        assert_ne!(&agent_d, &agent_f);

        agent_a.set_up_pending_transaction_id(U256::from(1234));
        agent_c.set_up_pending_transaction_id(U256::from(1234));
        assert_eq!(&agent_a, &agent_c);
        agent_c.set_up_pending_transaction_id(U256::from(5678));
        assert_ne!(&agent_a, &agent_c);
    }

    #[test]
    fn trait_object_like_payable_payments_agent_implements_debug() {
        let subject = Box::new(PayablePaymentsAgentWeb3::new(456)) as Box<dyn PayablePaymentsAgent>;

        let result = format!("{:?}", subject);

        let expected = "\
        Trait object of: PayablePaymentsAgentWeb3 { \
            gas_limit_const_part: 456, \
            upmost_added_gas_margin: 3328, \
            consuming_wallet_balance_opt: None, \
            pending_transaction_id_opt: None, \
            desired_fee_per_computed_unit_gwei_opt: None \
         }";
        assert_eq!(result, expected)
    }

    #[test]
    fn trait_object_like_payable_payments_agent_implements_clone() {
        assert_on_cloneable_agent_objects(|original_agent: PayablePaymentsAgentWeb3| {
            let boxed_agent = Box::new(original_agent) as Box<dyn PayablePaymentsAgent>;
            boxed_agent.clone()
        })
    }
}
