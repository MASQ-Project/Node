// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

//chains according to
//a) their utilization of the fee market (implying the requirement of a gas price proposal)
//b) custom limit of computation ("gas" limit)
//*wr = without any research yet

//CHAIN                 a)      b)
//Ethereum, Polygon     yes     yes
//Bitcoin               yes     no
//Qtum                  yes     *wr
//NEO                   yes     *wr
//Cardano               No      *wr

use crate::arbitrary_id_stamp_in_trait;
use crate::blockchain::blockchain_interface::{BlockchainError, BlockchainInterface};
use crate::db_config::persistent_configuration::{PersistentConfigError, PersistentConfiguration};
use crate::sub_lib::blockchain_bridge::ConsumingWalletBalances;
use crate::test_utils::unshared_test_utils::arbitrary_id_stamp::ArbitraryIdStamp;
use std::fmt::{Debug, Formatter};
use web3::types::U256;

pub trait PayablePaymentsAgent: Send {
    //e.g. Cardano does not require user's own choice of price
    fn ask_for_price_per_computed_unit(
        &mut self,
        persistent_config: &dyn PersistentConfiguration,
    ) -> Result<(), PersistentConfigError>;
    fn ask_for_pending_transaction_id(
        &mut self,
        blockchain_interface: &dyn BlockchainInterface,
    ) -> Result<(), BlockchainError>;
    fn set_up_consuming_wallet_balances(&mut self, balances: ConsumingWalletBalances);
    fn estimated_fees(&self, number_of_transactions: usize) -> u128;
    fn consuming_wallet_balances(&self) -> Option<&ConsumingWalletBalances>;
    fn price_per_computed_unit(&self) -> Option<u64>;
    fn pending_transaction_id(&self) -> Option<U256>;
    fn debug(&self) -> String;
    fn duplicate(&self) -> Box<dyn PayablePaymentsAgent>;
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
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use crate::accountant::scanners::payable_payments_agent_abstract_layer::PayablePaymentsAgent;
    use crate::accountant::scanners::payable_payments_agent_web3::PayablePaymentsAgentWeb3;
    use crate::accountant::test_utils::PayablePaymentsAgentMock;
    use crate::test_utils::unshared_test_utils::arbitrary_id_stamp::ArbitraryIdStamp;
    use web3::types::U256;

    #[test]
    fn even_abstract_payable_payments_agent_implements_partial_eq() {
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

        agent_a.ask_for_pending_transaction_id(U256::from(1234));
        agent_c.ask_for_pending_transaction_id(U256::from(1234));
        assert_eq!(&agent_a, &agent_c);
        agent_c.ask_for_pending_transaction_id(U256::from(5678));
        assert_ne!(&agent_a, &agent_c);
    }

    #[test]
    fn payable_payments_agent_implements_debug() {
        let subject = Box::new(PayablePaymentsAgentWeb3::new(456)) as Box<dyn PayablePaymentsAgent>;

        let result = format!("{:?}", subject);

        let expected = "Trait object of: PayablePaymentsAgentWeb3 \
        { gas_limit_const_part: 456, upmost_added_gas_margin: 3328, pending_transaction_id_opt: None }";
        assert_eq!(result, expected)
    }
}
