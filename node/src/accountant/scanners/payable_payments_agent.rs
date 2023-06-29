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
use crate::sub_lib::blockchain_bridge::ConsumingWalletBalances;
use crate::test_utils::unshared_test_utils::arbitrary_id_stamp::ArbitraryIdStamp;
use primitive_types::U256;
use std::fmt::{Debug, Formatter};

pub trait PayablePaymentsAgent: Send {
    //e.g. Cardano does not require user's own choice of price
    fn set_up_price_per_computed_unit(&mut self, price: Option<u64>);
    fn set_up_pending_transaction_id(&mut self, id: U256);
    fn set_up_consuming_wallet_balances(&mut self, balances: ConsumingWalletBalances);
    fn estimated_fees(&self, number_of_transactions: usize) -> u128;
    fn consuming_wallet_balances(&self) -> ConsumingWalletBalances;
    fn requested_price_per_computed_unit(&self) -> Option<u64>;
    fn pending_transaction_id(&self) -> Option<U256>;
    fn debug(&self) -> String;
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

#[derive(Debug)]
pub struct PayablePaymentsAgentWeb3 {
    gas_limit_const_part: u64,
    upmost_added_gas_margin: u64,
    pending_transaction_id_opt: Option<U256>,
}

impl PayablePaymentsAgent for PayablePaymentsAgentWeb3 {
    fn set_up_price_per_computed_unit(&mut self, price: Option<u64>) {
        todo!()
    }

    fn set_up_pending_transaction_id(&mut self, id: U256) {
        self.pending_transaction_id_opt.replace(id);
    }

    fn set_up_consuming_wallet_balances(&mut self, balances: ConsumingWalletBalances) {
        todo!()
    }

    fn estimated_fees(&self, number_of_transactions: usize) -> u128 {
        todo!()
    }

    fn consuming_wallet_balances(&self) -> ConsumingWalletBalances {
        todo!()
    }

    fn requested_price_per_computed_unit(&self) -> Option<u64> {
        todo!()
    }

    fn pending_transaction_id(&self) -> Option<U256> {
        todo!()
    }

    fn debug(&self) -> String {
        format!("{:?}", self)
    }
}

pub const WEB3_MAXIMAL_GAS_LIMIT_MARGIN: u64 = 3328; //64 * (64 - 12) ... std transaction has data of 64 bytes and 12 bytes are never used with us; each non-zero byte costs 64 units of gas

impl PayablePaymentsAgentWeb3 {
    pub fn new(gas_limit_const_part: u64) -> Self {
        Self {
            gas_limit_const_part,
            upmost_added_gas_margin: WEB3_MAXIMAL_GAS_LIMIT_MARGIN,
            pending_transaction_id_opt: None,
        }
    }
}

// pub struct Web3TransactionCalculator {
//     gas_limit_const_part: u64,
//     upmost_added_gas_margin: u64,
// }
//
// impl TransactionFeesCalculator for Web3TransactionFeesCalculator {
//     fn calculate_fees(&self, number_of_transactions: usize) -> u128 {
//         ((self.upmost_added_gas_margin + self.gas_limit_const_part) * number_of_transactions as u64) as u128
//     }
// }
//
// impl Web3TransactionFeesCalculator {
//     pub fn new(gas_limit_const_part: u64) -> Self{
//         Self{ gas_limit_const_part, upmost_added_gas_margin: WEB3_MAXIMAL_GAS_LIMIT_MARGIN}
//     }
// }

#[cfg(test)]
mod tests {
    use crate::accountant::scanners::payable_payments_agent::{
        PayablePaymentsAgent, PayablePaymentsAgentWeb3, WEB3_MAXIMAL_GAS_LIMIT_MARGIN,
    };
    use crate::accountant::test_utils::PayablePaymentsAgentMock;
    use crate::test_utils::unshared_test_utils::arbitrary_id_stamp::ArbitraryIdStamp;
    use primitive_types::U256;

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

        agent_a.set_up_pending_transaction_id(U256::from(1234));
        agent_c.set_up_pending_transaction_id(U256::from(1234));
        assert_eq!(&agent_a, &agent_c);
        agent_c.set_up_pending_transaction_id(U256::from(5678));
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

    // #[test]
    // fn web3_transaction_fees_calculator_can_be_properly_constructed() {
    //     let result = Web3TransactionFeesCalculator::new(1369);
    //
    //     assert_eq!(
    //         result.upmost_added_gas_margin,
    //         WEB3_MAXIMAL_GAS_LIMIT_MARGIN
    //     );
    //     assert_eq!(result.gas_limit_const_part, 1369);
    // }
    //
    // #[test]
    // fn web3_transaction_fees_calculator_calculates_fees() {
    //     let one_calculator = Web3TransactionFeesCalculator::new(11111);
    //     let second_calculator = Web3TransactionFeesCalculator::new(444);
    //
    //     assert_eq!(
    //         one_calculator.calculate_fees(7),
    //         (7 * (11111 + WEB3_MAXIMAL_GAS_LIMIT_MARGIN)) as u128
    //     );
    //     assert_eq!(
    //         second_calculator.calculate_fees(3),
    //         (3 * (444 + WEB3_MAXIMAL_GAS_LIMIT_MARGIN)) as u128
    //     )
    // }

    // #[test]
    // fn blockchain_interface_non_clandestine_returns_fees_calculator_for_eth_chains() {
    //     let eth_chains = vec![Chain::EthMainnet, Chain::EthRopsten, Chain::Dev];
    //     assert_appropriate_fees_calculator_given_by_web3_blockchain_interface(&eth_chains)
    // }
    //
    // #[test]
    // fn blockchain_interface_non_clandestine_returns_fees_calculator_for_polygon_chains() {
    //     let polygon_chains = vec![Chain::PolyMainnet, Chain::PolyMumbai];
    //     assert_appropriate_fees_calculator_given_by_web3_blockchain_interface(&polygon_chains)
    // }
    //
    // fn assert_appropriate_fees_calculator_given_by_web3_blockchain_interface(chains: &[Chain]) {
    //     chains.iter().enumerate().for_each(|(idx, chain)| {
    //         let subject = BlockchainInterfaceNonClandestine::new(
    //             TestTransport::default(),
    //             make_fake_event_loop_handle(),
    //             *chain,
    //             web3_gas_limit_const_part(*chain),
    //         );
    //         let fees_calculator = subject.transaction_fees_calculator();
    //
    //         assert_eq!(
    //             fees_calculator.calculate_fees(idx),
    //             (idx as u64 * (web3_gas_limit_const_part(*chain) + WEB3_MAXIMAL_GAS_LIMIT_MARGIN))
    //                 as u128
    //         )
    //     })
    // }
}
