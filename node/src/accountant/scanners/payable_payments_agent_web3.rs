// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::scanners::payable_payments_agent_abstract_layer::PayablePaymentsAgent;
use crate::blockchain::blockchain_interface::{BlockchainError, BlockchainInterface};
use crate::db_config::persistent_configuration::{PersistentConfigError, PersistentConfiguration};
use crate::sub_lib::blockchain_bridge::ConsumingWalletBalances;
use web3::types::U256;

#[derive(Debug, Clone)]
pub struct PayablePaymentsAgentWeb3 {
    gas_limit_const_part: u64,
    upmost_added_gas_margin: u64,
    consuming_wallet_balance_opt: Option<ConsumingWalletBalances>,
    pending_transaction_id_opt: Option<U256>,
    price_per_computed_unit_gwei_opt: Option<u64>,
}

impl PayablePaymentsAgent for PayablePaymentsAgentWeb3 {
    fn ask_for_price_per_computed_unit(
        &mut self,
        persistent_config: &dyn PersistentConfiguration,
    ) -> Result<(), PersistentConfigError> {
        todo!() //self.price_per_computed_unit_gwei_opt = price
    }

    fn ask_for_pending_transaction_id(
        &mut self,
        blockchain_interface: &dyn BlockchainInterface,
    ) -> Result<(), BlockchainError> {
        todo!() //   self.pending_transaction_id_opt.replace(id);

        //TODO the below was original code from BlockchainBridge
        // .get_transaction_count(consuming_wallet)
        //     .map_err(PayableTransactionError::TransactionCount)?;
    }

    fn set_up_consuming_wallet_balances(&mut self, balances: ConsumingWalletBalances) {
        self.consuming_wallet_balance_opt.replace(balances);
    }

    fn estimated_fees(&self, number_of_transactions: usize) -> u128 {
        todo!()
    }

    fn consuming_wallet_balances(&self) -> Option<&ConsumingWalletBalances> {
        self.consuming_wallet_balance_opt.as_ref()
    }

    fn price_per_computed_unit(&self) -> Option<u64> {
        self.price_per_computed_unit_gwei_opt
    }

    fn pending_transaction_id(&self) -> Option<U256> {
        self.pending_transaction_id_opt
    }

    fn debug(&self) -> String {
        format!("{:?}", self)
    }

    fn duplicate(&self) -> Box<dyn PayablePaymentsAgent> {
        todo!()
    }
}

pub const WEB3_MAXIMAL_GAS_LIMIT_MARGIN: u64 = 3328; //64 * (64 - 12) ... std transaction has data of 64 bytes and 12 bytes are never used with us; each non-zero byte costs 64 units of gas

impl PayablePaymentsAgentWeb3 {
    pub fn new(gas_limit_const_part: u64) -> Self {
        Self {
            gas_limit_const_part,
            upmost_added_gas_margin: WEB3_MAXIMAL_GAS_LIMIT_MARGIN,
            consuming_wallet_balance_opt: None,
            pending_transaction_id_opt: None,
            price_per_computed_unit_gwei_opt: None,
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
    use crate::accountant::scanners::payable_payments_agent_abstract_layer::PayablePaymentsAgent;
    use crate::accountant::scanners::payable_payments_agent_web3::{
        PayablePaymentsAgentWeb3, WEB3_MAXIMAL_GAS_LIMIT_MARGIN,
    };
    use crate::sub_lib::blockchain_bridge::ConsumingWalletBalances;
    use web3::types::U256;

    #[test]
    fn constants_are_correct() {
        assert_eq!(WEB3_MAXIMAL_GAS_LIMIT_MARGIN, 3328)
    }

    #[test]
    fn payable_payments_agent_is_properly_constructed() {
        let subject = PayablePaymentsAgentWeb3::new(455);

        assert_eq!(subject.gas_limit_const_part, 455);
        assert_eq!(
            subject.upmost_added_gas_margin,
            WEB3_MAXIMAL_GAS_LIMIT_MARGIN
        );
        assert_eq!(subject.pending_transaction_id_opt, None);
        assert_eq!(subject.price_per_computed_unit_gwei_opt, None)
    }

    #[test]
    fn set_and_get_for_price_per_computed_unit_works() {
        let mut subject = PayablePaymentsAgentWeb3::new(12345);

        subject.ask_for_price_per_computed_unit(Some(8765));

        assert_eq!(subject.price_per_computed_unit(), Some(8765))
    }

    #[test]
    fn set_and_get_for_pending_transaction_id_works() {
        let mut subject = PayablePaymentsAgentWeb3::new(12345);

        subject.ask_for_pending_transaction_id(U256::from(654));

        assert_eq!(subject.pending_transaction_id(), Some(U256::from(654)))
    }

    #[test]
    fn set_and_get_for_consuming_wallet_balances_works() {
        let mut subject = PayablePaymentsAgentWeb3::new(12345);
        let consuming_wallet_balances = ConsumingWalletBalances {
            transaction_fee_currency_in_minor_units: U256::from(45_000),
            masq_tokens_in_minor_units: U256::from(30_000),
        };

        subject.set_up_consuming_wallet_balances(consuming_wallet_balances.clone());

        assert_eq!(
            subject.consuming_wallet_balances(),
            Some(&consuming_wallet_balances)
        )
    }

    #[test]
    fn debug_works() {
        let subject = PayablePaymentsAgentWeb3::new(789);
        let std_debug = format!("{:?}", subject);

        let debug_from_trait = subject.debug();

        assert_eq!(debug_from_trait, std_debug)
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
