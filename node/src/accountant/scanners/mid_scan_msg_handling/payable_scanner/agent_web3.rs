// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use std::collections::HashMap;
use web3::types::Address;
use crate::accountant::scanners::mid_scan_msg_handling::payable_scanner::blockchain_agent::BlockchainAgent;
use crate::sub_lib::blockchain_bridge::{ConsumingWalletBalances, QualifiedPayableGasPriceSetup};
use crate::sub_lib::wallet::Wallet;
use masq_lib::blockchains::chains::Chain;
use crate::accountant::scanners::mid_scan_msg_handling::payable_scanner::msgs::{QualifiedPayablesRawPack, QualifiedPayablesRipePack};

#[derive(Debug, Clone)]
pub struct BlockchainAgentWeb3 {
    estimated_gas_price_wei: u128,
    // gas_price_hashmap: HashMap<Address, u128>,
    // gas_limit_const_part: u128,
    // maximum_added_gas_margin: u128,
    consuming_wallet: Wallet,
    consuming_wallet_balances: ConsumingWalletBalances,
    chain: Chain,
}

impl BlockchainAgent for BlockchainAgentWeb3 {
    fn estimated_transaction_fee_total(&self) -> u128 {
        todo!()// self.gas_price_hashmap.values().sum::<u128>() * (self.gas_limit_const_part + self.maximum_added_gas_margin)
    }

    fn consuming_wallet_balances(&self) -> ConsumingWalletBalances {
        self.consuming_wallet_balances
    }

    fn consuming_wallet(&self) -> &Wallet {
        &self.consuming_wallet
    }

    fn get_chain(&self) -> Chain {
        self.chain
    }
}

// 64 * (64 - 12) ... std transaction has data of 64 bytes and 12 bytes are never used with us;
// each non-zero byte costs 64 units of gas
pub const WEB3_MAXIMAL_GAS_LIMIT_MARGIN: u128 = 3328;

impl BlockchainAgentWeb3 {
    pub fn new(
        latest_gas_price_wei: u128,
        qualified_payables: QualifiedPayablesRawPack,
        gas_limit_const_part: u128,
        consuming_wallet: Wallet,
        consuming_wallet_balances: ConsumingWalletBalances,
        chain: Chain,
    ) -> (Box<dyn BlockchainAgent>, QualifiedPayablesRipePack) {
        todo!()
        // let increase_gas_price_by_margin = |gas_price_wei: u128| { (gas_price_wei * (100_u128 + chain.rec().gas_price_recommended_margin_percents as u128)) / 100};
        // let gas_price_hashmap: HashMap<Address, u128> = match &inputs_for_gas_price_hashmap {
        //     InputsForGasPriceHashmap::NewPayableMode(addresses) => {
        //         let common_gas_price_wei = increase_gas_price_by_margin(latest_gas_price_wei);
        //         addresses.into_iter().map(|addr|(*addr, common_gas_price_wei)).collect()
        //     },
        //     InputsForGasPriceHashmap::RetryPayableMode(addresses_and_previous_attempt_gas_prices) => {
        //         addresses_and_previous_attempt_gas_prices.into_iter().map(|(addr, gas_price_wei)| (*addr, increase_gas_price_by_margin(*gas_price_wei))).collect()
        //     }
        // }; 
        // 
        // Self {
        //     latest_gas_price_wei,
        //     gas_price_hashmap,
        //     gas_limit_const_part,
        //     consuming_wallet,
        //     maximum_added_gas_margin: WEB3_MAXIMAL_GAS_LIMIT_MARGIN,
        //     consuming_wallet_balances,
        //     chain,
        // }
    }
}

#[cfg(test)]
mod tests {
    use crate::accountant::scanners::mid_scan_msg_handling::payable_scanner::agent_web3::{
        BlockchainAgentWeb3, WEB3_MAXIMAL_GAS_LIMIT_MARGIN,
    };
    use crate::accountant::scanners::mid_scan_msg_handling::payable_scanner::blockchain_agent::BlockchainAgent;
    use crate::sub_lib::blockchain_bridge::{ConsumingWalletBalances};
    use crate::test_utils::make_wallet;
    use masq_lib::test_utils::utils::TEST_DEFAULT_CHAIN;
    use web3::types::{U256};
    use crate::blockchain::test_utils::{increase_gas_price_by_marginal};

    #[test]
    fn constants_are_correct() {
        assert_eq!(WEB3_MAXIMAL_GAS_LIMIT_MARGIN, 3_328)
    }

    #[test]
    fn blockchain_agent_can_return_non_computed_input_values() {
        let gas_limit_const_part = 44_000;
        let consuming_wallet = make_wallet("abcde");
        let consuming_wallet_balances = ConsumingWalletBalances {
            transaction_fee_balance_in_minor_units: U256::from(456_789),
            masq_token_balance_in_minor_units: U256::from(123_000_000),
        };

        let subject = BlockchainAgentWeb3::new(
            2222,
            None,
            gas_limit_const_part,
            consuming_wallet.clone(),
            consuming_wallet_balances,
            TEST_DEFAULT_CHAIN,
        );

        assert_eq!(subject.consuming_wallet(), &consuming_wallet);
        assert_eq!(
            subject.consuming_wallet_balances(),
            consuming_wallet_balances
        );
        assert_eq!(subject.get_chain(), TEST_DEFAULT_CHAIN);
    }

    // #[test]
    // fn returns_correct_gas_price_for_new_payable_scan() {
    //     let consuming_wallet = make_wallet("efg");
    //     let consuming_wallet_balances = ConsumingWalletBalances {
    //         transaction_fee_balance_in_minor_units: Default::default(),
    //         masq_token_balance_in_minor_units: Default::default(),
    //     };
    //     let gas_price_from_rpc = 555566667777;
    //     let chain = TEST_DEFAULT_CHAIN;
    //     let gas_price_hashmap_inputs = make_populated_new_payable_gas_price_hashmap_inputs(2);
    //     let addresses = if let InputsForGasPriceHashmap::NewPayableMode(inputs) = &gas_price_hashmap_inputs {
    //         inputs.clone()
    //     } else {
    //         panic!("Expected NewPayableMode, got {:?}", gas_price_hashmap_inputs)
    //     };
    //     let agent = BlockchainAgentWeb3::new(
    //         gas_price_from_rpc,
    //         gas_price_hashmap_inputs,
    //         77_777,
    //         consuming_wallet,
    //         consuming_wallet_balances,
    //         chain,
    //     );
    // 
    //     let result = agent.gas_price_for_individual_txs();
    // 
    //     let expected_result = QualifiedPayableGasPriceSetup{ gas_price_arranged_for_individual_txs_minor: addresses.into_iter().map(|addr|(addr, gas_price_from_rpc)).collect(), gas_price_from_last_rpc_minor: gas_price_from_rpc };
    //     assert_eq!(result, expected_result);
    // }
    // 
    // #[test]
    // fn provides_gas_price_for_retry_payable_scan_if_the_latest_value_is_also_the_highest() {
    //     let gas_price_from_rpc = 500_500_000;
    //     let wallet_1 = make_wallet("abc");
    //     let wallet_2 = make_wallet("def");
    //     let previous_attempt_gas_price_values_wei = InputsForGasPriceHashmap::RetryPayableMode(hashmap! {wallet_1.address() => 500_500_001, wallet_2.address() => 333_000_000});
    //     let chain = TEST_DEFAULT_CHAIN;
    //     let increase_gas_price_by_margin = |gas_price_wei: u128| {
    //         gas_price_wei * (100_u128 + chain.rec().gas_price_recommended_margin_percents as u128) / 100
    //     };
    // 
    //     let result = compute_gas_price_for_test(
    //         chain,
    //         gas_price_from_rpc,
    //         previous_attempt_gas_price_values_wei,
    //     );
    // 
    //     let expected_result =
    //     QualifiedPayablesRipePack{ payables: vec![] }
    //     hashmap!(wallet_1.address() => increase_gas_price_by_margin(500_500_001), wallet_2.address() => increase_gas_price_by_margin(500_500_000));
    //     assert_eq!(result, expected_result);
    // }
    // 
    // #[test]
    // fn provides_gas_price_for_retry_payable_scan_if_the_latest_value_equals_the_previous_attempt() {
    //     let gas_price_from_rpc = 500_500_000;
    //     let wallet_1 = make_wallet("abc");
    //     let wallet_2 = make_wallet("def");
    //     let previous_attempt_gas_price_values_wei = InputsForGasPriceHashmap::RetryPayableMode(hashmap! {wallet_1.address() => 499_999_999, wallet_2.address() => 500_500_000});
    //     let chain = TEST_DEFAULT_CHAIN;
    //     let increase_gas_price_by_margin = |gas_price_wei: u128| {
    //         gas_price_wei * (100_u128 + chain.rec().gas_price_recommended_margin_percents as u128) / 100
    //     };
    // 
    //     let result = compute_gas_price_for_test(
    //         chain,
    //         gas_price_from_rpc,
    //         previous_attempt_gas_price_values_wei,
    //     );
    // 
    //     let expected_result = hashmap!(wallet_1.address() => increase_gas_price_by_margin(500_500_000), wallet_2.address() => increase_gas_price_by_margin(500_500_000));
    //     assert_eq!(result, expected_result);
    // }
    // 
    // #[test]
    // fn provides_gas_price_for_retry_payable_scan_if_the_prev_attempt_value_is_under_the_latest() {
    //     let gas_price_from_rpc = 500_500_000;
    //     let wallet_1 = make_wallet("abc");
    //     let wallet_2 = make_wallet("def");
    //     let previous_attempt_gas_price_values_wei = InputsForGasPriceHashmap::RetryPayableMode(hashmap! {wallet_1.address() => 500_499_999, wallet_2.address() => 333_000_000});
    //     let chain = TEST_DEFAULT_CHAIN;
    //     let increase_gas_price_by_margin = |gas_price_wei: u128| {
    //         gas_price_wei * (100_u128 + chain.rec().gas_price_recommended_margin_percents as u128) / 100
    //     };
    // 
    //     let result = compute_gas_price_for_test(
    //         chain,
    //         gas_price_from_rpc,
    //         previous_attempt_gas_price_values_wei,
    //     );
    // 
    //     let expected_result = hashmap!(wallet_1.address() => increase_gas_price_by_margin(500_500_000), wallet_2.address() => increase_gas_price_by_margin(500_500_000));
    //     assert_eq!(result, expected_result);
    // }
    // 
    // fn compute_gas_price_for_test(
    //     chain: Chain,
    //     gas_price_from_rpc: u128,
    //     gas_price_hashmap_inputs: InputsForGasPriceHashmap,
    // ) -> QualifiedPayablesRipePack{
    //     let consuming_wallet = make_wallet("efg");
    //     let consuming_wallet_balances = ConsumingWalletBalances {
    //         transaction_fee_balance_in_minor_units: Default::default(),
    //         masq_token_balance_in_minor_units: Default::default(),
    //     };
    //     let agent = BlockchainAgentWeb3::new(
    //         gas_price_from_rpc,
    //         gas_price_hashmap_inputs,
    //         77_777,
    //         consuming_wallet,
    //         consuming_wallet_balances,
    //         chain,
    //     );
    // 
    //     agent.finalize_gas_price_per_payable()
    // }

    #[test]
    fn estimated_transaction_fee_works_for_new_payable() {
        let consuming_wallet = make_wallet("efg");
        let consuming_wallet_balances = ConsumingWalletBalances {
            transaction_fee_balance_in_minor_units: Default::default(),
            masq_token_balance_in_minor_units: Default::default(),
        };
        let agent = BlockchainAgentWeb3::new(
            444,
            gas_price_hashmap_inputs,
            77_777,
            consuming_wallet,
            consuming_wallet_balances,
            TEST_DEFAULT_CHAIN,
        );

        let result = agent.estimated_transaction_fee_total(3);

        assert_eq!(agent.gas_limit_const_part, 77_777);
        assert_eq!(
            agent.maximum_added_gas_margin,
            WEB3_MAXIMAL_GAS_LIMIT_MARGIN
        );
        assert_eq!(
            result,
            (3 * (77_777 + WEB3_MAXIMAL_GAS_LIMIT_MARGIN)) * 444
        );
    }

    #[test]
    fn estimated_transaction_fee_works_for_retry_payable() {
        let consuming_wallet = make_wallet("efg");
        let consuming_wallet_balances = ConsumingWalletBalances {
            transaction_fee_balance_in_minor_units: Default::default(),
            masq_token_balance_in_minor_units: Default::default(),
        };
        let payable_1 = make_wallet("abc");
        let payable_2 = make_wallet("def");
        let chain = TEST_DEFAULT_CHAIN;
        let agent = BlockchainAgentWeb3::new(
            444,
            gas_price_hashmap_inputs,
            77_777,
            consuming_wallet,
            consuming_wallet_balances,
            chain,
        );

        let result = agent.estimated_transaction_fee_total();

        assert_eq!(agent.gas_limit_const_part, 77_777);
        assert_eq!(
            agent.maximum_added_gas_margin,
            WEB3_MAXIMAL_GAS_LIMIT_MARGIN
        );
        let first_tx_limit = increase_gas_price_by_marginal(555, chain) * (77_777 + WEB3_MAXIMAL_GAS_LIMIT_MARGIN);
        let second_tx_limit = increase_gas_price_by_marginal(333, chain) * (77_777 + WEB3_MAXIMAL_GAS_LIMIT_MARGIN);
        assert_eq!(
            result,
            first_tx_limit + second_tx_limit
        )
    }
}
