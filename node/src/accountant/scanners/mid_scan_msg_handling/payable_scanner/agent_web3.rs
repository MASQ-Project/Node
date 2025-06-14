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
        qualified_payables: QualifiedPayablesRawPack,
        latest_gas_price_wei: u128,
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
    use crate::accountant::scanners::mid_scan_msg_handling::payable_scanner::msgs::{QualifiedPayableWithGasPrice, QualifiedPayablesBeforeGasPricePick, QualifiedPayablesRawPack, QualifiedPayablesRipePack};
    use crate::accountant::test_utils::make_payable_account;
    use crate::blockchain::test_utils::{increase_gas_price_by_marginal};

    #[test]
    fn constants_are_correct() {
        assert_eq!(WEB3_MAXIMAL_GAS_LIMIT_MARGIN, 3_328)
    }

    #[test]
    fn returns_correct_ripe_qualified_payables_for_new_payable_scan() {
        let consuming_wallet = make_wallet("efg");
        let consuming_wallet_balances = ConsumingWalletBalances {
            transaction_fee_balance_in_minor_units: Default::default(),
            masq_token_balance_in_minor_units: Default::default(),
        };
        let account_1 = make_payable_account(12);
        let account_2 = make_payable_account(34);
        let qualified_payables = QualifiedPayablesRawPack::from(vec![account_1.clone(), account_2.clone()]);
        let gas_price_from_rpc = 555_666_777;
        let chain = TEST_DEFAULT_CHAIN;
        let (_, ripe_qualified_payables) = BlockchainAgentWeb3::new(
            qualified_payables,
            gas_price_from_rpc,
            77_777,
            consuming_wallet,
            consuming_wallet_balances,
            chain,
        );
    
        let gas_price_with_margin = increase_gas_price_by_marginal(gas_price_from_rpc, chain);
        let expected_result = QualifiedPayablesRipePack{ payables:
            vec![QualifiedPayableWithGasPrice::new(account_1, gas_price_with_margin), QualifiedPayableWithGasPrice::new(account_2, gas_price_with_margin)]};
        assert_eq!(ripe_qualified_payables, expected_result);
    }

    #[test]
    fn returns_correct_ripe_qualified_payables_for_retry_payable_scan() {
        let consuming_wallet = make_wallet("efg");
        let consuming_wallet_balances = ConsumingWalletBalances {
            transaction_fee_balance_in_minor_units: Default::default(),
            masq_token_balance_in_minor_units: Default::default(),
        };
        let account_1 = make_payable_account(12);
        let account_2 = make_payable_account(34);
        let account_3 = make_payable_account(56);
        let account_4 = make_payable_account(78);
        let account_5 = make_payable_account(90);
        let qualified_payables = QualifiedPayablesRawPack{payables:
        vec![
            QualifiedPayablesBeforeGasPricePick::new(account_1, Some(444_555_665)),
            QualifiedPayablesBeforeGasPricePick::new(account_2, Some(444_555_666)),
            QualifiedPayablesBeforeGasPricePick::new(account_3, Some(444_555_667)),
            QualifiedPayablesBeforeGasPricePick::new(account_4, Some(111_111_111)),
            QualifiedPayablesBeforeGasPricePick::new(account_5, Some(500_000_000))
        ]};
        let gas_price_from_rpc = 444_555_666;
        let chain = TEST_DEFAULT_CHAIN;
        let (_, ripe_qualified_payables) = BlockchainAgentWeb3::new(
            qualified_payables,
            gas_price_from_rpc,
            77_777,
            consuming_wallet,
            consuming_wallet_balances,
            chain,
        );
        
        let expected_result = {
            let gas_price_account_1 = increase_gas_price_by_marginal(444_555_666, chain);
            let gas_price_account_2 = increase_gas_price_by_marginal(444_555_666, chain);
            let gas_price_account_3 = increase_gas_price_by_marginal(444_555_667, chain);
            let gas_price_account_4 = increase_gas_price_by_marginal(444_555_666, chain);
            let gas_price_account_5 = increase_gas_price_by_marginal(500_000_000, chain);
            QualifiedPayablesRipePack{ payables:
            vec![
                QualifiedPayableWithGasPrice::new(account_1, gas_price_account_1),
                QualifiedPayableWithGasPrice::new(account_2, gas_price_account_2),
                QualifiedPayableWithGasPrice::new(account_3, gas_price_account_3),
                QualifiedPayableWithGasPrice::new(account_4, gas_price_account_4),
                QualifiedPayableWithGasPrice::new(account_5, gas_price_account_5)   
            ]}
        };
        assert_eq!(ripe_qualified_payables, expected_result);
    }

    #[test]
    fn returns_correct_non_computed_values() {
        let gas_limit_const_part = 44_000;
        let consuming_wallet = make_wallet("abcde");
        let consuming_wallet_balances = ConsumingWalletBalances {
            transaction_fee_balance_in_minor_units: U256::from(456_789),
            masq_token_balance_in_minor_units: U256::from(123_000_000),
        };
        let qualified_payables = QualifiedPayablesRawPack::from(vec![make_payable_account(123)]);
        let (subject, _) = BlockchainAgentWeb3::new(
            qualified_payables,
            222_333_444,
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
    
    #[test]
    fn estimated_transaction_fee_works_for_new_payable() {
        let consuming_wallet = make_wallet("efg");
        let consuming_wallet_balances = ConsumingWalletBalances {
            transaction_fee_balance_in_minor_units: Default::default(),
            masq_token_balance_in_minor_units: Default::default(),
        };
        let account_1 = make_payable_account(12);
        let account_2 = make_payable_account(34);
        let chain = TEST_DEFAULT_CHAIN;
        let qualified_payables = QualifiedPayablesRawPack::from(vec![account_1, account_2]);
        let (agent, _) = BlockchainAgentWeb3::new(
            qualified_payables,
            444_555_666,
            77_777,
            consuming_wallet,
            consuming_wallet_balances,
            chain,
        );

        let result = agent.estimated_transaction_fee_total();
        
        assert_eq!(
            result,
            (2 * (77_777 + WEB3_MAXIMAL_GAS_LIMIT_MARGIN)) * increase_gas_price_by_marginal(444_555_666, chain)
        );
    }

    #[test]
    fn estimated_transaction_fee_works_for_retry_payable() {
        let consuming_wallet = make_wallet("efg");
        let consuming_wallet_balances = ConsumingWalletBalances {
            transaction_fee_balance_in_minor_units: Default::default(),
            masq_token_balance_in_minor_units: Default::default(),
        };
        let account_1 = make_payable_account(12);
        let account_2 = make_payable_account(34);
        let account_3 = make_payable_account(56);
        let account_4 = make_payable_account(78);
        let account_5 = make_payable_account(90);
        let qualified_payables = QualifiedPayablesRawPack{payables: 
        vec![
            QualifiedPayablesBeforeGasPricePick::new(account_1, Some(444_555_665)),
            QualifiedPayablesBeforeGasPricePick::new(account_2, Some(444_555_666)),
            QualifiedPayablesBeforeGasPricePick::new(account_3, Some(444_555_667)),
            QualifiedPayablesBeforeGasPricePick::new(account_4, Some(111_111_111)),
            QualifiedPayablesBeforeGasPricePick::new(account_5, Some(500_000_000)),
        ]};
        let chain = TEST_DEFAULT_CHAIN;
        let (agent, _) = BlockchainAgentWeb3::new(
            qualified_payables,
            444_555_666,
            77_777,
            consuming_wallet,
            consuming_wallet_balances,
            chain,
        );

        let result = agent.estimated_transaction_fee_total();
        
        assert_eq!(
            result,
            (
                increase_gas_price_by_marginal(444_555_666, chain) +
                increase_gas_price_by_marginal(444_555_666, chain) +
                increase_gas_price_by_marginal(444_555_667, chain) +
                increase_gas_price_by_marginal(444_555_666, chain) +
                increase_gas_price_by_marginal(500_000_000, chain)
            )  * (77_777 + WEB3_MAXIMAL_GAS_LIMIT_MARGIN)
        )
    }
}
