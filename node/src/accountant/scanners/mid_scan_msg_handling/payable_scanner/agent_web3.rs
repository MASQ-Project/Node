// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::scanners::mid_scan_msg_handling::payable_scanner::blockchain_agent::BlockchainAgent;

use crate::sub_lib::blockchain_bridge::ConsumingWalletBalances;
use crate::sub_lib::wallet::Wallet;

use crate::accountant::gwei_to_wei;
use crate::blockchain::blockchain_interface::blockchain_interface_web3::TRANSACTION_FEE_MARGIN;
use masq_lib::percentage::PurePercentage;
use web3::types::U256;

#[derive(Debug, Clone)]
pub struct BlockchainAgentWeb3 {
    gas_price_gwei: u64,
    gas_limit_const_part: u64,
    gas_price_margin: PurePercentage,
    maximum_added_gas_margin: u64,
    consuming_wallet: Wallet,
    consuming_wallet_balances: ConsumingWalletBalances,
    pending_transaction_id: U256,
}

impl BlockchainAgent for BlockchainAgentWeb3 {
    fn estimated_transaction_fee_per_transaction_minor(&self) -> u128 {
        let gas_price = self.gas_price_gwei as u128;
        let max_gas_limit = (self.maximum_added_gas_margin + self.gas_limit_const_part) as u128;
        gwei_to_wei(gas_price * max_gas_limit)
    }

    fn transaction_fee_balance_minor(&self) -> U256 {
        self.consuming_wallet_balances
            .transaction_fee_balance_in_minor_units
    }

    fn service_fee_balance_minor(&self) -> u128 {
        self.consuming_wallet_balances
            .service_fee_balance_in_minor_units
    }

    fn gas_price(&self) -> u64 {
        self.gas_price_gwei
    }

    fn gas_price_margin(&self) -> PurePercentage {
        self.gas_price_margin
    }

    fn consuming_wallet(&self) -> &Wallet {
        &self.consuming_wallet
    }

    fn pending_transaction_id(&self) -> U256 {
        self.pending_transaction_id
    }
}

// 64 * (64 - 12) ... std transaction has data of 64 bytes and 12 bytes are never used with us;
// each non-zero byte costs 64 units of gas
pub const WEB3_MAXIMAL_GAS_LIMIT_MARGIN: u64 = 3328;

impl BlockchainAgentWeb3 {
    pub fn new(
        gas_price_gwei: u64,
        gas_limit_const_part: u64,
        consuming_wallet: Wallet,
        consuming_wallet_balances: ConsumingWalletBalances,
        pending_transaction_id: U256,
    ) -> Self {
        let gas_price_margin = *TRANSACTION_FEE_MARGIN;
        let maximum_added_gas_margin = WEB3_MAXIMAL_GAS_LIMIT_MARGIN;
        Self {
            gas_price_gwei,
            gas_limit_const_part,
            gas_price_margin,
            consuming_wallet,
            maximum_added_gas_margin,
            consuming_wallet_balances,
            pending_transaction_id,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::accountant::scanners::mid_scan_msg_handling::payable_scanner::agent_web3::{
        BlockchainAgentWeb3, WEB3_MAXIMAL_GAS_LIMIT_MARGIN,
    };
    use crate::accountant::scanners::mid_scan_msg_handling::payable_scanner::blockchain_agent::BlockchainAgent;

    use crate::sub_lib::blockchain_bridge::ConsumingWalletBalances;
    use crate::test_utils::make_wallet;

    use crate::accountant::gwei_to_wei;
    use web3::types::U256;

    #[test]
    fn constants_are_correct() {
        assert_eq!(WEB3_MAXIMAL_GAS_LIMIT_MARGIN, 3328)
    }

    #[test]
    fn blockchain_agent_can_return_non_computed_input_values() {
        let gas_price_gwei = 123;
        let gas_limit_const_part = 44_000;
        let consuming_wallet = make_wallet("abcde");
        let consuming_wallet_balances = ConsumingWalletBalances {
            transaction_fee_balance_in_minor_units: U256::from(456_789),
            service_fee_balance_in_minor_units: 123_000_000,
        };
        let pending_transaction_id = U256::from(777);

        let subject = BlockchainAgentWeb3::new(
            gas_price_gwei,
            gas_limit_const_part,
            consuming_wallet.clone(),
            consuming_wallet_balances,
            pending_transaction_id,
        );

        assert_eq!(subject.gas_price(), gas_price_gwei);
        assert_eq!(subject.consuming_wallet(), &consuming_wallet);
        assert_eq!(
            subject.transaction_fee_balance_minor(),
            consuming_wallet_balances.transaction_fee_balance_in_minor_units
        );
        assert_eq!(
            subject.service_fee_balance_minor(),
            consuming_wallet_balances.service_fee_balance_in_minor_units
        );
        assert_eq!(subject.pending_transaction_id(), pending_transaction_id)
    }

    #[test]
    fn estimated_transaction_fee_works() {
        let consuming_wallet = make_wallet("efg");
        let consuming_wallet_balances = ConsumingWalletBalances {
            transaction_fee_balance_in_minor_units: Default::default(),
            service_fee_balance_in_minor_units: Default::default(),
        };
        let nonce = U256::from(55);
        let agent = BlockchainAgentWeb3::new(
            244,
            77_777,
            consuming_wallet,
            consuming_wallet_balances,
            nonce,
        );

        let result = agent.estimated_transaction_fee_per_transaction_minor();

        assert_eq!(agent.gas_limit_const_part, 77_777);
        assert_eq!(
            agent.maximum_added_gas_margin,
            WEB3_MAXIMAL_GAS_LIMIT_MARGIN
        );
        assert_eq!(result, 19789620000000000);
    }
}
