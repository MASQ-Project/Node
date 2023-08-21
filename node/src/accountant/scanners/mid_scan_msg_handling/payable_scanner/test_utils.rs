// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

#![cfg(test)]

use crate::accountant::scanners::mid_scan_msg_handling::payable_scanner::blockchain_agent::BlockchainAgent;
use crate::sub_lib::blockchain_bridge::ConsumingWalletBalances;
use crate::sub_lib::wallet::Wallet;
use crate::test_utils::unshared_test_utils::arbitrary_id_stamp::ArbitraryIdStamp;
use crate::{arbitrary_id_stamp_in_trait_impl, set_arbitrary_id_stamp_in_mock_impl};
use ethereum_types::U256;

#[derive(Default)]
pub struct BlockchainAgentMock {
    arbitrary_id_stamp_opt: Option<ArbitraryIdStamp>,
}

impl BlockchainAgent for BlockchainAgentMock {
    fn estimated_transaction_fee_total(&self, _number_of_transactions: usize) -> u128 {
        todo!()
    }

    fn consuming_wallet_balances(&self) -> ConsumingWalletBalances {
        todo!()
    }

    fn agreed_fee_per_computation_unit(&self) -> u64 {
        todo!()
    }

    fn consuming_wallet(&self) -> &Wallet {
        todo!()
    }

    fn pending_transaction_id(&self) -> U256 {
        todo!()
    }

    fn dup(&self) -> Box<dyn BlockchainAgent> {
        todo!()
    }

    arbitrary_id_stamp_in_trait_impl!();
}

impl BlockchainAgentMock {
    set_arbitrary_id_stamp_in_mock_impl!();
}
