// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

#![cfg(test)]

use crate::accountant::scanners::payable_scanner::data_structures::new_tx_template::NewTxTemplates;
use crate::accountant::scanners::payable_scanner::data_structures::priced_new_tx_template::PricedNewTxTemplates;
use crate::accountant::scanners::payable_scanner::data_structures::priced_retry_tx_template::PricedRetryTxTemplates;
use crate::accountant::scanners::payable_scanner::data_structures::retry_tx_template::RetryTxTemplates;
use crate::accountant::scanners::payable_scanner::payable_scanner_extension::msgs::BlockchainAgentWithContextMessage;
use crate::accountant::scanners::payable_scanner::payable_scanner_extension::PreparedAdjustment;
use crate::blockchain::blockchain_agent::test_utils::BlockchainAgentMock;
use crate::blockchain::blockchain_agent::BlockchainAgent;
use crate::sub_lib::blockchain_bridge::ConsumingWalletBalances;
use crate::sub_lib::wallet::Wallet;
use crate::test_utils::unshared_test_utils::arbitrary_id_stamp::ArbitraryIdStamp;
use crate::{arbitrary_id_stamp_in_trait_impl, set_arbitrary_id_stamp_in_mock_impl};
use itertools::Either;
use masq_lib::blockchains::chains::Chain;
use std::cell::RefCell;

impl Clone for BlockchainAgentWithContextMessage {
    fn clone(&self) -> Self {
        let original_agent_id = self.agent.arbitrary_id_stamp();
        let cloned_agent = BlockchainAgentMock::default().set_arbitrary_id_stamp(original_agent_id);
        Self {
            priced_templates: self.priced_templates.clone(),
            agent: Box::new(cloned_agent),
            response_skeleton_opt: self.response_skeleton_opt,
        }
    }
}

impl Clone for PreparedAdjustment {
    fn clone(&self) -> Self {
        Self {
            original_setup_msg: self.original_setup_msg.clone(),
            adjustment: self.adjustment.clone(),
        }
    }
}
