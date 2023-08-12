// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::database_access_objects::payable_dao::PayableAccount;
use crate::accountant::scanners::mid_scan_procedures::payable_scanner::agent_abstract_layer::PayablePaymentsAgent;
use crate::accountant::scanners::mid_scan_procedures::payable_scanner::setup_msg::QualifiedPayablesMessage;
use crate::accountant::{RequestTransactionReceipts, ResponseSkeleton, SkeletonOptHolder};
use crate::blockchain::blockchain_bridge::RetrieveTransactions;
use crate::sub_lib::peer_actors::BindMessage;
use actix::Message;
use actix::Recipient;
use masq_lib::blockchains::chains::Chain;
use masq_lib::ui_gateway::NodeFromUiMessage;
use std::fmt;
use std::fmt::{Debug, Formatter};
use web3::types::U256;

#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct BlockchainBridgeConfig {
    pub blockchain_service_url_opt: Option<String>,
    pub chain: Chain,
    pub gas_price: u64,
}

#[derive(Clone, PartialEq, Eq)]
pub struct BlockchainBridgeSubs {
    pub bind: Recipient<BindMessage>,
    pub outbound_payments_instructions: Recipient<OutboundPaymentsInstructions>,
    pub qualified_paybles_message: Recipient<QualifiedPayablesMessage>,
    pub retrieve_transactions: Recipient<RetrieveTransactions>,
    pub ui_sub: Recipient<NodeFromUiMessage>,
    pub request_transaction_receipts: Recipient<RequestTransactionReceipts>,
}

impl Debug for BlockchainBridgeSubs {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "BlockchainBridgeSubs")
    }
}

#[derive(Message)]
pub struct OutboundPaymentsInstructions {
    pub affordable_accounts: Vec<PayableAccount>,
    pub agent: Box<dyn PayablePaymentsAgent>,
    pub response_skeleton_opt: Option<ResponseSkeleton>,
}

impl SkeletonOptHolder for OutboundPaymentsInstructions {
    fn skeleton_opt(&self) -> Option<ResponseSkeleton> {
        self.response_skeleton_opt
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConsumingWalletBalances {
    pub transaction_fee_balance_in_minor_units: U256,
    pub masq_token_balance_in_minor_units: U256,
}

pub fn web3_gas_limit_const_part(chain: Chain) -> u64 {
    match chain {
        Chain::EthMainnet | Chain::EthRopsten | Chain::Dev => 55_000,
        Chain::PolyMainnet | Chain::PolyMumbai => 70_000,
    }
}

#[cfg(test)]
mod tests {
    use crate::sub_lib::blockchain_bridge::web3_gas_limit_const_part;
    use crate::test_utils::recorder::{make_blockchain_bridge_subs_from, Recorder};
    use actix::Actor;
    use masq_lib::blockchains::chains::Chain;

    #[test]
    fn blockchain_bridge_subs_debug() {
        let recorder = Recorder::new().start();

        let subject = make_blockchain_bridge_subs_from(&recorder);

        assert_eq!(format!("{:?}", subject), "BlockchainBridgeSubs");
    }

    #[test]
    fn web3_gas_limit_const_part_gives_right_values() {
        assert_eq!(web3_gas_limit_const_part(Chain::PolyMainnet), 70_000);
        assert_eq!(web3_gas_limit_const_part(Chain::PolyMumbai), 70_000);
        assert_eq!(web3_gas_limit_const_part(Chain::EthMainnet), 55_000);
        assert_eq!(web3_gas_limit_const_part(Chain::EthRopsten), 55_000);
        assert_eq!(web3_gas_limit_const_part(Chain::EthRopsten), 55_000);
        assert_eq!(web3_gas_limit_const_part(Chain::Dev), 55_000)
    }
}
