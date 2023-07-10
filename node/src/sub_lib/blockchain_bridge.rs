// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::database_access_objects::payable_dao::PayableAccount;
use crate::accountant::scanners::payable_payments_agent_abstract_layer::PayablePaymentsAgent;
use crate::accountant::scanners::payable_payments_setup_msg::PayablePaymentsSetupMsgPayload;
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
    pub initial_payable_payment_setup_msg: Recipient<PayablePaymentsSetupMsgPayload>,
    pub retrieve_transactions: Recipient<RetrieveTransactions>,
    pub ui_sub: Recipient<NodeFromUiMessage>,
    pub request_transaction_receipts: Recipient<RequestTransactionReceipts>,
}

impl Debug for BlockchainBridgeSubs {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "BlockchainBridgeSubs")
    }
}

#[derive(Debug, Clone, Message)]
pub struct OutboundPaymentsInstructions {
    pub checked_accounts: Vec<PayableAccount>,
    pub agent: Box<dyn PayablePaymentsAgent>,
    pub response_skeleton_opt: Option<ResponseSkeleton>,
}

// Derive version of PartialEq blows up because of the agent in it. Complaint about
// disability to use Copy in order to move out from behind a reference (???). Only the added
// references helped me move forward
#[allow(clippy::op_ref)]
impl PartialEq for OutboundPaymentsInstructions {
    fn eq(&self, other: &Self) -> bool {
        self.checked_accounts == other.checked_accounts
            && &self.agent == &other.agent
            && self.response_skeleton_opt == other.response_skeleton_opt
    }
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
    use crate::accountant::scanners::payable_payments_agent_abstract_layer::PayablePaymentsAgent;
    use crate::accountant::scanners::payable_payments_agent_web3::PayablePaymentsAgentWeb3;
    use crate::accountant::test_utils::{make_payable_account, PayablePaymentsAgentMock};
    use crate::accountant::ResponseSkeleton;
    use crate::sub_lib::blockchain_bridge::{
        web3_gas_limit_const_part, OutboundPaymentsInstructions,
    };
    use crate::test_utils::recorder::{make_blockchain_bridge_subs_from, Recorder};
    use actix::Actor;
    use masq_lib::blockchains::chains::Chain;
    use web3::types::U256;

    #[test]
    fn blockchain_bridge_subs_debug() {
        let recorder = Recorder::new().start();

        let subject = make_blockchain_bridge_subs_from(&recorder);

        assert_eq!(format!("{:?}", subject), "BlockchainBridgeSubs");
    }

    #[test]
    fn outbound_payments_instructions_implements_partial_eq() {
        let create_instructions = || OutboundPaymentsInstructions {
            checked_accounts: vec![make_payable_account(123)],
            agent: Box::new(PayablePaymentsAgentWeb3::new(123)),
            response_skeleton_opt: Some(ResponseSkeleton {
                client_id: 123,
                context_id: 456,
            }),
        };
        let mut instructions_1 = create_instructions();
        let mut instructions_2 = create_instructions();

        assert_eq!(instructions_1, instructions_2);
        instructions_2.agent = Box::new(PayablePaymentsAgentMock::default());
        assert_ne!(instructions_2, instructions_1);
        let mut also_different_agent = PayablePaymentsAgentWeb3::new(123);
        also_different_agent.set_up_pending_transaction_id(U256::from(111));
        instructions_2.agent = Box::new(also_different_agent);
        assert_ne!(instructions_2, instructions_1);
        instructions_1
            .agent
            .set_up_pending_transaction_id(U256::from(111));
        assert_eq!(instructions_2, instructions_1);

        instructions_2.checked_accounts = vec![];
        assert_ne!(instructions_2, instructions_1);
        instructions_1.checked_accounts = vec![];
        assert_eq!(instructions_2, instructions_1);
        instructions_2.response_skeleton_opt = None;
        assert_ne!(instructions_2, instructions_1);
        instructions_1.response_skeleton_opt = None;
        assert_eq!(instructions_2, instructions_1)
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
