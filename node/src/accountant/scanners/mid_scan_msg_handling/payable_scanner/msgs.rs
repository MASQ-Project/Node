// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use std::collections::{HashMap, HashSet};
use crate::accountant::scanners::mid_scan_msg_handling::payable_scanner::blockchain_agent::BlockchainAgent;
use crate::accountant::{ResponseSkeleton, SkeletonOptHolder};
use crate::sub_lib::wallet::Wallet;
use actix::Message;
use masq_lib::type_obfuscation::Obfuscated;
use std::fmt::Debug;
use crate::accountant::db_access_objects::payable_dao::PayableAccount;

#[derive(Debug, Message, PartialEq, Eq, Clone)]
pub struct QualifiedPayablesMessage {
    pub qualified_payables: QualifiedPayablesRawPack,
    pub consuming_wallet: Wallet,
    pub response_skeleton_opt: Option<ResponseSkeleton>,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct QualifiedPayablesRawPack {
    pub payables: Vec<QualifiedPayablesBeforeGasPricePick>,
}

impl From<Vec<PayableAccount>> for QualifiedPayablesRawPack {
    fn from(qualified_payable: Vec<PayableAccount>) -> Self {
       QualifiedPayablesRawPack{ payables: qualified_payable.into_iter().map(|payable| QualifiedPayablesBeforeGasPricePick::new(payable, None)).collect()}
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct QualifiedPayablesBeforeGasPricePick {
    pub payable: PayableAccount,
    pub previous_attempt_gas_price_minor_opt: Option<u128>
}

impl QualifiedPayablesBeforeGasPricePick {
    pub fn new(payable: PayableAccount, previous_attempt_gas_price_minor_opt: Option<u128>) -> Self {
        Self {
            payable,
            previous_attempt_gas_price_minor_opt
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct QualifiedPayablesRipePack {
    pub payables: Vec<QualifiedPayablesWithGasPrice>,
}

impl Into<Vec<PayableAccount>> for QualifiedPayablesRipePack {
    fn into(self) -> Vec<PayableAccount> {
        todo!()
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct QualifiedPayablesWithGasPrice{
    pub payable: PayableAccount,
    pub gas_price_minor: u128
}

impl QualifiedPayablesWithGasPrice {
    pub fn new(payable: PayableAccount, gas_price_minor: u128) -> Self {
        Self {
            payable,
            gas_price_minor
        }
    }
}

impl QualifiedPayablesMessage {
    pub(in crate::accountant) fn new(
        qualified_payables: QualifiedPayablesRawPack,
        consuming_wallet: Wallet,
        response_skeleton_opt: Option<ResponseSkeleton>,
    ) -> Self {
        Self {
            qualified_payables,
            consuming_wallet,
            response_skeleton_opt,
        }
    }
}

impl SkeletonOptHolder for QualifiedPayablesMessage {
    fn skeleton_opt(&self) -> Option<ResponseSkeleton> {
        self.response_skeleton_opt
    }
}

#[derive(Message)]
pub struct BlockchainAgentWithContextMessage {
    pub qualified_payables: QualifiedPayablesRipePack,
    pub agent: Box<dyn BlockchainAgent>,
    pub response_skeleton_opt: Option<ResponseSkeleton>,
}

impl BlockchainAgentWithContextMessage {
    pub fn new(
        qualified_payables: QualifiedPayablesRipePack,
        blockchain_agent: Box<dyn BlockchainAgent>,
        response_skeleton_opt: Option<ResponseSkeleton>,
    ) -> Self {
        Self {
            qualified_payables,
            agent: blockchain_agent,
            response_skeleton_opt,
        }
    }
}

#[cfg(test)]
mod tests {

    use crate::accountant::scanners::mid_scan_msg_handling::payable_scanner::msgs::BlockchainAgentWithContextMessage;
    use crate::accountant::scanners::mid_scan_msg_handling::payable_scanner::test_utils::BlockchainAgentMock;

    impl Clone for BlockchainAgentWithContextMessage {
        fn clone(&self) -> Self {
            let original_agent_id = self.agent.arbitrary_id_stamp();
            let cloned_agent =
                BlockchainAgentMock::default().set_arbitrary_id_stamp(original_agent_id);
            Self {
                qualified_payables: self.qualified_payables.clone(),
                agent: Box::new(cloned_agent),
                response_skeleton_opt: self.response_skeleton_opt,
            }
        }
    }
}
