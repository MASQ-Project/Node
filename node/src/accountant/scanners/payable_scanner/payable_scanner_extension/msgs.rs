// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::db_access_objects::payable_dao::PayableAccount;
use crate::accountant::scanners::payable_scanner::data_structures::new_tx_template::NewTxTemplates;
use crate::accountant::scanners::payable_scanner::data_structures::priced_new_tx_template::PricedNewTxTemplates;
use crate::accountant::scanners::payable_scanner::data_structures::priced_retry_tx_template::PricedRetryTxTemplates;
use crate::accountant::scanners::payable_scanner::data_structures::retry_tx_template::RetryTxTemplates;
use crate::accountant::{ResponseSkeleton, SkeletonOptHolder};
use crate::blockchain::blockchain_agent::BlockchainAgent;
use crate::sub_lib::wallet::Wallet;
use actix::Message;
use itertools::Either;
use std::fmt::Debug;

#[derive(Debug, Message, PartialEq, Eq, Clone)]
pub struct QualifiedPayablesMessage {
    pub tx_templates: Either<NewTxTemplates, RetryTxTemplates>,
    pub consuming_wallet: Wallet,
    pub response_skeleton_opt: Option<ResponseSkeleton>,
}

impl SkeletonOptHolder for QualifiedPayablesMessage {
    fn skeleton_opt(&self) -> Option<ResponseSkeleton> {
        self.response_skeleton_opt
    }
}

#[derive(Message)]
pub struct BlockchainAgentWithContextMessage {
    pub priced_templates: Either<PricedNewTxTemplates, PricedRetryTxTemplates>,
    pub agent: Box<dyn BlockchainAgent>,
    pub response_skeleton_opt: Option<ResponseSkeleton>,
}
