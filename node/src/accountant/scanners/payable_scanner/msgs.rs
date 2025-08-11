use crate::accountant::scanners::payable_scanner::tx_templates::initial::new::NewTxTemplates;
use crate::accountant::scanners::payable_scanner::tx_templates::initial::retry::RetryTxTemplates;
use crate::accountant::scanners::payable_scanner::tx_templates::priced::new::PricedNewTxTemplates;
use crate::accountant::scanners::payable_scanner::tx_templates::priced::retry::PricedRetryTxTemplates;
use crate::accountant::{ResponseSkeleton, SkeletonOptHolder};
use crate::blockchain::blockchain_agent::BlockchainAgent;
use crate::sub_lib::wallet::Wallet;
use actix::Message;
use itertools::Either;

// TODO: GH-605: Rename this to TxTemplates Message
#[derive(Debug, Message, PartialEq, Eq, Clone)]
pub struct QualifiedPayablesMessage {
    pub tx_templates: Either<NewTxTemplates, RetryTxTemplates>,
    pub consuming_wallet: Wallet,
    pub response_skeleton_opt: Option<ResponseSkeleton>,
}

#[derive(Message)]
pub struct BlockchainAgentWithContextMessage {
    pub priced_templates: Either<PricedNewTxTemplates, PricedRetryTxTemplates>,
    pub agent: Box<dyn BlockchainAgent>,
    pub response_skeleton_opt: Option<ResponseSkeleton>,
}

impl SkeletonOptHolder for QualifiedPayablesMessage {
    fn skeleton_opt(&self) -> Option<ResponseSkeleton> {
        self.response_skeleton_opt
    }
}
