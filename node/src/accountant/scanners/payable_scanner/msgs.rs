// Copyright (c) 2025, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
use crate::accountant::scanners::payable_scanner::tx_templates::initial::new::NewTxTemplates;
use crate::accountant::scanners::payable_scanner::tx_templates::initial::retry::RetryTxTemplates;
use crate::accountant::scanners::payable_scanner::tx_templates::priced::new::PricedNewTxTemplates;
use crate::accountant::scanners::payable_scanner::tx_templates::priced::retry::PricedRetryTxTemplates;
use crate::accountant::{ResponseSkeleton, SkeletonOptHolder};
use crate::blockchain::blockchain_agent::BlockchainAgent;
use crate::blockchain::blockchain_bridge::MsgInterpretableAsDetailedScanType;
use crate::sub_lib::accountant::DetailedScanType;
use crate::sub_lib::wallet::Wallet;
use actix::Message;
use itertools::Either;

#[derive(Debug, Message, PartialEq, Eq, Clone)]
pub struct InitialTemplatesMessage {
    pub initial_templates: Either<NewTxTemplates, RetryTxTemplates>,
    pub consuming_wallet: Wallet,
    pub response_skeleton_opt: Option<ResponseSkeleton>,
}

impl MsgInterpretableAsDetailedScanType for InitialTemplatesMessage {
    fn detailed_scan_type(&self) -> DetailedScanType {
        match self.initial_templates {
            Either::Left(_) => DetailedScanType::NewPayables,
            Either::Right(_) => DetailedScanType::RetryPayables,
        }
    }
}

#[derive(Message)]
pub struct PricedTemplatesMessage {
    pub priced_templates: Either<PricedNewTxTemplates, PricedRetryTxTemplates>,
    pub agent: Box<dyn BlockchainAgent>,
    pub response_skeleton_opt: Option<ResponseSkeleton>,
}

impl SkeletonOptHolder for InitialTemplatesMessage {
    fn skeleton_opt(&self) -> Option<ResponseSkeleton> {
        self.response_skeleton_opt
    }
}

#[cfg(test)]
mod tests {
    use crate::accountant::scanners::payable_scanner::msgs::InitialTemplatesMessage;
    use crate::accountant::scanners::payable_scanner::tx_templates::initial::new::NewTxTemplates;
    use crate::accountant::scanners::payable_scanner::tx_templates::initial::retry::RetryTxTemplates;
    use crate::blockchain::blockchain_bridge::MsgInterpretableAsDetailedScanType;
    use crate::sub_lib::accountant::DetailedScanType;
    use crate::test_utils::make_wallet;
    use itertools::Either;

    #[test]
    fn detailed_scan_type_is_implemented_for_initial_templates_message() {
        let msg_a = InitialTemplatesMessage {
            initial_templates: Either::Left(NewTxTemplates(vec![])),
            consuming_wallet: make_wallet("abc"),
            response_skeleton_opt: None,
        };
        let msg_b = InitialTemplatesMessage {
            initial_templates: Either::Right(RetryTxTemplates(vec![])),
            consuming_wallet: make_wallet("abc"),
            response_skeleton_opt: None,
        };

        assert_eq!(msg_a.detailed_scan_type(), DetailedScanType::NewPayables);
        assert_eq!(msg_b.detailed_scan_type(), DetailedScanType::RetryPayables);
    }
}
