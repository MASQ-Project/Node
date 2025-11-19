// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::db_access_objects::failed_payable_dao::FailedTx;
use crate::accountant::db_access_objects::utils::TxHash;
use crate::accountant::scanners::payable_scanner::msgs::InitialTemplatesMessage;
use crate::accountant::scanners::payable_scanner::tx_templates::priced::new::PricedNewTxTemplates;
use crate::accountant::scanners::payable_scanner::tx_templates::priced::retry::PricedRetryTxTemplates;
use crate::accountant::{
    PayableScanType, RequestTransactionReceipts, ResponseSkeleton, SimplePayable, SkeletonOptHolder,
};
use crate::blockchain::blockchain_agent::BlockchainAgent;
use crate::blockchain::blockchain_bridge::{
    MsgInterpretableAsPayableScanType, RetrieveTransactions,
};
use crate::sub_lib::peer_actors::BindMessage;
use actix::Message;
use actix::Recipient;
use itertools::Either;
use masq_lib::blockchains::chains::Chain;
use masq_lib::ui_gateway::NodeFromUiMessage;
use std::fmt;
use std::fmt::{Debug, Display, Formatter};
use web3::types::U256;

#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct BlockchainBridgeConfig {
    pub blockchain_service_url_opt: Option<String>,
    pub chain: Chain,
    // TODO: ignored during the setup of the actor.
    // Use it in the body or delete this field
    pub gas_price: u64,
}

#[derive(Clone, PartialEq, Eq)]
pub struct BlockchainBridgeSubs {
    pub bind: Recipient<BindMessage>,
    pub outbound_payments_instructions: Recipient<OutboundPaymentsInstructions>,
    pub qualified_payables: Recipient<InitialTemplatesMessage>,
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
    pub priced_templates: Either<PricedNewTxTemplates, PricedRetryTxTemplates>,
    pub agent: Box<dyn BlockchainAgent>,
    pub response_skeleton_opt: Option<ResponseSkeleton>,
}

impl MsgInterpretableAsPayableScanType for OutboundPaymentsInstructions {
    fn payable_scan_type(&self) -> PayableScanType {
        match self.priced_templates {
            Either::Left(_) => PayableScanType::New,
            Either::Right(_) => PayableScanType::Retry,
        }
    }
}

impl OutboundPaymentsInstructions {
    pub fn new(
        priced_templates: Either<PricedNewTxTemplates, PricedRetryTxTemplates>,
        agent: Box<dyn BlockchainAgent>,
        response_skeleton_opt: Option<ResponseSkeleton>,
    ) -> Self {
        Self {
            priced_templates,
            agent,
            response_skeleton_opt,
        }
    }

    pub fn scan_type(&self) -> PayableScanType {
        match &self.priced_templates {
            Either::Left(_new_templates) => PayableScanType::New,
            Either::Right(_retry_templates) => PayableScanType::Retry,
        }
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

impl ConsumingWalletBalances {
    pub fn new(transaction_fee: U256, masq_token: U256) -> Self {
        Self {
            transaction_fee_balance_in_minor_units: transaction_fee,
            masq_token_balance_in_minor_units: masq_token,
        }
    }
}

//TODO rename me to ExactScanType
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum DetailedScanType {
    NewPayables,
    RetryPayables,
    PendingPayables,
    Receivables,
}

impl From<&ScanErrorPayload> for DetailedScanType {
    fn from(payload: &ScanErrorPayload) -> Self {
        match payload {
            ScanErrorPayload::NewPayables(_) => DetailedScanType::NewPayables,
            ScanErrorPayload::RetryPayables(_) => DetailedScanType::RetryPayables,
            ScanErrorPayload::PendingPayables(_) => DetailedScanType::PendingPayables,
            ScanErrorPayload::Receivables(_) => DetailedScanType::Receivables,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanErrorPayload {
    NewPayables(PayableScanError),
    RetryPayables(PayableScanError),
    PendingPayables(String),
    Receivables(String),
}

impl Display for ScanErrorPayload {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        fn handle_payable_scan_error(
            f: &mut Formatter<'_>,
            payable_scan_type: PayableScanType,
            payable_scan_error: &PayableScanError,
        ) -> fmt::Result {
            match payable_scan_error {
                PayableScanError::PlainTextError(err) => write!(f, "{:?} payable scan error: '{}'", payable_scan_type,err),
                PayableScanError::ErrorWithTxsIssued { error, failed_txs } => match error
                {
                    ErrorWithTxsIssued::Sending(error) => write!(f, "{:?} payable scan error — during tx submission, {} failed tx records: '{}'", payable_scan_type, failed_txs.len(),error),
                    ErrorWithTxsIssued::FromRPCResponse => {
                        write!(f, "{:?} payable scan error — RPC response with {} failed tx records", payable_scan_type, failed_txs.len())
                    }
                }
            }
        }

        match self {
            ScanErrorPayload::NewPayables(err) => {
                handle_payable_scan_error(f, PayableScanType::New, err)
            }
            ScanErrorPayload::RetryPayables(err) => {
                handle_payable_scan_error(f, PayableScanType::Retry, err)
            }
            ScanErrorPayload::PendingPayables(err) => {
                write!(f, "Pending payable scan error: '{}'", err)
            }
            ScanErrorPayload::Receivables(err) => write!(f, "Receivable scan error: '{}'", err),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PayableScanError {
    PlainTextError(String),
    ErrorWithTxsIssued {
        error: ErrorWithTxsIssued,
        failed_txs: Vec<FailedTx>,
    },
}

// impl From<&PayableScanError> for Vec<SimplePayable> {
//     fn from(err: &PayableScanError) -> Self {
//         match err {
//             PayableScanError::PlainTextError(_) => vec![],
//             PayableScanError::ErrorWithTxsIssued { failed_txs, .. } => {
//                 failed_txs.iter().map(|tx|SimplePayable::new(tx.receiver_address, tx.hash)).collect()
//             }
//         }
//     }
// }

impl From<PayableScanError> for Vec<FailedTx> {
    fn from(err: PayableScanError) -> Self {
        match err {
            PayableScanError::PlainTextError(_) => vec![],
            PayableScanError::ErrorWithTxsIssued { failed_txs, .. } => failed_txs,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorWithTxsIssued {
    Sending(String),
    FromRPCResponse,
}

pub struct PayableScanPlainTextError {
    pub scan_type: PayableScanType,
    pub msg: String,
}

impl From<PayableScanPlainTextError> for ScanErrorPayload {
    fn from(_: PayableScanPlainTextError) -> Self {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use crate::accountant::db_access_objects::failed_payable_dao::FailedTx;
    use crate::accountant::db_access_objects::test_utils::make_failed_tx;
    use crate::accountant::scanners::payable_scanner::tx_templates::priced::retry::PricedRetryTxTemplates;
    use crate::accountant::scanners::payable_scanner::tx_templates::test_utils::make_priced_new_tx_templates;
    use crate::accountant::test_utils::make_payable_account;
    use crate::accountant::{PayableScanType, SimplePayable};
    use crate::actor_system_factory::SubsFactory;
    use crate::blockchain::blockchain_agent::test_utils::BlockchainAgentMock;
    use crate::blockchain::blockchain_bridge::{
        BlockchainBridge, BlockchainBridgeSubsFactoryReal, MsgInterpretableAsPayableScanType,
    };
    use crate::blockchain::test_utils::make_blockchain_interface_web3;
    use crate::sub_lib::blockchain_bridge::{
        DetailedScanType, ErrorWithTxsIssued, OutboundPaymentsInstructions, PayableScanError,
        ScanErrorPayload,
    };
    use crate::test_utils::persistent_configuration_mock::PersistentConfigurationMock;
    use crate::test_utils::recorder::{make_blockchain_bridge_subs_from_recorder, Recorder};
    use actix::{Actor, System};
    use itertools::Either;
    use masq_lib::messages::ScanType;
    use masq_lib::utils::find_free_port;
    use std::sync::{Arc, Mutex};
    impl From<DetailedScanType> for ScanType {
        fn from(scan_type: DetailedScanType) -> Self {
            match scan_type {
                DetailedScanType::NewPayables => ScanType::Payables,
                DetailedScanType::RetryPayables => ScanType::Payables,
                DetailedScanType::PendingPayables => ScanType::PendingPayables,
                DetailedScanType::Receivables => ScanType::Receivables,
            }
        }
    }

    #[test]
    fn blockchain_bridge_subs_debug() {
        let recorder = Recorder::new().start();

        let subject = make_blockchain_bridge_subs_from_recorder(&recorder);

        assert_eq!(format!("{:?}", subject), "BlockchainBridgeSubs");
    }

    #[test]
    fn blockchain_bridge_subs_factory_produces_proper_subs() {
        let subject = BlockchainBridgeSubsFactoryReal {};
        let blockchain_interface = make_blockchain_interface_web3(find_free_port());
        let persistent_config = PersistentConfigurationMock::new();
        let accountant = BlockchainBridge::new(
            Box::new(blockchain_interface),
            Arc::new(Mutex::new(persistent_config)),
            false,
        );
        let system = System::new("blockchain_bridge_subs_factory_produces_proper_subs");
        let addr = accountant.start();

        let subs = subject.make(&addr);

        System::current().stop();
        system.run();
        assert_eq!(subs, BlockchainBridge::make_subs_from(&addr))
    }

    #[test]
    fn payable_scan_type_is_implemented_for_outbound_payments_instructions() {
        let msg_a = OutboundPaymentsInstructions {
            priced_templates: Either::Left(make_priced_new_tx_templates(vec![(
                make_payable_account(123),
                123,
            )])),
            agent: Box::new(BlockchainAgentMock::default()),
            response_skeleton_opt: None,
        };
        let msg_b = OutboundPaymentsInstructions {
            priced_templates: Either::Right(PricedRetryTxTemplates(vec![])),
            agent: Box::new(BlockchainAgentMock::default()),
            response_skeleton_opt: None,
        };

        assert_eq!(msg_a.payable_scan_type(), PayableScanType::New);
        assert_eq!(msg_b.payable_scan_type(), PayableScanType::Retry)
    }

    #[test]
    fn detailed_scan_type_from_scan_error_payable() {
        assert_eq!(
            DetailedScanType::from(&ScanErrorPayload::NewPayables(
                PayableScanError::PlainTextError("bluh".to_string())
            )),
            DetailedScanType::NewPayables
        );
        assert_eq!(
            DetailedScanType::from(&ScanErrorPayload::NewPayables(
                PayableScanError::ErrorWithTxsIssued {
                    error: ErrorWithTxsIssued::Sending("bluh".to_string()),
                    failed_txs: vec![]
                }
            )),
            DetailedScanType::NewPayables
        );
        assert_eq!(
            DetailedScanType::from(&ScanErrorPayload::RetryPayables(
                PayableScanError::PlainTextError("bluh".to_string())
            )),
            DetailedScanType::RetryPayables
        );
        assert_eq!(
            DetailedScanType::from(&ScanErrorPayload::RetryPayables(
                PayableScanError::ErrorWithTxsIssued {
                    error: ErrorWithTxsIssued::Sending("bluh".to_string()),
                    failed_txs: vec![]
                }
            )),
            DetailedScanType::RetryPayables
        );
        assert_eq!(
            DetailedScanType::from(&ScanErrorPayload::PendingPayables("bluh".to_string())),
            DetailedScanType::PendingPayables
        );
        assert_eq!(
            DetailedScanType::from(&ScanErrorPayload::Receivables("bluh".to_string())),
            DetailedScanType::Receivables
        );
    }

    #[test]
    fn failed_txs_can_be_converted_from_payable_scan_error() {
        let result_1 = PayableScanError::PlainTextError("bluh".to_string());
        let result_2 = PayableScanError::ErrorWithTxsIssued {
            error: ErrorWithTxsIssued::Sending("bluh".to_string()),
            failed_txs: vec![make_failed_tx(456), make_failed_tx(789)],
        };

        assert_eq!(<Vec<FailedTx>>::from(result_1), vec![]);
        assert_eq!(
            <Vec<FailedTx>>::from(result_2),
            vec![make_failed_tx(456), make_failed_tx(789)]
        );
    }

    // #[test]
    // fn simple_payables_can_be_converted_from_ref_of_payable_scan_error() {
    //     let err_1 = PayableScanError::PlainTextError("bluh".to_string());
    //     let failed_tx_a = make_failed_tx(123);
    //     let receivable_address_a = failed_tx_a.receiver_address;
    //     let hash_a = failed_tx_a.hash.clone();
    //     let failed_tx_b = make_failed_tx(456);
    //     let receivable_address_b = failed_tx_b.receiver_address;
    //     let hash_b = failed_tx_b.hash.clone();
    //     let err_2 = PayableScanError::ErrorWithTxsIssued {
    //         error: ErrorWithTxsIssued::Sending("bluh".to_string()),
    //         failed_txs: vec![failed_tx_a, failed_tx_b],
    //     };
    //
    //     assert_eq!(<Vec<SimplePayable>>::from(&err_1), vec![]);
    //     assert_eq!(<Vec<SimplePayable>>::from(&err_2), vec![SimplePayable::new(receivable_address_a, hash_a), SimplePayable::new(receivable_address_b, hash_b)]);
    // }

    #[test]
    fn display_for_scan_error_payload_is_implemented() {
        let setup = vec![
            (ScanErrorPayload::NewPayables(PayableScanError::PlainTextError("One cannot be always correct".to_string())), "New payable scan error: 'One cannot be always correct'".to_string()),
            (ScanErrorPayload::RetryPayables(PayableScanError::ErrorWithTxsIssued{error: ErrorWithTxsIssued::Sending("When two at once, it's getting alarming".to_string()), failed_txs: vec![make_failed_tx(456)]}), "Retry payable scan error — during tx submission, 1 failed tx records: 'When two at once, it's getting alarming'".to_string()),
            (ScanErrorPayload::RetryPayables(PayableScanError::ErrorWithTxsIssued{error: ErrorWithTxsIssued::FromRPCResponse, failed_txs: vec![make_failed_tx(456), make_failed_tx(789)]}), "Retry payable scan error — RPC response with 2 failed tx records".to_string()),
            (ScanErrorPayload::PendingPayables("Three? Ring the bell!".to_string()), "Pending payable scan error: 'Three? Ring the bell!'".to_string()),
            (ScanErrorPayload::Receivables("Don't even say. Four men? <yelling>".to_string()), "Receivable scan error: 'Don't even say. Four men? <yelling>'".to_string())];

        setup
            .into_iter()
            .for_each(|(payload, expected_result)| assert_eq!(payload.to_string(), expected_result))
    }
}
