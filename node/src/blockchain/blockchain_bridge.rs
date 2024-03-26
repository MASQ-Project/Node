// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::db_access_objects::payable_dao::PayableAccount;
use crate::accountant::scanners::mid_scan_msg_handling::payable_scanner::blockchain_agent::BlockchainAgent;
use crate::accountant::scanners::mid_scan_msg_handling::payable_scanner::msgs::{
    BlockchainAgentWithContextMessage, QualifiedPayablesMessage,
};
use crate::accountant::{
    PaymentsAndStartBlock, ReceivedPayments, ReceivedPaymentsError, ResponseSkeleton, ScanError,
    SentPayables, SkeletonOptHolder,
};
use crate::accountant::{ReportTransactionReceipts, RequestTransactionReceipts};
use crate::actor_system_factory::SubsFactory;
use crate::blockchain::blockchain_interface::blockchain_interface_null::BlockchainInterfaceNull;
use crate::blockchain::blockchain_interface::blockchain_interface_web3::{
    HashAndAmount, ProcessedPayableFallible,
};
use crate::blockchain::blockchain_interface::data_structures::errors::{
    BlockchainError, PayableTransactionError,
};
use crate::blockchain::blockchain_interface::BlockchainInterface;
use crate::blockchain::blockchain_interface_initializer::BlockchainInterfaceInitializer;
use crate::blockchain::blockchain_interface_utils::send_payables_within_batch;
use crate::database::db_initializer::{DbInitializationConfig, DbInitializer, DbInitializerReal};
use crate::db_config::config_dao::ConfigDaoReal;
use crate::db_config::persistent_configuration::{
    PersistentConfiguration, PersistentConfigurationReal,
};
use crate::sub_lib::blockchain_bridge::{
    BlockchainBridgeSubs, ConsumingWalletBalances, OutboundPaymentsInstructions,
};
use crate::sub_lib::peer_actors::BindMessage;
use crate::sub_lib::utils::{db_connection_launch_panic, handle_ui_crash_request};
use crate::sub_lib::wallet::Wallet;
use actix::Actor;
use actix::Context;
use actix::Handler;
use actix::Message;
use actix::{Addr, Recipient};
use futures::future::err;
use futures::Future;
use itertools::Itertools;
use masq_lib::blockchains::chains::Chain;
use masq_lib::logger::Logger;
use masq_lib::messages::ScanType;
use masq_lib::ui_gateway::NodeFromUiMessage;
use regex::Regex;
use std::path::Path;
use std::time::SystemTime;
use web3::transports::Batch;
use web3::transports::Http;
use web3::types::{BlockNumber, TransactionReceipt, H256};

pub const CRASH_KEY: &str = "BLOCKCHAINBRIDGE";

pub struct BlockchainBridge {
    consuming_wallet_opt: Option<Wallet>,
    blockchain_interface: Box<dyn BlockchainInterface>,
    logger: Logger,
    persistent_config: Box<dyn PersistentConfiguration>,
    sent_payable_subs_opt: Option<Recipient<SentPayables>>,
    payable_payments_setup_subs_opt: Option<Recipient<BlockchainAgentWithContextMessage>>,
    received_payments_subs_opt: Option<Recipient<ReceivedPayments>>,
    scan_error_subs_opt: Option<Recipient<ScanError>>,
    update_start_block_subs_opt: Option<Recipient<UpdateStartBlockMessage>>,
    crashable: bool,
    pending_payable_confirmation: TransactionConfirmationTools,
}

struct TransactionConfirmationTools {
    new_pp_fingerprints_sub_opt: Option<Recipient<PendingPayableFingerprintSeeds>>,
    report_transaction_receipts_sub_opt: Option<Recipient<ReportTransactionReceipts>>,
}

impl Actor for BlockchainBridge {
    type Context = Context<Self>;
}

impl Handler<BindMessage> for BlockchainBridge {
    type Result = ();

    fn handle(&mut self, msg: BindMessage, _ctx: &mut Self::Context) -> Self::Result {
        self.pending_payable_confirmation
            .new_pp_fingerprints_sub_opt =
            Some(msg.peer_actors.accountant.init_pending_payable_fingerprints);
        self.pending_payable_confirmation
            .report_transaction_receipts_sub_opt =
            Some(msg.peer_actors.accountant.report_transaction_receipts);
        self.payable_payments_setup_subs_opt =
            Some(msg.peer_actors.accountant.report_payable_payments_setup);
        self.sent_payable_subs_opt = Some(msg.peer_actors.accountant.report_sent_payments);
        self.received_payments_subs_opt = Some(msg.peer_actors.accountant.report_inbound_payments);
        self.scan_error_subs_opt = Some(msg.peer_actors.accountant.scan_errors);
        self.update_start_block_subs_opt =
            Some(msg.peer_actors.blockchain_bridge.update_start_block_sub);
        match self.consuming_wallet_opt.as_ref() {
            Some(wallet) => debug!(
                self.logger,
                "Received BindMessage; consuming wallet address {}", wallet
            ),
            None => debug!(
                self.logger,
                "Received BindMessage; no consuming wallet address specified"
            ),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Message, Clone)]
pub struct RetrieveTransactions {
    pub recipient: Wallet,
    pub response_skeleton_opt: Option<ResponseSkeleton>,
}

impl SkeletonOptHolder for RetrieveTransactions {
    fn skeleton_opt(&self) -> Option<ResponseSkeleton> {
        self.response_skeleton_opt
    }
}

impl Handler<RetrieveTransactions> for BlockchainBridge {
    type Result = ();

    fn handle(
        &mut self,
        msg: RetrieveTransactions,
        _ctx: &mut Self::Context,
    ) -> <Self as Handler<RetrieveTransactions>>::Result {
        self.handle_scan_future(
            Self::handle_retrieve_transactions,
            ScanType::Receivables,
            msg,
        )
    }
}

impl Handler<RequestTransactionReceipts> for BlockchainBridge {
    type Result = ();

    fn handle(&mut self, msg: RequestTransactionReceipts, _ctx: &mut Self::Context) {
        self.handle_scan(
            Self::handle_request_transaction_receipts,
            ScanType::PendingPayables,
            msg,
        )
    }
}

impl Handler<QualifiedPayablesMessage> for BlockchainBridge {
    // Done
    type Result = ();

    fn handle(&mut self, msg: QualifiedPayablesMessage, _ctx: &mut Self::Context) {
        self.handle_scan_future(Self::handle_qualified_payable_msg, ScanType::Payables, msg);
    }
}

impl Handler<OutboundPaymentsInstructions> for BlockchainBridge {
    // Done
    type Result = ();

    fn handle(&mut self, msg: OutboundPaymentsInstructions, _ctx: &mut Self::Context) {
        self.handle_scan_future(
            Self::handle_outbound_payments_instructions,
            ScanType::Payables,
            msg,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Message)]
pub struct PendingPayableFingerprintSeeds {
    pub batch_wide_timestamp: SystemTime,
    pub hashes_and_balances: Vec<HashAndAmount>,
}

#[derive(Debug, Clone, PartialEq, Eq, Message)]
pub struct UpdateStartBlockMessage {
    pub start_block: u64,
}

impl Handler<UpdateStartBlockMessage> for BlockchainBridge {
    type Result = ();

    fn handle(&mut self, msg: UpdateStartBlockMessage, _ctx: &mut Self::Context) -> Self::Result {
        if let Err(e) = self.persistent_config.set_start_block(msg.start_block) {
            panic!(
                "Cannot set start block in database; payments to you may not be processed: {:?}",
                e
            )
        };
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct PendingPayableFingerprint {
    // Sqlite begins counting from 1
    pub rowid: u64,
    pub timestamp: SystemTime,
    pub hash: H256,
    // We have Sqlite begin counting from 1
    pub attempt: u16,
    pub amount: u128,
    pub process_error: Option<String>,
}

impl Handler<NodeFromUiMessage> for BlockchainBridge {
    type Result = ();

    fn handle(&mut self, msg: NodeFromUiMessage, _ctx: &mut Self::Context) -> Self::Result {
        handle_ui_crash_request(msg, &self.logger, self.crashable, CRASH_KEY)
    }
}

impl BlockchainBridge {
    pub fn new(
        blockchain_interface: Box<dyn BlockchainInterface>,
        persistent_config: Box<dyn PersistentConfiguration>,
        crashable: bool,
        consuming_wallet_opt: Option<Wallet>,
    ) -> BlockchainBridge {
        BlockchainBridge {
            consuming_wallet_opt,
            blockchain_interface,
            persistent_config,
            sent_payable_subs_opt: None,
            payable_payments_setup_subs_opt: None,
            received_payments_subs_opt: None,
            scan_error_subs_opt: None,
            update_start_block_subs_opt: None,
            crashable,
            logger: Logger::new("BlockchainBridge"),
            pending_payable_confirmation: TransactionConfirmationTools {
                new_pp_fingerprints_sub_opt: None,
                report_transaction_receipts_sub_opt: None,
            },
        }
    }

    pub fn initialize_persistent_configuration(
        data_directory: &Path,
    ) -> Box<dyn PersistentConfiguration> {
        let config_dao = Box::new(ConfigDaoReal::new(
            DbInitializerReal::default()
                .initialize(data_directory, DbInitializationConfig::panic_on_migration())
                .unwrap_or_else(|err| db_connection_launch_panic(err, data_directory)),
        ));
        Box::new(PersistentConfigurationReal::new(config_dao))
    }

    pub fn initialize_blockchain_interface(
        blockchain_service_url_opt: Option<String>,
        chain: Chain,
    ) -> Box<dyn BlockchainInterface> {
        match blockchain_service_url_opt {
            Some(url) => {
                // TODO if we decided to have interchangeably runtime switchable or simultaneously usable interfaces we will
                // probably want to make BlockchainInterfaceInitializer a collaborator that's a part of the actor
                BlockchainInterfaceInitializer {}.initialize_interface(&url, chain)
            }
            None => Box::new(BlockchainInterfaceNull::default()),
        }
    }

    pub fn make_subs_from(addr: &Addr<BlockchainBridge>) -> BlockchainBridgeSubs {
        BlockchainBridgeSubs {
            bind: recipient!(addr, BindMessage),
            outbound_payments_instructions: recipient!(addr, OutboundPaymentsInstructions),
            qualified_payables: recipient!(addr, QualifiedPayablesMessage),
            retrieve_transactions: recipient!(addr, RetrieveTransactions),
            ui_sub: recipient!(addr, NodeFromUiMessage),
            request_transaction_receipts: recipient!(addr, RequestTransactionReceipts),
            update_start_block_sub: recipient!(addr, UpdateStartBlockMessage),
        }
    }

    // fn handle_qualified_payable_msg(
    //     &mut self,
    //     incoming_message: QualifiedPayablesMessage,
    // ) -> Result<(), String> {
    //     let consuming_wallet = if let Some(wallet) = self.consuming_wallet_opt.as_ref() {
    //         wallet
    //     } else {
    //         return Err(
    //             "Cannot inspect available balances for payables while consuming wallet is missing"
    //                 .to_string(),
    //         );
    //     };
    //
    //     let agent = self
    //         .blockchain_interface
    //         .build_blockchain_agent(consuming_wallet, &*self.persistent_config)
    //         .map_err(to_string)?;
    //
    //     let outgoing_message = BlockchainAgentWithContextMessage::new(
    //         incoming_message.protected_qualified_payables,
    //         agent,
    //         incoming_message.response_skeleton_opt,
    //     );
    //
    //     self.payable_payments_setup_subs_opt
    //         .as_ref()
    //         .expect("Accountant is unbound")
    //         .try_send(outgoing_message)
    //         .expect("Accountant is dead");
    //
    //     Ok(())
    // }

    fn handle_qualified_payable_msg(
        &mut self,
        incoming_message: QualifiedPayablesMessage,
    ) -> Box<dyn Future<Item = (), Error = String>> {
        let consuming_wallet = match self.consuming_wallet_opt.as_ref() {
            Some(wallet) => wallet,
            None => {
                return Box::new(err(
                    "Cannot inspect available balances for payables while consuming wallet \
                    is missing"
                        .to_string(),
                ))
            }
        };
        //TODO rewrite this into a batch call as soon as GH-629 gets into master

        // TODO: GH-744 This is from Master

        //     let agent = self
        //         .blockchain_interface
        //         .build_blockchain_agent(consuming_wallet, &*self.persistent_config)
        //         .map_err(to_string)?;
        //
        //     let outgoing_message = BlockchainAgentWithContextMessage::new(
        //         incoming_message.protected_qualified_payables,
        //         agent,
        //         incoming_message.response_skeleton_opt,
        //     );
        //
        //     self.payable_payments_setup_subs_opt
        //         .as_ref()
        //         .expect("Accountant is unbound")
        //         .try_send(outgoing_message)
        //         .expect("Accountant is dead");

        // let balances_and_payables_sub_opt = self.balances_and_payables_sub_opt.clone();
        let get_transaction_fee_balance = self
            .blockchain_interface
            .get_transaction_fee_balance(consuming_wallet)
            .map_err(|e| {
                format!(
                    "Did not find out gas balance of the consuming wallet: {:?}",
                    e
                )
            });

        return Box::new(
            self.blockchain_interface
                .get_token_balance(consuming_wallet)
                .map_err(|e| {
                    format!(
                        "Did not find out token balance of the consuming wallet: {:?}",
                        e
                    )
                })
                .and_then(move |token_balance| {
                    get_transaction_fee_balance.and_then(move |gas_balance| {
                        let consuming_wallet_balances = {
                            ConsumingWalletBalances {
                                transaction_fee_balance_in_minor_units: gas_balance,
                                masq_token_balance_in_minor_units: token_balance,
                            }
                        };
                        todo!("TODO: GH-744: This needs to be updated with Masters code");
                        // balances_and_payables_sub_opt
                        //     .as_ref()
                        //     .expect("Accountant is unbound")
                        //     .try_send(ConsumingWalletBalancesAndQualifiedPayables {
                        //         qualified_payables: incoming_message.accounts,
                        //         consuming_wallet_balances,
                        //         response_skeleton_opt: incoming_message.response_skeleton_opt,
                        //     })
                        //     .expect("Accountant is dead");
                        Ok(())
                    })
                }),
        );
    }

    // fn handle_outbound_payments_instructions(
    //     &mut self,
    //     msg: OutboundPaymentsInstructions,
    // ) -> Result<(), String> {
    //     let skeleton_opt = msg.response_skeleton_opt;
    //     let agent = msg.agent;
    //     let checked_accounts = msg.affordable_accounts;
    //     let result = self.process_payments(agent, checked_accounts);
    //
    //     let locally_produced_result = match &result {
    //         Err(e) => Err(format!("ReportAccountsPayable: {}", e)),
    //         Ok(_) => Ok(()),
    //     };
    //
    //     self.sent_payable_subs_opt
    //         .as_ref()
    //         .expect("Accountant is unbound")
    //         .try_send(SentPayables {
    //             payment_procedure_result: result,
    //             response_skeleton_opt: skeleton_opt,
    //         })
    //         .expect("Accountant is dead");
    //
    //     locally_produced_result
    // }

    // Result<(), String>
    // handle_report_accounts_payable
    fn handle_outbound_payments_instructions(
        &mut self,
        msg: OutboundPaymentsInstructions,
    ) -> Box<dyn Future<Item = (), Error = String>> {
        let skeleton_opt = msg.response_skeleton_opt;
        let sent_payable_subs = self
            .sent_payable_subs_opt
            .as_ref()
            .expect("Accountant is unbound")
            .clone();

        let send_message_if_failure = move |msg: SentPayables| {
            eprintln!("Before Sending message: {:?}", msg);
            sent_payable_subs.try_send(msg).expect("Accountant is dead");
        };
        let send_message_if_successful = send_message_if_failure.clone();

        // todo!("GH-744: we are not passing the message in process_payments")
        return Box::new(
            self.process_payments(msg)
                .map_err(move |e: PayableTransactionError| {
                    send_message_if_failure(SentPayables {
                        payment_procedure_result: Err(e.clone()),
                        response_skeleton_opt: skeleton_opt,
                    });
                    format!("ReportAccountsPayable: {}", e)
                })
                .and_then(move |payment_result| {
                    todo!("GH-744: handle_outbound_payments_instructions Ok Case");
                    // send_message_if_successful(SentPayables {
                    //     payment_procedure_result: Ok(payment_result),
                    //     response_skeleton_opt: skeleton_opt,
                    // });
                    Ok(())
                }),
        );
    }

    fn handle_retrieve_transactions(
        &mut self,
        msg: RetrieveTransactions,
    ) -> Box<dyn Future<Item = (), Error = String>> {
        let start_block_nbr = match self.persistent_config.start_block() {
                Ok (sb) => sb,
                Err (e) => panic! ("Cannot retrieve start block from database; payments to you may not be processed: {:?}", e)
            };
        let max_block_count = match self.persistent_config.max_block_count() {
            Ok(Some(mbc)) => mbc,
            _ => u64::MAX,
        };
        let end_block = match self
            .blockchain_interface
            .lower_interface()
            .get_block_number()
        {
            Ok(eb) => {
                if u64::MAX == max_block_count {
                    BlockNumber::Number(eb)
                } else {
                    BlockNumber::Number(eb.as_u64().min(start_block_nbr + max_block_count).into())
                }
            }
            Err(e) => {
                info!(
                    self.logger,
                    "Using 'latest' block number instead of a literal number. {:?}", e
                );
                if max_block_count == u64::MAX {
                    BlockNumber::Latest
                } else {
                    BlockNumber::Number((start_block_nbr + max_block_count).into())
                }
            }
        };
        let start_block = BlockNumber::Number(start_block_nbr.into());
        let received_payments_subs_ok_case = self
            .received_payments_subs_opt
            .as_ref()
            .expect("Accountant is unbound")
            .clone();
        let received_payments_subs_error_case = self
            .received_payments_subs_opt
            .as_ref()
            .expect("Accountant is unbound")
            .clone();

        Box::new(
            self.blockchain_interface
                .retrieve_transactions(start_block, end_block, &msg.recipient)
                .map_err(move |e| {
                    // todo!("GH-744: handle_retrieve_transactions - error case");
                    let received_payments_error =
                        match BlockchainBridge::extract_max_block_count(e.clone()) {
                            Some(max_block_count) => {
                                ReceivedPaymentsError::ExceededBlockScanLimit(max_block_count)
                            }
                            None => ReceivedPaymentsError::OtherRPCError(format!(
                                "Attempted to retrieve received payments but failed: {:?}",
                                e
                            )),
                        };

                    received_payments_subs_error_case
                        .try_send(ReceivedPayments {
                            timestamp: SystemTime::now(),
                            scan_result: Err(received_payments_error.clone()),
                            response_skeleton_opt: msg.response_skeleton_opt,
                        })
                        .expect("Accountant is dead.");
                    format!(
                        "Error while retrieving transactions: {:?}",
                        received_payments_error
                    )
                })
                .and_then(move |transactions| {
                    // todo!("GH-744: handle_retrieve_transactions - Ok case");

                    let payments_and_start_block = PaymentsAndStartBlock {
                        payments: transactions.transactions,
                        new_start_block: transactions.new_start_block,
                    };

                    received_payments_subs_ok_case
                        .try_send(ReceivedPayments {
                            timestamp: SystemTime::now(),
                            scan_result: Ok(payments_and_start_block),
                            response_skeleton_opt: msg.response_skeleton_opt,
                        })
                        .expect("Accountant is dead.");
                    Ok(())
                }),
        )
    }

    fn handle_request_transaction_receipts(
        &mut self,
        msg: RequestTransactionReceipts,
    ) -> Result<(), String> {
        let init: (
            Vec<Option<TransactionReceipt>>,
            Option<(BlockchainError, H256)>,
        ) = (vec![], None);
        let (vector_of_results, error_opt) = msg.pending_payable.iter().fold(
            init,
            |(mut ok_receipts, err_opt), current_fingerprint| match err_opt {
                None => match self
                    .blockchain_interface
                    .get_transaction_receipt(current_fingerprint.hash)
                {
                    Ok(receipt_opt) => {
                        ok_receipts.push(receipt_opt);
                        (ok_receipts, None)
                    }
                    Err(e) => (ok_receipts, Some((e, current_fingerprint.hash))),
                },
                _ => (ok_receipts, err_opt),
            },
        );
        let pairs = vector_of_results
            .into_iter()
            .zip(msg.pending_payable.into_iter())
            .collect_vec();
        self.pending_payable_confirmation
            .report_transaction_receipts_sub_opt
            .as_ref()
            .expect("Accountant is unbound")
            .try_send(ReportTransactionReceipts {
                fingerprints_with_receipts: pairs,
                response_skeleton_opt: msg.response_skeleton_opt,
            })
            .expect("Accountant is dead");
        if let Some((e, hash)) = error_opt {
            return Err (format! (
                "Aborting scanning; request of a transaction receipt for '{:?}' failed due to '{:?}'",
                hash,
                e
            ));
        }
        Ok(())
    }

    fn handle_scan_future<M, F>(&mut self, handler: F, scan_type: ScanType, msg: M)
    where
        F: FnOnce(&mut BlockchainBridge, M) -> Box<dyn Future<Item = (), Error = String>>,
        M: SkeletonOptHolder,
    {
        // TODO: GH-744 This function could be Mocked and tested
        let skeleton_opt = msg.skeleton_opt();
        let logger = self.logger.clone();
        let scan_error_subs_opt = self.scan_error_subs_opt.clone();
        let future = handler(self, msg).map_err(move |e| {
            warning!(logger, "{}", e);
            // TODO: GH-744 This ScanError needs to be removed, And added into OutboundPaymentsInstructions & QualifiedPayablesMessage
            scan_error_subs_opt
                .as_ref()
                .expect("Accountant not bound")
                .try_send(ScanError {
                    scan_type,
                    response_skeleton_opt: skeleton_opt,
                    msg: e,
                })
                .expect("Accountant is dead");
        });

        actix::spawn(future);
    }

    fn handle_scan<M, F>(&mut self, handler: F, scan_type: ScanType, msg: M)
    where
        F: FnOnce(&mut BlockchainBridge, M) -> Result<(), String>,
        M: SkeletonOptHolder,
    {
        let skeleton_opt = msg.skeleton_opt();
        match handler(self, msg) {
            Ok(_r) => (),
            Err(e) => {
                warning!(self.logger, "{}", e);
                self.scan_error_subs_opt
                    .as_ref()
                    .expect("Accountant not bound")
                    .try_send(ScanError {
                        scan_type,
                        response_skeleton_opt: skeleton_opt,
                        msg: e,
                    })
                    .expect("Accountant is dead");
            }
        }
    }

    //
    // fn process_payments(
    //     &self,
    //     agent: Box<dyn BlockchainAgent>,
    //     affordable_accounts: Vec<PayableAccount>,
    // ) -> Result<Vec<ProcessedPayableFallible>, PayableTransactionError> {
    //     let new_fingerprints_recipient = self.new_fingerprints_recipient();
    //
    //     self.blockchain_interface.send_batch_of_payables(
    //         agent,
    //         new_fingerprints_recipient,
    //         &affordable_accounts,
    //     )
    // }

    fn process_payments(
        &self,
        msg: OutboundPaymentsInstructions, // agent: Box<dyn BlockchainAgent>,
                                           // affordable_accounts: Vec<PayableAccount>,
    ) -> Box<dyn Future<Item = Vec<ProcessedPayableFallible>, Error = PayableTransactionError>>
    {
        // todo!("GH-744: process_payments - come back to this");
        // let msg_clone = msg.clone();

        let (consuming_wallet, gas_price) = match self.consuming_wallet_opt.as_ref() {
            Some(consuming_wallet) => match self.persistent_config.gas_price() {
                Ok(gas_price) => (consuming_wallet, gas_price),
                Err(e) => {
                    return Box::new(err(PayableTransactionError::GasPriceQueryFailed(format!(
                        "{:?}",
                        e
                    ))))
                }
            },
            None => return Box::new(err(PayableTransactionError::MissingConsumingWallet)),
        };

        let new_fingerprints_recipient = self.new_fingerprints_recipient().clone();
        let logger = self.logger.clone();
        let chain = self.blockchain_interface.get_chain();
        let batch_web3 = self.blockchain_interface.get_web3_batch();
        let web3 = self.blockchain_interface.get_web3();
        let consuming_wallet_clone = consuming_wallet.clone();

        // todo!("Are we hitting this");
        return Box::new(
            self.blockchain_interface
                .get_transaction_count(consuming_wallet)
                .map_err(|e| PayableTransactionError::TransactionID(e))
                .and_then(move |pending_nonce| {
                    eprintln!("Recived pending_nonce: {:?}", pending_nonce);
                    send_payables_within_batch(
                        logger,
                        chain,
                        web3,
                        batch_web3,
                        consuming_wallet_clone,
                        gas_price,
                        pending_nonce,
                        new_fingerprints_recipient.clone(),
                        msg.affordable_accounts,
                    )
                }),
        );
    }

    fn new_fingerprints_recipient(&self) -> &Recipient<PendingPayableFingerprintSeeds> {
        self.pending_payable_confirmation
            .new_pp_fingerprints_sub_opt
            .as_ref()
            .expect("Accountant unbound")
    }

    pub fn extract_max_block_count(error: BlockchainError) -> Option<u64> {
        let regex_result =
            Regex::new(r".* (max: |allowed for your plan: |is limited to |block range limit \()(?P<max_block_count>\d+).*")
                .expect("Invalid regex");
        let max_block_count = match error {
            BlockchainError::QueryFailed(msg) => match regex_result.captures(msg.as_str()) {
                Some(captures) => match captures.name("max_block_count") {
                    Some(m) => match m.as_str().parse::<u64>() {
                        Ok(value) => Some(value),
                        Err(_) => None,
                    },
                    _ => None,
                },
                None => match msg.as_str() {
                    "Got invalid response: Expected batch, got single." => Some(1000),
                    _ => None,
                },
            },
            _ => None,
        };
        max_block_count
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
struct PendingTxInfo {
    hash: H256,
    when_sent: SystemTime,
}

pub struct BlockchainBridgeSubsFactoryReal {}

impl SubsFactory<BlockchainBridge, BlockchainBridgeSubs> for BlockchainBridgeSubsFactoryReal {
    fn make(&self, addr: &Addr<BlockchainBridge>) -> BlockchainBridgeSubs {
        BlockchainBridge::make_subs_from(addr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accountant::db_access_objects::payable_dao::PayableAccount;
    use crate::accountant::db_access_objects::utils::from_time_t;
    use crate::accountant::scanners::mid_scan_msg_handling::payable_scanner::test_utils::BlockchainAgentMock;
    use crate::accountant::scanners::test_utils::{
        make_empty_payments_and_start_block, protect_payables_in_test,
    };
    use crate::accountant::test_utils::make_pending_payable_fingerprint;
    use crate::blockchain::bip32::Bip32EncryptionKeyProvider;
    use crate::blockchain::blockchain_interface::blockchain_interface_null::BlockchainInterfaceNull;
    use crate::blockchain::blockchain_interface::blockchain_interface_web3::{
        BlockchainInterfaceWeb3, REQUESTS_IN_PARALLEL,
    };
    use crate::blockchain::blockchain_interface::data_structures::errors::{
        BlockchainAgentBuildError, PayableTransactionError,
    };
    use crate::blockchain::blockchain_interface::data_structures::{
        BlockchainTransaction, RetrievedBlockchainTransactions,
    };
    use crate::blockchain::blockchain_interface::lower_level_interface::LatestBlockNumber;
    use crate::blockchain::blockchain_interface::test_utils::LowBlockchainIntMock;
    use crate::blockchain::test_utils::{make_tx_hash, BlockchainInterfaceMock};
    use crate::db_config::persistent_configuration::PersistentConfigError;
    use crate::match_every_type_id;
    use crate::node_test_utils::check_timestamp;
    use crate::test_utils::http_test_server::TestServer;
    use crate::test_utils::persistent_configuration_mock::PersistentConfigurationMock;
    use crate::test_utils::recorder::{
        make_accountant_subs_from_recorder, make_recorder, peer_actors_builder,
    };
    use crate::test_utils::recorder_stop_conditions::StopCondition;
    use crate::test_utils::recorder_stop_conditions::StopConditions;
    use crate::test_utils::unshared_test_utils::arbitrary_id_stamp::ArbitraryIdStamp;
    use crate::test_utils::unshared_test_utils::{
        assert_on_initialization_with_panic_on_migration, configure_default_persistent_config,
        prove_that_crash_request_handler_is_hooked_up, AssertionsMessage, ZERO,
    };
    use crate::test_utils::{make_paying_wallet, make_wallet};
    use actix::System;
    use ethereum_types::U64;
    use masq_lib::constants::DEFAULT_CHAIN;
    use masq_lib::messages::ScanType;
    use masq_lib::test_utils::logging::init_test_logging;
    use masq_lib::test_utils::logging::TestLogHandler;
    use masq_lib::test_utils::utils::{ensure_node_home_directory_exists, TEST_DEFAULT_CHAIN};
    use masq_lib::utils::find_free_port;
    use rustc_hex::FromHex;
    use std::any::TypeId;
    use std::net::Ipv4Addr;
    use std::path::Path;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, SystemTime};
    use web3::types::{BlockNumber, TransactionReceipt, H160};
    use web3::Web3;

    impl Handler<AssertionsMessage<Self>> for BlockchainBridge {
        type Result = ();

        fn handle(
            &mut self,
            msg: AssertionsMessage<Self>,
            _ctx: &mut Self::Context,
        ) -> Self::Result {
            (msg.assertions)(self)
        }
    }

    #[test]
    fn update_start_block_message_works() {
        let persistent_config = configure_default_persistent_config(ZERO)
            .start_block_result(Ok(42143274))
            .set_start_block_result(Ok(()));
        let subject = BlockchainBridge::new(
            stub_bi(),
            Box::new(persistent_config),
            false,
            Some(make_wallet("test wallet")),
        );
        let system = System::new("blockchain_bridge_receives_bind_message");
        let addr = subject.start();
        addr.try_send(BindMessage {
            peer_actors: peer_actors_builder().build(),
        })
        .unwrap();

        addr.try_send(UpdateStartBlockMessage {
            start_block: 42143274,
        })
        .unwrap();

        addr.try_send(AssertionsMessage {
            assertions: Box::new(|blockchain_bridge: &mut BlockchainBridge| {
                let start_block = blockchain_bridge.persistent_config.start_block().unwrap();
                assert_eq!(start_block, 42143274);
            }),
        })
        .unwrap();
        System::current().stop();
        system.run();
    }

    #[test]
    fn constants_have_correct_values() {
        assert_eq!(CRASH_KEY, "BLOCKCHAINBRIDGE");
    }

    fn stub_bi() -> Box<dyn BlockchainInterface> {
        Box::new(BlockchainInterfaceMock::default())
    }

    #[test]
    fn blockchain_bridge_receives_bind_message_with_consuming_private_key() {
        init_test_logging();
        let secret: Vec<u8> = "cc46befe8d169b89db447bd725fc2368b12542113555302598430cb5d5c74ea9"
            .from_hex()
            .unwrap();
        let consuming_wallet =
            Wallet::from(Bip32EncryptionKeyProvider::from_raw_secret(&secret).unwrap());
        let subject = BlockchainBridge::new(
            stub_bi(),
            Box::new(configure_default_persistent_config(ZERO)),
            false,
            Some(consuming_wallet.clone()),
        );
        let system = System::new("blockchain_bridge_receives_bind_message");
        let addr = subject.start();

        addr.try_send(BindMessage {
            peer_actors: peer_actors_builder().build(),
        })
        .unwrap();

        System::current().stop();
        system.run();
        TestLogHandler::new().exists_log_containing(&format!(
            "DEBUG: BlockchainBridge: Received BindMessage; consuming wallet address {}",
            consuming_wallet
        ));
    }

    #[test]
    fn blockchain_interface_null_as_result_of_missing_blockchain_service_url() {
        let result = BlockchainBridge::initialize_blockchain_interface(None, TEST_DEFAULT_CHAIN);

        result
            .as_any()
            .downcast_ref::<BlockchainInterfaceNull>()
            .unwrap();
    }

    #[test]
    fn blockchain_bridge_receives_bind_message_without_consuming_private_key() {
        init_test_logging();
        let subject = BlockchainBridge::new(
            stub_bi(),
            Box::new(PersistentConfigurationMock::default()),
            false,
            None,
        );
        let system = System::new("blockchain_bridge_receives_bind_message");
        let addr = subject.start();

        addr.try_send(BindMessage {
            peer_actors: peer_actors_builder().build(),
        })
        .unwrap();

        System::current().stop();
        system.run();
        TestLogHandler::new().exists_log_containing(
            "DEBUG: BlockchainBridge: Received BindMessage; no consuming wallet address specified",
        );
    }

    #[test]
    fn qualified_payables_msg_is_handled_and_new_msg_with_an_added_blockchain_agent_returns_to_accountant(
    ) {
        let system = System::new(
        "qualified_payables_msg_is_handled_and_new_msg_with_an_added_blockchain_agent_returns_to_accountant",
        );
        let build_blockchain_agent_params_arc = Arc::new(Mutex::new(vec![]));
        let (accountant, _, accountant_recording_arc) = make_recorder();
        let agent_id_stamp = ArbitraryIdStamp::new();
        let agent = BlockchainAgentMock::default().set_arbitrary_id_stamp(agent_id_stamp);
        let blockchain_interface = BlockchainInterfaceMock::default()
            .build_blockchain_agent_params(&build_blockchain_agent_params_arc)
            .build_blockchain_agent_result(Ok(Box::new(agent)));
        let consuming_wallet = make_paying_wallet(b"somewallet");
        let persistent_config_id_stamp = ArbitraryIdStamp::new();
        let persistent_configuration = PersistentConfigurationMock::default()
            .set_arbitrary_id_stamp(persistent_config_id_stamp);
        let wallet_1 = make_wallet("booga");
        let wallet_2 = make_wallet("gulp");
        let qualified_payables = vec![
            PayableAccount {
                wallet: wallet_1.clone(),
                balance_wei: 78_654_321_124,
                last_paid_timestamp: SystemTime::now()
                    .checked_sub(Duration::from_secs(1000))
                    .unwrap(),
                pending_payable_opt: None,
            },
            PayableAccount {
                wallet: wallet_2.clone(),
                balance_wei: 60_457_111_003,
                last_paid_timestamp: SystemTime::now()
                    .checked_sub(Duration::from_secs(500))
                    .unwrap(),
                pending_payable_opt: None,
            },
        ];
        let subject = BlockchainBridge::new(
            Box::new(blockchain_interface),
            Box::new(persistent_configuration),
            false,
            Some(consuming_wallet.clone()),
        );
        let addr = subject.start();
        let subject_subs = BlockchainBridge::make_subs_from(&addr);
        let peer_actors = peer_actors_builder().accountant(accountant).build();
        let qualified_payables = protect_payables_in_test(qualified_payables.clone());
        let qualified_payables_msg = QualifiedPayablesMessage {
            protected_qualified_payables: qualified_payables.clone(),
            response_skeleton_opt: Some(ResponseSkeleton {
                client_id: 11122,
                context_id: 444,
            }),
        };
        send_bind_message!(subject_subs, peer_actors);

        addr.try_send(qualified_payables_msg).unwrap();

        System::current().stop();
        system.run();

        let build_blockchain_agent_params = build_blockchain_agent_params_arc.lock().unwrap();
        assert_eq!(
            *build_blockchain_agent_params,
            vec![(consuming_wallet.clone(), persistent_config_id_stamp)]
        );
        let accountant_received_payment = accountant_recording_arc.lock().unwrap();
        let blockchain_agent_with_context_msg_actual: &BlockchainAgentWithContextMessage =
            accountant_received_payment.get_record(0);
        assert_eq!(
            blockchain_agent_with_context_msg_actual.protected_qualified_payables,
            qualified_payables
        );
        assert_eq!(
            blockchain_agent_with_context_msg_actual
                .agent
                .arbitrary_id_stamp(),
            agent_id_stamp
        );
        assert_eq!(accountant_received_payment.len(), 1);
    }

    #[test]
    fn report_accounts_payable_returns_error_when_there_is_no_consuming_wallet_configured() {
        todo!("GH-744 - This test needs refactoring");
        // let blockchain_interface_mock = BlockchainInterfaceMock::default();
        // let persistent_configuration_mock = PersistentConfigurationMock::default();
        // let (accountant, _, accountant_recording_arc) = make_recorder();
        // let recipient = accountant.start().recipient();
        // let mut subject = BlockchainBridge::new(
        //     Box::new(blockchain_interface_mock),
        //     Box::new(persistent_configuration_mock),
        //     false,
        //     None,
        // );
        // subject.sent_payable_subs_opt = Some(recipient);
        // let request = ReportAccountsPayable {
        //     accounts: vec![PayableAccount {
        //         wallet: make_wallet("blah"),
        //         balance_wei: 42,
        //         last_paid_timestamp: SystemTime::now(),
        //         pending_payable_opt: None,
        //     }],
        //     response_skeleton_opt: None,
        // };
        // let system = System::new("test");
        //
        // let result = subject.handle_report_accounts_payable(request).wait();
        //
        // System::current().stop();
        // assert_eq!(system.run(), 0);
        // assert_eq!(
        //     result,
        //     Err("ReportAccountsPayable: Missing consuming wallet to pay payable from".to_string())
        // );
        // let accountant_recording = accountant_recording_arc.lock().unwrap();
        // let sent_payables_msg = accountant_recording.get_record::<SentPayables>(0);
        // assert_eq!(
        //     sent_payables_msg,
        //     &SentPayables {
        //         payment_procedure_result: Err(PayableTransactionError::MissingConsumingWallet),
        //         response_skeleton_opt: None
        //     }
        // );
        // assert_eq!(accountant_recording.len(), 1)
    }

    #[test]
    fn handle_request_balances_to_pay_payables_reports_balances_and_payables_back_to_accountant() {
        todo!("GH-744 - This test needs refactoring");
        // let system = System::new(
        //     "handle_request_balances_to_pay_payables_reports_balances_and_payables_back_to_accountant",
        // );
        // let get_transaction_fee_balance_params_arc = Arc::new(Mutex::new(vec![]));
        // let get_token_balance_params_arc = Arc::new(Mutex::new(vec![]));
        // let (accountant, _, accountant_recording_arc) = make_recorder();
        // let accountant = accountant.system_stop_conditions(match_every_type_id!(
        //     ConsumingWalletBalancesAndQualifiedPayables
        // ));
        // let gas_balance = U256::from(4455);
        // let token_balance = U256::from(112233);
        // let wallet_balances_found = ConsumingWalletBalances {
        //     transaction_fee_balance_in_minor_units: gas_balance,
        //     masq_token_balance_in_minor_units: token_balance,
        // };
        // let blockchain_interface = BlockchainInterfaceMock::default()
        //     .get_transaction_fee_balance_params(&get_transaction_fee_balance_params_arc)
        //     .get_transaction_fee_balance_result(Ok(gas_balance))
        //     .get_token_balance_params(&get_token_balance_params_arc)
        //     .get_token_balance_result(Ok(token_balance));
        // let consuming_wallet = make_paying_wallet(b"somewallet");
        // let persistent_configuration = PersistentConfigurationMock::default();
        // let qualified_accounts = vec![PayableAccount {
        //     wallet: make_wallet("booga"),
        //     balance_wei: 78_654_321,
        //     last_paid_timestamp: SystemTime::now()
        //         .checked_sub(Duration::from_secs(1000))
        //         .unwrap(),
        //     pending_payable_opt: None,
        // }];
        // let subject = BlockchainBridge::new(
        //     Box::new(blockchain_interface),
        //     Box::new(persistent_configuration),
        //     false,
        //     Some(consuming_wallet.clone()),
        // );
        // let addr = subject.start();
        // let subject_subs = BlockchainBridge::make_subs_from(&addr);
        // let peer_actors = peer_actors_builder().accountant(accountant).build();
        // send_bind_message!(subject_subs, peer_actors);
        //
        // addr.try_send(QualifiedPayablesMessage {
        //     protected_qualified_payables: protect_payables_in_test(qualified_accounts.clone()),
        //     response_skeleton_opt: Some(ResponseSkeleton {
        //         client_id: 11122,
        //         context_id: 444,
        //     }),
        // })
        // .unwrap();
        //
        // system.run();
        // let get_transaction_fee_balance_params =
        //     get_transaction_fee_balance_params_arc.lock().unwrap();
        // assert_eq!(
        //     *get_transaction_fee_balance_params,
        //     vec![consuming_wallet.clone()]
        // );
        // let get_token_balance_params = get_token_balance_params_arc.lock().unwrap();
        // assert_eq!(*get_token_balance_params, vec![consuming_wallet]);
        // let accountant_received_payment = accountant_recording_arc.lock().unwrap();
        // assert_eq!(accountant_received_payment.len(), 1);
        // let reported_balances_and_qualified_accounts: &ConsumingWalletBalancesAndQualifiedPayables =
        //     accountant_received_payment.get_record(0);
        // assert_eq!(
        //     reported_balances_and_qualified_accounts,
        //     &ConsumingWalletBalancesAndQualifiedPayables {
        //         qualified_payables: qualified_accounts,
        //         consuming_wallet_balances: wallet_balances_found,
        //         response_skeleton_opt: Some(ResponseSkeleton {
        //             client_id: 11122,
        //             context_id: 444
        //         })
        //     }
        // );
    }

    #[test]
    fn build_of_blockchain_agent_throws_err_out_and_ends_handling_qualified_payables_message() {
        init_test_logging();
        let test_name =
            "build_of_blockchain_agent_throws_err_out_and_ends_handling_qualified_payables_message";
        let (accountant, _, accountant_recording_arc) = make_recorder();
        let scan_error_recipient: Recipient<ScanError> = accountant
            .system_stop_conditions(match_every_type_id!(ScanError))
            .start()
            .recipient();
        let persistent_configuration = PersistentConfigurationMock::default();
        let consuming_wallet = make_wallet(test_name);
        let blockchain_interface = BlockchainInterfaceMock::default()
            .build_blockchain_agent_result(Err(BlockchainAgentBuildError::GasPrice(
                PersistentConfigError::NotPresent,
            )));
        let mut subject = BlockchainBridge::new(
            Box::new(blockchain_interface),
            Box::new(persistent_configuration),
            false,
            Some(consuming_wallet),
        );
        subject.logger = Logger::new(test_name);
        subject.scan_error_subs_opt = Some(scan_error_recipient);
        let request = QualifiedPayablesMessage {
            protected_qualified_payables: protect_payables_in_test(vec![PayableAccount {
                wallet: make_wallet("blah"),
                balance_wei: 42,
                last_paid_timestamp: SystemTime::now(),
                pending_payable_opt: None,
            }]),
            response_skeleton_opt: Some(ResponseSkeleton {
                client_id: 11,
                context_id: 2323,
            }),
        };
        let subject_addr = subject.start();
        let system = System::new(test_name);

        // Don't eliminate or bypass this message as an important check that
        // the Handler employs scan_handle()
        subject_addr.try_send(request).unwrap();

        system.run();
        let recording = accountant_recording_arc.lock().unwrap();
        let message = recording.get_record::<ScanError>(0);
        assert_eq!(recording.len(), 1);
        let expected_error_msg = "Blockchain agent construction failed at fetching gas \
        price from the database: NotPresent";
        assert_eq!(
            message,
            &ScanError {
                scan_type: ScanType::Payables,
                response_skeleton_opt: Some(ResponseSkeleton {
                    client_id: 11,
                    context_id: 2323
                }),
                msg: expected_error_msg.to_string()
            }
        );
        TestLogHandler::new()
            .exists_log_containing(&format!("WARN: {test_name}: {expected_error_msg}"));
    }

    fn assert_failure_during_balance_inspection(
        test_name: &str,
        blockchain_interface: BlockchainInterfaceMock,
        error_msg: &str,
    ) {
        init_test_logging();
        let (accountant, _, accountant_recording_arc) = make_recorder();
        let scan_error_recipient: Recipient<ScanError> = accountant
            .system_stop_conditions(match_every_type_id!(ScanError))
            .start()
            .recipient();
        let persistent_configuration = PersistentConfigurationMock::default();
        let consuming_wallet = make_wallet(test_name);
        let mut subject = BlockchainBridge::new(
            Box::new(blockchain_interface),
            Box::new(persistent_configuration),
            false,
            Some(consuming_wallet),
        );
        subject.logger = Logger::new(test_name);
        subject.scan_error_subs_opt = Some(scan_error_recipient);
        let request = QualifiedPayablesMessage {
            protected_qualified_payables: protect_payables_in_test(vec![PayableAccount {
                wallet: make_wallet("blah"),
                balance_wei: 42,
                last_paid_timestamp: SystemTime::now(),
                pending_payable_opt: None,
            }]),
            response_skeleton_opt: Some(ResponseSkeleton {
                client_id: 11,
                context_id: 2323,
            }),
        };
        let subject_addr = subject.start();
        let system = System::new(test_name);

        // Don't eliminate or bypass this message as an important check that
        // the Handler employs scan_handle()
        subject_addr.try_send(request).unwrap();

        system.run();
        let recording = accountant_recording_arc.lock().unwrap();
        let message = recording.get_record::<ScanError>(0);
        assert_eq!(recording.len(), 1);
        assert_eq!(
            message,
            &ScanError {
                scan_type: ScanType::Payables,
                response_skeleton_opt: Some(ResponseSkeleton {
                    client_id: 11,
                    context_id: 2323
                }),
                msg: error_msg.to_string()
            }
        );
        TestLogHandler::new().exists_log_containing(&format!("WARN: {}: {}", test_name, error_msg));
    }

    #[test]
    fn handle_request_balances_to_pay_payables_fails_at_missing_consuming_wallet() {
        let blockchain_interface = BlockchainInterfaceMock::default();
        let persistent_configuration = PersistentConfigurationMock::default();
        let mut subject = BlockchainBridge::new(
            Box::new(blockchain_interface),
            Box::new(persistent_configuration),
            false,
            None,
        );
        let request = QualifiedPayablesMessage {
            protected_qualified_payables: protect_payables_in_test(vec![PayableAccount {
                wallet: make_wallet("blah"),
                balance_wei: 4254,
                last_paid_timestamp: SystemTime::now(),
                pending_payable_opt: None,
            }]),
            response_skeleton_opt: None,
        };

        let result = subject.handle_qualified_payable_msg(request).wait();

        assert_eq!(
            result,
            Err(
                "Cannot inspect available balances for payables while consuming wallet is missing"
                    .to_string()
            )
        )
    }

    #[test]
    fn handle_outbound_payments_instructions_sees_payments_happen_and_sends_payment_results_back_to_accountant(
    ) {
        todo!("GH-744: Replace this test with a multi node test using ganache");
        // let system =
        //     System::new("handle_outbound_payments_instructions_sees_payments_happen_and_sends_payment_results_back_to_accountant");
        // let send_batch_of_payables_params_arc = Arc::new(Mutex::new(vec![]));
        // let (accountant, _, accountant_recording_arc) = make_recorder();
        // let accountant =
        //     accountant.system_stop_conditions(match_every_type_id!(PendingPayableFingerprintSeeds));
        // let wallet_account_1 = make_wallet("blah");
        // let wallet_account_2 = make_wallet("foo");
        // let blockchain_interface_id_stamp = ArbitraryIdStamp::new();
        // let blockchain_interface_mock = BlockchainInterfaceMock::default()
        //     .set_arbitrary_id_stamp(blockchain_interface_id_stamp)
        //     .send_batch_of_payables_params(&send_batch_of_payables_params_arc)
        //     .send_batch_of_payables_result(Ok(vec![
        //         Ok(PendingPayable {
        //             recipient_wallet: wallet_account_1.clone(),
        //             hash: H256::from("sometransactionhash".keccak256()),
        //         }),
        //         Ok(PendingPayable {
        //             recipient_wallet: wallet_account_2.clone(),
        //             hash: H256::from("someothertransactionhash".keccak256()),
        //         }),
        //     ]));
        // let consuming_wallet = make_paying_wallet(b"somewallet");
        // let subject = BlockchainBridge::new(
        //     Box::new(blockchain_interface_mock),
        //     Box::new(PersistentConfigurationMock::default()),
        //     false,
        //     Some(consuming_wallet.clone()),
        // );
        // let addr = subject.start();
        // let subject_subs = BlockchainBridge::make_subs_from(&addr);
        // let peer_actors = peer_actors_builder().accountant(accountant).build();
        // let accounts = vec![
        //     PayableAccount {
        //         wallet: wallet_account_1.clone(),
        //         balance_wei: 420,
        //         last_paid_timestamp: from_time_t(150_000_000),
        //         pending_payable_opt: None,
        //     },
        //     PayableAccount {
        //         wallet: wallet_account_2.clone(),
        //         balance_wei: 210,
        //         last_paid_timestamp: from_time_t(160_000_000),
        //         pending_payable_opt: None,
        //     },
        // ];
        // let agent_id_stamp = ArbitraryIdStamp::new();
        // let agent = BlockchainAgentMock::default().set_arbitrary_id_stamp(agent_id_stamp);
        // send_bind_message!(subject_subs, peer_actors);
        //
        // let _ = addr
        //     .try_send(OutboundPaymentsInstructions {
        //         affordable_accounts: accounts.clone(),
        //         agent: Box::new(agent),
        //         response_skeleton_opt: Some(ResponseSkeleton {
        //             client_id: 1234,
        //             context_id: 4321,
        //         }),
        //     })
        //     .unwrap();
        //
        // System::current().stop();
        // system.run();
        // let mut send_batch_of_payables_params = send_batch_of_payables_params_arc.lock().unwrap();
        // //cannot assert on the captured recipient as its actor is gone after the System stops spinning
        // let (actual_agent_id_stamp, _recipient_actual, accounts_actual) =
        //     send_batch_of_payables_params.remove(0);
        // assert!(send_batch_of_payables_params.is_empty());
        // assert_eq!(actual_agent_id_stamp, agent_id_stamp);
        // assert_eq!(accounts_actual, accounts);
        // let accountant_recording = accountant_recording_arc.lock().unwrap();
        // let sent_payments_msg = accountant_recording.get_record::<SentPayables>(0);
        // assert_eq!(
        //     *sent_payments_msg,
        //     SentPayables {
        //         payment_procedure_result: Ok(vec![
        //             Ok(PendingPayable {
        //                 recipient_wallet: wallet_account_1,
        //                 hash: H256::from("sometransactionhash".keccak256())
        //             }),
        //             Ok(PendingPayable {
        //                 recipient_wallet: wallet_account_2,
        //                 hash: H256::from("someothertransactionhash".keccak256())
        //             })
        //         ]),
        //         response_skeleton_opt: Some(ResponseSkeleton {
        //             client_id: 1234,
        //             context_id: 4321
        //         })
        //     }
        // );
        // assert_eq!(accountant_recording.len(), 1);
    }

    #[test]
    fn handle_outbound_payments_instructions_sends_eleventh_hour_error_back_to_accountant() {
        /// TODO: GH-744: We need to add a test sever that satisfies get transaction count.
        ///
        ///
        ///
        let system = System::new(
            "handle_outbound_payments_instructions_sends_eleventh_hour_error_back_to_accountant",
        );
        let port = find_free_port();
        let test_server = TestServer::start(
            port,
            vec![
                // br#"{"jsonrpc":"2.0","id":0,"result":"0xDEADBEEF"}"#.to_vec(),
                br#"{"jsonrpc":"2.0","id":1,"result":"0x20"}"#.to_vec(), // This is for getting Transaction count
                br#"{"jsonrpc":"2.0","id":0,"result":"0x000000000000000000000000000000000000000000000000000000000000FFFF"}"#.to_vec()
            ],
        );

        let (accountant, _, accountant_recording_arc) = make_recorder();
        let accountant_addr = accountant
            .system_stop_conditions(match_every_type_id!(SentPayables))
            .start();
        let wallet_account = make_wallet("blah");
        // let url = "https://www.example.com";
        // let (event_loop_handle, http) =
        //     Http::with_max_parallel(&url, REQUESTS_IN_PARALLEL).unwrap();
        let (event_loop_handle, http) = Http::with_max_parallel(
            &format!("http://{}:{}", &Ipv4Addr::LOCALHOST.to_string(), port),
            REQUESTS_IN_PARALLEL,
        )
        .unwrap();

        let blockchain_interface =
            BlockchainInterfaceWeb3::new(http, event_loop_handle, DEFAULT_CHAIN);

        // let blockchain_interface_mock = BlockchainInterfaceMock::default()
        //     .get_chain_result(DEFAULT_CHAIN)
        //     .get_batch_web3_result(Web3::new(Batch::new(http)));
        // .get_transaction_count_result(Ok(U256::from(1u64)));
        let persistent_configuration_mock =
            PersistentConfigurationMock::default().gas_price_result(Ok(123));
        // .send_batch_of_payables_result(expected_error.clone());
        // let persistent_configuration_mock = PersistentConfigurationMock::default();
        let consuming_wallet = make_paying_wallet(b"somewallet");
        let subject = BlockchainBridge::new(
            Box::new(blockchain_interface),
            Box::new(persistent_configuration_mock),
            false,
            Some(consuming_wallet),
        );
        let addr = subject.start();
        let subject_subs = BlockchainBridge::make_subs_from(&addr);
        let mut peer_actors = peer_actors_builder().build();
        peer_actors.accountant = make_accountant_subs_from_recorder(&accountant_addr);
        let accounts = vec![PayableAccount {
            wallet: wallet_account,
            balance_wei: 111_420_204,
            last_paid_timestamp: from_time_t(150_000_000),
            pending_payable_opt: None,
        }];
        let agent = BlockchainAgentMock::default();
        send_bind_message!(subject_subs, peer_actors);

        let _ = addr
            .try_send(OutboundPaymentsInstructions {
                affordable_accounts: accounts,
                // agent: Box::new(agent),
                response_skeleton_opt: Some(ResponseSkeleton {
                    client_id: 1234,
                    context_id: 4321,
                }),
            })
            .unwrap();

        system.run();
        let accountant_recording = accountant_recording_arc.lock().unwrap();
        // let sent_payments_msg = accountant_recording.get_record::<SentPayables>(1);
        let sent_payments_msg = accountant_recording.get_record::<SentPayables>(1);
        let scan_error_msg = accountant_recording.get_record::<ScanError>(2);
        assert_sending_error(
            sent_payments_msg
                .payment_procedure_result
                .as_ref()
                .unwrap_err(),
            "Got invalid response",
        );
        // let scan_error_msg = accountant_recording.get_record::<ScanError>(2);
        assert_eq!(
            *scan_error_msg,
            ScanError {
                scan_type: ScanType::Payables,
                response_skeleton_opt: Some(ResponseSkeleton {
                    client_id: 1234,
                    context_id: 4321
                }),
                msg: format!(
                    "ReportAccountsPayable: Sending phase: \"Got invalid response: Error(\"expected value\", line: 1, column: 1)\". Signed and hashed transactions: 0x1ceb46eee9890827f5fe9fef0243408f965a587688b81bb05a022b599ee96c6b"
                )
            }
        );
        assert_eq!(accountant_recording.len(), 3)
    }

    #[test]
    fn report_accounts_payable_returns_error_fetching_pending_nonce() {
        todo!("GH-744:  we are using a differnt message than ReportAccountsPayable");
        // let url = "https://www.example.com";
        // let (_event_loop_handle, http) =
        //     Http::with_max_parallel(&url, REQUESTS_IN_PARALLEL).unwrap();
        // let blockchain_interface_mock = BlockchainInterfaceMock::default()
        //     .get_chain_result(DEFAULT_CHAIN)
        //     .get_batch_web3_result(Web3::new(Batch::new(http)))
        //     .get_transaction_count_result(Err(BlockchainError::QueryFailed(
        //         "What the hack...??".to_string(),
        //     )));
        // let consuming_wallet = make_wallet("somewallet");
        // let persistent_configuration_mock =
        //     PersistentConfigurationMock::new().gas_price_result(Ok(3u64));
        // let (accountant, _, _) = make_recorder();
        // let accountant_addr = accountant.start();
        // let received_payments_subs: Recipient<ReceivedPayments> =
        //     accountant_addr.clone().recipient();
        // let fingerprint_recipient = accountant_addr.recipient();
        // let mut subject = BlockchainBridge::new(
        //     Box::new(blockchain_interface_mock),
        //     Box::new(persistent_configuration_mock),
        //     false,
        //     Some(consuming_wallet),
        // );
        // subject.received_payments_subs_opt = Some(received_payments_subs);
        // subject
        //     .pending_payable_confirmation
        //     .new_pp_fingerprints_sub_opt = Some(fingerprint_recipient);
        // let request = ReportAccountsPayable {
        //     accounts: vec![PayableAccount {
        //         wallet: make_wallet("blah"),
        //         balance_wei: 123_456,
        //         last_paid_timestamp: SystemTime::now(),
        //         pending_payable_opt: None,
        //     }],
        //     response_skeleton_opt: None,
        // };
        //
        // let result = subject.process_payments(&request).wait();
        //
        // assert_eq!(
        //     result,
        //     Err(PayableTransactionError::TransactionCount(
        //         BlockchainError::QueryFailed("What the hack...??".to_string())
        //     ))
        // );
    }

    #[test]
    fn process_payments_returns_error_from_sending_batch() {
        // todo!("GH-744: process_payments test needs refactoring");

        let port = find_free_port();
        let test_server = TestServer::start(
            port,
            vec![
                // br#"{"jsonrpc":"2.0","id":0,"result":"0xDEADBEEF"}"#.to_vec(),
                br#"{"jsonrpc":"2.0","id":1,"result":"0x20"}"#.to_vec(), // This is for getting Transaction count
                br#"[{"jsonrpc":"2.0","id":0,"result":"0x000000000000000000000000000000000000000000000000000000000000FFFF"}]"#.to_vec(),
            ],
        );

        let transaction_hash = make_tx_hash(789);
        // let url = "https://www.example.com";
        // let (_event_loop_handle, http) =
        //     Http::with_max_parallel(&url, REQUESTS_IN_PARALLEL).unwrap();

        let (event_loop_handle, http) = Http::with_max_parallel(
            &format!("http://{}:{}", &Ipv4Addr::LOCALHOST.to_string(), port),
            REQUESTS_IN_PARALLEL,
        )
        .unwrap();
        let blockchain_interface =
            BlockchainInterfaceWeb3::new(http, event_loop_handle, DEFAULT_CHAIN);

        // let blockchain_interface_mock = BlockchainInterfaceMock::default()
        // .send_batch_of_payables_result(Err(PayableTransactionError::Sending {
        //     msg: "failure from chronic exhaustion".to_string(),
        //     hashes: vec![transaction_hash],
        // }));
        // let consuming_wallet = make_wallet("somewallet");
        // let persistent_configuration_mock = PersistentConfigurationMock::new();
        // .get_transaction_count_result(Ok(web3::types::U256::from(1)))
        // .get_chain_result(DEFAULT_CHAIN)
        // .get_batch_web3_result(Web3::new(Batch::new(http)));
        let consuming_wallet = make_paying_wallet(format!("consuming").as_bytes());
        let persistent_configuration_mock =
            PersistentConfigurationMock::new().gas_price_result(Ok(3u64));
        let mut subject = BlockchainBridge::new(
            Box::new(blockchain_interface),
            Box::new(persistent_configuration_mock),
            false,
            Some(consuming_wallet.clone()),
        );
        let checked_accounts = vec![PayableAccount {
            wallet: make_wallet("blah"),
            balance_wei: 424_454,
            last_paid_timestamp: SystemTime::now(),
            pending_payable_opt: None,
        }];
        let agent = Box::new(BlockchainAgentMock::default());
        let (accountant, _, _) = make_recorder();
        let fingerprint_recipient = accountant.start().recipient();
        subject
            .pending_payable_confirmation
            .new_pp_fingerprints_sub_opt = Some(fingerprint_recipient);

        let outbound_payments_instructions = OutboundPaymentsInstructions {
            affordable_accounts: checked_accounts,
            response_skeleton_opt: None,
        };

        let result = subject
            .process_payments(outbound_payments_instructions)
            .wait();

        // TODO: GH-744: Fix this assert
        assert_eq!(
            result,
            Err(PayableTransactionError::Sending {
                msg: "failure from chronic exhaustion".to_string(),
                hashes: vec![transaction_hash]
            })
        );

        assert_sending_error(result.as_ref().unwrap_err(), "Got invalid response");
    }

    fn assert_sending_error(error: &PayableTransactionError, error_msg: &str) {
        if let PayableTransactionError::Sending { msg, .. } = error {
            assert!(
                msg.contains(error_msg),
                "Actual Error message: {} does not contain this fragment {}",
                msg,
                error_msg
            );
        } else {
            panic!("Received wrong error: {:?}", error);
        }
    }

    #[test]
    fn blockchain_bridge_processes_requests_for_transaction_receipts_when_all_were_ok() {
        let get_transaction_receipt_params_arc = Arc::new(Mutex::new(vec![]));
        let (accountant, _, accountant_recording_arc) = make_recorder();
        let pending_payable_fingerprint_1 = make_pending_payable_fingerprint();
        let hash_1 = pending_payable_fingerprint_1.hash;
        let hash_2 = make_tx_hash(78989);
        let pending_payable_fingerprint_2 = PendingPayableFingerprint {
            rowid: 456,
            timestamp: SystemTime::now(),
            hash: hash_2,
            attempt: 3,
            amount: 4565,
            process_error: None,
        };
        let blockchain_interface_mock = BlockchainInterfaceMock::default()
            .get_transaction_receipt_params(&get_transaction_receipt_params_arc)
            .get_transaction_receipt_result(Ok(Some(TransactionReceipt::default())))
            .get_transaction_receipt_result(Ok(None));
        let subject = BlockchainBridge::new(
            Box::new(blockchain_interface_mock),
            Box::new(PersistentConfigurationMock::default()),
            false,
            None,
        );
        let addr = subject.start();
        let subject_subs = BlockchainBridge::make_subs_from(&addr);
        let peer_actors = peer_actors_builder().accountant(accountant).build();
        send_bind_message!(subject_subs, peer_actors);
        let msg = RequestTransactionReceipts {
            pending_payable: vec![
                pending_payable_fingerprint_1.clone(),
                pending_payable_fingerprint_2.clone(),
            ],
            response_skeleton_opt: Some(ResponseSkeleton {
                client_id: 1234,
                context_id: 4321,
            }),
        };

        let _ = addr.try_send(msg).unwrap();

        let system = System::new("transaction receipts");
        System::current().stop();
        system.run();
        let accountant_recording = accountant_recording_arc.lock().unwrap();
        assert_eq!(accountant_recording.len(), 1);
        let received_message = accountant_recording.get_record::<ReportTransactionReceipts>(0);
        assert_eq!(
            received_message,
            &ReportTransactionReceipts {
                fingerprints_with_receipts: vec![
                    (
                        Some(TransactionReceipt::default()),
                        pending_payable_fingerprint_1
                    ),
                    (None, pending_payable_fingerprint_2),
                ],
                response_skeleton_opt: Some(ResponseSkeleton {
                    client_id: 1234,
                    context_id: 4321
                }),
            }
        );
        let get_transaction_receipt_params = get_transaction_receipt_params_arc.lock().unwrap();
        assert_eq!(*get_transaction_receipt_params, vec![hash_1, hash_2])
    }

    #[test]
    fn blockchain_bridge_logs_error_from_retrieving_received_payments() {
        init_test_logging();
        let (accountant, _, accountant_recording_arc) = make_recorder();
        let (blockchain_bridge, _, _) = make_recorder();
        let accountant_addr = accountant
            .system_stop_conditions(match_every_type_id!(ScanError))
            .start();
        let scan_error_recipient: Recipient<ScanError> = accountant_addr.clone().recipient();
        let received_payments_subs: Recipient<ReceivedPayments> = accountant_addr.recipient();
        let update_start_block_subs: Recipient<UpdateStartBlockMessage> =
            blockchain_bridge.start().recipient();
        let blockchain_interface = BlockchainInterfaceMock::default().retrieve_transactions_result(
            Err(BlockchainError::QueryFailed("we have no luck".to_string())),
        );
        let persistent_config = PersistentConfigurationMock::new().start_block_result(Ok(5));
        let lower_interface = LowBlockchainIntMock::default()
            .get_block_number_result(LatestBlockNumber::Ok(U64::from(1234u64)));
        let blockchain_interface = BlockchainInterfaceMock::default()
            .retrieve_transactions_result(Err(BlockchainError::QueryFailed(
                "we have no luck".to_string(),
            )))
            .lower_interface_results(Box::new(lower_interface));
        let persistent_config = PersistentConfigurationMock::new()
            .max_block_count_result(Ok(Some(100_000)))
            .start_block_result(Ok(5)); // no set_start_block_result: set_start_block() must not be called
        let mut subject = BlockchainBridge::new(
            Box::new(blockchain_interface),
            Box::new(persistent_config),
            false,
            None,
        );
        subject.scan_error_subs_opt = Some(scan_error_recipient);
        subject.received_payments_subs_opt = Some(received_payments_subs);
        subject.update_start_block_subs_opt = Some(update_start_block_subs);
        let msg = RetrieveTransactions {
            recipient: make_wallet("blah"),
            response_skeleton_opt: None,
        };
        let subject_addr = subject.start();
        let system = System::new("test");

        subject_addr.try_send(msg).unwrap();

        system.run();
        let recording = accountant_recording_arc.lock().unwrap();
        let message = recording.get_record::<ReceivedPayments>(0);
        assert_eq!(
            message.scan_result,
            Err(ReceivedPaymentsError::OtherRPCError("Attempted to retrieve received payments but failed: QueryFailed(\"we have no luck\")".to_string()))
        );
        let message_2 = recording.get_record::<ScanError>(1);
        assert_eq!(
          message_2,
          &ScanError {
              scan_type: ScanType::Receivables,
              response_skeleton_opt: None,
              msg: "Error while retrieving transactions: OtherRPCError(\"Attempted to retrieve received payments but failed: QueryFailed(\\\"we have no luck\\\")\")".to_string()
          }
        );
        assert_eq!(recording.len(), 2);
        TestLogHandler::new().exists_log_containing(
            "WARN: BlockchainBridge: Error while retrieving transactions: OtherRPCError(\"Attempted to retrieve received payments but failed: QueryFailed(\\\"we have no luck\\\")\")",
        );
    }

    #[test]
    fn handle_request_transaction_receipts_short_circuits_on_failure_from_remote_process_sends_back_all_good_results_and_logs_abort(
    ) {
        init_test_logging();
        let get_transaction_receipt_params_arc = Arc::new(Mutex::new(vec![]));
        let (accountant, _, accountant_recording_arc) = make_recorder();
        let accountant_addr = accountant
            .system_stop_conditions(match_every_type_id!(ReportTransactionReceipts, ScanError))
            .start();
        let report_transaction_receipt_recipient: Recipient<ReportTransactionReceipts> =
            accountant_addr.clone().recipient();
        let scan_error_recipient: Recipient<ScanError> = accountant_addr.recipient();
        let hash_1 = make_tx_hash(111334);
        let hash_2 = make_tx_hash(100000);
        let hash_3 = make_tx_hash(0x1348d);
        let hash_4 = make_tx_hash(11111);
        let mut fingerprint_1 = make_pending_payable_fingerprint();
        fingerprint_1.hash = hash_1;
        let fingerprint_2 = PendingPayableFingerprint {
            rowid: 454,
            timestamp: SystemTime::now(),
            hash: hash_2,
            attempt: 3,
            amount: 3333,
            process_error: None,
        };
        let fingerprint_3 = PendingPayableFingerprint {
            rowid: 456,
            timestamp: SystemTime::now(),
            hash: hash_3,
            attempt: 3,
            amount: 4565,
            process_error: None,
        };
        let fingerprint_4 = PendingPayableFingerprint {
            rowid: 450,
            timestamp: from_time_t(230_000_000),
            hash: hash_4,
            attempt: 1,
            amount: 7879,
            process_error: None,
        };
        let mut transaction_receipt = TransactionReceipt::default();
        transaction_receipt.block_number = Some(U64::from(4545454));
        transaction_receipt.contract_address = Some(H160::from_low_u64_be(887766));
        let blockchain_interface_mock = BlockchainInterfaceMock::default()
            .get_transaction_receipt_params(&get_transaction_receipt_params_arc)
            .get_transaction_receipt_result(Ok(None))
            .get_transaction_receipt_result(Ok(Some(transaction_receipt.clone())))
            .get_transaction_receipt_result(Err(BlockchainError::QueryFailed(
                "bad bad bad".to_string(),
            )));
        let system = System::new("test_transaction_receipts");
        let mut subject = BlockchainBridge::new(
            Box::new(blockchain_interface_mock),
            Box::new(PersistentConfigurationMock::default()),
            false,
            None,
        );
        subject
            .pending_payable_confirmation
            .report_transaction_receipts_sub_opt = Some(report_transaction_receipt_recipient);
        subject.scan_error_subs_opt = Some(scan_error_recipient);
        let msg = RequestTransactionReceipts {
            pending_payable: vec![
                fingerprint_1.clone(),
                fingerprint_2.clone(),
                fingerprint_3,
                fingerprint_4,
            ],
            response_skeleton_opt: Some(ResponseSkeleton {
                client_id: 1234,
                context_id: 4321,
            }),
        };
        let subject_addr = subject.start();

        subject_addr.try_send(msg).unwrap();

        assert_eq!(system.run(), 0);
        let get_transaction_receipts_params = get_transaction_receipt_params_arc.lock().unwrap();
        assert_eq!(
            *get_transaction_receipts_params,
            vec![hash_1, hash_2, hash_3]
        );
        let accountant_recording = accountant_recording_arc.lock().unwrap();
        assert_eq!(accountant_recording.len(), 2);
        let report_receipts_msg = accountant_recording.get_record::<ReportTransactionReceipts>(0);
        assert_eq!(
            *report_receipts_msg,
            ReportTransactionReceipts {
                fingerprints_with_receipts: vec![
                    (None, fingerprint_1),
                    (Some(transaction_receipt), fingerprint_2)
                ],
                response_skeleton_opt: Some(ResponseSkeleton {
                    client_id: 1234,
                    context_id: 4321
                }),
            }
        );
        let scan_error_msg = accountant_recording.get_record::<ScanError>(1);
        assert_eq!(*scan_error_msg, ScanError {
            scan_type: ScanType::PendingPayables,
            response_skeleton_opt: Some(ResponseSkeleton { client_id: 1234, context_id: 4321 }),
            msg: "Aborting scanning; request of a transaction receipt \
         for '0x000000000000000000000000000000000000000000000000000000000001348d' failed due to 'QueryFailed(\"bad bad bad\")'".to_string()
        });
        TestLogHandler::new().exists_log_containing("WARN: BlockchainBridge: Aborting scanning; request of a transaction receipt \
         for '0x000000000000000000000000000000000000000000000000000000000001348d' failed due to 'QueryFailed(\"bad bad bad\")'");
    }

    #[test]
    fn blockchain_bridge_can_return_report_transaction_receipts_with_an_empty_vector() {
        let (accountant, _, accountant_recording) = make_recorder();
        let recipient = accountant.start().recipient();
        let mut subject = BlockchainBridge::new(
            Box::new(BlockchainInterfaceMock::default()),
            Box::new(PersistentConfigurationMock::default()),
            false,
            Some(Wallet::new("mine")),
        );
        subject
            .pending_payable_confirmation
            .report_transaction_receipts_sub_opt = Some(recipient);
        let msg = RequestTransactionReceipts {
            pending_payable: vec![],
            response_skeleton_opt: None,
        };
        let system = System::new(
            "blockchain_bridge_can_return_report_transaction_receipts_with_an_empty_vector",
        );

        let _ = subject.handle_request_transaction_receipts(msg);

        System::current().stop();
        system.run();
        let recording = accountant_recording.lock().unwrap();
        assert_eq!(
            recording.get_record::<ReportTransactionReceipts>(0),
            &ReportTransactionReceipts {
                fingerprints_with_receipts: vec![],
                response_skeleton_opt: None
            }
        )
    }

    #[test]
    fn handle_request_transaction_receipts_short_circuits_on_failure_of_the_first_payment_and_it_sends_a_message_with_empty_vector_and_logs(
    ) {
        init_test_logging();
        let (accountant, _, accountant_recording) = make_recorder();
        let accountant_addr = accountant.start();
        let scan_error_recipient: Recipient<ScanError> = accountant_addr.clone().recipient();
        let report_transaction_recipient: Recipient<ReportTransactionReceipts> =
            accountant_addr.recipient();
        let get_transaction_receipt_params_arc = Arc::new(Mutex::new(vec![]));
        let hash_1 = make_tx_hash(0x1b2e6);
        let fingerprint_1 = PendingPayableFingerprint {
            rowid: 454,
            timestamp: SystemTime::now(),
            hash: hash_1,
            attempt: 3,
            amount: 3333,
            process_error: None,
        };
        let fingerprint_2 = PendingPayableFingerprint {
            rowid: 456,
            timestamp: SystemTime::now(),
            hash: make_tx_hash(222444),
            attempt: 3,
            amount: 4565,
            process_error: None,
        };
        let blockchain_interface_mock = BlockchainInterfaceMock::default()
            .get_transaction_receipt_params(&get_transaction_receipt_params_arc)
            .get_transaction_receipt_result(Err(BlockchainError::QueryFailed("booga".to_string())));
        let mut subject = BlockchainBridge::new(
            Box::new(blockchain_interface_mock),
            Box::new(PersistentConfigurationMock::default()),
            false,
            None,
        );
        subject
            .pending_payable_confirmation
            //due to this None we would've panicked if we tried to send a msg
            .report_transaction_receipts_sub_opt = Some(report_transaction_recipient);
        subject.scan_error_subs_opt = Some(scan_error_recipient);
        let msg = RequestTransactionReceipts {
            pending_payable: vec![fingerprint_1, fingerprint_2],
            response_skeleton_opt: None,
        };
        let system = System::new("test");

        let _ = subject.handle_scan(
            BlockchainBridge::handle_request_transaction_receipts,
            ScanType::PendingPayables,
            msg,
        );

        System::current().stop();
        system.run();
        let get_transaction_receipts_params = get_transaction_receipt_params_arc.lock().unwrap();
        let recording = accountant_recording.lock().unwrap();
        assert_eq!(*get_transaction_receipts_params, vec![hash_1]);
        assert_eq!(
            recording.get_record::<ReportTransactionReceipts>(0),
            &ReportTransactionReceipts {
                fingerprints_with_receipts: vec![],
                response_skeleton_opt: None
            }
        );
        assert_eq!(
            recording.get_record::<ScanError>(1),
            &ScanError {
                scan_type: ScanType::PendingPayables,
                response_skeleton_opt: None,
                msg: "Aborting scanning; request of a transaction receipt for '0x000000000000000000000000000000000000000000000000000000000001b2e6' failed due to 'QueryFailed(\"booga\")'".to_string()
            }
        );
        assert_eq!(recording.len(), 2);
        TestLogHandler::new().exists_log_containing("WARN: BlockchainBridge: Aborting scanning; request of a transaction \
         receipt for '0x000000000000000000000000000000000000000000000000000000000001b2e6' failed due to 'QueryFailed(\"booga\")'");
    }

    #[test]
    fn handle_retrieve_transactions_uses_latest_block_number_upon_get_block_number_error() {
        init_test_logging();
        let retrieve_transactions_params_arc = Arc::new(Mutex::new(vec![]));
        let system = System::new(
            "handle_retrieve_transactions_uses_latest_block_number_upon_get_block_number_error",
        );
        let (accountant, _, accountant_recording_arc) = make_recorder();
        let earning_wallet = make_wallet("somewallet");
        let amount = 42;
        let amount2 = 55;
        let expected_transactions = RetrievedBlockchainTransactions {
            new_start_block: 8675309u64,
            transactions: vec![
                BlockchainTransaction {
                    block_number: 7,
                    from: earning_wallet.clone(),
                    wei_amount: amount,
                },
                BlockchainTransaction {
                    block_number: 9,
                    from: earning_wallet.clone(),
                    wei_amount: amount2,
                },
            ],
        };
        let lower_interface =
            LowBlockchainIntMock::default().get_block_number_result(LatestBlockNumber::Err(
                BlockchainError::QueryFailed("Failed to read the latest block number".to_string()),
            ));
        let blockchain_interface_mock = BlockchainInterfaceMock::default()
            .retrieve_transactions_params(&retrieve_transactions_params_arc)
            .retrieve_transactions_result(Ok(expected_transactions.clone()))
            .lower_interface_results(Box::new(lower_interface));
        let persistent_config = PersistentConfigurationMock::new()
            .max_block_count_result(Ok(Some(10000u64)))
            .start_block_result(Ok(6));
        let mut subject = BlockchainBridge::new(
            Box::new(blockchain_interface_mock),
            Box::new(persistent_config),
            false,
            Some(make_wallet("consuming")),
        );
        subject.received_payments_subs_opt = Some(accountant.start().recipient());
        let retrieve_transactions = RetrieveTransactions {
            recipient: earning_wallet.clone(),
            response_skeleton_opt: Some(ResponseSkeleton {
                client_id: 1234,
                context_id: 4321,
            }),
        };
        let before = SystemTime::now();

        subject
            .handle_retrieve_transactions(retrieve_transactions)
            .wait()
            .unwrap();

        System::current().stop();
        system.run();
        let after = SystemTime::now();
        let retrieve_transactions_params = retrieve_transactions_params_arc.lock().unwrap();
        assert_eq!(
            *retrieve_transactions_params,
            vec![(
                BlockNumber::Number(6u64.into()),
                BlockNumber::Number(10006u64.into()),
                earning_wallet
            )]
        );
        let accountant_received_payment = accountant_recording_arc.lock().unwrap();
        assert_eq!(accountant_received_payment.len(), 1);
        let received_payments = accountant_received_payment.get_record::<ReceivedPayments>(0);
        check_timestamp(before, received_payments.timestamp, after);
        let mut scan_result = make_empty_payments_and_start_block();
        scan_result.payments = expected_transactions.transactions;
        scan_result.new_start_block = 8675309u64;
        assert_eq!(
            received_payments,
            &ReceivedPayments {
                timestamp: received_payments.timestamp,
                scan_result: Ok(scan_result),
                response_skeleton_opt: Some(ResponseSkeleton {
                    client_id: 1234,
                    context_id: 4321
                }),
            }
        );
        TestLogHandler::new().exists_log_containing("INFO: BlockchainBridge: Using 'latest' block number instead of a literal number. QueryFailed(\"Failed to read the latest block number\")");
    }

    #[test]
    fn handle_retrieve_transactions_sends_received_payments_back_to_accountant() {
        let retrieve_transactions_params_arc = Arc::new(Mutex::new(vec![]));
        let system =
            System::new("handle_retrieve_transactions_sends_received_payments_back_to_accountant");
        let (accountant, _, accountant_recording_arc) = make_recorder();
        let (blockchain_bridge, _, blockchain_bridge_recording_arc) = make_recorder();
        let accountant_addr = accountant
            .system_stop_conditions(match_every_type_id!(ReceivedPayments))
            .start();
        let earning_wallet = make_wallet("somewallet");
        let amount = 42;
        let amount2 = 55;
        let expected_transactions = RetrievedBlockchainTransactions {
            new_start_block: 9876,
            transactions: vec![
                BlockchainTransaction {
                    block_number: 7,
                    from: earning_wallet.clone(),
                    wei_amount: amount,
                },
                BlockchainTransaction {
                    block_number: 9,
                    from: earning_wallet.clone(),
                    wei_amount: amount2,
                },
            ],
        };
        let latest_block_number = LatestBlockNumber::Ok(1024u64.into());
        let lower_interface =
            LowBlockchainIntMock::default().get_block_number_result(latest_block_number);
        let blockchain_interface_mock = BlockchainInterfaceMock::default()
            .retrieve_transactions_params(&retrieve_transactions_params_arc)
            .retrieve_transactions_result(Ok(expected_transactions.clone()))
            .lower_interface_results(Box::new(lower_interface));
        let persistent_config = PersistentConfigurationMock::new().start_block_result(Ok(6));
        // let persistent_config = PersistentConfigurationMock::new().max_block_count_result(Ok(Some(10000u64))).start_block_result(Ok(6));
        let subject = BlockchainBridge::new(
            Box::new(blockchain_interface_mock),
            Box::new(persistent_config),
            false,
            Some(make_wallet("consuming")),
        );
        let addr = subject.start();
        let subject_subs = BlockchainBridge::make_subs_from(&addr);
        let mut peer_actors = peer_actors_builder()
            .blockchain_bridge(blockchain_bridge)
            .build();
        peer_actors.accountant = make_accountant_subs_from_recorder(&accountant_addr);
        send_bind_message!(subject_subs, peer_actors);
        let retrieve_transactions = RetrieveTransactions {
            recipient: earning_wallet.clone(),
            response_skeleton_opt: Some(ResponseSkeleton {
                client_id: 1234,
                context_id: 4321,
            }),
        };
        let before = SystemTime::now();

        let _ = addr.try_send(retrieve_transactions).unwrap();

        system.run();
        let after = SystemTime::now();
        let retrieve_transactions_params = retrieve_transactions_params_arc.lock().unwrap();

        assert_eq!(
            *retrieve_transactions_params,
            vec![(
                BlockNumber::Number(6u64.into()),
                BlockNumber::Number(1024u64.into()),
                earning_wallet
            )]
        );
        let accountant_received_payment = accountant_recording_arc.lock().unwrap();
        assert_eq!(accountant_received_payment.len(), 1);
        let blockchain_bridge_recording = blockchain_bridge_recording_arc.lock().unwrap();
        assert_eq!(blockchain_bridge_recording.len(), 1);
        let update_start_block_message =
            blockchain_bridge_recording.get_record::<UpdateStartBlockMessage>(0);
        assert_eq!(
            update_start_block_message,
            &UpdateStartBlockMessage { start_block: 1234 }
        );
        let accountant_recording = accountant_recording_arc.lock().unwrap();
        assert_eq!(accountant_recording.len(), 1);
        let received_payments_message = accountant_recording.get_record::<ReceivedPayments>(0);
        check_timestamp(before, received_payments_message.timestamp, after);
        assert_eq!(
            received_payments_message,
            &ReceivedPayments {
                timestamp: received_payments_message.timestamp,
                scan_result: Ok(PaymentsAndStartBlock {
                    payments: expected_transactions.transactions,
                    new_start_block: 9876,
                }),
                response_skeleton_opt: Some(ResponseSkeleton {
                    client_id: 1234,
                    context_id: 4321
                }),
            }
        );
    }

    #[test]
    fn processing_of_received_payments_continues_even_if_no_payments_are_detected() {
        todo!("GH-744 - Failing due to futures");
        // init_test_logging();
        // let lower_interface =
        //     LowBlockchainIntMock::default().get_block_number_result(Ok(0u64.into()));
        // let blockchain_interface_mock = BlockchainInterfaceMock::default()
        //     .retrieve_transactions_result(Ok(RetrievedBlockchainTransactions {
        //         new_start_block: 7,
        //         transactions: vec![],
        //     }))
        //     .lower_interface_results(Box::new(lower_interface));
        // let persistent_config = PersistentConfigurationMock::new()
        //     .max_block_count_result(Ok(Some(10000u64)))
        //     .start_block_result(Ok(6));
        // let (accountant, _, accountant_recording_arc) = make_recorder();
        // let system = System::new(
        //     "processing_of_received_payments_continues_even_if_no_payments_are_detected",
        // );
        // let subject = BlockchainBridge::new(
        //     Box::new(blockchain_interface_mock),
        //     Box::new(persistent_config),
        //     false,
        //     None, //not needed in this test
        // );
        // let addr = subject.start();
        // let subject_subs = BlockchainBridge::make_subs_from(&addr);
        // let peer_actors = peer_actors_builder().accountant(accountant).build();
        // send_bind_message!(subject_subs, peer_actors);
        // let retrieve_transactions = RetrieveTransactions {
        //     recipient: make_wallet("somewallet"),
        //     response_skeleton_opt: Some(ResponseSkeleton {
        //         client_id: 1234,
        //         context_id: 4321,
        //     }),
        // };
        // let before = SystemTime::now();
        //
        // let _ = addr.try_send(retrieve_transactions).unwrap();
        //
        // System::current().stop();
        // system.run();
        // let after = SystemTime::now();
        // let accountant_received_payment = accountant_recording_arc.lock().unwrap();
        // let received_payments = accountant_received_payment.get_record::<ReceivedPayments>(0);
        // check_timestamp(before, received_payments.timestamp, after);
        // assert_eq!(
        //     received_payments,
        //     &ReceivedPayments {
        //         timestamp: received_payments.timestamp,
        //         payments: vec![],
        //         new_start_block: 7,
        //         response_skeleton_opt: Some(ResponseSkeleton {
        //             client_id: 1234,
        //             context_id: 4321
        //         }),
        //     }
        // );
        // TestLogHandler::new()
        //     .exists_log_containing("DEBUG: BlockchainBridge: No new receivable detected");
    }

    #[test]
    #[should_panic(
        expected = "Cannot retrieve start block from database; payments to you may not be processed: TransactionError"
    )]
    fn handle_retrieve_transactions_panics_if_start_block_cannot_be_read() {
        let lower_interface =
            LowBlockchainIntMock::default().get_block_number_result(Ok(0u64.into()));
        let blockchain_interface =
            BlockchainInterfaceMock::default().lower_interface_results(Box::new(lower_interface));
        let persistent_config = PersistentConfigurationMock::new()
            .start_block_result(Err(PersistentConfigError::TransactionError));
        let mut subject = BlockchainBridge::new(
            Box::new(BlockchainInterfaceMock::default()),
            Box::new(persistent_config),
            false,
            None, //not needed in this test
        );
        let retrieve_transactions = RetrieveTransactions {
            recipient: make_wallet("somewallet"),
            response_skeleton_opt: None,
        };

        let _ = subject.handle_retrieve_transactions(retrieve_transactions);
    }

    #[test]
    #[should_panic(
        expected = "Cannot set start block in database; payments to you may not be processed: TransactionError"
    )]
    fn handle_retrieve_transactions_panics_if_start_block_cannot_be_written() {
        let system =
            System::new("handle_retrieve_transactions_panics_if_start_block_cannot_be_written");
        let persistent_config = PersistentConfigurationMock::new()
            .set_start_block_result(Err(PersistentConfigError::TransactionError));
        let blockchain_interface = BlockchainInterfaceMock::default();
        let subject = BlockchainBridge::new(
            Box::new(blockchain_interface),
            Box::new(persistent_config),
            false,
            None, //not needed in this test
        );
        let addr = subject.start();

        let _ = addr
            .try_send(UpdateStartBlockMessage { start_block: 1234 })
            .unwrap();

        System::current().stop();
        system.run();
    }

    fn success_handler(
        _bcb: &mut BlockchainBridge,
        _msg: RetrieveTransactions,
    ) -> Result<(), String> {
        Ok(())
    }

    fn failure_handler(
        _bcb: &mut BlockchainBridge,
        _msg: RetrieveTransactions,
    ) -> Result<(), String> {
        Err("My tummy hurts".to_string())
    }

    #[test]
    fn handle_scan_handles_success() {
        let (accountant, _, accountant_recording_arc) = make_recorder();
        let mut subject = BlockchainBridge::new(
            Box::new(BlockchainInterfaceMock::default()),
            Box::new(PersistentConfigurationMock::new()),
            false,
            None, //not needed in this test
        );
        let system = System::new("test");
        subject.scan_error_subs_opt = Some(accountant.start().recipient());
        let retrieve_transactions = RetrieveTransactions {
            recipient: make_wallet("somewallet"),
            response_skeleton_opt: Some(ResponseSkeleton {
                client_id: 1234,
                context_id: 4321,
            }),
        };

        subject.handle_scan(
            success_handler,
            ScanType::Receivables,
            retrieve_transactions,
        );

        System::current().stop();
        system.run();
        let accountant_recording = accountant_recording_arc.lock().unwrap();
        assert_eq!(accountant_recording.len(), 0);
    }

    #[test]
    fn handle_scan_handles_failure_without_skeleton() {
        init_test_logging();
        let (accountant, _, accountant_recording_arc) = make_recorder();
        let mut subject = BlockchainBridge::new(
            Box::new(BlockchainInterfaceMock::default()),
            Box::new(PersistentConfigurationMock::new()),
            false,
            None, //not needed in this test
        );
        let system = System::new("test");
        subject.scan_error_subs_opt = Some(accountant.start().recipient());
        let retrieve_transactions = RetrieveTransactions {
            recipient: make_wallet("somewallet"),
            response_skeleton_opt: None,
        };

        subject.handle_scan(
            failure_handler,
            ScanType::Receivables,
            retrieve_transactions,
        );

        System::current().stop();
        system.run();
        let accountant_recording = accountant_recording_arc.lock().unwrap();
        let message = accountant_recording.get_record::<ScanError>(0);
        assert_eq!(
            message,
            &ScanError {
                scan_type: ScanType::Receivables,
                response_skeleton_opt: None,
                msg: "My tummy hurts".to_string()
            }
        );
        assert_eq!(accountant_recording.len(), 1);
        TestLogHandler::new().exists_log_containing("WARN: BlockchainBridge: My tummy hurts");
    }

    #[test]
    fn handle_scan_handles_failure_with_skeleton() {
        init_test_logging();
        let (accountant, _, accountant_recording_arc) = make_recorder();
        let mut subject = BlockchainBridge::new(
            Box::new(BlockchainInterfaceMock::default()),
            Box::new(PersistentConfigurationMock::new()),
            false,
            None, //not needed in this test
        );
        let system = System::new("test");
        subject.scan_error_subs_opt = Some(accountant.start().recipient());
        let retrieve_transactions = RetrieveTransactions {
            recipient: make_wallet("somewallet"),
            response_skeleton_opt: Some(ResponseSkeleton {
                client_id: 1234,
                context_id: 4321,
            }),
        };

        subject.handle_scan(
            failure_handler,
            ScanType::Receivables,
            retrieve_transactions,
        );

        System::current().stop();
        system.run();
        let accountant_recording = accountant_recording_arc.lock().unwrap();
        assert_eq!(
            accountant_recording.get_record::<ScanError>(0),
            &ScanError {
                scan_type: ScanType::Receivables,
                response_skeleton_opt: Some(ResponseSkeleton {
                    client_id: 1234,
                    context_id: 4321
                }),
                msg: "My tummy hurts".to_string()
            }
        );
        TestLogHandler::new().exists_log_containing("WARN: BlockchainBridge: My tummy hurts");
    }

    #[test]
    #[should_panic(
        expected = "panic message (processed with: node_lib::sub_lib::utils::crash_request_analyzer)"
    )]
    fn blockchain_bridge_can_be_crashed_properly_but_not_improperly() {
        let crashable = true;
        let subject = BlockchainBridge::new(
            Box::new(BlockchainInterfaceMock::default()),
            Box::new(PersistentConfigurationMock::default()),
            crashable,
            None,
        );

        prove_that_crash_request_handler_is_hooked_up(subject, CRASH_KEY);
    }

    #[test]
    fn extract_max_block_range_from_error_response() {
        let result = BlockchainError::QueryFailed("RPC error: Error { code: ServerError(-32005), message: \"eth_getLogs block range too large, range: 33636, max: 3500\", data: None }".to_string());

        let max_block_count = BlockchainBridge::extract_max_block_count(result);

        assert_eq!(Some(3500u64), max_block_count);
    }

    #[test]
    fn extract_max_block_range_from_pokt_error_response() {
        let result = BlockchainError::QueryFailed("Rpc(Error { code: ServerError(-32001), message: \"Relay request failed validation: invalid relay request: eth_getLogs block range limit (100000 blocks) exceeded\", data: None })".to_string());

        let max_block_count = BlockchainBridge::extract_max_block_count(result);

        assert_eq!(Some(100000u64), max_block_count);
    }
    /*
        POKT (Polygon mainnet and mumbai)
        {"jsonrpc":"2.0","id":7,"error":{"message":"You cannot query logs for more than 100000 blocks at once.","code":-32064}}
    */
    /*
        Ankr
        {"jsonrpc":"2.0","error":{"code":-32600,"message":"block range is too wide"},"id":null}%
    */
    #[test]
    fn extract_max_block_range_for_ankr_error_response() {
        let result = BlockchainError::QueryFailed("RPC error: Error { code: ServerError(-32600), message: \"block range is too wide\", data: None }".to_string());

        let max_block_count = BlockchainBridge::extract_max_block_count(result);

        assert_eq!(None, max_block_count);
    }

    /*
    MaticVigil
    [{"error":{"message":"Blockheight too far in the past. Check params passed to eth_getLogs or eth_call requests.Range of blocks allowed for your plan: 1000","code":-32005},"jsonrpc":"2.0","id":7},{"error":{"message":"Blockheight too far in the past. Check params passed to eth_getLogs or eth_call requests.Range of blocks allowed for your plan: 1000","code":-32005},"jsonrpc":"2.0","id":8}]%
    */
    #[test]
    fn extract_max_block_range_for_matic_vigil_error_response() {
        let result = BlockchainError::QueryFailed("RPC error: Error { code: ServerError(-32005), message: \"Blockheight too far in the past. Check params passed to eth_getLogs or eth_call requests.Range of blocks allowed for your plan: 1000\", data: None }".to_string());

        let max_block_count = BlockchainBridge::extract_max_block_count(result);

        assert_eq!(Some(1000), max_block_count);
    }

    /*
    Blockpi
    [{"jsonrpc":"2.0","id":7,"result":"0x21db466"},{"jsonrpc":"2.0","id":8,"error":{"code":-32602,"message":"eth_getLogs is limited to 1024 block range. Please check the parameter requirements at  https://docs.blockpi.io/documentations/api-reference"}}]
    */
    #[test]
    fn extract_max_block_range_for_blockpi_error_response() {
        let result = BlockchainError::QueryFailed("RPC error: Error { code: ServerError(-32005), message: \"eth_getLogs is limited to 1024 block range. Please check the parameter requirements at  https://docs.blockpi.io/documentations/api-reference\", data: None }".to_string());

        let max_block_count = BlockchainBridge::extract_max_block_count(result);

        assert_eq!(Some(1024), max_block_count);
    }

    /*
    blastapi - completely rejected call on Public endpoint as won't handle eth_getLogs method on public API
    [{"jsonrpc":"2.0","id":2,"error":{"code":-32601,"message":"Method not found","data":{"method":""}}},{"jsonrpc":"2.0","id":1,"error":{"code":-32600,"message":"Invalid Request","data":{"message":"Cancelled due to validation errors in batch request"}}}] (edited)
    [8:50 AM]
    */

    #[test]
    fn extract_max_block_range_for_blastapi_error_response() {
        let result = BlockchainError::QueryFailed("RPC error: Error { code: ServerError(-32601), message: \"Method not found\", data: \"'eth_getLogs' is not available on our public API. Head over to https://docs.blastapi.io/blast-documentation/tutorials-and-guides/using-blast-to-get-a-blockchain-endpoint for more information\" }".to_string());

        let max_block_count = BlockchainBridge::extract_max_block_count(result);

        assert_eq!(None, max_block_count);
    }

    #[test]
    fn extract_max_block_range_for_expected_batch_got_single_error_response() {
        let result = BlockchainError::QueryFailed(
            "Got invalid response: Expected batch, got single.".to_string(),
        );

        let max_block_count = BlockchainBridge::extract_max_block_count(result);

        assert_eq!(Some(1000), max_block_count);
    }

    #[test]
    fn make_connections_implements_panic_on_migration() {
        let data_dir = ensure_node_home_directory_exists(
            "blockchain_bridge",
            "make_connections_with_panic_on_migration",
        );

        let act = |data_dir: &Path| {
            BlockchainBridge::initialize_persistent_configuration(data_dir);
        };

        assert_on_initialization_with_panic_on_migration(&data_dir, &act);
    }
}

#[cfg(test)]
pub mod exportable_test_parts {
    use super::*;
    use crate::bootstrapper::BootstrapperConfig;
    use crate::test_utils::http_test_server::TestServer;
    use crate::test_utils::make_wallet;
    use crate::test_utils::recorder::make_blockchain_bridge_subs_from_recorder;
    use crate::test_utils::unshared_test_utils::{AssertionsMessage, SubsFactoryTestAddrLeaker};
    use actix::System;
    use crossbeam_channel::{bounded, Receiver};
    use masq_lib::test_utils::utils::{ensure_node_home_directory_exists, TEST_DEFAULT_CHAIN};
    use masq_lib::utils::find_free_port;
    use serde_json::Value::Object;
    use serde_json::{Map, Value};
    use std::net::Ipv4Addr;

    impl SubsFactory<BlockchainBridge, BlockchainBridgeSubs>
        for SubsFactoryTestAddrLeaker<BlockchainBridge>
    {
        fn make(&self, addr: &Addr<BlockchainBridge>) -> BlockchainBridgeSubs {
            self.send_leaker_msg_and_return_meaningless_subs(
                addr,
                make_blockchain_bridge_subs_from_recorder,
            )
        }
    }

    pub fn test_blockchain_bridge_is_constructed_with_correctly_functioning_connections<A>(
        test_module: &str,
        test_name: &str,
        act: A,
    ) where
        A: FnOnce(
            BootstrapperConfig,
            SubsFactoryTestAddrLeaker<BlockchainBridge>,
        ) -> BlockchainBridgeSubs,
    {
        fn prepare_db_with_unique_value(data_dir: &Path, gas_price: u64) {
            let mut persistent_config = {
                let conn = DbInitializerReal::default()
                    .initialize(data_dir, DbInitializationConfig::test_default())
                    .unwrap();
                PersistentConfigurationReal::from(conn)
            };
            persistent_config.set_gas_price(gas_price).unwrap()
        }
        fn launch_prepared_test_server() -> (TestServer, String) {
            let port = find_free_port();
            let server_url = format!("http://{}:{}", &Ipv4Addr::LOCALHOST.to_string(), port);
            (
                TestServer::start(
                    port,
                    vec![br#"{"jsonrpc":"2.0","id":0,"result":someGarbage}"#.to_vec()],
                ),
                server_url,
            )
        }
        fn send_rpc_request_to_assert_on_later_and_assert_db_connection(
            actor_addr_rx: Receiver<Addr<BlockchainBridge>>,
            wallet: Wallet,
            expected_gas_price: u64,
        ) {
            let blockchain_bridge_addr = actor_addr_rx.try_recv().unwrap();
            let msg = AssertionsMessage {
                assertions: Box::new(move |bb: &mut BlockchainBridge| {
                    // We will assert on soundness of the connection by checking the receipt of
                    // this request
                    let _result = bb
                        .blockchain_interface
                        .lower_interface()
                        .get_service_fee_balance(&wallet);

                    // Asserting that we can look into the expected db from here, meaning the
                    // PersistentConfiguration was set up correctly
                    assert_eq!(
                        bb.persistent_config.gas_price().unwrap(),
                        expected_gas_price
                    );
                    // I don't know why exactly but the standard position
                    // of this call doesn't work
                    System::current().stop();
                }),
            };
            blockchain_bridge_addr.try_send(msg).unwrap();
        }
        fn assert_blockchain_interface_connection(test_server: &TestServer, wallet: Wallet) {
            let requests = test_server.requests_so_far();
            let bodies: Vec<Value> = requests
                .into_iter()
                .map(|request| serde_json::from_slice(&request.body()).unwrap())
                .collect();
            let params = &bodies[0]["params"];
            let expected_params = {
                let mut map = Map::new();
                let hashed_data = format!(
                    "0x70a08231000000000000000000000000{}",
                    &wallet.to_string()[2..]
                );
                map.insert("data".to_string(), Value::String(hashed_data));
                map.insert(
                    "to".to_string(),
                    Value::String(format!("{:?}", TEST_DEFAULT_CHAIN.rec().contract)),
                );
                map
            };
            assert_eq!(
                params,
                &Value::Array(vec![
                    Object(expected_params),
                    Value::String("latest".to_string())
                ])
            );
        }

        let data_dir = ensure_node_home_directory_exists(test_module, test_name);
        let gas_price = 444;
        prepare_db_with_unique_value(&data_dir, gas_price);
        let (test_server, server_url) = launch_prepared_test_server();
        let wallet = make_wallet("abc");
        let mut bootstrapper_config = BootstrapperConfig::new();
        bootstrapper_config
            .blockchain_bridge_config
            .blockchain_service_url_opt = Some(server_url);
        bootstrapper_config.blockchain_bridge_config.chain = TEST_DEFAULT_CHAIN;
        bootstrapper_config.data_directory = data_dir;
        let (tx, blockchain_bridge_addr_rx) = bounded(1);
        let address_leaker = SubsFactoryTestAddrLeaker { address_leaker: tx };
        let system = System::new(test_name);

        act(bootstrapper_config, address_leaker);

        send_rpc_request_to_assert_on_later_and_assert_db_connection(
            blockchain_bridge_addr_rx,
            wallet.clone(),
            gas_price,
        );
        assert_eq!(system.run(), 0);
        assert_blockchain_interface_connection(&test_server, wallet)
    }
}
