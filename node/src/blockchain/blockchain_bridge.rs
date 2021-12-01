// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::payable_dao::Payment;
use crate::blockchain::blockchain_interface::{
    BlockchainError, BlockchainInterface, BlockchainInterfaceClandestine,
    BlockchainInterfaceNonClandestine, BlockchainInterfaceToolFactories, BlockchainResult,
    Transaction,
};
use crate::blockchain::tool_wrappers::ToolFactories;
use crate::database::db_initializer::{DbInitializer, DATABASE_FILE};
use crate::database::db_migrations::MigratorConfig;
use crate::db_config::config_dao::ConfigDaoReal;
use crate::db_config::persistent_configuration::{
    PersistentConfiguration, PersistentConfigurationReal,
};
use crate::sub_lib::blockchain_bridge::BlockchainBridgeSubs;
use crate::sub_lib::blockchain_bridge::ReportAccountsPayable;
use crate::sub_lib::logger::Logger;
use crate::sub_lib::peer_actors::BindMessage;
use crate::sub_lib::set_consuming_wallet_message::SetConsumingWalletMessage;
use crate::sub_lib::utils::handle_ui_crash_request;
use crate::sub_lib::wallet::Wallet;
use actix::Handler;
use actix::Message;
use actix::{Actor, MessageResult};
use actix::{Addr, Recipient};
use actix::{AsyncContext, Context};
use masq_lib::blockchains::chains::Chain;
use masq_lib::ui_gateway::NodeFromUiMessage;
use std::cell::RefCell;
use std::collections::HashSet;
use std::convert::TryFrom;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};
use web3::transports::Http;
use web3::types::{TransactionReceipt, H256};

pub const CRASH_KEY: &str = "BLOCKCHAINBRIDGE";

//TODO this might become chain specific later on
pub const DEFAULT_PENDING_TX_CHECKOUT_INTERVAL_MS: u64 = 30;

pub struct BlockchainBridge {
    consuming_wallet_opt: Option<Wallet>,
    blockchain_interface: Box<dyn BlockchainInterface>,
    logger: Logger,
    persistent_config: Box<dyn PersistentConfiguration>,
    set_consuming_wallet_subs_opt: Option<Vec<Recipient<SetConsumingWalletMessage>>>,
    crashable: bool,
    blockchain_interface_tool_factories: BlockchainInterfaceToolFactories,
    tx_confirmation: TxConfirmationTools,
}

struct TxConfirmationTools {
    pending_tx_checkout_interval: u64,
    list_of_pending_txs: RefCell<HashSet<H256>>,
}

impl Actor for BlockchainBridge {
    type Context = Context<Self>;
}

impl Handler<BindMessage> for BlockchainBridge {
    type Result = ();

    fn handle(&mut self, msg: BindMessage, _ctx: &mut Self::Context) -> Self::Result {
        self.set_consuming_wallet_subs_opt = Some(vec![
            msg.peer_actors
                .neighborhood
                .set_consuming_wallet_sub
                .clone(),
            msg.peer_actors.proxy_server.set_consuming_wallet_sub,
        ]);
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

#[derive(Debug, Eq, PartialEq)]
pub struct RetrieveTransactions {
    pub start_block: u64,
    pub recipient: Wallet,
}

impl Message for RetrieveTransactions {
    type Result = Result<Vec<Transaction>, BlockchainError>;
}

impl Handler<RetrieveTransactions> for BlockchainBridge {
    type Result = MessageResult<RetrieveTransactions>;

    fn handle(
        &mut self,
        msg: RetrieveTransactions,
        _ctx: &mut Self::Context,
    ) -> <Self as Handler<RetrieveTransactions>>::Result {
        MessageResult(
            self.blockchain_interface
                .retrieve_transactions(msg.start_block, &msg.recipient),
        )
    }
}

#[derive(Debug, PartialEq, Message, Clone)]
pub struct CheckOutPendingTxForConfirmation {
    pending_txs_info: Vec<PendingTxInfo>,
    attempt: u16,
}

impl Handler<CheckOutPendingTxForConfirmation> for BlockchainBridge {
    type Result = ();

    fn handle(
        &mut self,
        msg: CheckOutPendingTxForConfirmation,
        ctx: &mut Self::Context,
    ) -> Self::Result {
        let attempt = msg.attempt;
        let statuses = self.handle_pending_tx_checkout(msg);
        let (cancelations, still_pending_as_actor_msg) =
            PendingTransactionStatus::merge_still_pending_and_separate_from_others(
                statuses, attempt,
            );
        unimplemented!()
    }
}

impl Handler<ReportAccountsPayable> for BlockchainBridge {
    type Result = MessageResult<ReportAccountsPayable>;

    fn handle(
        &mut self,
        msg: ReportAccountsPayable,
        ctx: &mut Self::Context,
    ) -> <Self as Handler<ReportAccountsPayable>>::Result {
        let (result, pending_txs_info) = self.handle_report_accounts_payable(msg);
        //TODO test later that if there is now hash we don't send a msg, but we will need more tools to set it up than I have now
        if !pending_txs_info.is_empty() {
            ctx.notify_later(
                CheckOutPendingTxForConfirmation {
                    pending_txs_info,
                    attempt: 1,
                },
                Duration::from_millis(self.tx_confirmation.pending_tx_checkout_interval),
            );
        }
        result
    }
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
        blockchain_interface_tool_factories: BlockchainInterfaceToolFactories,
        pending_tx_checkout_interval_ms: u64,
    ) -> BlockchainBridge {
        BlockchainBridge {
            consuming_wallet_opt,
            blockchain_interface,
            persistent_config,
            set_consuming_wallet_subs_opt: None,
            crashable,
            logger: Logger::new("BlockchainBridge"),
            blockchain_interface_tool_factories,
            tx_confirmation: TxConfirmationTools {
                pending_tx_checkout_interval: pending_tx_checkout_interval_ms,
                list_of_pending_txs: RefCell::new(Default::default()),
            },
        }
    }

    pub fn make_connections(
        blockchain_service_url: Option<String>,
        db_initializer: &dyn DbInitializer,
        data_directory: PathBuf,
        chain: Chain,
    ) -> (
        Box<dyn BlockchainInterface>,
        Box<dyn PersistentConfiguration>,
    ) {
        let blockchain_interface: Box<dyn BlockchainInterface> = {
            match blockchain_service_url {
                Some(url) => match Http::new(&url) {
                    Ok((event_loop_handle, transport)) => Box::new(
                        BlockchainInterfaceNonClandestine::new(transport, event_loop_handle, chain),
                    ),
                    Err(e) => panic!("Invalid blockchain node URL: {:?}", e),
                },
                None => Box::new(BlockchainInterfaceClandestine::new(chain)),
            }
        };
        let config_dao = Box::new(ConfigDaoReal::new(
            db_initializer
                .initialize(&data_directory, true, MigratorConfig::panic_on_migration())
                .unwrap_or_else(|_| {
                    panic!(
                        "Failed to connect to database at {:?}",
                        &data_directory.join(DATABASE_FILE)
                    )
                }),
        ));
        (
            blockchain_interface,
            Box::new(PersistentConfigurationReal::new(config_dao)),
        )
    }

    pub fn make_subs_from(addr: &Addr<BlockchainBridge>) -> BlockchainBridgeSubs {
        BlockchainBridgeSubs {
            bind: recipient!(addr, BindMessage),
            report_accounts_payable: recipient!(addr, ReportAccountsPayable),
            retrieve_transactions: recipient!(addr, RetrieveTransactions),
            ui_sub: recipient!(addr, NodeFromUiMessage),
        }
    }

    fn handle_report_accounts_payable(
        &self,
        creditors_msg: ReportAccountsPayable,
    ) -> (MessageResult<ReportAccountsPayable>, Vec<PendingTxInfo>) {
        let result = match self.consuming_wallet_opt.as_ref() {
            Some(consuming_wallet) => {
                let gas_price = match self.persistent_config.gas_price() {
                    Ok(num) => num,
                    Err(err) => {
                        return (
                            MessageResult(Err(format!(
                                "ReportAccountPayable: gas-price: {:?}",
                                err
                            ))),
                            vec![],
                        )
                    }
                };
                Ok(self.process_payments(creditors_msg, gas_price, consuming_wallet))
            }
            None => Err(String::from("No consuming wallet specified")),
        };
        let hashes = Self::collect_hashes_from_sent_payments(&result);
        if let Err(e) = self.add_new_pending_transactions_on_list(&hashes) {
            return (
                MessageResult(Err(format!("ReportAccountPayable: {}", e))),
                vec![],
            );
        };
        (MessageResult(result), hashes)
    }

    fn collect_hashes_from_sent_payments(
        result: &Result<Vec<BlockchainResult<Payment>>, String>,
    ) -> Vec<PendingTxInfo> {
        let mut hashes_of_pending_tx = vec![];
        result.as_ref().map(|collection| {
            collection.iter().for_each(|result| {
                result.as_ref().map(|payment| {
                    hashes_of_pending_tx.push(PendingTxInfo {
                        hash: payment.transaction.clone(),
                        when_sent: payment.timestamp,
                    })
                });
            })
        });
        hashes_of_pending_tx
    }

    fn add_new_pending_transactions_on_list(&self, txs: &[PendingTxInfo]) -> Result<(), String> {
        txs.iter().map(|pending_tx| if self.tx_confirmation.list_of_pending_txs.borrow_mut().insert(pending_tx.hash.clone())
        {Ok(())} else {Err(format!("Repeated attempt for an insertion of the same hash of a pending transaction: {}", pending_tx.hash))}).collect()
    }

    fn process_payments(
        &self,
        creditors_msg: ReportAccountsPayable,
        gas_price: u64,
        consuming_wallet: &Wallet,
    ) -> Vec<BlockchainResult<Payment>> {
        creditors_msg
            .accounts
            .iter()
            .map(|payable| {
                match self
                    .blockchain_interface
                    .get_transaction_count(consuming_wallet)
                {
                    Ok(nonce) => {
                        eprintln!("nonce: {}", nonce);
                        let amount = u64::try_from(payable.balance).unwrap_or_else(|_| {
                            panic!("Lost payable amount precision: {}", payable.balance)
                        });
                        match self.blockchain_interface.send_transaction(
                            consuming_wallet,
                            &payable.wallet,
                            amount,
                            nonce,
                            gas_price,
                            self.blockchain_interface
                                .make_send_transaction_tools(
                                    self.blockchain_interface_tool_factories
                                        .non_clandestine_send_transaction_factory
                                        .as_ref(),
                                )
                                .as_ref(),
                        ) {
                            Ok(hash) => Ok(Payment::new(payable.wallet.clone(), amount, hash)),
                            Err(e) => Err(e),
                        }
                    }
                    Err(e) => Err(e),
                }
            })
            .collect::<Vec<BlockchainResult<Payment>>>()
    }

    fn handle_pending_tx_checkout(
        &self,
        msg: CheckOutPendingTxForConfirmation,
    ) -> Vec<PendingTransactionStatus> {
        msg.pending_txs_info
            .iter()
            .map(|pending_tx_info| {
                match self
                    .blockchain_interface
                    .get_transaction_receipt(pending_tx_info.hash)
                {
                    Ok(receipt) => Self::receipt_check_for_pending_tx(
                        receipt,
                        pending_tx_info,
                        msg.attempt,
                        &self.logger,
                    ),
                    Err(e) => unimplemented!(),
                }
            })
            .collect()
    }

    fn receipt_check_for_pending_tx(
        receipt: TransactionReceipt,
        tx_info: &PendingTxInfo,
        attempt: u16,
        logger: &Logger,
    ) -> PendingTransactionStatus {
        fn elapsed_in_sec(old_timestamp: SystemTime) -> u64 {
            old_timestamp
                .elapsed()
                .expect("time counts for elapsed failed")
                .as_secs()
        }
        match receipt.status{
            None => {
                info!(logger,"Pending transaction '{}' couldn't be confirmed at attempt {} at {}s after its sending",tx_info.hash, attempt, elapsed_in_sec(tx_info.when_sent));
                PendingTransactionStatus::StillPending{ pending_tx_info: tx_info.clone(), attempt}},
            Some(status_code) => match status_code.as_u64(){
                0 => {info!(logger,"Transaction '{}' has been confirmed at attempt {} at {}s after its sending",tx_info.hash,attempt,elapsed_in_sec(tx_info.when_sent)); PendingTransactionStatus::Confirmed(tx_info.hash)},
                1 => {warning!(logger,"Pending transaction '{}' announced as a failure on the check of attempt {} at {}s after its sending",tx_info.hash,attempt,elapsed_in_sec(tx_info.when_sent)); PendingTransactionStatus::Failure(tx_info.hash)},
                _ => unreachable!("tx receipt for pending '{}' - tx status: code other than 0 or 1 shouldn't be possible",tx_info.hash)
            }
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
struct PendingTxInfo {
    hash: H256,
    when_sent: SystemTime,
}

#[derive(Debug, PartialEq, Clone)]
enum PendingTransactionStatus {
    StillPending {
        pending_tx_info: PendingTxInfo,
        attempt: u16,
    }, //will want to go back to the start and send a new
    Failure(H256), //will send a message to Accountant, log a warn and should resent the tx
    Confirmed(H256), //will send a message to Accountant
}

//TODO will send CancelPendingTxStatus msg to Accountant

impl PendingTransactionStatus {
    fn merge_still_pending_and_separate_from_others(
        vec: Vec<Self>,
        attempt: u16,
    ) -> (Vec<Self>, CheckOutPendingTxForConfirmation) {
        let (not_pending, pending): (Vec<PendingTransactionStatus>, Vec<PendingTransactionStatus>) =
            vec.into_iter().partition(|item| item.is_non_pending());

        let init = CheckOutPendingTxForConfirmation {
            pending_txs_info: vec![],
            attempt: attempt + 1,
        };
        let recollected = pending.into_iter().fold(init, |mut so_far, now| {
            if let PendingTransactionStatus::StillPending {
                pending_tx_info,
                attempt: attempt_from_tx_info,
            } = now
            {
                if attempt_from_tx_info != attempt {
                    panic!("incompatible attempts of tx confirmations, something is broken; should be {} but was {}", attempt, attempt_from_tx_info)
                };
                so_far.pending_txs_info.push(pending_tx_info)
            } else {
                panic!("previous measures failed")
            }
            so_far
        });
        (not_pending, recollected)
    }

    fn is_non_pending(&self) -> bool {
        match self {
            Self::StillPending { .. } => false,
            _ => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accountant::payable_dao::PayableAccount;
    use crate::accountant::test_utils::{bc_from_ac_plus_earning_wallet, make_accountant};
    use crate::accountant::tests::PayableDaoMock;
    use crate::accountant::{Accountant, SentPayments};
    use crate::blockchain::bip32::Bip32ECKeyPair;
    use crate::blockchain::blockchain_interface::{
        Balance, BlockchainError, BlockchainResult, Nonce, Transaction, Transactions, TxReceipt,
    };
    use crate::blockchain::test_utils::{
        make_blockchain_interface_tool_factories, CheckOutPendingTransactionToolWrapperFactoryMock,
        SendTransactionToolWrapperFactoryMock, SendTransactionToolWrapperMock,
    };
    use crate::blockchain::tool_wrappers::{
        SendTransactionToolWrapper, SendTransactionToolWrapperFactory,
    };
    use crate::database::dao_utils::{from_time_t, to_time_t};
    use crate::database::db_initializer::test_utils::DbInitializerMock;
    use crate::db_config::persistent_configuration::PersistentConfigError;
    use crate::sub_lib::accountant::AccountantConfig;
    use crate::test_utils::logging::init_test_logging;
    use crate::test_utils::logging::TestLogHandler;
    use crate::test_utils::persistent_configuration_mock::PersistentConfigurationMock;
    use crate::test_utils::pure_test_utils::{
        make_default_persistent_configuration, prove_that_crash_request_handler_is_hooked_up,
        CleanUpMessage, DummyActor,
    };
    use crate::test_utils::recorder::peer_actors_builder;
    use crate::test_utils::{make_paying_wallet, make_wallet};
    use actix::System;
    use actix::{Addr, Arbiter};
    use ethereum_types::{BigEndianHash, U64};
    use ethsign_crypto::Keccak256;
    use futures::future::Future;
    use masq_lib::constants::DEFAULT_CHAIN;
    use masq_lib::test_utils::utils::TEST_DEFAULT_CHAIN;
    use rustc_hex::FromHex;
    use std::cell::RefCell;
    use std::fmt::Debug;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, SystemTime};
    use web3::types::{Address, TransactionReceipt, H256, U256};

    fn stub_bi() -> Box<dyn BlockchainInterface> {
        Box::new(BlockchainInterfaceMock::default())
    }

    #[test]
    fn blockchain_bridge_receives_bind_message_with_consuming_private_key() {
        init_test_logging();
        let secret: Vec<u8> = "cc46befe8d169b89db447bd725fc2368b12542113555302598430cb5d5c74ea9"
            .from_hex()
            .unwrap();
        let consuming_wallet = Wallet::from(Bip32ECKeyPair::from_raw_secret(&secret).unwrap());
        let subject = BlockchainBridge::new(
            stub_bi(),
            Box::new(make_default_persistent_configuration()),
            false,
            Some(consuming_wallet.clone()),
            BlockchainInterfaceToolFactories::default(),
            DEFAULT_PENDING_TX_CHECKOUT_INTERVAL_MS, //irrelevant
        );
        let system = System::new("blockchain_bridge_receives_bind_message");
        let addr: Addr<BlockchainBridge> = subject.start();

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
    fn blockchain_bridge_receives_bind_message_without_consuming_private_key() {
        init_test_logging();
        let subject = BlockchainBridge::new(
            stub_bi(),
            Box::new(PersistentConfigurationMock::default()),
            false,
            None,
            BlockchainInterfaceToolFactories::default(),
            DEFAULT_PENDING_TX_CHECKOUT_INTERVAL_MS, //irrelevant
        );
        let system = System::new("blockchain_bridge_receives_bind_message");
        let addr: Addr<BlockchainBridge> = subject.start();

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

    #[derive(Debug, Default)]
    struct BlockchainInterfaceMock {
        pub retrieve_transactions_parameters: Arc<Mutex<Vec<(u64, Wallet)>>>,
        pub retrieve_transactions_results: RefCell<Vec<BlockchainResult<Vec<Transaction>>>>,
        send_transaction_parameters: Arc<Mutex<Vec<(Wallet, Wallet, u64, U256, u64)>>>,
        send_transaction_results: RefCell<Vec<BlockchainResult<H256>>>,
        get_transaction_receipt_params: Arc<Mutex<Vec<H256>>>,
        get_transaction_receipt_results: RefCell<Vec<TxReceipt>>,
        pub contract_address_results: RefCell<Vec<Address>>,
        pub get_transaction_count_parameters: Arc<Mutex<Vec<Wallet>>>,
        pub get_transaction_count_results: RefCell<Vec<BlockchainResult<U256>>>,
    }

    impl BlockchainInterfaceMock {
        fn retrieve_transactions_result(
            self,
            result: Result<Vec<Transaction>, BlockchainError>,
        ) -> Self {
            self.retrieve_transactions_results.borrow_mut().push(result);
            self
        }

        //TODO this isn't good that assertions for params are probably missing?

        fn send_transaction_result(self, result: BlockchainResult<H256>) -> Self {
            self.send_transaction_results.borrow_mut().push(result);
            self
        }

        fn contract_address_result(self, address: Address) -> Self {
            self.contract_address_results.borrow_mut().push(address);
            self
        }

        fn get_transaction_count_result(self, result: BlockchainResult<U256>) -> Self {
            self.get_transaction_count_results.borrow_mut().push(result);
            self
        }

        fn get_transaction_receipt_params(mut self, params: &Arc<Mutex<Vec<H256>>>) -> Self {
            self.get_transaction_receipt_params = params.clone();
            self
        }

        fn get_transaction_receipt_result(self, result: TxReceipt) -> Self {
            self.get_transaction_receipt_results
                .borrow_mut()
                .push(result);
            self
        }

        //looking for make_send_transaction_tools?
        //for injecting results for BlockchainBridge use the mocked factory: SendTransactionToolWrapperFactoryMock
    }

    impl BlockchainInterface for BlockchainInterfaceMock {
        fn contract_address(&self) -> Address {
            self.contract_address_results.borrow_mut().remove(0)
        }

        fn retrieve_transactions(&self, start_block: u64, recipient: &Wallet) -> Transactions {
            self.retrieve_transactions_parameters
                .lock()
                .unwrap()
                .push((start_block, recipient.clone()));
            self.retrieve_transactions_results.borrow_mut().remove(0)
        }

        fn send_transaction<'a>(
            &self,
            consuming_wallet: &Wallet,
            recipient: &Wallet,
            amount: u64,
            nonce: U256,
            gas_price: u64,
            _send_transaction_tools: &'a dyn SendTransactionToolWrapper,
        ) -> BlockchainResult<H256> {
            self.send_transaction_parameters.lock().unwrap().push((
                consuming_wallet.clone(),
                recipient.clone(),
                amount,
                nonce,
                gas_price,
            ));
            self.send_transaction_results.borrow_mut().remove(0)
        }

        fn get_eth_balance(&self, _address: &Wallet) -> Balance {
            unimplemented!()
        }

        fn get_token_balance(&self, _address: &Wallet) -> Balance {
            unimplemented!()
        }

        fn get_transaction_count(&self, wallet: &Wallet) -> Nonce {
            self.get_transaction_count_parameters
                .lock()
                .unwrap()
                .push(wallet.clone());
            self.get_transaction_count_results.borrow_mut().remove(0)
        }

        fn get_transaction_receipt(&self, hash: H256) -> TxReceipt {
            self.get_transaction_receipt_params
                .lock()
                .unwrap()
                .push(hash);
            self.get_transaction_receipt_results.borrow_mut().remove(0)
        }
    }

    impl ToolFactories for BlockchainInterfaceMock {
        fn make_send_transaction_tools<'a>(
            &'a self,
            tool_factory_from_blockchain_bridge: &'a (dyn SendTransactionToolWrapperFactory + 'a),
        ) -> Box<dyn SendTransactionToolWrapper + 'a> {
            tool_factory_from_blockchain_bridge.make(Box::new(
                || -> Box<dyn SendTransactionToolWrapper + 'a> { panic!("shouldn't be called") },
            ))
        }
    }

    #[test]
    #[should_panic(expected = "Invalid blockchain node URL")]
    fn invalid_blockchain_url_produces_panic() {
        let data_directory = PathBuf::new(); //never reached
        let blockchain_service_url = Some("http://λ:8545".to_string());
        let _ = BlockchainBridge::make_connections(
            blockchain_service_url,
            &DbInitializerMock::default(),
            data_directory,
            DEFAULT_CHAIN,
        );
    }

    #[test]
    fn ask_me_about_my_transactions() {
        let system = System::new("ask_me_about_my_transactions");
        let block_no = 37;
        let expected_results = vec![Transaction {
            block_number: 42u64,
            from: make_wallet("some_address"),
            gwei_amount: 21,
        }];
        let result = Ok(expected_results.clone());
        let wallet = make_wallet("smelly");
        let blockchain_interface_mock = BlockchainInterfaceMock::default()
            .retrieve_transactions_result(result)
            .contract_address_result(TEST_DEFAULT_CHAIN.rec().contract);
        let retrieve_transactions_parameters = blockchain_interface_mock
            .retrieve_transactions_parameters
            .clone();
        let subject = BlockchainBridge::new(
            Box::new(blockchain_interface_mock),
            Box::new(PersistentConfigurationMock::default()),
            false,
            None,
            make_blockchain_interface_tool_factories(None, None),
            DEFAULT_PENDING_TX_CHECKOUT_INTERVAL_MS, //irrelevant
        );
        let addr: Addr<BlockchainBridge> = subject.start();

        let request = addr.send(RetrieveTransactions {
            start_block: block_no,
            recipient: wallet.clone(),
        });
        System::current().stop();
        system.run();

        let retrieve_transactions_parameters = retrieve_transactions_parameters.lock().unwrap();
        assert_eq!((block_no, wallet), retrieve_transactions_parameters[0]);

        let result = request.wait().unwrap().unwrap();
        assert_eq!(expected_results, result);
    }

    #[test]
    fn report_accounts_payable_sends_transactions_to_blockchain_interface() {
        let system =
            System::new("report_accounts_payable_sends_transactions_to_blockchain_interface");
        let blockchain_interface_mock = BlockchainInterfaceMock::default()
            .get_transaction_count_result(Ok(U256::from(1)))
            .get_transaction_count_result(Ok(U256::from(2)))
            .send_transaction_result(Ok(H256::from("sometransactionhash".keccak256())))
            .send_transaction_result(Ok(H256::from("someothertransactionhash".keccak256())))
            .contract_address_result(TEST_DEFAULT_CHAIN.rec().contract);
        let send_parameters = blockchain_interface_mock
            .send_transaction_parameters
            .clone();
        let transaction_count_parameters = blockchain_interface_mock
            .get_transaction_count_parameters
            .clone();
        let expected_gas_price = 5u64;
        let persistent_configuration_mock =
            PersistentConfigurationMock::default().gas_price_result(Ok(expected_gas_price));
        let non_clandestine_send_tx_tool_factory = SendTransactionToolWrapperFactoryMock::default()
            .make_result(Box::new(SendTransactionToolWrapperMock::default()))
            .make_result(Box::new(SendTransactionToolWrapperMock::default()));
        let consuming_wallet = make_paying_wallet(b"somewallet");
        let subject = BlockchainBridge::new(
            Box::new(blockchain_interface_mock),
            Box::new(persistent_configuration_mock),
            false,
            Some(consuming_wallet.clone()),
            make_blockchain_interface_tool_factories(
                Some(non_clandestine_send_tx_tool_factory),
                None,
            ),
            DEFAULT_PENDING_TX_CHECKOUT_INTERVAL_MS,
        );
        let addr: Addr<BlockchainBridge> = subject.start();

        let request = addr.send(ReportAccountsPayable {
            accounts: vec![
                PayableAccount {
                    wallet: make_wallet("blah"),
                    balance: 42,
                    last_paid_timestamp: SystemTime::now(),
                    pending_payment_transaction: None,
                },
                PayableAccount {
                    wallet: make_wallet("foo"),
                    balance: 21,
                    last_paid_timestamp: SystemTime::now(),
                    pending_payment_transaction: None,
                },
            ],
        });
        System::current().stop();
        system.run();

        assert_eq!(
            send_parameters.lock().unwrap()[0],
            (
                consuming_wallet.clone(),
                make_wallet("blah"),
                42,
                U256::from(1),
                expected_gas_price
            )
        );
        assert_eq!(
            send_parameters.lock().unwrap()[1],
            (
                consuming_wallet.clone(),
                make_wallet("foo"),
                21,
                U256::from(2),
                expected_gas_price
            )
        );

        let result = request.wait().unwrap().unwrap();
        let mut expected_payment_0 = Payment::new(
            make_wallet("blah"),
            42,
            H256::from("sometransactionhash".keccak256()),
        );

        if let Ok(zero) = result.clone().get(0).unwrap().clone() {
            assert!(
                zero.timestamp
                    <= expected_payment_0
                        .timestamp
                        .checked_add(Duration::from_secs(2))
                        .unwrap()
            );
            assert!(
                zero.timestamp
                    >= expected_payment_0
                        .timestamp
                        .checked_sub(Duration::from_secs(2))
                        .unwrap()
            );
            expected_payment_0.timestamp = zero.timestamp
        }

        let mut expected_payment_1 = Payment::new(
            make_wallet("foo"),
            21,
            H256::from("someothertransactionhash".keccak256()),
        );

        if let Ok(one) = result.clone().get(1).unwrap().clone() {
            assert!(
                one.timestamp
                    <= expected_payment_1
                        .timestamp
                        .checked_add(Duration::from_secs(2))
                        .unwrap()
            );
            assert!(
                one.timestamp
                    >= expected_payment_1
                        .timestamp
                        .checked_sub(Duration::from_secs(2))
                        .unwrap()
            );
            expected_payment_1.timestamp = one.timestamp
        }

        assert_eq!(result[1], Ok(expected_payment_1));

        assert_eq!(
            transaction_count_parameters.lock().unwrap()[0],
            consuming_wallet.clone(),
        );
        assert_eq!(
            transaction_count_parameters.lock().unwrap()[1],
            consuming_wallet.clone(),
        );
    }

    #[test]
    fn report_accounts_payable_returns_error_for_blockchain_error() {
        let blockchain_interface_mock = BlockchainInterfaceMock::default()
            .get_transaction_count_result(Ok(web3::types::U256::from(1)))
            .send_transaction_result(Err(BlockchainError::TransactionFailed(String::from(
                "mock payment failure",
            ))));
        let transaction_count_parameters = blockchain_interface_mock
            .get_transaction_count_parameters
            .clone();
        let consuming_wallet = make_wallet("somewallet");
        let persistent_configuration_mock =
            PersistentConfigurationMock::new().gas_price_result(Ok(3u64));
        let non_clandestine_send_tx_tool_factory = SendTransactionToolWrapperFactoryMock::default()
            .make_result(Box::new(SendTransactionToolWrapperMock::default()));
        let subject = BlockchainBridge::new(
            Box::new(blockchain_interface_mock),
            Box::new(persistent_configuration_mock),
            false,
            Some(consuming_wallet.clone()),
            make_blockchain_interface_tool_factories(
                Some(non_clandestine_send_tx_tool_factory),
                None,
            ),
            DEFAULT_PENDING_TX_CHECKOUT_INTERVAL_MS,
        );
        let request = ReportAccountsPayable {
            accounts: vec![PayableAccount {
                wallet: make_wallet("blah"),
                balance: 42,
                last_paid_timestamp: SystemTime::now(),
                pending_payment_transaction: None,
            }],
        };

        let result = subject.handle_report_accounts_payable(request);

        let (result, pending_tx_info) = result;
        assert_eq!(
            result.0,
            Ok(vec![Err(BlockchainError::TransactionFailed(String::from(
                "mock payment failure"
            )))])
        );
        assert!(pending_tx_info.is_empty());
        let actual_wallet = transaction_count_parameters.lock().unwrap().remove(0);
        assert_eq!(actual_wallet, consuming_wallet);
    }

    #[test]
    fn report_accounts_payable_returns_error_when_there_is_no_consuming_wallet_configured() {
        let blockchain_interface_mock = BlockchainInterfaceMock::default();
        let persistent_configuration_mock = PersistentConfigurationMock::default();
        let subject = BlockchainBridge::new(
            Box::new(blockchain_interface_mock),
            Box::new(persistent_configuration_mock),
            false,
            None,
            BlockchainInterfaceToolFactories::default(),
            DEFAULT_PENDING_TX_CHECKOUT_INTERVAL_MS,
        );
        let request = ReportAccountsPayable {
            accounts: vec![PayableAccount {
                wallet: make_wallet("blah"),
                balance: 42,
                last_paid_timestamp: SystemTime::now(),
                pending_payment_transaction: None,
            }],
        };

        let result = subject.handle_report_accounts_payable(request);

        let (result, pending_tx_info) = result;
        assert_eq!(result.0, Err("No consuming wallet specified".to_string()));
        assert!(pending_tx_info.is_empty())
    }

    #[test]
    fn handle_report_account_payable_manages_gas_price_error() {
        let blockchain_interface_mock = BlockchainInterfaceMock::default()
            .get_transaction_count_result(Ok(web3::types::U256::from(1)));
        let persistent_configuration_mock = PersistentConfigurationMock::new()
            .gas_price_result(Err(PersistentConfigError::TransactionError));
        let consuming_wallet = make_wallet("somewallet");
        let subject = BlockchainBridge::new(
            Box::new(blockchain_interface_mock),
            Box::new(persistent_configuration_mock),
            false,
            Some(consuming_wallet),
            make_blockchain_interface_tool_factories(None, None),
            DEFAULT_PENDING_TX_CHECKOUT_INTERVAL_MS,
        );
        let request = ReportAccountsPayable {
            accounts: vec![PayableAccount {
                wallet: make_wallet("blah"),
                balance: 42,
                last_paid_timestamp: SystemTime::now(),
                pending_payment_transaction: None,
            }],
        };

        let result = subject.handle_report_accounts_payable(request);

        let (result, pending_tx_info) = result;
        assert_eq!(
            result.0,
            Err(String::from(
                "ReportAccountPayable: gas-price: TransactionError"
            ))
        );
        assert!(pending_tx_info.is_empty())
    }

    #[test]
    fn blockchain_bridge_lists_hashes_of_active_pending_txs() {
        let tx_hash1 = H256::from_uint(&U256::from(456));
        let tx_hash2 = H256::from_uint(&U256::from(123));
        let blockchain_interface_mock = BlockchainInterfaceMock::default()
            .get_transaction_count_result(Ok(web3::types::U256::from(1)))
            .get_transaction_count_result(Ok(web3::types::U256::from(2)))
            .send_transaction_result(Ok(tx_hash1))
            .send_transaction_result(Ok(tx_hash2));
        //injecting results is quite specific...they come in with "send_transaction_tool_wrapper_factory"
        let persistent_configuration_mock =
            PersistentConfigurationMock::new().gas_price_result(Ok(150));
        let send_transaction_tool_wrapper_factory =
            SendTransactionToolWrapperFactoryMock::default()
                .make_result(Box::new(SendTransactionToolWrapperMock::default()))
                .make_result(Box::new(SendTransactionToolWrapperMock::default()));
        let subject = BlockchainBridge::new(
            Box::new(blockchain_interface_mock),
            Box::new(persistent_configuration_mock),
            false,
            Some(make_wallet("ourWallet")),
            make_blockchain_interface_tool_factories(
                Some(send_transaction_tool_wrapper_factory),
                None,
            ),
            DEFAULT_PENDING_TX_CHECKOUT_INTERVAL_MS,
        );
        let wallet1 = make_wallet("blah");
        let timestamp1 = from_time_t(456000);
        let balance1 = 45_000;
        let wallet2 = make_wallet("hurrah");
        let timestamp2 = from_time_t(300000);
        let balance2 = 111;
        let account1 = PayableAccount {
            wallet: wallet1.clone(),
            balance: balance1,
            last_paid_timestamp: timestamp1,
            pending_payment_transaction: None,
        };
        let account2 = PayableAccount {
            wallet: wallet2.clone(),
            balance: balance2,
            last_paid_timestamp: timestamp2,
            pending_payment_transaction: None,
        };
        let request = ReportAccountsPayable {
            accounts: vec![account1, account2],
        };

        let result = subject.handle_report_accounts_payable(request);

        let (result, hashes) = result;
        let mut vec_of_payments = result.0.unwrap();
        let processed_payment_1 = vec_of_payments.remove(0).unwrap();
        assert_eq!(processed_payment_1.amount, balance1 as u64);
        assert_eq!(processed_payment_1.to, wallet1);
        assert_eq!(processed_payment_1.transaction, tx_hash1);
        assert!(to_time_t(processed_payment_1.timestamp) > (to_time_t(SystemTime::now()) - 10));
        let processed_payment_2 = vec_of_payments.remove(0).unwrap();
        assert_eq!(processed_payment_2.amount, balance2 as u64);
        assert_eq!(processed_payment_2.to, wallet2);
        assert_eq!(processed_payment_2.transaction, tx_hash2);
        assert!(to_time_t(processed_payment_2.timestamp) > (to_time_t(SystemTime::now()) - 10));
        assert_eq!(hashes.len(), 2);
        assert!(vec_of_payments.is_empty());
        assert_eq!(
            subject.tx_confirmation.list_of_pending_txs.borrow().len(),
            2
        );
        assert!(subject
            .tx_confirmation
            .list_of_pending_txs
            .borrow()
            .contains(&tx_hash1));
        assert!(subject
            .tx_confirmation
            .list_of_pending_txs
            .borrow()
            .contains(&tx_hash2));
        //TODO if you figure out assertion on params of making SendTransactionToolWrapperFactoryMock -> SendTransactionToolWrapperMock, put it here
    }

    #[test]
    fn add_new_pending_transaction_on_list_returns_error_on_double_insertion() {
        let pending_tx_hash = H256::from_uint(&U256::from(123));
        let blockchain_interface_mock = BlockchainInterfaceMock::default()
            .get_transaction_count_result(Ok(web3::types::U256::from(1)))
            .send_transaction_result(Ok(pending_tx_hash));
        let send_transaction_tool_wrapper_factory =
            SendTransactionToolWrapperFactoryMock::default()
                .make_result(Box::new(SendTransactionToolWrapperMock::default()));
        let persistent_config = PersistentConfigurationMock::default().gas_price_result(Ok(150));
        let subject = BlockchainBridge::new(
            Box::new(blockchain_interface_mock),
            Box::new(persistent_config),
            false,
            Some(make_wallet("blahBlah")),
            make_blockchain_interface_tool_factories(
                Some(send_transaction_tool_wrapper_factory),
                None,
            ),
            DEFAULT_PENDING_TX_CHECKOUT_INTERVAL_MS,
        );
        let wallet = make_wallet("blah");
        let timestamp = from_time_t(456000);
        let balance = 45_000;
        let account = PayableAccount {
            wallet: wallet.clone(),
            balance,
            last_paid_timestamp: timestamp,
            pending_payment_transaction: None,
        };
        let request = ReportAccountsPayable {
            accounts: vec![account],
        };
        assert!(subject
            .tx_confirmation
            .list_of_pending_txs
            .borrow_mut()
            .insert(pending_tx_hash));

        let result = subject.handle_report_accounts_payable(request);

        let (result, hash) = result;
        assert_eq!(result.0,Err("ReportAccountPayable: Repeated attempt for an insertion of the same hash of a pending transaction: 0x0000…007b".to_string()))
    }

    #[test]
    fn pending_transaction_is_registered_and_monitored_until_it_gets_confirmed() {
        //we send a list of creditor accounts with mature debts to BlockchainBridge
        //it acts like it's sending transactions for paying the debts (transacting is mocked),
        //next to that BlockchainBridge registers Hashes of the pending transactions and also prepares himself
        //a self-notification to be sent later on letting him know he should check whether the transactions have been confirmed
        // - this message will go over back repeatedly in intervals; when it finds a confirmation of the transaction
        //it sends a message to Accountant to update the state of the database by blanking out the column for pending
        //transactions for the given confirmed transaction;
        //along with the previous, right away when we get hashes of the new pending transactions Account is given a message
        //and writes a record for the respective account of the wallet where the transaction was sent to.

        // let db_dir = ensure_node_home_directory_exists("blockchain","pending_transaction_is_registered_and_monitored_until_it_gets_confirmed");
        // let conn_wrapped = DbInitializerReal::default().initialize(&db_dir,true,MigratorConfig::test_default()).unwrap();
        let payment_sent_params_arc = Arc::new(Mutex::new(vec![]));
        let transaction_confirmed_params_arc = Arc::new(Mutex::new(vec![]));
        let get_transaction_receipt_params_arc = Arc::new(Mutex::new(vec![]));
        let payable_dao = PayableDaoMock::new()
            .payment_sent_params(&payment_sent_params_arc)
            .payment_sent_result(Ok(()))
            .payment_sent_result(Ok(()))
            .transaction_confirmed_params(&transaction_confirmed_params_arc);
        //TODO we will want also results
        let bootstrapper_config = bc_from_ac_plus_earning_wallet(
            AccountantConfig {
                payable_scan_interval: Duration::from_secs(1_000_000), //we don't care about the scan
                payment_received_scan_interval: Duration::from_secs(1_000_000), //we don't care about the scan
            },
            make_wallet("some_wallet_address"),
        );
        let pending_tx_hash_1 = H256::from_uint(&U256::from(123));
        let pending_tx_hash_2 = H256::from_uint(&U256::from(567));
        let transaction_receipt_tx_1_first_round = TransactionReceipt::default();
        let transaction_receipt_tx_2_first_round = TransactionReceipt::default();
        let blockchain_interface = BlockchainInterfaceMock::default()
            .get_transaction_count_result(Ok(web3::types::U256::from(1)))
            .get_transaction_count_result(Ok(web3::types::U256::from(2)))
            .send_transaction_result(Ok(pending_tx_hash_1))
            .send_transaction_result(Ok(pending_tx_hash_2))
            .get_transaction_receipt_params(&get_transaction_receipt_params_arc)
            .get_transaction_receipt_result(Ok(transaction_receipt_tx_1_first_round))
            .get_transaction_receipt_result(Ok(transaction_receipt_tx_2_first_round));
        let consuming_wallet = make_paying_wallet(b"wallet");
        let system = System::new("pending_transaction");
        let persistent_config = PersistentConfigurationMock::default().gas_price_result(Ok(130));
        let non_clandestine_send_tx_tool_factory = SendTransactionToolWrapperFactoryMock::default()
            .make_result(Box::new(SendTransactionToolWrapperMock::default()))
            .make_result(Box::new(SendTransactionToolWrapperMock::default()));
        let non_clandestine_chack_out_pending_tx_tool_factory =
            CheckOutPendingTransactionToolWrapperFactoryMock::default();
        let pending_tx_checkout_interval_ms = 10;
        let subject = BlockchainBridge::new(
            Box::new(blockchain_interface),
            Box::new(persistent_config),
            false,
            Some(consuming_wallet),
            make_blockchain_interface_tool_factories(
                Some(non_clandestine_send_tx_tool_factory),
                Some(non_clandestine_chack_out_pending_tx_tool_factory),
            ),
            pending_tx_checkout_interval_ms,
        );
        let accountant_addr = Arbiter::builder()
            .stop_system_on_panic(true)
            .start(move |_| {
                make_accountant(
                    Some(bootstrapper_config),
                    Some(payable_dao),
                    None,
                    None,
                    None,
                )
            });
        let mut peer_actors = peer_actors_builder().build();
        let accountant_subs = Accountant::make_subs_from(&accountant_addr);
        let cloned_recipient_for_sent_payments = accountant_subs.report_sent_payments.clone();
        peer_actors.accountant = accountant_subs.clone();
        let blockchain_bridge_addr = subject.start();
        let blockchain_bridge_subs = BlockchainBridge::make_subs_from(&blockchain_bridge_addr);
        peer_actors.blockchain_bridge = blockchain_bridge_subs.clone();
        let wallet_account_1 = make_wallet("creditor1");
        let account_1 = PayableAccount {
            wallet: wallet_account_1.clone(),
            balance: 5500,
            last_paid_timestamp: from_time_t(16548475),
            pending_payment_transaction: None,
        };
        let wallet_account_2 = make_wallet("creditor2");
        let account_2 = PayableAccount {
            wallet: wallet_account_2.clone(),
            balance: 123456,
            last_paid_timestamp: from_time_t(16546300),
            pending_payment_transaction: None,
        };
        let creditor_message = ReportAccountsPayable {
            accounts: vec![account_1, account_2],
        };
        let gas_price = 130;
        let dummy_actor = DummyActor::new(None);
        let dummy_actor_addr = dummy_actor.start();
        send_bind_message!(accountant_subs, peer_actors);
        send_bind_message!(blockchain_bridge_subs, peer_actors);

        let response = blockchain_bridge_addr.send(creditor_message);

        let future = response.then(move |results| match results {
            Ok(Ok(results)) => {
                cloned_recipient_for_sent_payments
                    .try_send(SentPayments { payments: results })
                    .expect("Accountant is dead");
                Ok(())
            }
            _ => panic!(),
        });
        actix::spawn(future);

        //TODO try to delete the dummy acter once you have the self notifications ready to work
        dummy_actor_addr
            .try_send(CleanUpMessage { sleep_ms: 1 })
            .unwrap(); //I'm trying to prolong the life time of the system so that the future has time to complete
        assert_eq!(system.run(), 0);
        let mut payment_sent_parameters = payment_sent_params_arc.lock().unwrap();
        let first_payment = payment_sent_parameters.remove(0);
        assert_eq!(first_payment.to, wallet_account_1);
        assert_eq!(first_payment.amount, 5500);
        assert!(to_time_t(first_payment.timestamp) > (to_time_t(SystemTime::now()) - 10));
        assert_eq!(first_payment.transaction, pending_tx_hash_1);
        let second_payment = payment_sent_parameters.remove(0);
        assert!(
            payment_sent_parameters.is_empty(),
            "{:?}",
            payment_sent_parameters
        );
        assert_eq!(second_payment.to, wallet_account_2);
        assert_eq!(second_payment.amount, 123456);
        assert!(to_time_t(second_payment.timestamp) > (to_time_t(SystemTime::now()) - 10));
        assert_eq!(second_payment.transaction, pending_tx_hash_2);
        let transaction_confirmed_params = transaction_confirmed_params_arc.lock().unwrap();
        assert_eq!(
            *transaction_confirmed_params,
            vec![wallet_account_1, wallet_account_2]
        )
    }

    #[test]
    fn receipt_check_for_pending_tx_when_tx_confirmed() {
        init_test_logging();
        let hash = H256::from_uint(&U256::from(789));
        let mut tx_receipt = TransactionReceipt::default();
        tx_receipt.transaction_hash = hash;
        tx_receipt.status = Some(U64::from(0)); //success
        let when_sent = SystemTime::now()
            .checked_sub(Duration::from_secs(150))
            .unwrap();
        let pending_tx_info = PendingTxInfo { hash, when_sent };
        let attempt = 5;

        let result = BlockchainBridge::receipt_check_for_pending_tx(
            tx_receipt,
            &pending_tx_info,
            attempt,
            &Logger::new("receipt_check_logger"),
        );

        assert_eq!(result, PendingTransactionStatus::Confirmed(hash));
        TestLogHandler::new().exists_log_containing("INFO: receipt_check_logger: Transaction '0x0000…0315' has been confirmed at attempt 5 at 150s after its sending");
    }

    #[test]
    fn receipt_check_for_pending_tx_when_tx_status_is_none() {
        init_test_logging();
        let hash = H256::from_uint(&U256::from(567));
        let mut tx_receipt = TransactionReceipt::default();
        tx_receipt.transaction_hash = hash;
        let when_sent = SystemTime::now()
            .checked_sub(Duration::from_secs(5))
            .unwrap();
        let pending_tx_info = PendingTxInfo { hash, when_sent };
        let attempt = 1;

        let result = BlockchainBridge::receipt_check_for_pending_tx(
            tx_receipt,
            &pending_tx_info,
            attempt,
            &Logger::new("receipt_check_logger"),
        );

        assert_eq!(
            result,
            PendingTransactionStatus::StillPending {
                pending_tx_info,
                attempt
            }
        );
        TestLogHandler::new().exists_log_containing("INFO: receipt_check_logger: Pending transaction '0x0000…0237' couldn't be confirmed at attempt 1 at 5s after its sending");
    }

    #[test]
    fn receipt_check_for_pending_tx_when_tx_status_is_a_failure() {
        init_test_logging();
        let hash = H256::from_uint(&U256::from(789));
        let mut tx_receipt = TransactionReceipt::default();
        tx_receipt.transaction_hash = hash;
        tx_receipt.status = Some(U64::from(1)); //failure
        let when_sent = SystemTime::now()
            .checked_sub(Duration::from_secs(150))
            .unwrap();
        let pending_tx_info = PendingTxInfo { hash, when_sent };
        let attempt = 5;

        let result = BlockchainBridge::receipt_check_for_pending_tx(
            tx_receipt,
            &pending_tx_info,
            attempt,
            &Logger::new("receipt_check_logger"),
        );

        assert_eq!(result, PendingTransactionStatus::Failure(hash));
        TestLogHandler::new().exists_log_containing("WARN: receipt_check_logger: Pending transaction '0x0000…0315' announced as a failure on the check of attempt 5 at 150s after its sending");
    }

    #[test]
    #[should_panic(
        expected = "tx receipt for pending '0x0000…007b' - tx status: code other than 0 or 1 shouldn't be possible"
    )]
    fn receipt_check_for_pending_tx_panics_at_undefined_status_code() {
        let hash = H256::from_uint(&U256::from(123));
        let mut tx_receipt = TransactionReceipt::default();
        tx_receipt.status = Some(U64::from(456));
        tx_receipt.transaction_hash = hash;
        let when_sent = SystemTime::now();
        let pending_tx_info = PendingTxInfo { hash, when_sent };

        let result = BlockchainBridge::receipt_check_for_pending_tx(
            tx_receipt,
            &pending_tx_info,
            1,
            &Logger::new("receipt_check_logger"),
        );
    }

    #[test]
    fn merging_pending_tx_info_works_including_incrementing_the_attempt_number() {
        let confirmed_status =
            PendingTransactionStatus::Confirmed(H256::from_uint(&U256::from(123)));
        let failure_status = PendingTransactionStatus::Failure(H256::from_uint(&U256::from(456)));
        let first_tx_hash = H256::from_uint(&U256::from(123));
        let first_timestamp = from_time_t(150000);
        let first_pending_tx_info = PendingTxInfo {
            hash: first_tx_hash,
            when_sent: first_timestamp,
        };
        let attempt = 4;
        let first_pending_tx_status = PendingTransactionStatus::StillPending {
            pending_tx_info: first_pending_tx_info.clone(),
            attempt,
        };
        let second_tx_hash = H256::from_uint(&U256::from(578));
        let second_timestamp = from_time_t(178000);
        let second_pending_tx_info = PendingTxInfo {
            hash: second_tx_hash,
            when_sent: second_timestamp,
        };
        let second_pending_tx_status = PendingTransactionStatus::StillPending {
            pending_tx_info: second_pending_tx_info.clone(),
            attempt,
        };
        let statuses = vec![
            first_pending_tx_status,
            confirmed_status.clone(),
            second_pending_tx_status,
            failure_status.clone(),
        ];

        let result = PendingTransactionStatus::merge_still_pending_and_separate_from_others(
            statuses, attempt,
        );

        let (to_cancel, to_repeat) = result;
        assert_eq!(to_cancel, vec![confirmed_status, failure_status]);
        assert_eq!(
            to_repeat,
            CheckOutPendingTxForConfirmation {
                pending_txs_info: vec![first_pending_tx_info, second_pending_tx_info],
                attempt: 5
            }
        )
    }

    #[test]
    #[should_panic(
        expected = "incompatible attempts of tx confirmations, something is broken; should be 2 but was 5"
    )]
    fn merging_pending_tx_info_panics_at_pending_records_with_incompatible_attempt_numbers() {
        let first_tx_hash = H256::from_uint(&U256::from(123));
        let first_timestamp = from_time_t(150000);
        let first_pending_tx_info = PendingTxInfo {
            hash: first_tx_hash,
            when_sent: first_timestamp,
        };
        let believed_attempt = 2;
        let attempt_1 = 2;
        let first_pending_tx_status = PendingTransactionStatus::StillPending {
            pending_tx_info: first_pending_tx_info.clone(),
            attempt: attempt_1,
        };
        let second_tx_hash = H256::from_uint(&U256::from(578));
        let second_timestamp = from_time_t(178000);
        let second_pending_tx_info = PendingTxInfo {
            hash: second_tx_hash,
            when_sent: second_timestamp,
        };
        let attempt_2 = 5;
        let second_pending_tx_status = PendingTransactionStatus::StillPending {
            pending_tx_info: second_pending_tx_info.clone(),
            attempt: attempt_2,
        };
        let statuses = vec![first_pending_tx_status, second_pending_tx_status];

        let result = PendingTransactionStatus::merge_still_pending_and_separate_from_others(
            statuses,
            believed_attempt,
        );
    }

    #[test]
    fn is_non_pending_is_properly_set() {
        assert_eq!(
            PendingTransactionStatus::Failure(H256::from_uint(&U256::from(123))).is_non_pending(),
            true
        );
        assert_eq!(
            PendingTransactionStatus::Confirmed(H256::from_uint(&U256::from(123))).is_non_pending(),
            true
        );
        assert_eq!(
            PendingTransactionStatus::StillPending {
                pending_tx_info: PendingTxInfo {
                    hash: H256::from_uint(&U256::from(123)),
                    when_sent: SystemTime::now()
                },
                attempt: 4
            }
            .is_non_pending(),
            false
        );
    }

    #[test]
    #[should_panic(
        expected = "panic message (processed with: node_lib::sub_lib::utils::crash_request_analyzer)"
    )]
    fn blockchain_bridge_can_be_crashed_properly_but_not_improperly() {
        let crashable = true;
        let actor = BlockchainBridge::new(
            Box::new(BlockchainInterfaceMock::default()),
            Box::new(PersistentConfigurationMock::default()),
            crashable,
            None,
            make_blockchain_interface_tool_factories(None, None),
            DEFAULT_PENDING_TX_CHECKOUT_INTERVAL_MS, //irrelevant
        );

        prove_that_crash_request_handler_is_hooked_up(actor, CRASH_KEY);
    }
}
