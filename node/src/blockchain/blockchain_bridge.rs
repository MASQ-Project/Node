// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

use crate::accountant::payable_dao::Payment;
use crate::blockchain::bip32::Bip32ECKeyPair;
use crate::blockchain::blockchain_interface::{
    BlockchainError, BlockchainInterface, BlockchainResult, Transaction,
};
use crate::bootstrapper::BootstrapperConfig;
use crate::persistent_configuration::PersistentConfiguration;
use crate::sub_lib::blockchain_bridge::ReportAccountsPayable;
use crate::sub_lib::blockchain_bridge::SetDbPasswordMsg;
use crate::sub_lib::blockchain_bridge::{BlockchainBridgeSubs, SetGasPriceMsg};
use crate::sub_lib::logger::Logger;
use crate::sub_lib::peer_actors::BindMessage;
use crate::sub_lib::set_consuming_wallet_message::SetConsumingWalletMessage;
use crate::sub_lib::ui_gateway::{UiCarrierMessage, UiMessage};
use crate::sub_lib::wallet::Wallet;
use actix::Context;
use actix::Handler;
use actix::Message;
use actix::{Actor, MessageResult};
use actix::{Addr, Recipient};
use std::convert::TryFrom;

pub struct BlockchainBridge {
    consuming_wallet: Option<Wallet>,
    blockchain_interface: Box<dyn BlockchainInterface>,
    logger: Logger,
    persistent_config: Box<dyn PersistentConfiguration>,
    ui_carrier_message_sub: Option<Recipient<UiCarrierMessage>>,
    set_consuming_wallet_subs: Option<Vec<Recipient<SetConsumingWalletMessage>>>,
}

impl Actor for BlockchainBridge {
    type Context = Context<Self>;
}

impl Handler<BindMessage> for BlockchainBridge {
    type Result = ();

    fn handle(&mut self, msg: BindMessage, _ctx: &mut Self::Context) -> Self::Result {
        self.ui_carrier_message_sub = Some(msg.peer_actors.ui_gateway.ui_message_sub.clone());
        self.set_consuming_wallet_subs = Some(vec![
            msg.peer_actors
                .neighborhood
                .set_consuming_wallet_sub
                .clone(),
            msg.peer_actors.proxy_server.set_consuming_wallet_sub,
        ]);
        match self.consuming_wallet.as_ref() {
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

impl Handler<ReportAccountsPayable> for BlockchainBridge {
    type Result = MessageResult<ReportAccountsPayable>;

    fn handle(
        &mut self,
        msg: ReportAccountsPayable,
        _ctx: &mut Self::Context,
    ) -> <Self as Handler<ReportAccountsPayable>>::Result {
        MessageResult(match self.consuming_wallet.as_ref() {
            Some(consuming_wallet) => Ok(msg
                .accounts
                .iter()
                .map(|payable| {
                    match self
                        .blockchain_interface
                        .get_transaction_count(&consuming_wallet)
                    {
                        Ok(nonce) => {
                            match self.blockchain_interface.send_transaction(
                                &consuming_wallet,
                                &payable.wallet,
                                u64::try_from(payable.balance).unwrap_or_else(|_| {
                                    panic!("Lost payable amount precision: {}", payable.balance)
                                }),
                                nonce,
                                self.persistent_config.gas_price(),
                            ) {
                                Ok(hash) => Ok(Payment::new(
                                    payable.wallet.clone(),
                                    u64::try_from(payable.balance).unwrap_or_else(|_| {
                                        panic!("Lost payable amount precision: {}", payable.balance)
                                    }),
                                    hash,
                                )),
                                Err(e) => Err(e),
                            }
                        }
                        Err(e) => Err(e),
                    }
                })
                .collect::<Vec<BlockchainResult<Payment>>>()),
            None => Err(String::from("No consuming wallet specified")),
        })
    }
}

impl Handler<SetGasPriceMsg> for BlockchainBridge {
    type Result = ();

    fn handle(&mut self, msg: SetGasPriceMsg, _ctx: &mut Self::Context) -> Self::Result {
        let gas_price_accepted = match msg.gas_price.parse::<u64>() {
            Ok(gas_price) => {
                self.persistent_config.set_gas_price(gas_price);
                true
            }
            Err(e) => {
                debug!(
                    self.logger,
                    r#"error setting gas price to "{}" {:?}"#, &msg.gas_price, e
                );
                false
            }
        };
        self.ui_carrier_message_sub
            .as_ref()
            .expect("UiGateway is unbound")
            .try_send(UiCarrierMessage {
                client_id: msg.client_id,
                data: UiMessage::SetGasPriceResponse(gas_price_accepted),
            })
            .expect("UiGateway is dead");
    }
}

impl Handler<SetDbPasswordMsg> for BlockchainBridge {
    type Result = ();

    fn handle(&mut self, msg: SetDbPasswordMsg, _ctx: &mut Self::Context) -> Self::Result {
        let password_accepted = self.accept_db_password(&msg.password);
        self.ui_carrier_message_sub
            .as_ref()
            .expect("UiGateway is unbound")
            .try_send(UiCarrierMessage {
                client_id: msg.client_id,
                data: UiMessage::SetDbPasswordResponse(password_accepted),
            })
            .expect("UiGateway is dead")
    }
}

impl BlockchainBridge {
    pub fn new(
        config: &BootstrapperConfig,
        blockchain_interface: Box<dyn BlockchainInterface>,
        persistent_config: Box<dyn PersistentConfiguration>,
    ) -> BlockchainBridge {
        BlockchainBridge {
            consuming_wallet: config.consuming_wallet.clone(),
            blockchain_interface,
            logger: Logger::new("BlockchainBridge"),
            persistent_config,
            ui_carrier_message_sub: None,
            set_consuming_wallet_subs: None,
        }
    }

    pub fn make_subs_from(addr: &Addr<BlockchainBridge>) -> BlockchainBridgeSubs {
        BlockchainBridgeSubs {
            bind: recipient!(addr, BindMessage),
            report_accounts_payable: recipient!(addr, ReportAccountsPayable),
            retrieve_transactions: recipient!(addr, RetrieveTransactions),
            set_gas_price_sub: recipient!(addr, SetGasPriceMsg),
            set_consuming_db_password_sub: recipient!(addr, SetDbPasswordMsg),
        }
    }

    fn accept_db_password(&mut self, password: &str) -> bool {
        if self.consuming_wallet.is_some() {
            error!(
                self.logger,
                "Database password rejected: consuming wallet already active"
            );
            return false;
        }
        let consuming_wallet_derivation_path = match self
            .persistent_config
            .consuming_wallet_derivation_path()
        {
            Some(cwdp) => cwdp,
            None => {
                error!(
                    self.logger,
                    "Database password rejected: no consuming wallet derivation path has been configured"
                );
                return false;
            }
        };
        match self.persistent_config.mnemonic_seed(password) {
            Ok(Some(plain_data)) => {
                let key_pair = Bip32ECKeyPair::from_raw(
                    &plain_data.as_slice(),
                    &consuming_wallet_derivation_path,
                )
                .expect("Internal Error");
                let consuming_wallet = Wallet::from(key_pair);
                self.set_consuming_wallet_subs
                    .as_ref()
                    .expect("SetConsumingWalletMessage handlers are unbound in Blockchain Bridge")
                    .iter()
                    .for_each(|sub| {
                        sub.try_send(SetConsumingWalletMessage {
                            wallet: consuming_wallet.clone(),
                        })
                        .expect("SetConsumingWalletMessage handler is dead")
                    });
                self.consuming_wallet = Some(consuming_wallet);
                debug!(
                    self.logger,
                    "unlocked consuming wallet address {:?}", &self.consuming_wallet
                );
                true
            }
            Ok(None) => {
                error!(
                    self.logger,
                    "Database password rejected: no mnemonic phrase has been configured"
                );
                false
            }
            Err(e) => {
                warning!(self.logger, "failed to unlock consuming wallet: {:?}", e);
                false
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accountant::payable_dao::PayableAccount;
    use crate::blockchain::bip32::Bip32ECKeyPair;
    use crate::blockchain::blockchain_interface::{
        contract_address, Balance, BlockchainError, BlockchainResult, Nonce, Transaction,
        Transactions,
    };
    use crate::persistent_configuration::PersistentConfigError;
    use crate::sub_lib::cryptde::PlainData;
    use crate::sub_lib::set_consuming_wallet_message::SetConsumingWalletMessage;
    use crate::sub_lib::ui_gateway::UiMessage;
    use crate::sub_lib::wallet::DEFAULT_CONSUMING_DERIVATION_PATH;
    use crate::test_utils::logging::init_test_logging;
    use crate::test_utils::logging::TestLogHandler;
    use crate::test_utils::persistent_configuration_mock::PersistentConfigurationMock;
    use crate::test_utils::recorder::{make_recorder, peer_actors_builder};
    use crate::test_utils::{
        make_default_persistent_configuration, make_paying_wallet, make_wallet, DEFAULT_CHAIN_ID,
    };
    use actix::Addr;
    use actix::System;
    use bip39::{Language, Mnemonic, Seed};
    use ethsign::keyfile::Crypto;
    use ethsign::{Protected, SecretKey};
    use ethsign_crypto::Keccak256;
    use futures::future::Future;
    use rustc_hex::FromHex;
    use std::cell::RefCell;
    use std::num::NonZeroU32;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::{Duration, SystemTime};
    use web3::types::{Address, H256, U256};

    fn stub_bi() -> Box<dyn BlockchainInterface> {
        Box::new(BlockchainInterfaceMock::default())
    }

    #[test]
    fn blockchain_bridge_sets_wallet_when_password_is_received() {
        init_test_logging();
        let (ui_gateway, ui_gateway_awaiter, ui_gateway_recording_arc) = make_recorder();
        let (neighborhood, neighborhood_awaiter, neighborhood_recording_arc) = make_recorder();
        let (proxy_server, proxy_server_awaiter, proxy_server_recording_arc) = make_recorder();
        let password = "ilikecheetos";
        let mnemonic = Mnemonic::from_phrase(
            "timber cage wide hawk phone shaft pattern movie army dizzy hen tackle lamp \
             absent write kind term toddler sphere ripple idle dragon curious hold",
            Language::English,
        )
        .unwrap();
        let seed = Seed::new(&mnemonic, "some passphrase");
        let seed_bytes = seed.as_bytes().to_vec();
        let encrypted_seed = serde_cbor::to_vec(
            &Crypto::encrypt(
                &seed_bytes,
                &Protected::new(password.as_bytes()),
                NonZeroU32::new(10240).expect("Internal error"),
            )
            .unwrap(),
        )
        .unwrap();
        let crypto = serde_cbor::from_slice::<Crypto>(&encrypted_seed).unwrap();
        let mnemonic_seed = crypto
            .decrypt(&Protected::new(password.as_bytes()))
            .unwrap();
        let key_pair = Bip32ECKeyPair::from_raw(
            PlainData::new(&mnemonic_seed).as_slice(),
            DEFAULT_CONSUMING_DERIVATION_PATH,
        )
        .unwrap();
        let expected_wallet = Some(Wallet::from(key_pair));

        thread::spawn(move || {
            let persistent_config_mock = PersistentConfigurationMock::default()
                .mnemonic_seed_result(Ok(Some(PlainData::from(seed_bytes))))
                .consuming_wallet_derivation_path_result(Some(
                    DEFAULT_CONSUMING_DERIVATION_PATH.to_string(),
                ));

            let subject = BlockchainBridge::new(
                &bc_from_wallet(None),
                stub_bi(),
                Box::new(persistent_config_mock),
            );

            let system = System::new("blockchain_bridge_sets_wallet_when_password_is_received");
            let addr = subject.start();

            addr.try_send(BindMessage {
                peer_actors: peer_actors_builder()
                    .neighborhood(neighborhood)
                    .proxy_server(proxy_server)
                    .ui_gateway(ui_gateway)
                    .build(),
            })
            .unwrap();
            addr.try_send(SetDbPasswordMsg {
                client_id: 42,
                password: password.to_string(),
            })
            .unwrap();

            system.run();
        });

        ui_gateway_awaiter.await_message_count(1);

        let ui_gateway_recording = ui_gateway_recording_arc.lock().unwrap();
        assert_eq!(
            ui_gateway_recording.get_record::<UiCarrierMessage>(0),
            &UiCarrierMessage {
                client_id: 42,
                data: UiMessage::SetDbPasswordResponse(true),
            }
        );
        TestLogHandler::new().exists_log_containing(&format!(
            "unlocked consuming wallet address {:?}",
            &expected_wallet
        ));

        neighborhood_awaiter.await_message_count(1);
        let neighborhood_recording = neighborhood_recording_arc.lock().unwrap();
        assert_eq!(
            neighborhood_recording.get_record::<SetConsumingWalletMessage>(0),
            &SetConsumingWalletMessage {
                wallet: expected_wallet.clone().unwrap()
            }
        );

        proxy_server_awaiter.await_message_count(1);
        let proxy_server_recording = proxy_server_recording_arc.lock().unwrap();
        assert_eq!(
            proxy_server_recording.get_record::<SetConsumingWalletMessage>(0),
            &SetConsumingWalletMessage {
                wallet: expected_wallet.unwrap()
            }
        );
    }

    #[test]
    fn blockchain_bridge_logs_warning_when_setting_wallet_with_bad_password() {
        init_test_logging();
        let (ui_gateway, ui_gateway_awaiter, ui_gateway_recording_arc) = make_recorder();

        thread::spawn(move || {
            let persistent_config_mock = PersistentConfigurationMock::default()
                .mnemonic_seed_result(Err(PersistentConfigError::PasswordError))
                .consuming_wallet_derivation_path_result(Some(
                    DEFAULT_CONSUMING_DERIVATION_PATH.to_string(),
                ));

            let subject = BlockchainBridge::new(
                &bc_from_wallet(None),
                stub_bi(),
                Box::new(persistent_config_mock),
            );

            let system = System::new("blockchain_bridge_sets_wallet_when_password_is_received");
            let addr = subject.start();

            addr.try_send(BindMessage {
                peer_actors: peer_actors_builder().ui_gateway(ui_gateway).build(),
            })
            .unwrap();
            addr.try_send(SetDbPasswordMsg {
                client_id: 42,
                password: "ihatecheetos".to_string(),
            })
            .unwrap();

            system.run();
        });

        ui_gateway_awaiter.await_message_count(1);

        let ui_gateway_recording = ui_gateway_recording_arc.lock().unwrap();
        assert_eq!(
            ui_gateway_recording.get_record::<UiCarrierMessage>(0),
            &UiCarrierMessage {
                client_id: 42,
                data: UiMessage::SetDbPasswordResponse(false),
            }
        );
        TestLogHandler::new()
            .exists_log_containing(&format!("failed to unlock consuming wallet: PasswordError"));
    }

    #[test]
    fn blockchain_bridge_logs_error_when_setting_db_password_when_wallet_already_exists() {
        init_test_logging();
        let (ui_gateway, ui_gateway_awaiter, ui_gateway_recording_arc) = make_recorder();
        thread::spawn(move || {
            let persistent_config_mock = PersistentConfigurationMock::default();
            let subject = BlockchainBridge::new(
                &bc_from_wallet(Some(Wallet::new(
                    "0x0000000000000000000000000000000000000000",
                ))),
                stub_bi(),
                Box::new(persistent_config_mock),
            );

            let system = System::new(
                "blockchain_bridge_logs_error_when_setting_db_password_when_wallet_already_exists",
            );
            let addr = subject.start();

            addr.try_send(BindMessage {
                peer_actors: peer_actors_builder().ui_gateway(ui_gateway).build(),
            })
            .unwrap();
            addr.try_send(SetDbPasswordMsg {
                client_id: 42,
                password: "ilikecheetos".to_string(),
            })
            .unwrap();

            system.run();
        });

        ui_gateway_awaiter.await_message_count(1);

        let ui_gateway_recording = ui_gateway_recording_arc.lock().unwrap();
        assert_eq!(
            ui_gateway_recording.get_record::<UiCarrierMessage>(0),
            &UiCarrierMessage {
                client_id: 42,
                data: UiMessage::SetDbPasswordResponse(false),
            }
        );
        TestLogHandler::new().exists_log_containing(&format!(
            "Database password rejected: consuming wallet already active"
        ));
    }

    #[test]
    fn blockchain_bridge_logs_error_when_setting_db_password_when_no_consuming_wallet_derivation_path(
    ) {
        init_test_logging();
        let (ui_gateway, ui_gateway_awaiter, ui_gateway_recording_arc) = make_recorder();
        thread::spawn(move || {
            let persistent_config_mock =
                PersistentConfigurationMock::new().consuming_wallet_derivation_path_result(None);
            let subject = BlockchainBridge::new(
                &bc_from_wallet(None),
                stub_bi(),
                Box::new(persistent_config_mock),
            );

            let system = System::new("blockchain_bridge_logs_error_when_setting_db_password_when_no_consuming_wallet_derivation_path");
            let addr = subject.start();

            addr.try_send(BindMessage {
                peer_actors: peer_actors_builder().ui_gateway(ui_gateway).build(),
            })
            .unwrap();
            addr.try_send(SetDbPasswordMsg {
                client_id: 42,
                password: "ilikecheetos".to_string(),
            })
            .unwrap();

            system.run();
        });

        ui_gateway_awaiter.await_message_count(1);

        let ui_gateway_recording = ui_gateway_recording_arc.lock().unwrap();
        assert_eq!(
            ui_gateway_recording.get_record::<UiCarrierMessage>(0),
            &UiCarrierMessage {
                client_id: 42,
                data: UiMessage::SetDbPasswordResponse(false),
            }
        );
        TestLogHandler::new().exists_log_containing(&format!(
            "Database password rejected: no consuming wallet derivation path has been configured"
        ));
    }

    #[test]
    fn blockchain_bridge_logs_error_when_setting_db_password_when_no_mnemonic_seed() {
        init_test_logging();
        let (ui_gateway, ui_gateway_awaiter, ui_gateway_recording_arc) = make_recorder();
        thread::spawn(move || {
            let persistent_config_mock = PersistentConfigurationMock::new()
                .consuming_wallet_derivation_path_result(Some("m/44'/60'/1'/2/3".to_string()))
                .mnemonic_seed_result(Ok(None));
            let subject = BlockchainBridge::new(
                &bc_from_wallet(None),
                stub_bi(),
                Box::new(persistent_config_mock),
            );

            let system = System::new(
                "blockchain_bridge_logs_error_when_setting_db_password_when_no_mnemonic_seed",
            );
            let addr = subject.start();

            addr.try_send(BindMessage {
                peer_actors: peer_actors_builder().ui_gateway(ui_gateway).build(),
            })
            .unwrap();
            addr.try_send(SetDbPasswordMsg {
                client_id: 42,
                password: "ilikecheetos".to_string(),
            })
            .unwrap();

            system.run();
        });

        ui_gateway_awaiter.await_message_count(1);

        let ui_gateway_recording = ui_gateway_recording_arc.lock().unwrap();
        assert_eq!(
            ui_gateway_recording.get_record::<UiCarrierMessage>(0),
            &UiCarrierMessage {
                client_id: 42,
                data: UiMessage::SetDbPasswordResponse(false),
            }
        );
        TestLogHandler::new().exists_log_containing(&format!(
            "Database password rejected: no mnemonic phrase has been configured"
        ));
    }

    #[test]
    fn blockchain_bridge_receives_bind_message_with_consuming_private_key() {
        init_test_logging();
        let secret: Vec<u8> = "cc46befe8d169b89db447bd725fc2368b12542113555302598430cb5d5c74ea9"
            .from_hex()
            .unwrap();
        let consuming_private_key = SecretKey::from_raw(&secret).unwrap();
        let consuming_wallet = Wallet::from(Bip32ECKeyPair::from(consuming_private_key));
        let subject = BlockchainBridge::new(
            &bc_from_wallet(Some(consuming_wallet.clone())),
            stub_bi(),
            Box::new(make_default_persistent_configuration()),
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
            &bc_from_wallet(None),
            stub_bi(),
            Box::new(PersistentConfigurationMock::default()),
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

    #[test]
    fn blockchain_bridge_sets_gas_price_when_received() {
        let (ui_gateway, ui_gateway_awaiter, ui_gateway_recording_arc) = make_recorder();
        let gas_price_params_arc = Arc::new(Mutex::new(vec![]));

        let persistent_config_mock = PersistentConfigurationMock::default()
            .set_gas_price_params(&gas_price_params_arc.clone());

        thread::spawn(move || {
            let subject = BlockchainBridge::new(
                &bc_from_wallet(None),
                stub_bi(),
                Box::new(persistent_config_mock),
            );

            let system = System::new("blockchain_bridge_sets_gas_price_when_received");
            let addr = subject.start();

            addr.try_send(BindMessage {
                peer_actors: peer_actors_builder().ui_gateway(ui_gateway).build(),
            })
            .unwrap();
            addr.try_send(SetGasPriceMsg {
                client_id: 41,
                gas_price: "99".to_string(),
            })
            .unwrap();

            system.run();
        });

        ui_gateway_awaiter.await_message_count(1);

        let ui_gateway_recording = ui_gateway_recording_arc.lock().unwrap();
        assert_eq!(99u64, gas_price_params_arc.lock().unwrap()[0]);
        assert_eq!(
            ui_gateway_recording.get_record::<UiCarrierMessage>(0),
            &UiCarrierMessage {
                client_id: 41,
                data: UiMessage::SetGasPriceResponse(true),
            }
        );
    }

    #[test]
    fn blockchain_bridge_does_not_set_gas_price_when_received_badly() {
        let (ui_gateway, ui_gateway_awaiter, ui_gateway_recording_arc) = make_recorder();
        let gas_price_params_arc = Arc::new(Mutex::new(vec![]));

        let persistent_config_mock = PersistentConfigurationMock::default()
            .set_gas_price_params(&gas_price_params_arc.clone());

        thread::spawn(move || {
            let subject = BlockchainBridge::new(
                &bc_from_wallet(None),
                stub_bi(),
                Box::new(persistent_config_mock),
            );

            let system =
                System::new("blockchain_bridge_does_not_set_gas_price_when_received_badly");
            let addr = subject.start();

            addr.try_send(BindMessage {
                peer_actors: peer_actors_builder().ui_gateway(ui_gateway).build(),
            })
            .unwrap();
            addr.try_send(SetGasPriceMsg {
                client_id: 41,
                gas_price: "0xf".to_string(),
            })
            .unwrap();

            system.run();
        });

        ui_gateway_awaiter.await_message_count(1);

        let ui_gateway_recording = ui_gateway_recording_arc.lock().unwrap();
        assert!(gas_price_params_arc.lock().unwrap().is_empty());
        assert_eq!(
            ui_gateway_recording.get_record::<UiCarrierMessage>(0),
            &UiCarrierMessage {
                client_id: 41,
                data: UiMessage::SetGasPriceResponse(false),
            }
        );
    }

    #[derive(Debug, Default)]
    struct BlockchainInterfaceMock {
        pub retrieve_transactions_parameters: Arc<Mutex<Vec<(u64, Wallet)>>>,
        pub retrieve_transactions_results: RefCell<Vec<BlockchainResult<Vec<Transaction>>>>,
        pub send_transaction_parameters: Arc<Mutex<Vec<(Wallet, Wallet, u64, U256, u64)>>>,
        pub send_transaction_results: RefCell<Vec<BlockchainResult<H256>>>,
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

        fn send_transaction(
            &self,
            consuming_wallet: &Wallet,
            recipient: &Wallet,
            amount: u64,
            nonce: U256,
            gas_price: u64,
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
            .contract_address_result(contract_address(DEFAULT_CHAIN_ID));
        let retrieve_transactions_parameters = blockchain_interface_mock
            .retrieve_transactions_parameters
            .clone();
        let subject = BlockchainBridge::new(
            &bc_from_wallet(None),
            Box::new(blockchain_interface_mock),
            Box::new(PersistentConfigurationMock::default()),
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
            .contract_address_result(contract_address(DEFAULT_CHAIN_ID));
        let send_parameters = blockchain_interface_mock
            .send_transaction_parameters
            .clone();
        let transaction_count_parameters = blockchain_interface_mock
            .get_transaction_count_parameters
            .clone();
        let expected_gas_price = 5u64;
        let persistent_configuration_mock =
            PersistentConfigurationMock::default().gas_price_result(expected_gas_price);

        let consuming_wallet = make_paying_wallet(b"somewallet");
        let subject = BlockchainBridge::new(
            &bc_from_wallet(Some(consuming_wallet.clone())),
            Box::new(blockchain_interface_mock),
            Box::new(persistent_configuration_mock),
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
        let system = System::new("report_accounts_payable_returns_error_for_blockchain_error");

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
            PersistentConfigurationMock::new().gas_price_result(3u64);
        let subject = BlockchainBridge::new(
            &bc_from_wallet(Some(consuming_wallet.clone())),
            Box::new(blockchain_interface_mock),
            Box::new(persistent_configuration_mock),
        );
        let addr: Addr<BlockchainBridge> = subject.start();

        let request = addr.send(ReportAccountsPayable {
            accounts: vec![PayableAccount {
                wallet: make_wallet("blah"),
                balance: 42,
                last_paid_timestamp: SystemTime::now(),
                pending_payment_transaction: None,
            }],
        });

        System::current().stop();
        system.run();

        let result = &request.wait().unwrap().unwrap();

        assert_eq!(
            result,
            &[Err(BlockchainError::TransactionFailed(String::from(
                "mock payment failure"
            )))]
        );
        let actual_wallet = transaction_count_parameters.lock().unwrap().remove(0);

        assert_eq!(actual_wallet, consuming_wallet);
    }

    #[test]
    fn report_accounts_payable_returns_error_when_there_is_no_consuming_wallet_configured() {
        let system = System::new("report_accounts_payable_returns_error_for_blockchain_error");

        let blockchain_interface_mock = BlockchainInterfaceMock::default();
        let persistent_configuration_mock = PersistentConfigurationMock::default();

        let subject = BlockchainBridge::new(
            &BootstrapperConfig::new(),
            Box::new(blockchain_interface_mock),
            Box::new(persistent_configuration_mock),
        );
        let addr: Addr<BlockchainBridge> = subject.start();

        let request = addr.send(ReportAccountsPayable {
            accounts: vec![PayableAccount {
                wallet: make_wallet("blah"),
                balance: 42,
                last_paid_timestamp: SystemTime::now(),
                pending_payment_transaction: None,
            }],
        });

        System::current().stop();
        system.run();

        let result = &request.wait().unwrap();

        assert_eq!(result, &Err("No consuming wallet specified".to_string()));
    }

    fn bc_from_wallet(consuming_wallet: Option<Wallet>) -> BootstrapperConfig {
        let mut bc = BootstrapperConfig::new();
        bc.consuming_wallet = consuming_wallet;
        bc
    }
}
