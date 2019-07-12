// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

use crate::blockchain::bip32::Bip32ECKeyPair;
use crate::blockchain::bip39::Bip39Error;
use crate::blockchain::blockchain_interface::{BlockchainError, BlockchainInterface, Transaction};
use crate::bootstrapper::BootstrapperConfig;
use crate::persistent_configuration::PersistentConfiguration;
use crate::sub_lib::blockchain_bridge::BlockchainBridgeSubs;
use crate::sub_lib::blockchain_bridge::ReportAccountsPayable;
use crate::sub_lib::blockchain_bridge::{BlockchainBridgeConfig, SetWalletPasswordMsg};
use crate::sub_lib::logger::Logger;
use crate::sub_lib::peer_actors::BindMessage;
use crate::sub_lib::ui_gateway::{UiCarrierMessage, UiMessage};
use crate::sub_lib::wallet::Wallet;
use actix::Context;
use actix::Handler;
use actix::Message;
use actix::{Actor, MessageResult};
use actix::{Addr, Recipient};

pub struct BlockchainBridge {
    _config: BlockchainBridgeConfig, // TODO: Why is this not used? That seems wrong.
    consuming_wallet: Option<Wallet>,
    blockchain_interface: Box<dyn BlockchainInterface>,
    logger: Logger,
    persistent_config: Box<PersistentConfiguration>,
    ui_carrier_message_sub: Option<Recipient<UiCarrierMessage>>,
}

impl Actor for BlockchainBridge {
    type Context = Context<Self>;
}

impl Handler<BindMessage> for BlockchainBridge {
    type Result = ();

    fn handle(&mut self, msg: BindMessage, _ctx: &mut Self::Context) -> Self::Result {
        self.ui_carrier_message_sub = Some(msg.peer_actors.ui_gateway.ui_message_sub.clone());
        match self.consuming_wallet.as_ref() {
            Some(wallet) => {
                debug!(
                    self.logger,
                    format!("Received BindMessage; consuming wallet address {}", wallet)
                );
            }
            None => {
                debug!(
                    self.logger,
                    "Received BindMessage; no consuming wallet address specified".to_string()
                );
            }
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
    type Result = ();

    fn handle(&mut self, _msg: ReportAccountsPayable, _ctx: &mut Self::Context) -> Self::Result {
        debug!(
            self.logger,
            "Received ReportAccountsPayable message".to_string()
        );
    }
}

impl Handler<SetWalletPasswordMsg> for BlockchainBridge {
    type Result = ();

    fn handle(&mut self, msg: SetWalletPasswordMsg, _ctx: &mut Self::Context) -> Self::Result {
        let password_accepted = self.accept_wallet_password(&msg.password);
        self.ui_carrier_message_sub
            .as_ref()
            .expect("UiGateway is unbound")
            .try_send(UiCarrierMessage {
                client_id: msg.client_id,
                data: UiMessage::SetWalletPasswordResponse(password_accepted),
            })
            .expect("UiGateway is dead");
    }
}

impl BlockchainBridge {
    pub fn new(
        config: &BootstrapperConfig,
        blockchain_interface: Box<dyn BlockchainInterface>,
        persistent_config: Box<PersistentConfiguration>,
    ) -> BlockchainBridge {
        BlockchainBridge {
            _config: config.blockchain_bridge_config.clone(),
            consuming_wallet: config.consuming_wallet.clone(),
            blockchain_interface,
            logger: Logger::new("BlockchainBridge"),
            persistent_config,
            ui_carrier_message_sub: None,
        }
    }

    pub fn make_subs_from(addr: &Addr<BlockchainBridge>) -> BlockchainBridgeSubs {
        BlockchainBridgeSubs {
            bind: addr.clone().recipient::<BindMessage>(),
            report_accounts_payable: addr.clone().recipient::<ReportAccountsPayable>(),
            retrieve_transactions: addr.clone().recipient::<RetrieveTransactions>(),
            set_consuming_wallet_password_sub: addr.clone().recipient::<SetWalletPasswordMsg>(),
        }
    }

    fn accept_wallet_password(&mut self, password: &str) -> bool {
        if self.consuming_wallet.is_some() {
            error!(
                self.logger,
                "Wallet password rejected: consuming wallet already active".to_string()
            );
            return false;
        }
        let consuming_wallet_derivation_path = match self
            .persistent_config
            .consuming_wallet_derivation_path()
        {
            Some(cwdp) => cwdp,
            None => {
                error!(self.logger, "Wallet password rejected: no consuming wallet derivation path has been configured".to_string());
                return false;
            }
        };
        match self.persistent_config.mnemonic_seed(password) {
            Ok(plain_data) => {
                let key_pair = Bip32ECKeyPair::from_raw(
                    &plain_data.as_slice(),
                    &consuming_wallet_derivation_path,
                )
                .expect("Internal Error");
                self.consuming_wallet = Some(Wallet::from(key_pair));
                debug!(
                    self.logger,
                    format!(
                        "unlocked consuming wallet address {:?}",
                        &self.consuming_wallet
                    )
                );
                true
            }
            Err(Bip39Error::NotPresent) => {
                error!(
                    self.logger,
                    "Wallet password rejected: no mnemonic phrase has been configured".to_string()
                );
                false
            }
            Err(e) => {
                warning!(
                    self.logger,
                    format!("failed to unlock consuming wallet: {:?}", e)
                );
                false
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blockchain::bip32::Bip32ECKeyPair;
    use crate::blockchain::bip39::{Bip39, Bip39Error};
    use crate::blockchain::blockchain_interface::{
        Balance, BlockchainError, Transaction, Transactions, TESTNET_CONTRACT_ADDRESS,
    };
    use crate::sub_lib::cryptde::PlainData;
    use crate::sub_lib::ui_gateway::UiMessage;
    use crate::sub_lib::wallet::DEFAULT_CONSUMING_DERIVATION_PATH;
    use crate::test_utils::logging::init_test_logging;
    use crate::test_utils::logging::TestLogHandler;
    use crate::test_utils::persistent_configuration_mock::PersistentConfigurationMock;
    use crate::test_utils::recorder::{make_recorder, peer_actors_builder};
    use crate::test_utils::*;
    use actix::Addr;
    use actix::System;
    use bip39::{Language, Mnemonic, Seed};
    use ethsign::keyfile::Crypto;
    use ethsign::{Protected, SecretKey};
    use futures::future::Future;
    use rustc_hex::FromHex;
    use std::cell::RefCell;
    use std::num::NonZeroU32;
    use std::sync::{Arc, Mutex};
    use std::thread;

    fn stub_bi() -> Box<BlockchainInterface> {
        Box::new(BlockchainInterfaceMock::default())
    }

    #[test]
    fn blockchain_bridge_sets_wallet_when_password_is_received() {
        init_test_logging();
        let (ui_gateway, ui_gateway_awaiter, ui_gateway_recording_arc) = make_recorder();

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
                .encrypted_mnemonic_seed_result(Some(
                    Bip39::encrypt_bytes(&seed_bytes, password).unwrap(),
                ))
                .mnemonic_seed_result(Ok(PlainData::from(seed_bytes)))
                .consuming_wallet_derivation_path_result(Some(
                    DEFAULT_CONSUMING_DERIVATION_PATH.to_string(),
                ));

            let subject = BlockchainBridge::new(
                &bc_from_bbc_plus(
                    BlockchainBridgeConfig {
                        blockchain_service_url: None,
                        contract_address: TESTNET_CONTRACT_ADDRESS,
                    },
                    None,
                ),
                stub_bi(),
                Box::new(persistent_config_mock),
            );

            let system = System::new("blockchain_bridge_sets_wallet_when_password_is_received");
            let addr = subject.start();

            addr.try_send(BindMessage {
                peer_actors: peer_actors_builder().ui_gateway(ui_gateway).build(),
            })
            .unwrap();
            addr.try_send(SetWalletPasswordMsg {
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
                data: UiMessage::SetWalletPasswordResponse(true)
            }
        );
        TestLogHandler::new().exists_log_containing(&format!(
            "unlocked consuming wallet address {:?}",
            expected_wallet
        ));
    }

    #[test]
    fn blockchain_bridge_logs_warning_when_setting_wallet_with_bad_password() {
        init_test_logging();
        let (ui_gateway, ui_gateway_awaiter, ui_gateway_recording_arc) = make_recorder();

        thread::spawn(move || {
            let persistent_config_mock = PersistentConfigurationMock::default()
                .mnemonic_seed_result(Err(Bip39Error::DecryptionFailure(
                    "InvalidPassword".to_string(),
                )))
                .consuming_wallet_derivation_path_result(Some(
                    DEFAULT_CONSUMING_DERIVATION_PATH.to_string(),
                ));

            let subject = BlockchainBridge::new(
                &bc_from_bbc_plus(
                    BlockchainBridgeConfig {
                        blockchain_service_url: None,
                        contract_address: TESTNET_CONTRACT_ADDRESS,
                    },
                    None,
                ),
                stub_bi(),
                Box::new(persistent_config_mock),
            );

            let system = System::new("blockchain_bridge_sets_wallet_when_password_is_received");
            let addr = subject.start();

            addr.try_send(BindMessage {
                peer_actors: peer_actors_builder().ui_gateway(ui_gateway).build(),
            })
            .unwrap();
            addr.try_send(SetWalletPasswordMsg {
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
                data: UiMessage::SetWalletPasswordResponse(false)
            }
        );
        TestLogHandler::new().exists_log_containing(&format!(
            "failed to unlock consuming wallet: DecryptionFailure(\"InvalidPassword\")"
        ));
    }

    #[test]
    fn blockchain_bridge_logs_error_when_setting_wallet_password_when_wallet_already_exists() {
        init_test_logging();
        let (ui_gateway, ui_gateway_awaiter, ui_gateway_recording_arc) = make_recorder();
        thread::spawn(move || {
            let persistent_config_mock = PersistentConfigurationMock::default();

            let subject = BlockchainBridge::new(
                &bc_from_bbc_plus(
                    BlockchainBridgeConfig {
                        blockchain_service_url: None,
                        contract_address: TESTNET_CONTRACT_ADDRESS,
                    },
                    Some(Wallet::new("0x0000000000000000000000000000000000000000")),
                ),
                stub_bi(),
                Box::new(persistent_config_mock),
            );

            let system = System::new(
                "blockchain_bridge_logs_error_when_setting_wallet_password_when_wallet_already_exists",
            );
            let addr = subject.start();

            addr.try_send(BindMessage {
                peer_actors: peer_actors_builder().ui_gateway(ui_gateway).build(),
            })
            .unwrap();
            addr.try_send(SetWalletPasswordMsg {
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
                data: UiMessage::SetWalletPasswordResponse(false)
            }
        );
        TestLogHandler::new().exists_log_containing(&format!(
            "Wallet password rejected: consuming wallet already active"
        ));
    }

    #[test]
    fn blockchain_bridge_logs_error_when_setting_wallet_password_when_no_consuming_wallet_derivation_path(
    ) {
        init_test_logging();
        let (ui_gateway, ui_gateway_awaiter, ui_gateway_recording_arc) = make_recorder();
        thread::spawn(move || {
            let persistent_config_mock =
                PersistentConfigurationMock::new().consuming_wallet_derivation_path_result(None);

            let subject = BlockchainBridge::new(
                &bc_from_bbc_plus(
                    BlockchainBridgeConfig {
                        blockchain_service_url: None,
                        contract_address: TESTNET_CONTRACT_ADDRESS,
                    },
                    None,
                ),
                stub_bi(),
                Box::new(persistent_config_mock),
            );

            let system = System::new("blockchain_bridge_logs_error_when_setting_wallet_password_when_no_consuming_wallet_derivation_path");
            let addr = subject.start();

            addr.try_send(BindMessage {
                peer_actors: peer_actors_builder().ui_gateway(ui_gateway).build(),
            })
            .unwrap();
            addr.try_send(SetWalletPasswordMsg {
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
                data: UiMessage::SetWalletPasswordResponse(false)
            }
        );
        TestLogHandler::new().exists_log_containing(&format!(
            "Wallet password rejected: no consuming wallet derivation path has been configured"
        ));
    }

    #[test]
    fn blockchain_bridge_logs_error_when_setting_wallet_password_when_no_mnemonic_seed() {
        init_test_logging();
        let (ui_gateway, ui_gateway_awaiter, ui_gateway_recording_arc) = make_recorder();
        thread::spawn(move || {
            let persistent_config_mock = PersistentConfigurationMock::new()
                .consuming_wallet_derivation_path_result(Some("m/44'/60'/1'/2/3".to_string()))
                .mnemonic_seed_result(Err(Bip39Error::NotPresent));

            let subject = BlockchainBridge::new(
                &bc_from_bbc_plus(
                    BlockchainBridgeConfig {
                        blockchain_service_url: None,
                        contract_address: TESTNET_CONTRACT_ADDRESS,
                    },
                    None,
                ),
                stub_bi(),
                Box::new(persistent_config_mock),
            );

            let system = System::new(
                "blockchain_bridge_logs_error_when_setting_wallet_password_when_no_mnemonic_seed",
            );
            let addr = subject.start();

            addr.try_send(BindMessage {
                peer_actors: peer_actors_builder().ui_gateway(ui_gateway).build(),
            })
            .unwrap();
            addr.try_send(SetWalletPasswordMsg {
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
                data: UiMessage::SetWalletPasswordResponse(false)
            }
        );
        TestLogHandler::new().exists_log_containing(&format!(
            "Wallet password rejected: no mnemonic phrase has been configured"
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
            &bc_from_bbc_plus(
                BlockchainBridgeConfig {
                    blockchain_service_url: None,
                    contract_address: TESTNET_CONTRACT_ADDRESS,
                },
                Some(consuming_wallet.clone()),
            ),
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
            &bc_from_bbc_plus(
                BlockchainBridgeConfig {
                    blockchain_service_url: None,
                    contract_address: TESTNET_CONTRACT_ADDRESS,
                },
                None,
            ),
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
    fn blockchain_bridge_receives_report_accounts_payable_message_and_logs() {
        init_test_logging();

        let subject = BlockchainBridge::new(
            &bc_from_bbc_plus(
                BlockchainBridgeConfig {
                    blockchain_service_url: None,
                    contract_address: TESTNET_CONTRACT_ADDRESS,
                },
                None,
            ),
            stub_bi(),
            Box::new(PersistentConfigurationMock::default()),
        );

        let system = System::new("blockchain_bridge_receives_report_accounts_payable_message");
        let addr: Addr<BlockchainBridge> = subject.start();

        addr.try_send(ReportAccountsPayable { accounts: vec![] })
            .unwrap();

        System::current().stop_with_code(0);
        system.run();
        TestLogHandler::new().exists_log_containing(
            "DEBUG: BlockchainBridge: Received ReportAccountsPayable message",
        );
    }

    #[derive(Default)]
    struct BlockchainInterfaceMock {
        pub retrieve_transactions_parameters: Arc<Mutex<Vec<(u64, Wallet)>>>,
        pub retrieve_transactions_results: RefCell<Vec<Result<Vec<Transaction>, BlockchainError>>>,
    }

    impl BlockchainInterfaceMock {
        fn retrieve_transactions_result(
            self,
            result: Result<Vec<Transaction>, BlockchainError>,
        ) -> Self {
            self.retrieve_transactions_results.borrow_mut().push(result);
            self
        }
    }

    impl BlockchainInterface for BlockchainInterfaceMock {
        fn retrieve_transactions(&self, start_block: u64, recipient: &Wallet) -> Transactions {
            self.retrieve_transactions_parameters
                .lock()
                .unwrap()
                .push((start_block, recipient.clone()));
            self.retrieve_transactions_results.borrow_mut().remove(0)
        }

        fn get_eth_balance(&self, _address: &Wallet) -> Balance {
            unimplemented!()
        }

        fn get_token_balance(&self, _address: &Wallet) -> Balance {
            unimplemented!()
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
        let blockchain_interface_mock =
            BlockchainInterfaceMock::default().retrieve_transactions_result(result);
        let retrieve_transactions_parameters = blockchain_interface_mock
            .retrieve_transactions_parameters
            .clone();
        let subject = BlockchainBridge::new(
            &bc_from_bbc_plus(
                BlockchainBridgeConfig {
                    blockchain_service_url: None,
                    contract_address: TESTNET_CONTRACT_ADDRESS,
                },
                None,
            ),
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

    fn bc_from_bbc_plus(
        bbc: BlockchainBridgeConfig,
        consuming_wallet: Option<Wallet>,
    ) -> BootstrapperConfig {
        let mut bc = BootstrapperConfig::new();
        bc.blockchain_bridge_config = bbc;
        bc.consuming_wallet = consuming_wallet;
        bc
    }
}
