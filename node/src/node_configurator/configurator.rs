use std::path::PathBuf;

use actix::{Actor, Context, Handler, Recipient};

use masq_lib::messages::{
    FromMessageBody, ToMessageBody, UiChangePasswordRequest, UiChangePasswordResponse,
    UiCheckPasswordRequest, UiCheckPasswordResponse, UiGenerateWalletsRequest,
    UiGenerateWalletsResponse, UiNewPasswordBroadcast, UiRecoverWalletsRequest,
    UiRecoverWalletsResponse,
};
use masq_lib::ui_gateway::MessageTarget::ClientId;
use masq_lib::ui_gateway::{
    MessageBody, MessagePath, MessageTarget, NodeFromUiMessage, NodeToUiMessage,
};

use crate::blockchain::bip32::Bip32ECKeyPair;
use crate::blockchain::bip39::Bip39;
use crate::database::db_initializer::{DbInitializer, DbInitializerReal};
use crate::db_config::config_dao::ConfigDaoReal;
use crate::db_config::persistent_configuration::{
    PersistentConfiguration, PersistentConfigurationReal,
};
use crate::sub_lib::configurator::NewPasswordMessage;
use crate::sub_lib::logger::Logger;
use crate::sub_lib::peer_actors::BindMessage;
use crate::sub_lib::wallet::{Wallet, WalletError};
use bip39::{Language, Mnemonic, MnemonicType, Seed};
use std::str::FromStr;

pub const CONFIGURATOR_PREFIX: u64 = 0x0001_0000_0000_0000;
pub const CONFIGURATOR_READ_ERROR: u64 = CONFIGURATOR_PREFIX | 1;
pub const CONFIGURATOR_WRITE_ERROR: u64 = CONFIGURATOR_PREFIX | 2;
pub const UNRECOGNIZED_MNEMONIC_LANGUAGE_ERROR: u64 = CONFIGURATOR_PREFIX | 3;
pub const ILLEGAL_MNEMONIC_WORD_COUNT_ERROR: u64 = CONFIGURATOR_PREFIX | 4;
pub const KEY_PAIR_CONSTRUCTION_ERROR: u64 = CONFIGURATOR_PREFIX | 5;
pub const BAD_PASSWORD_ERROR: u64 = CONFIGURATOR_PREFIX | 6;
pub const ALREADY_INITIALIZED_ERROR: u64 = CONFIGURATOR_PREFIX | 7;
pub const DERIVATION_PATH_ERROR: u64 = CONFIGURATOR_PREFIX | 8;
pub const MNEMONIC_PHRASE_ERROR: u64 = CONFIGURATOR_PREFIX | 9;

pub struct Configurator {
    persistent_config: Box<dyn PersistentConfiguration>,
    node_to_ui_sub: Option<Recipient<NodeToUiMessage>>,
    new_password_subs: Option<Vec<Recipient<NewPasswordMessage>>>,
    logger: Logger,
}

impl Actor for Configurator {
    type Context = Context<Self>;
}

impl Handler<BindMessage> for Configurator {
    type Result = ();

    fn handle(&mut self, msg: BindMessage, _ctx: &mut Self::Context) -> Self::Result {
        self.node_to_ui_sub = Some(msg.peer_actors.ui_gateway.node_to_ui_message_sub.clone());
        self.new_password_subs = Some(vec![msg.peer_actors.neighborhood.new_password_sub])
    }
}

impl Handler<NodeFromUiMessage> for Configurator {
    type Result = ();

    fn handle(&mut self, msg: NodeFromUiMessage, _ctx: &mut Self::Context) -> Self::Result {
        if let Ok((body, context_id)) = UiCheckPasswordRequest::fmb(msg.clone().body) {
            debug!(
                &self.logger,
                "Handling {} message from client {}", msg.body.opcode, msg.client_id
            );
            let response = self.handle_check_password(body, context_id);
            self.send_to_ui_gateway(ClientId(msg.client_id), response);
        } else if let Ok((body, context_id)) = UiChangePasswordRequest::fmb(msg.clone().body) {
            debug!(
                &self.logger,
                "Handling {} message from client {}", msg.body.opcode, msg.client_id
            );
            let response = self.handle_change_password(body, msg.client_id, context_id);
            self.send_to_ui_gateway(ClientId(msg.client_id), response);
        } else if let Ok((body, context_id)) = UiGenerateWalletsRequest::fmb(msg.clone().body) {
            debug!(
                &self.logger,
                "Handling {} message from client {}", msg.body.opcode, msg.client_id
            );
            let response = self.handle_generate_wallets(body, context_id);
            debug!(
                &self.logger,
                "Sending response to generateWallets command:\n{:?}", response
            );
            self.send_to_ui_gateway(ClientId(msg.client_id), response);
        } else if let Ok((body, context_id)) = UiRecoverWalletsRequest::fmb(msg.clone().body) {
            debug!(
                &self.logger,
                "Handling {} message from client {}", msg.body.opcode, msg.client_id
            );
            let response = self.handle_recover_wallets(body, context_id);
            debug!(
                &self.logger,
                "Sending response to recoverWallets command:\n{:?}", response
            );
            self.send_to_ui_gateway(ClientId(msg.client_id), response);
        }
    }
}

impl From<Box<dyn PersistentConfiguration>> for Configurator {
    fn from(persistent_config: Box<dyn PersistentConfiguration>) -> Self {
        Configurator {
            persistent_config,
            node_to_ui_sub: None,
            new_password_subs: None,
            logger: Logger::new("Configurator"),
        }
    }
}

type MessageError = (u64, String);

impl Configurator {
    pub fn new(data_directory: PathBuf, chain_id: u8) -> Self {
        let initializer = DbInitializerReal::new();
        let conn = initializer
            .initialize(&data_directory, chain_id, false)
            .expect("Couldn't initialize database");
        let config_dao = ConfigDaoReal::new(conn);
        let persistent_config: Box<dyn PersistentConfiguration> =
            Box::new(PersistentConfigurationReal::new(Box::new(config_dao)));
        Configurator::from(persistent_config)
    }

    fn handle_check_password(
        &mut self,
        msg: UiCheckPasswordRequest,
        context_id: u64,
    ) -> MessageBody {
        match self
            .persistent_config
            .check_password(msg.db_password_opt.clone())
        {
            Ok(matches) => UiCheckPasswordResponse { matches }.tmb(context_id),
            Err(e) => {
                warning!(self.logger, "Failed to check password: {:?}", e);
                MessageBody {
                    opcode: msg.opcode().to_string(),
                    path: MessagePath::Conversation(context_id),
                    payload: Err((CONFIGURATOR_WRITE_ERROR, format!("{:?}", e))),
                }
            }
        }
    }

    fn handle_change_password(
        &mut self,
        msg: UiChangePasswordRequest,
        client_id: u64,
        context_id: u64,
    ) -> MessageBody {
        match self
            .persistent_config
            .change_password(msg.old_password_opt.clone(), &msg.new_password)
        {
            Ok(_) => {
                let broadcast = UiNewPasswordBroadcast {}.tmb(0);
                self.send_password_changes(msg.new_password.clone());
                self.send_to_ui_gateway(MessageTarget::AllExcept(client_id), broadcast);
                UiChangePasswordResponse {}.tmb(context_id)
            }

            Err(e) => {
                warning!(self.logger, "Failed to change password: {:?}", e);
                MessageBody {
                    opcode: msg.opcode().to_string(),
                    path: MessagePath::Conversation(context_id),
                    payload: Err((CONFIGURATOR_WRITE_ERROR, format!("{:?}", e))),
                }
            }
        }
    }

    fn handle_generate_wallets(
        &mut self,
        msg: UiGenerateWalletsRequest,
        context_id: u64,
    ) -> MessageBody {
        match Self::unfriendly_handle_generate_wallets(msg, context_id, &mut self.persistent_config)
        {
            Ok(message_body) => message_body,
            Err((code, msg)) => MessageBody {
                opcode: "generateWallets".to_string(),
                path: MessagePath::Conversation(context_id),
                payload: Err((code, msg)),
            },
        }
    }

    fn handle_recover_wallets(
        &mut self,
        msg: UiRecoverWalletsRequest,
        context_id: u64,
    ) -> MessageBody {
        match Self::unfriendly_handle_recover_wallets(msg, context_id, &mut self.persistent_config)
        {
            Ok(message_body) => message_body,
            Err((code, msg)) => MessageBody {
                opcode: "recoverWallets".to_string(),
                path: MessagePath::Conversation(context_id),
                payload: Err((code, msg)),
            },
        }
    }

    fn unfriendly_handle_generate_wallets(
        msg: UiGenerateWalletsRequest,
        context_id: u64,
        persistent_config: &mut Box<dyn PersistentConfiguration>,
    ) -> Result<MessageBody, MessageError> {
        Self::check_preconditions(persistent_config, "generate", &msg.db_password)?;
        let (seed, mnemonic_phrase) = Self::generate_mnemonic(
            &msg.mnemonic_passphrase_opt,
            &msg.mnemonic_phrase_language,
            msg.mnemonic_phrase_size,
        )?;
        let consuming_wallet = Self::generate_wallet(&seed, &msg.consuming_derivation_path)?;
        let earning_wallet = Self::generate_wallet(&seed, &msg.earning_derivation_path)?;
        Self::set_wallet_info(
            persistent_config,
            &seed,
            &msg.consuming_derivation_path,
            &earning_wallet.string_address_from_keypair(),
            &msg.db_password,
        )?;
        Ok(UiGenerateWalletsResponse {
            mnemonic_phrase,
            consuming_wallet_address: consuming_wallet.string_address_from_keypair(),
            earning_wallet_address: earning_wallet.string_address_from_keypair(),
        }
        .tmb(context_id))
    }

    fn unfriendly_handle_recover_wallets(
        msg: UiRecoverWalletsRequest,
        context_id: u64,
        persistent_config: &mut Box<dyn PersistentConfiguration>,
    ) -> Result<MessageBody, MessageError> {
        Self::check_preconditions(persistent_config, "recover", &msg.db_password)?;
        let language = Self::parse_language(&msg.mnemonic_phrase_language)?;
        let mnemonic = match Mnemonic::from_phrase(msg.mnemonic_phrase.join(" "), language) {
            Ok(m) => m,
            Err(e) => {
                return Err((
                    MNEMONIC_PHRASE_ERROR,
                    format!("Couldn't make a mnemonic out of the supplied phrase: {}", e),
                ))
            }
        };
        let passphrase = msg.mnemonic_passphrase_opt.unwrap_or_default();
        let seed = Seed::new(&mnemonic, &passphrase);
        let _ = Self::generate_wallet(&seed, &msg.consuming_derivation_path)?;
        let earning_wallet = match Wallet::from_str(&msg.earning_wallet) {
            Ok(w) => w,
            Err(WalletError::InvalidAddress) => Self::generate_wallet(&seed, &msg.earning_wallet)?,
            Err(e) => panic!("Unexpected error making Wallet from address: {:?}", e),
        };
        Self::set_wallet_info(
            persistent_config,
            &seed,
            &msg.consuming_derivation_path,
            &earning_wallet.string_address_from_keypair(),
            &msg.db_password,
        )?;
        Ok(UiRecoverWalletsResponse {}.tmb(context_id))
    }

    #[allow(clippy::borrowed_box)]
    fn check_preconditions(
        persistent_config: &Box<dyn PersistentConfiguration>,
        operation: &str,
        db_password: &str,
    ) -> Result<(), MessageError> {
        match persistent_config.check_password(Some(db_password.to_string())) {
            Err(e) => {
                return Err((
                    CONFIGURATOR_READ_ERROR,
                    format!("Error checking password: {:?}", e),
                ))
            }
            Ok(true) => (),
            Ok(false) => {
                return Err((
                    BAD_PASSWORD_ERROR,
                    format!("Bad password; can't {} wallets", operation),
                ))
            }
        }
        match persistent_config.mnemonic_seed_exists() {
            Err(e) => {
                return Err((
                    CONFIGURATOR_READ_ERROR,
                    format!("Error checking mnemonic seed: {:?}", e),
                ))
            }
            Ok(true) => {
                return Err((
                    ALREADY_INITIALIZED_ERROR,
                    format!(
                        "Node already has a wallet pair; can't {} another",
                        operation
                    ),
                ))
            }
            Ok(false) => (),
        }
        Ok(())
    }

    fn generate_mnemonic(
        passphrase_opt: &Option<String>,
        language_str: &str,
        word_count: usize,
    ) -> Result<(Seed, Vec<String>), MessageError> {
        let language = Self::parse_language(language_str)?;
        let mnemonic_type = Self::parse_word_count(word_count)?;
        let mnemonic = Bip39::mnemonic(mnemonic_type, language);
        let mnemonic_passphrase = match passphrase_opt {
            Some(phrase) => phrase.to_string(),
            None => "".to_string(),
        };
        let seed = Bip39::seed(&mnemonic, &mnemonic_passphrase);
        let phrase_words: Vec<String> = mnemonic
            .into_phrase()
            .split(' ')
            .map(|w| w.to_string())
            .collect();
        Ok((seed, phrase_words))
    }

    fn parse_language(language_str: &str) -> Result<Language, MessageError> {
        match vec![
            ("English", Language::English),
            ("Chinese", Language::ChineseSimplified),
            ("Traditional Chinese", Language::ChineseTraditional),
            ("French", Language::French),
            ("Italian", Language::Italian),
            ("Japanese", Language::Japanese),
            ("Korean", Language::Korean),
            ("Spanish", Language::Spanish),
        ]
        .into_iter()
        .find(|(name, _)| name == &language_str)
        {
            Some((_, language)) => Ok(language),
            None => Err((
                UNRECOGNIZED_MNEMONIC_LANGUAGE_ERROR,
                language_str.to_string(),
            )),
        }
    }

    fn parse_word_count(word_count: usize) -> Result<MnemonicType, MessageError> {
        match vec![
            MnemonicType::Words12,
            MnemonicType::Words15,
            MnemonicType::Words18,
            MnemonicType::Words21,
            MnemonicType::Words24,
        ]
        .into_iter()
        .find(|mt| mt.word_count() == word_count)
        {
            Some(mt) => Ok(mt),
            None => Err((ILLEGAL_MNEMONIC_WORD_COUNT_ERROR, word_count.to_string())),
        }
    }

    fn generate_wallet(seed: &Seed, derivation_path: &str) -> Result<Wallet, MessageError> {
        match Bip32ECKeyPair::from_raw(seed.as_bytes(), derivation_path) {
            Err(e) => Err((
                DERIVATION_PATH_ERROR,
                format!("Bad derivation-path syntax: {}: {}", e, derivation_path),
            )),
            Ok(kp) => Ok(Wallet::from(kp)),
        }
    }

    fn set_wallet_info(
        persistent_config: &mut Box<dyn PersistentConfiguration>,
        seed: &dyn AsRef<[u8]>,
        consuming_derivation_path: &str,
        earning_wallet_address: &str,
        db_password: &str,
    ) -> Result<(), MessageError> {
        if let Err(e) = persistent_config.set_wallet_info(
            seed,
            consuming_derivation_path,
            earning_wallet_address,
            db_password,
        ) {
            return Err((
                CONFIGURATOR_WRITE_ERROR,
                format!("Wallet information could not be set: {:?}", e),
            ));
        }
        Ok(())
    }

    fn send_to_ui_gateway(&self, target: MessageTarget, body: MessageBody) {
        let msg = NodeToUiMessage { target, body };
        self.node_to_ui_sub
            .as_ref()
            .expect("Configurator is unbound")
            .try_send(msg)
            .expect("UiGateway is dead");
    }

    fn send_password_changes(&self, new_password: String) {
        let msg = NewPasswordMessage { new_password };
        self.new_password_subs
            .as_ref()
            .expect("Configurator is unbound")
            .iter()
            .for_each(|sub| {
                sub.try_send(msg.clone())
                    .expect("New password recipient is dead")
            });
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use actix::System;

    use masq_lib::messages::{
        ToMessageBody, UiChangePasswordResponse, UiCheckPasswordRequest, UiCheckPasswordResponse,
        UiGenerateWalletsResponse, UiNewPasswordBroadcast, UiStartOrder,
    };
    use masq_lib::ui_gateway::{MessagePath, MessageTarget};

    use crate::db_config::persistent_configuration::{
        PersistentConfigError, PersistentConfigurationReal,
    };
    use crate::test_utils::logging::{init_test_logging, TestLogHandler};
    use crate::test_utils::persistent_configuration_mock::PersistentConfigurationMock;
    use crate::test_utils::recorder::{make_recorder, peer_actors_builder};

    use super::*;
    use crate::blockchain::bip32::Bip32ECKeyPair;
    use crate::blockchain::bip39::Bip39;
    use crate::database::db_initializer::{DbInitializer, DbInitializerReal};
    use crate::sub_lib::cryptde::PlainData;
    use crate::sub_lib::wallet::Wallet;
    use bip39::{Language, Mnemonic};
    use masq_lib::test_utils::utils::{ensure_node_home_directory_exists, DEFAULT_CHAIN_ID};
    use masq_lib::utils::derivation_path;

    #[test]
    fn constructor_connects_with_database() {
        let data_dir =
            ensure_node_home_directory_exists("configurator", "constructor_connects_with_database");
        let verifier = PersistentConfigurationReal::new(Box::new(ConfigDaoReal::new(
            DbInitializerReal::new()
                .initialize(&data_dir, DEFAULT_CHAIN_ID, true)
                .unwrap(),
        )));
        let (recorder, _, _) = make_recorder();
        let recorder_addr = recorder.start();
        let mut subject = Configurator::new(data_dir, DEFAULT_CHAIN_ID);
        subject.node_to_ui_sub = Some(recorder_addr.recipient());
        subject.new_password_subs = Some(vec![]);

        let _ = subject.handle_change_password(
            UiChangePasswordRequest {
                old_password_opt: None,
                new_password: "password".to_string(),
            },
            0,
            0,
        );

        assert_eq!(
            verifier.check_password(Some("password".to_string())),
            Ok(true)
        )
    }

    #[test]
    fn ignores_unexpected_message() {
        let system = System::new("test");
        let subject = make_subject(None);
        let subject_addr = subject.start();
        let (ui_gateway, _, ui_gateway_recording) = make_recorder();
        let peer_actors = peer_actors_builder().ui_gateway(ui_gateway).build();
        subject_addr.try_send(BindMessage { peer_actors }).unwrap();

        subject_addr
            .try_send(NodeFromUiMessage {
                client_id: 1234,
                body: UiStartOrder {}.tmb(4321),
            })
            .unwrap();

        System::current().stop();
        system.run();
        let recording = ui_gateway_recording.lock().unwrap();
        assert_eq!(recording.len(), 0);
    }

    #[test]
    fn check_password_works() {
        let system = System::new("test");
        let check_password_params_arc = Arc::new(Mutex::new(vec![]));
        let persistent_config = PersistentConfigurationMock::new()
            .check_password_params(&check_password_params_arc)
            .check_password_result(Ok(false));
        let subject = make_subject(Some(persistent_config));
        let subject_addr = subject.start();
        let (ui_gateway, _, ui_gateway_recording_arc) = make_recorder();
        let peer_actors = peer_actors_builder().ui_gateway(ui_gateway).build();
        subject_addr.try_send(BindMessage { peer_actors }).unwrap();

        subject_addr
            .try_send(NodeFromUiMessage {
                client_id: 1234,
                body: UiCheckPasswordRequest {
                    db_password_opt: Some("password".to_string()),
                }
                .tmb(4321),
            })
            .unwrap();

        System::current().stop();
        system.run();
        let check_password_params = check_password_params_arc.lock().unwrap();
        assert_eq!(*check_password_params, vec![Some("password".to_string())]);
        let ui_gateway_recording = ui_gateway_recording_arc.lock().unwrap();
        assert_eq!(
            ui_gateway_recording.get_record::<NodeToUiMessage>(0),
            &NodeToUiMessage {
                target: MessageTarget::ClientId(1234),
                body: UiCheckPasswordResponse { matches: false }.tmb(4321)
            }
        );
        assert_eq!(ui_gateway_recording.len(), 1);
    }

    #[test]
    fn handle_check_password_handles_error() {
        init_test_logging();
        let persistent_config = PersistentConfigurationMock::new()
            .check_password_result(Err(PersistentConfigError::NotPresent));
        let mut subject = make_subject(Some(persistent_config));
        let msg = UiCheckPasswordRequest {
            db_password_opt: None,
        };

        let result = subject.handle_check_password(msg, 4321);

        assert_eq!(
            result,
            MessageBody {
                opcode: "checkPassword".to_string(),
                path: MessagePath::Conversation(4321),
                payload: Err((CONFIGURATOR_WRITE_ERROR, "NotPresent".to_string()))
            }
        );
        TestLogHandler::new()
            .exists_log_containing("WARN: Configurator: Failed to check password: NotPresent");
    }

    #[test]
    fn change_password_works() {
        let system = System::new("test");
        let change_password_params_arc = Arc::new(Mutex::new(vec![]));
        let persistent_config = PersistentConfigurationMock::new()
            .change_password_params(&change_password_params_arc)
            .change_password_result(Ok(()));
        let subject = make_subject(Some(persistent_config));
        let subject_addr = subject.start();
        let (ui_gateway, _, ui_gateway_recording_arc) = make_recorder();
        let (neighborhood, _, neighborhood_recording_arc) = make_recorder();
        let peer_actors = peer_actors_builder()
            .ui_gateway(ui_gateway)
            .neighborhood(neighborhood)
            .build();
        subject_addr.try_send(BindMessage { peer_actors }).unwrap();

        subject_addr
            .try_send(NodeFromUiMessage {
                client_id: 1234,
                body: UiChangePasswordRequest {
                    old_password_opt: Some("old_password".to_string()),
                    new_password: "new_password".to_string(),
                }
                .tmb(4321),
            })
            .unwrap();

        System::current().stop();
        system.run();
        let change_password_params = change_password_params_arc.lock().unwrap();
        assert_eq!(
            *change_password_params,
            vec![(Some("old_password".to_string()), "new_password".to_string())]
        );
        let ui_gateway_recording = ui_gateway_recording_arc.lock().unwrap();
        assert_eq!(
            ui_gateway_recording.get_record::<NodeToUiMessage>(0),
            &NodeToUiMessage {
                target: MessageTarget::AllExcept(1234),
                body: UiNewPasswordBroadcast {}.tmb(0)
            }
        );
        assert_eq!(
            ui_gateway_recording.get_record::<NodeToUiMessage>(1),
            &NodeToUiMessage {
                target: MessageTarget::ClientId(1234),
                body: UiChangePasswordResponse {}.tmb(4321)
            }
        );
        let neighborhood_recording = neighborhood_recording_arc.lock().unwrap();
        assert_eq!(
            neighborhood_recording.get_record::<NewPasswordMessage>(0),
            &NewPasswordMessage {
                new_password: "new_password".to_string()
            }
        );
        assert_eq!(neighborhood_recording.len(), 1);
    }

    #[test]
    fn handle_change_password_handles_error() {
        init_test_logging();
        let persistent_config = PersistentConfigurationMock::new().change_password_result(Err(
            PersistentConfigError::DatabaseError("Didn't work good".to_string()),
        ));
        let mut subject = make_subject(Some(persistent_config));
        let msg = UiChangePasswordRequest {
            old_password_opt: None,
            new_password: "".to_string(),
        };

        let result = subject.handle_change_password(msg, 1234, 4321);

        assert_eq!(
            result,
            MessageBody {
                opcode: "changePassword".to_string(),
                path: MessagePath::Conversation(4321),
                payload: Err((
                    CONFIGURATOR_WRITE_ERROR,
                    r#"DatabaseError("Didn\'t work good")"#.to_string()
                )),
            }
        );
        TestLogHandler::new().exists_log_containing(
            r#"WARN: Configurator: Failed to change password: DatabaseError("Didn\'t work good")"#,
        );
    }

    #[test]
    fn handle_generate_wallets_works() {
        let check_password_params_arc = Arc::new(Mutex::new(vec![]));
        let set_wallet_info_params_arc = Arc::new(Mutex::new(vec![]));
        let (ui_gateway, _, ui_gateway_recording_arc) = make_recorder();
        let persistent_config = PersistentConfigurationMock::new()
            .check_password_params(&check_password_params_arc)
            .check_password_result(Ok(true))
            .mnemonic_seed_exists_result(Ok(false))
            .set_wallet_info_params(&set_wallet_info_params_arc)
            .set_wallet_info_result(Ok(()));
        let subject = make_subject(Some(persistent_config));
        let subject_addr = subject.start();
        let peer_actors = peer_actors_builder().ui_gateway(ui_gateway).build();
        subject_addr.try_send(BindMessage { peer_actors }).unwrap();

        subject_addr
            .try_send(NodeFromUiMessage {
                client_id: 1234,
                body: make_example_generate_wallets_request().tmb(4321),
            })
            .unwrap();

        let system = System::new("test");
        System::current().stop();
        system.run();
        let ui_gateway_recording = ui_gateway_recording_arc.lock().unwrap();
        let response = ui_gateway_recording.get_record::<NodeToUiMessage>(0);
        let (generated_wallets, context_id) =
            UiGenerateWalletsResponse::fmb(response.body.clone()).unwrap();
        assert_eq!(context_id, 4321);
        assert_eq!(generated_wallets.mnemonic_phrase.len(), 24);
        let mnemonic_phrase = generated_wallets.mnemonic_phrase.join(" ");
        let mnemonic = Mnemonic::from_phrase(&mnemonic_phrase, Language::English).unwrap();
        let seed = PlainData::new(Bip39::seed(&mnemonic, "booga").as_ref());
        let consuming_wallet = Wallet::from(
            Bip32ECKeyPair::from_raw(seed.as_slice(), &derivation_path(0, 4)).unwrap(),
        );
        assert_eq!(
            generated_wallets.consuming_wallet_address,
            consuming_wallet.string_address_from_keypair()
        );
        let earning_wallet = Wallet::from(
            Bip32ECKeyPair::from_raw(seed.as_slice(), &derivation_path(0, 5)).unwrap(),
        );
        assert_eq!(
            generated_wallets.earning_wallet_address,
            earning_wallet.string_address_from_keypair()
        );
        let check_password_params = check_password_params_arc.lock().unwrap();
        assert_eq!(*check_password_params, vec![Some("password".to_string())]);

        let set_wallet_info_params = set_wallet_info_params_arc.lock().unwrap();
        assert_eq!(
            *set_wallet_info_params,
            vec![(
                seed,
                derivation_path(0, 4),
                earning_wallet.string_address_from_keypair(),
                "password".to_string(),
            )]
        );
    }

    #[test]
    fn handle_generate_wallets_works_if_check_password_fails() {
        let persistent_config = PersistentConfigurationMock::new()
            .check_password_result(Err(PersistentConfigError::NotPresent));
        let mut subject = make_subject(Some(persistent_config));

        let result = subject.handle_generate_wallets(make_example_generate_wallets_request(), 4321);

        assert_eq!(
            result,
            MessageBody {
                opcode: "generateWallets".to_string(),
                path: MessagePath::Conversation(4321),
                payload: Err((
                    CONFIGURATOR_READ_ERROR,
                    "Error checking password: NotPresent".to_string()
                ))
            }
        )
    }

    #[test]
    fn handle_generate_wallets_works_if_password_is_incorrect() {
        let persistent_config = PersistentConfigurationMock::new().check_password_result(Ok(false));
        let mut subject = make_subject(Some(persistent_config));

        let result = subject.handle_generate_wallets(make_example_generate_wallets_request(), 4321);

        assert_eq!(
            result,
            MessageBody {
                opcode: "generateWallets".to_string(),
                path: MessagePath::Conversation(4321),
                payload: Err((
                    BAD_PASSWORD_ERROR,
                    "Bad password; can't generate wallets".to_string()
                ))
            }
        )
    }

    #[test]
    fn handle_generate_wallets_works_if_mnemonic_seed_cant_be_read() {
        let persistent_config = PersistentConfigurationMock::new()
            .check_password_result(Ok(true))
            .mnemonic_seed_exists_result(Err(PersistentConfigError::NotPresent));
        let mut subject = make_subject(Some(persistent_config));

        let result = subject.handle_generate_wallets(make_example_generate_wallets_request(), 4321);

        assert_eq!(
            result,
            MessageBody {
                opcode: "generateWallets".to_string(),
                path: MessagePath::Conversation(4321),
                payload: Err((
                    CONFIGURATOR_READ_ERROR,
                    "Error checking mnemonic seed: NotPresent".to_string()
                ))
            }
        )
    }

    #[test]
    fn handle_generate_wallets_manages_error_if_chosen_language_isnt_in_list() {
        let persistent_config = PersistentConfigurationMock::new()
            .check_password_result(Ok(true))
            .mnemonic_seed_exists_result(Ok(false));
        let mut subject = make_subject(Some(persistent_config));
        let msg = UiGenerateWalletsRequest {
            db_password: "blabla".to_string(),
            mnemonic_phrase_size: 24,
            mnemonic_phrase_language: "SuperSpecial".to_string(),
            mnemonic_passphrase_opt: None,
            consuming_derivation_path: derivation_path(0, 4),
            earning_derivation_path: derivation_path(0, 5),
        };

        let result = subject.handle_generate_wallets(msg, 4321);

        assert_eq!(
            result,
            MessageBody {
                opcode: "generateWallets".to_string(),
                path: MessagePath::Conversation(4321),
                payload: Err((
                    UNRECOGNIZED_MNEMONIC_LANGUAGE_ERROR,
                    "SuperSpecial".to_string()
                ))
            }
        )
    }

    #[test]
    fn handle_generate_wallets_works_if_mnemonic_seed_is_already_set() {
        let persistent_config = PersistentConfigurationMock::new()
            .check_password_result(Ok(true))
            .mnemonic_seed_exists_result(Ok(true));
        let mut subject = make_subject(Some(persistent_config));

        let result = subject.handle_generate_wallets(make_example_generate_wallets_request(), 4321);

        assert_eq!(
            result,
            MessageBody {
                opcode: "generateWallets".to_string(),
                path: MessagePath::Conversation(4321),
                payload: Err((
                    ALREADY_INITIALIZED_ERROR,
                    "Node already has a wallet pair; can't generate another".to_string()
                ))
            }
        )
    }

    #[test]
    fn handle_generate_wallets_works_if_wallet_info_cant_be_set() {
        let persistent_config = PersistentConfigurationMock::new()
            .check_password_result(Ok(true))
            .mnemonic_seed_exists_result(Ok(false))
            .set_wallet_info_result(Err(PersistentConfigError::BadDerivationPathFormat(
                "booga".to_string(),
            )));
        let mut subject = make_subject(Some(persistent_config));

        let result = subject.handle_generate_wallets(make_example_generate_wallets_request(), 4321);

        assert_eq!(
            result,
            MessageBody {
                opcode: "generateWallets".to_string(),
                path: MessagePath::Conversation(4321),
                payload: Err((
                    CONFIGURATOR_WRITE_ERROR,
                    "Wallet information could not be set: BadDerivationPathFormat(\"booga\")"
                        .to_string()
                ))
            }
        )
    }

    #[test]
    fn handle_recover_wallets_works_with_earning_wallet_address() {
        let check_password_params_arc = Arc::new(Mutex::new(vec![]));
        let set_wallet_info_params_arc = Arc::new(Mutex::new(vec![]));
        let (ui_gateway, _, ui_gateway_recording_arc) = make_recorder();
        let persistent_config = PersistentConfigurationMock::new()
            .check_password_params(&check_password_params_arc)
            .check_password_result(Ok(true))
            .mnemonic_seed_exists_result(Ok(false))
            .set_wallet_info_params(&set_wallet_info_params_arc)
            .set_wallet_info_result(Ok(()));
        let subject = make_subject(Some(persistent_config));
        let subject_addr = subject.start();
        let peer_actors = peer_actors_builder().ui_gateway(ui_gateway).build();
        subject_addr.try_send(BindMessage { peer_actors }).unwrap();
        let request = make_example_recover_wallets_request();

        subject_addr
            .try_send(NodeFromUiMessage {
                client_id: 1234,
                body: request.clone().tmb(4321),
            })
            .unwrap();

        let system = System::new("test");
        System::current().stop();
        system.run();
        let ui_gateway_recording = ui_gateway_recording_arc.lock().unwrap();
        let response = ui_gateway_recording.get_record::<NodeToUiMessage>(0);
        let (_, context_id) = UiRecoverWalletsResponse::fmb(response.body.clone()).unwrap();
        assert_eq!(context_id, 4321);
        let mnemonic_phrase = request.mnemonic_phrase.join(" ");
        let mnemonic = Mnemonic::from_phrase(&mnemonic_phrase, Language::English).unwrap();
        let seed = PlainData::new(
            Bip39::seed(&mnemonic, &request.mnemonic_passphrase_opt.unwrap()).as_ref(),
        );
        let check_password_params = check_password_params_arc.lock().unwrap();
        assert_eq!(
            *check_password_params,
            vec![Some(request.db_password.clone())]
        );

        let set_wallet_info_params = set_wallet_info_params_arc.lock().unwrap();
        assert_eq!(
            *set_wallet_info_params,
            vec![(
                seed,
                request.consuming_derivation_path,
                request.earning_wallet,
                request.db_password,
            )]
        );
    }

    #[test]
    fn handle_recover_wallets_works_with_earning_wallet_derivation_path() {
        let set_wallet_info_params_arc = Arc::new(Mutex::new(vec![]));
        let persistent_config = PersistentConfigurationMock::new()
            .check_password_result(Ok(true))
            .mnemonic_seed_exists_result(Ok(false))
            .set_wallet_info_params(&set_wallet_info_params_arc)
            .set_wallet_info_result(Ok(()));
        let mut subject = make_subject(Some(persistent_config));
        let mut request = make_example_recover_wallets_request();
        request.earning_wallet = derivation_path(0, 5);

        let result = subject.handle_recover_wallets(request.clone(), 1234);

        assert_eq!(result, UiRecoverWalletsResponse {}.tmb(1234));
        let mnemonic_phrase = request.mnemonic_phrase.join(" ");
        let mnemonic = Mnemonic::from_phrase(&mnemonic_phrase, Language::English).unwrap();
        let seed = Bip39::seed(&mnemonic, &request.mnemonic_passphrase_opt.unwrap());
        let earning_wallet = Configurator::generate_wallet(&seed, &request.earning_wallet).unwrap();
        let set_wallet_info_params = set_wallet_info_params_arc.lock().unwrap();
        assert_eq!(
            *set_wallet_info_params,
            vec![(
                PlainData::new(&seed.as_ref()),
                request.consuming_derivation_path,
                earning_wallet.string_address_from_keypair(),
                request.db_password,
            )]
        );
    }

    #[test]
    fn handle_recover_wallets_works_without_passphrase() {
        let set_wallet_info_params_arc = Arc::new(Mutex::new(vec![]));
        let persistent_config = PersistentConfigurationMock::new()
            .check_password_result(Ok(true))
            .mnemonic_seed_exists_result(Ok(false))
            .set_wallet_info_params(&set_wallet_info_params_arc)
            .set_wallet_info_result(Ok(()));
        let mut subject = make_subject(Some(persistent_config));
        let mut request = make_example_recover_wallets_request();
        request.mnemonic_passphrase_opt = None;

        let result = subject.handle_recover_wallets(request.clone(), 1234);

        assert_eq!(result, UiRecoverWalletsResponse {}.tmb(1234));
        let mnemonic_phrase = request.mnemonic_phrase.join(" ");
        let mnemonic = Mnemonic::from_phrase(&mnemonic_phrase, Language::English).unwrap();
        let seed = Bip39::seed(&mnemonic, "");
        let set_wallet_info_params = set_wallet_info_params_arc.lock().unwrap();
        assert_eq!(
            *set_wallet_info_params,
            vec![(
                PlainData::new(&seed.as_ref()),
                request.consuming_derivation_path,
                request.earning_wallet,
                request.db_password,
            )]
        );
    }

    #[test]
    fn handle_recover_wallets_works_with_check_password_error() {
        let persistent_config = PersistentConfigurationMock::new()
            .check_password_result(Err(PersistentConfigError::NotPresent));
        let mut subject = make_subject(Some(persistent_config));
        let request = make_example_recover_wallets_request();

        let result = subject.handle_recover_wallets(request, 1234);

        assert_eq!(
            result,
            MessageBody {
                opcode: "recoverWallets".to_string(),
                path: MessagePath::Conversation(1234),
                payload: Err((
                    CONFIGURATOR_READ_ERROR,
                    "Error checking password: NotPresent".to_string()
                ))
            }
        )
    }

    #[test]
    fn handle_recover_wallets_works_with_incorrect_password() {
        let persistent_config = PersistentConfigurationMock::new().check_password_result(Ok(false));
        let mut subject = make_subject(Some(persistent_config));
        let request = make_example_recover_wallets_request();

        let result = subject.handle_recover_wallets(request, 1234);

        assert_eq!(
            result,
            MessageBody {
                opcode: "recoverWallets".to_string(),
                path: MessagePath::Conversation(1234),
                payload: Err((
                    BAD_PASSWORD_ERROR,
                    "Bad password; can't recover wallets".to_string(),
                ))
            }
        )
    }

    #[test]
    fn handle_recover_wallets_handles_error_checking_for_mnemonic_seed() {
        let persistent_config = PersistentConfigurationMock::new()
            .check_password_result(Ok(true))
            .mnemonic_seed_exists_result(Err(PersistentConfigError::NotPresent));
        let mut subject = make_subject(Some(persistent_config));
        let request = make_example_recover_wallets_request();

        let result = subject.handle_recover_wallets(request, 1234);

        assert_eq!(
            result,
            MessageBody {
                opcode: "recoverWallets".to_string(),
                path: MessagePath::Conversation(1234),
                payload: Err((
                    CONFIGURATOR_READ_ERROR,
                    "Error checking mnemonic seed: NotPresent".to_string()
                ))
            }
        )
    }

    #[test]
    fn handle_recover_wallets_works_if_mnemonic_seed_is_already_set() {
        let persistent_config = PersistentConfigurationMock::new()
            .check_password_result(Ok(true))
            .mnemonic_seed_exists_result(Ok(true));
        let mut subject = make_subject(Some(persistent_config));

        let result = subject.handle_recover_wallets(make_example_recover_wallets_request(), 4321);

        assert_eq!(
            result,
            MessageBody {
                opcode: "recoverWallets".to_string(),
                path: MessagePath::Conversation(4321),
                payload: Err((
                    ALREADY_INITIALIZED_ERROR,
                    "Node already has a wallet pair; can't recover another".to_string()
                ))
            }
        )
    }

    #[test]
    fn handle_recover_wallets_works_if_mnemonic_cant_be_generated_from_phrase() {
        let persistent_config = PersistentConfigurationMock::new()
            .check_password_result(Ok(true))
            .mnemonic_seed_exists_result(Ok(false));
        let mut subject = make_subject(Some(persistent_config));
        let mut request = make_example_recover_wallets_request();
        request.mnemonic_phrase = vec!["ooga".to_string(), "booga".to_string()];

        let result = subject.handle_recover_wallets(request, 4321);

        assert_eq!(
            result,
            MessageBody {
                opcode: "recoverWallets".to_string(),
                path: MessagePath::Conversation(4321),
                payload: Err((
                    MNEMONIC_PHRASE_ERROR,
                    "Couldn't make a mnemonic out of the supplied phrase: invalid word in phrase"
                        .to_string()
                ))
            }
        )
    }

    #[test]
    fn handle_recover_wallets_works_if_wallet_info_cant_be_set() {
        let persistent_config = PersistentConfigurationMock::new()
            .check_password_result(Ok(true))
            .mnemonic_seed_exists_result(Ok(false))
            .set_wallet_info_result(Err(PersistentConfigError::BadDerivationPathFormat(
                "booga".to_string(),
            )));
        let mut subject = make_subject(Some(persistent_config));

        let result = subject.handle_recover_wallets(make_example_recover_wallets_request(), 4321);

        assert_eq!(
            result,
            MessageBody {
                opcode: "recoverWallets".to_string(),
                path: MessagePath::Conversation(4321),
                payload: Err((
                    CONFIGURATOR_WRITE_ERROR,
                    "Wallet information could not be set: BadDerivationPathFormat(\"booga\")"
                        .to_string()
                ))
            }
        )
    }

    #[test]
    fn parse_language_handles_expected_languages() {
        vec![
            "English",
            "Chinese",
            "Traditional Chinese",
            "French",
            "Italian",
            "Japanese",
            "Korean",
            "Spanish",
        ]
        .into_iter()
        .for_each(|input| {
            let result = Configurator::parse_language(input)
                .expect(format!("{} didn't parse", input).as_str());

            // I can't believe that PartialEq is not implemented for Language. Sheesh!
            match result {
                Language::English => assert_eq!(input, "English"),
                Language::ChineseSimplified => assert_eq!(input, "Chinese"),
                Language::ChineseTraditional => assert_eq!(input, "Traditional Chinese"),
                Language::French => assert_eq!(input, "French"),
                Language::Italian => assert_eq!(input, "Italian"),
                Language::Japanese => assert_eq!(input, "Japanese"),
                Language::Korean => assert_eq!(input, "Korean"),
                Language::Spanish => assert_eq!(input, "Spanish"),
            }
        })
    }

    #[test]
    fn parse_word_count_handles_expected_counts() {
        vec![12, 15, 18, 21, 24].into_iter().for_each(|input| {
            let result = Configurator::parse_word_count(input)
                .expect(format!("{} didn't parse", input).as_str());

            assert_eq!(result.word_count(), input);
        })
    }

    #[test]
    fn parse_word_count_handles_unexpected_count() {
        let result = Configurator::parse_word_count(13).err().unwrap();

        assert_eq!(
            result,
            (ILLEGAL_MNEMONIC_WORD_COUNT_ERROR, "13".to_string())
        );
    }

    #[test]
    fn generate_mnemonic_works_without_passphrase() {
        let (actual_seed, phrase_words) =
            Configurator::generate_mnemonic(&None, "English", 12).unwrap();

        let mnemonic_phrase = phrase_words.join(" ");
        let mnemonic = Mnemonic::from_phrase(&mnemonic_phrase, Language::English).unwrap();
        let expected_seed = Bip39::seed(&mnemonic, "");
        assert_eq!(actual_seed.as_ref(), expected_seed.as_ref());
    }

    fn make_example_generate_wallets_request() -> UiGenerateWalletsRequest {
        UiGenerateWalletsRequest {
            db_password: "password".to_string(),
            mnemonic_phrase_size: 24,
            mnemonic_phrase_language: "English".to_string(),
            mnemonic_passphrase_opt: Some("booga".to_string()),
            consuming_derivation_path: derivation_path(0, 4),
            earning_derivation_path: derivation_path(0, 5),
        }
    }

    fn make_example_recover_wallets_request() -> UiRecoverWalletsRequest {
        UiRecoverWalletsRequest {
            db_password: "password".to_string(),
            mnemonic_phrase: vec![
                "parent", "prevent", "vehicle", "tooth", "crazy", "cruel", "update", "mango",
                "female", "mad", "spread", "plunge", "tiny", "inch", "under", "engine", "enforce",
                "film", "awesome", "plunge", "cloud", "spell", "empower", "pipe",
            ]
            .into_iter()
            .map(|x| x.to_string())
            .collect::<Vec<String>>(),
            mnemonic_passphrase_opt: Some("ebullient".to_string()),
            mnemonic_phrase_language: "English".to_string(),
            consuming_derivation_path: derivation_path(0, 4),
            earning_wallet: "0x005e288d713a5fb3d7c9cf1b43810a98688c7223".to_string(),
        }
    }

    fn make_subject(persistent_config_opt: Option<PersistentConfigurationMock>) -> Configurator {
        let persistent_config: Box<dyn PersistentConfiguration> =
            Box::new(persistent_config_opt.unwrap_or(PersistentConfigurationMock::new()));
        Configurator::from(persistent_config)
    }
}
