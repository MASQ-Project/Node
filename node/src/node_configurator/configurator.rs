use std::path::PathBuf;

use actix::{Actor, Context, Handler, Recipient};

use masq_lib::messages::{
    FromMessageBody, ToMessageBody, UiChangePasswordRequest, UiChangePasswordResponse,
    UiCheckPasswordRequest, UiCheckPasswordResponse, UiConfigurationRequest,
    UiConfigurationResponse, UiGenerateWalletsRequest, UiGenerateWalletsResponse,
    UiNewPasswordBroadcast, UiRecoverWalletsRequest, UiRecoverWalletsResponse,
    UiSetConfigurationRequest, UiSetConfigurationResponse, UiWalletAddressesRequest,
    UiWalletAddressesResponse,
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
    PersistentConfigError, PersistentConfiguration, PersistentConfigurationReal,
};
use crate::sub_lib::configurator::NewPasswordMessage;
use crate::sub_lib::cryptde::PlainData;
use crate::sub_lib::logger::Logger;
use crate::sub_lib::peer_actors::BindMessage;
use crate::sub_lib::wallet::{Wallet, WalletError};
use crate::test_utils::main_cryptde;
use bip39::{Language, Mnemonic, MnemonicType, Seed};
use masq_lib::constants::{
    ALREADY_INITIALIZED_ERROR, BAD_PASSWORD_ERROR, CONFIGURATOR_READ_ERROR,
    CONFIGURATOR_WRITE_ERROR, DERIVATION_PATH_ERROR, EARLY_QUESTIONING_ABOUT_DATA,
    ILLEGAL_MNEMONIC_WORD_COUNT_ERROR, KEY_PAIR_CONSTRUCTION_ERROR, MNEMONIC_PHRASE_ERROR,
    NON_PARSABLE_VALUE, UNRECOGNIZED_MNEMONIC_LANGUAGE_ERROR, UNRECOGNIZED_PARAMETER,
};
use rustc_hex::ToHex;
use std::str::FromStr;

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
        if let Ok((body, context_id)) = UiChangePasswordRequest::fmb(msg.clone().body) {
            let client_id = msg.client_id;
            self.call_handler(msg, |c| {
                c.handle_change_password(body, client_id, context_id)
            });
        } else if let Ok((body, context_id)) = UiCheckPasswordRequest::fmb(msg.clone().body) {
            self.call_handler(msg, |c| c.handle_check_password(body, context_id));
        } else if let Ok((body, context_id)) = UiConfigurationRequest::fmb(msg.clone().body) {
            self.call_handler(msg, |c| c.handle_configuration(body, context_id));
        } else if let Ok((body, context_id)) = UiGenerateWalletsRequest::fmb(msg.clone().body) {
            self.call_handler(msg, |c| c.handle_generate_wallets(body, context_id));
        } else if let Ok((body, context_id)) = UiRecoverWalletsRequest::fmb(msg.clone().body) {
            self.call_handler(msg, |c| c.handle_recover_wallets(body, context_id));
        } else if let Ok((body, context_id)) = UiSetConfigurationRequest::fmb(msg.clone().body) {
            self.call_handler(msg, |c| c.handle_set_configuration(body, context_id));
        } else if let Ok((body, context_id)) = UiWalletAddressesRequest::fmb(msg.clone().body) {
            self.call_handler(msg, |c| c.handle_wallet_addresses(body, context_id));
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
                    payload: Err((CONFIGURATOR_READ_ERROR, format!("{:?}", e))),
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
                let error_m = Self::inspect_reason_of_password_error(e, &msg);
                warning!(self.logger, "Failed to change password: {}", error_m);
                MessageBody {
                    opcode: msg.opcode().to_string(),
                    path: MessagePath::Conversation(context_id),
                    payload: Err((CONFIGURATOR_WRITE_ERROR, error_m)),
                }
            }
        }
    }

    fn inspect_reason_of_password_error(
        e: PersistentConfigError,
        msg: &UiChangePasswordRequest,
    ) -> String {
        if msg.old_password_opt.is_none() && e == PersistentConfigError::PasswordError {
            "The database already has a password. You may only change it".to_string()
        } else {
            format!("{:?}", e)
        }
    }

    fn handle_wallet_addresses(
        &self,
        msg: UiWalletAddressesRequest,
        context_id: u64,
    ) -> MessageBody {
        match self.get_wallet_addresses(msg.db_password.clone()) {
            Ok((consuming, earning)) => UiWalletAddressesResponse {
                consuming_wallet_address: consuming,
                earning_wallet_address: earning,
            }
            .tmb(context_id),
            Err((code, e_msg)) => {
                warning!(
                    self.logger,
                    "Failed to obtain wallet addresses: {}, {}",
                    code,
                    e_msg
                );
                MessageBody {
                    opcode: msg.opcode().to_string(),
                    path: MessagePath::Conversation(context_id),
                    payload: Err((code, e_msg)),
                }
            }
        }
    }

    fn get_wallet_addresses(&self, db_password: String) -> Result<(String, String), (u64, String)> {
        let mnemonic = match self.persistent_config.mnemonic_seed(&db_password) {
            Ok(mnemonic_opt) => match mnemonic_opt {
                None => {
                    return Err((
                        EARLY_QUESTIONING_ABOUT_DATA,
                        "Wallets must exist prior to \
                 demanding info on them (recover or generate wallets first)"
                            .to_string(),
                    ))
                }
                Some(mnemonic) => mnemonic,
            },
            Err(e) => return Err((CONFIGURATOR_READ_ERROR, format!("{:?}", e))),
        };
        let derivation_path = match self.persistent_config.consuming_wallet_derivation_path() {
            Ok(deriv_path_opt) => match deriv_path_opt {
                None => panic!(
                    "Database corrupted: consuming derivation path not present despite \
                 mnemonic seed in place!"
                ),
                Some(deriv_path) => deriv_path,
            },
            Err(e) => return Err((CONFIGURATOR_READ_ERROR, format!("{:?}", e))),
        };
        let consuming_wallet_address =
            match Self::recalculate_consuming_wallet(mnemonic, derivation_path) {
                Ok(wallet) => wallet.string_address_from_keypair(),
                Err(e) => return Err((KEY_PAIR_CONSTRUCTION_ERROR, e)),
            };
        let earning_wallet_address = match self.persistent_config.earning_wallet_address() {
            Ok(address) => match address {
                None => panic!(
                    "Database corrupted: missing earning wallet address despite other \
                 values for wallets in place!"
                ),
                Some(address) => address,
            },
            Err(e) => return Err((CONFIGURATOR_READ_ERROR, format!("{:?}", e))),
        };

        Ok((consuming_wallet_address, earning_wallet_address))
    }

    fn recalculate_consuming_wallet(
        seed: PlainData,
        derivation_path: String,
    ) -> Result<Wallet, String> {
        match Bip32ECKeyPair::from_raw(seed.as_ref(), &derivation_path) {
            Err(e) => Err(format!(
                "Consuming wallet address error during generation: {}",
                e
            )),
            Ok(kp) => Ok(Wallet::from(kp)),
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

    fn handle_configuration(
        &mut self,
        msg: UiConfigurationRequest,
        context_id: u64,
    ) -> MessageBody {
        match Self::unfriendly_handle_configuration(msg, context_id, &mut self.persistent_config) {
            Ok(message_body) => message_body,
            Err((code, msg)) => MessageBody {
                opcode: "configuration".to_string(),
                path: MessagePath::Conversation(context_id),
                payload: Err((code, msg)),
            },
        }
    }

    fn unfriendly_handle_configuration(
        msg: UiConfigurationRequest,
        context_id: u64,
        persistent_config: &mut Box<dyn PersistentConfiguration>,
    ) -> Result<MessageBody, MessageError> {
        let good_password = match &msg.db_password_opt {
            None => None,
            Some(db_password) => {
                match persistent_config.check_password(Some(db_password.clone())) {
                    Ok(true) => Some(db_password),
                    Ok(false) => None,
                    Err(_) => return Err((CONFIGURATOR_READ_ERROR, "dbPassword".to_string())),
                }
            }
        };
        let current_schema_version = persistent_config.current_schema_version();
        let clandestine_port =
            Self::value_required(persistent_config.clandestine_port(), "clandestinePort")?;
        let gas_price = Self::value_required(persistent_config.gas_price(), "gasPrice")?;
        let consuming_wallet_derivation_path_opt = Self::value_not_required(
            persistent_config.consuming_wallet_derivation_path(),
            "consumingWalletDerivationPathOpt",
        )?;
        let earning_wallet_address_opt = Self::value_not_required(
            persistent_config.earning_wallet_address(),
            "earningWalletAddressOpt",
        )?;
        let start_block = Self::value_required(persistent_config.start_block(), "startBlock")?;
        let (mnemonic_seed_opt, past_neighbors) = match good_password {
            Some(password) => {
                let mnemonic_seed_opt = Self::value_not_required(
                    persistent_config.mnemonic_seed(password),
                    "mnemonicSeedOpt",
                )?
                .map(|bytes| bytes.as_slice().to_hex::<String>());
                let past_neighbors_opt = Self::value_not_required(
                    persistent_config.past_neighbors(password),
                    "pastNeighbors",
                )?;
                let past_neighbors = match past_neighbors_opt {
                    None => vec![],
                    Some(pns) => pns
                        .into_iter()
                        .map(|nd| nd.to_string(main_cryptde()))
                        .collect::<Vec<String>>(),
                };
                (mnemonic_seed_opt, past_neighbors)
            }
            None => (None, vec![]),
        };
        let response = UiConfigurationResponse {
            current_schema_version,
            clandestine_port,
            gas_price,
            mnemonic_seed_opt,
            consuming_wallet_derivation_path_opt,
            earning_wallet_address_opt,
            past_neighbors,
            start_block,
        };
        Ok(response.tmb(context_id))
    }

    fn value_required<T>(
        result: Result<T, PersistentConfigError>,
        field_name: &str,
    ) -> Result<T, MessageError> {
        match result {
            Ok(v) => Ok(v),
            Err(_) => Err((CONFIGURATOR_READ_ERROR, field_name.to_string())),
        }
    }

    fn value_not_required<T>(
        result: Result<Option<T>, PersistentConfigError>,
        field_name: &str,
    ) -> Result<Option<T>, MessageError> {
        match result {
            Ok(option) => Ok(option),
            Err(_) => Err((CONFIGURATOR_READ_ERROR, field_name.to_string())),
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

    fn handle_set_configuration(
        &mut self,
        msg: UiSetConfigurationRequest,
        context_id: u64,
    ) -> MessageBody {
        match Self::unfriendly_handle_set_configuration(
            msg,
            context_id,
            &mut self.persistent_config,
        ) {
            Ok(message_body) => message_body,
            Err((code, msg)) => MessageBody {
                opcode: "setConfiguration".to_string(),
                path: MessagePath::Conversation(context_id),
                payload: Err((code, msg)),
            },
        }
    }

    fn unfriendly_handle_set_configuration(
        msg: UiSetConfigurationRequest,
        context_id: u64,
        persist_config: &mut Box<dyn PersistentConfiguration>,
    ) -> Result<MessageBody, MessageError> {
        let password: Option<String> = None; //prepared for an upgrade with parameters requiring the password

        let _ = match password {
            None => {
                if "gas-price" == &msg.name {
                    Self::set_gas_price(msg.value, persist_config)?;
                } else if "start-block" == &msg.name {
                    Self::set_start_block(msg.value, persist_config)?;
                } else {
                    return Err((
                        UNRECOGNIZED_PARAMETER,
                        format!("This parameter name is not known: {}", &msg.name),
                    ));
                }
            }
            Some(_password) => {
                unimplemented!();
            }
        };

        Ok(UiSetConfigurationResponse {}.tmb(context_id))
    }

    fn set_gas_price(
        string_price: String,
        config: &mut Box<dyn PersistentConfiguration>,
    ) -> Result<(), (u64, String)> {
        let price_number = match string_price.parse::<u64>() {
            Ok(num) => num,
            Err(e) => return Err((NON_PARSABLE_VALUE, format!("gas price: {:?}", e))),
        };
        match config.set_gas_price(price_number) {
            Ok(_) => Ok(()),
            Err(e) => Err((CONFIGURATOR_WRITE_ERROR, format!("gas price: {:?}", e))),
        }
    }

    fn set_start_block(
        string_number: String,
        config: &mut Box<dyn PersistentConfiguration>,
    ) -> Result<(), (u64, String)> {
        let block_number = match string_number.parse::<u64>() {
            Ok(num) => num,
            Err(e) => return Err((NON_PARSABLE_VALUE, format!("start block: {:?}", e))),
        };
        match config.set_start_block(block_number) {
            Ok(_) => Ok(()),
            Err(e) => Err((CONFIGURATOR_WRITE_ERROR, format!("start block: {:?}", e))),
        }
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

    fn call_handler<F: FnOnce(&mut Configurator) -> MessageBody>(
        &mut self,
        msg: NodeFromUiMessage,
        handler: F,
    ) {
        self.log_begin_handle(&msg);
        let response = handler(self);
        self.log_end_handle(&response);
        self.send_to_ui_gateway(ClientId(msg.client_id), response);
    }

    fn log_begin_handle(&self, msg: &NodeFromUiMessage) {
        debug!(
            &self.logger,
            "Handling {} message from client {}", msg.body.opcode, msg.client_id
        );
    }

    fn log_end_handle(&self, body: &MessageBody) {
        debug!(&self.logger, "Sending response to {} command:", body.opcode);
    }
}

#[cfg(test)]
mod tests {
    use actix::System;
    use masq_lib::messages::{
        ToMessageBody, UiChangePasswordResponse, UiCheckPasswordRequest, UiCheckPasswordResponse,
        UiGenerateWalletsResponse, UiNewPasswordBroadcast, UiStartOrder, UiWalletAddressesRequest,
        UiWalletAddressesResponse,
    };
    use masq_lib::ui_gateway::{MessagePath, MessageTarget};
    use std::sync::{Arc, Mutex};

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
                payload: Err((CONFIGURATOR_READ_ERROR, "NotPresent".to_string()))
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
    fn handle_change_password_can_process_error() {
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
    fn handle_set_password_used_repeatedly_recommends_change_password_command_for_next_time() {
        init_test_logging();
        let persistent_config = PersistentConfigurationMock::new()
            .change_password_result(Err(PersistentConfigError::PasswordError));
        let mut subject = make_subject(Some(persistent_config));
        let msg = UiChangePasswordRequest {
            old_password_opt: None,
            new_password: "IAmSureThisPasswordMustBeRightDamn".to_string(),
        };

        let result = subject.handle_change_password(msg, 1234, 4321);

        assert_eq!(
            result,
            MessageBody {
                opcode: "changePassword".to_string(),
                path: MessagePath::Conversation(4321),
                payload: Err((
                    CONFIGURATOR_WRITE_ERROR,
                    "The database already has a password. You may only change it".to_string()
                )),
            }
        );
        TestLogHandler::new().exists_log_containing(
            "WARN: Configurator: Failed to change password: \
            The database already has a password. You may only change it",
        );
    }

    #[test]
    fn handle_wallet_addresses_works() {
        let system = System::new("test");
        let mnemonic_seed_params_arc = Arc::new(Mutex::new(vec![]));
        let persistent_config = PersistentConfigurationMock::new()
            .check_password_result(Ok(true))
            .mnemonic_seed_params(&mnemonic_seed_params_arc)
            .mnemonic_seed_result(Ok(Some(PlainData::new(
                "snake, goal, cook, doom".as_bytes(),
            ))))
            .consuming_wallet_derivation_path_result(Ok(Some(String::from(derivation_path(0, 4)))))
            .earning_wallet_address_result(Ok(Some(String::from(
                "0x01234567890aa345678901234567890123456789",
            ))));
        let subject = make_subject(Some(persistent_config));
        let subject_addr = subject.start();
        let (ui_gateway, _, ui_gateway_recording_arc) = make_recorder();
        let peer_actors = peer_actors_builder().ui_gateway(ui_gateway).build();
        subject_addr.try_send(BindMessage { peer_actors }).unwrap();

        subject_addr
            .try_send(NodeFromUiMessage {
                client_id: 1234,
                body: UiWalletAddressesRequest {
                    db_password: "123password".to_string(),
                }
                .tmb(4321),
            })
            .unwrap();

        System::current().stop();
        system.run();
        let mnemonic_seed_params = mnemonic_seed_params_arc.lock().unwrap();
        assert_eq!(*mnemonic_seed_params, vec!["123password".to_string()]);
        let ui_gateway_recording = ui_gateway_recording_arc.lock().unwrap();
        assert_eq!(
            ui_gateway_recording.get_record::<NodeToUiMessage>(0),
            &NodeToUiMessage {
                target: MessageTarget::ClientId(1234),
                body: UiWalletAddressesResponse {
                    consuming_wallet_address: "0x84646fb4dd69dd12fd779a569f7cdbe1e133b29b"
                        .to_string(),
                    earning_wallet_address: "0x01234567890aa345678901234567890123456789"
                        .to_string()
                }
                .tmb(4321)
            }
        );
        assert_eq!(ui_gateway_recording.len(), 1);
    }

    #[test]
    fn handle_wallet_addresses_works_if_mnemonic_seed_causes_error() {
        // also consider as a test for bad password supplied; mnemonic_seed solves that within
        init_test_logging();
        let persistent_config = PersistentConfigurationMock::new().mnemonic_seed_result(Err(
            PersistentConfigError::DatabaseError("Unknown error".to_string()),
        ));
        let subject = make_subject(Some(persistent_config));
        let msg = UiWalletAddressesRequest {
            db_password: "some password".to_string(),
        };

        let result = subject.handle_wallet_addresses(msg, 1234);

        assert_eq!(
            result,
            MessageBody {
                opcode: "walletAddresses".to_string(),
                path: MessagePath::Conversation(1234),
                payload: Err((
                    CONFIGURATOR_READ_ERROR,
                    r#"DatabaseError("Unknown error")"#.to_string()
                ))
            }
        );
        TestLogHandler::new().exists_log_containing(
            r#"WARN: Configurator: Failed to obtain wallet addresses: 281474976710657, DatabaseError("Unknown error")"#,
        );
    }

    #[test]
    fn handle_wallet_addresses_works_if_mnemonic_seed_is_none() {
        init_test_logging();
        let persistent_config = PersistentConfigurationMock::new().mnemonic_seed_result(Ok(None));
        let subject = make_subject(Some(persistent_config));
        let msg = UiWalletAddressesRequest {
            db_password: "some password".to_string(),
        };

        let result = subject.handle_wallet_addresses(msg, 1234);

        assert_eq!(
            result,
            MessageBody {
                opcode: "walletAddresses".to_string(),
                path: MessagePath::Conversation(1234),
                payload: Err((
                    EARLY_QUESTIONING_ABOUT_DATA,
                    "Wallets must exist prior to demanding info on them (recover or generate wallets first)".to_string()
                ))
            }
        );
        TestLogHandler::new().exists_log_containing(
            "WARN: Configurator: Failed to obtain wallet addresses: 281474976710666, Wallets \
             must exist prior to demanding info on them (recover or generate wallets first)",
        );
    }

    #[test]
    #[should_panic(
        expected = "Database corrupted: consuming derivation path not present despite mnemonic seed in place!"
    )]
    fn handle_wallet_addresses_panics_if_derivation_path_is_none() {
        let persistent_config = PersistentConfigurationMock::new()
            .mnemonic_seed_result(Ok(Some(PlainData::new(b"snake, goal, cook, doom"))))
            .consuming_wallet_derivation_path_result(Ok(None));
        let subject = make_subject(Some(persistent_config));
        let msg = UiWalletAddressesRequest {
            db_password: "some password".to_string(),
        };

        let _ = subject.handle_wallet_addresses(msg, 1234);
    }

    #[test]
    fn handle_wallet_addresses_works_if_derivation_path_causes_error() {
        init_test_logging();
        let persistent_config = PersistentConfigurationMock::new()
            .mnemonic_seed_result(Ok(Some(PlainData::new(b"snake, goal, cook, doom"))))
            .consuming_wallet_derivation_path_result(Err(PersistentConfigError::DatabaseError(
                "Unknown error 2".to_string(),
            )));
        let subject = make_subject(Some(persistent_config));
        let msg = UiWalletAddressesRequest {
            db_password: "some password".to_string(),
        };

        let result = subject.handle_wallet_addresses(msg, 1234);

        assert_eq!(
            result,
            MessageBody {
                opcode: "walletAddresses".to_string(),
                path: MessagePath::Conversation(1234),
                payload: Err((
                    CONFIGURATOR_READ_ERROR,
                    r#"DatabaseError("Unknown error 2")"#.to_string()
                ))
            }
        );
        TestLogHandler::new().exists_log_containing(
            r#"WARN: Configurator: Failed to obtain wallet addresses: 281474976710657, DatabaseError("Unknown error 2")"#,
        );
    }

    #[test]
    fn handle_wallet_addresses_works_if_consuming_wallet_address_error() {
        init_test_logging();
        let persistent_config = PersistentConfigurationMock::new()
            .mnemonic_seed_result(Ok(Some(PlainData::new(b"snake, goal, cook, doom"))))
            .consuming_wallet_derivation_path_result(Ok(Some(String::from("*************"))));
        let subject = make_subject(Some(persistent_config));
        let msg = UiWalletAddressesRequest {
            db_password: "some password".to_string(),
        };

        let result = subject.handle_wallet_addresses(msg, 1234);

        assert_eq!(
            result,
            MessageBody {
                opcode: "walletAddresses".to_string(),
                path: MessagePath::Conversation(1234),
                payload: Err((
                    KEY_PAIR_CONSTRUCTION_ERROR,
                    r#"Consuming wallet address error during generation: InvalidDerivationPath"#
                        .to_string()
                ))
            }
        );
        TestLogHandler::new().exists_log_containing(
            "WARN: Configurator: Failed to obtain wallet addresses: 281474976710661, Consuming \
             wallet address error during generation: InvalidDerivationPath",
        );
    }

    #[test]
    fn handle_wallet_addresses_works_if_earning_wallet_address_triggers_database_error() {
        init_test_logging();
        let persistent_config = PersistentConfigurationMock::new()
            .mnemonic_seed_result(Ok(Some(PlainData::new(
                "snake, goal, cook, doom".as_bytes(),
            ))))
            .consuming_wallet_derivation_path_result(Ok(Some(String::from(derivation_path(0, 4)))))
            .earning_wallet_address_result(Err(PersistentConfigError::DatabaseError(
                "Unknown error 3".to_string(),
            )));
        let subject = make_subject(Some(persistent_config));
        let msg = UiWalletAddressesRequest {
            db_password: "some password".to_string(),
        };

        let result = subject.handle_wallet_addresses(msg, 1234);

        assert_eq!(
            result,
            MessageBody {
                opcode: "walletAddresses".to_string(),
                path: MessagePath::Conversation(1234),
                payload: Err((
                    CONFIGURATOR_READ_ERROR,
                    r#"DatabaseError("Unknown error 3")"#.to_string()
                ))
            }
        );
        TestLogHandler::new().exists_log_containing(
            r#"WARN: Configurator: Failed to obtain wallet addresses: 281474976710657, DatabaseError("Unknown error 3")"#,
        );
    }

    #[test]
    #[should_panic(
        expected = "Database corrupted: missing earning wallet address despite other values for wallets in place!"
    )]
    fn handle_wallet_addresses_panics_if_earning_wallet_address_is_missing() {
        let persistent_config = PersistentConfigurationMock::new()
            .mnemonic_seed_result(Ok(Some(PlainData::new(b"snake, goal, cook, doom"))))
            .consuming_wallet_derivation_path_result(Ok(Some(String::from(derivation_path(0, 4)))))
            .earning_wallet_address_result(Ok(None));
        let subject = make_subject(Some(persistent_config));
        let msg = UiWalletAddressesRequest {
            db_password: "some password".to_string(),
        };

        let _ = subject.handle_wallet_addresses(msg, 1234);
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
    fn handle_set_configuration_works() {
        let set_start_block_params_arc = Arc::new(Mutex::new(vec![]));
        let (ui_gateway, _, ui_gateway_recording_arc) = make_recorder();
        let persistent_config = PersistentConfigurationMock::new()
            .set_start_block_params(&set_start_block_params_arc)
            .set_start_block_result(Ok(()));
        let subject = make_subject(Some(persistent_config));
        let subject_addr = subject.start();
        let peer_actors = peer_actors_builder().ui_gateway(ui_gateway).build();
        subject_addr.try_send(BindMessage { peer_actors }).unwrap();

        subject_addr
            .try_send(NodeFromUiMessage {
                client_id: 1234,
                body: UiSetConfigurationRequest {
                    name: "start-block".to_string(),
                    value: "166666".to_string(),
                }
                .tmb(4444),
            })
            .unwrap();

        let system = System::new("test");
        System::current().stop();
        system.run();
        let ui_gateway_recording = ui_gateway_recording_arc.lock().unwrap();
        let response = ui_gateway_recording.get_record::<NodeToUiMessage>(0);
        let (_, context_id) = UiSetConfigurationResponse::fmb(response.body.clone()).unwrap();
        assert_eq!(context_id, 4444);

        let check_start_block_params = set_start_block_params_arc.lock().unwrap();
        assert_eq!(*check_start_block_params, vec![166666]);
    }

    #[test]
    fn handle_set_configuration_works_for_gas_price() {
        let set_gas_price_params_arc = Arc::new(Mutex::new(vec![]));
        let persistent_config = PersistentConfigurationMock::new()
            .set_gas_price_params(&set_gas_price_params_arc)
            .set_gas_price_result(Ok(()));
        let mut subject = make_subject(Some(persistent_config));

        let result = subject.handle_set_configuration(
            UiSetConfigurationRequest {
                name: "gas-price".to_string(),
                value: "68".to_string(),
            },
            4000,
        );

        assert_eq!(
            result,
            MessageBody {
                opcode: "setConfiguration".to_string(),
                path: MessagePath::Conversation(4000),
                payload: Ok(r#"{}"#.to_string())
            }
        );
        let set_gas_price_params = set_gas_price_params_arc.lock().unwrap();
        assert_eq!(*set_gas_price_params, vec![68])
    }

    #[test]
    fn handle_set_configuration_handles_failure_on_gas_price_database_issue() {
        let persistent_config = PersistentConfigurationMock::new()
            .set_gas_price_result(Err(PersistentConfigError::TransactionError));
        let mut subject = make_subject(Some(persistent_config));

        let result = subject.handle_set_configuration(
            UiSetConfigurationRequest {
                name: "gas-price".to_string(),
                value: "55".to_string(),
            },
            4000,
        );

        assert_eq!(
            result,
            MessageBody {
                opcode: "setConfiguration".to_string(),
                path: MessagePath::Conversation(4000),
                payload: Err((
                    CONFIGURATOR_WRITE_ERROR,
                    "gas price: TransactionError".to_string()
                ))
            }
        );
    }

    #[test]
    fn handle_set_configuration_handle_gas_price_non_parsable_value_issue() {
        let persistent_config = PersistentConfigurationMock::new();
        let mut subject = make_subject(Some(persistent_config));

        let result = subject.handle_set_configuration(
            UiSetConfigurationRequest {
                name: "gas-price".to_string(),
                value: "fiftyfive".to_string(),
            },
            4000,
        );

        assert_eq!(
            result,
            MessageBody {
                opcode: "setConfiguration".to_string(),
                path: MessagePath::Conversation(4000),
                payload: Err((
                    NON_PARSABLE_VALUE,
                    "gas price: ParseIntError { kind: InvalidDigit }".to_string()
                ))
            }
        );
    }

    #[test]
    fn handle_set_configuration_terminates_after_failure_on_start_block() {
        let persistent_config = PersistentConfigurationMock::new().set_start_block_result(Err(
            PersistentConfigError::DatabaseError("dunno".to_string()),
        ));
        let mut subject = make_subject(Some(persistent_config));

        let result = subject.handle_set_configuration(
            UiSetConfigurationRequest {
                name: "start-block".to_string(),
                value: "166666".to_string(),
            },
            4000,
        );

        assert_eq!(
            result,
            MessageBody {
                opcode: "setConfiguration".to_string(),
                path: MessagePath::Conversation(4000),
                payload: Err((
                    CONFIGURATOR_WRITE_ERROR,
                    r#"start block: DatabaseError("dunno")"#.to_string()
                ))
            }
        );
    }

    #[test]
    fn handle_set_configuration_argue_decently_about_non_parsable_value_at_start_block() {
        let persistent_config = PersistentConfigurationMock::new();
        let mut subject = make_subject(Some(persistent_config));

        let result = subject.handle_set_configuration(
            UiSetConfigurationRequest {
                name: "start-block".to_string(),
                value: "hundred_and_half".to_string(),
            },
            4000,
        );

        assert_eq!(
            result,
            MessageBody {
                opcode: "setConfiguration".to_string(),
                path: MessagePath::Conversation(4000),
                payload: Err((
                    NON_PARSABLE_VALUE,
                    r#"start block: ParseIntError { kind: InvalidDigit }"#.to_string()
                ))
            }
        );
    }

    #[test]
    fn handle_set_configuration_complains_about_unexpected_parameter() {
        let persistent_config = PersistentConfigurationMock::new();
        let mut subject = make_subject(Some(persistent_config));

        let result = subject.handle_set_configuration(
            UiSetConfigurationRequest {
                name: "blabla".to_string(),
                value: "166666".to_string(),
            },
            4000,
        );

        assert_eq!(
            result,
            MessageBody {
                opcode: "setConfiguration".to_string(),
                path: MessagePath::Conversation(4000),
                payload: Err((
                    UNRECOGNIZED_PARAMETER,
                    "This parameter name is not known: blabla".to_string()
                ))
            }
        );
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

    #[test]
    fn configuration_works_with_missing_secrets() {
        let persistent_config = PersistentConfigurationMock::new()
            .check_password_result(Ok(true))
            .current_schema_version_result("1.2.3")
            .clandestine_port_result(Ok(1234))
            .gas_price_result(Ok(2345))
            .mnemonic_seed_result(Ok(None))
            .consuming_wallet_derivation_path_result(Ok(None))
            .past_neighbors_result(Ok(Some(vec![])))
            .earning_wallet_address_result(Ok(None))
            .start_block_result(Ok(3456));
        let mut subject = make_subject(Some(persistent_config));

        let (configuration, context_id) =
            UiConfigurationResponse::fmb(subject.handle_configuration(
                UiConfigurationRequest {
                    db_password_opt: None,
                },
                4321,
            ))
            .unwrap();

        assert_eq!(context_id, 4321);
        assert_eq!(
            configuration,
            UiConfigurationResponse {
                current_schema_version: "1.2.3".to_string(),
                clandestine_port: 1234,
                gas_price: 2345,
                mnemonic_seed_opt: None,
                consuming_wallet_derivation_path_opt: None,
                earning_wallet_address_opt: None,
                past_neighbors: vec![],
                start_block: 3456
            }
        );
    }

    #[test]
    fn configuration_handles_check_password_error() {
        let persistent_config = PersistentConfigurationMock::new()
            .check_password_result(Err(PersistentConfigError::NotPresent));
        let mut subject = make_subject(Some(persistent_config));

        let result = subject.handle_configuration(
            UiConfigurationRequest {
                db_password_opt: Some("password".to_string()),
            },
            4321,
        );

        assert_eq!(
            result,
            MessageBody {
                opcode: "configuration".to_string(),
                path: MessagePath::Conversation(4321),
                payload: Err((CONFIGURATOR_READ_ERROR, "dbPassword".to_string()))
            }
        );
    }

    #[test]
    fn value_required_plain_works() {
        let result: Result<u64, MessageError> = Configurator::value_required(Ok(6), "Field");

        assert_eq!(result, Ok(6))
    }

    #[test]
    fn value_required_plain_handles_error() {
        let result: Result<u64, MessageError> =
            Configurator::value_required(Err(PersistentConfigError::NotPresent), "Field");

        assert_eq!(result, Err((CONFIGURATOR_READ_ERROR, "Field".to_string())))
    }

    #[test]
    fn value_required_handles_read_error() {
        let result: Result<String, MessageError> =
            Configurator::value_required(Err(PersistentConfigError::NotPresent), "Field");

        assert_eq!(result, Err((CONFIGURATOR_READ_ERROR, "Field".to_string())))
    }

    #[test]
    fn value_not_required_handles_read_error() {
        let result: Result<Option<String>, MessageError> =
            Configurator::value_not_required(Err(PersistentConfigError::NotPresent), "Field");

        assert_eq!(result, Err((CONFIGURATOR_READ_ERROR, "Field".to_string())))
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
