// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

pub mod node_configurator_generate_wallet;
pub mod node_configurator_initialization;
pub mod node_configurator_recover_wallet;
pub mod node_configurator_standard;

use crate::blockchain::bip32::Bip32ECKeyPair;
use crate::blockchain::bip39::Bip39;
use crate::blockchain::blockchain_interface::chain_id_from_name;
use crate::bootstrapper::RealUser;
use crate::database::db_initializer::{DbInitializer, DbInitializerReal, DATABASE_FILE};
use crate::persistent_configuration::{
    PersistentConfigError, PersistentConfiguration, PersistentConfigurationReal,
};
use crate::sub_lib::cryptde::PlainData;
use crate::sub_lib::utils::make_new_multi_config;
use crate::sub_lib::wallet::Wallet;
use crate::sub_lib::wallet::{DEFAULT_CONSUMING_DERIVATION_PATH, DEFAULT_EARNING_DERIVATION_PATH};
use bip39::Language;
use clap::{crate_description, value_t, App, AppSettings, Arg};
use dirs::{data_local_dir, home_dir};
use masq_lib::command::StdStreams;
use masq_lib::constants::DEFAULT_CHAIN_NAME;
use masq_lib::multi_config::{merge, CommandLineVcl, EnvironmentVcl, MultiConfig, VclArg};
use masq_lib::shared_schema::{
    chain_arg, config_file_arg, data_directory_arg, real_user_arg, ConfiguratorError,
};
use masq_lib::test_utils::fake_stream_holder::FakeStreamHolder;
use masq_lib::utils::{exit_process, localhost};
use rpassword::read_password_with_reader;
use rustc_hex::FromHex;
use std::fmt::Debug;
use std::io;
use std::io::Read;
use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;
use std::str::FromStr;
use tiny_hderive::bip44::DerivationPath;

pub trait NodeConfigurator<T> {
    fn configure(
        &self,
        args: &[String],
        streams: &mut StdStreams<'_>,
    ) -> Result<T, ConfiguratorError>;
}

pub const CONSUMING_WALLET_HELP: &str = "The BIP32 derivation path for the wallet from which your Node \
     should pay other Nodes for routing and exit services. (If the path includes single quotes, enclose it in \
     double quotes.) Defaults to m/44'/60'/0'/0/0.";
pub const EARNING_WALLET_HELP: &str =
    "Denotes the wallet into which other Nodes will pay yours for its routing and exit services. May either be a \
     BIP32 derivation path (defaults to m/44'/60'/0'/0/1) or an Ethereum wallet address. (If the derivation path \
     includes single quotes, enclose it in double quotes.) Addresses must begin with 0x followed by 40 hexadecimal \
     digits (case-insensitive).";
pub const LANGUAGE_HELP: &str = "The language of the mnemonic phrase.";
pub const MNEMONIC_PASSPHRASE_HELP: &str =
    "A passphrase for the mnemonic phrase. Cannot be changed later and still produce the same addresses. This is a \
     secret; providing it on the command line or in a config file is insecure and unwise. If you don't specify it anywhere, \
     you'll be prompted for it at the console.";
pub const DB_PASSWORD_HELP: &str =
    "A password or phrase to encrypt your consuming wallet in the MASQ Node database or decrypt a keystore file. Can be changed \
     later and still produce the same addresses. This is a secret; providing it on the command line or in a config file is \
     insecure and unwise. If you don't specify it anywhere, you'll be prompted for it at the console.";

pub fn app_head() -> App<'static, 'static> {
    App::new("MASQNode")
        .global_settings(if cfg!(test) {
            &[AppSettings::ColorNever]
        } else {
            &[AppSettings::ColorAuto, AppSettings::ColoredHelp]
        })
        //.version(crate_version!())
        //.author(crate_authors!("\n")) // TODO: Put this back in when clap is compatible with Rust 1.38.0
        .version("1.0.0")
        .author("Substratum, MASQ")
        .about(crate_description!())
}

// These Args are needed in more than one clap schema. To avoid code duplication, they're defined here and referred
// to from multiple places.

pub fn consuming_wallet_arg<'a>() -> Arg<'a, 'a> {
    Arg::with_name("consuming-wallet")
        .long("consuming-wallet")
        .value_name("CONSUMING-WALLET")
        .empty_values(false)
        .validator(common_validators::validate_derivation_path)
        .help(&CONSUMING_WALLET_HELP)
}

pub fn earning_wallet_arg<F>(help: &str, validator: F) -> Arg
where
    F: 'static,
    F: Fn(String) -> Result<(), String>,
{
    Arg::with_name("earning-wallet")
        .long("earning-wallet")
        .value_name("EARNING-WALLET")
        .required(false)
        .takes_value(true)
        .validator(validator)
        .help(help)
}

pub fn language_arg<'a>() -> Arg<'a, 'a> {
    Arg::with_name("language")
        .alias("language")
        .long("language")
        .value_name("LANGUAGE")
        .required(true)
        .case_insensitive(true)
        .possible_values(&Bip39::possible_language_values().as_slice())
        .default_value(Bip39::name_from_language(Language::default()))
        .help(&LANGUAGE_HELP)
}

pub fn mnemonic_passphrase_arg<'a>() -> Arg<'a, 'a> {
    Arg::with_name("mnemonic-passphrase")
        .long("mnemonic-passphrase")
        .value_name("MNEMONIC-PASSPHRASE")
        .required(false)
        .takes_value(true)
        .min_values(0)
        .max_values(1)
        .help(MNEMONIC_PASSPHRASE_HELP)
}

pub fn determine_config_file_path(
    dirs_wrapper: &dyn DirsWrapper,
    app: &App,
    args: &[String],
) -> Result<(PathBuf, bool), ConfiguratorError> {
    let orientation_schema = App::new("MASQNode")
        .arg(chain_arg())
        .arg(real_user_arg())
        .arg(data_directory_arg())
        .arg(config_file_arg());
    let orientation_args: Vec<Box<dyn VclArg>> = merge(
        Box::new(EnvironmentVcl::new(app)),
        Box::new(CommandLineVcl::new(args.to_vec())),
    )
    .vcl_args()
    .into_iter()
    .filter(|vcl_arg| {
        (vcl_arg.name() == "--chain")
            || (vcl_arg.name() == "--real-user")
            || (vcl_arg.name() == "--data-directory")
            || (vcl_arg.name() == "--config-file")
    })
    .map(|vcl_arg| vcl_arg.dup())
    .collect();
    let orientation_vcl = CommandLineVcl::from(orientation_args);
    let multi_config = make_new_multi_config(
        &orientation_schema,
        vec![Box::new(orientation_vcl)],
        &mut FakeStreamHolder::new().streams(),
    )?;
    let config_file_path =
        value_m!(multi_config, "config-file", PathBuf).expect("config-file should be defaulted");
    let user_specified = multi_config.arg_matches().occurrences_of("config-file") > 0;
    let (real_user, data_directory_opt, chain_name) =
        real_user_data_directory_opt_and_chain_name(dirs_wrapper, &multi_config);
    let directory =
        data_directory_from_context(dirs_wrapper, &real_user, &data_directory_opt, &chain_name);
    Ok((directory.join(config_file_path), user_specified))
}

pub fn create_wallet(
    config: &WalletCreationConfig,
    persistent_config: &dyn PersistentConfiguration,
) {
    if let Some(address) = &config.earning_wallet_address_opt {
        persistent_config.set_earning_wallet_address(address)
    }
    if let Some(derivation_path_info) = &config.derivation_path_info_opt {
        persistent_config
            .set_mnemonic_seed(
                &derivation_path_info.mnemonic_seed,
                &derivation_path_info.db_password,
            )
            .expect("Failed to set mnemonic seed");
        if let Some(consuming_derivation_path) = &derivation_path_info.consuming_derivation_path_opt
        {
            persistent_config.set_consuming_wallet_derivation_path(
                consuming_derivation_path,
                &derivation_path_info.db_password,
            )
        }
    }
}

pub fn initialize_database(
    data_directory: &PathBuf,
    chain_id: u8,
) -> Box<dyn PersistentConfiguration> {
    let conn = DbInitializerReal::new()
        .initialize(data_directory, chain_id, true)
        .unwrap_or_else(|e| {
            panic!(
                "Can't initialize database at {:?}: {:?}",
                data_directory.join(DATABASE_FILE),
                e
            )
        });
    Box::new(PersistentConfigurationReal::from(conn))
}

pub fn update_db_password(
    wallet_config: &WalletCreationConfig,
    persistent_config: &dyn PersistentConfiguration,
) {
    match &wallet_config.derivation_path_info_opt {
        Some(dpwi) => persistent_config.set_password(&dpwi.db_password),
        None => (),
    }
}

pub fn real_user_data_directory_opt_and_chain_name(
    dirs_wrapper: &dyn DirsWrapper,
    multi_config: &MultiConfig,
) -> (RealUser, Option<PathBuf>, String) {
    let real_user = match value_m!(multi_config, "real-user", RealUser) {
        None => RealUser::null().populate(dirs_wrapper),
        Some(real_user) => real_user.populate(dirs_wrapper),
    };
    let chain_name =
        value_m!(multi_config, "chain", String).unwrap_or_else(|| DEFAULT_CHAIN_NAME.to_string());
    let data_directory_opt = value_m!(multi_config, "data-directory", PathBuf);
    (real_user, data_directory_opt, chain_name)
}

pub fn data_directory_from_context(
    dirs_wrapper: &dyn DirsWrapper,
    real_user: &RealUser,
    data_directory_opt: &Option<PathBuf>,
    chain_name: &str,
) -> PathBuf {
    match data_directory_opt {
        Some(data_directory) => data_directory.clone(),
        None => {
            let right_home_dir = real_user
                .home_dir
                .as_ref()
                .expect("No real-user home directory; specify --real-user")
                .to_string_lossy()
                .to_string();
            let wrong_home_dir = dirs_wrapper
                .home_dir()
                .expect("No privileged home directory; specify --data-directory")
                .to_string_lossy()
                .to_string();
            let wrong_local_data_dir = dirs_wrapper
                .data_dir()
                .expect("No privileged local data directory; specify --data-directory")
                .to_string_lossy()
                .to_string();
            let right_local_data_dir =
                wrong_local_data_dir.replace(&wrong_home_dir, &right_home_dir);
            PathBuf::from(right_local_data_dir)
                .join("MASQ")
                .join(chain_name)
        }
    }
}

pub fn prepare_initialization_mode<'a>(
    dirs_wrapper: &dyn DirsWrapper,
    app: &'a App,
    args: &[String],
    streams: &mut StdStreams,
) -> Result<(MultiConfig<'a>, Box<dyn PersistentConfiguration>), ConfiguratorError> {
    let multi_config = make_new_multi_config(
        &app,
        vec![
            Box::new(CommandLineVcl::new(args.to_vec())),
            Box::new(EnvironmentVcl::new(&app)),
        ],
        streams,
    )?;

    let (real_user, data_directory_opt, chain_name) =
        real_user_data_directory_opt_and_chain_name(dirs_wrapper, &multi_config);
    let directory = data_directory_from_context(
        &RealDirsWrapper {},
        &real_user,
        &data_directory_opt,
        &chain_name,
    );
    let persistent_config_box = initialize_database(&directory, chain_id_from_name(&chain_name));
    if mnemonic_seed_exists(persistent_config_box.as_ref()) {
        exit_process(1, "Cannot re-initialize Node: already initialized")
    }
    Ok((multi_config, persistent_config_box))
}

pub fn request_new_db_password(
    streams: &mut StdStreams,
    possible_preamble: Option<&str>,
    prompt: &str,
    confirmation_prompt: &str,
) -> Option<String> {
    if let Some(preamble) = possible_preamble {
        flushed_write(streams.stdout, &format!("{}\n", preamble));
    }
    match request_password_with_retry(prompt, streams, |streams| {
        request_password_with_confirmation(
            confirmation_prompt,
            "Passwords do not match.",
            streams,
            cannot_be_blank,
        )
    }) {
        Ok(password) => Some(password),
        Err(PasswordError::RetriesExhausted) => None,
        Err(PasswordError::Mismatch) => None,
        Err(PasswordError::VerifyError(e)) => {
            flushed_write(
                streams.stdout,
                &format!("Could not elicit wallet encryption password: {:?}\n", e),
            );
            None
        }
    }
}

pub fn request_existing_db_password(
    streams: &mut StdStreams,
    possible_preamble: Option<&str>,
    prompt: &str,
    persistent_config: &dyn PersistentConfiguration,
) -> Option<String> {
    if persistent_config.check_password("bad password") == None {
        return None;
    }
    if let Some(preamble) = possible_preamble {
        flushed_write(streams.stdout, &format!("{}\n", preamble))
    };
    let verifier = move |password: &str| {
        if password.is_empty() {
            return Err("Password must not be blank.".to_string());
        }
        match persistent_config.check_password(password) {
            None => panic!("Database password disappeared"),
            Some(true) => Ok(()),
            Some(false) => Err("Incorrect password.".to_string()),
        }
    };
    match request_password_with_retry(prompt, streams, |streams| {
        request_existing_password(streams, verifier)
    }) {
        Ok(ref password) if password.is_empty() => None,
        Ok(password) => Some(password),
        Err(PasswordError::RetriesExhausted) => None,
        Err(e) => {
            flushed_write(
                streams.stdout,
                &format!("Could not elicit wallet decryption password: {:?}\n", e),
            );
            None
        }
    }
}

pub fn cannot_be_blank(password: &str) -> Result<(), String> {
    if password.is_empty() {
        Err("Password cannot be blank.".to_string())
    } else {
        Ok(())
    }
}

pub fn mnemonic_seed_exists(persistent_config: &dyn PersistentConfiguration) -> bool {
    matches! (persistent_config.mnemonic_seed("bad password"), Ok(Some(_)) | Err(PersistentConfigError::PasswordError))
}

#[derive(Debug, PartialEq, Clone)]
pub enum PasswordError {
    Mismatch,
    RetriesExhausted,
    VerifyError(String),
}

pub fn request_existing_password<F>(
    streams: &mut StdStreams,
    verifier: F,
) -> Result<String, PasswordError>
where
    F: FnOnce(&str) -> Result<(), String>,
{
    let reader_opt = possible_reader_from_stream(streams);
    let password = read_password_with_reader(reader_opt).expect("Fatal error");
    match verifier(&password) {
        Ok(_) => Ok(password),
        Err(msg) => Err(PasswordError::VerifyError(msg)),
    }
}

// require two matching entries
pub fn request_password_with_confirmation<F>(
    confirmation_prompt: &str,
    mismatch_msg: &str,
    streams: &mut StdStreams,
    verifier: F,
) -> Result<String, PasswordError>
where
    F: FnOnce(&str) -> Result<(), String>,
{
    let reader_opt = possible_reader_from_stream(streams);
    let password = read_password_with_reader(reader_opt).expect("Fatal error");
    match verifier(&password) {
        Ok(_) => {
            flushed_write(streams.stdout, confirmation_prompt);
            let reader_opt = possible_reader_from_stream(streams);
            let confirm = read_password_with_reader(reader_opt).expect("Fatal error");
            if password == confirm {
                Ok(password)
            } else {
                flushed_write(streams.stdout, mismatch_msg);
                Err(PasswordError::Mismatch)
            }
        }
        Err(msg) => Err(PasswordError::VerifyError(msg)),
    }
}

pub fn request_password_with_retry<R>(
    prompt: &str,
    streams: &mut StdStreams,
    requester: R,
) -> Result<String, PasswordError>
where
    R: Fn(&mut StdStreams) -> Result<String, PasswordError>,
{
    for attempt in &["Try again.", "Try again.", "Giving up."] {
        flushed_write(streams.stdout, prompt);
        match requester(streams) {
            Ok(password) => return Ok(password),
            Err(PasswordError::Mismatch) => {
                flushed_write(streams.stdout, &format!(" {}\n", attempt))
            }
            Err(PasswordError::VerifyError(msg)) => {
                flushed_write(streams.stdout, &format!("{} {}\n", msg, attempt))
            }
            Err(e) => flushed_write(streams.stdout, &format!("{:?} {}\n", e, attempt)),
        }
    }
    Err(PasswordError::RetriesExhausted)
}

pub fn possible_reader_from_stream(
    streams: &'_ mut StdStreams,
) -> Option<::std::io::Cursor<Vec<u8>>> {
    if cfg!(test) {
        let inner = streams
            .stdin
            .bytes()
            .take_while(|possible_byte| match possible_byte {
                Ok(possible_newline) => possible_newline != &10u8,
                _ => false,
            })
            .map(|possible_byte| possible_byte.expect("Not a byte"))
            .collect::<Vec<u8>>();
        Some(::std::io::Cursor::new(inner))
    } else {
        None
    }
}

pub fn data_directory_default(dirs_wrapper: &dyn DirsWrapper, chain_name: &'static str) -> String {
    match dirs_wrapper.data_dir() {
        Some(path) => path.join("MASQ").join(chain_name),
        None => PathBuf::from(""),
    }
    .to_str()
    .expect("Internal Error")
    .to_string()
}

pub fn flushed_write(target: &mut dyn io::Write, string: &str) {
    write!(target, "{}", string).expect("Failed console write.");
    target.flush().expect("Failed flush.");
}

pub fn port_is_busy(port: u16) -> bool {
    TcpListener::bind(SocketAddr::new(localhost(), port)).is_err()
}

pub mod common_validators {
    use masq_lib::constants::LOWEST_USABLE_INSECURE_PORT;
    use regex::Regex;
    use tiny_hderive::bip44::DerivationPath;

    pub fn validate_earning_wallet(value: String) -> Result<(), String> {
        validate_ethereum_address(value.clone()).or_else(|_| validate_derivation_path(value))
    }

    pub fn validate_ethereum_address(address: String) -> Result<(), String> {
        if Regex::new("^0x[0-9a-fA-F]{40}$")
            .expect("Failed to compile regular expression")
            .is_match(&address)
        {
            Ok(())
        } else {
            Err(address)
        }
    }

    pub fn validate_derivation_path(path: String) -> Result<(), String> {
        let possible_path = path.parse::<DerivationPath>();

        match possible_path {
            Ok(derivation_path) => {
                validate_derivation_path_is_sufficiently_hardened(derivation_path, path)
            }
            Err(e) => Err(format!("{} is not valid: {:?}", path, e)),
        }
    }

    pub fn validate_derivation_path_is_sufficiently_hardened(
        derivation_path: DerivationPath,
        path: String,
    ) -> Result<(), String> {
        if derivation_path
            .iter()
            .filter(|child_nbr| child_nbr.is_hardened())
            .count()
            > 2
        {
            Ok(())
        } else {
            Err(format!("{} may be too weak", path))
        }
    }

    pub fn validate_real_user(triple: String) -> Result<(), String> {
        if Regex::new("^[0-9]*:[0-9]*:.*$")
            .expect("Failed to compile regular expression")
            .is_match(&triple)
        {
            Ok(())
        } else {
            Err(triple)
        }
    }

    pub fn validate_ui_port(port: String) -> Result<(), String> {
        match str::parse::<u16>(&port) {
            Ok(port_number) if port_number < LOWEST_USABLE_INSECURE_PORT => Err(port),
            Ok(_) => Ok(()),
            Err(_) => Err(port),
        }
    }
}

pub trait DirsWrapper: Send {
    fn data_dir(&self) -> Option<PathBuf>;
    fn home_dir(&self) -> Option<PathBuf>;
    fn dup(&self) -> Box<dyn DirsWrapper>; // because implementing Clone for traits is problematic.
}

pub struct RealDirsWrapper;

impl DirsWrapper for RealDirsWrapper {
    fn data_dir(&self) -> Option<PathBuf> {
        data_local_dir()
    }
    fn home_dir(&self) -> Option<PathBuf> {
        home_dir()
    }
    fn dup(&self) -> Box<dyn DirsWrapper> {
        Box::new(RealDirsWrapper {})
    }
}

#[derive(Debug, PartialEq)]
pub enum Either<L: Debug + PartialEq, R: Debug + PartialEq> {
    Left(L),
    Right(R),
}

#[derive(PartialEq, Debug)]
pub struct DerivationPathWalletInfo {
    pub mnemonic_seed: PlainData,
    pub db_password: String,
    pub consuming_derivation_path_opt: Option<String>,
}

#[derive(PartialEq, Debug)]
pub struct WalletCreationConfig {
    pub earning_wallet_address_opt: Option<String>,
    pub derivation_path_info_opt: Option<DerivationPathWalletInfo>,
    pub real_user: RealUser,
}

pub trait WalletCreationConfigMaker {
    fn make_wallet_creation_config(
        &self,
        multi_config: &MultiConfig,
        streams: &mut StdStreams<'_>,
    ) -> WalletCreationConfig {
        let mnemonic_passphrase = match value_m!(multi_config, "mnemonic-passphrase", String) {
            Some(mp) => mp,
            None => self.make_mnemonic_passphrase(multi_config, streams),
        };
        let db_password = match value_m!(multi_config, "db-password", String) {
            Some(wp) => wp,
            None => self.make_db_password(streams),
        };
        let consuming_derivation_path = match value_m!(multi_config, "consuming-wallet", String) {
            Some(cdp) => cdp,
            None => self.make_consuming_derivation_path(streams),
        };
        let earning_wallet_info = match value_m!(multi_config, "earning-wallet", String) {
            Some(value) => match DerivationPath::from_str(&value) {
                Ok(_) => Either::Right(value),
                Err(_) => match value[2..].from_hex::<Vec<u8>>() {
                    Ok(bytes) => match bytes.len() {
                        20 => Either::Left(value),
                        _ => panic!("--earning-wallet not properly validated by clap"),
                    },
                    Err(e) => panic!("--earning-wallet not properly validated by clap: {:?}", e),
                },
            },
            None => self.make_earning_wallet_info(streams),
        };
        let mnemonic_seed = self.make_mnemonic_seed(
            multi_config,
            streams,
            &mnemonic_passphrase,
            &consuming_derivation_path,
            &earning_wallet_info,
        );
        let real_user = match value_m!(multi_config, "real-user", RealUser) {
            Some(ru) => ru,
            None => RealUser::null(),
        };
        WalletCreationConfig {
            earning_wallet_address_opt: match &earning_wallet_info {
                Either::Left(address) => Some(address.clone()),
                Either::Right(path) => {
                    let keypair = Bip32ECKeyPair::from_raw(mnemonic_seed.as_slice(), path)
                        .expect("--earning-wallet not properly validated by clap");
                    let wallet = Wallet::from(keypair);
                    Some(wallet.to_string())
                }
            },
            derivation_path_info_opt: Some(DerivationPathWalletInfo {
                mnemonic_seed,
                db_password,
                consuming_derivation_path_opt: Some(consuming_derivation_path),
            }),
            real_user,
        }
    }

    fn make_db_password(&self, streams: &mut StdStreams) -> String {
        match request_new_db_password(
            streams,
            Some("\n\nPlease provide a password to encrypt your wallet (This password can be changed later)..."),
            "  Enter password: ",
            "  Confirm password: ",
        ) {
            Some(wp) => wp,
            None => panic!("Wallet encryption password is required!")
        }
    }

    fn make_consuming_derivation_path(&self, _streams: &mut StdStreams) -> String {
        DEFAULT_CONSUMING_DERIVATION_PATH.to_string()
    }

    fn make_earning_wallet_info(&self, _streams: &mut StdStreams) -> Either<String, String> {
        Either::Right(DEFAULT_EARNING_DERIVATION_PATH.to_string())
    }

    fn make_mnemonic_passphrase(
        &self,
        multi_config: &MultiConfig,
        streams: &mut StdStreams<'_>,
    ) -> String;

    fn make_mnemonic_seed(
        &self,
        multi_config: &MultiConfig,
        streams: &mut StdStreams<'_>,
        mnemonic_passphrase: &str,
        consuming_derivation_path: &str,
        earning_wallet_info: &Either<String, String>,
    ) -> PlainData;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blockchain::bip32::Bip32ECKeyPair;
    use crate::node_configurator::node_configurator_standard::app;
    use crate::node_test_utils::MockDirsWrapper;
    use crate::sub_lib::utils::make_new_test_multi_config;
    use crate::sub_lib::wallet::{Wallet, DEFAULT_EARNING_DERIVATION_PATH};
    use crate::test_utils::persistent_configuration_mock::PersistentConfigurationMock;
    use crate::test_utils::ArgsBuilder;
    use bip39::{Mnemonic, MnemonicType, Seed};
    use masq_lib::constants::DEFAULT_CHAIN_NAME;
    use masq_lib::multi_config::MultiConfig;
    use masq_lib::shared_schema::db_password_arg;
    use masq_lib::test_utils::environment_guard::EnvironmentGuard;
    use masq_lib::test_utils::fake_stream_holder::{ByteArrayWriter, FakeStreamHolder};
    use masq_lib::test_utils::utils::{
        ensure_node_home_directory_exists, DEFAULT_CHAIN_ID, TEST_DEFAULT_CHAIN_NAME,
    };
    use masq_lib::utils::{find_free_port, running_test};
    use std::io::Cursor;
    use std::net::{SocketAddr, TcpListener};
    use std::sync::{Arc, Mutex};
    use tiny_hderive::bip44::DerivationPath;

    #[test]
    fn validate_ethereum_address_requires_an_address_that_is_42_characters_long() {
        assert_eq!(
            Err(String::from("my-favorite-wallet.com")),
            common_validators::validate_ethereum_address(String::from("my-favorite-wallet.com")),
        );
    }

    #[test]
    fn validate_ethereum_address_must_start_with_0x() {
        assert_eq!(
            Err(String::from("x0my-favorite-wallet.com222222222222222222")),
            common_validators::validate_ethereum_address(String::from(
                "x0my-favorite-wallet.com222222222222222222"
            ))
        );
    }

    #[test]
    fn validate_ethereum_address_must_contain_only_hex_characters() {
        assert_eq!(
            Err(String::from("0x9707f21F95B9839A54605100Ca69dCc2e7eaA26q")),
            common_validators::validate_ethereum_address(String::from(
                "0x9707f21F95B9839A54605100Ca69dCc2e7eaA26q"
            ))
        );
    }

    #[test]
    fn validate_ethereum_address_when_happy() {
        assert_eq!(
            Ok(()),
            common_validators::validate_ethereum_address(String::from(
                "0xbDfeFf9A1f4A1bdF483d680046344316019C58CF"
            ))
        );
    }

    #[test]
    fn validate_earning_wallet_works_with_address() {
        assert!(common_validators::validate_earning_wallet(String::from(
            "0xbDfeFf9A1f4A1bdF483d680046344316019C58CF"
        ))
        .is_ok());
    }

    #[test]
    fn validate_earning_wallet_works_with_derivation_path() {
        assert!(common_validators::validate_earning_wallet(String::from(
            DEFAULT_EARNING_DERIVATION_PATH
        ))
        .is_ok());
    }

    #[test]
    fn validate_derivation_path_happy() {
        assert_eq!(
            Ok(()),
            common_validators::validate_derivation_path(
                DEFAULT_CONSUMING_DERIVATION_PATH.to_string()
            )
        );
    }

    #[test]
    fn validate_derivation_path_sad_eth_address() {
        assert_eq!(
            Err(
                "0xbDfeFf9A1f4A1bdF483d680046344316019C58CF is not valid: InvalidDerivationPath"
                    .to_string()
            ),
            common_validators::validate_derivation_path(
                "0xbDfeFf9A1f4A1bdF483d680046344316019C58CF".to_string()
            )
        );
    }

    #[test]
    fn validate_derivation_path_sad_malformed_with_backslashes() {
        assert_eq!(
            Err(r"m\44'\60'\0'\0\0 is not valid: InvalidDerivationPath".to_string()),
            common_validators::validate_derivation_path(r"m\44'\60'\0'\0\0".to_string())
        );
    }

    #[test]
    fn validate_derivation_path_sad_malformed_missing_m() {
        assert_eq!(
            Err("/44'/60'/0'/0/0 is not valid: InvalidDerivationPath".to_string()),
            common_validators::validate_derivation_path("/44'/60'/0'/0/0".to_string())
        );
    }

    #[test]
    fn validate_derivation_path_sad_insufficiently_hardened() {
        assert_eq!(
            common_validators::validate_derivation_path("m/44/60/0/0/0".to_string()),
            Err("m/44/60/0/0/0 may be too weak".to_string()),
        );
    }

    #[test]
    fn validate_derivation_path_is_sufficiently_hardened_happy() {
        assert!(
            common_validators::validate_derivation_path_is_sufficiently_hardened(
                DEFAULT_CONSUMING_DERIVATION_PATH
                    .parse::<DerivationPath>()
                    .unwrap(),
                DEFAULT_CONSUMING_DERIVATION_PATH.to_string(),
            )
            .is_ok()
        );
    }

    #[test]
    fn validate_derivation_path_is_sufficiently_hardened_sad() {
        assert_eq!(
            Err("m/44'/60'/0/0/0 may be too weak".to_string()),
            common_validators::validate_derivation_path_is_sufficiently_hardened(
                "m/44'/60'/0/0/0".parse::<DerivationPath>().unwrap(),
                "m/44'/60'/0/0/0".to_string(),
            )
        );
    }

    #[test]
    fn validate_derivation_path_is_sufficiently_hardened_very_sad() {
        assert_eq!(
            Err("m/44/60/0/0/0 may be too weak".to_string()),
            common_validators::validate_derivation_path_is_sufficiently_hardened(
                "m/44/60/0/0/0".parse::<DerivationPath>().unwrap(),
                "m/44/60/0/0/0".to_string(),
            )
        );
    }

    #[test]
    fn validate_real_user_accepts_all_fields() {
        let result = common_validators::validate_real_user(String::from("999:999:/home/booga"));

        assert_eq!(Ok(()), result);
    }

    #[test]
    fn validate_real_user_accepts_no_fields() {
        let result = common_validators::validate_real_user(String::from("::"));

        assert_eq!(Ok(()), result);
    }

    #[test]
    fn validate_real_user_rejects_non_numeric_uid() {
        let result = common_validators::validate_real_user(String::from("abc:999:/home/booga"));

        assert_eq!(Err(String::from("abc:999:/home/booga")), result);
    }

    #[test]
    fn validate_real_user_rejects_non_numeric_gid() {
        let result = common_validators::validate_real_user(String::from("999:abc:/home/booga"));

        assert_eq!(Err(String::from("999:abc:/home/booga")), result);
    }

    #[test]
    fn validate_real_user_rejects_too_few_colons() {
        let result = common_validators::validate_real_user(String::from(":"));

        assert_eq!(Err(String::from(":")), result);
    }

    #[test]
    fn validate_real_user_accepts_too_many_colons() {
        let result = common_validators::validate_real_user(String::from(":::"));

        assert_eq!(Ok(()), result);
    }

    #[test]
    fn data_directory_default_given_no_default() {
        assert_eq!(
            String::from(""),
            data_directory_default(
                &MockDirsWrapper::new().data_dir_result(None),
                TEST_DEFAULT_CHAIN_NAME
            )
        );
    }

    #[test]
    fn data_directory_default_works() {
        let mock_dirs_wrapper = MockDirsWrapper::new().data_dir_result(Some("mocked/path".into()));

        let result = data_directory_default(&mock_dirs_wrapper, DEFAULT_CHAIN_NAME);

        let expected = PathBuf::from("mocked/path")
            .join("MASQ")
            .join(DEFAULT_CHAIN_NAME);
        assert_eq!(result, expected.as_path().to_str().unwrap().to_string());
    }

    #[test]
    #[should_panic(expected = "1: Cannot re-initialize Node: already initialized")]
    fn prepare_initialization_mode_fails_if_mnemonic_seed_already_exists() {
        let data_dir = ensure_node_home_directory_exists(
            "node_configurator",
            "prepare_initialization_mode_fails_if_mnemonic_seed_already_exists",
        )
        .join("Substratum")
        .join(TEST_DEFAULT_CHAIN_NAME);
        {
            let conn = DbInitializerReal::new()
                .initialize(&data_dir, DEFAULT_CHAIN_ID, true)
                .unwrap();
            let persistent_config = PersistentConfigurationReal::from(conn);
            persistent_config
                .set_mnemonic_seed(&PlainData::new(&[1, 2, 3, 4]), "password")
                .unwrap();
        }
        let app = App::new("test".to_string())
            .arg(data_directory_arg())
            .arg(chain_arg());
        let args = ArgsBuilder::new()
            .param("--data-directory", data_dir.to_str().unwrap())
            .param("--chain", TEST_DEFAULT_CHAIN_NAME);
        let args_vec: Vec<String> = args.into();

        let _ = prepare_initialization_mode(
            &RealDirsWrapper {},
            &app,
            args_vec.as_slice(),
            &mut FakeStreamHolder::new().streams(),
        );
    }

    fn determine_config_file_path_app() -> App<'static, 'static> {
        App::new("test")
            .arg(data_directory_arg())
            .arg(config_file_arg())
    }

    #[test]
    fn real_user_data_directory_and_chain_id_picks_correct_directory_for_default_chain() {
        let args = ArgsBuilder::new();
        let vcl = Box::new(CommandLineVcl::new(args.into()));
        let multi_config = make_new_test_multi_config(&app(), vec![vcl]).unwrap();

        let (real_user, data_directory_opt, chain_name) =
            real_user_data_directory_opt_and_chain_name(&RealDirsWrapper {}, &multi_config);
        let directory = data_directory_from_context(
            &RealDirsWrapper {},
            &real_user,
            &data_directory_opt,
            &chain_name,
        );

        let expected_root = RealDirsWrapper {}.data_dir().unwrap();
        let expected_directory = expected_root.join("MASQ").join(DEFAULT_CHAIN_NAME);
        assert_eq!(directory, expected_directory);
        assert_eq!(&chain_name, DEFAULT_CHAIN_NAME);
    }

    #[test]
    fn determine_config_file_path_finds_path_in_args() {
        let _guard = EnvironmentGuard::new();
        let args = ArgsBuilder::new()
            .param("--clandestine-port", "2345")
            .param("--data-directory", "data-dir")
            .param("--config-file", "booga.toml");
        let args_vec: Vec<String> = args.into();

        let (config_file_path, user_specified) = determine_config_file_path(
            &RealDirsWrapper {},
            &determine_config_file_path_app(),
            args_vec.as_slice(),
        )
        .unwrap();

        assert_eq!(
            &format!("{}", config_file_path.parent().unwrap().display()),
            "data-dir",
        );
        assert_eq!("booga.toml", config_file_path.file_name().unwrap());
        assert_eq!(true, user_specified);
    }

    #[test]
    fn determine_config_file_path_finds_path_in_environment() {
        let _guard = EnvironmentGuard::new();
        let args = ArgsBuilder::new();
        let args_vec: Vec<String> = args.into();
        std::env::set_var("MASQ_DATA_DIRECTORY", "data_dir");
        std::env::set_var("MASQ_CONFIG_FILE", "booga.toml");

        let (config_file_path, user_specified) = determine_config_file_path(
            &RealDirsWrapper {},
            &determine_config_file_path_app(),
            args_vec.as_slice(),
        )
        .unwrap();

        assert_eq!(
            "data_dir",
            &format!("{}", config_file_path.parent().unwrap().display())
        );
        assert_eq!("booga.toml", config_file_path.file_name().unwrap());
        assert_eq!(true, user_specified);
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn determine_config_file_path_ignores_data_dir_if_config_file_has_root() {
        let _guard = EnvironmentGuard::new();
        let args = ArgsBuilder::new()
            .param("--data-directory", "data-dir")
            .param("--config-file", "/tmp/booga.toml");
        let args_vec: Vec<String> = args.into();

        let (config_file_path, user_specified) = determine_config_file_path(
            &RealDirsWrapper {},
            &determine_config_file_path_app(),
            args_vec.as_slice(),
        )
        .unwrap();

        assert_eq!(
            "/tmp/booga.toml",
            &format!("{}", config_file_path.display())
        );
        assert_eq!(true, user_specified);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn determine_config_file_path_ignores_data_dir_if_config_file_has_separator_root() {
        let _guard = EnvironmentGuard::new();
        let args = ArgsBuilder::new()
            .param("--data-directory", "data-dir")
            .param("--config-file", r"\tmp\booga.toml");
        let args_vec: Vec<String> = args.into();

        let (config_file_path, user_specified) = determine_config_file_path(
            &RealDirsWrapper {},
            &determine_config_file_path_app(),
            args_vec.as_slice(),
        )
        .unwrap();

        assert_eq!(
            r"\tmp\booga.toml",
            &format!("{}", config_file_path.display())
        );
        assert_eq!(true, user_specified);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn determine_config_file_path_ignores_data_dir_if_config_file_has_drive_root() {
        let _guard = EnvironmentGuard::new();
        let args = ArgsBuilder::new()
            .param("--data-directory", "data-dir")
            .param("--config-file", r"c:\tmp\booga.toml");
        let args_vec: Vec<String> = args.into();

        let (config_file_path, user_specified) = determine_config_file_path(
            &RealDirsWrapper {},
            &determine_config_file_path_app(),
            args_vec.as_slice(),
        )
        .unwrap();

        assert_eq!(
            r"c:\tmp\booga.toml",
            &format!("{}", config_file_path.display())
        );
        assert_eq!(true, user_specified);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn determine_config_file_path_ignores_data_dir_if_config_file_has_network_root() {
        let _guard = EnvironmentGuard::new();
        let args = ArgsBuilder::new()
            .param("--data-directory", "data-dir")
            .param("--config-file", r"\\TMP\booga.toml");
        let args_vec: Vec<String> = args.into();

        let (config_file_path, user_specified) = determine_config_file_path(
            &RealDirsWrapper {},
            &determine_config_file_path_app(),
            args_vec.as_slice(),
        )
        .unwrap();

        assert_eq!(
            r"\\TMP\booga.toml",
            &format!("{}", config_file_path.display())
        );
        assert_eq!(true, user_specified);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn determine_config_file_path_ignores_data_dir_if_config_file_has_drive_letter_but_no_separator(
    ) {
        let _guard = EnvironmentGuard::new();
        let args = ArgsBuilder::new()
            .param("--data-directory", "data-dir")
            .param("--config-file", r"c:tmp\booga.toml");
        let args_vec: Vec<String> = args.into();

        let (config_file_path, user_specified) = determine_config_file_path(
            &RealDirsWrapper {},
            &determine_config_file_path_app(),
            args_vec.as_slice(),
        )
        .unwrap();

        assert_eq!(
            r"c:tmp\booga.toml",
            &format!("{}", config_file_path.display())
        );
        assert_eq!(true, user_specified);
    }

    #[test]
    fn request_database_password_happy_path() {
        let stdout_writer = &mut ByteArrayWriter::new();
        let streams = &mut StdStreams {
            stdin: &mut Cursor::new(&b"Too Many S3cr3ts!\n"[..]),
            stdout: stdout_writer,
            stderr: &mut ByteArrayWriter::new(),
        };
        let persistent_configuration = PersistentConfigurationMock::new()
            .check_password_result(Some(false))
            .check_password_result(Some(true));

        let actual = request_existing_db_password(
            streams,
            Some("Decrypt wallet"),
            "Enter password: ",
            &persistent_configuration,
        );

        assert_eq!(actual, Some("Too Many S3cr3ts!".to_string()));
        assert_eq!(
            stdout_writer.get_string(),
            "Decrypt wallet\n\
             Enter password: "
                .to_string()
        );
    }

    #[test]
    fn request_database_password_rejects_blank_password() {
        let stdout_writer = &mut ByteArrayWriter::new();
        let streams = &mut StdStreams {
            stdin: &mut Cursor::new(&b"\nbooga\n"[..]),
            stdout: stdout_writer,
            stderr: &mut ByteArrayWriter::new(),
        };
        let persistent_configuration = PersistentConfigurationMock::new()
            .check_password_result(Some(false))
            .check_password_result(Some(true));

        let actual = request_existing_db_password(
            streams,
            Some("Decrypt wallet"),
            "Enter password: ",
            &persistent_configuration,
        );

        assert_eq!(actual, Some("booga".to_string()));
        assert_eq!(
            stdout_writer.get_string(),
            "Decrypt wallet\n\
             Enter password: \
             Password must not be blank. Try again.\n\
             Enter password: "
                .to_string()
        );
    }

    #[test]
    fn request_database_password_detects_bad_passwords() {
        let stdout_writer = &mut ByteArrayWriter::new();
        let streams = &mut StdStreams {
            stdin: &mut Cursor::new(
                &b"first bad password\nanother bad password\nfinal bad password\n"[..],
            ),
            stdout: stdout_writer,
            stderr: &mut ByteArrayWriter::new(),
        };
        let check_password_params_arc = Arc::new(Mutex::new(vec![]));
        let persistent_configuration = PersistentConfigurationMock::new()
            .check_password_params(&check_password_params_arc)
            .check_password_result(Some(false))
            .check_password_result(Some(false))
            .check_password_result(Some(false))
            .check_password_result(Some(false));

        let actual = request_existing_db_password(
            streams,
            Some("Decrypt wallet"),
            "Enter password: ",
            &persistent_configuration,
        );

        assert_eq!(actual, None);
        assert_eq!(
            stdout_writer.get_string(),
            "Decrypt wallet\n\
             Enter password: \
             Incorrect password. Try again.\n\
             Enter password: \
             Incorrect password. Try again.\n\
             Enter password: \
             Incorrect password. Giving up.\n"
                .to_string()
        );
        let check_password_params = check_password_params_arc.lock().unwrap();
        assert_eq!(
            *check_password_params,
            vec![
                "bad password".to_string(),
                "first bad password".to_string(),
                "another bad password".to_string(),
                "final bad password".to_string()
            ]
        )
    }

    #[test]
    fn request_database_password_aborts_before_prompting_if_database_has_no_password() {
        let stdout_writer = &mut ByteArrayWriter::new();
        let streams = &mut StdStreams {
            stdin: &mut Cursor::new(&b""[..]),
            stdout: stdout_writer,
            stderr: &mut ByteArrayWriter::new(),
        };
        let persistent_configuration =
            PersistentConfigurationMock::new().check_password_result(None);

        let actual = request_existing_db_password(
            streams,
            Some("Decrypt wallet"),
            "Enter password: ",
            &persistent_configuration,
        );

        assert_eq!(actual, None);
        assert_eq!(stdout_writer.get_string(), "".to_string());
    }

    #[test]
    fn request_wallet_encryption_password_succeeds_on_reattempt() {
        let stdout_writer = &mut ByteArrayWriter::new();
        let streams = &mut StdStreams {
            stdin: &mut Cursor::new(
                &b"Too Many S3cr3ts!\ngarbage garbage\nToo Many S3cr3ts!\nToo Many S3cr3ts!\n"[..],
            ),
            stdout: stdout_writer,
            stderr: &mut ByteArrayWriter::new(),
        };

        let actual = request_new_db_password(
            streams,
            Some("\n\nPlease provide a password to encrypt your wallet (This password can be changed \
             later)..."), "  Enter password: ", "Confirm password: ",
        );

        assert_eq!(actual, Some("Too Many S3cr3ts!".to_string()));
        assert_eq!(
            stdout_writer.get_string(),
            "\n\nPlease provide a password to encrypt your wallet (This password can be changed later)...\
                \n  Enter password: \
                Confirm password: \
                Passwords do not match. Try again.\
                \n  Enter password: \
                Confirm password: "
                .to_string()
        );
    }

    #[test]
    fn request_wallet_encryption_password_gives_up_after_three_blank_passwords() {
        let stdout_writer = &mut ByteArrayWriter::new();
        let streams = &mut StdStreams {
            stdin: &mut Cursor::new(&b"\n\n\n"[..]),
            stdout: stdout_writer,
            stderr: &mut ByteArrayWriter::new(),
        };

        let actual = request_new_db_password(
            streams,
            Some("\n\nPlease provide a password to encrypt your wallet (This password can be changed \
             later)..."), "  Enter password: ", "\nConfirm password: ",
        );

        assert_eq!(actual, None);
        assert_eq!(
            stdout_writer.get_string(),
            "\n\nPlease provide a password to encrypt your wallet (This password can be changed later)...\
                \n  Enter password: \
                Password cannot be blank. Try again.\
                \n  Enter password: \
                Password cannot be blank. Try again.\
                \n  Enter password: \
                Password cannot be blank. Giving up.\
                \n"
                .to_string()
        );
    }

    #[test]
    fn request_wallet_encryption_password_gives_up_after_three_mismatches() {
        let stdout_writer = &mut ByteArrayWriter::new();
        let streams = &mut StdStreams {
            stdin: &mut Cursor::new(&b"one\n\ntwo\n\nthree\n\n"[..]),
            stdout: stdout_writer,
            stderr: &mut ByteArrayWriter::new(),
        };

        let actual = request_new_db_password(
            streams,
            Some("\n\nPlease provide a password to encrypt your wallet (This password can be changed \
             later)..."), "  Enter password: ", "Confirm password: ",
        );

        assert_eq!(actual, None);
        assert_eq!(
            stdout_writer.get_string(),
            "\n\nPlease provide a password to encrypt your wallet (This password can be changed later)...\
                \n  Enter password: \
                Confirm password: \
                Passwords do not match. Try again.\
                \n  Enter password: \
                Confirm password: \
                Passwords do not match. Try again.\
                \n  Enter password: \
                Confirm password: \
                Passwords do not match. Giving up.\
                \n"
                .to_string()
        );
    }

    struct TameWalletCreationConfigMaker {
        app: App<'static, 'static>,
    }

    impl WalletCreationConfigMaker for TameWalletCreationConfigMaker {
        fn make_mnemonic_passphrase(
            &self,
            _multi_config: &MultiConfig,
            streams: &mut StdStreams,
        ) -> String {
            flushed_write(streams.stdout, "Enter mnemonic passphrase: ");
            "mnemonic passphrase".to_string()
        }

        fn make_mnemonic_seed(
            &self,
            _multi_config: &MultiConfig,
            _streams: &mut StdStreams,
            _mnemonic_passphrase: &str,
            _consuming_derivation_path: &str,
            _earning_wallet_info: &Either<String, String>,
        ) -> PlainData {
            Self::hardcoded_mnemonic_seed()
        }
    }

    impl TameWalletCreationConfigMaker {
        fn hardcoded_mnemonic_seed() -> PlainData {
            let mnemonic = Mnemonic::from_phrase(
                "list noble dove unable pioneer alien live market mercy equip supreme agree",
                Language::English,
            )
            .unwrap();
            PlainData::new(Seed::new(&mnemonic, "passphrase").as_ref())
        }
    }

    impl TameWalletCreationConfigMaker {
        pub fn new() -> TameWalletCreationConfigMaker {
            TameWalletCreationConfigMaker {
                app: App::new("TameWalletCreationConfigMaker")
                    .arg(consuming_wallet_arg())
                    .arg(earning_wallet_arg("", |_| Ok(())))
                    .arg(mnemonic_passphrase_arg())
                    .arg(real_user_arg())
                    .arg(db_password_arg(DB_PASSWORD_HELP)),
            }
        }
    }

    #[test]
    fn make_wallet_creation_config_defaults() {
        let subject = TameWalletCreationConfigMaker::new();
        let vcl = Box::new(CommandLineVcl::new(vec!["test".to_string()]));
        let multi_config = make_new_test_multi_config(&subject.app, vec![vcl]).unwrap();
        let stdout_writer = &mut ByteArrayWriter::new();
        let mut streams = &mut StdStreams {
            stdin: &mut Cursor::new(&b"a terrible db password\na terrible db password\n"[..]),
            stdout: stdout_writer,
            stderr: &mut ByteArrayWriter::new(),
        };

        let config = subject.make_wallet_creation_config(&multi_config, &mut streams);

        let captured_output = stdout_writer.get_string();
        let expected_output = "Enter mnemonic passphrase: \
        \n\nPlease provide a password to encrypt your wallet (This password can be changed later)...\
        \n  Enter password:   Confirm password: ";
        assert_eq!(&captured_output, expected_output);
        let earning_wallet = Wallet::from(
            Bip32ECKeyPair::from_raw(
                TameWalletCreationConfigMaker::hardcoded_mnemonic_seed().as_ref(),
                DEFAULT_EARNING_DERIVATION_PATH,
            )
            .unwrap(),
        );
        assert_eq!(
            config,
            WalletCreationConfig {
                earning_wallet_address_opt: Some(earning_wallet.to_string()),
                derivation_path_info_opt: Some(DerivationPathWalletInfo {
                    mnemonic_seed: TameWalletCreationConfigMaker::hardcoded_mnemonic_seed(),
                    db_password: "a terrible db password".to_string(),
                    consuming_derivation_path_opt: Some(
                        DEFAULT_CONSUMING_DERIVATION_PATH.to_string()
                    ),
                }),
                real_user: RealUser::null(),
            },
        );
    }

    #[test]
    fn make_wallet_creation_config_non_defaults_with_earning_derivation_path() {
        running_test();
        let earning_path = "m/44'/60'/3'/2/1";
        let subject = TameWalletCreationConfigMaker::new();
        let args = ArgsBuilder::new()
            .param("--consuming-wallet", "m/44'/60'/1'/2/3")
            .param("--earning-wallet", "m/44'/60'/3'/2/1")
            .param("--mnemonic-passphrase", "mnemonic passphrase")
            .param("--db-password", "db password")
            .param("--real-user", "123::");
        let vcl = Box::new(CommandLineVcl::new(args.into()));
        let multi_config = make_new_test_multi_config(&subject.app, vec![vcl]).unwrap();
        let stdout_writer = &mut ByteArrayWriter::new();
        let mut streams = &mut StdStreams {
            stdin: &mut Cursor::new(&[]),
            stdout: stdout_writer,
            stderr: &mut ByteArrayWriter::new(),
        };

        let config = subject.make_wallet_creation_config(&multi_config, &mut streams);

        let captured_output = stdout_writer.get_string();
        let expected_output = "";
        assert_eq!(&captured_output, expected_output);
        let earning_wallet = Wallet::from(
            Bip32ECKeyPair::from_raw(
                TameWalletCreationConfigMaker::hardcoded_mnemonic_seed().as_ref(),
                earning_path,
            )
            .unwrap(),
        );
        assert_eq!(
            config,
            WalletCreationConfig {
                earning_wallet_address_opt: Some(earning_wallet.to_string()),
                derivation_path_info_opt: Some(DerivationPathWalletInfo {
                    mnemonic_seed: TameWalletCreationConfigMaker::hardcoded_mnemonic_seed(),
                    db_password: "db password".to_string(),
                    consuming_derivation_path_opt: Some("m/44'/60'/1'/2/3".to_string()),
                }),
                real_user: RealUser::new(Some(123), None, None),
            },
        );
    }

    #[test]
    fn make_wallet_creation_config_non_defaults_with_earning_address() {
        running_test();
        let subject = TameWalletCreationConfigMaker::new();
        let args = ArgsBuilder::new()
            .param("--consuming-wallet", "m/44'/60'/1'/2/3")
            .param(
                "--earning-wallet",
                "0x0123456789ABCDEF0123456789ABCDEF01234567",
            )
            .param("--mnemonic-passphrase", "mnemonic passphrase")
            .param("--db-password", "db password")
            .param("--real-user", "123::");
        let vcl = Box::new(CommandLineVcl::new(args.into()));
        let multi_config = make_new_test_multi_config(&subject.app, vec![vcl]).unwrap();
        let stdout_writer = &mut ByteArrayWriter::new();
        let mut streams = &mut StdStreams {
            stdin: &mut Cursor::new(&[]),
            stdout: stdout_writer,
            stderr: &mut ByteArrayWriter::new(),
        };

        let config = subject.make_wallet_creation_config(&multi_config, &mut streams);

        let captured_output = stdout_writer.get_string();
        let expected_output = "";
        assert_eq!(&captured_output, expected_output);
        assert_eq!(
            config,
            WalletCreationConfig {
                earning_wallet_address_opt: Some(
                    "0x0123456789ABCDEF0123456789ABCDEF01234567".to_string()
                ),
                derivation_path_info_opt: Some(DerivationPathWalletInfo {
                    mnemonic_seed: TameWalletCreationConfigMaker::hardcoded_mnemonic_seed(),
                    db_password: "db password".to_string(),
                    consuming_derivation_path_opt: Some("m/44'/60'/1'/2/3".to_string()),
                }),
                real_user: RealUser::new(Some(123), None, None),
            },
        );
    }

    #[test]
    #[should_panic(expected = "Wallet encryption password is required!")]
    fn make_wallet_creation_config_panics_after_three_password_mismatches() {
        running_test();
        let subject = TameWalletCreationConfigMaker::new();
        let streams = &mut StdStreams {
            stdin: &mut Cursor::new(&b"one\n\ntwo\n\nthree\n\n"[..]),
            stdout: &mut ByteArrayWriter::new(),
            stderr: &mut ByteArrayWriter::new(),
        };
        let vcl = Box::new(CommandLineVcl::new(vec!["test".to_string()]));
        let multi_config = make_new_test_multi_config(&subject.app, vec![vcl]).unwrap();

        subject.make_wallet_creation_config(&multi_config, streams);
    }

    #[test]
    fn create_wallet_configures_database_with_earning_path() {
        let earning_path = "m/44'/60'/3'/2/1";
        let mnemonic = Mnemonic::new(MnemonicType::Words24, Language::English);
        let seed = Seed::new(&mnemonic, "passphrase");
        let earning_keypair = Bip32ECKeyPair::from_raw(seed.as_ref(), earning_path).unwrap();
        let earning_address = Wallet::from(earning_keypair).to_string();
        let config = WalletCreationConfig {
            earning_wallet_address_opt: Some(earning_address.clone()),
            derivation_path_info_opt: Some(DerivationPathWalletInfo {
                mnemonic_seed: PlainData::new(seed.as_ref()),
                db_password: "db password".to_string(),
                consuming_derivation_path_opt: Some("m/44'/60'/1'/2/3".to_string()),
            }),
            real_user: RealUser::null(),
        };
        let set_mnemonic_seed_params_arc = Arc::new(Mutex::new(vec![]));
        let set_consuming_wallet_derivation_path_params_arc = Arc::new(Mutex::new(vec![]));
        let set_earning_wallet_address_params_arc = Arc::new(Mutex::new(vec![]));
        let persistent_config = PersistentConfigurationMock::new()
            .set_mnemonic_seed_params(&set_mnemonic_seed_params_arc)
            .set_mnemonic_seed_result(Ok(()))
            .set_consuming_wallet_derivation_path_params(
                &set_consuming_wallet_derivation_path_params_arc,
            )
            .set_earning_wallet_address_params(&set_earning_wallet_address_params_arc);

        create_wallet(&config, &persistent_config);

        let set_mnemonic_seed_params = set_mnemonic_seed_params_arc.lock().unwrap();
        assert_eq!(
            *set_mnemonic_seed_params,
            vec![(seed.as_ref().to_vec(), "db password".to_string())]
        );
        let set_consuming_wallet_derivation_path_params =
            set_consuming_wallet_derivation_path_params_arc
                .lock()
                .unwrap();
        assert_eq!(
            *set_consuming_wallet_derivation_path_params,
            vec![("m/44'/60'/1'/2/3".to_string(), "db password".to_string())]
        );
        let set_earning_wallet_address_params =
            set_earning_wallet_address_params_arc.lock().unwrap();
        assert_eq!(*set_earning_wallet_address_params, vec![earning_address]);
    }

    #[test]
    fn create_wallet_configures_database_with_earning_address() {
        let config = WalletCreationConfig {
            earning_wallet_address_opt: Some(
                "0x9707f21F95B9839A54605100Ca69dCc2e7eaA26q".to_string(),
            ),
            derivation_path_info_opt: Some(DerivationPathWalletInfo {
                mnemonic_seed: PlainData::new(&[1, 2, 3, 4]),
                db_password: "db password".to_string(),
                consuming_derivation_path_opt: Some("m/44'/60'/1'/2/3".to_string()),
            }),
            real_user: RealUser::null(),
        };
        let set_mnemonic_seed_params_arc = Arc::new(Mutex::new(vec![]));
        let set_consuming_wallet_derivation_path_params_arc = Arc::new(Mutex::new(vec![]));
        let set_earning_wallet_address_params_arc = Arc::new(Mutex::new(vec![]));
        let persistent_config = PersistentConfigurationMock::new()
            .set_mnemonic_seed_params(&set_mnemonic_seed_params_arc)
            .set_mnemonic_seed_result(Ok(()))
            .set_consuming_wallet_derivation_path_params(
                &set_consuming_wallet_derivation_path_params_arc,
            )
            .set_earning_wallet_address_params(&set_earning_wallet_address_params_arc);

        create_wallet(&config, &persistent_config);

        let set_mnemonic_seed_params = set_mnemonic_seed_params_arc.lock().unwrap();
        assert_eq!(
            *set_mnemonic_seed_params,
            vec![(vec![1u8, 2u8, 3u8, 4u8], "db password".to_string())]
        );
        let set_consuming_wallet_derivation_path_params =
            set_consuming_wallet_derivation_path_params_arc
                .lock()
                .unwrap();
        assert_eq!(
            *set_consuming_wallet_derivation_path_params,
            vec![("m/44'/60'/1'/2/3".to_string(), "db password".to_string())]
        );
        let set_earning_wallet_address_params =
            set_earning_wallet_address_params_arc.lock().unwrap();
        assert_eq!(
            *set_earning_wallet_address_params,
            vec!["0x9707f21F95B9839A54605100Ca69dCc2e7eaA26q".to_string()]
        );
    }

    #[test]
    pub fn update_db_password_does_nothing_if_no_derivation_path_info_is_supplied() {
        let wallet_config = WalletCreationConfig {
            earning_wallet_address_opt: None,
            derivation_path_info_opt: None,
            real_user: RealUser::default(),
        };
        let set_password_params_arc = Arc::new(Mutex::new(vec![]));
        let persistent_config =
            PersistentConfigurationMock::new().set_password_params(&set_password_params_arc);

        update_db_password(&wallet_config, &persistent_config);

        let set_password_params = set_password_params_arc.lock().unwrap();
        assert!(set_password_params.is_empty());
    }

    #[test]
    pub fn update_db_password_sets_password_if_derivation_path_info_is_supplied() {
        let wallet_config = WalletCreationConfig {
            earning_wallet_address_opt: None,
            derivation_path_info_opt: Some(DerivationPathWalletInfo {
                mnemonic_seed: PlainData::new(&[]),
                db_password: "booga".to_string(),
                consuming_derivation_path_opt: None,
            }),
            real_user: RealUser::default(),
        };
        let set_password_params_arc = Arc::new(Mutex::new(vec![]));
        let persistent_config =
            PersistentConfigurationMock::new().set_password_params(&set_password_params_arc);

        update_db_password(&wallet_config, &persistent_config);

        let set_password_params = set_password_params_arc.lock().unwrap();
        assert_eq!(*set_password_params, vec!["booga".to_string()]);
    }

    #[test]
    pub fn port_is_busy_detects_free_port() {
        let port = find_free_port();

        let result = port_is_busy(port);

        assert_eq!(result, false);
    }

    #[test]
    pub fn port_is_busy_detects_busy_port() {
        let port = find_free_port();
        let _listener = TcpListener::bind(SocketAddr::new(localhost(), port)).unwrap();

        let result = port_is_busy(port);

        assert_eq!(result, true);
    }
}
