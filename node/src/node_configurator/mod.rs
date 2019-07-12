// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

pub mod node_configurator_generate_wallet;
pub mod node_configurator_recover_wallet;
pub mod node_configurator_standard;

#[cfg(test)]
mod test_utils;

use crate::blockchain::bip39::{Bip39, Bip39Error};
use crate::database::db_initializer::{DbInitializer, DbInitializerReal, DATABASE_FILE};
use crate::multi_config::{
    merge, CommandLineVCL, ConfigFileVCL, EnvironmentVCL, MultiConfig, VclArg,
};
use crate::persistent_configuration::{PersistentConfiguration, PersistentConfigurationReal};
use crate::sub_lib::cryptde::PlainData;
use crate::sub_lib::main_tools::StdStreams;
use crate::sub_lib::wallet::{DEFAULT_CONSUMING_DERIVATION_PATH, DEFAULT_EARNING_DERIVATION_PATH};
use bip39::Language;
use clap::{value_t, App, Arg};
use dirs::data_local_dir;
use lazy_static::lazy_static;
use rpassword;
use rpassword::read_password_with_reader;
use rustc_hex::FromHex;
use std::fmt::Debug;
use std::io;
use std::io::Read;
use std::path::PathBuf;
use std::str::FromStr;
use tiny_hderive::bip44::DerivationPath;

pub trait NodeConfigurator<T> {
    fn configure(&self, args: &Vec<String>, streams: &mut StdStreams<'_>) -> T;
}

lazy_static! {
    static ref DEFAULT_DATA_DIR_VALUE: String = data_directory_default(&RealDirsWrapper {});
}

pub const CONSUMING_PRIVATE_KEY_HELP: &str = "Must be 64 hexadecimal digits (case-insensitive)";
pub const CONSUMING_WALLET_HELP: &str = "The BIP32 derivation path for the wallet from which SubstratumNode should pay others. Defaults to m/44'/60'/0'/0/0";
pub const EARNING_WALLET_HELP: &str =
    "Denotes the wallet into which other SubstratumNodes will pay. May either be a BIP32 derivation path (defaults to m/44'/60'/0'/0/1) or an Ethereum wallet address. \
     Addresses must begin with 0x followed by 40 hexadecimal digits (case-insensitive)";
pub const LANGUAGE_HELP: &str = "The language of the mnemonic phrase.";
pub const MNEMONIC_PASSPHRASE_HELP: &str =
    "A passphrase for the mnemonic phrase. Cannot be changed later and still produce \
     the same addresses. Not valid as a configuration file item nor an environment variable.";
pub const WALLET_PASSWORD_HELP: &str =
    "A password or phrase to encrypt your consuming wallet in the SubstratumNode database or decrypt a keystore file. Can be changed \
     later and still produce the same addresses.";

// These Args are needed in more than one clap schema. To avoid code duplication, they're defined here and referred
// to from multiple places.
pub fn config_file_arg<'a>() -> Arg<'a, 'a> {
    Arg::with_name("config-file")
        .long("config-file")
        .aliases(&["config-file", "config_file"])
        .value_name("FILE-PATH")
        .default_value("config.toml")
        .takes_value(true)
        .required(false)
}

pub fn consuming_wallet_arg<'a>() -> Arg<'a, 'a> {
    Arg::with_name("consuming-wallet")
        .long("consuming-wallet")
        .aliases(&["consuming-wallet", "consuming_wallet"])
        .value_name("CONSUMING-WALLET")
        .empty_values(false)
        .validator(common_validators::validate_derivation_path)
        .help(&CONSUMING_WALLET_HELP)
}

pub fn data_directory_arg<'a>() -> Arg<'a, 'a> {
    Arg::with_name("data-directory")
        .long("data-directory")
        .aliases(&["data-directory", "data_directory"])
        .value_name("DATA-DIRECTORY")
        .required(false)
        .takes_value(true)
        .empty_values(false)
        .default_value(&DEFAULT_DATA_DIR_VALUE)
}

pub fn earning_wallet_arg<F>(help: &str, validator: F) -> Arg
where
    F: 'static,
    F: Fn(String) -> Result<(), String>,
{
    Arg::with_name("earning-wallet")
        .long("earning-wallet")
        .aliases(&[
            "earning-wallet",
            "earning_wallet",
            "wallet-address",
            "wallet_address",
        ])
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
        .aliases(&["mnemonic-passphrase", "mnemonic_passphrase"])
        .value_name("MNEMONIC-PASSPHRASE")
        .required(false)
        .takes_value(true)
        .min_values(0)
        .max_values(1)
        .help(MNEMONIC_PASSPHRASE_HELP)
}

pub fn wallet_password_arg(help: &str) -> Arg {
    Arg::with_name("wallet-password")
        .long("wallet-password")
        .aliases(&["wallet-password", "wallet_password"])
        .value_name("WALLET-PASSWORD")
        .required(false)
        .takes_value(true)
        .min_values(0)
        .max_values(1)
        .help(help)
}

pub fn make_multi_config<'a>(app: &'a App, args: &Vec<String>) -> MultiConfig<'a> {
    let (config_file_path, user_specified) = determine_config_file_path(app, args);
    MultiConfig::new(
        &app,
        vec![
            Box::new(CommandLineVCL::new(args.clone())),
            Box::new(EnvironmentVCL::new(&app)),
            Box::new(ConfigFileVCL::new(&config_file_path, user_specified)),
        ],
    )
}

pub fn determine_config_file_path(app: &App, args: &Vec<String>) -> (PathBuf, bool) {
    let orientation_schema = App::new("Preliminary")
        .arg(data_directory_arg())
        .arg(config_file_arg());
    let orientation_args: Vec<Box<VclArg>> = merge(
        Box::new(EnvironmentVCL::new(app)),
        Box::new(CommandLineVCL::new(args.clone())),
    )
    .vcl_args()
    .into_iter()
    .filter(|vcl_arg| (vcl_arg.name() == "--data-directory") || (vcl_arg.name() == "--config-file"))
    .map(|vcl_arg| vcl_arg.dup())
    .collect();
    let orientation_vcl = CommandLineVCL::from(orientation_args);

    let multi_config = MultiConfig::new(&orientation_schema, vec![Box::new(orientation_vcl)]);
    let config_file_path =
        value_m!(multi_config, "config-file", PathBuf).expect("config-file should be defaulted");
    let user_specified = multi_config.arg_matches().occurrences_of("config-file") > 0;
    let data_directory: PathBuf = value_m!(multi_config, "data-directory", PathBuf)
        .expect("data-directory should be defaulted");
    (data_directory.join(config_file_path), user_specified)
}

pub fn create_wallet(config: &WalletCreationConfig, persistent_config: &PersistentConfiguration) {
    if config.earning_wallet_address_opt.as_ref().is_some()
        && config.derivation_path_info_opt.is_some()
        && config
            .derivation_path_info_opt
            .as_ref()
            .expect("Disappeared!")
            .earning_derivation_path_opt
            .is_some()
    {
        panic!("Internal error: somehow the earning address and the earning derivation path are both set");
    }
    if let Some(address) = &config.earning_wallet_address_opt {
        persistent_config.set_earning_wallet_address(address)
    }
    if let Some(derivation_path_info) = &config.derivation_path_info_opt {
        persistent_config.set_mnemonic_seed(
            &derivation_path_info.mnemonic_seed,
            &derivation_path_info.wallet_password,
        );
        if let Some(consuming_derivation_path) = &derivation_path_info.consuming_derivation_path_opt
        {
            persistent_config.set_consuming_wallet_derivation_path(consuming_derivation_path)
        }
        if let Some(earning_derivation_path) = &derivation_path_info.earning_derivation_path_opt {
            persistent_config.set_earning_wallet_derivation_path(earning_derivation_path)
        }
    }
}

pub fn initialize_database(multi_config: &MultiConfig) -> Box<PersistentConfiguration> {
    let data_directory: PathBuf =
        value_m!(multi_config, "data-directory", PathBuf).expect("data-directory is not defaulted");
    let conn = DbInitializerReal::new()
        .initialize(&data_directory)
        .unwrap_or_else(|_| {
            panic!(
                "Can't initialize database at {:?}",
                data_directory.join(DATABASE_FILE)
            )
        });
    Box::new(PersistentConfigurationReal::from(conn))
}

pub fn request_wallet_encryption_password(
    streams: &mut StdStreams,
    possible_preamble: Option<&str>,
    prompt: &str,
    confirmation_prompt: &str,
) -> Option<String> {
    if let Some(preamble) = possible_preamble {
        flushed_write(streams.stdout, &format!("{}\n", preamble));
    }
    match request_password_with_retry(prompt, streams, |streams| {
        request_new_password(
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

pub fn request_wallet_decryption_password(
    streams: &mut StdStreams,
    possible_preamble: Option<&str>,
    prompt: &str,
    encrypted_mnemonic_seed: &str,
) -> Option<String> {
    if let Some(preamble) = possible_preamble {
        flushed_write(streams.stdout, preamble)
    };
    let verifier = move |password: &str| {
        if password.is_empty() {
            return Err("Password must not be blank.".to_string());
        }
        match Bip39::decrypt_bytes(encrypted_mnemonic_seed, &password) {
            Ok(_) => Ok(()),
            Err(Bip39Error::DecryptionFailure(_)) => Err("Incorrect password.".to_string()),
            Err(e) => panic!("Could not verify password: {:?}", e),
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
pub fn request_new_password<F>(
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

pub fn data_directory_default(dirs_wrapper: &DirsWrapper) -> String {
    dirs_wrapper
        .data_dir()
        .unwrap_or_else(|| PathBuf::from(""))
        .to_str()
        .expect("Internal Error")
        .to_string()
}

pub fn flushed_write(target: &mut io::Write, string: &str) {
    write!(target, "{}", string).expect("Failed console write.");
    target.flush().expect("Failed flush.");
}

pub mod common_validators {
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
}

pub trait DirsWrapper {
    fn data_dir(&self) -> Option<PathBuf>;
}

struct RealDirsWrapper {}

impl DirsWrapper for RealDirsWrapper {
    fn data_dir(&self) -> Option<PathBuf> {
        data_local_dir()
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
    pub wallet_password: String,
    pub consuming_derivation_path_opt: Option<String>,
    pub earning_derivation_path_opt: Option<String>,
}

#[derive(PartialEq, Debug)]
pub struct WalletCreationConfig {
    pub earning_wallet_address_opt: Option<String>,
    pub derivation_path_info_opt: Option<DerivationPathWalletInfo>,
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
        let wallet_password = match value_m!(multi_config, "wallet-password", String) {
            Some(wp) => wp,
            None => self.make_wallet_password(streams),
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
                    Err(_) => panic!("--earning-wallet not properly validated by clap"),
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
        WalletCreationConfig {
            earning_wallet_address_opt: match &earning_wallet_info {
                Either::Left(address) => Some(address.to_string()),
                Either::Right(_) => None,
            },
            derivation_path_info_opt: Some(DerivationPathWalletInfo {
                mnemonic_seed,
                wallet_password,
                consuming_derivation_path_opt: Some(consuming_derivation_path),
                earning_derivation_path_opt: match earning_wallet_info {
                    Either::Left(_) => None,
                    Either::Right(path) => Some(path),
                },
            }),
        }
    }

    fn make_wallet_password(&self, streams: &mut StdStreams) -> String {
        match request_wallet_encryption_password(
            streams,
            Some("\n\nPlease provide a password to encrypt your wallet (This password can be changed later)..."),
            "  Enter password: ",
            "  Confirm password: "
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
    use crate::node_configurator::test_utils::{BadMockDirsWrapper, MockDirsWrapper};
    use crate::sub_lib::wallet::DEFAULT_EARNING_DERIVATION_PATH;
    use crate::test_utils::environment_guard::EnvironmentGuard;
    use crate::test_utils::persistent_configuration_mock::PersistentConfigurationMock;
    use crate::test_utils::ByteArrayWriter;
    use bip39::{Mnemonic, MnemonicType, Seed};
    use std::io::Cursor;
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
                DEFAULT_CONSUMING_DERIVATION_PATH.to_string()
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
                "m/44'/60'/0/0/0".to_string()
            )
        );
    }

    #[test]
    fn validate_derivation_path_is_sufficiently_hardened_very_sad() {
        assert_eq!(
            Err("m/44/60/0/0/0 may be too weak".to_string()),
            common_validators::validate_derivation_path_is_sufficiently_hardened(
                "m/44/60/0/0/0".parse::<DerivationPath>().unwrap(),
                "m/44/60/0/0/0".to_string()
            )
        );
    }

    #[test]
    fn data_directory_default_given_no_default() {
        assert_eq!(
            String::from(""),
            data_directory_default(&BadMockDirsWrapper {})
        );
    }

    #[test]
    fn data_directory_default_works() {
        let mock_dirs_wrapper = MockDirsWrapper {};

        let result = data_directory_default(&mock_dirs_wrapper);

        assert_eq!(String::from("mocked/path"), result);
    }

    fn determine_config_file_path_app() -> App<'static, 'static> {
        App::new("test")
            .arg(data_directory_arg())
            .arg(config_file_arg())
    }

    #[test]
    fn determine_config_file_path_finds_path_in_args() {
        let _guard = EnvironmentGuard::new();
        let args: Vec<String> = vec![
            "SubstratumNode",
            "--clandestine_port",
            "2345",
            "--data-directory",
            "data-dir",
            "--config-file",
            "booga.toml",
            "--dns-servers",
            "1.2.3.4",
        ]
        .into_iter()
        .map(String::from)
        .collect();

        let (config_file_path, user_specified) =
            determine_config_file_path(&determine_config_file_path_app(), &args);

        assert_eq!(
            "data-dir",
            &format!("{}", config_file_path.parent().unwrap().display())
        );
        assert_eq!("booga.toml", config_file_path.file_name().unwrap());
        assert_eq!(true, user_specified);
    }

    #[test]
    fn determine_config_file_path_finds_path_in_environment() {
        let _guard = EnvironmentGuard::new();
        let args: Vec<String> = vec!["SubstratumNode", "--dns-servers", "1.2.3.4"]
            .into_iter()
            .map(String::from)
            .collect();
        std::env::set_var("SUB_DATA_DIRECTORY", "data_dir");
        std::env::set_var("SUB_CONFIG_FILE", "booga.toml");

        let (config_file_path, user_specified) =
            determine_config_file_path(&determine_config_file_path_app(), &args);

        assert_eq!(
            "data_dir",
            &format!("{}", config_file_path.parent().unwrap().display())
        );
        assert_eq!("booga.toml", config_file_path.file_name().unwrap());
        assert_eq!(true, user_specified);
    }

    #[cfg(not(windows))]
    #[test]
    fn determine_config_file_path_ignores_data_dir_if_config_file_has_root() {
        let _guard = EnvironmentGuard::new();
        let args: Vec<String> = vec![
            "SubstratumNode",
            "--data-directory",
            "data-dir",
            "--config-file",
            "/tmp/booga.toml",
            "--dns-servers",
            "1.2.3.4",
        ]
        .into_iter()
        .map(String::from)
        .collect();

        let (config_file_path, user_specified) =
            determine_config_file_path(&determine_config_file_path_app(), &args);

        assert_eq!(
            "/tmp/booga.toml",
            &format!("{}", config_file_path.display())
        );
        assert_eq!(true, user_specified);
    }

    #[cfg(windows)]
    #[test]
    fn determine_config_file_path_ignores_data_dir_if_config_file_has_separator_root() {
        let _guard = EnvironmentGuard::new();
        let args: Vec<String> = vec![
            "SubstratumNode",
            "--data-directory",
            "data-dir",
            "--config-file",
            r"\tmp\booga.toml",
            "--dns-servers",
            "1.2.3.4",
        ]
        .into_iter()
        .map(String::from)
        .collect();

        let (config_file_path, user_specified) =
            determine_config_file_path(&determine_config_file_path_app(), &args);

        assert_eq!(
            r"\tmp\booga.toml",
            &format!("{}", config_file_path.display())
        );
        assert_eq!(true, user_specified);
    }

    #[cfg(windows)]
    #[test]
    fn determine_config_file_path_ignores_data_dir_if_config_file_has_drive_root() {
        let _guard = EnvironmentGuard::new();
        let args: Vec<String> = vec![
            "SubstratumNode",
            "--data-directory",
            "data-dir",
            "--config-file",
            r"c:\tmp\booga.toml",
            "--dns-servers",
            "1.2.3.4",
        ]
        .into_iter()
        .map(String::from)
        .collect();

        let (config_file_path, user_specified) =
            determine_config_file_path(&determine_config_file_path_app(), &args);

        assert_eq!(
            r"c:\tmp\booga.toml",
            &format!("{}", config_file_path.display())
        );
        assert_eq!(true, user_specified);
    }

    #[cfg(windows)]
    #[test]
    fn determine_config_file_path_ignores_data_dir_if_config_file_has_network_root() {
        let _guard = EnvironmentGuard::new();
        let args: Vec<String> = vec![
            "SubstratumNode",
            "--data-directory",
            "data-dir",
            "--config-file",
            r"\\TMP\booga.toml",
            "--dns-servers",
            "1.2.3.4",
        ]
        .into_iter()
        .map(String::from)
        .collect();

        let (config_file_path, user_specified) =
            determine_config_file_path(&determine_config_file_path_app(), &args);

        assert_eq!(
            r"\\TMP\booga.toml",
            &format!("{}", config_file_path.display())
        );
        assert_eq!(true, user_specified);
    }

    #[cfg(windows)]
    #[test]
    fn determine_config_file_path_ignores_data_dir_if_config_file_has_drive_letter_but_no_separator(
    ) {
        let _guard = EnvironmentGuard::new();
        let args: Vec<String> = vec![
            "SubstratumNode",
            "--data-directory",
            "data-dir",
            "--config-file",
            r"c:tmp\booga.toml",
            "--dns-servers",
            "1.2.3.4",
        ]
        .into_iter()
        .map(String::from)
        .collect();

        let (config_file_path, user_specified) =
            determine_config_file_path(&determine_config_file_path_app(), &args);

        assert_eq!(
            r"c:tmp\booga.toml",
            &format!("{}", config_file_path.display())
        );
        assert_eq!(true, user_specified);
    }

    #[test]
    fn request_wallet_decryption_password_happy_path() {
        let stdout_writer = &mut ByteArrayWriter::new();
        let streams = &mut StdStreams {
            stdin: &mut Cursor::new(&b"Too Many S3cr3ts!\n"[..]),
            stdout: stdout_writer,
            stderr: &mut ByteArrayWriter::new(),
        };
        let mnemonic_seed = Seed::new(
            &Mnemonic::new(MnemonicType::Words12, Language::English),
            "phrase",
        );
        let encrypted_mnemonic_seed =
            Bip39::encrypt_bytes(&mnemonic_seed, "Too Many S3cr3ts!").unwrap();

        let actual = request_wallet_decryption_password(
            streams,
            Some("Decrypt wallet"),
            "Enter password: ",
            &encrypted_mnemonic_seed,
        );

        assert_eq!(actual, Some("Too Many S3cr3ts!".to_string()));
        assert_eq!(
            stdout_writer.get_string(),
            "Decrypt wallet\
             Enter password: "
                .to_string()
        );
    }

    #[test]
    fn request_wallet_decryption_password_rejects_blank_password() {
        let stdout_writer = &mut ByteArrayWriter::new();
        let streams = &mut StdStreams {
            stdin: &mut Cursor::new(&b"\nbooga\n"[..]),
            stdout: stdout_writer,
            stderr: &mut ByteArrayWriter::new(),
        };
        let mnemonic_seed = Seed::new(
            &Mnemonic::new(MnemonicType::Words12, Language::English),
            "phrase",
        );
        let encrypted_mnemonic_seed = Bip39::encrypt_bytes(&mnemonic_seed, "booga").unwrap();

        let actual = request_wallet_decryption_password(
            streams,
            Some("Decrypt wallet"),
            "Enter password: ",
            &encrypted_mnemonic_seed,
        );

        assert_eq!(actual, Some("booga".to_string()));
        assert_eq!(
            stdout_writer.get_string(),
            "Decrypt wallet\
             Enter password: \
             Password must not be blank. Try again.\n\
             Enter password: "
                .to_string()
        );
    }

    #[test]
    fn request_wallet_decryption_password_detects_bad_passwords() {
        let stdout_writer = &mut ByteArrayWriter::new();
        let streams = &mut StdStreams {
            stdin: &mut Cursor::new(
                &b"bad password\nanother bad password\nfinal bad password\n"[..],
            ),
            stdout: stdout_writer,
            stderr: &mut ByteArrayWriter::new(),
        };
        let mnemonic_seed = Seed::new(
            &Mnemonic::new(MnemonicType::Words12, Language::English),
            "phrase",
        );
        let encrypted_mnemonic_seed =
            Bip39::encrypt_bytes(&mnemonic_seed, "Too Many S3cr3ts!").unwrap();

        let actual = request_wallet_decryption_password(
            streams,
            Some("Decrypt wallet"),
            "Enter password: ",
            &encrypted_mnemonic_seed,
        );

        assert_eq!(actual, None);
        assert_eq!(
            stdout_writer.get_string(),
            "Decrypt wallet\
             Enter password: \
             Incorrect password. Try again.\n\
             Enter password: \
             Incorrect password. Try again.\n\
             Enter password: \
             Incorrect password. Giving up.\n"
                .to_string()
        );
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

        let actual = request_wallet_encryption_password(
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

        let actual = request_wallet_encryption_password(
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

        let actual = request_wallet_encryption_password(
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
            PlainData::new(b"mnemonic seed")
        }
    }

    impl TameWalletCreationConfigMaker {
        pub fn new() -> TameWalletCreationConfigMaker {
            TameWalletCreationConfigMaker {
                app: App::new("TameWalletCreationConfigMaker")
                    .arg(consuming_wallet_arg())
                    .arg(earning_wallet_arg("", |_| Ok(())))
                    .arg(mnemonic_passphrase_arg())
                    .arg(wallet_password_arg(WALLET_PASSWORD_HELP)),
            }
        }
    }

    #[test]
    fn make_wallet_creation_config_defaults() {
        let subject = TameWalletCreationConfigMaker::new();
        let vcl = Box::new(CommandLineVCL::new(vec!["test".to_string()]));
        let multi_config = MultiConfig::new(&subject.app, vec![vcl]);
        let stdout_writer = &mut ByteArrayWriter::new();
        let mut streams = &mut StdStreams {
            stdin: &mut Cursor::new(
                &b"a terrible wallet password\na terrible wallet password\n"[..],
            ),
            stdout: stdout_writer,
            stderr: &mut ByteArrayWriter::new(),
        };

        let config = subject.make_wallet_creation_config(&multi_config, &mut streams);

        let captured_output = stdout_writer.get_string();
        let expected_output = "Enter mnemonic passphrase: \
        \n\nPlease provide a password to encrypt your wallet (This password can be changed later)...\
        \n  Enter password:   Confirm password: ";
        assert_eq!(&captured_output, expected_output);
        assert_eq!(
            config,
            WalletCreationConfig {
                earning_wallet_address_opt: None,
                derivation_path_info_opt: Some(DerivationPathWalletInfo {
                    mnemonic_seed: PlainData::new(b"mnemonic seed"),
                    wallet_password: "a terrible wallet password".to_string(),
                    consuming_derivation_path_opt: Some(
                        DEFAULT_CONSUMING_DERIVATION_PATH.to_string()
                    ),
                    earning_derivation_path_opt: Some(DEFAULT_EARNING_DERIVATION_PATH.to_string())
                })
            },
        );
    }

    #[test]
    fn make_wallet_creation_config_non_defaults_with_earning_derivation_path() {
        let subject = TameWalletCreationConfigMaker::new();
        let args: Vec<String> = vec![
            "test",
            "--consuming-wallet",
            "m/44'/60'/1'/2/3",
            "--earning-wallet",
            "m/44'/60'/3'/2/1",
            "--mnemonic-passphrase",
            "mnemonic passphrase",
            "--wallet-password",
            "wallet password",
        ]
        .into_iter()
        .map(String::from)
        .collect();
        let vcl = Box::new(CommandLineVCL::new(args));
        let multi_config = MultiConfig::new(&subject.app, vec![vcl]);
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
                earning_wallet_address_opt: None,
                derivation_path_info_opt: Some(DerivationPathWalletInfo {
                    mnemonic_seed: PlainData::new(b"mnemonic seed"),
                    wallet_password: "wallet password".to_string(),
                    consuming_derivation_path_opt: Some("m/44'/60'/1'/2/3".to_string()),
                    earning_derivation_path_opt: Some("m/44'/60'/3'/2/1".to_string())
                })
            },
        );
    }

    #[test]
    fn make_wallet_creation_config_non_defaults_with_earning_address() {
        let subject = TameWalletCreationConfigMaker::new();
        let args: Vec<String> = vec![
            "test",
            "--consuming-wallet",
            "m/44'/60'/1'/2/3",
            "--earning-wallet",
            "0x0123456789ABCDEF0123456789ABCDEF01234567",
            "--mnemonic-passphrase",
            "mnemonic passphrase",
            "--wallet-password",
            "wallet password",
        ]
        .into_iter()
        .map(String::from)
        .collect();
        let vcl = Box::new(CommandLineVCL::new(args));
        let multi_config = MultiConfig::new(&subject.app, vec![vcl]);
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
                    mnemonic_seed: PlainData::new(b"mnemonic seed"),
                    wallet_password: "wallet password".to_string(),
                    consuming_derivation_path_opt: Some("m/44'/60'/1'/2/3".to_string()),
                    earning_derivation_path_opt: None
                })
            },
        );
    }

    #[test]
    #[should_panic(expected = "Wallet encryption password is required!")]
    fn make_wallet_creation_config_panics_after_three_password_mismatches() {
        let subject = TameWalletCreationConfigMaker::new();
        let streams = &mut StdStreams {
            stdin: &mut Cursor::new(&b"one\n\ntwo\n\nthree\n\n"[..]),
            stdout: &mut ByteArrayWriter::new(),
            stderr: &mut ByteArrayWriter::new(),
        };
        let vcl = Box::new(CommandLineVCL::new(vec!["test".to_string()]));
        let multi_config = MultiConfig::new(&subject.app, vec![vcl]);

        subject.make_wallet_creation_config(&multi_config, streams);
    }

    #[test]
    fn create_wallet_configures_database_with_earning_path() {
        let config = WalletCreationConfig {
            earning_wallet_address_opt: None,
            derivation_path_info_opt: Some(DerivationPathWalletInfo {
                mnemonic_seed: PlainData::new(&[1, 2, 3, 4]),
                wallet_password: "wallet password".to_string(),
                consuming_derivation_path_opt: Some("m/44'/60'/1'/2/3".to_string()),
                earning_derivation_path_opt: Some("m/44'/60'/3'/2/1".to_string()),
            }),
        };
        let set_mnemonic_seed_params_arc = Arc::new(Mutex::new(vec![]));
        let set_consuming_wallet_derivation_path_params_arc = Arc::new(Mutex::new(vec![]));
        let set_earning_wallet_derivation_path_params_arc = Arc::new(Mutex::new(vec![]));
        let persistent_config = PersistentConfigurationMock::new()
            .set_mnemonic_seed_params(&set_mnemonic_seed_params_arc)
            .set_consuming_wallet_derivation_path_params(
                &set_consuming_wallet_derivation_path_params_arc,
            )
            .set_earning_wallet_derivation_path_params(
                &set_earning_wallet_derivation_path_params_arc,
            );

        create_wallet(&config, &persistent_config);

        let set_mnemonic_seed_params = set_mnemonic_seed_params_arc.lock().unwrap();
        assert_eq!(
            *set_mnemonic_seed_params,
            vec![(vec![1u8, 2u8, 3u8, 4u8], "wallet password".to_string())]
        );
        let set_consuming_wallet_derivation_path_params =
            set_consuming_wallet_derivation_path_params_arc
                .lock()
                .unwrap();
        assert_eq!(
            *set_consuming_wallet_derivation_path_params,
            vec!["m/44'/60'/1'/2/3".to_string()]
        );
        let set_earning_wallet_derivation_path_params =
            set_earning_wallet_derivation_path_params_arc
                .lock()
                .unwrap();
        assert_eq!(
            *set_earning_wallet_derivation_path_params,
            vec!["m/44'/60'/3'/2/1".to_string()]
        );
    }

    #[test]
    fn create_wallet_configures_database_with_earning_address() {
        let config = WalletCreationConfig {
            earning_wallet_address_opt: Some(
                "0x9707f21F95B9839A54605100Ca69dCc2e7eaA26q".to_string(),
            ),
            derivation_path_info_opt: Some(DerivationPathWalletInfo {
                mnemonic_seed: PlainData::new(&[1, 2, 3, 4]),
                wallet_password: "wallet password".to_string(),
                consuming_derivation_path_opt: Some("m/44'/60'/1'/2/3".to_string()),
                earning_derivation_path_opt: None,
            }),
        };
        let set_mnemonic_seed_params_arc = Arc::new(Mutex::new(vec![]));
        let set_consuming_wallet_derivation_path_params_arc = Arc::new(Mutex::new(vec![]));
        let set_earning_wallet_address_params_arc = Arc::new(Mutex::new(vec![]));
        let persistent_config = PersistentConfigurationMock::new()
            .set_mnemonic_seed_params(&set_mnemonic_seed_params_arc)
            .set_consuming_wallet_derivation_path_params(
                &set_consuming_wallet_derivation_path_params_arc,
            )
            .set_earning_wallet_address_params(&set_earning_wallet_address_params_arc);

        create_wallet(&config, &persistent_config);

        let set_mnemonic_seed_params = set_mnemonic_seed_params_arc.lock().unwrap();
        assert_eq!(
            *set_mnemonic_seed_params,
            vec![(vec![1u8, 2u8, 3u8, 4u8], "wallet password".to_string())]
        );
        let set_consuming_wallet_derivation_path_params =
            set_consuming_wallet_derivation_path_params_arc
                .lock()
                .unwrap();
        assert_eq!(
            *set_consuming_wallet_derivation_path_params,
            vec!["m/44'/60'/1'/2/3".to_string()]
        );
        let set_earning_wallet_address_params =
            set_earning_wallet_address_params_arc.lock().unwrap();
        assert_eq!(
            *set_earning_wallet_address_params,
            vec!["0x9707f21F95B9839A54605100Ca69dCc2e7eaA26q".to_string()]
        );
    }

    #[test]
    #[should_panic(
        expected = "Internal error: somehow the earning address and the earning derivation path are both set"
    )]
    fn create_wallet_fails_with_earning_address_plus_earning_derivation_path() {
        let config = WalletCreationConfig {
            earning_wallet_address_opt: Some(
                "0x9707f21F95B9839A54605100Ca69dCc2e7eaA26q".to_string(),
            ),
            derivation_path_info_opt: Some(DerivationPathWalletInfo {
                mnemonic_seed: PlainData::new(&[1, 2, 3, 4]),
                wallet_password: "wallet password".to_string(),
                consuming_derivation_path_opt: None,
                earning_derivation_path_opt: Some("m/44'/60'/3'/2/1".to_string()),
            }),
        };
        let persistent_config = PersistentConfigurationMock::new();;

        create_wallet(&config, &persistent_config);
    }
}
