// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

pub mod utils;

use bip39::{Language, Mnemonic, Seed};
use node_lib::blockchain::bip32::Bip32ECKeyPair;
use node_lib::database::db_initializer::{
    DbInitializer, DbInitializerReal, CURRENT_SCHEMA_VERSION,
};
use node_lib::persistent_configuration::{PersistentConfiguration, PersistentConfigurationReal};
use node_lib::sub_lib::wallet::{
    Wallet, DEFAULT_CONSUMING_DERIVATION_PATH, DEFAULT_EARNING_DERIVATION_PATH,
};
use node_lib::test_utils::environment_guard::EnvironmentGuard;
use node_lib::test_utils::{assert_string_contains, DEFAULT_CHAIN_ID};
use regex::Regex;
use std::str::FromStr;
use utils::CommandConfig;
use utils::MASQNode;

const PHRASE: &str =
    "snake gorilla marine couch wheel decline stamp glass aunt antenna transfer exit";
const PASSPHRASE: &str = "passphrase";
const PASSWORD: &str = "password";
const EARNING_PATH: &str = "m/44'/60'/3'/2/1";
const EARNING_ADDRESS: &str = "0x0123456789ABCDEF0123456789ABCDEF01234567";
const CONSUMING_PATH: &str = "m/44'/60'/1'/2/3";

fn persistent_config(chain_id: u8) -> PersistentConfigurationReal {
    PersistentConfigurationReal::from(
        DbInitializerReal::new()
            .initialize(&MASQNode::data_dir().to_path_buf(), chain_id)
            .unwrap(),
    )
}

fn earning_path_wallet() -> Wallet {
    wallet_from_phrase_and_path(PHRASE, EARNING_PATH)
}

fn default_earning_path_wallet() -> Wallet {
    wallet_from_phrase_and_path(PHRASE, DEFAULT_EARNING_DERIVATION_PATH)
}

fn wallet_from_phrase_and_path(phrase: &str, path: &str) -> Wallet {
    let mnemonic = Mnemonic::from_phrase(phrase, Language::English).unwrap();
    let seed = Seed::new(&mnemonic, PASSPHRASE);
    let keypair = Bip32ECKeyPair::from_raw(seed.as_ref(), path).unwrap();
    Wallet::from(keypair).as_address_wallet()
}

fn phrase_from_console_log(console_log: &str) -> String {
    let regex = Regex::new("if you provided one\\.\\s+(.+)[\r\n]").unwrap();
    match regex.captures(console_log) {
        None => panic!(
            "Couldn't parse phrase out of console output:\n{}",
            console_log
        ),
        Some(captures) => captures.get(1).unwrap().as_str().to_string(),
    }
}

// TODO These tests could all run concurrently if each was given a different data directory.
// That would mean test infrastructure changes, but it's possible.
#[test]
fn dump_configuration_integration() {
    let _eg = EnvironmentGuard::new();
    let console_log = MASQNode::run_dump_config();

    assert_string_contains(
        &console_log,
        &format!("\"schemaVersion\": \"{}\"", CURRENT_SCHEMA_VERSION),
    );
}

#[test]
fn create_database_recovering_both_derivation_paths_integration() {
    let _eg = EnvironmentGuard::new();
    let _console_log = MASQNode::run_recover(
        CommandConfig::new()
            .pair("--mnemonic", PHRASE)
            .pair("--mnemonic-passphrase", PASSPHRASE)
            .pair("--wallet-password", PASSWORD)
            .pair("--earning-wallet", EARNING_PATH)
            .pair("--consuming-wallet", CONSUMING_PATH),
    );

    let persistent_config = persistent_config(DEFAULT_CHAIN_ID);
    let mnemonic = Mnemonic::from_phrase(PHRASE, Language::English).unwrap();
    let expected_seed = Seed::new(&mnemonic, PASSPHRASE);
    assert_eq!(
        persistent_config.mnemonic_seed(PASSWORD).unwrap().as_ref(),
        expected_seed.as_ref()
    );
    assert_eq!(
        persistent_config.consuming_wallet_derivation_path(),
        Some(CONSUMING_PATH.to_string())
    );
    assert_eq!(
        persistent_config.earning_wallet_from_address(),
        Some(earning_path_wallet())
    );
    assert_eq!(persistent_config.consuming_wallet_public_key(), None);
}

#[test]
fn create_database_recovering_neither_derivation_path_integration() {
    let _eg = EnvironmentGuard::new();
    let _console_log = MASQNode::run_recover(
        CommandConfig::new()
            .pair("--mnemonic", PHRASE)
            .pair("--mnemonic-passphrase", PASSPHRASE)
            .pair("--wallet-password", PASSWORD),
    );

    let persistent_config = persistent_config(DEFAULT_CHAIN_ID);
    assert_eq!(
        persistent_config.consuming_wallet_derivation_path(),
        Some(DEFAULT_CONSUMING_DERIVATION_PATH.to_string())
    );
    assert_eq!(
        persistent_config.earning_wallet_from_address(),
        Some(default_earning_path_wallet())
    );
    assert_eq!(persistent_config.consuming_wallet_public_key(), None);
}

#[test]
fn create_database_recovering_only_earning_derivation_path_integration() {
    let _eg = EnvironmentGuard::new();
    let _console_log = MASQNode::run_recover(
        CommandConfig::new()
            .pair("--mnemonic", PHRASE)
            .pair("--mnemonic-passphrase", PASSPHRASE)
            .pair("--wallet-password", PASSWORD)
            .pair("--earning-wallet", EARNING_PATH),
    );

    let persistent_config = persistent_config(DEFAULT_CHAIN_ID);
    let mnemonic = Mnemonic::from_phrase(PHRASE, Language::English).unwrap();
    let expected_seed = Seed::new(&mnemonic, PASSPHRASE);
    assert_eq!(
        persistent_config.mnemonic_seed(PASSWORD).unwrap().as_ref(),
        expected_seed.as_ref()
    );
    assert_eq!(
        persistent_config.consuming_wallet_derivation_path(),
        Some(DEFAULT_CONSUMING_DERIVATION_PATH.to_string())
    );
    assert_eq!(
        persistent_config.earning_wallet_from_address(),
        Some(earning_path_wallet())
    );
    assert_eq!(persistent_config.consuming_wallet_public_key(), None);
}

#[test]
fn create_database_recovering_only_earning_address_integration() {
    let _eg = EnvironmentGuard::new();
    let _console_log = MASQNode::run_recover(
        CommandConfig::new()
            .pair("--mnemonic", PHRASE)
            .pair("--mnemonic-passphrase", PASSPHRASE)
            .pair("--wallet-password", PASSWORD)
            .pair("--earning-wallet", EARNING_ADDRESS),
    );

    let persistent_config = persistent_config(DEFAULT_CHAIN_ID);
    let mnemonic = Mnemonic::from_phrase(PHRASE, Language::English).unwrap();
    let expected_seed = Seed::new(&mnemonic, PASSPHRASE);
    assert_eq!(
        persistent_config.mnemonic_seed(PASSWORD).unwrap().as_ref(),
        expected_seed.as_ref()
    );
    assert_eq!(
        persistent_config.consuming_wallet_derivation_path(),
        Some(DEFAULT_CONSUMING_DERIVATION_PATH.to_string())
    );
    assert_eq!(
        persistent_config.earning_wallet_from_address(),
        Some(Wallet::from_str(EARNING_ADDRESS).unwrap())
    );
    assert_eq!(persistent_config.consuming_wallet_public_key(), None);
}

#[test]
fn create_database_recovering_only_consuming_derivation_path_integration() {
    let _eg = EnvironmentGuard::new();
    let _console_log = MASQNode::run_recover(
        CommandConfig::new()
            .pair("--mnemonic", PHRASE)
            .pair("--mnemonic-passphrase", PASSPHRASE)
            .pair("--wallet-password", PASSWORD)
            .pair("--consuming-wallet", CONSUMING_PATH),
    );

    let persistent_config = persistent_config(DEFAULT_CHAIN_ID);
    let mnemonic = Mnemonic::from_phrase(PHRASE, Language::English).unwrap();
    let expected_seed = Seed::new(&mnemonic, PASSPHRASE);
    assert_eq!(
        persistent_config.mnemonic_seed(PASSWORD).unwrap().as_ref(),
        expected_seed.as_ref()
    );
    assert_eq!(
        persistent_config.consuming_wallet_derivation_path(),
        Some(CONSUMING_PATH.to_string())
    );
    assert_eq!(
        persistent_config.earning_wallet_from_address(),
        Some(default_earning_path_wallet())
    );
    assert_eq!(persistent_config.consuming_wallet_public_key(), None);
}

#[test]
fn create_database_generating_both_derivation_paths_integration() {
    let _eg = EnvironmentGuard::new();

    let console_log = MASQNode::run_generate(
        CommandConfig::new()
            .pair("--mnemonic-passphrase", PASSPHRASE)
            .pair("--wallet-password", PASSWORD)
            .pair("--earning-wallet", EARNING_PATH)
            .pair("--consuming-wallet", CONSUMING_PATH),
    );

    let phrase = phrase_from_console_log(&console_log);
    let persistent_config = persistent_config(DEFAULT_CHAIN_ID);
    assert_eq!(
        persistent_config.consuming_wallet_derivation_path(),
        Some(CONSUMING_PATH.to_string())
    );
    assert_eq!(
        persistent_config.earning_wallet_from_address(),
        Some(wallet_from_phrase_and_path(&phrase, EARNING_PATH))
    );
    assert_eq!(persistent_config.consuming_wallet_public_key(), None);
}

#[test]
fn create_database_generating_neither_derivation_path_integration() {
    let _eg = EnvironmentGuard::new();

    let console_log = MASQNode::run_generate(
        CommandConfig::new()
            .pair("--mnemonic-passphrase", PASSPHRASE)
            .pair("--wallet-password", PASSWORD),
    );

    let phrase = phrase_from_console_log(&console_log);
    let persistent_config = persistent_config(DEFAULT_CHAIN_ID);
    assert_eq!(
        persistent_config.consuming_wallet_derivation_path(),
        Some(DEFAULT_CONSUMING_DERIVATION_PATH.to_string())
    );
    assert_eq!(
        persistent_config.earning_wallet_from_address(),
        Some(wallet_from_phrase_and_path(
            &phrase,
            DEFAULT_EARNING_DERIVATION_PATH
        ))
    );
    assert_eq!(persistent_config.consuming_wallet_public_key(), None);
}

#[test]
fn create_database_generating_only_earning_derivation_path_integration() {
    let _eg = EnvironmentGuard::new();
    let console_log = MASQNode::run_generate(
        CommandConfig::new()
            .pair("--mnemonic-passphrase", PASSPHRASE)
            .pair("--wallet-password", PASSWORD)
            .pair("--earning-wallet", EARNING_PATH),
    );

    let phrase = phrase_from_console_log(&console_log);
    let persistent_config = persistent_config(DEFAULT_CHAIN_ID);
    assert_eq!(
        persistent_config.consuming_wallet_derivation_path(),
        Some(DEFAULT_CONSUMING_DERIVATION_PATH.to_string())
    );
    assert_eq!(
        persistent_config.earning_wallet_from_address(),
        Some(wallet_from_phrase_and_path(&phrase, EARNING_PATH))
    );
    assert_eq!(persistent_config.consuming_wallet_public_key(), None);
}

#[test]
fn create_database_generating_only_earning_address_integration() {
    let _eg = EnvironmentGuard::new();
    let _console_log = MASQNode::run_generate(
        CommandConfig::new()
            .pair("--mnemonic-passphrase", PASSPHRASE)
            .pair("--wallet-password", PASSWORD)
            .pair("--earning-wallet", EARNING_ADDRESS),
    );

    let persistent_config = persistent_config(DEFAULT_CHAIN_ID);
    assert_eq!(
        persistent_config.consuming_wallet_derivation_path(),
        Some(DEFAULT_CONSUMING_DERIVATION_PATH.to_string())
    );
    assert_eq!(
        persistent_config.earning_wallet_from_address(),
        Some(Wallet::new(EARNING_ADDRESS))
    );
    assert_eq!(persistent_config.consuming_wallet_public_key(), None);
}

#[test]
fn create_database_generating_only_consuming_derivation_path_integration() {
    let _eg = EnvironmentGuard::new();
    let console_log = MASQNode::run_generate(
        CommandConfig::new()
            .pair("--mnemonic-passphrase", PASSPHRASE)
            .pair("--wallet-password", PASSWORD)
            .pair("--consuming-wallet", CONSUMING_PATH),
    );

    let phrase = phrase_from_console_log(&console_log);
    let persistent_config = persistent_config(DEFAULT_CHAIN_ID);
    assert_eq!(
        persistent_config.consuming_wallet_derivation_path(),
        Some(CONSUMING_PATH.to_string())
    );
    assert_eq!(
        persistent_config.earning_wallet_from_address(),
        Some(wallet_from_phrase_and_path(
            &phrase,
            DEFAULT_EARNING_DERIVATION_PATH
        ))
    );
    assert_eq!(persistent_config.consuming_wallet_public_key(), None);
}
