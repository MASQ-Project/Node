// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

mod utils;

use bip39::{Language, Mnemonic, Seed};
use node_lib::blockchain::bip32::Bip32ECKeyPair;
use node_lib::database::db_initializer::{DbInitializer, DbInitializerReal};
use node_lib::persistent_configuration::{PersistentConfiguration, PersistentConfigurationReal};
use node_lib::sub_lib::wallet::{
    Wallet, DEFAULT_CONSUMING_DERIVATION_PATH, DEFAULT_EARNING_DERIVATION_PATH,
};
use node_lib::test_utils::environment_guard::EnvironmentGuard;
use std::str::FromStr;
use utils::CommandConfig;
use utils::SubstratumNode;

const PHRASE: &str =
    "snake gorilla marine couch wheel decline stamp glass aunt antenna transfer exit";
const PASSPHRASE: &str = "passphrase";
const PASSWORD: &str = "password";
const EARNING_PATH: &str = "m/44'/60'/3'/2/1";
const EARNING_ADDRESS: &str = "0x0123456789ABCDEF0123456789ABCDEF01234567";
const CONSUMING_PATH: &str = "m/44'/60'/1'/2/3";

fn persistent_config() -> PersistentConfigurationReal {
    PersistentConfigurationReal::from(
        DbInitializerReal::new()
            .initialize(&SubstratumNode::data_dir().to_path_buf())
            .unwrap(),
    )
}

// TODO These tests could all run concurrently if each was given a different data directory.
// That would mean test infrastructure changes, but it's possible.
#[test]
fn create_database_recovering_both_derivation_paths_integration() {
    let _eg = EnvironmentGuard::new();
    let _console_log = SubstratumNode::run_recover(
        CommandConfig::new()
            .pair("--mnemonic", PHRASE)
            .pair("--mnemonic-passphrase", PASSPHRASE)
            .pair("--wallet-password", PASSWORD)
            .pair("--earning-wallet", EARNING_PATH)
            .pair("--consuming-wallet", CONSUMING_PATH),
    );

    let persistent_config = persistent_config();
    let mnemonic = Mnemonic::from_phrase(PHRASE, Language::English).unwrap();
    let expected_seed = Seed::new(&mnemonic, PASSPHRASE);
    assert_eq!(
        persistent_config.mnemonic_seed(PASSWORD).unwrap().as_ref(),
        expected_seed.as_ref()
    );
    let keypair = Bip32ECKeyPair::from_raw(expected_seed.as_ref(), EARNING_PATH).unwrap();
    let expected_earning_wallet = Wallet::from(keypair);
    assert_eq!(
        persistent_config.earning_wallet_from_derivation_path(PASSWORD),
        Some(expected_earning_wallet)
    );
    assert_eq!(
        persistent_config.consuming_wallet_derivation_path(),
        Some(CONSUMING_PATH.to_string())
    );
    assert_eq!(persistent_config.earning_wallet_from_address(), None);
    assert_eq!(
        persistent_config.consuming_wallet_private_public_key(),
        None
    );
}

#[test]
fn create_database_recovering_neither_derivation_path_integration() {
    let _eg = EnvironmentGuard::new();
    let _console_log = SubstratumNode::run_recover(
        CommandConfig::new()
            .pair("--mnemonic", PHRASE)
            .pair("--mnemonic-passphrase", PASSPHRASE)
            .pair("--wallet-password", PASSWORD),
    );

    let persistent_config = persistent_config();
    let mnemonic = Mnemonic::from_phrase(PHRASE, Language::English).unwrap();
    let expected_seed = Seed::new(&mnemonic, PASSPHRASE);
    assert_eq!(
        persistent_config.mnemonic_seed(PASSWORD).unwrap().as_ref(),
        expected_seed.as_ref()
    );
    let keypair =
        Bip32ECKeyPair::from_raw(expected_seed.as_ref(), DEFAULT_EARNING_DERIVATION_PATH).unwrap();
    let expected_earning_wallet = Wallet::from(keypair);
    assert_eq!(
        persistent_config.earning_wallet_from_derivation_path(PASSWORD),
        Some(expected_earning_wallet)
    );
    assert_eq!(
        persistent_config.consuming_wallet_derivation_path(),
        Some(DEFAULT_CONSUMING_DERIVATION_PATH.to_string())
    );
    assert_eq!(persistent_config.earning_wallet_from_address(), None);
    assert_eq!(
        persistent_config.consuming_wallet_private_public_key(),
        None
    );
}

#[test]
fn create_database_recovering_only_earning_derivation_path_integration() {
    let _eg = EnvironmentGuard::new();
    let _console_log = SubstratumNode::run_recover(
        CommandConfig::new()
            .pair("--mnemonic", PHRASE)
            .pair("--mnemonic-passphrase", PASSPHRASE)
            .pair("--wallet-password", PASSWORD)
            .pair("--earning-wallet", EARNING_PATH),
    );

    let persistent_config = persistent_config();
    let mnemonic = Mnemonic::from_phrase(PHRASE, Language::English).unwrap();
    let expected_seed = Seed::new(&mnemonic, PASSPHRASE);
    assert_eq!(
        persistent_config.mnemonic_seed(PASSWORD).unwrap().as_ref(),
        expected_seed.as_ref()
    );
    let keypair = Bip32ECKeyPair::from_raw(expected_seed.as_ref(), EARNING_PATH).unwrap();
    let expected_earning_wallet = Wallet::from(keypair);
    assert_eq!(
        persistent_config.earning_wallet_from_derivation_path(PASSWORD),
        Some(expected_earning_wallet)
    );
    assert_eq!(
        persistent_config.consuming_wallet_derivation_path(),
        Some(DEFAULT_CONSUMING_DERIVATION_PATH.to_string())
    );
    assert_eq!(persistent_config.earning_wallet_from_address(), None);
    assert_eq!(
        persistent_config.consuming_wallet_private_public_key(),
        None
    );
}

#[test]
fn create_database_recovering_only_earning_address_integration() {
    let _eg = EnvironmentGuard::new();
    let _console_log = SubstratumNode::run_recover(
        CommandConfig::new()
            .pair("--mnemonic", PHRASE)
            .pair("--mnemonic-passphrase", PASSPHRASE)
            .pair("--wallet-password", PASSWORD)
            .pair("--earning-wallet", EARNING_ADDRESS),
    );

    let persistent_config = persistent_config();
    let mnemonic = Mnemonic::from_phrase(PHRASE, Language::English).unwrap();
    let expected_seed = Seed::new(&mnemonic, PASSPHRASE);
    assert_eq!(
        persistent_config.mnemonic_seed(PASSWORD).unwrap().as_ref(),
        expected_seed.as_ref()
    );
    assert_eq!(
        persistent_config.earning_wallet_from_derivation_path(PASSWORD),
        None
    );
    assert_eq!(
        persistent_config.consuming_wallet_derivation_path(),
        Some(DEFAULT_CONSUMING_DERIVATION_PATH.to_string())
    );
    assert_eq!(
        persistent_config.earning_wallet_from_address(),
        Some(Wallet::from_str(EARNING_ADDRESS).unwrap())
    );
    assert_eq!(
        persistent_config.consuming_wallet_private_public_key(),
        None
    );
}

#[test]
fn create_database_recovering_only_consuming_derivation_path_integration() {
    let _eg = EnvironmentGuard::new();
    let _console_log = SubstratumNode::run_recover(
        CommandConfig::new()
            .pair("--mnemonic", PHRASE)
            .pair("--mnemonic-passphrase", PASSPHRASE)
            .pair("--wallet-password", PASSWORD)
            .pair("--consuming-wallet", CONSUMING_PATH),
    );

    let persistent_config = persistent_config();
    let mnemonic = Mnemonic::from_phrase(PHRASE, Language::English).unwrap();
    let expected_seed = Seed::new(&mnemonic, PASSPHRASE);
    assert_eq!(
        persistent_config.mnemonic_seed(PASSWORD).unwrap().as_ref(),
        expected_seed.as_ref()
    );
    let keypair =
        Bip32ECKeyPair::from_raw(expected_seed.as_ref(), DEFAULT_EARNING_DERIVATION_PATH).unwrap();
    let expected_earning_wallet = Wallet::from(keypair);
    assert_eq!(
        persistent_config.earning_wallet_from_derivation_path(PASSWORD),
        Some(expected_earning_wallet)
    );
    assert_eq!(
        persistent_config.consuming_wallet_derivation_path(),
        Some(CONSUMING_PATH.to_string())
    );
    assert_eq!(persistent_config.earning_wallet_from_address(), None);
    assert_eq!(
        persistent_config.consuming_wallet_private_public_key(),
        None
    );
}

#[test]
fn create_database_generating_both_derivation_paths_integration() {
    let _eg = EnvironmentGuard::new();
    let _console_log = SubstratumNode::run_generate(
        CommandConfig::new()
            .pair("--mnemonic-passphrase", PASSPHRASE)
            .pair("--wallet-password", PASSWORD)
            .pair("--earning-wallet", EARNING_PATH)
            .pair("--consuming-wallet", CONSUMING_PATH),
    );

    let persistent_config = persistent_config();
    let expected_seed = persistent_config.mnemonic_seed(PASSWORD).unwrap();
    let keypair = Bip32ECKeyPair::from_raw(expected_seed.as_ref(), EARNING_PATH).unwrap();
    let expected_earning_wallet = Wallet::from(keypair);
    assert_eq!(
        persistent_config.earning_wallet_from_derivation_path(PASSWORD),
        Some(expected_earning_wallet)
    );
    assert_eq!(
        persistent_config.consuming_wallet_derivation_path(),
        Some(CONSUMING_PATH.to_string())
    );
    assert_eq!(persistent_config.earning_wallet_from_address(), None);
    assert_eq!(
        persistent_config.consuming_wallet_private_public_key(),
        None
    );
}

#[test]
fn create_database_generating_neither_derivation_path_integration() {
    let _eg = EnvironmentGuard::new();
    let _console_log = SubstratumNode::run_generate(
        CommandConfig::new()
            .pair("--mnemonic-passphrase", PASSPHRASE)
            .pair("--wallet-password", PASSWORD),
    );

    let persistent_config = persistent_config();
    let expected_seed = persistent_config.mnemonic_seed(PASSWORD).unwrap();
    let keypair =
        Bip32ECKeyPair::from_raw(expected_seed.as_ref(), DEFAULT_EARNING_DERIVATION_PATH).unwrap();
    let expected_earning_wallet = Wallet::from(keypair);
    assert_eq!(
        persistent_config.earning_wallet_from_derivation_path(PASSWORD),
        Some(expected_earning_wallet)
    );
    assert_eq!(
        persistent_config.consuming_wallet_derivation_path(),
        Some(DEFAULT_CONSUMING_DERIVATION_PATH.to_string())
    );
    assert_eq!(persistent_config.earning_wallet_from_address(), None);
    assert_eq!(
        persistent_config.consuming_wallet_private_public_key(),
        None
    );
}

#[test]
fn create_database_generating_only_earning_derivation_path_integration() {
    let _eg = EnvironmentGuard::new();
    let _console_log = SubstratumNode::run_generate(
        CommandConfig::new()
            .pair("--mnemonic-passphrase", PASSPHRASE)
            .pair("--wallet-password", PASSWORD)
            .pair("--earning-wallet", EARNING_PATH),
    );

    let persistent_config = persistent_config();
    let expected_seed = persistent_config.mnemonic_seed(PASSWORD).unwrap();
    let keypair = Bip32ECKeyPair::from_raw(expected_seed.as_ref(), EARNING_PATH).unwrap();
    let expected_earning_wallet = Wallet::from(keypair);
    assert_eq!(
        persistent_config.earning_wallet_from_derivation_path(PASSWORD),
        Some(expected_earning_wallet)
    );
    assert_eq!(
        persistent_config.consuming_wallet_derivation_path(),
        Some(DEFAULT_CONSUMING_DERIVATION_PATH.to_string())
    );
    assert_eq!(persistent_config.earning_wallet_from_address(), None);
    assert_eq!(
        persistent_config.consuming_wallet_private_public_key(),
        None
    );
}

#[test]
fn create_database_generating_only_earning_address_integration() {
    let _eg = EnvironmentGuard::new();
    let _console_log = SubstratumNode::run_generate(
        CommandConfig::new()
            .pair("--mnemonic-passphrase", PASSPHRASE)
            .pair("--wallet-password", PASSWORD)
            .pair("--earning-wallet", EARNING_PATH),
    );

    let persistent_config = persistent_config();
    let expected_seed = persistent_config.mnemonic_seed(PASSWORD).unwrap();
    let keypair = Bip32ECKeyPair::from_raw(expected_seed.as_ref(), EARNING_PATH).unwrap();
    let expected_earning_wallet = Wallet::from(keypair);
    assert_eq!(
        persistent_config.earning_wallet_from_derivation_path(PASSWORD),
        Some(expected_earning_wallet)
    );
    assert_eq!(
        persistent_config.consuming_wallet_derivation_path(),
        Some(DEFAULT_CONSUMING_DERIVATION_PATH.to_string())
    );
    assert_eq!(persistent_config.earning_wallet_from_address(), None);
    assert_eq!(
        persistent_config.consuming_wallet_private_public_key(),
        None
    );
}

#[test]
fn create_database_generating_only_consuming_derivation_path_integration() {
    let _eg = EnvironmentGuard::new();
    let _console_log = SubstratumNode::run_generate(
        CommandConfig::new()
            .pair("--mnemonic-passphrase", PASSPHRASE)
            .pair("--wallet-password", PASSWORD)
            .pair("--consuming-wallet", CONSUMING_PATH),
    );

    let persistent_config = persistent_config();
    let expected_seed = persistent_config.mnemonic_seed(PASSWORD).unwrap();
    let keypair =
        Bip32ECKeyPair::from_raw(expected_seed.as_ref(), DEFAULT_EARNING_DERIVATION_PATH).unwrap();
    let expected_earning_wallet = Wallet::from(keypair);
    assert_eq!(
        persistent_config.earning_wallet_from_derivation_path(PASSWORD),
        Some(expected_earning_wallet)
    );
    assert_eq!(
        persistent_config.consuming_wallet_derivation_path(),
        Some(CONSUMING_PATH.to_string())
    );
    assert_eq!(persistent_config.earning_wallet_from_address(), None);
    assert_eq!(
        persistent_config.consuming_wallet_private_public_key(),
        None
    );
}
