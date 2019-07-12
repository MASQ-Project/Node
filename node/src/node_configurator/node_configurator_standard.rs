// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

use crate::bootstrapper::BootstrapperConfig;
use crate::node_configurator::node_configurator;
use crate::node_configurator::node_configurator::{
    common_validators, config_file_arg, data_directory_arg, earning_wallet_arg,
    initialize_database, make_multi_config, wallet_password_arg, NodeConfigurator,
};
use crate::sub_lib::crash_point::CrashPoint;
use crate::sub_lib::main_tools::StdStreams;
use crate::sub_lib::neighborhood::sentinel_ip_addr;
use crate::sub_lib::ui_gateway::DEFAULT_UI_PORT;
use clap::{crate_authors, crate_description, crate_version, App, AppSettings, Arg};
use indoc::indoc;
use lazy_static::lazy_static;

pub const LOWEST_USABLE_INSECURE_PORT: u16 = 1025;
pub const HIGHEST_USABLE_PORT: u16 = 65535;

pub struct NodeConfiguratorStandardPrivileged {}

impl NodeConfigurator<BootstrapperConfig> for NodeConfiguratorStandardPrivileged {
    fn configure(&self, args: &Vec<String>, streams: &mut StdStreams) -> BootstrapperConfig {
        let app = app();
        let multi_config = make_multi_config(&app, args);
        let mut bootstrapper_config = BootstrapperConfig::new();
        standard::establish_port_configurations(&mut bootstrapper_config);
        standard::privileged_parse_args(&multi_config, &mut bootstrapper_config, streams);
        bootstrapper_config
    }
}

pub struct NodeConfiguratorStandardUnprivileged {}

impl NodeConfigurator<BootstrapperConfig> for NodeConfiguratorStandardUnprivileged {
    fn configure(&self, args: &Vec<String>, streams: &mut StdStreams<'_>) -> BootstrapperConfig {
        let app = app();
        let multi_config = make_multi_config(&app, args);
        let persistent_config = initialize_database(&multi_config);
        let mut bootstrapper_config = BootstrapperConfig::new();
        standard::unprivileged_parse_args(
            &multi_config,
            &mut bootstrapper_config,
            streams,
            persistent_config.as_ref(),
        );
        standard::configure_database(&bootstrapper_config, persistent_config.as_ref());
        bootstrapper_config
    }
}

lazy_static! {
    static ref DEFAULT_UI_PORT_VALUE: String = DEFAULT_UI_PORT.to_string();
    static ref DEFAULT_CRASH_POINT_VALUE: String = format!("{}", CrashPoint::None);
    static ref DEFAULT_IP_VALUE: String = sentinel_ip_addr().to_string();
    static ref UI_PORT_HELP: String = format!(
        "Must be between {} and {}",
        LOWEST_USABLE_INSECURE_PORT, HIGHEST_USABLE_PORT
    );
    static ref CLANDESTINE_PORT_HELP: String = format!(
        "Must be between {} and {} [default: last used port]",
        LOWEST_USABLE_INSECURE_PORT, HIGHEST_USABLE_PORT
    );
}

const BLOCKCHAIN_SERVICE_HELP: &str =
    "The Ethereum client you wish to use to provide Blockchain \
     exit services from your SubstratumNode (e.g. http://localhost:8545, \
     https://ropsten.infura.io/v3/YOUR-PROJECT-ID, https://mainnet.infura.io/v3/YOUR-PROJECT-ID).";
const DNS_SERVERS_HELP: &str =
    "IP addresses of DNS Servers for host name look-up while providing exit \
     services for other SubstratumNodes (e.g. 1.0.0.1, 1.1.1.1, 8.8.8.8, 9.9.9.9, etc.)";
pub const EARNING_WALLET_HELP: &str =
    "An Ethereum wallet address. Addresses must begin with 0x followed by 40 hexadecimal digits \
     (case-insensitive). If you already have a derivation-path earning wallet, don't supply this. \
     If you have supplied an earning wallet address before, either don't supply it again or be \
     careful to supply exactly the same one you supplied before.";
const IP_ADDRESS_HELP: &str = "The public IP address of your SubstratumNode: that is, the IPv4 \
                               address at which other SubstratumNodes can contact yours.";
const WALLET_PASSWORD_HELP: &str =
    "A password or phrase to decrypt your consuming wallet or a keystore file. Can be changed \
     later and still produce the same addresses.";

const HELP_TEXT: &str = indoc!(
    r"ADDITIONAL HELP:
    If you want to generate wallets to earn money into and spend money from, try:

        SubstratumNode --help --generate-wallet

    If you already have a set of wallets, try:

        SubstratumNode --help --recover-wallet

    SubstratumNode listens for connections from other SubstratumNodes using the computer's
    network interface. Configuring the internet router for port forwarding is a necessary
    step for SubstratumNode users to permit network communication between SubstratumNodes.

    Once started, SubstratumNode prints the node descriptor to the console. The descriptor
    indicates the required port needing to be forwarded by the network router. The port is
    the last number in the descriptor, as shown below:

    95VjByq5tEUUpDcczA//zXWGE6+7YFEvzN4CDVoPbWw:86.75.30.9:1234
                                                           ^^^^
    Steps To Forwarding Ports In The Router
        1. Log in to the router.
        2. Navigate to the router's port forwarding section, also frequently called virtual server.
        3. Create the port forwarding entries in the router."
);

fn app() -> App<'static, 'static> {
    App::new("SubstratumNode")
        .global_settings(if cfg!(test) {
            &[AppSettings::ColorNever]
        } else {
            &[AppSettings::ColorAuto, AppSettings::ColoredHelp]
        })
        .version(crate_version!())
        .author(crate_authors!("\n"))
        .about(crate_description!())
        .after_help(HELP_TEXT)
        .arg(
            Arg::with_name("blockchain-service-url")
                .long("blockchain-service-url")
                .aliases(&["blockchain-service-url", "blockchain_service_url"])
                .empty_values(false)
                .value_name("URL")
                .takes_value(true)
                .help(BLOCKCHAIN_SERVICE_HELP),
        )
        .arg(
            Arg::with_name("clandestine-port")
                .long("clandestine-port")
                .aliases(&["clandestine-port", "clandestine_port"])
                .value_name("CLANDESTINE-PORT")
                .empty_values(false)
                .validator(validators::validate_clandestine_port)
                .help(&CLANDESTINE_PORT_HELP),
        )
        .arg(config_file_arg())
        .arg(
            Arg::with_name("consuming-private-key")
                .long("consuming-private-key")
                .aliases(&["consuming-private-key", "consuming_private_key"])
                .value_name("PRIVATE-KEY")
                .takes_value(true)
                .validator(validators::validate_private_key)
                .help(node_configurator::CONSUMING_PRIVATE_KEY_HELP),
        )
        .arg(
            Arg::with_name("crash-point")
                .long("crash-point")
                .aliases(&["crash-point", "crash_point"])
                .value_name("CRASH-POINT")
                .takes_value(true)
                .default_value(&DEFAULT_CRASH_POINT_VALUE)
                .possible_values(&CrashPoint::variants())
                .case_insensitive(true)
                .hidden(true),
        )
        .arg(data_directory_arg())
        .arg(
            Arg::with_name("dns-servers")
                .long("dns-servers")
                .aliases(&["dns-servers", "dns_servers"])
                .value_name("DNS-SERVERS")
                .takes_value(true)
                .use_delimiter(true)
                .validator(validators::validate_ip_address)
                .help(DNS_SERVERS_HELP),
        )
        .arg(earning_wallet_arg(
            EARNING_WALLET_HELP,
            common_validators::validate_ethereum_address,
        ))
        .arg(
            Arg::with_name("fake-public-key")
                .long("fake-public-key")
                .aliases(&["fake-public-key", "fake_public_key"])
                .value_name("FAKE-PUBLIC-KEY")
                .takes_value(true)
                .hidden(true),
        )
        .arg(
            Arg::with_name("ip")
                .long("ip")
                .value_name("IP")
                .takes_value(true)
                .default_value(&DEFAULT_IP_VALUE)
                .validator(validators::validate_ip_address)
                .help(IP_ADDRESS_HELP),
        )
        .arg(
            Arg::with_name("log-level")
                .long("log-level")
                .aliases(&["log-level", "log_level"])
                .value_name("FILTER")
                .takes_value(true)
                .possible_values(&["error", "warn", "info", "debug", "trace", "off"])
                .default_value("warn")
                .case_insensitive(true),
        )
        .arg(
            Arg::with_name("neighbors")
                .long("neighbors")
                .value_name("NODE-DESCRIPTORS")
                .takes_value(true)
                .use_delimiter(true)
                .requires("ip"),
        )
        .arg(
            Arg::with_name("ui-port")
                .long("ui-port")
                .aliases(&["ui-port", "ui_port"])
                .value_name("UI-PORT")
                .takes_value(true)
                .default_value(&DEFAULT_UI_PORT_VALUE)
                .validator(validators::validate_ui_port)
                .help(&UI_PORT_HELP),
        )
        .arg(wallet_password_arg(WALLET_PASSWORD_HELP))
}

mod standard {
    use super::*;
    use std::net::IpAddr;
    use std::net::SocketAddr;
    use std::path::PathBuf;

    use clap::{value_t, values_t};
    use log::LevelFilter;

    use crate::blockchain::bip32::Bip32ECKeyPair;
    use crate::blockchain::bip39::{Bip39, Bip39Error};
    use crate::bootstrapper::PortConfiguration;
    use crate::http_request_start_finder::HttpRequestDiscriminatorFactory;
    use crate::multi_config::MultiConfig;
    use crate::node_configurator::node_configurator::request_wallet_decryption_password;
    use crate::persistent_configuration::{PersistentConfiguration, HTTP_PORT, TLS_PORT};
    use crate::sub_lib::accountant::DEFAULT_EARNING_WALLET;
    use crate::sub_lib::cryptde::{PlainData, PublicKey};
    use crate::sub_lib::cryptde_null::CryptDENull;
    use crate::sub_lib::wallet::Wallet;
    use crate::tls_discriminator_factory::TlsDiscriminatorFactory;
    use rustc_hex::FromHex;
    use std::convert::TryInto;
    use std::str::FromStr;

    pub fn establish_port_configurations(config: &mut BootstrapperConfig) {
        config.port_configurations.insert(
            HTTP_PORT,
            PortConfiguration::new(
                vec![Box::new(HttpRequestDiscriminatorFactory::new())],
                false,
            ),
        );
        config.port_configurations.insert(
            TLS_PORT,
            PortConfiguration::new(
                vec![
                    Box::new(TlsDiscriminatorFactory::new()),
                    Box::new(HttpRequestDiscriminatorFactory::new()),
                ],
                false,
            ),
        );
    }

    pub fn privileged_parse_args(
        multi_config: &MultiConfig,
        config: &mut BootstrapperConfig,
        _streams: &mut StdStreams<'_>,
    ) {
        config.blockchain_bridge_config.blockchain_service_url =
            value_m!(multi_config, "blockchain-service-url", String);

        config.data_directory =
            value_m!(multi_config, "data-directory", PathBuf).expect("Internal Error");

        config.dns_servers = values_m!(multi_config, "dns-servers", IpAddr)
            .into_iter()
            .map(|ip| SocketAddr::from((ip, 53)))
            .collect();

        config.neighborhood_config.local_ip_addr =
            value_m!(multi_config, "ip", IpAddr).expect("Internal Error");

        config.log_level =
            value_m!(multi_config, "log-level", LevelFilter).expect("Internal Error");

        config.neighborhood_config.neighbor_configs = values_m!(multi_config, "neighbors", String);

        config.ui_gateway_config.ui_port =
            value_m!(multi_config, "ui-port", u16).expect("Internal Error");

        config.crash_point =
            value_m!(multi_config, "crash-point", CrashPoint).expect("Internal Error");

        match value_m!(multi_config, "fake-public-key", String) {
            None => (),
            Some(public_key_str) => {
                let public_key = match base64::decode(&public_key_str) {
                    Ok(key) => PublicKey::new(&key),
                    Err(_) => panic!("Invalid fake public key: {}", public_key_str),
                };
                let cryptde_null = CryptDENull::from(&public_key);
                config.cryptde_null_opt = Some(cryptde_null);
            }
        }
    }

    pub fn unprivileged_parse_args(
        multi_config: &MultiConfig,
        config: &mut BootstrapperConfig,
        streams: &mut StdStreams<'_>,
        persistent_config: &PersistentConfiguration,
    ) {
        config.clandestine_port_opt = value_m!(multi_config, "clandestine-port", u16);

        config.data_directory =
            value_m!(multi_config, "data-directory", PathBuf).expect("Internal Error");

        get_wallets(streams, multi_config, persistent_config, config);
    }

    pub fn configure_database(
        config: &BootstrapperConfig,
        persistent_config: &PersistentConfiguration,
    ) {
        if let Some(port) = config.clandestine_port_opt {
            persistent_config.set_clandestine_port(port)
        }
        match &config.consuming_wallet {
            Some(wallet) => {
                let keypair_opt: Option<Bip32ECKeyPair> = match wallet.clone().try_into() {
                    Ok(kp) => Some(kp),
                    Err(_) => None,
                };
                if let Some(keypair) = keypair_opt {
                    let public_key = PlainData::new(keypair.secret().public().bytes());
                    persistent_config.set_consuming_wallet_private_public_key(&public_key);
                }
            }
            None => (),
        }
    }

    pub fn get_wallets(
        streams: &mut StdStreams,
        multi_config: &MultiConfig,
        persistent_config: &PersistentConfiguration,
        config: &mut BootstrapperConfig,
    ) {
        let mut earning_wallet_opt =
            standard::get_earning_wallet_from_address(multi_config, persistent_config);
        let mut consuming_wallet_opt =
            standard::get_consuming_wallet_from_private_key(multi_config);
        let encrypted_mnemonic_seed = persistent_config.encrypted_mnemonic_seed();
        if earning_wallet_opt.is_some()
            && consuming_wallet_opt.is_some()
            && encrypted_mnemonic_seed.is_some()
        {
            panic! ("Cannot use --consuming-private-key and earning wallet address when database contains mnemonic seed")
        }

        if earning_wallet_opt.is_none() || consuming_wallet_opt.is_none() {
            match standard::get_mnemonic_seed_and_password(multi_config, streams, persistent_config)
            {
                Some((_, wallet_password)) => {
                    if earning_wallet_opt.is_none() {
                        earning_wallet_opt = standard::get_earning_wallet_from_derivation_path(
                            persistent_config,
                            &wallet_password,
                        );
                    } else if standard::get_earning_wallet_from_derivation_path(
                        persistent_config,
                        &wallet_password,
                    )
                    .is_some()
                    {
                        panic! ("Database is corrupt: contains both address and derivation path for earning wallet")
                    }
                    if consuming_wallet_opt.is_none() {
                        consuming_wallet_opt =
                            standard::get_consuming_wallet_opt_from_derivation_path(
                                persistent_config,
                                &wallet_password,
                            );
                    } else if persistent_config
                        .consuming_wallet_derivation_path()
                        .is_some()
                    {
                        panic! ("Cannot use --consuming-private-key when database contains mnemonic seed and consuming wallet derivation path")
                    }
                }
                None => {
                    if persistent_config
                        .consuming_wallet_derivation_path()
                        .is_some()
                    {
                        panic! ("Database is corrupt: consuming wallet derivation path is present, but no mnemonic seed")
                    }
                }
            }
        }
        config.consuming_wallet = consuming_wallet_opt;
        config.earning_wallet = match earning_wallet_opt {
            Some(earning_wallet) => earning_wallet,
            None => DEFAULT_EARNING_WALLET.clone(),
        };
    }

    fn get_earning_wallet_from_address(
        multi_config: &MultiConfig,
        persistent_config: &PersistentConfiguration,
    ) -> Option<Wallet> {
        let earning_wallet_from_command_line_opt = value_m!(multi_config, "earning-wallet", String);
        let earning_wallet_from_database_opt = persistent_config.earning_wallet_from_address();
        match (
            earning_wallet_from_command_line_opt,
            earning_wallet_from_database_opt,
        ) {
            (None, None) => None,
            (Some(address), None) => Some(
                Wallet::from_str(&address)
                    .expect("--earning-wallet not properly constrained by clap"),
            ),
            (None, Some(wallet)) => Some(wallet),
            (Some(address), Some(wallet)) => {
                if wallet.to_string() == address {
                    Some(wallet)
                } else {
                    panic! ("Cannot use --earning-wallet to specify an address ({}) different from that previously set ({})", address, wallet)
                }
            }
        }
    }

    fn get_earning_wallet_from_derivation_path(
        persistent_config: &PersistentConfiguration,
        wallet_password: &str,
    ) -> Option<Wallet> {
        persistent_config.earning_wallet_from_derivation_path(wallet_password)
    }

    fn get_consuming_wallet_opt_from_derivation_path(
        persistent_config: &PersistentConfiguration,
        wallet_password: &str,
    ) -> Option<Wallet> {
        match persistent_config.consuming_wallet_derivation_path() {
            None => None,
            Some(derivation_path) => match persistent_config.mnemonic_seed(wallet_password) {
                Err(Bip39Error::NotPresent) => None,
                Ok(mnemonic_seed) => {
                    let keypair =
                        Bip32ECKeyPair::from_raw(mnemonic_seed.as_ref(), &derivation_path).expect(
                            &format!(
                                "Error making keypair from mnemonic seed and derivation path {}",
                                derivation_path
                            ),
                        );
                    Some(Wallet::from(keypair))
                }
                Err(e) => panic!("Error retrieving mnemonic seed from database: {:?}", e),
            },
        }
    }

    fn get_consuming_wallet_from_private_key(multi_config: &MultiConfig) -> Option<Wallet> {
        match value_m!(multi_config, "consuming-private-key", String) {
            Some(consuming_private_key_string) => {
                match consuming_private_key_string.from_hex::<Vec<u8>>() {
                    Ok(raw_secret) => match Bip32ECKeyPair::from_raw_secret(&raw_secret[..]) {
                        Ok(keypair) => Some(Wallet::from(keypair)),
                        Err(e) => panic!("Cannot create consuming wallet from private key {}", e),
                    },
                    Err(e) => panic!("Unable to parse private key {}", e),
                }
            }
            None => None,
        }
    }

    fn get_mnemonic_seed_and_password(
        multi_config: &MultiConfig,
        streams: &mut StdStreams,
        persistent_config: &PersistentConfiguration,
    ) -> Option<(PlainData, String)> {
        match persistent_config.encrypted_mnemonic_seed() {
            None => None,
            Some(encrypted_mnemonic_seed) => {
                let wallet_password =
                    match value_user_specified_m!(multi_config, "wallet-password", String) {
                        (Some(wp), true) => wp,
                        _ => request_wallet_decryption_password(
                            streams,
                            Some("Decrypt wallet from database"),
                            "Enter password: ",
                            &encrypted_mnemonic_seed,
                        )
                        .expect("Decryption password is required"),
                    };
                match Bip39::decrypt_bytes(&encrypted_mnemonic_seed, &wallet_password) {
                    Ok(plain_data) => Some((plain_data, wallet_password)),
                    Err(e) => panic!("Could not verify password: {:?}", e),
                }
            }
        }
    }
}

mod validators {
    use super::*;
    use regex::Regex;
    use std::net::IpAddr;
    use std::str::FromStr;

    pub fn validate_ip_address(address: String) -> Result<(), String> {
        match IpAddr::from_str(&address) {
            Ok(_) => Ok(()),
            Err(_) => Err(address),
        }
    }

    pub fn validate_ui_port(port: String) -> Result<(), String> {
        match str::parse::<u16>(&port) {
            Ok(port_number) if port_number < LOWEST_USABLE_INSECURE_PORT => Err(port),
            Ok(_) => Ok(()),
            Err(_) => Err(port),
        }
    }

    pub fn validate_clandestine_port(clandestine_port: String) -> Result<(), String> {
        match clandestine_port.parse::<u16>() {
            Ok(clandestine_port) if clandestine_port >= LOWEST_USABLE_INSECURE_PORT => Ok(()),
            _ => Err(clandestine_port),
        }
    }

    pub fn validate_private_key(key: String) -> Result<(), String> {
        if Regex::new("^[0-9a-fA-F]{64}$")
            .expect("Failed to compile regular expression")
            .is_match(&key)
        {
            Ok(())
        } else {
            Err(key)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::Cursor;
    use std::io::Write;
    use std::net::SocketAddr;
    use std::net::{IpAddr, Ipv4Addr};
    use std::num::NonZeroU32;
    use std::str::FromStr;

    use ethsign::keyfile::Crypto;
    use ethsign::Protected;
    use rustc_hex::{FromHex, ToHex};

    use crate::blockchain::bip32::Bip32ECKeyPair;
    use crate::config_dao::{ConfigDao, ConfigDaoReal};
    use crate::database::db_initializer;
    use crate::multi_config::tests::FauxEnvironmentVCL;
    use crate::multi_config::{
        CommandLineVCL, ConfigFileVCL, MultiConfig, NameValueVclArg, VclArg, VirtualCommandLine,
    };
    use crate::sub_lib::cryptde::{CryptDE, PlainData, PublicKey};
    use crate::sub_lib::neighborhood::sentinel_ip_addr;
    use crate::sub_lib::wallet::Wallet;
    use crate::test_utils::environment_guard::EnvironmentGuard;
    use crate::test_utils::test_utils::{ensure_node_home_directory_exists, make_wallet};
    use crate::test_utils::test_utils::{ByteArrayWriter, FakeStreamHolder};

    use super::*;
    use crate::blockchain::bip39::{Bip39, Bip39Error};
    use crate::database::db_initializer::{DbInitializer, DbInitializerReal};
    use crate::persistent_configuration::PersistentConfigurationReal;
    use crate::sub_lib::accountant::DEFAULT_EARNING_WALLET;
    use crate::sub_lib::crash_point::CrashPoint;
    use crate::test_utils::persistent_configuration_mock::PersistentConfigurationMock;
    use crate::test_utils::test_utils::make_default_persistent_configuration;
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};

    fn make_default_cli_params() -> Vec<String> {
        vec![
            String::from("SubstratumNode"),
            String::from("--dns-servers"),
            String::from("222.222.222.222"),
        ]
    }

    #[test]
    fn validate_private_key_requires_a_key_that_is_64_characters_long() {
        let result = validators::validate_private_key(String::from("42"));

        assert_eq!(Err("42".to_string()), result);
    }

    #[test]
    fn validate_private_key_must_contain_only_hex_characters() {
        let result = validators::validate_private_key(String::from(
            "cc46befe8d169b89db447bd725fc2368b12542113555302598430cinvalidhex",
        ));

        assert_eq!(
            Err("cc46befe8d169b89db447bd725fc2368b12542113555302598430cinvalidhex".to_string()),
            result
        );
    }

    #[test]
    fn validate_private_key_handles_happy_path() {
        let result = validators::validate_private_key(String::from(
            "cc46befe8d169b89db447bd725fc2368b12542113555302598430cb5d5c74ea9",
        ));

        assert_eq!(Ok(()), result);
    }

    #[test]
    fn validate_ip_address_given_invalid_input() {
        assert_eq!(
            Err(String::from("not-a-valid-IP")),
            validators::validate_ip_address(String::from("not-a-valid-IP")),
        );
    }

    #[test]
    fn validate_ip_address_given_valid_input() {
        assert_eq!(
            Ok(()),
            validators::validate_ip_address(String::from("1.2.3.4"))
        );
    }

    #[test]
    fn validate_ui_port_complains_about_non_numeric_ui_port() {
        let result = validators::validate_ui_port(String::from("booga"));

        assert_eq!(Err(String::from("booga")), result);
    }

    #[test]
    fn validate_ui_port_complains_about_ui_port_too_low() {
        let result = validators::validate_ui_port(String::from("1023"));

        assert_eq!(Err(String::from("1023")), result);
    }

    #[test]
    fn validate_ui_port_complains_about_ui_port_too_high() {
        let result = validators::validate_ui_port(String::from("65536"));

        assert_eq!(Err(String::from("65536")), result);
    }

    #[test]
    fn validate_ui_port_works() {
        let result = validators::validate_ui_port(String::from("5335"));

        assert_eq!(Ok(()), result);
    }

    #[test]
    fn validate_clandestine_port_rejects_badly_formatted_port_number() {
        let result = validators::validate_clandestine_port(String::from("booga"));

        assert_eq!(Err(String::from("booga")), result);
    }

    #[test]
    fn validate_clandestine_port_rejects_port_number_too_low() {
        let result = validators::validate_clandestine_port(String::from("1024"));

        assert_eq!(Err(String::from("1024")), result);
    }

    #[test]
    fn validate_clandestine_port_rejects_port_number_too_high() {
        let result = validators::validate_clandestine_port(String::from("65536"));

        assert_eq!(Err(String::from("65536")), result);
    }

    #[test]
    fn validate_clandestine_port_accepts_port_if_provided() {
        let result = validators::validate_clandestine_port(String::from("4567"));

        assert_eq!(Ok(()), result);
    }

    #[test]
    fn can_read_required_parameters_from_config_file() {
        let _guard = EnvironmentGuard::new();
        let home_dir = ensure_node_home_directory_exists(
            "node_configurator",
            "can_read_required_parameters_from_config_file",
        );
        {
            let mut config_file = File::create(home_dir.join("config.toml")).unwrap();
            config_file
                .write_all(b"dns-servers = \"1.2.3.4\"\n")
                .unwrap();
        }
        let subject = NodeConfiguratorStandardPrivileged {};

        let configuration = subject.configure(
            &vec![
                "".to_string(),
                "--data-directory".to_string(),
                home_dir.to_str().unwrap().to_string(),
            ],
            &mut FakeStreamHolder::new().streams(),
        );

        assert_eq!(
            vec![SocketAddr::new(IpAddr::from_str("1.2.3.4").unwrap(), 53)],
            configuration.dns_servers
        );
    }

    #[test]
    fn can_read_dns_servers_and_consuming_private_key_from_config_file() {
        let home_dir = ensure_node_home_directory_exists(
            "node_configurator",
            "can_read_wallet_parameters_from_config_file",
        );
        let persistent_config = PersistentConfigurationReal::new(Box::new(ConfigDaoReal::new(
            DbInitializerReal::new()
                .initialize(&home_dir.clone())
                .unwrap(),
        )));
        let consuming_private_key =
            "89ABCDEF89ABCDEF89ABCDEF89ABCDEF89ABCDEF89ABCDEF89ABCDEF89ABCDEF";
        let config_file_path = home_dir.join("config.toml");
        {
            let mut config_file = File::create(&config_file_path).unwrap();
            writeln!(
                config_file,
                "dns_servers = \"1.2.3.4\"\nconsuming-private-key = \"{}\"",
                consuming_private_key
            )
            .unwrap();
        }
        let args: Vec<String> = vec![
            "SubstratumNode",
            "--data-directory",
            home_dir.to_str().unwrap(),
        ]
        .into_iter()
        .map(String::from)
        .collect();

        let mut bootstrapper_config = BootstrapperConfig::new();
        let multi_config = MultiConfig::new(
            &app(),
            vec![
                Box::new(CommandLineVCL::new(args.clone())),
                Box::new(ConfigFileVCL::new(&config_file_path, false)),
            ],
        );

        standard::privileged_parse_args(
            &multi_config,
            &mut bootstrapper_config,
            &mut FakeStreamHolder::new().streams(),
        );
        standard::unprivileged_parse_args(
            &multi_config,
            &mut bootstrapper_config,
            &mut FakeStreamHolder::new().streams(),
            &persistent_config,
        );

        assert_eq!(
            bootstrapper_config.dns_servers,
            vec![SocketAddr::new(IpAddr::from_str("1.2.3.4").unwrap(), 53)],
        );

        let consuming_private_key_bytes: Vec<u8> = consuming_private_key.from_hex().unwrap();
        let consuming_keypair =
            Bip32ECKeyPair::from_raw_secret(consuming_private_key_bytes.as_ref()).unwrap();
        assert_eq!(
            bootstrapper_config.consuming_wallet,
            Some(Wallet::from(consuming_keypair)),
        );

        let public_key = PublicKey::new(&[1, 2, 3]);
        let payer = bootstrapper_config
            .consuming_wallet
            .unwrap()
            .as_payer(&public_key);
        assert!(
            payer.owns_secret_key(&public_key),
            "Neighborhood config should have a WalletKind::KeyPair wallet"
        );
    }

    #[test]
    fn privileged_parse_args_creates_configurations() {
        let home_dir = ensure_node_home_directory_exists(
            "node_configurator",
            "privileged_parse_args_creates_configurations",
        );
        let args: Vec<String> = vec![
            "SubstratumNode",
            "--config-file",
            "specified_config.toml",
            "--dns-servers",
            "12.34.56.78,23.45.67.89",
            "--neighbors",
            "QmlsbA:1.2.3.4:1234;2345,VGVk:2.3.4.5:3456;4567",
            "--ip",
            "34.56.78.90",
            "--clandestine-port",
            "1234",
            "--ui-port",
            "5335",
            "--data-directory",
            home_dir.to_str().unwrap(),
            "--blockchain-service-url",
            "http://127.0.0.1:8545",
            "--log-level",
            "trace",
            "--fake-public-key",
            "AQIDBA",
            "--wallet-password",
            "secret-wallet-password",
            "--earning-wallet",
            "0x0123456789012345678901234567890123456789",
            "--consuming-private-key",
            "ABCDEF01ABCDEF01ABCDEF01ABCDEF01ABCDEF01ABCDEF01ABCDEF01ABCDEF01",
        ]
        .into_iter()
        .map(String::from)
        .collect();

        let mut config = BootstrapperConfig::new();
        let vcls: Vec<Box<dyn VirtualCommandLine>> = vec![Box::new(CommandLineVCL::new(args))];
        let multi_config = MultiConfig::new(&app(), vcls);

        standard::privileged_parse_args(
            &multi_config,
            &mut config,
            &mut FakeStreamHolder::new().streams(),
        );

        assert_eq!(
            value_m!(multi_config, "config-file", PathBuf),
            Some(PathBuf::from("specified_config.toml")),
        );
        assert_eq!(
            config.dns_servers,
            vec!(
                SocketAddr::from_str("12.34.56.78:53").unwrap(),
                SocketAddr::from_str("23.45.67.89:53").unwrap()
            ),
        );
        assert_eq!(
            config.neighborhood_config.neighbor_configs,
            vec!(
                "QmlsbA:1.2.3.4:1234;2345".to_string(),
                "VGVk:2.3.4.5:3456;4567".to_string()
            ),
        );
        assert_eq!(
            config.neighborhood_config.local_ip_addr,
            IpAddr::V4(Ipv4Addr::new(34, 56, 78, 90)),
        );
        assert_eq!(config.ui_gateway_config.ui_port, 5335);
        let expected_port_list: Vec<u16> = vec![];
        assert_eq!(
            config.neighborhood_config.clandestine_port_list,
            expected_port_list,
        );
        assert_eq!(
            config.blockchain_bridge_config.blockchain_service_url,
            Some("http://127.0.0.1:8545".to_string()),
        );
        assert_eq!(config.data_directory, home_dir);
        assert_eq!(
            config.cryptde_null_opt.unwrap().public_key(),
            &PublicKey::new(&[1, 2, 3, 4]),
        );
    }

    #[test]
    fn unprivileged_parse_args_creates_configurations() {
        let home_dir = ensure_node_home_directory_exists(
            "node_configurator",
            "unprivileged_parse_args_creates_configurations",
        );
        let config_dao: Box<ConfigDao> = Box::new(ConfigDaoReal::new(
            DbInitializerReal::new()
                .initialize(&home_dir.clone())
                .unwrap(),
        ));
        let consuming_private_key_text =
            "ABCDEF01ABCDEF01ABCDEF01ABCDEF01ABCDEF01ABCDEF01ABCDEF01ABCDEF01";
        let consuming_private_key =
            PlainData::from(consuming_private_key_text.from_hex::<Vec<u8>>().unwrap());
        let persistent_config = PersistentConfigurationReal::new(config_dao);
        let password = "secret-wallet-password";
        let args: Vec<String> = vec![
            "SubstratumNode",
            "--config-file",
            "specified_config.toml",
            "--dns-servers",
            "12.34.56.78,23.45.67.89",
            "--neighbors",
            "QmlsbA:1.2.3.4:1234;2345,VGVk:2.3.4.5:3456;4567",
            "--ip",
            "34.56.78.90",
            "--clandestine-port",
            "1234",
            "--ui-port",
            "5335",
            "--data-directory",
            home_dir.to_str().unwrap(),
            "--blockchain-service-url",
            "http://127.0.0.1:8545",
            "--log-level",
            "trace",
            "--fake-public-key",
            "AQIDBA",
            "--wallet-password",
            password,
            "--earning-wallet",
            "0x0123456789012345678901234567890123456789",
            "--consuming-private-key",
            consuming_private_key_text,
        ]
        .into_iter()
        .map(String::from)
        .collect();

        let mut config = BootstrapperConfig::new();
        let vcls: Vec<Box<dyn VirtualCommandLine>> = vec![Box::new(CommandLineVCL::new(args))];
        let multi_config = MultiConfig::new(&app(), vcls);

        standard::unprivileged_parse_args(
            &multi_config,
            &mut config,
            &mut FakeStreamHolder::new().streams(),
            &persistent_config,
        );

        assert_eq!(
            value_m!(multi_config, "config-file", PathBuf),
            Some(PathBuf::from("specified_config.toml")),
        );
        assert_eq!(
            config.earning_wallet,
            Wallet::from_str("0x0123456789012345678901234567890123456789").unwrap()
        );
        assert_eq!(config.data_directory, home_dir);
        assert_eq!(Some(1234u16), config.clandestine_port_opt);
        assert_eq!(
            config.earning_wallet,
            Wallet::from_str("0x0123456789012345678901234567890123456789").unwrap()
        );
        assert_eq!(
            config.consuming_wallet,
            Some(Wallet::from(
                Bip32ECKeyPair::from_raw_secret(consuming_private_key.as_slice()).unwrap()
            )),
        );
    }

    #[test]
    fn privileged_parse_args_creates_configuration_with_defaults() {
        let args: Vec<String> = vec!["SubstratumNode", "--dns-servers", "12.34.56.78,23.45.67.89"]
            .into_iter()
            .map(String::from)
            .collect();

        let mut config = BootstrapperConfig::new();
        let vcls: Vec<Box<dyn VirtualCommandLine>> = vec![Box::new(CommandLineVCL::new(args))];
        let multi_config = MultiConfig::new(&app(), vcls);

        standard::privileged_parse_args(
            &multi_config,
            &mut config,
            &mut FakeStreamHolder::new().streams(),
        );

        assert_eq!(
            Some(PathBuf::from("config.toml")),
            value_m!(multi_config, "config-file", PathBuf)
        );
        assert_eq!(
            config.dns_servers,
            vec!(
                SocketAddr::from_str("12.34.56.78:53").unwrap(),
                SocketAddr::from_str("23.45.67.89:53").unwrap()
            )
        );
        assert_eq!(CrashPoint::None, config.crash_point);
        assert!(config.data_directory.is_dir());
        assert_eq!(sentinel_ip_addr(), config.neighborhood_config.local_ip_addr,);
        assert_eq!(5333, config.ui_gateway_config.ui_port);
        assert!(config.cryptde_null_opt.is_none());
    }

    #[test]
    fn unprivileged_parse_args_creates_configuration_with_defaults() {
        let args: Vec<String> = vec!["SubstratumNode", "--dns-servers", "12.34.56.78,23.45.67.89"]
            .into_iter()
            .map(String::from)
            .collect();

        let mut config = BootstrapperConfig::new();
        let vcls: Vec<Box<dyn VirtualCommandLine>> = vec![Box::new(CommandLineVCL::new(args))];
        let multi_config = MultiConfig::new(&app(), vcls);

        standard::unprivileged_parse_args(
            &multi_config,
            &mut config,
            &mut FakeStreamHolder::new().streams(),
            &make_default_persistent_configuration(),
        );

        assert_eq!(
            Some(PathBuf::from("config.toml")),
            value_m!(multi_config, "config-file", PathBuf)
        );
        assert_eq!(None, config.clandestine_port_opt);
        assert!(config.data_directory.is_dir());
        assert_eq!(config.earning_wallet, DEFAULT_EARNING_WALLET.clone(),);
        assert_eq!(config.consuming_wallet, None,);
    }

    fn make_multi_config(parms: Vec<&str>) -> MultiConfig {
        let mut arg_strs = vec!["SubstratumNode", "--dns-servers", "12.34.56.78,23.45.67.89"];
        arg_strs.extend(parms);
        let args: Vec<String> = arg_strs.into_iter().map(String::from).collect();
        let vcls: Vec<Box<dyn VirtualCommandLine>> = vec![Box::new(CommandLineVCL::new(args))];
        MultiConfig::new(&app(), vcls)
    }

    fn make_persistent_config(
        mnemonic_seed_prefix_and_password_opt: Option<(&str, &str)>,
        consuming_wallet_private_public_key_opt: Option<&str>,
        consuming_wallet_derivation_path_opt: Option<&str>,
        earning_wallet_address_opt: Option<&str>,
        earning_wallet_derivation_path_opt: Option<&str>,
    ) -> PersistentConfigurationMock {
        let (mnemonic_seed_result, encrypted_mnemonic_seed_opt) =
            match mnemonic_seed_prefix_and_password_opt {
                None => (Err(Bip39Error::NotPresent), None),
                Some((mnemonic_seed_prefix, wallet_password)) => {
                    let mnemonic_seed = make_mnemonic_seed(mnemonic_seed_prefix);
                    let encrypted_mnemonic_seed =
                        Bip39::encrypt_bytes(&mnemonic_seed, wallet_password).unwrap();
                    (Ok(mnemonic_seed), Some(encrypted_mnemonic_seed))
                }
            };
        let consuming_wallet_private_public_key_opt =
            consuming_wallet_private_public_key_opt.map(|x| make_wallet(x).to_string());
        let consuming_wallet_derivation_path_opt =
            consuming_wallet_derivation_path_opt.map(|x| x.to_string());
        let earning_wallet_from_address_opt = match earning_wallet_address_opt {
            None => None,
            Some(address) => Some(Wallet::from_str(address).unwrap()),
        };
        let earning_wallet_from_derivation_path_opt = match earning_wallet_derivation_path_opt {
            None => None,
            Some(derivation_path) => match mnemonic_seed_result.clone() {
                Err(_) => Some(make_wallet(derivation_path)), // throwaway; the test calling this will panic
                Ok(mnemonic_seed) => Some(Wallet::from(
                    Bip32ECKeyPair::from_raw(mnemonic_seed.as_ref(), derivation_path).unwrap(),
                )),
            },
        };
        PersistentConfigurationMock::new()
            .mnemonic_seed_result(mnemonic_seed_result)
            .encrypted_mnemonic_seed_result(encrypted_mnemonic_seed_opt)
            .consuming_wallet_private_public_key_result(consuming_wallet_private_public_key_opt)
            .consuming_wallet_derivation_path_result(consuming_wallet_derivation_path_opt)
            .earning_wallet_from_address_result(earning_wallet_from_address_opt)
            .earning_wallet_from_derivation_path_result(earning_wallet_from_derivation_path_opt)
    }

    fn make_mnemonic_seed(prefix: &str) -> PlainData {
        let mut bytes: Vec<u8> = vec![];
        while bytes.len() < 64 {
            bytes.extend(prefix.as_bytes())
        }
        bytes.truncate(64);
        let result = PlainData::from(bytes);
        result
    }

    #[test]
    fn get_wallets_with_brand_new_database_establishes_default_earning_wallet_without_requiring_password(
    ) {
        let multi_config = make_multi_config(vec![]);
        let persistent_config = make_persistent_config(None, None, None, None, None);
        let mut config = BootstrapperConfig::new();

        standard::get_wallets(
            &mut FakeStreamHolder::new().streams(),
            &multi_config,
            &persistent_config,
            &mut config,
        );

        assert_eq!(config.consuming_wallet, None);
        assert_eq!(config.earning_wallet, DEFAULT_EARNING_WALLET.clone());
    }

    #[test]
    #[should_panic(
        expected = "Cannot use --consuming-private-key when database contains mnemonic seed and consuming wallet derivation path"
    )]
    fn consuming_wallet_private_key_plus_consuming_wallet_derivation_path() {
        let consuming_private_key_hex =
            "ABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCD";
        let multi_config = make_multi_config(vec![
            "--wallet-password",
            "password",
            "--consuming-private-key",
            consuming_private_key_hex,
        ]);
        let mnemonic_seed_prefix = "mnemonic_seed";
        let persistent_config = make_persistent_config(
            Some((mnemonic_seed_prefix, "password")),
            None,
            Some("m/44'/60'/1'/2/3"),
            None,
            None,
        );
        let mut config = BootstrapperConfig::new();

        standard::get_wallets(
            &mut FakeStreamHolder::new().streams(),
            &multi_config,
            &persistent_config,
            &mut config,
        );
    }

    #[test]
    #[should_panic(
        expected = "Database is corrupt: contains both address and derivation path for earning wallet"
    )]
    fn earning_wallet_address_specified_when_earning_wallet_path_exists() {
        let multi_config = make_multi_config(vec![
            "--earning-wallet",
            "0x0123456789012345678901234567890123456789",
            "--wallet-password",
            "password",
        ]);
        let persistent_config = make_persistent_config(
            Some(("seed", "password")),
            None,
            None,
            None,
            Some("m/44'/60'/3'/2/1"),
        );
        let mut config = BootstrapperConfig::new();

        standard::get_wallets(
            &mut FakeStreamHolder::new().streams(),
            &multi_config,
            &persistent_config,
            &mut config,
        );
        assert!(false);
    }

    #[test]
    #[should_panic(
        expected = "Cannot use --earning-wallet to specify an address (0x0123456789012345678901234567890123456789) different from that previously set (0x9876543210987654321098765432109876543210)"
    )]
    fn earning_wallet_different_from_database() {
        let multi_config = make_multi_config(vec![
            "--earning-wallet",
            "0x0123456789012345678901234567890123456789",
        ]);
        let persistent_config = make_persistent_config(
            None,
            None,
            None,
            Some("0x9876543210987654321098765432109876543210"),
            None,
        );
        let mut config = BootstrapperConfig::new();

        standard::get_wallets(
            &mut FakeStreamHolder::new().streams(),
            &multi_config,
            &persistent_config,
            &mut config,
        );
    }

    #[test]
    #[should_panic(
        expected = "Database is corrupt: contains both address and derivation path for earning wallet"
    )]
    fn earning_wallet_address_plus_earning_wallet_derivation_path() {
        let multi_config = make_multi_config(vec!["--wallet-password", "password"]);
        let mnemonic_seed_prefix = "mnemonic_seed";
        let persistent_config = make_persistent_config(
            Some((mnemonic_seed_prefix, "password")),
            None,
            None,
            Some("0xcafedeadbeefbabefacecafedeadbeefbabeface"),
            Some("m/44'/60'/3'/2/1"),
        );
        let mut config = BootstrapperConfig::new();

        standard::get_wallets(
            &mut FakeStreamHolder::new().streams(),
            &multi_config,
            &persistent_config,
            &mut config,
        );
    }

    #[test]
    #[should_panic(
        expected = "Database is corrupt: consuming wallet derivation path is present, but no mnemonic seed"
    )]
    fn consuming_wallet_derivation_path_without_mnemonic_seed() {
        let multi_config = make_multi_config(vec!["--wallet-password", "password"]);
        let persistent_config =
            make_persistent_config(None, None, Some("m/44'/60'/1'/2/3"), None, None);
        let mut config = BootstrapperConfig::new();

        standard::get_wallets(
            &mut FakeStreamHolder::new().streams(),
            &multi_config,
            &persistent_config,
            &mut config,
        );
    }

    #[test]
    #[should_panic(
        expected = "Cannot use --consuming-private-key and earning wallet address when database contains mnemonic seed"
    )]
    fn consuming_wallet_private_key_plus_earning_wallet_address_plus_mnemonic_seed() {
        let consuming_private_key_hex =
            "ABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCD";
        let multi_config = make_multi_config(vec![
            "--wallet-password",
            "password",
            "--consuming-private-key",
            consuming_private_key_hex,
        ]);
        let mnemonic_seed_prefix = "mnemonic_seed";
        let persistent_config = make_persistent_config(
            Some((mnemonic_seed_prefix, "password")),
            None,
            None,
            Some("0xcafedeadbeefbabefacecafedeadbeefbabeface"),
            None,
        );
        let mut config = BootstrapperConfig::new();

        standard::get_wallets(
            &mut FakeStreamHolder::new().streams(),
            &multi_config,
            &persistent_config,
            &mut config,
        );
    }

    #[test]
    fn consuming_wallet_private_key_plus_earning_wallet_derivation_path_plus_mnemonic_seed() {
        let consuming_private_key_hex =
            "ABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCD";
        let multi_config = make_multi_config(vec![
            "--wallet-password",
            "password",
            "--consuming-private-key",
            consuming_private_key_hex,
        ]);
        let mnemonic_seed_prefix = "mnemonic_seed";
        let persistent_config = make_persistent_config(
            Some((mnemonic_seed_prefix, "password")),
            None,
            None,
            None,
            Some("m/44'/60'/3'/2/1"),
        );
        let mut config = BootstrapperConfig::new();

        standard::get_wallets(
            &mut FakeStreamHolder::new().streams(),
            &multi_config,
            &persistent_config,
            &mut config,
        );

        let mnemonic_seed = make_mnemonic_seed(mnemonic_seed_prefix);
        let expected_consuming_wallet = Wallet::from(
            Bip32ECKeyPair::from_raw_secret(
                &consuming_private_key_hex.from_hex::<Vec<u8>>().unwrap(),
            )
            .unwrap(),
        );
        let expected_earning_wallet = Wallet::from(
            Bip32ECKeyPair::from_raw(mnemonic_seed.as_ref(), "m/44'/60'/3'/2/1").unwrap(),
        );
        assert_eq!(config.consuming_wallet, Some(expected_consuming_wallet));
        assert_eq!(config.earning_wallet, expected_earning_wallet);
    }

    // TODO consuming_private_key_matches_database: SC-930

    // TODO consuming_private_key_doesnt_match_database: SC-930

    #[test]
    fn consuming_wallet_derivation_path_plus_earning_wallet_address_plus_mnemonic_seed() {
        let multi_config = make_multi_config(vec!["--wallet-password", "password"]);
        let mnemonic_seed_prefix = "mnemonic_seed";
        let persistent_config = make_persistent_config(
            Some((mnemonic_seed_prefix, "password")),
            None,
            Some("m/44'/60'/1'/2/3"),
            Some("0xcafedeadbeefbabefacecafedeadbeefbabeface"),
            None,
        );
        let mut config = BootstrapperConfig::new();

        standard::get_wallets(
            &mut FakeStreamHolder::new().streams(),
            &multi_config,
            &persistent_config,
            &mut config,
        );

        let mnemonic_seed = make_mnemonic_seed(mnemonic_seed_prefix);
        let expected_consuming_wallet = Wallet::from(
            Bip32ECKeyPair::from_raw(mnemonic_seed.as_ref(), "m/44'/60'/1'/2/3").unwrap(),
        );
        assert_eq!(config.consuming_wallet, Some(expected_consuming_wallet));
        assert_eq!(
            config.earning_wallet,
            Wallet::from_str("0xcafedeadbeefbabefacecafedeadbeefbabeface").unwrap()
        );
    }

    #[test]
    fn consuming_wallet_derivation_path_plus_earning_wallet_derivation_path_plus_mnemonic_seed() {
        let multi_config = make_multi_config(vec!["--wallet-password", "password"]);
        let mnemonic_seed_prefix = "mnemonic_seed";
        let persistent_config = make_persistent_config(
            Some((mnemonic_seed_prefix, "password")),
            None,
            Some("m/44'/60'/1'/2/3"),
            None,
            Some("m/44'/60'/3'/2/1"),
        );
        let mut config = BootstrapperConfig::new();

        standard::get_wallets(
            &mut FakeStreamHolder::new().streams(),
            &multi_config,
            &persistent_config,
            &mut config,
        );

        let mnemonic_seed = make_mnemonic_seed(mnemonic_seed_prefix);
        let expected_consuming_wallet = Wallet::from(
            Bip32ECKeyPair::from_raw(mnemonic_seed.as_ref(), "m/44'/60'/1'/2/3").unwrap(),
        );
        let expected_earning_wallet = Wallet::from(
            Bip32ECKeyPair::from_raw(mnemonic_seed.as_ref(), "m/44'/60'/3'/2/1").unwrap(),
        );
        assert_eq!(config.consuming_wallet, Some(expected_consuming_wallet));
        assert_eq!(config.earning_wallet, expected_earning_wallet);
    }

    #[test]
    #[should_panic(
        expected = "error: Invalid value for '--consuming-private-key <PRIVATE-KEY>': not valid hex"
    )]
    fn unprivileged_parse_args_with_invalid_consuming_wallet_private_key_panics_correctly() {
        let home_directory = ensure_node_home_directory_exists(
            "node_configurator",
            "parse_args_with_invalid_consuming_wallet_private_key_panics_correctly",
        );

        let args: Vec<String> = vec![
            "SubstratumNode",
            "--dns-servers",
            "12.34.56.78,23.45.67.89",
            "--data-directory",
            home_directory.to_str().unwrap(),
        ]
        .into_iter()
        .map(String::from)
        .collect();

        let vcl_args: Vec<Box<dyn VclArg>> = vec![Box::new(NameValueVclArg::new(
            &"--consuming_private_key", // this is equal to SUB_CONSUMING_PRIVATE_KEY
            &"not valid hex",
        ))];

        let faux_environment = FauxEnvironmentVCL { vcl_args };

        let mut config = BootstrapperConfig::new();
        let vcls: Vec<Box<dyn VirtualCommandLine>> = vec![
            Box::new(faux_environment),
            Box::new(CommandLineVCL::new(args)),
        ];
        let multi_config = MultiConfig::new(&app(), vcls);

        standard::unprivileged_parse_args(
            &multi_config,
            &mut config,
            &mut FakeStreamHolder::new().streams(),
            &PersistentConfigurationMock::new(),
        );
    }

    #[test]
    fn unprivileged_parse_args_consuming_private_key_happy_path() {
        let home_directory = ensure_node_home_directory_exists(
            "node_configurator",
            "parse_args_consuming_private_key_happy_path",
        );

        let args: Vec<String> = vec![
            "SubstratumNode",
            "--dns-servers",
            "12.34.56.78,23.45.67.89",
            "--data-directory",
            home_directory.to_str().unwrap(),
            "--wallet-password",
        ]
        .into_iter()
        .map(String::from)
        .collect();

        let vcl_args: Vec<Box<dyn VclArg>> = vec![Box::new(NameValueVclArg::new(
            &"--consuming_private_key", // this is equal to SUB_CONSUMING_PRIVATE_KEY
            &"cc46befe8d169b89db447bd725fc2368b12542113555302598430cb5d5c74ea9",
        ))];

        let faux_environment = FauxEnvironmentVCL { vcl_args };

        let mut config = BootstrapperConfig::new();
        let vcls: Vec<Box<dyn VirtualCommandLine>> = vec![
            Box::new(faux_environment),
            Box::new(CommandLineVCL::new(args)),
        ];
        let multi_config = MultiConfig::new(&app(), vcls);
        let stdout_writer = &mut ByteArrayWriter::new();
        let mut streams = &mut StdStreams {
            stdin: &mut Cursor::new(&b""[..]),
            stdout: stdout_writer,
            stderr: &mut ByteArrayWriter::new(),
        };

        standard::unprivileged_parse_args(
            &multi_config,
            &mut config,
            &mut streams,
            &make_default_persistent_configuration(),
        );

        let captured_output = stdout_writer.get_string();
        let expected_output = "";
        assert!(config.consuming_wallet.is_some());
        assert_eq!(
            format!("{}", config.consuming_wallet.unwrap()),
            "0x8e4d2317e56c8fd1fc9f13ba2aa62df1c5a542a7".to_string()
        );
        assert_eq!(captured_output, expected_output);
    }

    #[test]
    #[should_panic(
        expected = "Could not verify password: ConversionError(\"Invalid character \\'o\\' at position 1\")"
    )]
    fn invalid_mnemonic_seed_causes_conversion_error_and_panics() {
        let data_directory = ensure_node_home_directory_exists(
            "node_configurator",
            "invalid_mnemonic_seed_causes_conversion_error_and_panics",
        );

        let conn = db_initializer::DbInitializerReal::new()
            .initialize(&data_directory)
            .unwrap();
        let config_dao: Box<ConfigDao> = Box::new(ConfigDaoReal::new(conn));
        config_dao.set_string("seed", "booga booga").unwrap();
        let mut args = make_default_cli_params();
        args.extend(
            vec![
                "--data-directory",
                data_directory.to_str().unwrap(),
                "--wallet-password",
                "rick-rolled",
            ]
            .into_iter()
            .map(String::from)
            .collect::<Vec<String>>(),
        );
        let mut config = BootstrapperConfig::new();
        let vcl = Box::new(CommandLineVCL::new(args));
        let multi_config = MultiConfig::new(&app(), vec![vcl]);

        standard::unprivileged_parse_args(
            &multi_config,
            &mut config,
            &mut FakeStreamHolder::new().streams(),
            &PersistentConfigurationReal::from(config_dao),
        );
    }

    #[test]
    #[should_panic(
        expected = "Could not verify password: DeserializationFailure(\"trailing data at offset 324\")"
    )]
    fn mnemonic_seed_deserialization_failure_aborts_as_expected() {
        let data_directory = ensure_node_home_directory_exists(
            "node_configurator",
            "mnemonic_seed_deserialization_failure_aborts_as_expected",
        );

        let conn = db_initializer::DbInitializerReal::new()
            .initialize(&data_directory)
            .unwrap();
        let config_dao: Box<ConfigDao> = Box::new(ConfigDaoReal::new(conn));

        let crypto = Crypto::encrypt(
            b"never gonna give you up",
            &Protected::new("ricked rolled"),
            NonZeroU32::new(1024).unwrap(),
        )
        .unwrap();
        let mut crypto_seed = serde_cbor::to_vec(&crypto).unwrap();
        crypto_seed.extend_from_slice(&b"choke on these extra bytes"[..]);
        let mnemonic_seed_with_extras = crypto_seed.to_hex::<String>();

        config_dao
            .set_string("seed", &mnemonic_seed_with_extras)
            .unwrap();
        let mut args = make_default_cli_params();
        args.extend(
            vec![
                "--data-directory",
                data_directory.to_str().unwrap(),
                "--wallet-password",
                "ricked rolled",
            ]
            .into_iter()
            .map(String::from)
            .collect::<Vec<String>>(),
        );
        let mut config = BootstrapperConfig::new();
        let vcl = Box::new(CommandLineVCL::new(args));
        let multi_config = MultiConfig::new(&app(), vec![vcl]);

        standard::unprivileged_parse_args(
            &multi_config,
            &mut config,
            &mut FakeStreamHolder::new().streams(),
            &PersistentConfigurationReal::from(config_dao),
        );
    }

    #[test]
    fn no_parameters_produces_configuration_for_crash_point() {
        let args = make_default_cli_params();
        let mut config = BootstrapperConfig::new();
        let vcl = Box::new(CommandLineVCL::new(args));
        let multi_config = MultiConfig::new(&app(), vec![vcl]);

        standard::privileged_parse_args(
            &multi_config,
            &mut config,
            &mut FakeStreamHolder::new().streams(),
        );

        assert_eq!(config.crash_point, CrashPoint::None);
    }

    #[test]
    fn with_parameters_produces_configuration_for_crash_point() {
        let mut args = make_default_cli_params();
        let crash_args = vec![String::from("--crash-point"), String::from("panic")];
        args.extend(crash_args);
        let mut config = BootstrapperConfig::new();
        let vcl = Box::new(CommandLineVCL::new(args));
        let multi_config = MultiConfig::new(&app(), vec![vcl]);

        standard::privileged_parse_args(
            &multi_config,
            &mut config,
            &mut FakeStreamHolder::new().streams(),
        );

        assert_eq!(config.crash_point, CrashPoint::Panic);
    }

    #[test]
    #[should_panic(expected = "could not be read: ")]
    fn privileged_generate_configuration_senses_when_user_specifies_config_file() {
        let subject = NodeConfiguratorStandardPrivileged {};
        let args = vec![
            "SubstratumNode",
            "--dns-servers",
            "1.2.3.4",
            "--config-file",
            "booga.toml", // nonexistent config file: should stimulate panic because user-specified
        ]
        .into_iter()
        .map(String::from)
        .collect::<Vec<String>>();

        subject.configure(&args, &mut FakeStreamHolder::new().streams());
    }

    #[test]
    #[should_panic(expected = "could not be read: ")]
    fn unprivileged_generate_configuration_senses_when_user_specifies_config_file() {
        let subject = NodeConfiguratorStandardUnprivileged {};
        let args = vec![
            "SubstratumNode",
            "--dns-servers",
            "1.2.3.4",
            "--config-file",
            "booga.toml", // nonexistent config file: should stimulate panic because user-specified
        ]
        .into_iter()
        .map(String::from)
        .collect::<Vec<String>>();

        subject.configure(&args, &mut FakeStreamHolder::new().streams());
    }

    #[test]
    fn configure_database_with_data_specified() {
        let mut config = BootstrapperConfig::new();
        config.clandestine_port_opt = Some(1234);
        let secret_key_text = "ABCD00EFABCD00EFABCD00EFABCD00EFABCD00EFABCD00EFABCD00EFABCD00EF";
        let secret_key = PlainData::from(secret_key_text.from_hex::<Vec<u8>>().unwrap());
        let keypair = Bip32ECKeyPair::from_raw_secret(secret_key.as_slice()).unwrap();
        let public_key = keypair.secret().public();
        config.consuming_wallet = Some(Wallet::from(keypair));
        let set_clandestine_port_params_arc = Arc::new(Mutex::new(vec![]));
        let set_consuming_private_public_key_params_arc = Arc::new(Mutex::new(vec![]));
        let persistent_config = PersistentConfigurationMock::new()
            .set_clandestine_port_params(&set_clandestine_port_params_arc)
            .set_consuming_wallet_private_public_key_params(
                &set_consuming_private_public_key_params_arc,
            );

        standard::configure_database(&config, &persistent_config);

        let set_clandestine_port_params = set_clandestine_port_params_arc.lock().unwrap();
        assert_eq!(*set_clandestine_port_params, vec![1234]);
        let set_consuming_private_public_key_params =
            set_consuming_private_public_key_params_arc.lock().unwrap();
        assert_eq!(
            *set_consuming_private_public_key_params,
            vec![PlainData::new(public_key.bytes())]
        );
    }

    #[test]
    fn configure_database_with_non_keypair_wallet() {
        let mut config = BootstrapperConfig::new();
        config.clandestine_port_opt = Some(1234);
        config.consuming_wallet =
            Some(Wallet::from_str("0x0123456789ABCDEF0123456789ABCDEF01234567").unwrap());
        let set_clandestine_port_params_arc = Arc::new(Mutex::new(vec![]));
        let set_consuming_private_public_key_params_arc = Arc::new(Mutex::new(vec![]));
        let persistent_config = PersistentConfigurationMock::new()
            .set_clandestine_port_params(&set_clandestine_port_params_arc)
            .set_consuming_wallet_private_public_key_params(
                &set_consuming_private_public_key_params_arc,
            );

        standard::configure_database(&config, &persistent_config);

        let set_clandestine_port_params = set_clandestine_port_params_arc.lock().unwrap();
        assert_eq!(*set_clandestine_port_params, vec![1234]);
        let set_consuming_private_public_key_params =
            set_consuming_private_public_key_params_arc.lock().unwrap();
        let no_keys: Vec<PlainData> = vec![];
        assert_eq!(*set_consuming_private_public_key_params, no_keys);
    }

    #[test]
    fn configure_database_with_data_unspecified() {
        let mut config = BootstrapperConfig::new();
        config.clandestine_port_opt = None;
        config.consuming_wallet = None;
        let set_clandestine_port_params_arc = Arc::new(Mutex::new(vec![]));
        let set_consuming_private_public_key_params_arc = Arc::new(Mutex::new(vec![]));
        let persistent_config = PersistentConfigurationMock::new()
            .set_clandestine_port_params(&set_clandestine_port_params_arc)
            .set_consuming_wallet_private_public_key_params(
                &set_consuming_private_public_key_params_arc,
            );

        standard::configure_database(&config, &persistent_config);

        let set_clandestine_port_params = set_clandestine_port_params_arc.lock().unwrap();
        let no_ports: Vec<u16> = vec![];
        assert_eq!(*set_clandestine_port_params, no_ports);
        let set_consuming_private_public_key_params =
            set_consuming_private_public_key_params_arc.lock().unwrap();
        let no_keys: Vec<PlainData> = vec![];
        assert_eq!(*set_consuming_private_public_key_params, no_keys);
    }
}
