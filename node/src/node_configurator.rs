// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

use std::io::Read;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;

use bip39::{Language, Mnemonic, MnemonicType};
use clap::{
    crate_authors, crate_description, crate_version, value_t, values_t, App, AppSettings, Arg,
};
use dirs::data_dir;
use log::LevelFilter;
use regex::Regex;
use rpassword;
use rpassword::read_password_with_reader;
use rustc_hex::ToHex;

use indoc::indoc;
use lazy_static::lazy_static;

use crate::blockchain::bip39::Bip39;
use crate::bootstrapper::{BootstrapperConfig, PortConfiguration};
use crate::config_dao::ConfigDaoReal;
use crate::database::db_initializer::{DbInitializer, DbInitializerReal};
use crate::http_request_start_finder::HttpRequestDiscriminatorFactory;
use crate::multi_config::{
    merge, CommandLineVCL, ConfigFileVCL, EnvironmentVCL, MultiConfig, VclArg,
};
use crate::persistent_configuration::{PersistentConfigurationReal, HTTP_PORT, TLS_PORT};
use crate::sub_lib::accountant::DEFAULT_EARNING_WALLET;
use crate::sub_lib::accountant::TEMPORARY_CONSUMING_WALLET;
use crate::sub_lib::crash_point::CrashPoint;
use crate::sub_lib::cryptde::{CryptDE, PublicKey};
use crate::sub_lib::cryptde_null::CryptDENull;
use crate::sub_lib::main_tools::StdStreams;
use crate::sub_lib::neighborhood::sentinel_ip_addr;
use crate::sub_lib::ui_gateway::DEFAULT_UI_PORT;
use crate::sub_lib::wallet::Wallet;
use crate::tls_discriminator_factory::TlsDiscriminatorFactory;

pub const LOWEST_USABLE_INSECURE_PORT: u16 = 1025;
pub const HIGHEST_USABLE_PORT: u16 = 65535;

pub trait NodeConfigurator {
    fn generate_configuration(
        &self,
        args: &Vec<String>,
        streams: &mut StdStreams<'_>,
    ) -> BootstrapperConfig;
}

pub struct NodeConfiguratorReal {
    app: App<'static, 'static>,
}

impl NodeConfigurator for NodeConfiguratorReal {
    fn generate_configuration(
        &self,
        args: &Vec<String>,
        streams: &mut StdStreams<'_>,
    ) -> BootstrapperConfig {
        let mut bootstrapper_config = BootstrapperConfig::new();
        self.establish_port_configurations(&mut bootstrapper_config);
        let (config_file_path, user_specified) = self.determine_config_file_path(args);
        let multi_config = MultiConfig::new(
            &self.app,
            vec![
                Box::new(CommandLineVCL::new(args.clone())),
                Box::new(EnvironmentVCL::new(&self.app)),
                Box::new(ConfigFileVCL::new(&config_file_path, user_specified)),
            ],
        );
        self.parse_args(&multi_config, &mut bootstrapper_config, streams);
        bootstrapper_config
    }
}

lazy_static! {
    static ref DEFAULT_UI_PORT_VALUE: String = DEFAULT_UI_PORT.to_string();
    static ref DEFAULT_EARNING_WALLET_VALUE: String =
        String::from(DEFAULT_EARNING_WALLET.clone().address);
    static ref DEFAULT_CRASH_POINT_VALUE: String = format!("{}", CrashPoint::None);
    static ref DEFAULT_IP_VALUE: String = sentinel_ip_addr().to_string();
    static ref DEFAULT_DATA_DIR_VALUE: String =
        NodeConfiguratorReal::data_directory_default(&RealDirsWrapper {});
    static ref UI_PORT_HELP: String = format!(
        "Must be between {} and {}",
        LOWEST_USABLE_INSECURE_PORT, HIGHEST_USABLE_PORT
    );
    static ref CLANDESTINE_PORT_HELP: String = format!(
        "Must be between {} and {} [default: last used port]",
        LOWEST_USABLE_INSECURE_PORT, HIGHEST_USABLE_PORT
    );
}

const LANGUAGE_HELP: &str = "The language of the mnemonic phrase.";
const BLOCKCHAIN_SERVICE_HELP: &str =
    "The Ethereum client you wish to use to provide Blockchain \
     exit services from your SubstratumNode (e.g. http://localhost:8545, \
     https://ropsten.infura.io/v3/YOUR-PROJECT-ID, https://mainnet.infura.io/v3/YOUR-PROJECT-ID).";
const DNS_SERVERS_HELP: &str =
    "IP addresses of DNS Servers for host name look-up while providing exit \
     services for other SubstratumNodes (e.g. 1.0.0.1, 1.1.1.1, 8.8.8.8, 9.9.9.9, etc.)";
const GENERATE_WALLET_HELP: &str =
    "Generate a new HD wallet with mnemonic recovery phrase from the standard \
     BIP39 predefined list of words. Not valid as a configuration file item nor an \
     environment variable";
const IP_ADDRESS_HELP: &str = "The public IP address of your SubstratumNode: that is, the IPv4 \
                               address at which other SubstratumNodes can contact yours.";
const MNEMONIC_HELP: &str =
    "An HD wallet mnemonic recovery phrase using predefined BIP39 word lists. Not valid as a \
     configuration file item nor an environment variable.";
const MNEMONIC_PASSPHRASE_HELP: &str =
    "A passphrase for the mnemonic phrase. Cannot be changed later and still produce \
     the same addresses. Not valid as a configuration file item nor an environment variable.";
const WALLET_PASSWORD: &str =
    "A password or phrase to encrypt your wallet or decrypt a keystore file. Can be changed \
     later and still produce the same addresses.";
const WALLET_ADDRESS_HELP: &str =
    "Must begin with 0x followed by 40 hexadecimal digits (case-insensitive)";
const WORD_COUNT_HELP: &str =
    "The number of words in the mnemonic phrase. Ropsten defaults to 12 words. \
     Mainnet defaults to 24 words.";
const CONSUMING_PRIVATE_KEY_HELP: &str = "Must be 64 hexadecimal digits (case-insensitive)";

// These Args are needed both for the preliminary pass to find the config file and for the main
// pass to configure everything. To avoid code duplication, they're defined here and referred
// to from both places.
fn data_directory_arg<'a>() -> Arg<'a, 'a> {
    Arg::with_name("data_directory")
        .long("data-directory")
        .aliases(&["data-directory", "data_directory"])
        .value_name("DATA-DIRECTORY")
        .required(false)
        .takes_value(true)
        .empty_values(false)
        .default_value(&DEFAULT_DATA_DIR_VALUE)
}

fn config_file_arg<'a>() -> Arg<'a, 'a> {
    Arg::with_name("config_file")
        .long("config-file")
        .aliases(&["config-file", "config_file"])
        .value_name("FILE-PATH")
        .default_value("config.toml")
        .takes_value(true)
        .required(false)
}

const HELP_TEXT: &str = indoc!(r"ADDITIONAL HELP:
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
                               3. Create the port forwarding entries in the router.");

impl NodeConfiguratorReal {
    pub fn new() -> NodeConfiguratorReal {
        NodeConfiguratorReal {
            app: App::new("SubstratumNode")
                .global_settings(if cfg!(test) {
                    &[AppSettings::ColorNever]
                } else {
                    &[AppSettings::ColorAuto, AppSettings::ColoredHelp]
                })
                .version(crate_version!())
                .author(crate_authors!("\n"))
                .about(crate_description!())
                .after_help(HELP_TEXT)
                .arg(config_file_arg())
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
                    Arg::with_name("clandestine_port")
                        .long("clandestine-port")
                        .aliases(&["clandestine-port", "clandestine_port"])
                        .value_name("CLANDESTINE-PORT")
                        .empty_values(false)
                        .validator(Validators::validate_clandestine_port)
                        .help(&CLANDESTINE_PORT_HELP),
                )
                .arg(data_directory_arg())
                .arg(
                    Arg::with_name("dns_servers")
                        .long("dns-servers")
                        .aliases(&["dns-servers", "dns_servers"])
                        .value_name("DNS-SERVERS")
                        .takes_value(true)
                        .required_unless_one(&["generate-wallet", "mnemonic", "help", "version"])
                        .use_delimiter(true)
                        .validator(Validators::validate_ip_address)
                        .help(DNS_SERVERS_HELP),
                )
                .arg(
                    Arg::with_name("generate-wallet")
                        .long("generate-wallet")
                        .aliases(&["generate-wallet", "generate_wallet"])
                        .value_name("GENERATE-WALLET")
                        .required(false)
                        .takes_value(true)
                        .min_values(0)
                        .max_values(1)
                        .conflicts_with_all(&[
                            "dns_servers",
                            "neighbors",
                            "wallet_address",
                            "mnemonic",
                        ])
                        .requires_all(&["language", "word-count"])
                        .help(GENERATE_WALLET_HELP),
                )
                .arg(
                    Arg::with_name("ip")
                        .long("ip")
                        .value_name("IP")
                        .takes_value(true)
                        .default_value(&DEFAULT_IP_VALUE)
                        .validator(Validators::validate_ip_address)
                        .help(IP_ADDRESS_HELP),
                )
                .arg(
                    Arg::with_name("language")
                        .alias("language")
                        .long("language")
                        .value_name("LANGUAGE")
                        .required(false)
                        .case_insensitive(true)
                        .possible_values(&Bip39::possible_language_values().as_slice())
                        .default_value(Bip39::name_from_language(Language::default()))
                        .help(&LANGUAGE_HELP),
                )
                .arg(
                    Arg::with_name("log_level")
                        .long("log-level")
                        .aliases(&["log-level", "log_level"])
                        .value_name("FILTER")
                        .takes_value(true)
                        .possible_values(&["error", "warn", "info", "debug", "trace", "off"])
                        .default_value("warn")
                        .case_insensitive(true),
                )
                .arg(
                    Arg::with_name("mnemonic")
                        .long("mnemonic")
                        .value_name("MNEMONIC-WORDS")
                        .required(false)
                        .empty_values(false)
                        .require_delimiter(true)
                        .value_delimiter(" ")
                        .min_values(12)
                        .max_values(24)
                        .validator(Validators::validate_mnemonic_word)
                        .help(MNEMONIC_HELP),
                )
                .arg(
                    Arg::with_name("mnemonic-passphrase")
                        .long("mnemonic-passphrase")
                        .aliases(&["mnemonic-passphrase", "mnemonic_passphrase"])
                        .value_name("MNEMONIC-PASSPHRASE")
                        .required(false)
                        .takes_value(true)
                        .min_values(0)
                        .max_values(1)
                        .conflicts_with_all(&["dns_servers", "neighbors"])
                        .help(MNEMONIC_PASSPHRASE_HELP),
                )
                .arg(
                    Arg::with_name("wallet-password")
                        .long("wallet-password")
                        .aliases(&["wallet-password", "wallet_password"])
                        .value_name("WALLET-PASSWORD")
                        .required(false)
                        .takes_value(true)
                        .min_values(0)
                        .max_values(1)
                        .help(WALLET_PASSWORD),
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
                    Arg::with_name("ui_port")
                        .long("ui-port")
                        .aliases(&["ui-port", "ui_port"])
                        .value_name("UI-PORT")
                        .takes_value(true)
                        .default_value(&DEFAULT_UI_PORT_VALUE)
                        .validator(Validators::validate_ui_port)
                        .help(&UI_PORT_HELP),
                )
                .arg(
                    Arg::with_name("wallet_address")
                        .long("wallet-address")
                        .aliases(&["wallet-address", "wallet_address"])
                        .value_name("WALLET-ADDRESS")
                        .required(false)
                        .takes_value(true)
                        .default_value(&DEFAULT_EARNING_WALLET_VALUE)
                        .validator(Validators::validate_ethereum_address)
                        .help(WALLET_ADDRESS_HELP),
                )
                .arg(
                    Arg::with_name("word-count")
                        .long("word-count")
                        .aliases(&["word-count", "word_count"])
                        .value_name("WORD-COUNT")
                        .possible_values(&["12", "15", "18", "21", "24"])
                        .default_value("12")
                        .hide_default_value(true)
                        .help(WORD_COUNT_HELP),
                )
                .arg(
                    Arg::with_name("consuming_private_key")
                        .long("consuming-private-key")
                        .aliases(&["consuming-private-key", "consuming_private_key"])
                        .value_name("PRIVATE-KEY")
                        .takes_value(true)
                        .validator(Validators::validate_private_key)
                        .help(CONSUMING_PRIVATE_KEY_HELP),
                )
                .arg(
                    Arg::with_name("crash_point")
                        .long("crash-point")
                        .aliases(&["crash-point", "crash_point"])
                        .value_name("CRASH-POINT")
                        .takes_value(true)
                        .default_value(&DEFAULT_CRASH_POINT_VALUE)
                        .possible_values(&CrashPoint::variants())
                        .case_insensitive(true)
                        .hidden(true)
                        .help("Only used for testing"),
                )
                .arg(
                    Arg::with_name("fake_public_key")
                        .long("fake-public-key")
                        .aliases(&["fake-public-key", "fake_public_key"])
                        .value_name("FAKE-PUBLIC-KEY")
                        .takes_value(true)
                        .help("Only used for testing"),
                ),
        }
    }

    fn establish_port_configurations(&self, config: &mut BootstrapperConfig) {
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

    fn determine_config_file_path(&self, args: &Vec<String>) -> (PathBuf, bool) {
        let orientation_schema = App::new("Preliminary")
            .arg(data_directory_arg())
            .arg(config_file_arg());
        let orientation_args: Vec<Box<VclArg>> = merge(
            Box::new(EnvironmentVCL::new(&self.app)),
            Box::new(CommandLineVCL::new(args.clone())),
        )
        .vcl_args()
        .into_iter()
        .filter(|vcl_arg| {
            (vcl_arg.name() == "--data_directory") || (vcl_arg.name() == "--config_file")
        })
        .map(|vcl_arg| vcl_arg.dup())
        .collect();
        let orientation_vcl = CommandLineVCL::from(orientation_args);

        let multi_config = MultiConfig::new(&orientation_schema, vec![Box::new(orientation_vcl)]);
        let config_file_path = value_m!(multi_config, "config_file", PathBuf)
            .expect("config-file should be defaulted");
        let user_specified = multi_config.arg_matches().occurrences_of("config_file") > 0;
        let data_directory: PathBuf = value_m!(multi_config, "data_directory", PathBuf)
            .expect("data-directory should be defaulted");
        (data_directory.join(config_file_path), user_specified)
    }

    fn request_wallet_encryption_password(&self, streams: &mut StdStreams) -> Option<String> {
        writeln!(
            streams.stdout,
            "\n\nPlease provide a password to encrypt your wallet (This password can be changed \
             later)..."
        )
        .expect("Failed console write.");
        streams.stdout.flush().expect("Failed flush.");

        for attempt in &["Try again", "Try again", "Giving up"] {
            write!(streams.stdout, "  Enter password: ").expect("Failed console write.");
            streams.stdout.flush().expect("Failed flush.");
            let (possible_password, possible_confirm) =
                match read_password_with_reader(Self::possible_reader_from_stream(streams)) {
                    Ok(password) => {
                        if password.is_empty() {
                            writeln!(streams.stdout, "\nPassword cannot be blank. {}.", attempt)
                                .expect("Failed console write.");
                            streams.stdout.flush().expect("Failed flush.");
                            (None, None)
                        } else {
                            write!(streams.stdout, "\nConfirm password: ")
                                .expect("Failed console write.");
                            streams.stdout.flush().expect("Failed flush.");

                            match read_password_with_reader(Self::possible_reader_from_stream(
                                streams,
                            )) {
                                Ok(confirm) => {
                                    if password == confirm {
                                        (Some(password), Some(confirm))
                                    } else {
                                        writeln!(
                                            streams.stdout,
                                            "\nPasswords do not match. {}.",
                                            attempt
                                        )
                                        .expect("Failed console write.");
                                        streams.stdout.flush().expect("Failed flush.");

                                        (None, None)
                                    }
                                }
                                Err(e) => panic!("Fatal error: {:?}", e),
                            }
                        }
                    }
                    Err(e) => panic!("Fatal error: {:?}", e),
                };

            match (possible_password, possible_confirm) {
                (Some(ref password), Some(ref confirm)) if password == confirm => {
                    return Some(password.to_string());
                }
                _ => continue,
            }
        }
        None
    }

    fn request_mnemonic_passphrase(&self, streams: &mut StdStreams) -> Option<String> {
        writeln!(
            streams.stdout,
            "\nPlease provide an extra mnemonic passphrase to ensure your wallet is unique (NOTE: \
            This passphrase cannot be changed later and still produce the same addresses). You will \
            encrypt your wallet in a following step...",
        )
            .expect("Failed console write.");
        streams.stdout.flush().expect("Failed flush.");

        for attempts in &["Try again", "Try again", "Giving up"] {
            write!(streams.stdout, "Mnemonic Passphrase (Recommended): ")
                .expect("Failed console write.");
            streams.stdout.flush().expect("Failed flush.");

            match read_password_with_reader(Self::possible_reader_from_stream(streams)) {
                Ok(passphrase) => {
                    if passphrase.is_empty() {
                        write!(
                            streams.stdout,
                            "\nWhile ill-advised, proceeding with no mnemonic passphrase.\nPress enter to continue...",
                        )
                            .expect("Failed to write warning.");
                        streams.stdout.flush().expect("Failed flush.");

                        let _ = streams.stdin.read(&mut [0u8]).is_ok();
                        return None;
                    } else {
                        write!(streams.stdout, "Confirm Mnemonic Passphrase: ")
                            .expect("Failed to write confirmation prompt.");
                        streams.stdout.flush().expect("Failed flush.");

                        match read_password_with_reader(Self::possible_reader_from_stream(streams))
                        {
                            Ok(confirmation) => {
                                if confirmation == passphrase {
                                    return Some(passphrase);
                                } else {
                                    writeln!(
                                        streams.stdout,
                                        "\nPassphrases do not match. {}.",
                                        attempts
                                    )
                                    .expect("Failed to write retry.");
                                    streams.stdout.flush().expect("Failed flush.");
                                    continue;
                                }
                            }
                            Err(e) => panic!("Fatal error: {:?}", e),
                        }
                    }
                }
                Err(e) => panic!("Fatal error: {:?}", e),
            }
        }
        writeln!(streams.stdout, "Proceeding without a mnemonic passphrase.")
            .expect("Failed console write.");
        streams.stdout.flush().expect("Failed flush.");
        None
    }

    fn possible_reader_from_stream(
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
                .into_iter()
                .collect::<Vec<u8>>();
            Some(::std::io::Cursor::new(inner))
        } else {
            None
        }
    }

    fn parse_args(
        &self,
        multi_config: &MultiConfig,
        config: &mut BootstrapperConfig,
        streams: &mut StdStreams<'_>,
    ) {
        config.blockchain_bridge_config.blockchain_service_url =
            value_m!(multi_config, "blockchain-service-url", String);

        config.clandestine_port_opt = value_m!(multi_config, "clandestine_port", u16);

        config.data_directory =
            value_m!(multi_config, "data_directory", PathBuf).expect("Internal Error");

        config.dns_servers = values_m!(multi_config, "dns_servers", IpAddr)
            .into_iter()
            .map(|ip| SocketAddr::from((ip, 53)))
            .collect();

        config.neighborhood_config.local_ip_addr =
            value_m!(multi_config, "ip", IpAddr).expect("Internal Error");

        config.log_level =
            value_m!(multi_config, "log_level", LevelFilter).expect("Internal Error");

        config.neighborhood_config.neighbor_configs = values_m!(multi_config, "neighbors", String);

        config.ui_gateway_config.ui_port =
            value_m!(multi_config, "ui_port", u16).expect("Internal Error");

        let earning_wallet = Wallet::new(
            value_m!(multi_config, "wallet_address", String)
                .expect("Internal Error")
                .as_str(),
        );
        config.neighborhood_config.earning_wallet = earning_wallet.clone();
        config.accountant_config.earning_wallet = earning_wallet;

        config.crash_point =
            value_m!(multi_config, "crash_point", CrashPoint).expect("Internal Error");

        match value_m!(multi_config, "fake_public_key", String) {
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

        // TODO: In real life this should come from a command-line parameter
        config.neighborhood_config.consuming_wallet = Some(TEMPORARY_CONSUMING_WALLET.clone());

        config.blockchain_bridge_config.consuming_private_key =
            value_m!(multi_config, "consuming_private_key", String);

        let phrase_words: Vec<String> = values_m!(multi_config, "mnemonic", String);
        if !(phrase_words.is_empty()) {
            let language = match value_m!(multi_config, "language", String) {
                Some(language) => Bip39::language_from_name(&language),
                None => Language::default(),
            };

            match Validators::validate_mnemonic_words(phrase_words.join(" "), language) {
                Ok(()) => {} //TODO: implement mnemonic-recovery here
                Err(_) => panic!("Invalid mnemonic phrase: {}", phrase_words.join(" ")),
            }
        }

        let matches = multi_config.arg_matches();
        if matches.is_present("generate-wallet") {
            let _ = self.generate_wallet(config, multi_config, streams);
        }
    }

    fn generate_wallet(
        &self,
        config: &mut BootstrapperConfig,
        multi_config: &MultiConfig,
        streams: &mut StdStreams,
    ) -> Result<(), String> {
        let mut possible_mnemonic_passphrase: Option<String> =
            value_m!(multi_config, "mnemonic-passphrase", String);
        let possible_language = match value_m!(multi_config, "language", String) {
            Some(language) => Some(Bip39::language_from_name(&language)),
            None => Some(Language::default()),
        };
        let possible_mnemonic_type = match value_m!(multi_config, "word-count", usize) {
            Some(word_count) => match MnemonicType::for_word_count(word_count) {
                Ok(m) => Some(m),
                _ => Some(MnemonicType::Words12), // TODO: Change this to MnemonicType::Words24 for mainnet
            },
            _ => Some(MnemonicType::Words12), // TODO: Change this to MnemonicType::Words24 for mainnet
        };

        if possible_mnemonic_passphrase.is_none() {
            possible_mnemonic_passphrase = self.request_mnemonic_passphrase(streams);
            match (possible_mnemonic_type, possible_language) {
                (Some(mnemonic_type), Some(language)) => {
                    let possible_wallet_password =
                        value_m!(multi_config, "wallet-password", String);
                    match if possible_wallet_password.is_none() {
                        self.request_wallet_encryption_password(streams)
                    } else {
                        possible_wallet_password
                    } {
                        Some(password) => {
                            let db_initializer = DbInitializerReal::new();
                            let possible_connection =
                                db_initializer.initialize(&config.data_directory);
                            match possible_connection {
                                Ok(conn) => {
                                    let public_key = PublicKey::from(CryptDENull::other_key_data(
                                        password.as_bytes(),
                                    ));
                                    let cryptde: &CryptDE = &CryptDENull::from(&public_key);
                                    let bip39 = Bip39::new(
                                        Box::new(PersistentConfigurationReal::new(Box::new(
                                            ConfigDaoReal::new(conn),
                                        ))),
                                        cryptde,
                                    );
                                    let mnemonic = bip39.mnemonic(mnemonic_type, language);
                                    writeln!(
                                        streams.stdout,
                                        "\n\nRecord the following mnemonic recovery \
                                         phrase in the sequence provided and keep it secret! \
                                         You cannot recover your wallet without these words \
                                         plus your mnemonic passphrase if you provided one.\n",
                                    )
                                    .expect("Failed console write.");
                                    writeln!(streams.stdout, "{}", mnemonic.phrase())
                                        .expect("Failed console write.");
                                    writeln!(streams.stdout, "\n\n")
                                        .expect("Failed console write.");
                                    let mnemonic_passphrase =
                                        possible_mnemonic_passphrase.unwrap_or("".to_string());
                                    let seed = bip39.seed(&mnemonic, &mnemonic_passphrase);
                                    match bip39.store(&seed) {
                                        Ok(()) => {
                                            config.blockchain_bridge_config.mnemonic_seed =
                                                Some(seed.as_bytes().to_hex())
                                        }
                                        Err(e) => panic!("Could not store mnemonic seed: {:?}", e),
                                    }
                                }
                                Err(e) => {
                                    panic!("Could not connect and initialize the database. {:?}", e)
                                }
                            }
                        }
                        None => panic!("Wallet Encryption Password is required!"),
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn data_directory_default(dirs_wrapper: &DirsWrapper) -> String {
        dirs_wrapper
            .data_dir()
            .unwrap_or(PathBuf::from(""))
            .to_str()
            .expect("Internal Error")
            .to_string()
    }
}

struct Validators {}

impl Validators {
    fn validate_ethereum_address(address: String) -> Result<(), String> {
        match Regex::new("^0x[0-9a-fA-F]{40}$")
            .expect("Failed to compile regular expression")
            .is_match(&address)
        {
            true => Ok(()),
            false => Err(address),
        }
    }

    fn validate_ip_address(address: String) -> Result<(), String> {
        match IpAddr::from_str(&address) {
            Ok(_) => Ok(()),
            Err(_) => Err(address),
        }
    }

    fn validate_ui_port(port: String) -> Result<(), String> {
        match str::parse::<u16>(&port) {
            Ok(port_number) if port_number < LOWEST_USABLE_INSECURE_PORT => Err(port),
            Ok(_) => Ok(()),
            Err(_) => Err(port),
        }
    }

    fn validate_clandestine_port(clandestine_port: String) -> Result<(), String> {
        match clandestine_port.parse::<u16>() {
            Ok(clandestine_port) if clandestine_port >= LOWEST_USABLE_INSECURE_PORT => Ok(()),
            _ => Err(clandestine_port),
        }
    }

    fn validate_private_key(key: String) -> Result<(), String> {
        if Regex::new("^[0-9a-fA-F]{64}$")
            .expect("Failed to compile regular expression")
            .is_match(&key)
        {
            Ok(())
        } else {
            Err(key)
        }
    }

    fn validate_mnemonic_word(word: String) -> Result<(), String> {
        if vec![
            Language::ChineseSimplified,
            Language::ChineseTraditional,
            Language::English,
            Language::French,
            Language::Italian,
            Language::Japanese,
            Language::Korean,
            Language::Spanish,
        ]
        .iter()
        .any(|language| language.wordmap().get_bits(&word).is_ok())
        {
            Ok(())
        } else {
            Err(word)
        }
    }

    fn validate_mnemonic_words(phrase: String, language: Language) -> Result<(), String> {
        match Mnemonic::validate(phrase.as_str(), language) {
            Ok(()) => Ok(()),
            Err(e) => Err(format!(
                "\"{}\" is not valid for {} ({})",
                phrase,
                Bip39::name_from_language(language),
                e
            )),
        }
    }
}

struct RealDirsWrapper {}

trait DirsWrapper {
    fn data_dir(&self) -> Option<PathBuf>;
}

impl DirsWrapper for RealDirsWrapper {
    fn data_dir(&self) -> Option<PathBuf> {
        data_dir()
    }
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::Cursor;
    use std::io::Write;
    use std::net::Ipv4Addr;
    use std::net::SocketAddr;
    use std::str::FromStr;

    use bip39::Seed;
    use rustc_hex::ToHex;

    use crate::multi_config::VirtualCommandLine;
    use crate::sub_lib::cryptde::PublicKey;
    use crate::sub_lib::neighborhood::sentinel_ip_addr;
    use crate::sub_lib::wallet::Wallet;
    use crate::test_utils::environment_guard::EnvironmentGuard;
    use crate::test_utils::test_utils::{
        ensure_node_home_directory_does_not_exist, ensure_node_home_directory_exists,
    };
    use crate::test_utils::test_utils::{ByteArrayWriter, FakeStreamHolder};

    use super::*;

    struct MockDirsWrapper {}

    impl DirsWrapper for MockDirsWrapper {
        fn data_dir(&self) -> Option<PathBuf> {
            Some(PathBuf::from("mocked/path"))
        }
    }

    struct BadMockDirsWrapper {}

    impl DirsWrapper for BadMockDirsWrapper {
        fn data_dir(&self) -> Option<PathBuf> {
            None
        }
    }

    fn make_default_cli_params() -> Vec<String> {
        vec![
            String::from("SubstratumNode"),
            String::from("--dns-servers"),
            String::from("222.222.222.222"),
        ]
    }

    #[test]
    fn validate_private_key_requires_a_key_that_is_64_characters_long() {
        let result = Validators::validate_private_key(String::from("42"));

        assert_eq!(Err("42".to_string()), result);
    }

    #[test]
    fn validate_private_key_must_contain_only_hex_characters() {
        let result = Validators::validate_private_key(String::from(
            "cc46befe8d169b89db447bd725fc2368b12542113555302598430cinvalidhex",
        ));

        assert_eq!(
            Err("cc46befe8d169b89db447bd725fc2368b12542113555302598430cinvalidhex".to_string()),
            result
        );
    }

    #[test]
    fn validate_private_key_handles_happy_path() {
        let result = Validators::validate_private_key(String::from(
            "cc46befe8d169b89db447bd725fc2368b12542113555302598430cb5d5c74ea9",
        ));

        assert_eq!(Ok(()), result);
    }

    #[test]
    fn validate_ip_address_given_invalid_input() {
        assert_eq!(
            Err(String::from("not-a-valid-IP")),
            Validators::validate_ip_address(String::from("not-a-valid-IP")),
        );
    }

    #[test]
    fn validate_ip_address_given_valid_input() {
        assert_eq!(
            Ok(()),
            Validators::validate_ip_address(String::from("1.2.3.4"))
        );
    }

    #[test]
    fn validate_ethereum_address_requires_an_address_that_is_42_characters_long() {
        assert_eq!(
            Err(String::from("my-favorite-wallet.com")),
            Validators::validate_ethereum_address(String::from("my-favorite-wallet.com")),
        );
    }

    #[test]
    fn validate_ethereum_address_must_start_with_0x() {
        assert_eq!(
            Err(String::from("x0my-favorite-wallet.com222222222222222222")),
            Validators::validate_ethereum_address(String::from(
                "x0my-favorite-wallet.com222222222222222222"
            ))
        );
    }

    #[test]
    fn validate_ethereum_address_must_contain_only_hex_characters() {
        assert_eq!(
            Err(String::from("0x9707f21F95B9839A54605100Ca69dCc2e7eaA26q")),
            Validators::validate_ethereum_address(String::from(
                "0x9707f21F95B9839A54605100Ca69dCc2e7eaA26q"
            ))
        );
    }

    #[test]
    fn validate_ethereum_address_when_happy() {
        assert_eq!(
            Ok(()),
            Validators::validate_ethereum_address(String::from(
                "0xbDfeFf9A1f4A1bdF483d680046344316019C58CF"
            ))
        );
    }

    #[test]
    fn parse_complains_about_non_numeric_ui_port() {
        let result = Validators::validate_ui_port(String::from("booga"));

        assert_eq!(Err(String::from("booga")), result);
    }

    #[test]
    fn parse_complains_about_ui_port_too_low() {
        let result = Validators::validate_ui_port(String::from("1023"));

        assert_eq!(Err(String::from("1023")), result);
    }

    #[test]
    fn parse_complains_about_ui_port_too_high() {
        let result = Validators::validate_ui_port(String::from("65536"));

        assert_eq!(Err(String::from("65536")), result);
    }

    #[test]
    fn parse_ui_port_works() {
        let result = Validators::validate_ui_port(String::from("5335"));

        assert_eq!(Ok(()), result);
    }

    #[test]
    fn data_directory_default_given_no_default() {
        assert_eq!(
            String::from(""),
            NodeConfiguratorReal::data_directory_default(&BadMockDirsWrapper {})
        );
    }

    #[test]
    fn data_directory_default_works() {
        let mock_dirs_wrapper = MockDirsWrapper {};

        let result = NodeConfiguratorReal::data_directory_default(&mock_dirs_wrapper);

        assert_eq!(String::from("mocked/path"), result);
    }

    #[test]
    fn validate_clandestine_port_rejects_badly_formatted_port_number() {
        let result = Validators::validate_clandestine_port(String::from("booga"));

        assert_eq!(Err(String::from("booga")), result);
    }

    #[test]
    fn validate_clandestine_port_rejects_port_number_too_low() {
        let result = Validators::validate_clandestine_port(String::from("1024"));

        assert_eq!(Err(String::from("1024")), result);
    }

    #[test]
    fn validate_clandestine_port_rejects_port_number_too_high() {
        let result = Validators::validate_clandestine_port(String::from("65536"));

        assert_eq!(Err(String::from("65536")), result);
    }

    #[test]
    fn validate_clandestine_port_accepts_port_if_provided() {
        let result = Validators::validate_clandestine_port(String::from("4567"));

        assert_eq!(Ok(()), result);
    }

    #[test]
    fn determine_config_file_path_finds_path_in_args() {
        let args: Vec<String> = vec![
            "SubstratumNode",
            "--clandestine_port",
            "2345",
            "--data_directory",
            "data_dir",
            "--config_file",
            "booga.toml",
            "--dns_servers",
            "1.2.3.4",
        ]
        .into_iter()
        .map(String::from)
        .collect();
        let subject = NodeConfiguratorReal::new();

        let (config_file_path, user_specified) = subject.determine_config_file_path(&args);

        assert_eq!(
            "data_dir",
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
        let subject = NodeConfiguratorReal::new();

        let (config_file_path, user_specified) = subject.determine_config_file_path(&args);

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
        let args: Vec<String> = vec![
            "SubstratumNode",
            "--data_directory",
            "data_dir",
            "--config_file",
            "/tmp/booga.toml",
            "--dns_servers",
            "1.2.3.4",
        ]
        .into_iter()
        .map(String::from)
        .collect();
        let subject = NodeConfiguratorReal::new();

        let (config_file_path, user_specified) = subject.determine_config_file_path(&args);

        assert_eq!(
            "/tmp/booga.toml",
            &format!("{}", config_file_path.display())
        );
        assert_eq!(true, user_specified);
    }

    #[cfg(windows)]
    #[test]
    fn determine_config_file_path_ignores_data_dir_if_config_file_has_separator_root() {
        let args: Vec<String> = vec![
            "SubstratumNode",
            "--data_directory",
            "data_dir",
            "--config_file",
            r"\tmp\booga.toml",
            "--dns_servers",
            "1.2.3.4",
        ]
        .into_iter()
        .map(String::from)
        .collect();
        let subject = NodeConfiguratorReal::new();

        let (config_file_path, user_specified) = subject.determine_config_file_path(&args);

        assert_eq!(
            r"\tmp\booga.toml",
            &format!("{}", config_file_path.display())
        );
        assert_eq!(true, user_specified);
    }

    #[cfg(windows)]
    #[test]
    fn determine_config_file_path_ignores_data_dir_if_config_file_has_drive_root() {
        let args: Vec<String> = vec![
            "SubstratumNode",
            "--data_directory",
            "data_dir",
            "--config_file",
            r"c:\tmp\booga.toml",
            "--dns_servers",
            "1.2.3.4",
        ]
        .into_iter()
        .map(String::from)
        .collect();
        let subject = NodeConfiguratorReal::new();

        let (config_file_path, user_specified) = subject.determine_config_file_path(&args);

        assert_eq!(
            r"c:\tmp\booga.toml",
            &format!("{}", config_file_path.display())
        );
        assert_eq!(true, user_specified);
    }

    #[cfg(windows)]
    #[test]
    fn determine_config_file_path_ignores_data_dir_if_config_file_has_network_root() {
        let args: Vec<String> = vec![
            "SubstratumNode",
            "--data_directory",
            "data_dir",
            "--config_file",
            r"\\TMP\booga.toml",
            "--dns_servers",
            "1.2.3.4",
        ]
        .into_iter()
        .map(String::from)
        .collect();
        let subject = NodeConfiguratorReal::new();

        let (config_file_path, user_specified) = subject.determine_config_file_path(&args);

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
        let args: Vec<String> = vec![
            "SubstratumNode",
            "--data_directory",
            "data_dir",
            "--config_file",
            r"c:tmp\booga.toml",
            "--dns_servers",
            "1.2.3.4",
        ]
        .into_iter()
        .map(String::from)
        .collect();
        let subject = NodeConfiguratorReal::new();

        let (config_file_path, user_specified) = subject.determine_config_file_path(&args);

        assert_eq!(
            r"c:tmp\booga.toml",
            &format!("{}", config_file_path.display())
        );
        assert_eq!(true, user_specified);
    }

    #[test]
    fn validate_mnemonic_word_fails_for_wrong_word() {
        assert!(Validators::validate_mnemonic_word("booga".to_string()).is_err());
    }

    #[test]
    fn validate_mnemonic_word_fails_for_empty_string() {
        assert!(Validators::validate_mnemonic_word("".to_string()).is_err());
    }

    #[test]
    fn validate_mnemonic_word_succeeds_for_english_word() {
        assert!(Validators::validate_mnemonic_word("timber".to_string()).is_ok());
    }

    #[test]
    fn validate_mnemonic_word_succeeds_for_chinese_simplified_word() {
        assert!(Validators::validate_mnemonic_word("据".to_string()).is_ok());
    }

    #[test]
    fn validate_mnemonic_word_succeeds_for_chinese_traditional_word() {
        assert!(Validators::validate_mnemonic_word("腸".to_string()).is_ok());
    }

    #[test]
    fn validate_mnemonic_word_succeeds_for_french_word() {
        assert!(Validators::validate_mnemonic_word("amour".to_string()).is_ok());
    }

    #[test]
    fn validate_mnemonic_word_succeeds_for_italian_word() {
        assert!(Validators::validate_mnemonic_word("stizzoso".to_string()).is_ok());
    }

    #[test]
    fn validate_mnemonic_word_succeeds_for_japanese_word() {
        assert!(Validators::validate_mnemonic_word("おおう".to_string()).is_ok());
    }

    #[test]
    fn validate_mnemonic_word_succeeds_for_korean_word() {
        assert!(Validators::validate_mnemonic_word("음주".to_string()).is_ok());
    }

    #[test]
    fn validate_mnemonic_word_succeeds_for_spanish_word() {
        assert!(Validators::validate_mnemonic_word("bolero".to_string()).is_ok());
    }

    #[test]
    fn validate_mnemonic_words_if_provided_in_chinese_simplified() {
        assert!(Validators::validate_mnemonic_words(
            "昨 据 肠 介 甘 橡 峰 冬 点 显 假 覆 归 了 曰 露 胀 偷 盆 缸 操 举 除 喜"
                .to_string(),
            Language::ChineseSimplified
        )
        .is_ok());
    }

    #[test]
    fn validate_mnemonic_words_if_provided_in_chinese_traditional() {
        assert!(Validators::validate_mnemonic_words(
            "昨 據 腸 介 甘 橡 峰 冬 點 顯 假 覆 歸 了 曰 露 脹 偷 盆 缸 操 舉 除 喜"
                .to_string(),
            Language::ChineseTraditional
        )
        .is_ok());
    }

    #[test]
    fn validate_mnemonic_words_if_provided_in_english() {
        assert!(Validators::validate_mnemonic_words(
            "timber cage wide hawk phone shaft pattern movie army dizzy hen tackle lamp \
             absent write kind term toddler sphere ripple idle dragon curious hold"
                .to_string(),
            Language::English
        )
        .is_ok());
    }

    #[test]
    fn fails_to_validate_nonsense_words_if_provided_in_english() {
        let phrase =
            "ooga booga gahooga zoo fail test twelve twenty four token smoke fire".to_string();
        let result = Validators::validate_mnemonic_words(phrase.clone(), Language::English);

        assert_eq!(
            result.unwrap_err(),
            format!(
                "\"{}\" is not valid for English (invalid word in phrase)",
                phrase
            )
        );
    }

    #[test]
    fn fails_to_validate_english_words_with_french() {
        let phrase =
            "timber cage wide hawk phone shaft pattern movie army dizzy hen tackle lamp absent write kind term \
            toddler sphere ripple idle dragon curious hold".to_string();
        let result = Validators::validate_mnemonic_words(phrase.clone(), Language::French);

        assert_eq!(
            result.unwrap_err(),
            format!(
                "\"{}\" is not valid for Français (invalid word in phrase)",
                phrase
            )
        );
    }

    #[test]
    fn fails_to_validate_sorted_wordlist_words_if_provided_in_english() {
        assert!(Validators::validate_mnemonic_words(
            "absent army cage curious dizzy dragon hawk hen hold idle kind lamp movie \
             pattern phone ripple shaft sphere tackle term timber toddler wide write"
                .to_string(),
            Language::English
        )
        .is_err());
    }

    #[test]
    fn validate_mnemonic_words_if_provided_in_french() {
        assert!(Validators::validate_mnemonic_words(
            "stable bolide vignette fluvial ne\u{301}faste purifier muter lombric amour \
             de\u{301}cupler fouge\u{300}re silicium humble aborder vortex histoire somnoler \
             substrat rompre pivoter gendarme demeurer colonel frelon"
                .to_string(),
            Language::French
        )
        .is_ok());
    }

    #[test]
    fn validate_mnemonic_words_if_provided_in_italian() {
        assert!(Validators::validate_mnemonic_words(
            "tampone bravura viola inodore poderoso scheda pimpante onice anca dote \
             intuito stizzoso mensola abolire zenzero massaia supporto taverna sistole riverso \
             lentezza ecco curatore ironico"
                .to_string(),
            Language::Italian
        )
        .is_ok());
    }

    #[test]
    fn validate_mnemonic_words_if_provided_in_japanese() {
        assert!(Validators::validate_mnemonic_words(
            "まよう おおう るいせき しゃちょう てんし はっほ\u{309a}う てほと\u{3099}き た\u{3099}んな \
            いつか けいかく しゅらは\u{3099} ほけん そうか\u{3099}んきょう あきる ろんは\u{309a} せんぬき ほんき \
            みうち ひんは\u{309a}ん ねわさ\u{3099} すのこ け\u{3099}きとつ きふく し\u{3099}んし\u{3099}ゃ"
                .to_string(), Language::Japanese
        )
            .is_ok());
    }

    #[test]
    fn validate_mnemonic_words_if_provided_in_korean() {
        assert!(Validators::validate_mnemonic_words(
            "텔레비전 기법 확보 성당 음주 주문 유물 연휴 경주 무릎 세월 캐릭터 \
             신고 가르침 흐름 시중 큰아들 통장 창밖 전쟁 쇠고기 물가 마사지 소득"
                .to_string(),
            Language::Korean
        )
        .is_ok());
    }

    #[test]
    fn validate_mnemonic_words_if_provided_in_spanish() {
        assert!(Validators::validate_mnemonic_words(
            "tarro bolero villa hacha opaco regalo oferta mochila amistad definir helio \
             suerte leer abono yeso lana taco tejado salto premio iglesia destino colcha himno"
                .to_string(),
            Language::Spanish
        )
        .is_ok());
    }

    #[test]
    fn request_mnemonic_passphrase_happy_path() {
        let subject = NodeConfiguratorReal::new();
        let stdout_writer = &mut ByteArrayWriter::new();
        let streams = &mut StdStreams {
            stdin: &mut Cursor::new(&b"a very poor passphrase\na very poor passphrase\n"[..]),
            stdout: stdout_writer,
            stderr: &mut ByteArrayWriter::new(),
        };

        let actual = subject.request_mnemonic_passphrase(streams);

        assert_eq!(actual, Some("a very poor passphrase".to_string()));
        assert_eq!(
            stdout_writer.get_string(),
            "\nPlease provide an extra mnemonic passphrase to ensure your wallet is unique (NOTE: \
            This passphrase cannot be changed later and still produce the same addresses). You will \
            encrypt your wallet in a following step...\nMnemonic Passphrase (Recommended): Confirm \
            Mnemonic Passphrase: ".to_string()
        );
    }

    #[test]
    fn request_mnemonic_passphrase_given_blank_is_allowed() {
        let subject = NodeConfiguratorReal::new();
        let stdout_writer = &mut ByteArrayWriter::new();
        let streams = &mut StdStreams {
            stdin: &mut Cursor::new(&b"\n"[..]),
            stdout: stdout_writer,
            stderr: &mut ByteArrayWriter::new(),
        };

        let actual = subject.request_mnemonic_passphrase(streams);

        assert_eq!(actual, None);
        assert_eq!(
            stdout_writer.get_string(),
            "\nPlease provide an extra mnemonic passphrase to ensure your wallet is unique (NOTE: This passphrase \
                cannot be changed later and still produce the same addresses). You will encrypt your wallet in a following step...\
                \nMnemonic Passphrase (Recommended): \nWhile ill-advised, proceeding with no mnemonic \
             passphrase.\nPress enter to continue..."
                .to_string()
        );
    }

    #[test]
    fn request_mnemonic_passphrase_mismatch_error() {
        let subject = NodeConfiguratorReal::new();
        let stdout_writer = &mut ByteArrayWriter::new();
        let streams = &mut StdStreams {
            stdin: &mut Cursor::new(&b"a very poor passphrase\na non-matching passphrase\n"[..]),
            stdout: stdout_writer,
            stderr: &mut ByteArrayWriter::new(),
        };

        let actual = subject.request_mnemonic_passphrase(streams);

        assert_eq!(actual, None);
        assert_eq!(
            stdout_writer.get_string(),
            "\nPlease provide an extra mnemonic passphrase to ensure your wallet is unique (NOTE: This passphrase \
            cannot be changed later and still produce the same addresses). You will encrypt your wallet in a following step...\
            \nMnemonic Passphrase (Recommended): Confirm Mnemonic Passphrase: \
             \nPassphrases do not match. Try again.\nMnemonic Passphrase (Recommended): \
             \nWhile ill-advised, proceeding with no mnemonic passphrase.\
             \nPress enter to continue..."
                .to_string()
        );
    }

    #[test]
    fn request_mnemonic_passphrase_mismatch_error_succeeds_on_reattempt() {
        let subject = NodeConfiguratorReal::new();
        let stdout_writer = &mut ByteArrayWriter::new();
        let streams = &mut StdStreams {
            stdin: &mut Cursor::new(
                &b"a very poor passphrase\na non-matching passphrase\
            \nA Somewhat Improved P455phras3!\nA Somewhat Improved P455phras3!\n"[..],
            ),
            stdout: stdout_writer,
            stderr: &mut ByteArrayWriter::new(),
        };

        let actual = subject.request_mnemonic_passphrase(streams);

        assert_eq!(actual, Some("A Somewhat Improved P455phras3!".to_string()));
        assert_eq!(
            stdout_writer.get_string(),
            "\nPlease provide an extra mnemonic passphrase to ensure your wallet is unique (NOTE: This passphrase \
            cannot be changed later and still produce the same addresses). You will encrypt your wallet in a following step...\
            \nMnemonic Passphrase (Recommended): Confirm Mnemonic Passphrase: \
             \nPassphrases do not match. Try again.\
             \nMnemonic Passphrase (Recommended): Confirm Mnemonic Passphrase: "
                .to_string()
        );
    }

    #[test]
    fn request_mnemonic_passphrase_gives_up_after_three_attempts() {
        let subject = NodeConfiguratorReal::new();
        let stdout_writer = &mut ByteArrayWriter::new();
        let streams = &mut StdStreams {
            stdin: &mut Cursor::new(&b"one\n\ntwo\n\nthree\n\n"[..]),
            stdout: stdout_writer,
            stderr: &mut ByteArrayWriter::new(),
        };

        let actual = subject.request_mnemonic_passphrase(streams);

        assert_eq!(actual, None);
        assert_eq!(
            stdout_writer.get_string(),
            "\nPlease provide an extra mnemonic passphrase to ensure your wallet is unique (NOTE: This passphrase \
            cannot be changed later and still produce the same addresses). You will encrypt your wallet in a following step...\
            \nMnemonic Passphrase (Recommended): Confirm Mnemonic Passphrase: \
             \nPassphrases do not match. Try again.\
             \nMnemonic Passphrase (Recommended): Confirm Mnemonic Passphrase: \
             \nPassphrases do not match. Try again.\
             \nMnemonic Passphrase (Recommended): Confirm Mnemonic Passphrase: \
             \nPassphrases do not match. Giving up.\
             \nProceeding without a mnemonic passphrase.\n"
                .to_string()
        );
    }

    #[test]
    fn request_wallet_encryption_password_happy_path() {
        let subject = NodeConfiguratorReal::new();
        let stdout_writer = &mut ByteArrayWriter::new();
        let streams = &mut StdStreams {
            stdin: &mut Cursor::new(&b"one\n\ntwo\n\nthree\n\n"[..]),
            stdout: stdout_writer,
            stderr: &mut ByteArrayWriter::new(),
        };

        let actual = subject.request_wallet_encryption_password(streams);

        assert_eq!(actual, None);
        assert_eq!(
            stdout_writer.get_string(),
            "\n\nPlease provide a password to encrypt your wallet (This password can be changed later)...\
                \n  Enter password: \
                \nConfirm password: \
                \nPasswords do not match. Try again.\
                \n  Enter password: \
                \nConfirm password: \
                \nPasswords do not match. Try again.\
                \n  Enter password: \
                \nConfirm password: \
                \nPasswords do not match. Giving up.\n"
                .to_string()
        );
    }

    #[test]
    fn request_wallet_encryption_password_succeeds_on_reattempt() {
        let subject = NodeConfiguratorReal::new();
        let stdout_writer = &mut ByteArrayWriter::new();
        let streams = &mut StdStreams {
            stdin: &mut Cursor::new(
                &b"Too Many S3cr3ts!\n\nToo Many S3cr3ts!\nToo Many S3cr3ts!\n"[..],
            ),
            stdout: stdout_writer,
            stderr: &mut ByteArrayWriter::new(),
        };

        let actual = subject.request_wallet_encryption_password(streams);

        assert_eq!(actual, Some("Too Many S3cr3ts!".to_string()));
        assert_eq!(
            stdout_writer.get_string(),
            "\n\nPlease provide a password to encrypt your wallet (This password can be changed later)...\
                \n  Enter password: \
                \nConfirm password: \
                \nPasswords do not match. Try again.\
                \n  Enter password: \
                \nConfirm password: "
                .to_string()
        );
    }

    #[test]
    fn request_wallet_encryption_password_gives_up_after_three_blank_passwords() {
        let subject = NodeConfiguratorReal::new();
        let stdout_writer = &mut ByteArrayWriter::new();
        let streams = &mut StdStreams {
            stdin: &mut Cursor::new(&b"\n\n\n"[..]),
            stdout: stdout_writer,
            stderr: &mut ByteArrayWriter::new(),
        };

        let actual = subject.request_wallet_encryption_password(streams);

        assert_eq!(actual, None);
        assert_eq!(
            stdout_writer.get_string(),
            "\n\nPlease provide a password to encrypt your wallet (This password can be changed later)...\
                \n  Enter password: \
                \nPassword cannot be blank. Try again.\
                \n  Enter password: \
                \nPassword cannot be blank. Try again.\
                \n  Enter password: \
                \nPassword cannot be blank. Giving up.\n"
                .to_string()
        );
    }

    #[test]
    fn request_wallet_encryption_password_gives_up_after_three_mismatches() {
        let subject = NodeConfiguratorReal::new();
        let stdout_writer = &mut ByteArrayWriter::new();
        let streams = &mut StdStreams {
            stdin: &mut Cursor::new(&b"one\n\ntwo\n\nthree\n\n"[..]),
            stdout: stdout_writer,
            stderr: &mut ByteArrayWriter::new(),
        };

        let actual = subject.request_wallet_encryption_password(streams);

        assert_eq!(actual, None);
        assert_eq!(
            stdout_writer.get_string(),
            "\n\nPlease provide a password to encrypt your wallet (This password can be changed later)...\
                \n  Enter password: \
                \nConfirm password: \
                \nPasswords do not match. Try again.\
                \n  Enter password: \
                \nConfirm password: \
                \nPasswords do not match. Try again.\
                \n  Enter password: \
                \nConfirm password: \
                \nPasswords do not match. Giving up.\n"
                .to_string()
        );
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
                .write_all(b"dns_servers = \"1.2.3.4\"\n")
                .unwrap();
        }
        let subject = NodeConfiguratorReal::new();

        let configuration = subject.generate_configuration(
            &vec![
                "".to_string(),
                "--data_directory".to_string(),
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
    fn parse_args_creates_configurations() {
        let _guard = EnvironmentGuard::new();
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
            "--wallet-address",
            "0xbDfeFf9A1f4A1bdF483d680046344316019C58CF",
            "--data-directory",
            "~/.booga",
            "--blockchain-service-url",
            "http://127.0.0.1:8545",
            "--log-level",
            "trace",
            "--fake_public_key",
            "AQIDBA",
        ]
        .into_iter()
        .map(String::from)
        .collect();
        std::env::set_var(
            "SUB_CONSUMING_PRIVATE_KEY",
            "1234567891123456789212345678913234567894123456789512345678961234",
        );
        let mut config = BootstrapperConfig::new();
        let subject = NodeConfiguratorReal::new();
        let vcls: Vec<Box<VirtualCommandLine>> = vec![
            Box::new(EnvironmentVCL::new(&subject.app)),
            Box::new(CommandLineVCL::new(args)),
        ];
        let multi_config = MultiConfig::new(&subject.app, vcls);

        subject.parse_args(
            &multi_config,
            &mut config,
            &mut FakeStreamHolder::new().streams(),
        );

        assert_eq!(
            value_m!(multi_config, "config_file", PathBuf),
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
        let earning_wallet = Wallet::new("0xbDfeFf9A1f4A1bdF483d680046344316019C58CF");
        assert_eq!(config.neighborhood_config.earning_wallet, earning_wallet);
        assert_eq!(config.accountant_config.earning_wallet, earning_wallet);
        assert_eq!(
            config.neighborhood_config.earning_wallet,
            Wallet::new("0xbDfeFf9A1f4A1bdF483d680046344316019C58CF"),
        );
        let expected_port_list: Vec<u16> = vec![];
        assert_eq!(
            config.neighborhood_config.clandestine_port_list,
            expected_port_list,
        );
        assert_eq!(
            config.blockchain_bridge_config.blockchain_service_url,
            Some("http://127.0.0.1:8545".to_string()),
        );
        assert_eq!(PathBuf::from("~/.booga"), config.data_directory,);
        assert_eq!(Some(1234u16), config.clandestine_port_opt);
        assert_eq!(
            config.blockchain_bridge_config.consuming_private_key,
            Some("1234567891123456789212345678913234567894123456789512345678961234".to_string()),
        );
        assert_eq!(
            config.cryptde_null_opt.unwrap().public_key(),
            &PublicKey::new(&[1, 2, 3, 4]),
        );
    }

    #[test]
    fn parse_args_creates_configuration_with_defaults() {
        let _guard = EnvironmentGuard::new();
        let args: Vec<String> = vec!["SubstratumNode", "--dns-servers", "12.34.56.78,23.45.67.89"]
            .into_iter()
            .map(String::from)
            .collect();
        let mut config = BootstrapperConfig::new();
        let subject = NodeConfiguratorReal::new();
        let vcls: Vec<Box<VirtualCommandLine>> = vec![
            Box::new(CommandLineVCL::new(args)),
            Box::new(EnvironmentVCL::new(&subject.app)),
        ];
        let multi_config = MultiConfig::new(&subject.app, vcls);

        subject.parse_args(
            &multi_config,
            &mut config,
            &mut FakeStreamHolder::new().streams(),
        );

        assert_eq!(
            Some(PathBuf::from("config.toml")),
            value_m!(multi_config, "config_file", PathBuf)
        );
        assert_eq!(
            config.dns_servers,
            vec!(
                SocketAddr::from_str("12.34.56.78:53").unwrap(),
                SocketAddr::from_str("23.45.67.89:53").unwrap()
            )
        );
        assert_eq!(None, config.clandestine_port_opt);
        assert_eq!(CrashPoint::None, config.crash_point);
        assert!(config.data_directory.is_dir());
        assert_eq!(
            Wallet::new("0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
            config.neighborhood_config.earning_wallet,
        );
        assert_eq!(sentinel_ip_addr(), config.neighborhood_config.local_ip_addr,);
        assert_eq!(5333, config.ui_gateway_config.ui_port);
        assert_eq!(None, config.blockchain_bridge_config.consuming_private_key);
        assert!(config.cryptde_null_opt.is_none());
    }

    #[test]
    #[should_panic(
        expected = "error: The argument '--wallet-address <WALLET-ADDRESS>' cannot be used with '--generate-wallet <GENERATE-WALLET>'"
    )]
    fn parse_args_enforces_conflicting_wallet_options() {
        let args: Vec<String> = vec![
            "SubstratumNode",
            "--generate-wallet",
            "ignored",
            "--wallet-address",
            "0x0123456789abcdefcafebabefeedfacedeadbeef",
        ]
        .into_iter()
        .map(String::from)
        .collect();
        let mut config = BootstrapperConfig::new();
        let subject = NodeConfiguratorReal::new();
        let vcl = Box::new(CommandLineVCL::new(args));
        let multi_config = MultiConfig::new(&subject.app, vec![vcl]);

        subject.parse_args(
            &multi_config,
            &mut config,
            &mut FakeStreamHolder::new().streams(),
        );
    }

    #[test]
    #[should_panic(
        expected = "error: The argument '--mnemonic <MNEMONIC-WORDS>' cannot be used with '--generate-wallet <GENERATE-WALLET>'"
    )]
    fn parse_args_enforces_conflicting_wallet_options_with_conflict_panic() {
        let args: Vec<String> = vec![
            "SubstratumNode",
            "--generate-wallet",
            "ignored",
            "--mnemonic",
            "\"one two three toy frame can photo viola string crop circle zoo\"",
        ]
        .into_iter()
        .map(String::from)
        .collect();
        let mut config = BootstrapperConfig::new();
        let subject = NodeConfiguratorReal::new();
        let vcl = Box::new(CommandLineVCL::new(args));
        let multi_config = MultiConfig::new(&subject.app, vec![vcl]);

        subject.parse_args(
            &multi_config,
            &mut config,
            &mut FakeStreamHolder::new().streams(),
        );
    }

    #[test]
    fn parse_args_allows_generate_wallet_and_passphrase_happy_path() {
        ensure_node_home_directory_does_not_exist(
            "node_configurator",
            "parse_args_allows_generate_wallet_and_passphrase_happy_path",
        );
        let node_home_directory = ensure_node_home_directory_exists(
            "node_configurator",
            "parse_args_allows_generate_wallet_and_passphrase_happy_path",
        );

        let args: Vec<String> = vec![
            "SubstratumNode",
            "--data-directory",
            node_home_directory.to_str().unwrap(),
            "--generate-wallet",
            "yes",
            "--language",
            "english",
            "--word-count",
            "12",
        ]
        .into_iter()
        .map(String::from)
        .collect();

        let mut config = BootstrapperConfig::new();
        let subject = NodeConfiguratorReal::new();
        let stdout_writer = &mut ByteArrayWriter::new();
        let mut streams = &mut StdStreams {
            stdin: &mut Cursor::new(
                &b"very poor passphrase\nvery poor passphrase\na terrible \
            wallet password\na terrible wallet password\n"[..],
            ),
            stdout: stdout_writer,
            stderr: &mut ByteArrayWriter::new(),
        };
        let vcl = Box::new(CommandLineVCL::new(args));
        let multi_config = MultiConfig::new(&subject.app, vec![vcl]);

        subject.parse_args(&multi_config, &mut config, &mut streams);

        let captured_output = stdout_writer.get_string();
        let expected_output = "\nPlease provide an extra mnemonic passphrase to ensure your wallet is unique (NOTE: This passphrase \
                cannot be changed later and still produce the same addresses). You will encrypt your wallet in a following step...\
                \nMnemonic Passphrase (Recommended): Confirm Mnemonic Passphrase: \
        \n\nPlease provide a password to encrypt your wallet (This password can be changed later)...\
        \n  Enter password: \nConfirm password: \n\nRecord the following mnemonic recovery phrase \
        in the sequence provided and keep it secret! You cannot recover your wallet without these \
        words plus your mnemonic passphrase if you provided one.\n\n";

        assert_eq!(&captured_output[..expected_output.len()], expected_output);
        assert!(dbg!(config
            .blockchain_bridge_config
            .mnemonic_seed
            .is_some()));

        let mnemonic = captured_output[expected_output.len()..].trim();
        match Mnemonic::from_phrase(mnemonic, Language::English) {
            Ok(m) => assert_eq!(
                Some(Seed::new(&m, "very poor passphrase").as_bytes().to_hex()),
                config.blockchain_bridge_config.mnemonic_seed
            ),
            _ => assert!(false),
        }
    }

    #[test]
    fn parse_args_allows_generate_wallet_with_blank_mnemonic_passphrase() {
        ensure_node_home_directory_does_not_exist(
            "node_configurator",
            "parse_args_allows_generate_wallet_with_blank_mnemonic_passphrase",
        );
        let node_home_directory = ensure_node_home_directory_exists(
            "node_configurator",
            "parse_args_allows_generate_wallet_with_blank_mnemonic_passphrase",
        );

        let args: Vec<String> = vec![
            "SubstratumNode",
            "--data-directory",
            node_home_directory.to_str().unwrap(),
            "--generate-wallet",
            "please",
            "--language",
            "english",
            "--word-count",
            "12",
        ]
        .into_iter()
        .map(String::from)
        .collect();

        let mut config = BootstrapperConfig::new();
        let subject = NodeConfiguratorReal::new();
        let stdout_writer = &mut ByteArrayWriter::new();
        let mut streams = &mut StdStreams {
            stdin: &mut Cursor::new(
                &b"\n\na terrible wallet password\na terrible wallet password\n"[..],
            ),
            stdout: stdout_writer,
            stderr: &mut ByteArrayWriter::new(),
        };
        let vcl = Box::new(CommandLineVCL::new(args));
        let multi_config = MultiConfig::new(&subject.app, vec![vcl]);

        subject.parse_args(&multi_config, &mut config, &mut streams);

        let captured_output = stdout_writer.get_string();
        let expected_output = "\nPlease provide an extra mnemonic passphrase to ensure your \
        wallet is unique (NOTE: This passphrase cannot be changed later and still produce the same \
        addresses). You will encrypt your wallet in a following step...\nMnemonic Passphrase \
        (Recommended): \nWhile ill-advised, proceeding with no mnemonic passphrase.\
        \nPress enter to continue...\n\nPlease provide a password to encrypt your wallet \
        (This password can be changed later)...\n  Enter password: \nConfirm password: \
        \n\nRecord the following mnemonic recovery phrase in the sequence provided and keep it \
        secret! You cannot recover your wallet without these words plus your mnemonic passphrase \
        if you provided one.\n\n";

        assert_eq!(&captured_output[..expected_output.len()], expected_output);
        assert!(config.blockchain_bridge_config.mnemonic_seed.is_some());
        let mnemonic = captured_output[expected_output.len()..].trim();
        match Mnemonic::from_phrase(mnemonic, Language::English) {
            Ok(m) => assert_eq!(
                Some(Seed::new(&m, "").as_bytes().to_hex()),
                config.blockchain_bridge_config.mnemonic_seed
            ),
            _ => assert!(
                false,
                format!("Invalid mnemonic from end of captured_output {}", mnemonic)
            ),
        }
    }

    #[test]
    #[should_panic(expected = "Wallet Encryption Password is required!")]
    fn generate_wallet_panics_after_three_password_mismatches() {
        let _guard = EnvironmentGuard::new();
        let subject = NodeConfiguratorReal::new();
        let stdout_writer = &mut ByteArrayWriter::new();
        let streams = &mut StdStreams {
            stdin: &mut Cursor::new(&b"one\n\ntwo\n\nthree\n\n"[..]),
            stdout: stdout_writer,
            stderr: &mut ByteArrayWriter::new(),
        };

        let args: Vec<String> = vec!["SubstratumNode", "--generate-wallet", "ignored"]
            .into_iter()
            .map(String::from)
            .collect();
        subject.generate_configuration(&args, streams);
    }

    #[test]
    fn parse_args_allows_generate_wallet_with_value_less_passphrase_blank_passphrase() {
        ensure_node_home_directory_does_not_exist(
            "node_configurator",
            "parse_args_allows_generate_wallet_with_value_less_passphrase_blank_passphrase",
        );
        let node_home_directory = ensure_node_home_directory_exists(
            "node_configurator",
            "parse_args_allows_generate_wallet_with_value_less_passphrase_blank_passphrase",
        );

        let args: Vec<String> = vec![
            "SubstratumNode",
            "--data-directory",
            node_home_directory.to_str().unwrap(),
            "--generate-wallet",
            "please",
            "--language",
            "english",
            "--word-count",
            "12",
            "--mnemonic-passphrase",
        ]
        .into_iter()
        .map(String::from)
        .collect();

        let mut config = BootstrapperConfig::new();
        let subject = NodeConfiguratorReal::new();
        let stdout_writer = &mut ByteArrayWriter::new();
        let mut streams = &mut StdStreams {
            stdin: &mut Cursor::new(
                &b"\n\na terrible wallet password\na terrible wallet password\n"[..],
            ),
            stdout: stdout_writer,
            stderr: &mut ByteArrayWriter::new(),
        };
        let vcl = Box::new(CommandLineVCL::new(args));
        let multi_config = MultiConfig::new(&subject.app, vec![vcl]);

        subject.parse_args(&multi_config, &mut config, &mut streams);

        let captured_output = stdout_writer.get_string();
        let expected_output = "\nPlease provide an extra mnemonic passphrase to ensure your wallet is unique (NOTE: This passphrase \
                cannot be changed later and still produce the same addresses). You will encrypt your wallet in a following step...\
                \nMnemonic Passphrase (Recommended): \nWhile ill-advised, proceeding with no mnemonic passphrase.\
        \nPress enter to continue...\
        \n\nPlease provide a password to encrypt your wallet (This password can be changed later)...\
        \n  Enter password: \
        \nConfirm password: \
        \n\nRecord the following mnemonic recovery phrase in the sequence provided and keep it \
        secret! You cannot recover your wallet without these words plus your mnemonic passphrase \
        if you provided one.\n\n";

        assert_eq!(&captured_output[..expected_output.len()], expected_output);
        assert!(config.blockchain_bridge_config.mnemonic_seed.is_some());
        let mnemonic = captured_output[expected_output.len()..].trim();
        match Mnemonic::from_phrase(mnemonic, Language::English) {
            Ok(m) => assert_eq!(
                Some(Seed::new(&m, "").as_bytes().to_hex()),
                config.blockchain_bridge_config.mnemonic_seed
            ),
            _ => assert!(
                false,
                format!("Invalid mnemonic from end of captured_output {}", mnemonic)
            ),
        }
    }

    #[test]
    #[should_panic(expected = "error: Invalid value for '--mnemonic <MNEMONIC-WORDS>': four")]
    fn mnemonic_argument_fails_with_invalid_words() {
        let args: Vec<String> = vec![
            "SubstratumNode",
            "--mnemonic",
            "one two three four five six seven eight nine ten eleven twelve",
        ]
        .into_iter()
        .map(String::from)
        .collect();

        let mut config = BootstrapperConfig::new();
        let subject = NodeConfiguratorReal::new();
        let stdout_writer = &mut ByteArrayWriter::new();
        let mut streams = &mut StdStreams {
            stdin: &mut Cursor::new(
                &b"\n\na terrible wallet password\na terrible wallet password\n"[..],
            ),
            stdout: stdout_writer,
            stderr: &mut ByteArrayWriter::new(),
        };

        let vcl = Box::new(CommandLineVCL::new(args));
        let multi_config = MultiConfig::new(&subject.app, vec![vcl]);

        subject.parse_args(&multi_config, &mut config, &mut streams);
    }

    #[test]
    fn no_parameters_produces_configuration_for_crash_point() {
        let args = make_default_cli_params();
        let mut config = BootstrapperConfig::new();
        let subject = NodeConfiguratorReal::new();
        let vcl = Box::new(CommandLineVCL::new(args));
        let multi_config = MultiConfig::new(&subject.app, vec![vcl]);

        subject.parse_args(
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
        let subject = NodeConfiguratorReal::new();
        let vcl = Box::new(CommandLineVCL::new(args));
        let multi_config = MultiConfig::new(&subject.app, vec![vcl]);

        subject.parse_args(
            &multi_config,
            &mut config,
            &mut FakeStreamHolder::new().streams(),
        );

        assert_eq!(config.crash_point, CrashPoint::Panic);
    }

    #[test]
    #[should_panic(expected = "could not be read: ")]
    fn generate_configuration_senses_when_user_specifies_config_file() {
        let subject = NodeConfiguratorReal::new();
        let args = vec![
            "SubstratumNode",
            "--dns-servers",
            "1.2.3.4",
            "--config_file",
            "booga.toml", // nonexistent config file: should stimulate panic because user-specified
        ]
        .into_iter()
        .map(String::from)
        .collect::<Vec<String>>();
        subject.generate_configuration(&args, &mut FakeStreamHolder::new().streams());
    }
}
