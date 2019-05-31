// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

use crate::bootstrapper::{BootstrapperConfig, PortConfiguration};
use crate::http_request_start_finder::HttpRequestDiscriminatorFactory;
use crate::multi_config::{CommandLineVCL, ConfigFileVCL, EnvironmentVCL, MultiConfig};
use crate::persistent_configuration::{HTTP_PORT, TLS_PORT};
use crate::sub_lib::accountant::DEFAULT_EARNING_WALLET;
use crate::sub_lib::accountant::TEMPORARY_CONSUMING_WALLET;
use crate::sub_lib::crash_point::CrashPoint;
use crate::sub_lib::neighborhood::{sentinel_ip_addr, NodeDescriptor};
use crate::sub_lib::ui_gateway::DEFAULT_UI_PORT;
use crate::sub_lib::wallet::Wallet;
use crate::tls_discriminator_factory::TlsDiscriminatorFactory;
use clap::{crate_authors, crate_description, crate_version, App, Arg};
use dirs::data_dir;
use indoc::indoc;
use lazy_static::lazy_static;
use log::LevelFilter;
use regex::Regex;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;

pub const LOWEST_USABLE_INSECURE_PORT: u16 = 1025;
pub const HIGHEST_USABLE_PORT: u16 = 65535;

pub trait NodeConfigurator {
    fn generate_configuration(&self, args: &Vec<String>) -> BootstrapperConfig;
}

pub struct NodeConfiguratorReal {
    app: App<'static, 'static>,
}

impl NodeConfigurator for NodeConfiguratorReal {
    fn generate_configuration(&self, args: &Vec<String>) -> BootstrapperConfig {
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
        self.parse_args(&multi_config, &mut bootstrapper_config);
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
        "Must be between {} and {}; defaults to {}",
        LOWEST_USABLE_INSECURE_PORT, HIGHEST_USABLE_PORT, DEFAULT_UI_PORT
    );
    static ref CLANDESTINE_PORT_HELP: String = format!(
        "Must be between {} and {}; defaults to last used port",
        LOWEST_USABLE_INSECURE_PORT, HIGHEST_USABLE_PORT
    );
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
                .version(crate_version!())
                .author(crate_authors!("\n"))
                .about(crate_description!())
                .after_help(HELP_TEXT)
                .arg(
                    Arg::with_name("config_file")
                        .long("config_file")
                        .value_name("FILE_PATH")
                        .default_value("config.toml")
                        .takes_value(true)
                        .required(false),
                )
                .arg(
                    Arg::with_name("blockchain_service_url")
                        .long("blockchain_service_url")
                        .value_name("URL")
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("clandestine_port")
                        .long("clandestine_port")
                        .value_name("CLANDESTINE_PORT")
                        .empty_values(false)
                        .validator(Validators::validate_clandestine_port)
                        .help(&CLANDESTINE_PORT_HELP),
                )
                .arg(
                    Arg::with_name("data_directory")
                        .long("data_directory")
                        .value_name("DATA_DIRECTORY")
                        .empty_values(false)
                        .default_value(&DEFAULT_DATA_DIR_VALUE),
                )
                .arg(
                    Arg::with_name("dns_servers")
                        .long("dns_servers")
                        .value_name("DNS_SERVERS")
                        .takes_value(true)
                        .required(true)
                        .use_delimiter(true)
                        .validator(Validators::validate_ip_address),
                )
                .arg(
                    Arg::with_name("ip")
                        .long("ip")
                        .value_name("IP")
                        .takes_value(true)
                        .default_value(&DEFAULT_IP_VALUE)
                        .validator(Validators::validate_ip_address),
                )
                .arg(
                    Arg::with_name("log_level")
                        .long("log_level")
                        .value_name("FILTER")
                        .takes_value(true)
                        .possible_values(&["error", "warn", "info", "debug", "trace", "off"])
                        .default_value("warn")
                        .case_insensitive(true),
                )
                .arg(
                    Arg::with_name("neighbors")
                        .long("neighbors")
                        .value_name("NODE_DESCRIPTORS")
                        .takes_value(true)
                        .use_delimiter(true)
                        .requires("ip")
                        .validator(|s| NodeDescriptor::from_str(&s).map(|_| ())),
                )
                .arg(
                    Arg::with_name("ui_port")
                        .long("ui_port")
                        .value_name("UI_PORT")
                        .takes_value(true)
                        .default_value(&DEFAULT_UI_PORT_VALUE)
                        .validator(Validators::validate_ui_port)
                        .help(&UI_PORT_HELP),
                )
                .arg(
                    Arg::with_name("wallet_address")
                        .long("wallet_address")
                        .value_name("WALLET_ADDRESS")
                        .takes_value(true)
                        .default_value(&DEFAULT_EARNING_WALLET_VALUE)
                        .hide_default_value(true)
                        .validator(Validators::validate_ethereum_address)
                        .help("Must be 42 characters long, contain only hex and start with 0x"),
                )
                .arg(
                    Arg::with_name("consuming_private_key")
                        .long("consuming_private_key")
                        .value_name("PRIVATE_KEY")
                        .takes_value(true)
                        .validator(Validators::validate_private_key)
                        .help("Must be 64 characters long and contain only hex"),
                )
                .arg(
                    Arg::with_name("crash_point")
                        .long("crash_point")
                        .value_name("CRASH_POINT")
                        .takes_value(true)
                        .default_value(&DEFAULT_CRASH_POINT_VALUE)
                        .possible_values(&CrashPoint::variants())
                        .case_insensitive(true)
                        .hidden(true)
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
        let multi_config = MultiConfig::new(
            &self.app,
            vec![
                Box::new(EnvironmentVCL::new(&self.app)),
                Box::new(CommandLineVCL::new(args.clone())),
            ],
        );
        let config_file_path = value_m!(multi_config, "config_file", PathBuf)
            .expect("config_file should be defaulted");
        let user_specified = multi_config.arg_matches().occurrences_of("config_file") > 0;
        let data_directory: PathBuf = value_m!(multi_config, "data_directory", PathBuf)
            .expect("data_directory should be defaulted");
        (data_directory.join(config_file_path), user_specified)
    }

    fn parse_args(&self, multi_config: &MultiConfig, config: &mut BootstrapperConfig) {
        config.blockchain_bridge_config.blockchain_service_url =
            value_m!(multi_config, "blockchain_service_url", String);

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

        config.neighborhood_config.neighbor_configs =
            values_m!(multi_config, "neighbors", NodeDescriptor);

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

        // TODO: In real life this should come from a command-line parameter
        config.neighborhood_config.consuming_wallet = Some(TEMPORARY_CONSUMING_WALLET.clone());

        config.blockchain_bridge_config.consuming_private_key =
            value_m!(multi_config, "consuming_private_key", String);
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
    use super::*;
    use crate::multi_config::VirtualCommandLine;
    use crate::sub_lib::cryptde::PublicKey;
    use crate::sub_lib::neighborhood::sentinel_ip_addr;
    use crate::sub_lib::node_addr::NodeAddr;
    use crate::sub_lib::wallet::Wallet;
    use crate::test_utils::environment_guard::EnvironmentGuard;
    use std::net::Ipv4Addr;
    use std::net::SocketAddr;
    use std::str::FromStr;

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
            String::from("--dns_servers"),
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
        let args: Vec<String> = vec!["SubstratumNode", "--dns_servers", "1.2.3.4"]
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
    fn parse_args_creates_configurations() {
        let _guard = EnvironmentGuard::new();
        let args: Vec<String> = vec![
            "SubstratumNode",
            "--config_file",
            "specified_config.toml",
            "--dns_servers",
            "12.34.56.78,23.45.67.89",
            "--neighbors",
            "QmlsbA:1.2.3.4:1234;2345,VGVk:2.3.4.5:3456;4567",
            "--ip",
            "34.56.78.90",
            "--clandestine_port",
            "1234",
            "--ui_port",
            "5335",
            "--wallet_address",
            "0xbDfeFf9A1f4A1bdF483d680046344316019C58CF",
            "--data_directory",
            "~/.booga",
            "--blockchain_service_url",
            "http://127.0.0.1:8545",
            "--log_level",
            "trace",
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

        subject.parse_args(&multi_config, &mut config);

        assert_eq!(
            Some(PathBuf::from("specified_config.toml")),
            value_m!(multi_config, "config_file", PathBuf)
        );
        assert_eq!(
            vec!(
                SocketAddr::from_str("12.34.56.78:53").unwrap(),
                SocketAddr::from_str("23.45.67.89:53").unwrap()
            ),
            config.dns_servers,
        );
        assert_eq!(
            vec!(
                NodeDescriptor {
                    public_key: PublicKey::new(b"Bill"),
                    node_addr: NodeAddr::new(
                        &IpAddr::from_str("1.2.3.4").unwrap(),
                        &vec!(1234, 2345)
                    )
                },
                NodeDescriptor {
                    public_key: PublicKey::new(b"Ted"),
                    node_addr: NodeAddr::new(
                        &IpAddr::from_str("2.3.4.5").unwrap(),
                        &vec!(3456, 4567)
                    )
                }
            ),
            config.neighborhood_config.neighbor_configs,
        );
        assert_eq!(
            IpAddr::V4(Ipv4Addr::new(34, 56, 78, 90)),
            config.neighborhood_config.local_ip_addr,
        );
        assert_eq!(config.ui_gateway_config.ui_port, 5335);
        let earning_wallet = Wallet::new("0xbDfeFf9A1f4A1bdF483d680046344316019C58CF");
        assert_eq!(earning_wallet, config.neighborhood_config.earning_wallet);
        assert_eq!(earning_wallet, config.accountant_config.earning_wallet);
        assert_eq!(
            Wallet::new("0xbDfeFf9A1f4A1bdF483d680046344316019C58CF"),
            config.neighborhood_config.earning_wallet,
        );
        let expected_port_list: Vec<u16> = vec![];
        assert_eq!(
            expected_port_list,
            config.neighborhood_config.clandestine_port_list
        );
        assert_eq!(
            Some("http://127.0.0.1:8545".to_string()),
            config.blockchain_bridge_config.blockchain_service_url
        );
        assert_eq!(PathBuf::from("~/.booga"), config.data_directory,);
        assert_eq!(Some(1234u16), config.clandestine_port_opt);
        assert_eq!(
            Some("1234567891123456789212345678913234567894123456789512345678961234".to_string()),
            config.blockchain_bridge_config.consuming_private_key
        );
    }

    #[test]
    fn parse_args_creates_configuration_with_defaults() {
        let _guard = EnvironmentGuard::new();
        let args: Vec<String> = vec!["SubstratumNode", "--dns_servers", "12.34.56.78,23.45.67.89"]
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

        subject.parse_args(&multi_config, &mut config);

        assert_eq!(
            Some(PathBuf::from("config.toml")),
            value_m!(multi_config, "config_file", PathBuf)
        );
        assert_eq!(
            vec!(
                SocketAddr::from_str("12.34.56.78:53").unwrap(),
                SocketAddr::from_str("23.45.67.89:53").unwrap()
            ),
            config.dns_servers,
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
    }

    #[test]
    fn no_parameters_produces_configuration_for_crash_point() {
        let args = make_default_cli_params();
        let mut config = BootstrapperConfig::new();
        let subject = NodeConfiguratorReal::new();
        let vcl = Box::new(CommandLineVCL::new(args));
        let multi_config = MultiConfig::new(&subject.app, vec![vcl]);

        subject.parse_args(&multi_config, &mut config);

        assert_eq!(config.crash_point, CrashPoint::None);
    }

    #[test]
    fn with_parameters_produces_configuration_for_crash_point() {
        let mut args = make_default_cli_params();
        let crash_args = vec![String::from("--crash_point"), String::from("panic")];
        args.extend(crash_args);
        let mut config = BootstrapperConfig::new();
        let subject = NodeConfiguratorReal::new();
        let vcl = Box::new(CommandLineVCL::new(args));
        let multi_config = MultiConfig::new(&subject.app, vec![vcl]);

        subject.parse_args(&multi_config, &mut config);

        assert_eq!(config.crash_point, CrashPoint::Panic);
    }

    #[test]
    #[should_panic(expected = "could not be read: ")]
    fn generate_configuration_senses_when_user_specifies_config_file() {
        let subject = NodeConfiguratorReal::new();
        let args = vec![
            "SubstratumNode",
            "--dns_servers",
            "1.2.3.4",
            "--config_file",
            "booga.toml", // nonexistent config file: should stimulate panic because user-specified
        ]
        .into_iter()
        .map(String::from)
        .collect::<Vec<String>>();
        subject.generate_configuration(&args);
    }
}
