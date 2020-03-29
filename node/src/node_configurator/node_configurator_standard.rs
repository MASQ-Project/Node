// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

use crate::bootstrapper::BootstrapperConfig;
use crate::node_configurator::{app_head, initialize_database, NodeConfigurator};
use clap::App;
use indoc::indoc;
use masq_lib::command::StdStreams;
use masq_lib::crash_point::CrashPoint;
use masq_lib::shared_schema::UI_PORT_HELP;
use masq_lib::shared_schema::{shared_app, ui_port_arg};

pub struct NodeConfiguratorStandardPrivileged {}

impl NodeConfigurator<BootstrapperConfig> for NodeConfiguratorStandardPrivileged {
    fn configure(&self, args: &Vec<String>, streams: &mut StdStreams) -> BootstrapperConfig {
        let app = app();
        let multi_config = standard::make_service_mode_multi_config(&app, args);
        let mut bootstrapper_config = BootstrapperConfig::new();
        standard::establish_port_configurations(&mut bootstrapper_config);
        standard::privileged_parse_args(&multi_config, &mut bootstrapper_config, streams);
        bootstrapper_config
    }
}

pub struct NodeConfiguratorStandardUnprivileged {
    privileged_config: BootstrapperConfig,
}

impl NodeConfigurator<BootstrapperConfig> for NodeConfiguratorStandardUnprivileged {
    fn configure(&self, args: &Vec<String>, streams: &mut StdStreams<'_>) -> BootstrapperConfig {
        let app = app();
        let persistent_config = initialize_database(
            &self.privileged_config.data_directory,
            self.privileged_config.blockchain_bridge_config.chain_id,
        );
        let mut unprivileged_config = BootstrapperConfig::new();
        let multi_config = standard::make_service_mode_multi_config(&app, args);
        standard::unprivileged_parse_args(
            &multi_config,
            &mut unprivileged_config,
            streams,
            persistent_config.as_ref(),
        );
        standard::configure_database(&unprivileged_config, persistent_config.as_ref());
        unprivileged_config
    }
}

impl NodeConfiguratorStandardUnprivileged {
    pub fn new(privileged_config: &BootstrapperConfig) -> Self {
        Self {
            privileged_config: privileged_config.clone(),
        }
    }
}

const HELP_TEXT: &str = indoc!(
    r"ADDITIONAL HELP:
    If you want to generate wallets to earn money into and spend money from, try:

        MASQNode --help --generate-wallet

    If you already have a set of wallets you want Node to use, try:

        MASQNode --help --recover-wallet

    MASQ Node listens for connections from other Nodes using the computer's
    network interface. Configuring the internet router for port forwarding is a necessary
    step for Node users to permit network communication between Nodes.

    Once started, Node prints the node descriptor to the console. The descriptor
    indicates the required port needing to be forwarded by the network router. The port is
    the last number in the descriptor, as shown below:

    95VjByq5tEUUpDcczA//zXWGE6+7YFEvzN4CDVoPbWw:86.75.30.9:1234 for testnet
                                               ^           ^^^^
    95VjByq5tEUUpDcczA//zXWGE6+7YFEvzN4CDVoPbWw@86.75.30.9:1234 for mainnet
                                               ^           ^^^^
    Note: testnet uses ':' to separate the encoded key from the IP address.
          mainnet uses '@' to separate the encoded key from the IP address.
    Steps To Forwarding Ports In The Router
        1. Log in to the router.
        2. Navigate to the router's port forwarding section, also frequently called virtual server.
        3. Create the port forwarding entries in the router."
);

pub fn app() -> App<'static, 'static> {
    shared_app(app_head().after_help(HELP_TEXT)).arg(ui_port_arg(&UI_PORT_HELP))
}

pub mod standard {
    use super::*;
    use std::net::IpAddr;
    use std::net::SocketAddr;

    use clap::{value_t, values_t};
    use log::LevelFilter;

    use crate::blockchain::bip32::Bip32ECKeyPair;
    use crate::blockchain::blockchain_interface::chain_id_from_name;
    use crate::bootstrapper::PortConfiguration;
    use crate::http_request_start_finder::HttpRequestDiscriminatorFactory;
    use crate::node_configurator::{
        determine_config_file_path, mnemonic_seed_exists, real_user_data_directory_and_chain_id,
        request_existing_db_password,
    };
    use crate::persistent_configuration::PersistentConfiguration;
    use crate::sub_lib::accountant::DEFAULT_EARNING_WALLET;
    use crate::sub_lib::cryptde::{CryptDE, PlainData, PublicKey};
    use crate::sub_lib::cryptde_null::CryptDENull;
    use crate::sub_lib::cryptde_real::CryptDEReal;
    use crate::sub_lib::neighborhood::{
        NeighborhoodConfig, NeighborhoodMode, NodeDescriptor, DEFAULT_RATE_PACK,
    };
    use crate::sub_lib::node_addr::NodeAddr;
    use crate::sub_lib::wallet::Wallet;
    use crate::test_utils::DEFAULT_CHAIN_ID;
    use crate::tls_discriminator_factory::TlsDiscriminatorFactory;
    use itertools::Itertools;
    use masq_lib::constants::{HTTP_PORT, TLS_PORT};
    use masq_lib::multi_config::{CommandLineVcl, ConfigFileVcl, EnvironmentVcl, MultiConfig};
    use rustc_hex::{FromHex, ToHex};
    use std::convert::TryInto;
    use std::str::FromStr;

    pub fn make_service_mode_multi_config<'a>(app: &'a App, args: &Vec<String>) -> MultiConfig<'a> {
        let (config_file_path, user_specified) = determine_config_file_path(app, args);
        MultiConfig::new(
            &app,
            vec![
                Box::new(CommandLineVcl::new(args.clone())),
                Box::new(EnvironmentVcl::new(&app)),
                Box::new(ConfigFileVcl::new(&config_file_path, user_specified)),
            ],
        )
    }

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
        privileged_config: &mut BootstrapperConfig,
        _streams: &mut StdStreams<'_>,
    ) {
        if let Some(chain_name) = value_m!(multi_config, "chain", String) {
            privileged_config.blockchain_bridge_config.chain_id =
                chain_id_from_name(chain_name.as_str());
        }

        privileged_config
            .blockchain_bridge_config
            .blockchain_service_url = value_m!(multi_config, "blockchain-service-url", String);

        let (real_user, data_directory, chain_id) =
            real_user_data_directory_and_chain_id(multi_config);
        privileged_config.real_user = real_user;
        privileged_config.data_directory = data_directory;
        privileged_config.blockchain_bridge_config.chain_id = chain_id;

        privileged_config.dns_servers = values_m!(multi_config, "dns-servers", IpAddr)
            .into_iter()
            .map(|ip| SocketAddr::from((ip, 53)))
            .collect();

        privileged_config.log_level =
            value_m!(multi_config, "log-level", LevelFilter).expect("Internal Error");

        privileged_config.ui_gateway_config.ui_port =
            value_m!(multi_config, "ui-port", u16).expect("Internal Error");

        privileged_config.crash_point =
            value_m!(multi_config, "crash-point", CrashPoint).expect("Internal Error");

        match value_m!(multi_config, "fake-public-key", String) {
            None => (),
            Some(public_key_str) => {
                let (main_public_key, alias_public_key) = match base64::decode(&public_key_str) {
                    Ok(mut key) => {
                        let main_public_key = PublicKey::new(&key);
                        key.reverse();
                        let alias_public_key = PublicKey::new(&key);
                        (main_public_key, alias_public_key)
                    }
                    Err(_) => panic!("Invalid fake public key: {}", public_key_str),
                };
                let main_cryptde_null = CryptDENull::from(
                    &main_public_key,
                    privileged_config.blockchain_bridge_config.chain_id,
                );
                let alias_cryptde_null = CryptDENull::from(
                    &alias_public_key,
                    privileged_config.blockchain_bridge_config.chain_id,
                );
                privileged_config.main_cryptde_null_opt = Some(main_cryptde_null);
                privileged_config.alias_cryptde_null_opt = Some(alias_cryptde_null);
            }
        }
    }

    pub fn unprivileged_parse_args(
        multi_config: &MultiConfig,
        unprivileged_config: &mut BootstrapperConfig,
        streams: &mut StdStreams<'_>,
        persistent_config: &dyn PersistentConfiguration,
    ) {
        unprivileged_config.clandestine_port_opt = value_m!(multi_config, "clandestine-port", u16);
        unprivileged_config.blockchain_bridge_config.gas_price =
            value_m!(multi_config, "gas-price", u64);
        get_wallets(
            streams,
            multi_config,
            persistent_config,
            unprivileged_config,
        );
        unprivileged_config.neighborhood_config = make_neighborhood_config(
            multi_config,
            streams,
            persistent_config,
            unprivileged_config,
        );
    }

    pub fn configure_database(
        config: &BootstrapperConfig,
        persistent_config: &dyn PersistentConfiguration,
    ) {
        if let Some(port) = config.clandestine_port_opt {
            persistent_config.set_clandestine_port(port)
        }
        if persistent_config.earning_wallet_address().is_none() {
            persistent_config.set_earning_wallet_address(&config.earning_wallet.to_string());
        }
        if let Some(gas_price) = config.blockchain_bridge_config.gas_price {
            persistent_config.set_gas_price(gas_price)
        }
        match &config.consuming_wallet {
            Some(consuming_wallet)
                if persistent_config
                    .consuming_wallet_derivation_path()
                    .is_none()
                    && persistent_config.consuming_wallet_public_key().is_none() =>
            {
                let keypair: Bip32ECKeyPair = match consuming_wallet.clone().try_into() {
                    Err(_) => {
                        panic!("Internal error: consuming wallet must be derived from keypair")
                    }
                    Ok(keypair) => keypair,
                };
                let public_key = PlainData::new(keypair.secret().public().bytes());
                persistent_config.set_consuming_wallet_public_key(&public_key)
            }
            _ => (),
        }
    }

    pub fn get_wallets(
        streams: &mut StdStreams,
        multi_config: &MultiConfig,
        persistent_config: &dyn PersistentConfiguration,
        config: &mut BootstrapperConfig,
    ) {
        let earning_wallet_opt =
            standard::get_earning_wallet_from_address(multi_config, persistent_config);
        let mut consuming_wallet_opt =
            standard::get_consuming_wallet_from_private_key(multi_config, persistent_config);
        if earning_wallet_opt.is_some()
            && consuming_wallet_opt.is_some()
            && mnemonic_seed_exists(persistent_config)
        {
            panic!("Cannot use --consuming-private-key and earning wallet address when database contains mnemonic seed")
        }

        if (earning_wallet_opt.is_none() || consuming_wallet_opt.is_none())
            && mnemonic_seed_exists(persistent_config)
        {
            if let Some(db_password) =
                standard::get_db_password(multi_config, streams, config, persistent_config)
            {
                if consuming_wallet_opt.is_none() {
                    consuming_wallet_opt = standard::get_consuming_wallet_opt_from_derivation_path(
                        persistent_config,
                        &db_password,
                    );
                } else if persistent_config
                    .consuming_wallet_derivation_path()
                    .is_some()
                {
                    panic!("Cannot use --consuming-private-key when database contains mnemonic seed and consuming wallet derivation path")
                }
            }
        }
        config.consuming_wallet = consuming_wallet_opt;
        config.earning_wallet = match earning_wallet_opt {
            Some(earning_wallet) => earning_wallet,
            None => DEFAULT_EARNING_WALLET.clone(),
        };
    }

    pub fn make_neighborhood_config(
        multi_config: &MultiConfig,
        streams: &mut StdStreams,
        persistent_config: &dyn PersistentConfiguration,
        unprivileged_config: &mut BootstrapperConfig,
    ) -> NeighborhoodConfig {
        let neighbor_configs: Vec<NodeDescriptor> = {
            match convert_ci_configs(multi_config) {
                Some(configs) => configs,
                None => get_past_neighbors(
                    multi_config,
                    streams,
                    persistent_config,
                    unprivileged_config,
                ),
            }
        };
        NeighborhoodConfig {
            mode: make_neighborhood_mode(multi_config, neighbor_configs),
        }
    }

    pub fn convert_ci_configs(multi_config: &MultiConfig) -> Option<Vec<NodeDescriptor>> {
        let cli_configs = values_m!(multi_config, "neighbors", String);
        if !cli_configs.is_empty() {
            let dummy_cryptde: Box<dyn CryptDE> = {
                if value_m!(multi_config, "fake-public-key", String) == None {
                    Box::new(CryptDEReal::new(DEFAULT_CHAIN_ID))
                } else {
                    Box::new(CryptDENull::new(DEFAULT_CHAIN_ID))
                }
            };
            Some(
                cli_configs
                    .into_iter()
                    .map(
                        |s| match NodeDescriptor::from_str(dummy_cryptde.as_ref(), &s) {
                            Ok(nd) => nd,
                            Err(e) => panic!("Neighbor syntax error. {}", e),
                        },
                    )
                    .collect_vec(),
            )
        } else {
            None
        }
    }

    pub fn get_past_neighbors(
        multi_config: &MultiConfig,
        streams: &mut StdStreams,
        persistent_config: &dyn PersistentConfiguration,
        unprivileged_config: &mut BootstrapperConfig,
    ) -> Vec<NodeDescriptor> {
        match &standard::get_db_password(
            multi_config,
            streams,
            unprivileged_config,
            persistent_config,
        ) {
            Some(db_password) => match persistent_config.past_neighbors(db_password) {
                Ok(Some(past_neighbors)) => past_neighbors,
                Ok(None) => vec![],
                Err(e) => panic!("Could not retrieve past neighbors: {:?}", e),
            },
            None => vec![],
        }
    }

    fn make_neighborhood_mode(
        multi_config: &MultiConfig,
        neighbor_configs: Vec<NodeDescriptor>,
    ) -> NeighborhoodMode {
        match value_m!(multi_config, "neighborhood-mode", String) {
            Some(ref s) if s == "standard" => NeighborhoodMode::Standard(
                NodeAddr::new(
                    &value_m!(multi_config, "ip", IpAddr).expect(
                        "Node cannot run as --neighborhood_mode standard without --ip specified",
                    ),
                    &vec![],
                ),
                neighbor_configs,
                DEFAULT_RATE_PACK,
            ),
            Some(ref s) if s == "originate-only" => {
                if neighbor_configs.is_empty() {
                    panic! ("Node cannot run as --neighborhood_mode originate-only without --neighbors specified")
                }
                NeighborhoodMode::OriginateOnly(neighbor_configs, DEFAULT_RATE_PACK)
            }
            Some(ref s) if s == "consume-only" => {
                if neighbor_configs.is_empty() {
                    panic! ("Node cannot run as --neighborhood_mode consume-only without --neighbors specified")
                }
                NeighborhoodMode::ConsumeOnly(neighbor_configs)
            }
            Some(ref s) if s == "zero-hop" => {
                if !neighbor_configs.is_empty() {
                    panic!("Node cannot run as --neighborhood_mode zero-hop if --neighbors is specified")
                }
                if value_m!(multi_config, "ip", IpAddr).is_some() {
                    panic!("Node cannot run as --neighborhood_mode zero-hop if --ip is specified")
                }
                NeighborhoodMode::ZeroHop
            }
            // These two cases are untestable
            Some(ref s) => panic!(
                "--neighborhood_mode {} has not been properly provided for in the code",
                s
            ),
            None => panic!("--neighborhood_mode is not properly defaulted in clap"),
        }
    }

    fn get_earning_wallet_from_address(
        multi_config: &MultiConfig,
        persistent_config: &dyn PersistentConfiguration,
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
                if wallet.to_string().to_lowercase() == address.to_lowercase() {
                    Some(wallet)
                } else {
                    panic!("Cannot use --earning-wallet to specify an address ({}) different from that previously set ({})", address, wallet)
                }
            }
        }
    }

    fn get_consuming_wallet_opt_from_derivation_path(
        persistent_config: &dyn PersistentConfiguration,
        db_password: &str,
    ) -> Option<Wallet> {
        match persistent_config.consuming_wallet_derivation_path() {
            None => None,
            Some(derivation_path) => match persistent_config.mnemonic_seed(db_password) {
                Ok(None) => None,
                Ok(Some(mnemonic_seed)) => {
                    let keypair =
                        Bip32ECKeyPair::from_raw(mnemonic_seed.as_ref(), &derivation_path)
                            .unwrap_or_else(|_| {
                                panic!(
                            "Error making keypair from mnemonic seed and derivation path {}",
                            derivation_path
                        )
                            });
                    Some(Wallet::from(keypair))
                }
                Err(e) => panic!("{:?}", e),
            },
        }
    }

    fn get_consuming_wallet_from_private_key(
        multi_config: &MultiConfig,
        persistent_config: &dyn PersistentConfiguration,
    ) -> Option<Wallet> {
        match value_m!(multi_config, "consuming-private-key", String) {
            Some(consuming_private_key_string) => {
                match consuming_private_key_string.from_hex::<Vec<u8>>() {
                    Ok(raw_secret) => match Bip32ECKeyPair::from_raw_secret(&raw_secret[..]) {
                        Ok(keypair) => {
                            match persistent_config.consuming_wallet_public_key() {
                                None => (),
                                Some(established_public_key_hex) => {
                                    let proposed_public_key_hex =
                                        keypair.secret().public().bytes().to_hex::<String>();
                                    if proposed_public_key_hex != established_public_key_hex {
                                        panic!("The specified --consuming-private-key does not denote the same consuming wallet you have used in the past.")
                                    }
                                }
                            }
                            Some(Wallet::from(keypair))
                        }
                        Err(e) => panic!("Cannot create consuming wallet from private key {}", e),
                    },
                    Err(e) => panic!("Unable to parse private key {}", e),
                }
            }
            None => None,
        }
    }

    pub fn get_db_password(
        multi_config: &MultiConfig,
        streams: &mut StdStreams,
        config: &mut BootstrapperConfig,
        persistent_config: &dyn PersistentConfiguration,
    ) -> Option<String> {
        if config.db_password_opt.is_some() {
            return config.db_password_opt.clone();
        }
        let db_password_opt = match value_user_specified_m!(multi_config, "db-password", String) {
            (Some(dbp), _) => Some(dbp),
            (None, false) => None,
            (None, true) => request_existing_db_password(
                streams,
                Some("Decrypt information from previous runs"),
                "Enter password: ",
                persistent_config,
            ),
        };
        if db_password_opt.is_some() {
            config.db_password_opt = db_password_opt.clone();
        };
        db_password_opt
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blockchain::bip32::Bip32ECKeyPair;
    use crate::blockchain::blockchain_interface::{chain_id_from_name, contract_address};
    use crate::bootstrapper::RealUser;
    use crate::config_dao::{ConfigDao, ConfigDaoReal};
    use crate::database::db_initializer::{DbInitializer, DbInitializerReal};
    use crate::persistent_configuration::{PersistentConfigError, PersistentConfigurationReal};
    use crate::sub_lib::accountant::DEFAULT_EARNING_WALLET;
    use crate::sub_lib::cryptde::{CryptDE, PlainData, PublicKey};
    use crate::sub_lib::cryptde_null::CryptDENull;
    use crate::sub_lib::cryptde_real::CryptDEReal;
    use crate::sub_lib::neighborhood::{
        NeighborhoodConfig, NeighborhoodMode, NodeDescriptor, DEFAULT_RATE_PACK,
    };
    use crate::sub_lib::node_addr::NodeAddr;
    use crate::sub_lib::wallet::Wallet;
    use crate::test_utils::persistent_configuration_mock::PersistentConfigurationMock;
    use crate::test_utils::{main_cryptde, ArgsBuilder, TEST_DEFAULT_CHAIN_NAME};
    use crate::test_utils::{make_default_persistent_configuration, DEFAULT_CHAIN_ID};
    use masq_lib::constants::{DEFAULT_CHAIN_NAME, DEFAULT_GAS_PRICE, DEFAULT_UI_PORT};
    use masq_lib::multi_config::{
        CommandLineVcl, ConfigFileVcl, MultiConfig, NameValueVclArg, VclArg, VirtualCommandLine,
    };
    use masq_lib::test_utils::environment_guard::EnvironmentGuard;
    use masq_lib::test_utils::fake_stream_holder::{ByteArrayWriter, FakeStreamHolder};
    use masq_lib::test_utils::utils::ensure_node_home_directory_exists;
    use rustc_hex::{FromHex, ToHex};
    use std::fs::File;
    use std::io::Cursor;
    use std::io::Write;
    use std::net::IpAddr;
    use std::net::SocketAddr;
    use std::path::PathBuf;
    use std::str::FromStr;
    use std::sync::{Arc, Mutex};

    fn make_default_cli_params() -> ArgsBuilder {
        ArgsBuilder::new().param("--ip", "1.2.3.4")
    }

    #[test]
    fn make_neighborhood_config_standard_happy_path() {
        let multi_config = MultiConfig::new(
            &app(),
            vec![Box::new(CommandLineVcl::new(
                ArgsBuilder::new()
                    .param("--neighborhood-mode", "standard")
                    .param("--ip", "1.2.3.4")
                    .param(
                        "--neighbors",
                        "mhtjjdMt7Gyoebtb1yiK0hdaUx6j84noHdaAHeDR1S4:1.2.3.4:1234;2345,Si06R3ulkOjJOLw1r2R9GOsY87yuinHU/IHK2FJyGnk:2.3.4.5:3456;4567",
                    )
                    .into(),
            ))],
        );

        let result = standard::make_neighborhood_config(
            &multi_config,
            &mut FakeStreamHolder::new().streams(),
            &make_default_persistent_configuration(),
            &mut BootstrapperConfig::new(),
        );

        let dummy_cryptde = CryptDEReal::new(DEFAULT_CHAIN_ID);
        assert_eq!(
            result,
            NeighborhoodConfig {
                mode: NeighborhoodMode::Standard(
                    NodeAddr::new(&IpAddr::from_str("1.2.3.4").unwrap(), &vec![]),
                    vec![
                        NodeDescriptor::from_str(
                            &dummy_cryptde,
                            "mhtjjdMt7Gyoebtb1yiK0hdaUx6j84noHdaAHeDR1S4:1.2.3.4:1234;2345"
                        )
                        .unwrap(),
                        NodeDescriptor::from_str(
                            &dummy_cryptde,
                            "Si06R3ulkOjJOLw1r2R9GOsY87yuinHU/IHK2FJyGnk:2.3.4.5:3456;4567"
                        )
                        .unwrap()
                    ],
                    DEFAULT_RATE_PACK
                )
            }
        );
    }

    #[test]
    #[should_panic(
        expected = "Node cannot run as --neighborhood_mode standard without --ip specified"
    )]
    fn make_neighborhood_config_standard_missing_ip() {
        let multi_config = MultiConfig::new(
            &app(),
            vec![Box::new(CommandLineVcl::new(
                ArgsBuilder::new()
                    .param("--neighborhood-mode", "standard")
                    .param(
                        "--neighbors",
                        "QmlsbA:1.2.3.4:1234;2345,VGVk:2.3.4.5:3456;4567",
                    )
                    .param("--fake-public-key", "booga")
                    .into(),
            ))],
        );

        standard::make_neighborhood_config(
            &multi_config,
            &mut FakeStreamHolder::new().streams(),
            &make_default_persistent_configuration(),
            &mut BootstrapperConfig::new(),
        );
    }

    #[test]
    fn make_neighborhood_config_originate_only_doesnt_need_ip() {
        let multi_config = MultiConfig::new(
            &app(),
            vec![Box::new(CommandLineVcl::new(
                ArgsBuilder::new()
                    .param("--neighborhood-mode", "originate-only")
                    .param(
                        "--neighbors",
                        "QmlsbA:1.2.3.4:1234;2345,VGVk:2.3.4.5:3456;4567",
                    )
                    .param("--fake-public-key", "booga")
                    .into(),
            ))],
        );

        let result = standard::make_neighborhood_config(
            &multi_config,
            &mut FakeStreamHolder::new().streams(),
            &make_default_persistent_configuration(),
            &mut BootstrapperConfig::new(),
        );

        assert_eq!(
            result,
            NeighborhoodConfig {
                mode: NeighborhoodMode::OriginateOnly(
                    vec![
                        NodeDescriptor::from_str(main_cryptde(), "QmlsbA:1.2.3.4:1234;2345")
                            .unwrap(),
                        NodeDescriptor::from_str(main_cryptde(), "VGVk:2.3.4.5:3456;4567").unwrap()
                    ],
                    DEFAULT_RATE_PACK
                )
            }
        );
    }

    #[test]
    #[should_panic(
        expected = "Node cannot run as --neighborhood_mode originate-only without --neighbors specified"
    )]
    fn make_neighborhood_config_originate_only_does_need_at_least_one_neighbor() {
        let multi_config = MultiConfig::new(
            &app(),
            vec![Box::new(CommandLineVcl::new(
                ArgsBuilder::new()
                    .param("--neighborhood-mode", "originate-only")
                    .into(),
            ))],
        );

        standard::make_neighborhood_config(
            &multi_config,
            &mut FakeStreamHolder::new().streams(),
            &make_default_persistent_configuration().check_password_result(Some(false)),
            &mut BootstrapperConfig::new(),
        );
    }

    #[test]
    fn make_neighborhood_config_consume_only_doesnt_need_ip() {
        let multi_config = MultiConfig::new(
            &app(),
            vec![Box::new(CommandLineVcl::new(
                ArgsBuilder::new()
                    .param("--neighborhood-mode", "consume-only")
                    .param(
                        "--neighbors",
                        "QmlsbA:1.2.3.4:1234;2345,VGVk:2.3.4.5:3456;4567",
                    )
                    .param("--fake-public-key", "booga")
                    .into(),
            ))],
        );

        let result = standard::make_neighborhood_config(
            &multi_config,
            &mut FakeStreamHolder::new().streams(),
            &make_default_persistent_configuration(),
            &mut BootstrapperConfig::new(),
        );

        assert_eq!(
            result,
            NeighborhoodConfig {
                mode: NeighborhoodMode::ConsumeOnly(vec![
                    NodeDescriptor::from_str(main_cryptde(), "QmlsbA:1.2.3.4:1234;2345").unwrap(),
                    NodeDescriptor::from_str(main_cryptde(), "VGVk:2.3.4.5:3456;4567").unwrap()
                ],)
            }
        );
    }

    #[test]
    #[should_panic(
        expected = "Node cannot run as --neighborhood_mode consume-only without --neighbors specified"
    )]
    fn make_neighborhood_config_consume_only_does_need_at_least_one_neighbor() {
        let multi_config = MultiConfig::new(
            &app(),
            vec![Box::new(CommandLineVcl::new(
                ArgsBuilder::new()
                    .param("--neighborhood-mode", "consume-only")
                    .into(),
            ))],
        );

        standard::make_neighborhood_config(
            &multi_config,
            &mut FakeStreamHolder::new().streams(),
            &make_default_persistent_configuration().check_password_result(Some(false)),
            &mut BootstrapperConfig::new(),
        );
    }

    #[test]
    fn make_neighborhood_config_zero_hop_doesnt_need_ip_or_neighbors() {
        let multi_config = MultiConfig::new(
            &app(),
            vec![Box::new(CommandLineVcl::new(
                ArgsBuilder::new()
                    .param("--neighborhood-mode", "zero-hop")
                    .into(),
            ))],
        );

        let result = standard::make_neighborhood_config(
            &multi_config,
            &mut FakeStreamHolder::new().streams(),
            &make_default_persistent_configuration().check_password_result(Some(false)),
            &mut BootstrapperConfig::new(),
        );

        assert_eq!(
            result,
            NeighborhoodConfig {
                mode: NeighborhoodMode::ZeroHop
            }
        );
    }

    #[test]
    #[should_panic(
        expected = "Node cannot run as --neighborhood_mode zero-hop if --ip is specified"
    )]
    fn make_neighborhood_config_zero_hop_cant_tolerate_ip() {
        let multi_config = MultiConfig::new(
            &app(),
            vec![Box::new(CommandLineVcl::new(
                ArgsBuilder::new()
                    .param("--neighborhood-mode", "zero-hop")
                    .param("--ip", "1.2.3.4")
                    .into(),
            ))],
        );

        standard::make_neighborhood_config(
            &multi_config,
            &mut FakeStreamHolder::new().streams(),
            &make_default_persistent_configuration().check_password_result(Some(false)),
            &mut BootstrapperConfig::new(),
        );
    }

    #[test]
    #[should_panic(
        expected = "Node cannot run as --neighborhood_mode zero-hop if --neighbors is specified"
    )]
    fn make_neighborhood_config_zero_hop_cant_tolerate_neighbors() {
        let multi_config = MultiConfig::new(
            &app(),
            vec![Box::new(CommandLineVcl::new(
                ArgsBuilder::new()
                    .param("--neighborhood-mode", "zero-hop")
                    .param(
                        "--neighbors",
                        "QmlsbA:1.2.3.4:1234;2345,VGVk:2.3.4.5:3456;4567",
                    )
                    .param("--fake-public-key", "booga")
                    .into(),
            ))],
        );

        standard::make_neighborhood_config(
            &multi_config,
            &mut FakeStreamHolder::new().streams(),
            &make_default_persistent_configuration(),
            &mut BootstrapperConfig::new(),
        );
    }

    #[test]
    fn get_past_neighbors_handles_good_password_but_no_past_neighbors() {
        let multi_config = MultiConfig::new(&app(), vec![]);
        let persistent_config =
            make_default_persistent_configuration().past_neighbors_result(Ok(None));
        let mut unprivileged_config = BootstrapperConfig::new();
        unprivileged_config.db_password_opt = Some("password".to_string());

        let result = standard::get_past_neighbors(
            &multi_config,
            &mut FakeStreamHolder::new().streams(),
            &persistent_config,
            &mut unprivileged_config,
        );

        assert!(result.is_empty());
    }

    #[test]
    fn get_past_neighbors_handles_unavailable_password() {
        let multi_config = MultiConfig::new(&app(), vec![]);
        let persistent_config = make_default_persistent_configuration().check_password_result(None);
        let mut unprivileged_config = BootstrapperConfig::new();
        unprivileged_config.db_password_opt = Some("password".to_string());

        let result = standard::get_past_neighbors(
            &multi_config,
            &mut FakeStreamHolder::new().streams(),
            &persistent_config,
            &mut unprivileged_config,
        );

        assert!(result.is_empty());
    }

    #[test]
    #[should_panic(expected = "Could not retrieve past neighbors: PasswordError")]
    fn get_past_neighbors_does_not_like_error_getting_past_neighbors() {
        let multi_config = MultiConfig::new(&app(), vec![]);
        let persistent_config = PersistentConfigurationMock::new()
            .check_password_result(Some(false))
            .past_neighbors_result(Err(PersistentConfigError::PasswordError));
        let mut unprivileged_config = BootstrapperConfig::new();
        unprivileged_config.db_password_opt = Some("password".to_string());

        let _ = standard::get_past_neighbors(
            &multi_config,
            &mut FakeStreamHolder::new().streams(),
            &persistent_config,
            &mut unprivileged_config,
        );
    }

    #[test]
    #[should_panic(
        expected = "Neighbor syntax error. Should be <public key>[@ | :]<node address>, not 'ooga'"
    )]
    fn convert_ci_configs_does_not_like_neighbors_with_bad_syntax() {
        let multi_config = MultiConfig::new(
            &app(),
            vec![Box::new(CommandLineVcl::new(
                ArgsBuilder::new().param("--neighbors", "ooga,booga").into(),
            ))],
        );

        let _ = standard::convert_ci_configs(&multi_config);
    }

    #[test]
    fn can_read_parameters_from_config_file() {
        let _guard = EnvironmentGuard::new();
        let home_dir = ensure_node_home_directory_exists(
            "node_configurator",
            "can_read_parameters_from_config_file",
        );
        {
            let mut config_file = File::create(home_dir.join("config.toml")).unwrap();
            config_file
                .write_all(b"dns-servers = \"111.111.111.111,222.222.222.222\"\n")
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
            configuration.dns_servers,
            vec![
                SocketAddr::from_str("111.111.111.111:53").unwrap(),
                SocketAddr::from_str("222.222.222.222:53").unwrap(),
            ]
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
                .initialize(&home_dir.clone(), DEFAULT_CHAIN_ID)
                .unwrap(),
        )));
        let consuming_private_key =
            "89ABCDEF89ABCDEF89ABCDEF89ABCDEF89ABCDEF89ABCDEF89ABCDEF89ABCDEF";
        let config_file_path = home_dir.join("config.toml");
        {
            let mut config_file = File::create(&config_file_path).unwrap();
            writeln!(
                config_file,
                "consuming-private-key = \"{}\"",
                consuming_private_key
            )
            .unwrap();
        }
        let args = ArgsBuilder::new()
            .param("--data-directory", home_dir.to_str().unwrap())
            .param("--ip", "1.2.3.4");
        let mut bootstrapper_config = BootstrapperConfig::new();
        let multi_config = MultiConfig::new(
            &app(),
            vec![
                Box::new(CommandLineVcl::new(args.into())),
                Box::new(ConfigFileVcl::new(&config_file_path, false)),
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
            .as_payer(&public_key, &contract_address(DEFAULT_CHAIN_ID));
        let cryptdenull = CryptDENull::from(&public_key, DEFAULT_CHAIN_ID);
        assert!(
            payer.owns_secret_key(&cryptdenull.digest()),
            "Neighborhood config should have a WalletKind::KeyPair wallet"
        );
    }

    #[test]
    fn privileged_parse_args_creates_configurations() {
        let home_dir = ensure_node_home_directory_exists(
            "node_configurator",
            "privileged_parse_args_creates_configurations",
        );
        let args = ArgsBuilder::new()
            .param("--config-file", "specified_config.toml")
            .param("--dns-servers", "12.34.56.78,23.45.67.89")
            .param(
                "--neighbors",
                "QmlsbA:1.2.3.4:1234;2345,VGVk:2.3.4.5:3456;4567",
            )
            .param("--ip", "34.56.78.90")
            .param("--clandestine-port", "1234")
            .param("--ui-port", "5335")
            .param("--data-directory", home_dir.to_str().unwrap())
            .param("--blockchain-service-url", "http://127.0.0.1:8545")
            .param("--log-level", "trace")
            .param("--fake-public-key", "AQIDBA")
            .param("--db-password", "secret-db-password")
            .param(
                "--earning-wallet",
                "0x0123456789012345678901234567890123456789",
            )
            .param(
                "--consuming-private-key",
                "ABCDEF01ABCDEF01ABCDEF01ABCDEF01ABCDEF01ABCDEF01ABCDEF01ABCDEF01",
            )
            .param("--real-user", "999:999:/home/booga");
        let mut config = BootstrapperConfig::new();
        let vcls: Vec<Box<dyn VirtualCommandLine>> =
            vec![Box::new(CommandLineVcl::new(args.into()))];
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
        assert_eq!(config.ui_gateway_config.ui_port, 5335);
        assert_eq!(
            config.neighborhood_config,
            NeighborhoodConfig {
                mode: NeighborhoodMode::ZeroHop // not populated on the privileged side
            }
        );
        assert_eq!(
            config.blockchain_bridge_config.blockchain_service_url,
            Some("http://127.0.0.1:8545".to_string()),
        );
        assert_eq!(config.data_directory, home_dir);
        assert_eq!(
            config.main_cryptde_null_opt.unwrap().public_key(),
            &PublicKey::new(&[1, 2, 3, 4]),
        );
        assert_eq!(
            config.real_user,
            RealUser::new(Some(999), Some(999), Some(PathBuf::from("/home/booga")))
        );
    }

    #[test]
    fn unprivileged_parse_args_creates_configurations() {
        let home_dir = ensure_node_home_directory_exists(
            "node_configurator",
            "unprivileged_parse_args_creates_configurations",
        );
        let config_dao: Box<dyn ConfigDao> = Box::new(ConfigDaoReal::new(
            DbInitializerReal::new()
                .initialize(&home_dir.clone(), DEFAULT_CHAIN_ID)
                .unwrap(),
        ));
        let consuming_private_key_text =
            "ABCDEF01ABCDEF01ABCDEF01ABCDEF01ABCDEF01ABCDEF01ABCDEF01ABCDEF01";
        let consuming_private_key =
            PlainData::from(consuming_private_key_text.from_hex::<Vec<u8>>().unwrap());
        let persistent_config = PersistentConfigurationReal::new(config_dao);
        let password = "secret-db-password";
        let args = ArgsBuilder::new()
            .param("--config-file", "specified_config.toml")
            .param("--dns-servers", "12.34.56.78,23.45.67.89")
            .param(
                "--neighbors",
                "QmlsbA:1.2.3.4:1234;2345,VGVk:2.3.4.5:3456;4567",
            )
            .param("--ip", "34.56.78.90")
            .param("--clandestine-port", "1234")
            .param("--ui-port", "5335")
            .param("--data-directory", home_dir.to_str().unwrap())
            .param("--blockchain-service-url", "http://127.0.0.1:8545")
            .param("--log-level", "trace")
            .param("--fake-public-key", "AQIDBA")
            .param("--db-password", password)
            .param(
                "--earning-wallet",
                "0x0123456789012345678901234567890123456789",
            )
            .param("--consuming-private-key", consuming_private_key_text)
            .param("--real-user", "999:999:/home/booga");
        let mut config = BootstrapperConfig::new();
        let vcls: Vec<Box<dyn VirtualCommandLine>> =
            vec![Box::new(CommandLineVcl::new(args.into()))];
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
        assert_eq!(
            config.neighborhood_config,
            NeighborhoodConfig {
                mode: NeighborhoodMode::Standard(
                    NodeAddr::new(&IpAddr::from_str("34.56.78.90").unwrap(), &vec![]),
                    vec![
                        NodeDescriptor::from_str(main_cryptde(), "QmlsbA:1.2.3.4:1234;2345")
                            .unwrap(),
                        NodeDescriptor::from_str(main_cryptde(), "VGVk:2.3.4.5:3456;4567").unwrap(),
                    ],
                    DEFAULT_RATE_PACK.clone()
                )
            }
        );
    }

    #[test]
    fn unprivileged_parse_args_creates_configuration_with_defaults() {
        let args = ArgsBuilder::new().param("--ip", "1.2.3.4");
        let mut config = BootstrapperConfig::new();
        let vcls: Vec<Box<dyn VirtualCommandLine>> =
            vec![Box::new(CommandLineVcl::new(args.into()))];
        let multi_config = MultiConfig::new(&app(), vcls);

        standard::unprivileged_parse_args(
            &multi_config,
            &mut config,
            &mut FakeStreamHolder::new().streams(),
            &make_default_persistent_configuration().check_password_result(Some(false)),
        );

        assert_eq!(
            Some(PathBuf::from("config.toml")),
            value_m!(multi_config, "config-file", PathBuf)
        );
        assert_eq!(None, config.clandestine_port_opt);
        assert!(config
            .neighborhood_config
            .mode
            .neighbor_configs()
            .is_empty());
        assert_eq!(
            config
                .neighborhood_config
                .mode
                .node_addr_opt()
                .unwrap()
                .ip_addr(),
            IpAddr::from_str("1.2.3.4").unwrap(),
        );
        assert_eq!(config.earning_wallet, DEFAULT_EARNING_WALLET.clone(),);
        assert_eq!(config.consuming_wallet, None,);
    }

    #[test]
    fn unprivileged_parse_args_with_neighbor_in_database_but_not_command_line() {
        let args = ArgsBuilder::new()
            .param("--ip", "1.2.3.4")
            .param("--fake-public-key", "BORSCHT")
            .param("--db-password", "password");
        let mut config = BootstrapperConfig::new();
        config.db_password_opt = Some("password".to_string());
        let vcls: Vec<Box<dyn VirtualCommandLine>> =
            vec![Box::new(CommandLineVcl::new(args.into()))];
        let multi_config = MultiConfig::new(&app(), vcls);
        let past_neighbors_params_arc = Arc::new(Mutex::new(vec![]));
        let persistent_configuration = make_persistent_config(
            None,
            Some("password"),
            None,
            None,
            None,
            None,
            Some("AQIDBA:1.2.3.4:1234,AgMEBQ:2.3.4.5:2345"),
        )
        .past_neighbors_params(&past_neighbors_params_arc);

        standard::unprivileged_parse_args(
            &multi_config,
            &mut config,
            &mut FakeStreamHolder::new().streams(),
            &persistent_configuration,
        );

        assert_eq!(
            config.neighborhood_config.mode.neighbor_configs(),
            &vec![
                NodeDescriptor::from_str(main_cryptde(), "AQIDBA:1.2.3.4:1234").unwrap(),
                NodeDescriptor::from_str(main_cryptde(), "AgMEBQ:2.3.4.5:2345").unwrap(),
            ]
        );
        let past_neighbors_params = past_neighbors_params_arc.lock().unwrap();
        assert_eq!(past_neighbors_params[0], "password".to_string());
    }

    #[test]
    fn privileged_parse_args_creates_configuration_with_defaults() {
        let args = ArgsBuilder::new().param("--ip", "1.2.3.4");
        let mut config = BootstrapperConfig::new();
        let vcls: Vec<Box<dyn VirtualCommandLine>> =
            vec![Box::new(CommandLineVcl::new(args.into()))];
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
            vec!(SocketAddr::from_str("1.1.1.1:53").unwrap())
        );
        assert_eq!(config.crash_point, CrashPoint::None);
        assert_eq!(config.ui_gateway_config.ui_port, DEFAULT_UI_PORT);
        assert!(config.main_cryptde_null_opt.is_none());
        assert_eq!(config.real_user, RealUser::null().populate());
    }

    #[test]
    #[cfg(not(target_os = "windows"))]
    fn privileged_parse_args_with_real_user_defaults_data_directory_properly() {
        let args = ArgsBuilder::new()
            .param("--ip", "1.2.3.4")
            .param("--real-user", "::/home/booga");
        let mut config = BootstrapperConfig::new();
        let vcls: Vec<Box<dyn VirtualCommandLine>> =
            vec![Box::new(CommandLineVcl::new(args.into()))];
        let multi_config = MultiConfig::new(&app(), vcls);

        standard::privileged_parse_args(
            &multi_config,
            &mut config,
            &mut FakeStreamHolder::new().streams(),
        );

        #[cfg(target_os = "linux")]
        assert_eq!(
            config.data_directory,
            PathBuf::from("/home/booga/.local/share/MASQ").join(DEFAULT_CHAIN_NAME)
        );

        #[cfg(target_os = "macos")]
        assert_eq!(
            config.data_directory,
            PathBuf::from("/home/booga/Library/Application Support/MASQ").join(DEFAULT_CHAIN_NAME)
        );
    }

    fn make_multi_config<'a>(args: ArgsBuilder) -> MultiConfig<'a> {
        let vcls: Vec<Box<dyn VirtualCommandLine>> =
            vec![Box::new(CommandLineVcl::new(args.into()))];
        MultiConfig::new(&app(), vcls)
    }

    fn make_persistent_config(
        mnemonic_seed_prefix_opt: Option<&str>,
        db_password_opt: Option<&str>,
        consuming_wallet_private_key_opt: Option<&str>,
        consuming_wallet_derivation_path_opt: Option<&str>,
        earning_wallet_address_opt: Option<&str>,
        gas_price_opt: Option<&str>,
        past_neighbors_opt: Option<&str>,
    ) -> PersistentConfigurationMock {
        let mnemonic_seed_result = match (mnemonic_seed_prefix_opt, db_password_opt) {
            (None, None) => Ok(None),
            (None, Some(_)) => Ok(None),
            (Some(mnemonic_seed_prefix), _) => Ok(Some(make_mnemonic_seed(mnemonic_seed_prefix))),
        };
        let consuming_wallet_public_key_opt = match consuming_wallet_private_key_opt {
            None => None,
            Some(consuming_wallet_private_key_hex) => {
                let consuming_wallet_private_key = consuming_wallet_private_key_hex
                    .from_hex::<Vec<u8>>()
                    .unwrap();
                let keypair =
                    Bip32ECKeyPair::from_raw_secret(&consuming_wallet_private_key).unwrap();
                let consuming_wallet_public_key = keypair.secret().public();
                let consuming_wallet_public_key_bytes = consuming_wallet_public_key.bytes();
                let consuming_wallet_public_key_hex =
                    consuming_wallet_public_key_bytes.to_hex::<String>();
                Some(consuming_wallet_public_key_hex)
            }
        };
        let consuming_wallet_derivation_path_opt =
            consuming_wallet_derivation_path_opt.map(|x| x.to_string());
        let earning_wallet_from_address_opt = match earning_wallet_address_opt {
            None => None,
            Some(address) => Some(Wallet::from_str(address).unwrap()),
        };
        let gas_price = gas_price_opt
            .unwrap_or(DEFAULT_GAS_PRICE)
            .parse::<u64>()
            .unwrap();
        let past_neighbors_result = match (past_neighbors_opt, db_password_opt) {
            (Some(past_neighbors), Some(_)) => Ok(Some(
                past_neighbors
                    .split(",")
                    .map(|s| NodeDescriptor::from_str(main_cryptde(), s).unwrap())
                    .collect::<Vec<NodeDescriptor>>(),
            )),
            _ => Ok(None),
        };
        PersistentConfigurationMock::new()
            .mnemonic_seed_result(mnemonic_seed_result)
            .consuming_wallet_public_key_result(consuming_wallet_public_key_opt)
            .consuming_wallet_derivation_path_result(consuming_wallet_derivation_path_opt)
            .earning_wallet_from_address_result(earning_wallet_from_address_opt)
            .gas_price_result(gas_price)
            .past_neighbors_result(past_neighbors_result)
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
        let multi_config = make_multi_config(ArgsBuilder::new());
        let persistent_config = make_persistent_config(None, None, None, None, None, None, None);
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
        let multi_config = make_multi_config(
            ArgsBuilder::new()
                .param("--db-password", "password")
                .param("--consuming-private-key", &consuming_private_key_hex),
        );
        let mnemonic_seed_prefix = "mnemonic_seed";
        let persistent_config = make_persistent_config(
            Some(mnemonic_seed_prefix),
            Some("password"),
            None,
            Some("m/44'/60'/1'/2/3"),
            None,
            None,
            None,
        )
        .check_password_result(Some(false));
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
        expected = "Cannot use --earning-wallet to specify an address (0x0123456789012345678901234567890123456789) different from that previously set (0x9876543210987654321098765432109876543210)"
    )]
    fn earning_wallet_address_different_from_database() {
        let multi_config = make_multi_config(ArgsBuilder::new().param(
            "--earning-wallet",
            "0x0123456789012345678901234567890123456789",
        ));
        let persistent_config = make_persistent_config(
            None,
            None,
            None,
            None,
            Some("0x9876543210987654321098765432109876543210"),
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
    fn earning_wallet_address_matches_database() {
        let multi_config = make_multi_config(ArgsBuilder::new().param(
            "--earning-wallet",
            "0xb00fa567890123456789012345678901234B00FA",
        ));
        let persistent_config = make_persistent_config(
            None,
            None,
            None,
            None,
            Some("0xB00FA567890123456789012345678901234b00fa"),
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

        assert_eq!(
            config.earning_wallet,
            Wallet::new("0xb00fa567890123456789012345678901234b00fa")
        );
    }

    #[test]
    #[should_panic(
        expected = "Cannot use --consuming-private-key and earning wallet address when database contains mnemonic seed"
    )]
    fn consuming_wallet_private_key_plus_earning_wallet_address_plus_mnemonic_seed() {
        let consuming_private_key_hex =
            "ABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCD";
        let multi_config = make_multi_config(
            ArgsBuilder::new()
                .param("--db-password", "password")
                .param("--consuming-private-key", &consuming_private_key_hex),
        );
        let mnemonic_seed_prefix = "mnemonic_seed";
        let persistent_config = make_persistent_config(
            Some(mnemonic_seed_prefix),
            Some("password"),
            None,
            None,
            Some("0xcafedeadbeefbabefacecafedeadbeefbabeface"),
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
    fn consuming_private_key_matches_database() {
        let consuming_private_key_hex =
            "ABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCD";
        let multi_config = make_multi_config(
            ArgsBuilder::new()
                .param("--db-password", "password")
                .param("--consuming-private-key", &consuming_private_key_hex),
        );
        let persistent_config = make_persistent_config(
            None,
            None,
            Some(consuming_private_key_hex),
            None,
            None,
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

        let keypair = Bip32ECKeyPair::from_raw_secret(
            &consuming_private_key_hex.from_hex::<Vec<u8>>().unwrap(),
        )
        .unwrap();
        let expected_consuming_wallet = Wallet::from(keypair);
        assert_eq!(config.consuming_wallet, Some(expected_consuming_wallet));
    }

    #[test]
    #[should_panic(
        expected = "The specified --consuming-private-key does not denote the same consuming wallet you have used in the past."
    )]
    fn consuming_private_key_doesnt_match_database() {
        let good_consuming_private_key_hex =
            "ABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCD";
        let mut bad_consuming_private_key = good_consuming_private_key_hex
            .from_hex::<Vec<u8>>()
            .unwrap();
        bad_consuming_private_key[0] ^= 0x80; // one bit different
        let bad_consuming_private_key_hex = bad_consuming_private_key.to_hex::<String>();
        let multi_config = make_multi_config(
            ArgsBuilder::new()
                .param("--db-password", "password")
                .param("--consuming-private-key", &bad_consuming_private_key_hex),
        );
        let persistent_config = make_persistent_config(
            None,
            None,
            Some(good_consuming_private_key_hex),
            None,
            None,
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
    fn consuming_wallet_derivation_path_plus_earning_wallet_address_plus_mnemonic_seed() {
        let multi_config = make_multi_config(ArgsBuilder::new().param("--db-password", "password"));
        let mnemonic_seed_prefix = "mnemonic_seed";
        let persistent_config = make_persistent_config(
            Some(mnemonic_seed_prefix),
            Some("password"),
            None,
            Some("m/44'/60'/1'/2/3"),
            Some("0xcafedeadbeefbabefacecafedeadbeefbabeface"),
            None,
            None,
        )
        .check_password_result(Some(false));
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
    fn consuming_wallet_derivation_path_plus_mnemonic_seed_with_no_db_password_parameter() {
        let multi_config = make_multi_config(ArgsBuilder::new());
        let mnemonic_seed_prefix = "mnemonic_seed";
        let persistent_config = make_persistent_config(
            Some(mnemonic_seed_prefix),
            None,
            None,
            Some("m/44'/60'/1'/2/3"),
            Some("0xcafedeadbeefbabefacecafedeadbeefbabeface"),
            None,
            None,
        )
        .check_password_result(Some(false));
        let mut config = BootstrapperConfig::new();

        standard::get_wallets(
            &mut FakeStreamHolder::new().streams(),
            &multi_config,
            &persistent_config,
            &mut config,
        );

        assert_eq!(config.consuming_wallet, None);
        assert_eq!(
            config.earning_wallet,
            Wallet::from_str("0xcafedeadbeefbabefacecafedeadbeefbabeface").unwrap()
        );
    }

    #[test]
    fn consuming_wallet_derivation_path_plus_mnemonic_seed_with_no_db_password_value() {
        let multi_config = make_multi_config(ArgsBuilder::new().opt("--db-password"));
        let mnemonic_seed_prefix = "mnemonic_seed";
        let persistent_config = make_persistent_config(
            Some(mnemonic_seed_prefix),
            None,
            None,
            Some("m/44'/60'/1'/2/3"),
            Some("0xcafedeadbeefbabefacecafedeadbeefbabeface"),
            None,
            None,
        )
        .check_password_result(Some(false))
        .check_password_result(Some(true));
        let mut config = BootstrapperConfig::new();
        let mut stdout_writer = ByteArrayWriter::new();
        let mut streams = &mut StdStreams {
            stdin: &mut Cursor::new(&b"prompt for me\n"[..]),
            stdout: &mut stdout_writer,
            stderr: &mut ByteArrayWriter::new(),
        };

        standard::get_wallets(&mut streams, &multi_config, &persistent_config, &mut config);

        let captured_output = stdout_writer.get_string();
        assert_eq!(
            captured_output,
            "Decrypt information from previous runs\nEnter password: "
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
    #[should_panic(
        expected = "error: Invalid value for \\'--consuming-private-key <PRIVATE-KEY>\\': not valid hex"
    )]
    fn unprivileged_parse_args_with_invalid_consuming_wallet_private_key_panics_correctly() {
        let home_directory = ensure_node_home_directory_exists(
            "node_configurator",
            "parse_args_with_invalid_consuming_wallet_private_key_panics_correctly",
        );

        let args = ArgsBuilder::new().param("--data-directory", home_directory.to_str().unwrap());
        let vcl_args: Vec<Box<dyn VclArg>> = vec![Box::new(NameValueVclArg::new(
            &"--consuming-private-key", // this is equal to SUB_CONSUMING_PRIVATE_KEY
            &"not valid hex",
        ))];

        let faux_environment = CommandLineVcl::from(vcl_args);

        let mut config = BootstrapperConfig::new();
        let vcls: Vec<Box<dyn VirtualCommandLine>> = vec![
            Box::new(faux_environment),
            Box::new(CommandLineVcl::new(args.into())),
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

        let args = ArgsBuilder::new()
            .param("--ip", "1.2.3.4")
            .param("--data-directory", home_directory.to_str().unwrap())
            .opt("--db-password");
        let vcl_args: Vec<Box<dyn VclArg>> = vec![Box::new(NameValueVclArg::new(
            &"--consuming-private-key", // this is equal to SUB_CONSUMING_PRIVATE_KEY
            &"cc46befe8d169b89db447bd725fc2368b12542113555302598430cb5d5c74ea9",
        ))];

        let faux_environment = CommandLineVcl::from(vcl_args);

        let mut config = BootstrapperConfig::new();
        config.db_password_opt = Some("password".to_string());
        let vcls: Vec<Box<dyn VirtualCommandLine>> = vec![
            Box::new(faux_environment),
            Box::new(CommandLineVcl::new(args.into())),
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
    fn get_db_password_shortcuts_if_its_already_gotten() {
        let multi_config = MultiConfig::new(&app(), vec![]);
        let mut holder = FakeStreamHolder::new();
        let mut config = BootstrapperConfig::new();
        let persistent_config =
            make_default_persistent_configuration().check_password_result(Some(false));
        config.db_password_opt = Some("password".to_string());

        let result = standard::get_db_password(
            &multi_config,
            &mut holder.streams(),
            &mut config,
            &persistent_config,
        );

        assert_eq!(result, Some("password".to_string()));
    }

    #[test]
    fn get_db_password_doesnt_bother_if_database_has_no_password_yet() {
        let multi_config = MultiConfig::new(&app(), vec![]);
        let mut holder = FakeStreamHolder::new();
        let mut config = BootstrapperConfig::new();
        let persistent_config = make_default_persistent_configuration().check_password_result(None);

        let result = standard::get_db_password(
            &multi_config,
            &mut holder.streams(),
            &mut config,
            &persistent_config,
        );

        assert_eq!(result, None);
    }

    #[test]
    fn no_parameters_produces_configuration_for_crash_point() {
        let args = make_default_cli_params();
        let mut config = BootstrapperConfig::new();
        let vcl = Box::new(CommandLineVcl::new(args.into()));
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
        let args = make_default_cli_params().param("--crash-point", "panic");
        let mut config = BootstrapperConfig::new();
        let vcl = Box::new(CommandLineVcl::new(args.into()));
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
        let args = ArgsBuilder::new().param("--config-file", "booga.toml"); // nonexistent config file: should stimulate panic because user-specified

        subject.configure(&args.into(), &mut FakeStreamHolder::new().streams());
    }

    #[test]
    #[should_panic(expected = "could not be read: ")]
    fn unprivileged_generate_configuration_senses_when_user_specifies_config_file() {
        let data_dir = ensure_node_home_directory_exists(
            "node_configurator_standard",
            "unprivileged_generate_configuration_senses_when_user_specifies_config_file",
        );
        let mut subject = NodeConfiguratorStandardUnprivileged::new(&BootstrapperConfig::new());
        subject.privileged_config = BootstrapperConfig::new();
        subject.privileged_config.data_directory = data_dir;
        let args = ArgsBuilder::new().param("--config-file", "booga.toml"); // nonexistent config file: should stimulate panic because user-specified

        subject.configure(&args.into(), &mut FakeStreamHolder::new().streams());
    }

    #[test]
    fn privileged_configuration_accepts_network_chain_selection_for_multinode() {
        let subject = NodeConfiguratorStandardPrivileged {};
        let args = ArgsBuilder::new()
            .param("--ip", "1.2.3.4")
            .param("--chain", "dev");

        let config = subject.configure(&args.into(), &mut FakeStreamHolder::new().streams());

        assert_eq!(
            config.blockchain_bridge_config.chain_id,
            chain_id_from_name("dev")
        );
    }

    #[test]
    fn privileged_configuration_accepts_network_chain_selection_for_ropsten() {
        let subject = NodeConfiguratorStandardPrivileged {};
        let args = ArgsBuilder::new()
            .param("--ip", "1.2.3.4")
            .param("--chain", "ropsten");

        let config = subject.configure(&args.into(), &mut FakeStreamHolder::new().streams());

        assert_eq!(
            config.blockchain_bridge_config.chain_id,
            chain_id_from_name("ropsten")
        );
    }

    #[test]
    fn privileged_configuration_defaults_network_chain_selection_to_mainnet() {
        let subject = NodeConfiguratorStandardPrivileged {};
        let args = ArgsBuilder::new().param("--ip", "1.2.3.4");

        let config = subject.configure(&args.into(), &mut FakeStreamHolder::new().streams());

        assert_eq!(
            config.blockchain_bridge_config.chain_id,
            chain_id_from_name(DEFAULT_CHAIN_NAME)
        );
    }

    #[test]
    fn privileged_configuration_accepts_ropsten_network_chain_selection() {
        let subject = NodeConfiguratorStandardPrivileged {};
        let args = ArgsBuilder::new()
            .param("--ip", "1.2.3.4")
            .param("--chain", TEST_DEFAULT_CHAIN_NAME);

        let bootstrapper_config =
            subject.configure(&args.into(), &mut FakeStreamHolder::new().streams());
        assert_eq!(
            bootstrapper_config.blockchain_bridge_config.chain_id,
            chain_id_from_name(TEST_DEFAULT_CHAIN_NAME)
        );
    }

    #[test]
    fn unprivileged_configuration_gets_parameter_gas_price() {
        let data_dir = ensure_node_home_directory_exists(
            "node_configurator_standard",
            "unprivileged_configuration_gets_parameter_gas_price",
        );
        let mut subject = NodeConfiguratorStandardUnprivileged::new(&BootstrapperConfig::new());
        subject.privileged_config = BootstrapperConfig::new();
        subject.privileged_config.data_directory = data_dir;
        let expected_gas_price = "57";
        let args = ArgsBuilder::new()
            .param("--ip", "1.2.3.4")
            .param("--gas-price", expected_gas_price);

        let config = subject.configure(&args.into(), &mut FakeStreamHolder::new().streams());

        assert_eq!(
            config.blockchain_bridge_config.gas_price,
            u64::from_str_radix(expected_gas_price, 10).ok()
        );
    }

    #[test]
    fn unprivileged_configuration_does_not_set_gas_price_when_not_provided() {
        let data_dir = ensure_node_home_directory_exists(
            "node_configurator_standard",
            "unprivileged_configuration_does_not_set_gas_price_when_not_provided",
        );
        let mut subject = NodeConfiguratorStandardUnprivileged::new(&BootstrapperConfig::new());
        subject.privileged_config = BootstrapperConfig::new();
        subject.privileged_config.data_directory = data_dir;
        let args = ArgsBuilder::new().param("--ip", "1.2.3.4");

        let config = subject.configure(&args.into(), &mut FakeStreamHolder::new().streams());

        assert_eq!(config.blockchain_bridge_config.gas_price, None);
    }

    #[test]
    #[should_panic(expected = "error: Invalid value for \\'--gas-price <GAS-PRICE>\\': unleaded")]
    fn privileged_configuration_rejects_invalid_gas_price() {
        let subject = NodeConfiguratorStandardPrivileged {};
        let args = ArgsBuilder::new().param("--gas-price", "unleaded");

        subject.configure(&args.into(), &mut FakeStreamHolder::new().streams());
    }

    #[test]
    fn configure_database_with_data_specified_on_command_line_but_not_in_database_without_seed() {
        let mut config = BootstrapperConfig::new();
        config.clandestine_port_opt = Some(1234);
        let earning_address = "0x0123456789012345678901234567890123456789";
        let consuming_private_key_text =
            "ABCD00EFABCD00EFABCD00EFABCD00EFABCD00EFABCD00EFABCD00EFABCD00EF";
        let consuming_private_key =
            PlainData::from(consuming_private_key_text.from_hex::<Vec<u8>>().unwrap());
        let gas_price = 4u64;
        let keypair = Bip32ECKeyPair::from_raw_secret(consuming_private_key.as_slice()).unwrap();
        let consuming_public_key = keypair.secret().public();
        let consuming_public_key_bytes = consuming_public_key.bytes();
        config.earning_wallet = Wallet::new(earning_address);
        config.consuming_wallet = Some(Wallet::from(keypair));
        config.blockchain_bridge_config.gas_price = Some(gas_price);
        let set_clandestine_port_params_arc = Arc::new(Mutex::new(vec![]));
        let set_earning_wallet_address_params_arc = Arc::new(Mutex::new(vec![]));
        let set_consuming_public_key_params_arc = Arc::new(Mutex::new(vec![]));
        let set_gas_price_params_arc = Arc::new(Mutex::new(vec![]));
        let persistent_config = PersistentConfigurationMock::new()
            .earning_wallet_address_result(None)
            .consuming_wallet_public_key_result(None)
            .consuming_wallet_derivation_path_result(None)
            .set_clandestine_port_params(&set_clandestine_port_params_arc)
            .set_earning_wallet_address_params(&set_earning_wallet_address_params_arc)
            .set_consuming_wallet_public_key_params(&set_consuming_public_key_params_arc)
            .set_gas_price_params(&set_gas_price_params_arc);

        standard::configure_database(&config, &persistent_config);

        let set_clandestine_port_params = set_clandestine_port_params_arc.lock().unwrap();
        assert_eq!(*set_clandestine_port_params, vec![1234]);
        let set_earning_wallet_address_params =
            set_earning_wallet_address_params_arc.lock().unwrap();
        assert_eq!(
            *set_earning_wallet_address_params,
            vec![earning_address.to_string()]
        );
        let set_consuming_public_key_params = set_consuming_public_key_params_arc.lock().unwrap();
        assert_eq!(
            *set_consuming_public_key_params,
            vec![PlainData::new(consuming_public_key_bytes)]
        );
        let set_gas_price_params = set_gas_price_params_arc.lock().unwrap();
        assert_eq!(*set_gas_price_params, vec![gas_price]);
    }

    #[test]
    fn configure_database_with_data_specified_on_command_line_and_in_database_without_seed() {
        let mut config = BootstrapperConfig::new();
        config.clandestine_port_opt = Some(1234);
        let earning_address = "0x0123456789012345678901234567890123456789";
        let consuming_private_key_text =
            "ABCD00EFABCD00EFABCD00EFABCD00EFABCD00EFABCD00EFABCD00EFABCD00EF";
        let consuming_private_key =
            PlainData::from(consuming_private_key_text.from_hex::<Vec<u8>>().unwrap());
        let keypair = Bip32ECKeyPair::from_raw_secret(consuming_private_key.as_slice()).unwrap();
        let consuming_public_key = keypair.secret().public();
        let consuming_public_key_text = consuming_public_key.bytes().to_hex::<String>();
        config.consuming_wallet = Some(Wallet::from(keypair));
        let set_clandestine_port_params_arc = Arc::new(Mutex::new(vec![]));
        let set_earning_wallet_address_params_arc = Arc::new(Mutex::new(vec![]));
        let set_consuming_public_key_params_arc = Arc::new(Mutex::new(vec![]));
        let persistent_config = PersistentConfigurationMock::new()
            .earning_wallet_address_result(Some(earning_address.to_string()))
            .consuming_wallet_public_key_result(Some(consuming_public_key_text))
            .consuming_wallet_derivation_path_result(None)
            .set_clandestine_port_params(&set_clandestine_port_params_arc)
            .set_earning_wallet_address_params(&set_earning_wallet_address_params_arc)
            .set_consuming_wallet_public_key_params(&set_consuming_public_key_params_arc);

        standard::configure_database(&config, &persistent_config);

        let set_clandestine_port_params = set_clandestine_port_params_arc.lock().unwrap();
        assert_eq!(*set_clandestine_port_params, vec![1234]);
        let set_earning_wallet_address_params =
            set_earning_wallet_address_params_arc.lock().unwrap();
        assert_eq!(set_earning_wallet_address_params.len(), 0);
        let set_consuming_public_key_params = set_consuming_public_key_params_arc.lock().unwrap();
        assert_eq!(set_consuming_public_key_params.len(), 0);
    }

    #[test]
    #[should_panic(expected = "Internal error: consuming wallet must be derived from keypair")]
    fn configure_database_with_non_keypair_consuming_wallet() {
        let mut config = BootstrapperConfig::new();
        config.clandestine_port_opt = Some(1234);
        config.consuming_wallet =
            Some(Wallet::from_str("0x0123456789ABCDEF0123456789ABCDEF01234567").unwrap());
        let set_clandestine_port_params_arc = Arc::new(Mutex::new(vec![]));
        let set_consuming_public_key_params_arc = Arc::new(Mutex::new(vec![]));
        let persistent_config = PersistentConfigurationMock::new()
            .earning_wallet_address_result(None)
            .consuming_wallet_public_key_result(None)
            .consuming_wallet_derivation_path_result(None)
            .set_clandestine_port_params(&set_clandestine_port_params_arc)
            .set_consuming_wallet_public_key_params(&set_consuming_public_key_params_arc);

        standard::configure_database(&config, &persistent_config);
    }

    #[test]
    fn configure_database_with_no_data_specified() {
        let mut config = BootstrapperConfig::new();
        config.clandestine_port_opt = None;
        config.consuming_wallet = None;
        config.earning_wallet = DEFAULT_EARNING_WALLET.clone();
        let set_clandestine_port_params_arc = Arc::new(Mutex::new(vec![]));
        let set_consuming_public_key_params_arc = Arc::new(Mutex::new(vec![]));
        let set_earning_wallet_address_params_arc = Arc::new(Mutex::new(vec![]));
        let persistent_config = PersistentConfigurationMock::new()
            .earning_wallet_address_result(None)
            .consuming_wallet_public_key_result(None)
            .consuming_wallet_derivation_path_result(None)
            .set_clandestine_port_params(&set_clandestine_port_params_arc)
            .set_consuming_wallet_public_key_params(&set_consuming_public_key_params_arc)
            .set_earning_wallet_address_params(&set_earning_wallet_address_params_arc);

        standard::configure_database(&config, &persistent_config);

        let set_clandestine_port_params = set_clandestine_port_params_arc.lock().unwrap();
        let no_ports: Vec<u16> = vec![];
        assert_eq!(*set_clandestine_port_params, no_ports);
        let set_consuming_public_key_params = set_consuming_public_key_params_arc.lock().unwrap();
        let no_keys: Vec<PlainData> = vec![];
        assert_eq!(*set_consuming_public_key_params, no_keys);
        let set_earning_wallet_address_params =
            set_earning_wallet_address_params_arc.lock().unwrap();
        assert_eq!(
            *set_earning_wallet_address_params,
            vec![DEFAULT_EARNING_WALLET.to_string()]
        )
    }
}
