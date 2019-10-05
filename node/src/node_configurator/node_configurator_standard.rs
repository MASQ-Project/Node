// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

use crate::blockchain::blockchain_interface::DEFAULT_GAS_PRICE;
use crate::bootstrapper::BootstrapperConfig;
use crate::node_configurator;
use crate::node_configurator::{
    app_head, chain_arg, common_validators, config_file_arg, data_directory_arg,
    earning_wallet_arg, initialize_database, real_user_arg, wallet_password_arg, NodeConfigurator,
};
use crate::sub_lib::crash_point::CrashPoint;
use crate::sub_lib::main_tools::StdStreams;
use crate::sub_lib::ui_gateway::DEFAULT_UI_PORT;
use clap::{App, Arg};
use indoc::indoc;
use lazy_static::lazy_static;

pub const LOWEST_USABLE_INSECURE_PORT: u16 = 1025;
pub const HIGHEST_USABLE_PORT: u16 = 65535;

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

lazy_static! {
    static ref DEFAULT_UI_PORT_VALUE: String = DEFAULT_UI_PORT.to_string();
    static ref DEFAULT_CRASH_POINT_VALUE: String = format!("{}", CrashPoint::None);
    static ref UI_PORT_HELP: String = format!(
        "The port at which user interfaces will connect to the Node. Best to accept the default unless \
        you know what you're doing. Must be between {} and {}.",
        LOWEST_USABLE_INSECURE_PORT, HIGHEST_USABLE_PORT
    );
    static ref CLANDESTINE_PORT_HELP: String = format!(
        "The port this Node will advertise to other Nodes at which clandestine traffic will be \
         received. If you don't specify a clandestine port, the Node will choose an unused \
         one at random on first startup, then use that one for every subsequent run unless \
         you change it by specifying a different clandestine port here. --clandestine-port is \
         meaningless except in --neighborhood-mode standard. \
         Must be between {} and {} [default: last used port]",
        LOWEST_USABLE_INSECURE_PORT, HIGHEST_USABLE_PORT
    );
    static ref GAS_PRICE_HELP: String = format!(
       "The Gas Price is the amount of Gwei you will pay per unit of gas used in a transaction. \
       If left unspecified SubstratumNode will use the previously stored value (Default {}). Valid range is 1-99 Gwei.",
       DEFAULT_GAS_PRICE);
}

const BLOCKCHAIN_SERVICE_HELP: &str =
    "The Ethereum client you wish to use to provide Blockchain \
     exit services from your SubstratumNode (e.g. http://localhost:8545, \
     https://ropsten.infura.io/v3/YOUR-PROJECT-ID, https://mainnet.infura.io/v3/YOUR-PROJECT-ID).";
const DNS_SERVERS_HELP: &str =
    "IP addresses of DNS Servers for host name look-up while providing exit \
     services for other SubstratumNodes (e.g. 1.0.0.1,1.1.1.1,8.8.8.8,9.9.9.9, etc.)";
const EARNING_WALLET_HELP: &str =
    "An Ethereum wallet address. Addresses must begin with 0x followed by 40 hexadecimal digits \
     (case-insensitive). If you already have a derivation-path earning wallet, don't supply this. \
     If you have supplied an earning wallet address before, either don't supply it again or be \
     careful to supply exactly the same one you supplied before.";
const IP_ADDRESS_HELP: &str = "The public IP address of your SubstratumNode: that is, the IPv4 \
     address at which other SubstratumNodes can contact yours. If you're running your Node behind \
     a router, this will be the IP address of the router. If this IP address starts with 192.168 or 10.0, \
     it's a local address rather than a public address, and other Nodes won't be able to see yours. \
     --ip is meaningless except in --neighborhood-mode standard.";
const LOG_LEVEL_HELP: &str =
    "The minimum severity of the logs that should appear in the Node's logfile. You should probably not specify \
     a level lower than the default unless you're doing testing or forensics: a Node at the 'trace' log level \
     generates a lot of log traffic. This will both consume your disk space and degrade your Node's performance. \
     You should probably not specify a level higher than the default unless you have security concerns about \
     persistent logs being kept on your computer: if your Node crashes, it's good to know why.";
const NEIGHBORS_HELP: &str = "One or more Node descriptors for running Nodes in the Substratum \
     Network to which you'd like your Node to connect on startup. A Node descriptor looks like \
     this:\n\ngBviQbjOS3e5ReFQCvIhUM3i02d1zPleo1iXg/EN6zQ:86.75.30.9:5542 (initial ':' for testnet) and\n\
     gBviQbjOS3e5ReFQCvIhUM3i02d1zPleo1iXg/EN6zQ@86.75.30.9:5542 (initial '@' for mainnet)\n\n\
     If you have more than one, separate them with commas (but no spaces). There is no default value; \
     if you don't specify a neighbor, your Node will start without being connected to any Substratum \
     Network, although other Nodes will be able to connect to yours if they know your Node's descriptor. \
     --neighbors is meaningless in --neighborhood-mode zero-hop.";
const NEIGHBORHOOD_MODE_HELP: &str = "This configures the way the Node relates to other Nodes.\n\n\
     zero-hop means that your Node will operate as its own Substratum Network and will not communicate with any \
     other Nodes. --ip, --neighbors, and --clandestine-port are incompatible with --neighborhood_mode \
     zero-hop.\n\n\
     originate-only means that your Node will not accept connections from any other Node; it \
     will only originate connections to other Nodes. This will reduce your Node's opportunity to route \
     data (it will only ever have two neighbors, so the number of routes it can participate in is limited), \
     it will reduce redundancy in the Substratum Network, and it will prevent your Node from acting as \
     a connection point for other Nodes to get on the Network; but it will enable your Node to operate in \
     an environment where your network hookup is preventing you from accepting connections, and it means \
     that you don't have to forward any incoming ports through your router. --ip and --clandestine_port \
     are incompatible with --neighborhood_mode originate-only.\n\n\
     consume-only means that your Node will not accept connections from or route data for any other Node; \
     it will only consume services from the Substratum Network. This mode is appropriate for devices that \
     cannot maintain a constant IP address or stay constantly on the Network. --ip and --clandestine_port \
     are incompatible with --neighborhood_mode consume-only.\n\n\
     standard means that your Node will operate fully unconstrained, both originating and accepting \
     connections, both consuming and providing services, and when you operate behind a router, it \
     requires that you forward your clandestine port through that router to your Node's machine.";
const WALLET_PASSWORD_HELP: &str =
    "A password or phrase to decrypt your consuming wallet or a keystore file. Can be changed \
     later and still produce the same addresses.";

const HELP_TEXT: &str = indoc!(
    r"ADDITIONAL HELP:
    If you want to generate wallets to earn money into and spend money from, try:

        SubstratumNode --help --generate-wallet

    If you already have a set of wallets you want SubstratumNode to use, try:

        SubstratumNode --help --recover-wallet

    SubstratumNode listens for connections from other SubstratumNodes using the computer's
    network interface. Configuring the internet router for port forwarding is a necessary
    step for SubstratumNode users to permit network communication between SubstratumNodes.

    Once started, SubstratumNode prints the node descriptor to the console. The descriptor
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

fn app() -> App<'static, 'static> {
    app_head()
        .after_help(HELP_TEXT)
        .arg(
            Arg::with_name("blockchain-service-url")
                .long("blockchain-service-url")
                .empty_values(false)
                .value_name("URL")
                .takes_value(true)
                .help(BLOCKCHAIN_SERVICE_HELP),
        )
        .arg(
            Arg::with_name("clandestine-port")
                .long("clandestine-port")
                .value_name("CLANDESTINE-PORT")
                .empty_values(false)
                .validator(validators::validate_clandestine_port)
                .help(&CLANDESTINE_PORT_HELP),
        )
        .arg(config_file_arg())
        .arg(
            Arg::with_name("consuming-private-key")
                .long("consuming-private-key")
                .value_name("PRIVATE-KEY")
                .takes_value(true)
                .validator(validators::validate_private_key)
                .help(node_configurator::CONSUMING_PRIVATE_KEY_HELP),
        )
        .arg(
            Arg::with_name("crash-point")
                .long("crash-point")
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
        .arg(chain_arg())
        .arg(
            Arg::with_name("fake-public-key")
                .long("fake-public-key")
                .value_name("FAKE-PUBLIC-KEY")
                .takes_value(true)
                .hidden(true),
        )
        .arg(
            Arg::with_name("gas-price")
                .long("gas-price")
                .value_name("GAS-PRICE")
                .min_values(1)
                .max_values(1)
                .takes_value(true)
                .validator(validators::validate_gas_price)
                .help(&GAS_PRICE_HELP),
        )
        .arg(
            Arg::with_name("ip")
                .long("ip")
                .value_name("IP")
                .takes_value(true)
                .validator(validators::validate_ip_address)
                .help(IP_ADDRESS_HELP),
        )
        .arg(
            Arg::with_name("log-level")
                .long("log-level")
                .value_name("FILTER")
                .takes_value(true)
                .possible_values(&["off", "error", "warn", "info", "debug", "trace"])
                .default_value("warn")
                .case_insensitive(true)
                .help(LOG_LEVEL_HELP),
        )
        .arg(
            Arg::with_name("neighborhood-mode")
                .long("neighborhood-mode")
                .value_name("NEIGHBORHOOD-MODE")
                .takes_value(true)
                .possible_values(&["zero-hop", "originate-only", "consume-only", "standard"])
                .default_value("standard")
                .case_insensitive(true)
                .help(NEIGHBORHOOD_MODE_HELP),
        )
        .arg(
            Arg::with_name("neighbors")
                .long("neighbors")
                .value_name("NODE-DESCRIPTORS")
                .takes_value(true)
                .use_delimiter(true)
                .help(NEIGHBORS_HELP),
        )
        .arg(real_user_arg())
        .arg(
            Arg::with_name("ui-port")
                .long("ui-port")
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

    use clap::{value_t, values_t};
    use log::LevelFilter;

    use crate::blockchain::bip32::Bip32ECKeyPair;
    use crate::blockchain::bip39::{Bip39, Bip39Error};
    use crate::blockchain::blockchain_interface::chain_id_from_name;
    use crate::bootstrapper::PortConfiguration;
    use crate::http_request_start_finder::HttpRequestDiscriminatorFactory;
    use crate::multi_config::{CommandLineVcl, ConfigFileVcl, EnvironmentVcl, MultiConfig};
    use crate::node_configurator::{
        determine_config_file_path, real_user_data_directory_and_chain_id,
        request_wallet_decryption_password,
    };
    use crate::persistent_configuration::{PersistentConfiguration, HTTP_PORT, TLS_PORT};
    use crate::sub_lib::accountant::DEFAULT_EARNING_WALLET;
    use crate::sub_lib::cryptde::{PlainData, PublicKey};
    use crate::sub_lib::cryptde_null::CryptDENull;
    use crate::sub_lib::neighborhood::{NeighborhoodConfig, NeighborhoodMode, DEFAULT_RATE_PACK};
    use crate::sub_lib::node_addr::NodeAddr;
    use crate::sub_lib::wallet::Wallet;
    use crate::tls_discriminator_factory::TlsDiscriminatorFactory;
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
        config: &mut BootstrapperConfig,
        _streams: &mut StdStreams<'_>,
    ) {
        if let Some(chain_name) = value_m!(multi_config, "chain", String) {
            config.blockchain_bridge_config.chain_id = chain_id_from_name(chain_name.as_str());
        }

        config.blockchain_bridge_config.blockchain_service_url =
            value_m!(multi_config, "blockchain-service-url", String);

        let (real_user, data_directory, chain_id) =
            real_user_data_directory_and_chain_id(multi_config);
        config.real_user = real_user;
        config.data_directory = data_directory;
        config.blockchain_bridge_config.chain_id = chain_id;

        config.dns_servers = values_m!(multi_config, "dns-servers", IpAddr)
            .into_iter()
            .map(|ip| SocketAddr::from((ip, 53)))
            .collect();

        config.log_level =
            value_m!(multi_config, "log-level", LevelFilter).expect("Internal Error");

        config.neighborhood_config = make_neighborhood_config(multi_config);

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
                let cryptde_null =
                    CryptDENull::from(&public_key, config.blockchain_bridge_config.chain_id);
                config.cryptde_null_opt = Some(cryptde_null);
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
        let encrypted_mnemonic_seed = persistent_config.encrypted_mnemonic_seed();
        if earning_wallet_opt.is_some()
            && consuming_wallet_opt.is_some()
            && encrypted_mnemonic_seed.is_some()
        {
            panic!("Cannot use --consuming-private-key and earning wallet address when database contains mnemonic seed")
        }

        if earning_wallet_opt.is_none() || consuming_wallet_opt.is_none() {
            if let Some((_, wallet_password)) =
                standard::get_mnemonic_seed_and_password(multi_config, streams, persistent_config)
            {
                if consuming_wallet_opt.is_none() {
                    consuming_wallet_opt = standard::get_consuming_wallet_opt_from_derivation_path(
                        persistent_config,
                        &wallet_password,
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

    pub fn make_neighborhood_config(multi_config: &MultiConfig) -> NeighborhoodConfig {
        let neighbor_configs = values_m!(multi_config, "neighbors", String);
        match value_m! (multi_config, "neighborhood-mode", String) {
            Some (ref s) if s == "standard" => NeighborhoodConfig {
                mode: NeighborhoodMode::Standard (
                NodeAddr::new (&value_m! (multi_config, "ip", IpAddr).expect ("Node cannot run as --neighborhood_mode standard without --ip specified"), &vec![]),
                neighbor_configs,
                DEFAULT_RATE_PACK,
            )},
            Some (ref s) if s == "originate-only" => {
                if neighbor_configs.is_empty () {
                    panic! ("Node cannot run as --neighborhood_mode originate-only without --neighbors specified")
                }
                NeighborhoodConfig {
                    mode: NeighborhoodMode::OriginateOnly (
                    neighbor_configs,
                    DEFAULT_RATE_PACK,
                )}
            },
            Some (ref s) if s == "consume-only" => {
                if neighbor_configs.is_empty () {
                    panic! ("Node cannot run as --neighborhood_mode consume-only without --neighbors specified")
                }
                NeighborhoodConfig {
                    mode: NeighborhoodMode::ConsumeOnly (
                    neighbor_configs,
                )}
            },
            Some (ref s) if s == "zero-hop" => {
                if !neighbor_configs.is_empty () {
                    panic!("Node cannot run as --neighborhood_mode zero-hop if --neighbors is specified")
                }
                if value_m! (multi_config, "ip", IpAddr).is_some () {
                    panic! ("Node cannot run as --neighborhood_mode zero-hop if --ip is specified")
                }
                NeighborhoodConfig { mode: NeighborhoodMode::ZeroHop}
            },
            // These two cases are untestable
            Some (ref s) => panic! ("--neighborhood_mode {} has not been properly provided for in the code", s),
            None => panic! ("--neighborhood_mode is not properly defaulted in clap"),
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
        wallet_password: &str,
    ) -> Option<Wallet> {
        match persistent_config.consuming_wallet_derivation_path() {
            None => None,
            Some(derivation_path) => match persistent_config.mnemonic_seed(wallet_password) {
                Err(Bip39Error::NotPresent) => None,
                Ok(mnemonic_seed) => {
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
                Err(e) => panic!("Error retrieving mnemonic seed from database: {:?}", e),
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

    fn get_mnemonic_seed_and_password(
        multi_config: &MultiConfig,
        streams: &mut StdStreams,
        persistent_config: &dyn PersistentConfiguration,
    ) -> Option<(PlainData, String)> {
        match persistent_config.encrypted_mnemonic_seed() {
            None => None,
            Some(encrypted_mnemonic_seed) => {
                let wallet_password =
                    match value_user_specified_m!(multi_config, "wallet-password", String) {
                        (Some(wp), _) => wp,
                        (None, false) => return None,
                        (None, true) => request_wallet_decryption_password(
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

    pub fn validate_gas_price(gas_price: String) -> Result<(), String> {
        match gas_price.parse::<u8>() {
            Ok(gp) if gp > 0 && gp < 100 => Ok(()),
            _ => Err(gas_price),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blockchain::bip32::Bip32ECKeyPair;
    use crate::blockchain::bip39::{Bip39, Bip39Error};
    use crate::blockchain::blockchain_interface::{
        chain_id_from_name, contract_address, DEFAULT_CHAIN_NAME,
    };
    use crate::bootstrapper::RealUser;
    use crate::config_dao::{ConfigDao, ConfigDaoReal};
    use crate::database::db_initializer;
    use crate::database::db_initializer::{DbInitializer, DbInitializerReal};
    use crate::multi_config::tests::FauxEnvironmentVcl;
    use crate::multi_config::{
        CommandLineVcl, ConfigFileVcl, MultiConfig, NameValueVclArg, VclArg, VirtualCommandLine,
    };
    use crate::persistent_configuration::PersistentConfigurationReal;
    use crate::sub_lib::accountant::DEFAULT_EARNING_WALLET;
    use crate::sub_lib::crash_point::CrashPoint;
    use crate::sub_lib::cryptde::{CryptDE, PlainData, PublicKey};
    use crate::sub_lib::cryptde_null::CryptDENull;
    use crate::sub_lib::neighborhood::{NeighborhoodConfig, NeighborhoodMode, DEFAULT_RATE_PACK};
    use crate::sub_lib::node_addr::NodeAddr;
    use crate::sub_lib::wallet::Wallet;
    use crate::test_utils::environment_guard::EnvironmentGuard;
    use crate::test_utils::persistent_configuration_mock::PersistentConfigurationMock;
    use crate::test_utils::{ensure_node_home_directory_exists, ArgsBuilder};
    use crate::test_utils::{make_default_persistent_configuration, DEFAULT_CHAIN_ID};
    use crate::test_utils::{ByteArrayWriter, FakeStreamHolder};
    use ethsign::keyfile::Crypto;
    use ethsign::Protected;
    use rustc_hex::{FromHex, ToHex};
    use std::fs::File;
    use std::io::Cursor;
    use std::io::Write;
    use std::net::SocketAddr;
    use std::net::{IpAddr, Ipv4Addr};
    use std::num::NonZeroU32;
    use std::path::PathBuf;
    use std::str::FromStr;
    use std::sync::{Arc, Mutex};

    fn make_default_cli_params() -> ArgsBuilder {
        ArgsBuilder::new()
            .param("--dns-servers", "222.222.222.222")
            .param("--ip", "1.2.3.4")
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

        assert!(result.is_ok());
        assert_eq!(Ok(()), result);
    }

    #[test]
    fn validate_gas_price_zero() {
        let result = validators::validate_gas_price("0".to_string());

        assert!(result.is_err());
        assert_eq!(Err(String::from("0")), result);
    }

    #[test]
    fn validate_gas_price_normal_ropsten() {
        let result = validators::validate_gas_price("2".to_string());

        assert!(result.is_ok());
        assert_eq!(Ok(()), result);
    }

    #[test]
    fn validate_gas_price_normal_mainnet() {
        let result = validators::validate_gas_price("20".to_string());

        assert!(result.is_ok());
        assert_eq!(Ok(()), result);
    }

    #[test]
    fn validate_gas_price_max() {
        let result = validators::validate_gas_price("99".to_string());
        assert!(result.is_ok());
        assert_eq!(Ok(()), result);
    }

    #[test]
    fn validate_gas_price_too_large_and_fails() {
        let result = validators::validate_gas_price("100".to_string());
        assert!(result.is_err());
        assert_eq!(Err(String::from("100")), result);
    }

    #[test]
    fn validate_gas_price_not_digits_fails() {
        let result = validators::validate_gas_price("not".to_string());
        assert!(result.is_err());
        assert_eq!(Err(String::from("not")), result);
    }

    #[test]
    fn validate_gas_price_hex_fails() {
        let result = validators::validate_gas_price("0x0".to_string());
        assert!(result.is_err());
        assert_eq!(Err(String::from("0x0")), result);
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
                        "QmlsbA:1.2.3.4:1234;2345,VGVk:2.3.4.5:3456;4567",
                    )
                    .into(),
            ))],
        );

        let result = standard::make_neighborhood_config(&multi_config);

        assert_eq!(
            result,
            NeighborhoodConfig {
                mode: NeighborhoodMode::Standard(
                    NodeAddr::new(&IpAddr::from_str("1.2.3.4").unwrap(), &vec![]),
                    vec![
                        "QmlsbA:1.2.3.4:1234;2345".to_string(),
                        "VGVk:2.3.4.5:3456;4567".to_string()
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
                    .into(),
            ))],
        );

        standard::make_neighborhood_config(&multi_config);
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
                    .into(),
            ))],
        );

        let result = standard::make_neighborhood_config(&multi_config);

        assert_eq!(
            result,
            NeighborhoodConfig {
                mode: NeighborhoodMode::OriginateOnly(
                    vec![
                        "QmlsbA:1.2.3.4:1234;2345".to_string(),
                        "VGVk:2.3.4.5:3456;4567".to_string()
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

        standard::make_neighborhood_config(&multi_config);
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
                    .into(),
            ))],
        );

        let result = standard::make_neighborhood_config(&multi_config);

        assert_eq!(
            result,
            NeighborhoodConfig {
                mode: NeighborhoodMode::ConsumeOnly(vec![
                    "QmlsbA:1.2.3.4:1234;2345".to_string(),
                    "VGVk:2.3.4.5:3456;4567".to_string()
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

        standard::make_neighborhood_config(&multi_config);
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

        let result = standard::make_neighborhood_config(&multi_config);

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

        standard::make_neighborhood_config(&multi_config);
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
                    .into(),
            ))],
        );

        standard::make_neighborhood_config(&multi_config);
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
                .write_all(b"dns-servers = \"1.2.3.4\"\nip = \"1.2.3.4\"\n")
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
                "dns-servers = \"1.2.3.4\"\nconsuming-private-key = \"{}\"",
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
            .param("--wallet-password", "secret-wallet-password")
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
        assert_eq!(
            config.neighborhood_config.mode.neighbor_configs(),
            &vec!(
                "QmlsbA:1.2.3.4:1234;2345".to_string(),
                "VGVk:2.3.4.5:3456;4567".to_string()
            ),
        );
        assert_eq!(
            config
                .neighborhood_config
                .mode
                .node_addr_opt()
                .unwrap()
                .ip_addr(),
            IpAddr::V4(Ipv4Addr::new(34, 56, 78, 90)),
        );
        assert_eq!(config.ui_gateway_config.ui_port, 5335);
        let expected_port_list: Vec<u16> = vec![];
        assert_eq!(
            config
                .neighborhood_config
                .mode
                .node_addr_opt()
                .unwrap()
                .ports(),
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
        let password = "secret-wallet-password";
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
            .param("--wallet-password", password)
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
    }

    #[test]
    fn privileged_parse_args_creates_configuration_with_defaults() {
        let args = ArgsBuilder::new()
            .param("--dns-servers", "12.34.56.78,23.45.67.89")
            .param("--ip", "1.2.3.4");
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
            vec!(
                SocketAddr::from_str("12.34.56.78:53").unwrap(),
                SocketAddr::from_str("23.45.67.89:53").unwrap()
            )
        );
        assert_eq!(config.crash_point, CrashPoint::None);
        assert_eq!(
            config
                .neighborhood_config
                .mode
                .node_addr_opt()
                .unwrap()
                .ip_addr(),
            IpAddr::from_str("1.2.3.4").unwrap()
        );
        assert_eq!(config.ui_gateway_config.ui_port, 5333);
        assert!(config.cryptde_null_opt.is_none());
        assert_eq!(config.real_user, RealUser::null().populate());
    }

    #[test]
    #[cfg(not(target_os = "windows"))]
    fn privileged_parse_args_with_real_user_defaults_data_directory_properly() {
        let args = ArgsBuilder::new()
            .param("--dns-servers", "12.34.56.78,23.45.67.89")
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
            PathBuf::from("/home/booga/.local/share/Substratum").join(DEFAULT_CHAIN_NAME)
        );

        #[cfg(target_os = "macos")]
        assert_eq!(
            config.data_directory,
            PathBuf::from("/home/booga/Library/Application Support/Substratum")
                .join(DEFAULT_CHAIN_NAME)
        );
    }

    #[test]
    fn unprivileged_parse_args_creates_configuration_with_defaults() {
        let args = ArgsBuilder::new().param("--dns-servers", "12.34.56.78,23.45.67.89");
        let mut config = BootstrapperConfig::new();
        let vcls: Vec<Box<dyn VirtualCommandLine>> =
            vec![Box::new(CommandLineVcl::new(args.into()))];
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
        assert_eq!(config.earning_wallet, DEFAULT_EARNING_WALLET.clone(),);
        assert_eq!(config.consuming_wallet, None,);
    }

    fn make_multi_config<'a>(args: ArgsBuilder) -> MultiConfig<'a> {
        let args = args.param("--dns-servers", "12.34.56.78,23.45.67.89");
        let vcls: Vec<Box<dyn VirtualCommandLine>> =
            vec![Box::new(CommandLineVcl::new(args.into()))];
        MultiConfig::new(&app(), vcls)
    }

    fn make_persistent_config(
        mnemonic_seed_prefix_opt: Option<&str>,
        wallet_password_opt: Option<&str>,
        consuming_wallet_private_key_opt: Option<&str>,
        consuming_wallet_derivation_path_opt: Option<&str>,
        earning_wallet_address_opt: Option<&str>,
    ) -> PersistentConfigurationMock {
        let (mnemonic_seed_result, encrypted_mnemonic_seed_opt) =
            match (mnemonic_seed_prefix_opt, wallet_password_opt) {
                (None, None) => (Err(Bip39Error::NotPresent), None),
                (None, Some(_)) => (Err(Bip39Error::NotPresent), None),
                (Some(mnemonic_seed_prefix), None) => {
                    let mnemonic_seed = make_mnemonic_seed(mnemonic_seed_prefix);
                    let encrypted_mnemonic_seed =
                        Bip39::encrypt_bytes(&mnemonic_seed, "prompt for me").unwrap();
                    (Ok(mnemonic_seed), Some(encrypted_mnemonic_seed))
                }
                (Some(mnemonic_seed_prefix), Some(wallet_password)) => {
                    let mnemonic_seed = make_mnemonic_seed(mnemonic_seed_prefix);
                    let encrypted_mnemonic_seed =
                        Bip39::encrypt_bytes(&mnemonic_seed, wallet_password).unwrap();
                    (Ok(mnemonic_seed), Some(encrypted_mnemonic_seed))
                }
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
        PersistentConfigurationMock::new()
            .mnemonic_seed_result(mnemonic_seed_result)
            .encrypted_mnemonic_seed_result(encrypted_mnemonic_seed_opt)
            .consuming_wallet_public_key_result(consuming_wallet_public_key_opt)
            .consuming_wallet_derivation_path_result(consuming_wallet_derivation_path_opt)
            .earning_wallet_from_address_result(earning_wallet_from_address_opt)
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
        let multi_config = make_multi_config(
            ArgsBuilder::new()
                .param("--wallet-password", "password")
                .param("--consuming-private-key", &consuming_private_key_hex),
        );
        let mnemonic_seed_prefix = "mnemonic_seed";
        let persistent_config = make_persistent_config(
            Some(mnemonic_seed_prefix),
            Some("password"),
            None,
            Some("m/44'/60'/1'/2/3"),
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
                .param("--wallet-password", "password")
                .param("--consuming-private-key", &consuming_private_key_hex),
        );
        let mnemonic_seed_prefix = "mnemonic_seed";
        let persistent_config = make_persistent_config(
            Some(mnemonic_seed_prefix),
            Some("password"),
            None,
            None,
            Some("0xcafedeadbeefbabefacecafedeadbeefbabeface"),
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
                .param("--wallet-password", "password")
                .param("--consuming-private-key", &consuming_private_key_hex),
        );
        let persistent_config =
            make_persistent_config(None, None, Some(consuming_private_key_hex), None, None);
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
                .param("--wallet-password", "password")
                .param("--consuming-private-key", &bad_consuming_private_key_hex),
        );
        let persistent_config =
            make_persistent_config(None, None, Some(good_consuming_private_key_hex), None, None);
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
        let multi_config =
            make_multi_config(ArgsBuilder::new().param("--wallet-password", "password"));
        let mnemonic_seed_prefix = "mnemonic_seed";
        let persistent_config = make_persistent_config(
            Some(mnemonic_seed_prefix),
            Some("password"),
            None,
            Some("m/44'/60'/1'/2/3"),
            Some("0xcafedeadbeefbabefacecafedeadbeefbabeface"),
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
    fn consuming_wallet_derivation_path_plus_mnemonic_seed_with_no_wallet_password_parameter() {
        let multi_config = make_multi_config(ArgsBuilder::new());
        let mnemonic_seed_prefix = "mnemonic_seed";
        let persistent_config = make_persistent_config(
            Some(mnemonic_seed_prefix),
            None,
            None,
            Some("m/44'/60'/1'/2/3"),
            Some("0xcafedeadbeefbabefacecafedeadbeefbabeface"),
        );
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
    fn consuming_wallet_derivation_path_plus_mnemonic_seed_with_no_wallet_password_value() {
        let multi_config = make_multi_config(ArgsBuilder::new().opt("--wallet-password"));
        let mnemonic_seed_prefix = "mnemonic_seed";
        let persistent_config = make_persistent_config(
            Some(mnemonic_seed_prefix),
            None,
            None,
            Some("m/44'/60'/1'/2/3"),
            Some("0xcafedeadbeefbabefacecafedeadbeefbabeface"),
        );
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
            "Decrypt wallet from database\nEnter password: "
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

        let args = ArgsBuilder::new()
            .param("--dns-servers", "12.34.56.78,23.45.67.89")
            .param("--data-directory", home_directory.to_str().unwrap());
        let vcl_args: Vec<Box<dyn VclArg>> = vec![Box::new(NameValueVclArg::new(
            &"--consuming-private-key", // this is equal to SUB_CONSUMING_PRIVATE_KEY
            &"not valid hex",
        ))];

        let faux_environment = FauxEnvironmentVcl { vcl_args };

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
            .param("--dns-servers", "12.34.56.78,23.45.67.89")
            .param("--data-directory", home_directory.to_str().unwrap())
            .opt("--wallet-password");
        let vcl_args: Vec<Box<dyn VclArg>> = vec![Box::new(NameValueVclArg::new(
            &"--consuming-private-key", // this is equal to SUB_CONSUMING_PRIVATE_KEY
            &"cc46befe8d169b89db447bd725fc2368b12542113555302598430cb5d5c74ea9",
        ))];

        let faux_environment = FauxEnvironmentVcl { vcl_args };

        let mut config = BootstrapperConfig::new();
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
    #[should_panic(
        expected = "Could not verify password: ConversionError(\"Invalid character \\'o\\' at position 1\")"
    )]
    fn invalid_mnemonic_seed_causes_conversion_error_and_panics() {
        let data_directory = ensure_node_home_directory_exists(
            "node_configurator",
            "invalid_mnemonic_seed_causes_conversion_error_and_panics",
        );

        let conn = db_initializer::DbInitializerReal::new()
            .initialize(&data_directory, DEFAULT_CHAIN_ID)
            .unwrap();
        let config_dao: Box<dyn ConfigDao> = Box::new(ConfigDaoReal::new(conn));
        config_dao.set_string("seed", "booga booga").unwrap();
        let args = make_default_cli_params()
            .param("--data-directory", data_directory.to_str().unwrap())
            .param("--wallet-password", "rick-rolled");
        let mut config = BootstrapperConfig::new();
        let vcl = Box::new(CommandLineVcl::new(args.into()));
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
            .initialize(&data_directory, DEFAULT_CHAIN_ID)
            .unwrap();
        let config_dao: Box<dyn ConfigDao> = Box::new(ConfigDaoReal::new(conn));

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
        let args = make_default_cli_params()
            .param("--data-directory", data_directory.to_str().unwrap())
            .param("--wallet-password", "ricked rolled");
        let mut config = BootstrapperConfig::new();
        let vcl = Box::new(CommandLineVcl::new(args.into()));
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
        let args = ArgsBuilder::new()
            .param("--dns-servers", "1.2.3.4")
            .param("--config-file", "booga.toml"); // nonexistent config file: should stimulate panic because user-specified

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
        let args = ArgsBuilder::new()
            .param("--dns-servers", "1.2.3.4")
            .param("--config-file", "booga.toml"); // nonexistent config file: should stimulate panic because user-specified

        subject.configure(&args.into(), &mut FakeStreamHolder::new().streams());
    }

    #[test]
    fn privileged_configuration_accepts_network_chain_selection_for_multinode() {
        let subject = NodeConfiguratorStandardPrivileged {};
        let args = ArgsBuilder::new()
            .param("--dns-servers", "1.2.3.4")
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
            .param("--dns-servers", "1.2.3.4")
            .param("--ip", "1.2.3.4")
            .param("--chain", "ropsten");

        let config = subject.configure(&args.into(), &mut FakeStreamHolder::new().streams());

        assert_eq!(
            config.blockchain_bridge_config.chain_id,
            chain_id_from_name("ropsten")
        );
    }

    #[test]
    fn privileged_configuration_defaults_network_chain_selection_to_ropsten() {
        let subject = NodeConfiguratorStandardPrivileged {};
        let args = ArgsBuilder::new()
            .param("--dns-servers", "1.2.3.4")
            .param("--ip", "1.2.3.4");

        let config = subject.configure(&args.into(), &mut FakeStreamHolder::new().streams());

        assert_eq!(
            config.blockchain_bridge_config.chain_id,
            chain_id_from_name(DEFAULT_CHAIN_NAME)
        );
    }

    #[test]
    fn privileged_configuration_rejects_mainnet_network_chain_selection() {
        let subject = NodeConfiguratorStandardPrivileged {};
        let args = ArgsBuilder::new()
            .param("--dns-servers", "1.2.3.4")
            .param("--ip", "1.2.3.4")
            .param("--chain", "mainnet");

        let bootstrapper_config =
            subject.configure(&args.into(), &mut FakeStreamHolder::new().streams());
        assert_eq!(
            bootstrapper_config.blockchain_bridge_config.chain_id,
            chain_id_from_name("mainnet")
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
            .param("--dns-servers", "1.2.3.4")
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
        let args = ArgsBuilder::new().param("--dns-servers", "1.2.3.4");

        let config = subject.configure(&args.into(), &mut FakeStreamHolder::new().streams());

        assert_eq!(config.blockchain_bridge_config.gas_price, None);
    }

    #[test]
    #[should_panic(expected = "error: Invalid value for \\'--gas-price <GAS-PRICE>\\': unleaded")]
    fn privileged_configuration_rejects_invalid_gas_price() {
        let subject = NodeConfiguratorStandardPrivileged {};
        let args = ArgsBuilder::new()
            .param("--dns-servers", "1.2.3.4")
            .param("--gas-price", "unleaded");

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
