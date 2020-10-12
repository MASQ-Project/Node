use crate::constants::{
    DEFAULT_CHAIN_NAME, DEFAULT_GAS_PRICE, DEFAULT_UI_PORT, HIGHEST_USABLE_PORT,
    LOWEST_USABLE_INSECURE_PORT,
};
use crate::crash_point::CrashPoint;
use clap::{App, Arg};
use lazy_static::lazy_static;

pub const BLOCKCHAIN_SERVICE_HELP: &str =
    "The Ethereum client you wish to use to provide Blockchain \
     exit services from your MASQ Node (e.g. http://localhost:8545, \
     https://ropsten.infura.io/v3/YOUR-PROJECT-ID, https://mainnet.infura.io/v3/YOUR-PROJECT-ID).";
pub const CHAIN_HELP: &str =
    "The blockchain network MASQ Node will configure itself to use. You must ensure the \
    Ethereum client specified by --blockchain-service-url communicates with the same blockchain network.";
pub const CONFIG_FILE_HELP: &str =
    "Optional TOML file containing configuration that doesn't often change. Should contain only \
     scalar items, string or numeric, whose names are exactly the same as the command-line parameters \
     they replace (except no '--' prefix). If you specify a relative path, or no path, the Node will \
     look for your config file starting in the --data-directory. If you specify an absolute path, \
     --data-directory will be ignored when searching for the config file. A few parameters \
     (such as --config-file, --generate-wallet, and --recover-wallet) must not be specified in a config file.";
pub const CONSUMING_PRIVATE_KEY_HELP: &str = "The private key for the Ethereum wallet from which you wish to pay \
     other Nodes for routing and exit services. Mostly this is used for testing; be careful using it for real \
     traffic, because this value is very sensitive: anyone who sees it can use it to drain your consuming wallet. \
     If you use it, don't put it on the command line (the environment is good, the config file is less so), \
     make sure you haven't already set up a consuming wallet with a derivation path, and make sure that you always \
     supply exactly the same private key every time you run the Node. A consuming private key is 64 case-insensitive \
     hexadecimal digits.";
pub const DATA_DIRECTORY_HELP: &str =
    "Directory in which the Node will store its persistent state, including at \
     least its database and by default its configuration file as well.";
pub const DB_PASSWORD_HELP: &str =
    "A password or phrase to decrypt the encrypted material in the database, to include your \
     mnemonic seed (if applicable) and your list of previous neighbors. If you don't provide this \
     password, none of the encrypted data in your database will be used.";
pub const DNS_SERVERS_HELP: &str =
    "IP addresses of DNS Servers for host name look-up while providing exit \
     services for other MASQ Nodes (e.g. 1.0.0.1,1.1.1.1,8.8.8.8,9.9.9.9, etc.)";
pub const EARNING_WALLET_HELP: &str =
    "An Ethereum wallet address. Addresses must begin with 0x followed by 40 hexadecimal digits \
     (case-insensitive). If you already have a derivation-path earning wallet, don't supply this. \
     If you have supplied an earning wallet address before, either don't supply it again or be \
     careful to supply exactly the same one you supplied before.";
pub const IP_ADDRESS_HELP: &str = "The public IP address of your MASQ Node: that is, the IPv4 \
     address at which other Nodes can contact yours. If you're running your Node behind \
     a router, this will be the IP address of the router. If this IP address starts with 192.168 or 10.0, \
     it's a local address rather than a public address, and other Nodes won't be able to see yours. \
     --ip is meaningless except in --neighborhood-mode standard.";
pub const LOG_LEVEL_HELP: &str =
    "The minimum severity of the logs that should appear in the Node's logfile. You should probably not specify \
     a level lower than the default unless you're doing testing or forensics: a Node at the 'trace' log level \
     generates a lot of log traffic. This will both consume your disk space and degrade your Node's performance. \
     You should probably not specify a level higher than the default unless you have security concerns about \
     persistent logs being kept on your computer: if your Node crashes, it's good to know why.";
pub const NEIGHBORS_HELP: &str = "One or more Node descriptors for running Nodes in the MASQ \
     Network to which you'd like your Node to connect on startup. A Node descriptor looks like \
     this:\n\ngBviQbjOS3e5ReFQCvIhUM3i02d1zPleo1iXg/EN6zQ:86.75.30.9:5542 (initial ':' for testnet) and\n\
     gBviQbjOS3e5ReFQCvIhUM3i02d1zPleo1iXg/EN6zQ@86.75.30.9:5542 (initial '@' for mainnet)\n\n\
     If you have more than one, separate them with commas (but no spaces). There is no default value; \
     if you don't specify a neighbor, your Node will start without being connected to any MASQ \
     Network, although other Nodes will be able to connect to yours if they know your Node's descriptor. \
     --neighbors is meaningless in --neighborhood-mode zero-hop.";
pub const NEIGHBORHOOD_MODE_HELP: &str = "This configures the way the Node relates to other Nodes.\n\n\
     zero-hop means that your Node will operate as its own MASQ Network and will not communicate with any \
     other Nodes. --ip, --neighbors, and --clandestine-port are incompatible with --neighborhood_mode \
     zero-hop.\n\n\
     originate-only means that your Node will not accept connections from any other Node; it \
     will only originate connections to other Nodes. This will reduce your Node's opportunity to route \
     data (it will only ever have two neighbors, so the number of routes it can participate in is limited), \
     it will reduce redundancy in the MASQ Network, and it will prevent your Node from acting as \
     a connection point for other Nodes to get on the Network; but it will enable your Node to operate in \
     an environment where your network hookup is preventing you from accepting connections, and it means \
     that you don't have to forward any incoming ports through your router. --ip and --clandestine_port \
     are incompatible with --neighborhood_mode originate-only.\n\n\
     consume-only means that your Node will not accept connections from or route data for any other Node; \
     it will only consume services from the MASQ Network. This mode is appropriate for devices that \
     cannot maintain a constant IP address or stay constantly on the Network. --ip and --clandestine_port \
     are incompatible with --neighborhood_mode consume-only.\n\n\
     standard means that your Node will operate fully unconstrained, both originating and accepting \
     connections, both consuming and providing services, and when you operate behind a router, it \
     requires that you forward your clandestine port through that router to your Node's machine.";
pub const REAL_USER_HELP: &str =
    "The user whose identity Node will assume when dropping privileges after bootstrapping. Since Node refuses to \
     run with root privilege after bootstrapping, you might want to use this if you start the Node as root, or if \
     you start the Node using pkexec or some other method that doesn't populate the SUDO_xxx variables. Use a value \
     like <uid>:<gid>:<home directory>.";

lazy_static! {
    pub static ref DEFAULT_UI_PORT_VALUE: String = DEFAULT_UI_PORT.to_string();
    pub static ref UI_PORT_HELP: String = format!(
        "The port at which user interfaces will connect to the Node. Best to accept the default unless \
        you know what you're doing. Must be between {} and {}.",
        LOWEST_USABLE_INSECURE_PORT, HIGHEST_USABLE_PORT
    );
    pub static ref CLANDESTINE_PORT_HELP: String = format!(
        "The port this Node will advertise to other Nodes at which clandestine traffic will be \
         received. If you don't specify a clandestine port, the Node will choose an unused \
         one at random on first startup, then use that one for every subsequent run unless \
         you change it by specifying a different clandestine port here. --clandestine-port is \
         meaningless except in --neighborhood-mode standard. \
         Must be between {} and {} [default: last used port]",
        LOWEST_USABLE_INSECURE_PORT, HIGHEST_USABLE_PORT
    );
    pub static ref GAS_PRICE_HELP: String = format!(
       "The Gas Price is the amount of Gwei you will pay per unit of gas used in a transaction. \
       If left unspecified, MASQ Node will use the previously stored value (Default {}). Valid range is 1-99 Gwei.",
       DEFAULT_GAS_PRICE);
}

// These Args are needed in more than one clap schema. To avoid code duplication, they're defined here and referred
// to from multiple places.
pub fn config_file_arg<'a>() -> Arg<'a, 'a> {
    Arg::with_name("config-file")
        .long("config-file")
        .value_name("FILE-PATH")
        .default_value("config.toml")
        .min_values(0)
        .max_values(1)
        .required(false)
        .help(CONFIG_FILE_HELP)
}

pub fn data_directory_arg<'a>() -> Arg<'a, 'a> {
    Arg::with_name("data-directory")
        .long("data-directory")
        .value_name("DATA-DIRECTORY")
        .required(false)
        .min_values(0)
        .max_values(1)
        .empty_values(false)
        .help(DATA_DIRECTORY_HELP)
}

pub fn chain_arg<'a>() -> Arg<'a, 'a> {
    Arg::with_name("chain")
        .long("chain")
        .value_name("CHAIN")
        .min_values(0)
        .max_values(1)
        .possible_values(&["dev", DEFAULT_CHAIN_NAME, "ropsten", "rinkeby"])
        .help(CHAIN_HELP)
}

pub fn db_password_arg(help: &str) -> Arg {
    Arg::with_name("db-password")
        .long("db-password")
        .value_name("DB-PASSWORD")
        .required(false)
        .min_values(0)
        .max_values(1)
        .help(help)
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
        .min_values(0)
        .max_values(1)
        .validator(validator)
        .help(help)
}

#[cfg(not(target_os = "windows"))]
pub fn real_user_arg<'a>() -> Arg<'a, 'a> {
    Arg::with_name("real-user")
        .long("real-user")
        .value_name("REAL-USER")
        .required(false)
        .min_values(0)
        .max_values(1)
        .validator(common_validators::validate_real_user)
        .help(REAL_USER_HELP)
}

#[cfg(target_os = "windows")]
pub fn real_user_arg<'a>() -> Arg<'a, 'a> {
    Arg::with_name("real-user")
        .long("real-user")
        .value_name("REAL-USER")
        .required(false)
        .takes_value(true)
        .validator(common_validators::validate_real_user)
        .hidden(true)
}

pub fn ui_port_arg(help: &str) -> Arg {
    Arg::with_name("ui-port")
        .long("ui-port")
        .value_name("UI-PORT")
        .takes_value(true)
        .default_value(&DEFAULT_UI_PORT_VALUE)
        .validator(common_validators::validate_ui_port)
        .help(help)
}

pub fn shared_app(head: App<'static, 'static>) -> App<'static, 'static> {
    head.arg(
        Arg::with_name("blockchain-service-url")
            .long("blockchain-service-url")
            .empty_values(false)
            .value_name("URL")
            .min_values(0)
            .max_values(1)
            .help(BLOCKCHAIN_SERVICE_HELP),
    )
    .arg(
        Arg::with_name("clandestine-port")
            .long("clandestine-port")
            .value_name("CLANDESTINE-PORT")
            .empty_values(false)
            .min_values(0)
            .validator(common_validators::validate_clandestine_port)
            .help(&CLANDESTINE_PORT_HELP),
    )
    .arg(config_file_arg())
    .arg(
        Arg::with_name("consuming-private-key")
            .long("consuming-private-key")
            .value_name("PRIVATE-KEY")
            .min_values(0)
            .max_values(1)
            .validator(common_validators::validate_private_key)
            .help(CONSUMING_PRIVATE_KEY_HELP),
    )
    .arg(
        Arg::with_name("crash-point")
            .long("crash-point")
            .value_name("CRASH-POINT")
            .min_values(0)
            .max_values(1)
            .possible_values(&CrashPoint::variants())
            .case_insensitive(true)
            .hidden(true),
    )
    .arg(data_directory_arg())
    .arg(db_password_arg(DB_PASSWORD_HELP))
    .arg(
        Arg::with_name("dns-servers")
            .long("dns-servers")
            .value_name("DNS-SERVERS")
            .min_values(0)
            .max_values(1)
            .validator(common_validators::validate_ip_addresses)
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
            .min_values(0)
            .max_values(1)
            .hidden(true),
    )
    .arg(
        Arg::with_name("gas-price")
            .long("gas-price")
            .value_name("GAS-PRICE")
            .min_values(0)
            .max_values(1)
            .validator(common_validators::validate_gas_price)
            .help(&GAS_PRICE_HELP),
    )
    .arg(
        Arg::with_name("ip")
            .long("ip")
            .value_name("IP")
            .min_values(0)
            .max_values(1)
            .validator(common_validators::validate_ip_address)
            .help(IP_ADDRESS_HELP),
    )
    .arg(
        Arg::with_name("log-level")
            .long("log-level")
            .value_name("FILTER")
            .min_values(0)
            .max_values(1)
            .possible_values(&["off", "error", "warn", "info", "debug", "trace"])
            .case_insensitive(true)
            .help(LOG_LEVEL_HELP),
    )
    .arg(
        Arg::with_name("neighborhood-mode")
            .long("neighborhood-mode")
            .value_name("NEIGHBORHOOD-MODE")
            .min_values(0)
            .max_values(1)
            .possible_values(&["zero-hop", "originate-only", "consume-only", "standard"])
            .case_insensitive(true)
            .help(NEIGHBORHOOD_MODE_HELP),
    )
    .arg(
        Arg::with_name("neighbors")
            .long("neighbors")
            .value_name("NODE-DESCRIPTORS")
            .min_values(0)
            .help(NEIGHBORS_HELP),
    )
    .arg(real_user_arg())
}

pub mod common_validators {
    use crate::constants::LOWEST_USABLE_INSECURE_PORT;
    use regex::Regex;
    use std::net::IpAddr;
    use std::str::FromStr;
    use tiny_hderive::bip44::DerivationPath;

    pub fn validate_ip_address(address: String) -> Result<(), String> {
        match IpAddr::from_str(&address) {
            Ok(_) => Ok(()),
            Err(_) => Err(address),
        }
    }

    pub fn validate_ip_addresses(addresses: String) -> Result<(), String> {
        let errors = addresses
            .split(',')
            .map(|address| validate_ip_address(address.to_string()))
            .flat_map(|result| match result {
                Ok(_) => None,
                Err(e) => Some(format!("{:?}", e)),
            })
            .collect::<Vec<String>>()
            .join(";");
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
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

#[derive(Debug, PartialEq, Clone)]
pub struct ParamError {
    pub parameter: String,
    pub reason: String,
}

impl ParamError {
    pub fn new(parameter: &str, reason: &str) -> Self {
        Self {
            parameter: parameter.to_string(),
            reason: reason.to_string(),
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct ConfiguratorError {
    pub param_errors: Vec<ParamError>,
}

impl ConfiguratorError {
    pub fn new(param_errors: Vec<ParamError>) -> Self {
        Self { param_errors }
    }

    pub fn required(parameter: &str, reason: &str) -> Self {
        ConfiguratorError {
            param_errors: vec![ParamError::new(parameter, reason)],
        }
    }

    pub fn another_required(mut self, parameter: &str, reason: &str) -> Self {
        self.param_errors.push(ParamError::new(parameter, reason));
        self
    }

    pub fn extend(&mut self, extension: Self) {
        self.param_errors.extend(extension.param_errors);
    }
}

#[cfg(test)]
mod tests {
    use crate::shared_schema::common_validators;

    #[test]
    fn validate_private_key_requires_a_key_that_is_64_characters_long() {
        let result = common_validators::validate_private_key(String::from("42"));

        assert_eq!(Err("42".to_string()), result);
    }

    #[test]
    fn validate_private_key_must_contain_only_hex_characters() {
        let result = common_validators::validate_private_key(String::from(
            "cc46befe8d169b89db447bd725fc2368b12542113555302598430cinvalidhex",
        ));

        assert_eq!(
            Err("cc46befe8d169b89db447bd725fc2368b12542113555302598430cinvalidhex".to_string()),
            result
        );
    }

    #[test]
    fn validate_private_key_handles_happy_path() {
        let result = common_validators::validate_private_key(String::from(
            "cc46befe8d169b89db447bd725fc2368b12542113555302598430cb5d5c74ea9",
        ));

        assert_eq!(Ok(()), result);
    }

    #[test]
    fn validate_ip_address_given_invalid_input() {
        assert_eq!(
            Err(String::from("not-a-valid-IP")),
            common_validators::validate_ip_address(String::from("not-a-valid-IP")),
        );
    }

    #[test]
    fn validate_ip_address_given_valid_input() {
        assert_eq!(
            Ok(()),
            common_validators::validate_ip_address(String::from("1.2.3.4"))
        );
    }

    #[test]
    fn validate_ui_port_complains_about_non_numeric_ui_port() {
        let result = common_validators::validate_ui_port(String::from("booga"));

        assert_eq!(Err(String::from("booga")), result);
    }

    #[test]
    fn validate_ui_port_complains_about_ui_port_too_low() {
        let result = common_validators::validate_ui_port(String::from("1023"));

        assert_eq!(Err(String::from("1023")), result);
    }

    #[test]
    fn validate_ui_port_complains_about_ui_port_too_high() {
        let result = common_validators::validate_ui_port(String::from("65536"));

        assert_eq!(Err(String::from("65536")), result);
    }

    #[test]
    fn validate_ui_port_works() {
        let result = common_validators::validate_ui_port(String::from("5335"));

        assert_eq!(Ok(()), result);
    }

    #[test]
    fn validate_clandestine_port_rejects_badly_formatted_port_number() {
        let result = common_validators::validate_clandestine_port(String::from("booga"));

        assert_eq!(Err(String::from("booga")), result);
    }

    #[test]
    fn validate_clandestine_port_rejects_port_number_too_low() {
        let result = common_validators::validate_clandestine_port(String::from("1024"));

        assert_eq!(Err(String::from("1024")), result);
    }

    #[test]
    fn validate_clandestine_port_rejects_port_number_too_high() {
        let result = common_validators::validate_clandestine_port(String::from("65536"));

        assert_eq!(Err(String::from("65536")), result);
    }

    #[test]
    fn validate_clandestine_port_accepts_port_if_provided() {
        let result = common_validators::validate_clandestine_port(String::from("4567"));

        assert!(result.is_ok());
        assert_eq!(Ok(()), result);
    }

    #[test]
    fn validate_gas_price_zero() {
        let result = common_validators::validate_gas_price("0".to_string());

        assert!(result.is_err());
        assert_eq!(Err(String::from("0")), result);
    }

    #[test]
    fn validate_gas_price_normal_ropsten() {
        let result = common_validators::validate_gas_price("2".to_string());

        assert!(result.is_ok());
        assert_eq!(Ok(()), result);
    }

    #[test]
    fn validate_gas_price_normal_mainnet() {
        let result = common_validators::validate_gas_price("20".to_string());

        assert!(result.is_ok());
        assert_eq!(Ok(()), result);
    }

    #[test]
    fn validate_gas_price_max() {
        let result = common_validators::validate_gas_price("99".to_string());
        assert!(result.is_ok());
        assert_eq!(Ok(()), result);
    }

    #[test]
    fn validate_gas_price_too_large_and_fails() {
        let result = common_validators::validate_gas_price("100".to_string());
        assert!(result.is_err());
        assert_eq!(Err(String::from("100")), result);
    }

    #[test]
    fn validate_gas_price_not_digits_fails() {
        let result = common_validators::validate_gas_price("not".to_string());
        assert!(result.is_err());
        assert_eq!(Err(String::from("not")), result);
    }

    #[test]
    fn validate_gas_price_hex_fails() {
        let result = common_validators::validate_gas_price("0x0".to_string());
        assert!(result.is_err());
        assert_eq!(Err(String::from("0x0")), result);
    }
}
