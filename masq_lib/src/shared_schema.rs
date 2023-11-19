use std::fmt::{Display, Formatter};
use crate::constants::{
    DEFAULT_GAS_PRICE, DEFAULT_UI_PORT, DEV_CHAIN_FULL_IDENTIFIER, ETH_MAINNET_FULL_IDENTIFIER,
    ETH_ROPSTEN_FULL_IDENTIFIER, HIGHEST_USABLE_PORT, LOWEST_USABLE_INSECURE_PORT,
    POLYGON_MAINNET_FULL_IDENTIFIER, POLYGON_MUMBAI_FULL_IDENTIFIER,
};
use clap::{value_parser, Arg, Command};
use lazy_static::lazy_static;
use std::net::IpAddr;
use std::path::PathBuf;
use std::str::FromStr;
use clap::builder::ValueRange;
use itertools::Itertools;
use url::Url;
use crate::blockchains::chains::Chain;
use crate::crash_point::CrashPoint;
use crate::node_addr::NodeAddr;

pub const BLOCKCHAIN_SERVICE_HELP: &str =
    "The Ethereum client you wish to use to provide Blockchain \
     exit services from your MASQ Node (e.g. http://localhost:8545, \
     https://ropsten.infura.io/v3/YOUR-PROJECT-ID, https://mainnet.infura.io/v3/YOUR-PROJECT-ID), \
     https://polygon-mainnet.infura.io/v3/YOUR-PROJECT-ID";
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
    "Directory in which the Node will store its persistent state, including at least its database \
    and by default its configuration file as well.\nNote: any existing database in the data directory \
    must have been created from the same chain this run is using, or the Node will be terminated.";
pub const DB_PASSWORD_HELP: &str =
    "A password or phrase to decrypt the encrypted material in the database, to include your \
     mnemonic seed (if applicable) and your list of previous neighbors. If you don't provide this \
     password, none of the encrypted data in your database will be used. This is a secret;\
     providing it on the command line or in a config file may be insecure";
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
     One or more Node descriptors for active Nodes in the MASQ Network to which you'd like your Node to connect \
     on startup. A Node descriptor looks similar to one of these:\n\n\
     masq://polygon-mainnet:d2U3Dv1BqtS5t_Zz3mt9_sCl7AgxUlnkB4jOMElylrU@172.50.48.6:9342\n\
     masq://eth-mainnet:gBviQbjOS3e5ReFQCvIhUM3i02d1zPleo1iXg_EN6zQ@86.75.30.9:5542\n\
     masq://polygon-mumbai:A6PGHT3rRjaeFpD_rFi3qGEXAVPq7bJDfEUZpZaIyq8@14.10.50.6:10504\n\
     masq://eth-ropsten:OHsC2CAm4rmfCkaFfiynwxflUgVTJRb2oY5mWxNCQkY@150.60.42.72:6642/4789/5254\n\n\
     Notice each of the different chain identifiers in the masq protocol prefix - they determine a family of chains \
     and also the network the descriptor belongs to (mainnet or a testnet). See also the last descriptor which shows \
     a configuration with multiple clandestine ports.\n\n\
     If you have more than one descriptor, separate them with commas. Whether single or multiple descriptors, they \
     should be enclosed by quotes. No default value is available; \
     if you don't specify a neighbor, your Node will start without being connected to any MASQ \
     Network, although other Nodes will be able to connect to yours if they know your Node's descriptor. \
     --neighbors is meaningless in --neighborhood-mode zero-hop.";

// generated valid encoded keys for future needs
// UJNoZW5p/PDVqEjpr3b+8jZ/93yPG8i5dOAgE1bhK+A
// ZjPLnb9RrgsRM1D9edqH8jx9DkbPZSWqqFqLnmdKhsk
// BE1ZIbcxwGTQjzzkkq3qSAK6YKsu8ncVzUfMxTdw5fc

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
pub const MAPPING_PROTOCOL_HELP: &str =
    "The Node can speak three protocols to your router to make it allow outside Nodes to connect inward \
    through it to your machine. These three protocols are pcp, pmp, and igdp. The Node can try them one \
    by one to determine which your router supports, but if you happen to know already, you can supply the \
    name of the protocol here. If you've taken care of port mapping in some other way, \
    and you don't need Node to negotiate with your router, say 'none' here and be sure to specify your \
    public IP address with the --ip parameter. If the Node communicates successfully with your router, \
    it will remember the protocol it used, and on its next run it will try that protocol first, unless \
    you specify a different protocol on the command line.";
pub const MIN_HOPS_HELP: &str =
    "The Node is a system that routes data through multiple Nodes to enhance security and privacy. \
    However, the level of anonymity and security provided depends on the number of hops specified \
    by the user. By default, the system allows the user to customize the number of hops within a \
    range of 1 to 6.\n\n\
    It's important to note that if the user selects less than 3 hops, the anonymity of their data \
    cannot be guaranteed. Here's a breakdown of the different hop counts and their implications:\n\n\
    1. A 1-hop route means that the exit Node will know the IP address of the originating Node. \
    Also, someone snooping traffic on the network will be able to see both the originating Node's IP \
    and the exit Node's IP in the same packet. A 1-hop route makes MASQ the equivalent of a VPN. \n\
    2. A 2-hop route removes the ability to see both the originating and exit IP addresses on the \
    same packet, but it means that the relay Node in the middle (which could be subverted by an attacker) \
    knows both IP addresses.\n\
    3. A 3-hop route is the shortest route that prevents any Node in the network (even the originating Node) \
    from knowing the IP addresses of all the Nodes in the route.\n\
    4. Increasing the number of hops to 4, 5, or 6 can enhance security, but it will also \
    increase the cost and latency of the route.\n\
    If you want to specify a minimum hops count, you can do so by entering a number after the \
    '--min-hops' parameter. For example, '--min-hops 4' would require at least 4 hops. If you fail \
    to provide this argument, the system will default to a minimum hops count of 3.";
pub const REAL_USER_HELP: &str =
    "The user whose identity Node will assume when dropping privileges after bootstrapping. Since Node refuses to \
     run with root privilege after bootstrapping, you might want to use this if you start the Node as root, or if \
     you start the Node using pkexec or some other method that doesn't populate the SUDO_xxx variables. Use a value \
     like <uid>:<gid>:<home directory>.";
pub const SCANS_HELP: &str =
    "The Node, when running, performs various periodic scans, including scanning for payables that need to be paid, \
    for pending payables that have arrived (and are no longer pending), for incoming receivables that need to be \
    recorded, and for delinquent Nodes that need to be banned. If you don't specify this parameter, or if you give \
    it the value 'on', these scans will proceed normally. But if you give the value 'off', the scans won't be \
    started when the Node starts, and will have to be triggered later manually and individually with the \
    MASQNode-UIv2 'scan' command. (If you don't, you'll most likely be delinquency-banned by all your neighbors.) \
    This parameter is most useful for testing.";
pub const RATE_PACK_HELP: &str = "\
     These four parameters specify your rates that your Node will use for charging other Nodes for your provided \
     services. These are ever present values, defaulted if left unspecified. The parameters must be always supplied \
     all together, delimited by vertical bars and in the right order.\n\n\
     1. Routing Byte Rate: This parameter indicates an amount of MASQ in wei demanded to process 1 byte of routed payload \
     while the Node is a common relay Node.\n\n\
     2. Routing Service Rate: This parameter indicates an amount of MASQ in wei demanded to provide services, unpacking \
     and repacking 1 CORES package, while the Node is a common relay Node.\n\n\
     3. Exit Byte Rate: This parameter indicates an amount of MASQ in wei demanded to process 1 byte of routed payload \
     while the Node acts as the exit Node.\n\n\
     4. Exit Service Rate: This parameter indicates an amount of MASQ in wei demanded to provide services, unpacking and \
     repacking 1 CORES package, while the Node acts as the exit Node.";
pub const PAYMENT_THRESHOLDS_HELP: &str = "\
     These are parameters that define thresholds to determine when and how much to pay other Nodes for routing and \
     exit services and the expectations the Node should have for receiving payments from other Nodes for routing and \
     exit services. The thresholds are also used to determine whether to offer services to other Nodes or enact a ban \
     since they have not paid mature debts. These are ever present values, no matter if the user's set any value, as \
     they have defaults. The parameters must be always supplied all together, delimited by vertical bars and in the right \
     order.\n\n\
     1. Debt Threshold gwei: Payables higher than this -- in gwei of MASQ -- will be suggested for payment immediately \
     upon passing the Maturity Threshold Sec age. Payables less than this can stay unpaid longer. Receivables higher than \
     this will be expected to be settled by other Nodes, but will never cause bans until they pass the Maturity Threshold Sec \
     + Payment Grace Period Sec age. Receivables less than this will survive longer without banning.\n\n\
     2. Maturity Threshold Sec: Large payables can get this old -- in seconds -- before the Accountant's scanner suggests \
     that it be paid.\n\n\
     3. Payment Grace Period Sec: A large receivable can get as old as Maturity Threshold Sec + Payment Grace Period Sec \
     -- in seconds -- before the Node that owes it will be banned.\n\n\
     4. Permanent Debt Allowed gwei: Receivables this small and smaller -- in gwei of MASQ -- will not cause bans no \
     matter how old they get.\n\n\
     5. Threshold Interval Sec: This interval -- in seconds -- begins after Maturity Threshold Sec for payables and after \
     Maturity Threshold Sec + Payment Grace Period Sec for receivables. During the interval, the amount of a payable that is \
     allowed to remain unpaid, or a pending receivable that won’t cause a ban, decreases linearly from the Debt Threshold gwei \
     to Permanent Debt Allowed gwei or Unban Below gwei.\n\n\
     6. Unban Below gwei: When a delinquent Node has been banned due to non-payment, the receivables balance must be paid \
     below this level -- in gwei of MASQ -- to cause them to be unbanned. In most cases, you'll want this to be set the same \
     as Permanent Debt Allowed gwei.";
// TODO Need an example for SCAN_INTERVALS_HELP
pub const SCAN_INTERVALS_HELP:&str = "\
     These three intervals describe the length of three different scan cycles running automatically in the background \
     since the Node has connected to a qualified neighborhood that consists of neighbors enabling a complete 3-hop \
     route. Each parameter can be set independently, but by default are all the same which currently is most desirable \
     for the consistency of service payments to and from your Node. Technically, there doesn't have to be any lower \
     limit for the minimum of time you can set; two scans of the same sort would never run at the same time but the \
     next one is always scheduled not earlier than the end of the previous one. These are ever present values, no matter \
     if the user's set any value, they have defaults. The parameters must be always supplied all together, delimited by vertical \
     bars and in the right order.\n\n\
     1. Pending Payable Scan Interval: Amount of seconds between two sequential cycles of scanning for payments that are \
     marked as currently pending; the payments were sent to pay our debts, the payable. The purpose of this process is to \
     confirm the status of the pending payment; either the payment transaction was written on blockchain as successful or \
     failed.\n\n\
     2. Payable Scan Interval: Amount of seconds between two sequential cycles of scanning aimed to find payable accounts \
     of that meet the criteria set by the Payment Thresholds; these accounts are tracked on behalf of our creditors. If \
     they meet the Payment Threshold criteria, our Node will send a debt payment transaction to the creditor in question.\n\n\
     3. Receivable Scan Interval: Amount of seconds between two sequential cycles of scanning for payments on the \
     blockchain that have been sent by our creditors to us, which are credited against receivables recorded for services \
     provided.";

lazy_static! {
    pub static ref DEFAULT_UI_PORT_VALUE: String = DEFAULT_UI_PORT.to_string();
    pub static ref UI_PORT_HELP: String = format!(
        "The port at which user interfaces will connect to the Node. Best to accept the default unless \
        you know what you're doing. Must be between {} and {}.",
        LOWEST_USABLE_INSECURE_PORT, HIGHEST_USABLE_PORT
    );
}

#[allow(non_snake_case)]
pub fn CLANDESTINE_PORT_HELP() -> String {
    format!(
        "The port this Node will advertise to other Nodes at which clandestine traffic will be \
         received. If you don't specify a clandestine port, the Node will choose an unused \
         one at random on first startup, then use that one for every subsequent run unless \
         you change it by specifying a different clandestine port here. --clandestine-port is \
         meaningless except in --neighborhood-mode standard. \
         Must be between {} and {} [default: last used port]",
        LOWEST_USABLE_INSECURE_PORT, HIGHEST_USABLE_PORT
    )
}

#[allow(non_snake_case)]
pub fn GAS_PRICE_HELP() -> String {
    format!(
        "The Gas Price is the amount of gwei you will pay per unit of gas used in a transaction. \
       If left unspecified, MASQ Node will use the previously stored value (Default {}).",
        DEFAULT_GAS_PRICE
    )
}

// These Args are needed in more than one clap schema. To avoid code duplication, they're defined here and referred
// to from multiple places.
pub fn config_file_arg() -> Arg {
    Arg::new("config-file")
        .long("config-file")
        .value_name("FILE-PATH")
        .default_value("config.toml")
        .num_args(ValueRange::new(0..=1))
        .value_parser(value_parser!(ConfigFile))
        .required(false)
        .help(CONFIG_FILE_HELP)
}

pub fn data_directory_arg(help: String) -> Arg {
    Arg::new("data-directory")
        .long("data-directory")
        .value_name("DATA-DIRECTORY")
        .required(false)
        .num_args(ValueRange::new(0..=1))
        .value_parser(value_parser!(DataDirectory))
        .help(help)
}

pub fn chain_arg() -> Arg {
    Arg::new("chain")
        .long("chain")
        .value_name("CHAIN")
        .num_args(ValueRange::new(0..=1))
        .value_parser(value_parser!(Chain))
        .help(CHAIN_HELP)
}

pub fn official_chain_names() -> &'static [&'static str] {
    &[
        POLYGON_MAINNET_FULL_IDENTIFIER,
        ETH_MAINNET_FULL_IDENTIFIER,
        POLYGON_MUMBAI_FULL_IDENTIFIER,
        ETH_ROPSTEN_FULL_IDENTIFIER,
        DEV_CHAIN_FULL_IDENTIFIER,
    ]
}

pub fn db_password_arg(help: String) -> Arg {
    Arg::new("db-password")
        .long("db-password")
        .value_name("DB-PASSWORD")
        .required(false)
        .num_args(ValueRange::new(0..=1))
        .help(help)
}

pub fn earning_wallet_arg(help: String) -> Arg {
    Arg::new("earning-wallet")
        .long("earning-wallet")
        .value_name("EARNING-WALLET")
        .required(false)
        .num_args(ValueRange::new(0..=1))
        .value_parser(value_parser!(common_validators::Wallet))
        .help(help)
}

#[cfg(not(target_os = "windows"))]
pub fn real_user_arg() -> Arg {
    Arg::new("real-user")
        .long("real-user")
        .value_name("REAL-USER")
        .required(false)
        .num_args(ValueRange::new(0..=1))
        .value_parser(value_parser!(common_validators::RealUser))
        .help(REAL_USER_HELP)
}

#[cfg(target_os = "windows")]
pub fn real_user_arg<'a>() -> Arg {
    Arg::new("real-user")
        .long("real-user")
        .value_name("REAL-USER")
        .required(false)
        .takes_value(true)
        .value_parser(value_parser!(common_validators::RealUser))
        .hidden(true)
}

pub fn ui_port_arg(help: String) -> Arg {
    Arg::new("ui-port")
        .long("ui-port")
        .value_name("UI-PORT")
        .default_value(DEFAULT_UI_PORT_VALUE.as_str())
        .value_parser(value_parser!(common_validators::InsecurePort))
        .help(help)
}

fn common_parameter_with_separate_u64_values(name: &'static str, help: String) -> Arg {
    Arg::new(name)
        .long(name)
        .value_name(name.to_uppercase())
        .num_args(ValueRange::new(0..=1))
        .help(help)
        .value_parser(value_parser!(common_validators::VecU64))
}

pub fn shared_app(head: Command) -> Command {
    head.arg(
        Arg::new("blockchain-service-url")
            .long("blockchain-service-url")
            .value_name("URL")
            .num_args(ValueRange::new(0..=1))
            .value_parser(value_parser!(Url))
            .help(BLOCKCHAIN_SERVICE_HELP),
    )
    .arg(chain_arg())
    .arg(
        Arg::new("clandestine-port")
            .long("clandestine-port")
            .value_name("CLANDESTINE-PORT")
            .num_args(ValueRange::new(0..)) // TODO: Should this be 0..=1 instead?
            .value_parser(value_parser!(common_validators::InsecurePort))
            .help(CLANDESTINE_PORT_HELP()),
    )
    .arg(config_file_arg())
    .arg(
        Arg::new("consuming-private-key")
            .long("consuming-private-key")
            .value_name("PRIVATE-KEY")
            .num_args(ValueRange::new(0..=1))
            .value_parser(value_parser!(common_validators::PrivateKey))
            .help(CONSUMING_PRIVATE_KEY_HELP),
    )
    .arg(
        Arg::new("crash-point")
            .long("crash-point")
            .value_name("CRASH-POINT")
            .num_args(ValueRange::new(0..=1))
            .value_parser(value_parser!(CrashPoint))
            .ignore_case(false)
            .hide(true),
    )
    .arg(data_directory_arg(DATA_DIRECTORY_HELP.to_string()))
    .arg(db_password_arg(DB_PASSWORD_HELP.to_string()))
    .arg(
        Arg::new("dns-servers")
            .long("dns-servers")
            .value_name("DNS-SERVERS")
            .num_args(ValueRange::new(0..=1))
            .value_parser(value_parser!(common_validators::IpAddrs))
            .help(DNS_SERVERS_HELP),
    )
    .arg(earning_wallet_arg(EARNING_WALLET_HELP.to_string()))
    .arg(
        Arg::new("fake-public-key")
            .long("fake-public-key")
            .value_name("FAKE-PUBLIC-KEY")
            .num_args(ValueRange::new(0..=1))
            .value_parser(value_parser!(PublicKey))
            .hide(true),
    )
    .arg(
        Arg::new("gas-price")
            .long("gas-price")
            .value_name("GAS-PRICE")
            .num_args(ValueRange::new(0..=1))
            .value_parser(value_parser!(u64))
            .help(GAS_PRICE_HELP()),
    )
    .arg(
        Arg::new("ip")
            .long("ip")
            .value_name("IP")
            .num_args(ValueRange::new(0..=1))
            .value_parser(value_parser!(IpAddr))
            .help(IP_ADDRESS_HELP),
    )
    .arg(
        Arg::new("log-level")
            .long("log-level")
            .value_name("FILTER")
            .num_args(ValueRange::new(0..=1))
            .value_parser(value_parser!(LogLevel))
            .help(LOG_LEVEL_HELP),
    )
    .arg(
        Arg::new("mapping-protocol")
            .long("mapping-protocol")
            .value_name("MAPPING-PROTOCOL")
            .num_args(ValueRange::new(0..=1))
            .value_parser(value_parser!(MappingProtocol))
            .help(MAPPING_PROTOCOL_HELP),
    )
    .arg(
        Arg::new("min-hops")
            .long("min-hops")
            .value_name("MIN_HOPS")
            .required(false)
            .num_args(ValueRange::new(0..=1))
            .value_parser(value_parser!(MinHops))
            .help(MIN_HOPS_HELP),
    )
    .arg(
        Arg::new("neighborhood-mode")
            .long("neighborhood-mode")
            .value_name("NEIGHBORHOOD-MODE")
            .required(false)
            .num_args(ValueRange::new(0..=1))
            .value_parser(value_parser!(NeighborhoodMode))
            .help(NEIGHBORHOOD_MODE_HELP),
    )
    .arg(
        Arg::new("neighbors")
            .long("neighbors")
            .value_name("NODE-DESCRIPTORS")
            .num_args(ValueRange::new(0..))
            .value_parser(value_parser!(Neighbors))
            .help(NEIGHBORS_HELP),
    )
    .arg(real_user_arg())
    .arg(
        Arg::new("scans")
            .long("scans")
            .value_name("SCANS")
            .value_parser(value_parser!(OnOff))
            .help(SCANS_HELP),
    )
    .arg(common_parameter_with_separate_u64_values(
        "scan-intervals",
        SCAN_INTERVALS_HELP.to_string())
        .value_parser(value_parser!(ScanIntervals))
    )
    .arg(common_parameter_with_separate_u64_values(
        "rate-pack",
        RATE_PACK_HELP.to_string())
        .value_parser(value_parser!(RatePack))
    )
    .arg(common_parameter_with_separate_u64_values(
        "payment-thresholds",
        PAYMENT_THRESHOLDS_HELP.to_string())
        .value_parser(value_parser!(PaymentThresholds))
    )
}

pub mod common_validators {
    use std::fmt::{Display, Formatter};
    use crate::constants::LOWEST_USABLE_INSECURE_PORT;
    use crate::utils::{hex_to_u128, partition};
    use regex::Regex;
    use std::net::IpAddr;
    use std::path::PathBuf;
    use std::str::FromStr;
    use itertools::Itertools;
    use rustc_hex::{FromHexIter, ToHexIter};

    #[derive(Debug, PartialEq, Clone)]
    pub struct IpAddrs {
        pub ips: Vec<IpAddr>,
    }

    impl FromStr for IpAddrs {
        type Err = String;

        fn from_str(s: &str) -> Result<Self, Self::Err> {
            let init: (Vec<IpAddr>, bool) = (vec![], false);
            let (ip_addrs, error_encountered) = s
                .split(",")
                .map(|ip_addr_str| IpAddr::from_str(ip_addr_str))
                .fold(init, |sofar, ip_addr_result| {
                    let (mut ip_addrs, error_encountered) = sofar;
                    if error_encountered {
                        (vec![], true)
                    }
                    else {
                        match ip_addr_result {
                            Ok(ip_addr) => {
                                ip_addrs.push(ip_addr);
                                (ip_addrs, false)
                            },
                            Err(_) => (vec![], true)
                        }
                    }
                });
            if error_encountered {
                Err(format!("Must be a comma-separated list of IP addresses (no spaces), not '{}'", s))
            }
            else {
                Ok(IpAddrs {ips: ip_addrs})
            }
        }
    }

    impl From<IpAddrs> for Vec<IpAddr> {
        fn from(value: IpAddrs) -> Self {
            todo!()
        }
    }

    impl Display for IpAddrs {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            let string = self
                .ips
                .iter()
                .map(|ip_addr| ip_addr.to_string())
                .join(",");
            write!(f, "{}", string)
        }
    }

    #[derive(Debug, PartialEq, Clone)]
    pub struct PrivateKey {
        pub data: Vec<u8>,
    }

    impl FromStr for PrivateKey {
        type Err = String;

        fn from_str(s: &str) -> Result<Self, Self::Err> {
            if Regex::new("^[0-9a-fA-F]{64}$")
                .expect("Failed to compile regular expression")
                .is_match(s)
            {
                let pairs: Vec<String> = partition(s, 2).expect("64 just became odd");
                let bytes = pairs
                    .into_iter()
                    .map(|pair| hex_to_u128(pair.as_str()).expect("Regex no longer works") as u8)
                    .collect::<Vec<u8>>();
                Ok(PrivateKey { data: bytes })
            } else {
                Err(format!(
                    "Private key should be 64 hex characters long, not '{}'",
                    s
                ))
            }
        }
    }

    impl From<PrivateKey> for String {
        fn from(_value: PrivateKey) -> Self {
            todo!()
        }
    }

    // pub fn validate_private_key(_key: String) -> Result<(), String> {
    //     todo! ("Use PrivateKey instead");
    //     if Regex::new("^[0-9a-fA-F]{64}$")
    //         .expect("Failed to compile regular expression")
    //         .is_match(&_key)
    //     {
    //         Ok(())
    //     } else {
    //         Err(_key)
    //     }
    // }

    #[derive(Debug, PartialEq, Clone)]
    pub struct GasPrice {
        pub price: u64,
    }

    impl FromStr for GasPrice {
        type Err = String;

        fn from_str(s: &str) -> Result<Self, Self::Err> {
            match s.parse::<u64>() {
                Ok(price) if price > 0 => Ok(GasPrice { price }),
                _ => Err(format!(
                    "Gas price must be a decimal number greater than zero, not '{}'",
                    s
                )),
            }
        }
    }

    #[derive(Debug, PartialEq, Clone)]
    pub struct Wallet {
        pub address: Vec<u8>,
    }

    impl FromStr for Wallet {
        type Err = String;

        fn from_str(s: &str) -> Result<Self, Self::Err> {
            let regex = Regex::new("^0x([0-9a-fA-F]{40})$")
                .expect("Failed to compile regular expression");
            let hex_string = match regex.captures(s) {
                Some(captures) => captures.get(1).expect("Bad regular expression"),
                None => return Err(format!("Must begin with '0x' followed by 40 hexadecimal digits, not '{}'", s)),
            }.as_str();
            let address = FromHexIter::new(hex_string)
                .map(|result| result.ok().expect("Regular expression allowed non-hex characters through"))
                .collect_vec();
            Ok(Self { address })
        }
    }

    impl Display for Wallet {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            let hex_string = ToHexIter::new(self.address.iter()).join("");
            write!(f, "0x{}", hex_string)
        }
    }

    // pub fn validate_earning_wallet(value: String) -> Result<(), String> {
    //     validate_ethereum_address(value.clone()).or_else(|_| validate_derivation_path(value))
    // }

    // pub fn validate_ethereum_address(address: String) -> Result<(), String> {
    //     if Regex::new("^0x[0-9a-fA-F]{40}$")
    //         .expect("Failed to compile regular expression")
    //         .is_match(&address)
    //     {
    //         Ok(())
    //     } else {
    //         Err(address)
    //     }
    // }

    // pub fn validate_derivation_path(path: String) -> Result<(), String> {
    //     let possible_path = path.parse::<DerivationPath>();
    //
    //     match possible_path {
    //         Ok(derivation_path) => {
    //             validate_derivation_path_is_sufficiently_hardened(derivation_path, path)
    //         }
    //         Err(e) => Err(format!("{} is not valid: {:?}", path, e)),
    //     }
    // }

    // pub fn validate_derivation_path_is_sufficiently_hardened(
    //     derivation_path: DerivationPath,
    //     path: String,
    // ) -> Result<(), String> {
    //     if derivation_path
    //         .iter()
    //         .filter(|child_nbr| child_nbr.is_hardened())
    //         .count()
    //         > 2
    //     {
    //         Ok(())
    //     } else {
    //         Err(format!("{} may be too weak", path))
    //     }
    // }

    #[derive(Debug, PartialEq, Clone)]
    pub struct RealUser {
        pub uid: u32,
        pub gid: u32,
        pub home_dir: PathBuf,
    }

    impl FromStr for RealUser {
        type Err = String;

        fn from_str(triple: &str) -> Result<Self, Self::Err> {
            if let Some(captures) = Regex::new("^([0-9]*):([0-9]*):(.*)$")
                .expect("Failed to compile regular expression")
                .captures(triple)
            {
                let uid_str = captures.get(1).expect("Regex failed").as_str();
                let uid = match uid_str.parse::<u32>() {
                    Ok(uid) => uid,
                    Err(_) => {
                        return Err(format!("--real_user specified invalid uid: {}", uid_str))
                    }
                };
                let gid_str = captures.get(2).expect("Regex failed").as_str();
                let gid = match gid_str.parse::<u32>() {
                    Ok(gid) => gid,
                    Err(_) => {
                        return Err(format!("--real_user specified invalid gid: {}", gid_str))
                    }
                };
                let home_dir_str = captures.get(3).expect("Regex failed").as_str();
                let home_dir = PathBuf::from(home_dir_str);
                if !home_dir.is_absolute() {
                    return Err(format!(
                        "--real_user specified non-absolute home directory: '{}'",
                        home_dir_str
                    ));
                }
                Ok(RealUser { uid, gid, home_dir })
            } else {
                Err(format!(
                    "--real_user should look like <uid>:<gid>:<home directory>, not '{}'",
                    triple
                ))
            }
        }
    }

    #[derive(Debug, PartialEq, Clone)]
    pub struct InsecurePort {
        pub port: u16,
    }

    impl FromStr for InsecurePort {
        type Err = String;

        fn from_str(s: &str) -> Result<Self, Self::Err> {
            match str::parse::<u16>(s) {
                Ok(port) => {
                    if port < LOWEST_USABLE_INSECURE_PORT {
                        Err(format!(
                            "Port number must be between {} and 65535, not '{}'",
                            LOWEST_USABLE_INSECURE_PORT, s
                        ))
                    } else {
                        Ok(InsecurePort { port })
                    }
                }
                Err(_) => Err(format!(
                    "Port number must be between {} and 65535, not '{}'",
                    LOWEST_USABLE_INSECURE_PORT, s
                )),
            }
        }
    }

    impl Display for InsecurePort {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", self.port)
        }
    }

    impl From<InsecurePort> for u16 {
        fn from(_value: InsecurePort) -> Self {
            todo!()
        }
    }

    #[derive(Debug, PartialEq, Clone)]
    pub struct VecU64 {
        pub data: Vec<u64>,
    }

    impl FromStr for VecU64 {
        type Err = String;

        fn from_str(values_with_delimiters: &str) -> Result<Self, Self::Err> {
            let str_values = values_with_delimiters.split('|');
            let init: Vec<u64> = vec![];
            let result = str_values
                .into_iter()
                .try_fold(init, |mut so_far, str_value| {
                    match str_value.parse::<u64>() {
                        Err(e) => Err(e),
                        Ok(value) => {
                            so_far.push(value);
                            Ok(so_far)
                        }
                    }
                });
            result
                .map(|data| VecU64{data})
                .map_err (|_| format!("Supply positive numeric values separated by vertical bars like 111|222|333, not '{}'", values_with_delimiters))
        }
    }

    impl Display for VecU64 {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            let strings = self.data.iter().map(|v| v.to_string()).collect_vec();
            write!(f, "{}", strings.join("|"))
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
pub enum LogLevel {
    Off,
    Error,
    Warn,
    Info,
    Debug,
    Trace
}

impl FromStr for LogLevel {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "off" => Ok(Self::Off),
            "error" => Ok(Self::Error),
            "warn" => Ok(Self::Warn),
            "info" => Ok(Self::Info),
            "debug" => Ok(Self::Debug),
            "trace" => Ok(Self::Trace),
            _ => Err(format!("Unrecognized log-level value '{}'", s))
        }
    }
}

impl Display for LogLevel {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Self::Off => "off",
            Self::Error => "error",
            Self::Warn => "warn",
            Self::Info => "info",
            Self::Debug => "debug",
            Self::Trace => "trace",
        };
        write!(f, "{}", name)
    }
}

#[derive(Debug, PartialEq, Clone)]
pub enum NeighborhoodMode {
    ZeroHop,
    OriginateOnly,
    ConsumeOnly,
    Standard
}

impl FromStr for NeighborhoodMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "zero-hop" => Ok(Self::ZeroHop),
            "originate-only" => Ok(Self::OriginateOnly),
            "consume-only" => Ok(Self::ConsumeOnly),
            "standard" => Ok(Self::Standard),
            _ => Err(format!("Unrecognized neighborhood-mode value '{}'", s))
        }
    }
}

impl Display for NeighborhoodMode {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Self::ZeroHop => "zero-hop",
            Self::OriginateOnly => "originate-only",
            Self::ConsumeOnly => "consume-only",
            Self::Standard => "standard",
        };
        write!(f, "{}", name)
    }
}

#[derive (Debug, PartialEq, Clone)]
pub enum MappingProtocol {
    Pcp,
    Pmp,
    Igdp
}

impl FromStr for MappingProtocol {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "pcp" => Ok(Self::Pcp),
            "pmp" => Ok(Self::Pmp),
            "igdp" => Ok(Self::Igdp),
            _ => Err(format!("Unrecognized mapping-protocol value '{}'", s))
        }
    }
}

impl Display for MappingProtocol {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Self::Pcp => "pcp",
            Self::Pmp => "pmp",
            Self::Igdp => "igdp",
        };
        write!(f, "{}", name)
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct ConfigFile {
    pub path: PathBuf,
}

impl FromStr for ConfigFile {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let config_file = match PathBuf::from_str(s) {
            Ok(cf) => cf,
            Err(infallible) => return Err(infallible.to_string()),
        };
        if config_file.is_dir() {
            return Err(format!("Config file must be a file, not a directory: '{}'", s))
        }
        Ok(ConfigFile {path: config_file})
    }
}

impl Display for ConfigFile {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.path.as_os_str().to_string_lossy().to_string())
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct DataDirectory {
    pub path: PathBuf,
}

impl FromStr for DataDirectory {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let data_directory = match PathBuf::from_str(s) {
            Ok(dd) => dd,
            Err(infallible) => return Err(infallible.to_string()),
        };
        if data_directory.is_file() {
            return Err(format!("Data directory must be a directory, not a file: '{}'", s))
        }
        Ok(DataDirectory {path: data_directory })
    }
}

impl Display for DataDirectory {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.path.as_os_str().to_string_lossy().to_string())
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct PublicKey {
    data: Vec<u8>,
}

impl FromStr for PublicKey {
    type Err = String;

    fn from_str(_s: &str) -> Result<Self, Self::Err> {
        todo!()
    }
}

impl Display for PublicKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        todo!()
    }
}

#[derive(Debug, PartialEq, Clone)]
pub enum MinHops { One, Two, Three, Four, Five, Six }

impl FromStr for MinHops {
    type Err = String;

    fn from_str(_s: &str) -> Result<Self, Self::Err> {
        todo!()
    }
}

impl Display for MinHops {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        todo!()
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct Neighbors {
    neighbors: Vec<NodeAddr>
}

impl FromStr for Neighbors {
    type Err = String;

    fn from_str(_s: &str) -> Result<Self, Self::Err> {
        todo!()
    }
}

impl Display for Neighbors {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        todo!()
    }
}

#[derive(Debug, PartialEq, Clone)]
pub enum OnOff { On, Off }

impl FromStr for OnOff {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "on" => Ok(OnOff::On),
            "off" => Ok(OnOff::Off),
            s => Err(format!("Must be either 'on' or 'off', not '{}'", s)),
        }
    }
}

impl Display for OnOff {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let string = match self {
            OnOff::On => "on",
            OnOff::Off => "off",
        };
        write!(f, "{}", string)
    }
}

fn from_str_for_vec_u64(values_with_delimiters: &str, expected_count: usize) -> Result<Vec<u64>, String> {
    let example = || (1..=expected_count)
        .map (|i| format!("{}{}{}", i, i, i))
        .collect_vec()
        .join("|");
    let str_values = values_with_delimiters.split('|').collect_vec();
    if str_values.len() != expected_count {
        return Err(format!("Supply {} positive numeric values separated by vertical bars like {}, not '{}'",
            expected_count, example(), values_with_delimiters))
    }
    let init: Vec<u64> = vec![];
    let result = str_values
        .into_iter()
        .try_fold(init, |mut so_far, str_value| {
            match str_value.parse::<u64>() {
                Err(e) => Err(e),
                Ok(value) => {
                    so_far.push(value);
                    Ok(so_far)
                }
            }
        });
    result
        .map_err (|_| {
            format!("Supply {} positive numeric values separated by vertical bars like {}, not '{}'",
                    expected_count, example(), values_with_delimiters)
        })
}

fn fmt_vec_u64(numbers: &Vec<u64>, f: &mut Formatter<'_>) -> std::fmt::Result {
    let strings = numbers.iter().map(|v| v.to_string()).collect_vec();
    write!(f, "{}", strings.join("|"))
}

macro_rules! make_vec_u64_type {
    ($new_type: ident, $length: expr) => {
        #[derive(Debug, PartialEq, Clone)]
        struct $new_type {data: Vec<u64>}
        impl FromStr for $new_type {
            type Err = String;
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Ok($new_type {data: from_str_for_vec_u64(s, $length)?})
            }
        }
        impl Display for $new_type {
            fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
                fmt_vec_u64(&self.data, f)
            }
        }
    };
}

make_vec_u64_type!(ScanIntervals, 3);
make_vec_u64_type!(RatePack, 4);
make_vec_u64_type!(PaymentThresholds, 6);

#[derive(Debug, PartialEq, Eq, Clone)]
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

#[derive(Debug, PartialEq, Eq, Clone)]
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

    pub fn len(&self) -> usize {
        self.param_errors.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use super::*;
    use crate::blockchains::chains::Chain;
    use crate::shared_schema::common_validators::{IpAddrs, RealUser, VecU64, Wallet};
    use crate::shared_schema::{common_validators, official_chain_names};
    use std::path::PathBuf;
    use std::str::FromStr;
    use itertools::Itertools;
    use crate::test_utils::utils::ensure_node_home_directory_exists;

    #[test]
    fn constants_have_correct_values() {
        assert_eq!(
            BLOCKCHAIN_SERVICE_HELP,
            "The Ethereum client you wish to use to provide Blockchain \
             exit services from your MASQ Node (e.g. http://localhost:8545, \
             https://ropsten.infura.io/v3/YOUR-PROJECT-ID, https://mainnet.infura.io/v3/YOUR-PROJECT-ID), \
             https://polygon-mainnet.infura.io/v3/YOUR-PROJECT-ID"
        );
        assert_eq!(
            CHAIN_HELP,
            "The blockchain network MASQ Node will configure itself to use. You must ensure the \
             Ethereum client specified by --blockchain-service-url communicates with the same blockchain network."
        );
        assert_eq!(
            CONFIG_FILE_HELP,
            "Optional TOML file containing configuration that doesn't often change. Should contain only \
             scalar items, string or numeric, whose names are exactly the same as the command-line parameters \
             they replace (except no '--' prefix). If you specify a relative path, or no path, the Node will \
             look for your config file starting in the --data-directory. If you specify an absolute path, \
             --data-directory will be ignored when searching for the config file. A few parameters \
             (such as --config-file, --generate-wallet, and --recover-wallet) must not be specified in a config file."
        );
        assert_eq!(
            CONSUMING_PRIVATE_KEY_HELP,
            "The private key for the Ethereum wallet from which you wish to pay \
             other Nodes for routing and exit services. Mostly this is used for testing; be careful using it for real \
             traffic, because this value is very sensitive: anyone who sees it can use it to drain your consuming wallet. \
             If you use it, don't put it on the command line (the environment is good, the config file is less so), \
             make sure you haven't already set up a consuming wallet with a derivation path, and make sure that you always \
             supply exactly the same private key every time you run the Node. A consuming private key is 64 case-insensitive \
             hexadecimal digits."
        );
        assert_eq!(
            DATA_DIRECTORY_HELP,
            "Directory in which the Node will store its persistent state, including at \
             least its database and by default its configuration file as well.\nNote: any existing \
             database in the data directory must have been created from the same chain this run is using, \
             or the Node will be terminated."
        );
        assert_eq!(
            DB_PASSWORD_HELP,
            "A password or phrase to decrypt the encrypted material in the database, to include your \
             mnemonic seed (if applicable) and your list of previous neighbors. If you don't provide this \
             password, none of the encrypted data in your database will be used. This is a secret;\
             providing it on the command line or in a config file may be insecure"
        );
        assert_eq!(
            DNS_SERVERS_HELP,
            "IP addresses of DNS Servers for host name look-up while providing exit \
             services for other MASQ Nodes (e.g. 1.0.0.1,1.1.1.1,8.8.8.8,9.9.9.9, etc.)"
        );
        assert_eq!(
            EARNING_WALLET_HELP,
            "An Ethereum wallet address. Addresses must begin with 0x followed by 40 hexadecimal digits \
             (case-insensitive). If you already have a derivation-path earning wallet, don't supply this. \
             If you have supplied an earning wallet address before, either don't supply it again or be \
             careful to supply exactly the same one you supplied before."
        );
        assert_eq!(
            IP_ADDRESS_HELP,
            "The public IP address of your MASQ Node: that is, the IPv4 \
             address at which other Nodes can contact yours. If you're running your Node behind \
             a router, this will be the IP address of the router. If this IP address starts with 192.168 or 10.0, \
             it's a local address rather than a public address, and other Nodes won't be able to see yours. \
             --ip is meaningless except in --neighborhood-mode standard."
        );
        assert_eq!(
            LOG_LEVEL_HELP,
            "The minimum severity of the logs that should appear in the Node's logfile. You should probably not specify \
             a level lower than the default unless you're doing testing or forensics: a Node at the 'trace' log level \
             generates a lot of log traffic. This will both consume your disk space and degrade your Node's performance. \
             You should probably not specify a level higher than the default unless you have security concerns about \
             persistent logs being kept on your computer: if your Node crashes, it's good to know why.");
        assert_eq!(
            NEIGHBORS_HELP,
            "One or more Node descriptors for running Nodes in the MASQ \
             One or more Node descriptors for active Nodes in the MASQ Network to which you'd like your Node to connect \
             on startup. A Node descriptor looks similar to one of these:\n\n\
                  masq://polygon-mainnet:d2U3Dv1BqtS5t_Zz3mt9_sCl7AgxUlnkB4jOMElylrU@172.50.48.6:9342\n\
                  masq://eth-mainnet:gBviQbjOS3e5ReFQCvIhUM3i02d1zPleo1iXg_EN6zQ@86.75.30.9:5542\n\
                  masq://polygon-mumbai:A6PGHT3rRjaeFpD_rFi3qGEXAVPq7bJDfEUZpZaIyq8@14.10.50.6:10504\n\
                  masq://eth-ropsten:OHsC2CAm4rmfCkaFfiynwxflUgVTJRb2oY5mWxNCQkY@150.60.42.72:6642/4789/5254\n\n\
             Notice each of the different chain identifiers in the masq protocol prefix - they determine a family of chains \
             and also the network the descriptor belongs to (mainnet or a testnet). See also the last descriptor which shows \
             a configuration with multiple clandestine ports.\n\n\
             If you have more than one descriptor, separate them with commas. Whether single or multiple descriptors, they \
             should be enclosed by quotes. No default value is available; \
             if you don't specify a neighbor, your Node will start without being connected to any MASQ \
             Network, although other Nodes will be able to connect to yours if they know your Node's descriptor. \
             --neighbors is meaningless in --neighborhood-mode zero-hop."
        );
        assert_eq!(
            NEIGHBORHOOD_MODE_HELP,
            "This configures the way the Node relates to other Nodes.\n\n\
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
             requires that you forward your clandestine port through that router to your Node's machine."
        );
        assert_eq!(
            MAPPING_PROTOCOL_HELP,
            "The Node can speak three protocols to your router to make it allow outside Nodes to connect inward \
             through it to your machine. These three protocols are pcp, pmp, and igdp. The Node can try them one \
             by one to determine which your router supports, but if you happen to know already, you can supply the \
             name of the protocol here. If you've taken care of port mapping in some other way, \
             and you don't need Node to negotiate with your router, say 'none' here and be sure to specify your \
             public IP address with the --ip parameter. If the Node communicates successfully with your router, \
             it will remember the protocol it used, and on its next run it will try that protocol first, unless \
             you specify a different protocol on the command line."
        );
        assert_eq!(
            MIN_HOPS_HELP,
            "The Node is a system that routes data through multiple Nodes to enhance security and privacy. \
             However, the level of anonymity and security provided depends on the number of hops specified \
             by the user. By default, the system allows the user to customize the number of hops within a \
             range of 1 to 6.\n\n\
             It's important to note that if the user selects less than 3 hops, the anonymity of their data \
             cannot be guaranteed. Here's a breakdown of the different hop counts and their implications:\n\n\
             1. A 1-hop route means that the exit Node will know the IP address of the originating Node. \
             Also, someone snooping traffic on the network will be able to see both the originating Node's IP \
             and the exit Node's IP in the same packet. A 1-hop route makes MASQ the equivalent of a VPN. \n\
             2. A 2-hop route removes the ability to see both the originating and exit IP addresses on the \
             same packet, but it means that the relay Node in the middle (which could be subverted by an attacker) \
             knows both IP addresses.\n\
             3. A 3-hop route is the shortest route that prevents any Node in the network (even the originating Node) \
             from knowing the IP addresses of all the Nodes in the route.\n\
             4. Increasing the number of hops to 4, 5, or 6 can enhance security, but it will also \
             increase the cost and latency of the route.\n\
             If you want to specify a minimum hops count, you can do so by entering a number after the \
             '--min-hops' parameter. For example, '--min-hops 4' would require at least 4 hops. If you fail \
             to provide this argument, the system will default to a minimum hops count of 3."
        );
        assert_eq!(
            REAL_USER_HELP,
            "The user whose identity Node will assume when dropping privileges after bootstrapping. Since Node refuses to \
             run with root privilege after bootstrapping, you might want to use this if you start the Node as root, or if \
             you start the Node using pkexec or some other method that doesn't populate the SUDO_xxx variables. Use a value \
             like <uid>:<gid>:<home directory>."
        );

        assert_eq!(
            DEFAULT_UI_PORT_VALUE.to_string(),
            DEFAULT_UI_PORT.to_string()
        );
        assert_eq!(
            UI_PORT_HELP.to_string(),
            format!(
                "The port at which user interfaces will connect to the Node. Best to accept the default unless \
                 you know what you're doing. Must be between {} and {}.",
                LOWEST_USABLE_INSECURE_PORT, HIGHEST_USABLE_PORT
            )
        );
        assert_eq!(
            CLANDESTINE_PORT_HELP(),
            format!(
                "The port this Node will advertise to other Nodes at which clandestine traffic will be \
                 received. If you don't specify a clandestine port, the Node will choose an unused \
                 one at random on first startup, then use that one for every subsequent run unless \
                 you change it by specifying a different clandestine port here. --clandestine-port is \
                 meaningless except in --neighborhood-mode standard. \
                 Must be between {} and {} [default: last used port]",
                LOWEST_USABLE_INSECURE_PORT, HIGHEST_USABLE_PORT
            )
        );
        assert_eq!(
            GAS_PRICE_HELP(),
            format!(
                "The Gas Price is the amount of gwei you will pay per unit of gas used in a transaction. \
                 If left unspecified, MASQ Node will use the previously stored value (Default {}).",
                DEFAULT_GAS_PRICE
            )
        );
        assert_eq!(
            RATE_PACK_HELP,
            "These four parameters specify your rates that your Node will use for charging other Nodes for your provided \
             services. These are ever present values, defaulted if left unspecified. The parameters must be always supplied \
             all together, delimited by vertical bars and in the right order.\n\n\
             1. Routing Byte Rate: This parameter indicates an amount of MASQ in wei demanded to process 1 byte of routed payload \
             while the Node is a common relay Node.\n\n\
             2. Routing Service Rate: This parameter indicates an amount of MASQ in wei demanded to provide services, unpacking \
             and repacking 1 CORES package, while the Node is a common relay Node.\n\n\
             3. Exit Byte Rate: This parameter indicates an amount of MASQ in wei demanded to process 1 byte of routed payload \
             while the Node acts as the exit Node.\n\n\
             4. Exit Service Rate: This parameter indicates an amount of MASQ in wei demanded to provide services, unpacking and \
             repacking 1 CORES package, while the Node acts as the exit Node."
        );
        assert_eq!(
            PAYMENT_THRESHOLDS_HELP,
            "These are parameters that define thresholds to determine when and how much to pay other Nodes for routing and \
             exit services and the expectations the Node should have for receiving payments from other Nodes for routing and \
             exit services. The thresholds are also used to determine whether to offer services to other Nodes or enact a ban \
             since they have not paid mature debts. These are ever present values, no matter if the user's set any value, as \
             they have defaults. The parameters must be always supplied all together, delimited by vertical bars and in the right order.\n\n\
             1. Debt Threshold gwei: Payables higher than this -- in gwei of MASQ -- will be suggested for payment immediately \
             upon passing the Maturity Threshold Sec age. Payables less than this can stay unpaid longer. Receivables higher than \
             this will be expected to be settled by other Nodes, but will never cause bans until they pass the Maturity Threshold Sec \
             + Payment Grace Period Sec age. Receivables less than this will survive longer without banning.\n\n\
             2. Maturity Threshold Sec: Large payables can get this old -- in seconds -- before the Accountant's scanner suggests \
             that it be paid.\n\n\
             3. Payment Grace Period Sec: A large receivable can get as old as Maturity Threshold Sec + Payment Grace Period Sec \
             -- in seconds -- before the Node that owes it will be banned.\n\n\
             4. Permanent Debt Allowed gwei: Receivables this small and smaller -- in gwei of MASQ -- will not cause bans no \
             matter how old they get.\n\n\
             5. Threshold Interval Sec: This interval -- in seconds -- begins after Maturity Threshold Sec for payables and after \
             Maturity Threshold Sec + Payment Grace Period Sec for receivables. During the interval, the amount of a payable that is \
             allowed to remain unpaid, or a pending receivable that won’t cause a ban, decreases linearly from the Debt Threshold gwei \
             to Permanent Debt Allowed gwei or Unban Below gwei.\n\n\
             6. Unban Below gwei: When a delinquent Node has been banned due to non-payment, the receivables balance must be paid \
             below this level -- in gwei of MASQ -- to cause them to be unbanned. In most cases, you'll want this to be set the same \
             as Permanent Debt Allowed gwei."
        );
        assert_eq!(
            SCAN_INTERVALS_HELP,
            "These three intervals describe the length of three different scan cycles running automatically in the background \
             since the Node has connected to a qualified neighborhood that consists of neighbors enabling a complete 3-hop \
             route. Each parameter can be set independently, but by default are all the same which currently is most desirable \
             for the consistency of service payments to and from your Node. Technically, there doesn't have to be any lower \
             limit for the minimum of time you can set; two scans of the same sort would never run at the same time but the \
             next one is always scheduled not earlier than the end of the previous one. These are ever present values, no matter \
             if the user's set any value, they have defaults. The parameters must be always supplied all together, delimited by \
             vertical bars and in the right order.\n\n\
             1. Pending Payable Scan Interval: Amount of seconds between two sequential cycles of scanning for payments that are \
             marked as currently pending; the payments were sent to pay our debts, the payable. The purpose of this process is to \
             confirm the status of the pending payment; either the payment transaction was written on blockchain as successful or \
             failed.\n\n\
             2. Payable Scan Interval: Amount of seconds between two sequential cycles of scanning aimed to find payable accounts \
             of that meet the criteria set by the Payment Thresholds; these accounts are tracked on behalf of our creditors. If \
             they meet the Payment Threshold criteria, our Node will send a debt payment transaction to the creditor in question.\n\n\
             3. Receivable Scan Interval: Amount of seconds between two sequential cycles of scanning for payments on the \
             blockchain that have been sent by our creditors to us, which are credited against receivables recorded for services \
             provided."
        )
    }

    #[test]
    fn validate_private_key_requires_a_key_that_is_64_characters_long() {
        let result = common_validators::PrivateKey::from_str("42");

        assert_eq!(
            result,
            Err("Private key should be 64 hex characters long, not '42'".to_string()),
        );
    }

    #[test]
    fn validate_private_key_must_contain_only_hex_characters() {
        let result = common_validators::PrivateKey::from_str(
            "cc46befe8d169b89db447bd725fc2368b12542113555302598430cinvalidhex",
        );

        assert_eq!(
            result,
            Err("Private key should be 64 hex characters long, not 'cc46befe8d169b89db447bd725fc2368b12542113555302598430cinvalidhex'".to_string()),
        );
    }

    #[test]
    fn validate_private_key_handles_happy_path() {
        let result = common_validators::PrivateKey::from_str(
            "cc46befe8d169b89db447bd725fc2368b12542113555302598430cb5d5c74ea9",
        );

        assert_eq!(
            result,
            Ok(common_validators::PrivateKey {
                data: vec![
                    0xcc, 0x46, 0xbe, 0xfe, 0x8d, 0x16, 0x9b, 0x89, 0xdb, 0x44, 0x7b, 0xd7, 0x25,
                    0xfc, 0x23, 0x68, 0xb1, 0x25, 0x42, 0x11, 0x35, 0x55, 0x30, 0x25, 0x98, 0x43,
                    0x0c, 0xb5, 0xd5, 0xc7, 0x4e, 0xa9
                ]
            })
        );
    }

    #[test]
    fn insecure_port_validation_rejects_badly_formatted_port_number() {
        let result = common_validators::InsecurePort::from_str("booga");

        assert_eq!(
            result,
            Err(String::from(
                "Port number must be between 1025 and 65535, not 'booga'".to_string()
            ))
        );
    }

    #[test]
    fn insecure_port_validation_rejects_negative_port_number() {
        let result = common_validators::InsecurePort::from_str("-1234");

        assert_eq!(
            result,
            Err(String::from(
                "Port number must be between 1025 and 65535, not '-1234'".to_string()
            ))
        );
    }

    #[test]
    fn insecure_port_validation_rejects_port_number_too_low() {
        let result = common_validators::InsecurePort::from_str("1024");

        assert_eq!(
            result,
            Err(String::from(
                "Port number must be between 1025 and 65535, not '1024'".to_string()
            ))
        );
    }

    #[test]
    fn insecure_port_validation_rejects_port_number_too_high() {
        let result = common_validators::InsecurePort::from_str("65536");

        assert_eq!(
            result,
            Err(String::from(
                "Port number must be between 1025 and 65535, not '65536'".to_string()
            ))
        );
    }

    #[test]
    fn insecure_port_validation_accepts_port_if_provided() {
        let result = common_validators::InsecurePort::from_str("4567");

        assert_eq!(result, Ok(common_validators::InsecurePort { port: 4567 }));
    }

    #[test]
    fn validate_gas_price_zero() {
        let result = common_validators::GasPrice::from_str("0");

        assert_eq!(
            result,
            Err("Gas price must be a decimal number greater than zero, not '0'".to_string())
        );
    }

    #[test]
    fn validate_gas_price_normal() {
        let result = common_validators::GasPrice::from_str("2");

        assert_eq!(result, Ok(common_validators::GasPrice { price: 2 }));
    }

    #[test]
    fn validate_gas_price_max() {
        let max = 0xFFFFFFFFFFFFFFFFu64;
        let max_string = max.to_string();

        let result = common_validators::GasPrice::from_str(&max_string);

        assert_eq!(result, Ok(common_validators::GasPrice { price: max }));
    }

    #[test]
    fn validate_gas_price_not_digits_fails() {
        let result = common_validators::GasPrice::from_str("not");

        assert_eq!(
            result,
            Err("Gas price must be a decimal number greater than zero, not 'not'".to_string())
        );
    }

    #[test]
    fn validate_gas_price_hex_fails() {
        let result = common_validators::GasPrice::from_str("0x0");

        assert_eq!(
            result,
            Err("Gas price must be a decimal number greater than zero, not '0x0'".to_string())
        );
    }

    #[test]
    fn validate_real_user_happy_path() {
        let result = RealUser::from_str("1234:5678:/home/booga");

        assert_eq!(
            result,
            Ok(RealUser {
                uid: 1234,
                gid: 5678,
                home_dir: PathBuf::from_str("/home/booga").unwrap(),
            })
        )
    }

    #[test]
    fn validate_real_user_complains_about_value_that_doesnt_match_regex() {
        let result = RealUser::from_str("not enough colons");

        assert_eq! (result, Err ("--real_user should look like <uid>:<gid>:<home directory>, not 'not enough colons'".to_string()));
    }

    #[test]
    fn validate_real_user_cant_handle_uid_too_big() {
        let result = RealUser::from_str("5000000000:0:/home/dir");

        assert_eq!(
            result,
            Err("--real_user specified invalid uid: 5000000000".to_string())
        );
    }

    #[test]
    fn validate_real_user_cant_handle_gid_too_big() {
        let result = RealUser::from_str("0:5000000000:/home/dir");

        assert_eq!(
            result,
            Err("--real_user specified invalid gid: 5000000000".to_string())
        );
    }

    #[test]
    fn validate_real_user_cant_handle_home_directory_that_isnt_absolute() {
        let result = RealUser::from_str("1234:5678:home/dir");

        assert_eq!(
            result,
            Err("--real_user specified non-absolute home directory: 'home/dir'".to_string())
        );
    }

    #[test]
    fn validate_separate_u64_values_happy_path() {
        let result = common_validators::VecU64::from_str("4567|1111|444");

        assert_eq!(
            result,
            Ok(VecU64 {
                data: vec![4567, 1111, 444]
            })
        )
    }

    #[test]
    fn validate_separate_u64_values_sad_path_with_wrong_number_of_values() {
        let result = ScanIntervals::from_str("111|222|333|444");

        assert_eq!(
            result,
            Err(String::from(
                "Supply 3 positive numeric values separated by vertical bars like 111|222|333, not '111|222|333|444'"
            ))
        )
    }

    #[test]
    fn validate_separate_u64_values_sad_path_with_non_numeric_values() {
        let result = ScanIntervals::from_str("4567|foooo|444");

        assert_eq!(
            result,
            Err(String::from(
                "Supply 3 positive numeric values separated by vertical bars like 111|222|333, not '4567|foooo|444'"
            ))
        )
    }

    #[test]
    fn validate_separate_u64_values_sad_path_bad_delimiters_generally() {
        let result = RatePack::from_str("4567,555,444,3245");

        assert_eq!(
            result,
            Err(String::from(
                "Supply 4 positive numeric values separated by vertical bars like 111|222|333|444, not '4567,555,444,3245'"
            ))
        )
    }

    #[test]
    fn validate_separate_u64_values_sad_path_bad_delimiters_at_the_end() {
        let result = PaymentThresholds::from_str("|4567|5555|444|2345|3234|4|");

        assert_eq!(
            result,
            Err(String::from(
                "Supply 6 positive numeric values separated by vertical bars like 111|222|333|444|555|666, not '|4567|5555|444|2345|3234|4|'"
            ))
        )
    }

    #[test]
    fn official_chain_names_are_reliable() {
        let mut iterator = official_chain_names().iter();
        assert_eq!(Chain::from_str(*iterator.next().unwrap()), Ok(Chain::PolyMainnet));
        assert_eq!(Chain::from_str(*iterator.next().unwrap()), Ok(Chain::EthMainnet));
        assert_eq!(Chain::from_str(*iterator.next().unwrap()), Ok(Chain::PolyMumbai));
        assert_eq!(Chain::from_str(*iterator.next().unwrap()), Ok(Chain::EthRopsten));
        assert_eq!(Chain::from_str(*iterator.next().unwrap()), Ok(Chain::Dev));
        assert_eq!(iterator.next(), None)
    }

    #[test]
    fn config_file_can_be_parsed_from_string() {
        let input = "this/should/be/valid.toml";

        let result = ConfigFile::from_str(input).unwrap();

        assert_eq!(result.path, PathBuf::from_str(input).unwrap());
    }

    #[test]
    fn config_file_rejects_directory() {
        let current_directory = std::env::current_dir().unwrap();
        let cd_str = current_directory.as_os_str().to_string_lossy();

        let result = ConfigFile::from_str(&cd_str);

        assert_eq!(result, Err(format!("Config file must be a file, not a directory: '{}'", &cd_str)));
    }

    #[test]
    fn config_file_can_be_rendered_as_string() {
        let config_file = PathBuf::from_str("parent_dir/file.toml").unwrap();
        let cf_str = config_file.as_os_str().to_string_lossy().to_string();
        let subject = ConfigFile {path: config_file};

        let result = subject.to_string();

        assert_eq!(result, cf_str);
    }

    #[test]
    fn data_directory_can_be_parsed_from_string() {
        let input = "this/should/be/valid";

        let result = DataDirectory::from_str(input).unwrap();

        assert_eq!(result.path, PathBuf::from_str(input).unwrap());
    }

    #[test]
    fn data_directory_rejects_file() {
        let directory = ensure_node_home_directory_exists("shared_schema", "data_directory_rejects_file");
        let file_path = directory.join("data-directory-file.toml");
        {
            let _ = File::create(&file_path).unwrap();
        }
        let dd_str = file_path.as_os_str().to_string_lossy();

        let result = DataDirectory::from_str(&dd_str);

        assert_eq!(result, Err(format!("Data directory must be a directory, not a file: '{}'", &dd_str)));
    }

    #[test]
    fn data_directory_can_be_rendered_as_string() {
        let config_file = PathBuf::from_str("parent_dir/child_dir").unwrap();
        let cf_str = config_file.as_os_str().to_string_lossy().to_string();
        let subject = DataDirectory {path: config_file};

        let result = subject.to_string();

        assert_eq!(result, cf_str);
    }

    #[test]
    fn ip_addrs_can_be_parsed_from_string() {
        let input = "1.2.3.4,2001:db8:85a3:8d3:1319:8a2e:370:7348";

        let result = IpAddrs::from_str(input).unwrap();

        assert_eq!(result.ips, vec![
            IpAddr::from_str("1.2.3.4").unwrap(),
            IpAddr::from_str("2001:db8:85a3:8d3:1319:8a2e:370:7348").unwrap()
        ]);
    }

    #[test]
    fn ip_addrs_rejects_bad_syntax() {

        let result = IpAddrs::from_str("boogety,boo");

        assert_eq!(result, Err("Must be a comma-separated list of IP addresses (no spaces), not 'boogety,boo'".to_string()));
    }

    #[test]
    fn ip_addrs_can_be_rendered_as_string() {
        let subject = IpAddrs{ips: vec![
            IpAddr::from_str("1.2.3.4").unwrap(),
            IpAddr::from_str("2001:db8:85a3:8d3:1319:8a2e:370:7348").unwrap()
        ]};

        let result = subject.to_string();

        assert_eq!(result, "1.2.3.4,2001:db8:85a3:8d3:1319:8a2e:370:7348");
    }

    #[test]
    fn wallet_can_be_parsed_from_string() {
        let input = "0x0123456789abcDEFfedCBA987654321012345678";

        let result = Wallet::from_str(input).unwrap();

        let expected: Vec<u8> = vec![
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10, 0x12, 0x34, 0x56, 0x78
        ];
        assert_eq!(result.address, expected);
    }

    #[test]
    fn wallet_rejects_bad_syntax() {
        let input = "Oy0123456789abcDEFfedCBA98765432101234567";

        let result = Wallet::from_str(input);

        assert_eq!(result, Err(format!("Must begin with '0x' followed by 40 hexadecimal digits, not '{}'", input)));
    }

    #[test]
    fn wallet_can_be_rendered_as_string() {
        let subject = Wallet{address: vec![
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10, 0x12, 0x34, 0x56, 0x78
        ]};

        let result = subject.to_string();

        assert_eq!(result, "0x0123456789abcdeffedcba987654321012345678");
    }

    #[test]
    fn log_level_can_be_parsed_from_strings() {
        let inputs = vec!["off", "error", "warn", "info", "debug", "trace"];

        let result = inputs
            .into_iter()
            .map(|input| LogLevel::from_str(input).unwrap())
            .collect_vec();

        assert_eq! (result, vec![
            LogLevel::Off,
            LogLevel::Error,
            LogLevel::Warn,
            LogLevel::Info,
            LogLevel::Debug,
            LogLevel::Trace
        ])
    }

    #[test]
    fn log_level_detects_invalid_value() {

        let result = LogLevel::from_str("booga");

        assert_eq! (result, Err("Unrecognized log-level value 'booga'".to_string()))
    }

    #[test]
    fn log_level_displays_properly() {
        let inputs = vec![
            LogLevel::Off,
            LogLevel::Error,
            LogLevel::Warn,
            LogLevel::Info,
            LogLevel::Debug,
            LogLevel::Trace
        ];

        let result = inputs
            .into_iter()
            .map(|input| input.to_string())
            .collect_vec();

        assert_eq! (
            result,
            vec!["off", "error", "warn", "info", "debug", "trace"]
                .into_iter()
                .map(|x| x.to_string())
                .collect_vec()
        )
    }

    #[test]
    fn neighborhood_mode_can_be_parsed_from_strings() {
        let inputs = vec!["zero-hop", "originate-only", "consume-only", "standard"];

        let result = inputs
            .into_iter()
            .map(|input| NeighborhoodMode::from_str(input).unwrap())
            .collect_vec();

        assert_eq! (result, vec![
            NeighborhoodMode::ZeroHop,
            NeighborhoodMode::OriginateOnly,
            NeighborhoodMode::ConsumeOnly,
            NeighborhoodMode::Standard,
        ])
    }

    #[test]
    fn neighborhood_mode_detects_invalid_value() {

        let result = NeighborhoodMode::from_str("booga");

        assert_eq! (result, Err("Unrecognized neighborhood-mode value 'booga'".to_string()))
    }

    #[test]
    fn neighborhood_mode_displays_properly() {
        let inputs = vec![
            NeighborhoodMode::ZeroHop,
            NeighborhoodMode::OriginateOnly,
            NeighborhoodMode::ConsumeOnly,
            NeighborhoodMode::Standard,
        ];

        let result = inputs
            .into_iter()
            .map(|input| input.to_string())
            .collect_vec();

        assert_eq! (
            result,
            vec!["zero-hop", "originate-only", "consume-only", "standard"]
                .into_iter()
                .map(|x| x.to_string())
                .collect_vec()
        )
    }

    #[test]
    fn mapping_protocol_can_be_parsed_from_strings() {
        let inputs = vec!["pcp", "pmp", "igdp"];

        let result = inputs
            .into_iter()
            .map(|input| MappingProtocol::from_str(input).unwrap())
            .collect_vec();

        assert_eq! (result, vec![
            MappingProtocol::Pcp,
            MappingProtocol::Pmp,
            MappingProtocol::Igdp,
        ])
    }

    #[test]
    fn mapping_protocol_detects_invalid_value() {

        let result = MappingProtocol::from_str("booga");

        assert_eq! (result, Err("Unrecognized mapping-protocol value 'booga'".to_string()))
    }

    #[test]
    fn mapping_protocol_displays_properly() {
        let inputs = vec![
            MappingProtocol::Pcp,
            MappingProtocol::Pmp,
            MappingProtocol::Igdp,
        ];

        let result = inputs
            .into_iter()
            .map(|input| input.to_string())
            .collect_vec();

        assert_eq! (
            result,
            vec!["pcp", "pmp", "igdp"]
                .into_iter()
                .map(|x| x.to_string())
                .collect_vec()
        )
    }

    #[test]
    fn on_off_from_str_and_display_work() {
        vec!["on", "off"].into_iter().for_each(|expected_value| {
            let value = OnOff::from_str (expected_value).unwrap();
            let actual_value = value.to_string();
            assert_eq!(&actual_value, expected_value);
        })
    }

    #[test]
    fn on_off_from_str_rejects_bad_string() {
        let value = OnOff::from_str("booga");

        assert_eq!(value, Err("Must be either 'on' or 'off', not 'booga'".to_string()))
    }
}
