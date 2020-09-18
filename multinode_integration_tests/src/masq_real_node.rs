// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use crate::command::Command;
use crate::masq_node::MASQNode;
use crate::masq_node::MASQNodeUtils;
use crate::masq_node::NodeReference;
use crate::masq_node::PortSelector;
use crate::masq_node_client::MASQNodeClient;
use crate::masq_node_server::MASQNodeServer;
use bip39::{Language, Mnemonic, Seed};
use masq_lib::test_utils::utils::{DEFAULT_CHAIN_ID, TEST_DEFAULT_CHAIN_NAME};
use masq_lib::utils::localhost;
use node_lib::blockchain::bip32::Bip32ECKeyPair;
use node_lib::blockchain::blockchain_interface::chain_id_from_name;
use node_lib::sub_lib::accountant::DEFAULT_EARNING_WALLET;
use node_lib::sub_lib::cryptde::{CryptDE, PublicKey};
use node_lib::sub_lib::cryptde_null::CryptDENull;
use node_lib::sub_lib::neighborhood::RatePack;
use node_lib::sub_lib::neighborhood::DEFAULT_RATE_PACK;
use node_lib::sub_lib::neighborhood::ZERO_RATE_PACK;
use node_lib::sub_lib::node_addr::NodeAddr;
use node_lib::sub_lib::wallet::{
    Wallet, DEFAULT_CONSUMING_DERIVATION_PATH, DEFAULT_EARNING_DERIVATION_PATH,
};
use regex::Regex;
use rustc_hex::{FromHex, ToHex};
use std::fmt::Display;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::rc::Rc;
use std::str::FromStr;
use std::string::ToString;
use std::thread;
use std::time::Duration;

pub const DATA_DIRECTORY: &str = "/node_root/home";

#[derive(Clone, Debug, PartialEq)]
pub struct Firewall {
    ports_to_open: Vec<u16>,
}

#[derive(PartialEq, Clone, Debug, Copy)]
pub enum LocalIpInfo {
    ZeroHop,
    DistributedUnknown,
    DistributedKnown(IpAddr),
}

pub const DEFAULT_MNEMONIC_PHRASE: &str =
    "lamp sadness busy twist illegal task neither survey copper object room project";
pub const DEFAULT_MNEMONIC_PASSPHRASE: &str = "weenie";

#[derive(PartialEq, Clone, Debug)]
pub enum EarningWalletInfo {
    None,
    Address(String), // wallet address in string form: "0x<40 hex chars>"
    DerivationPath(String, String), // mnemonic phrase, derivation path
}

pub fn default_earning_wallet_info() -> EarningWalletInfo {
    EarningWalletInfo::Address(DEFAULT_EARNING_WALLET.to_string())
}

pub fn meaningless_earning_derivation_path_info() -> EarningWalletInfo {
    EarningWalletInfo::DerivationPath(
        DEFAULT_MNEMONIC_PHRASE.to_string(),
        DEFAULT_EARNING_DERIVATION_PATH.to_string(),
    )
}

pub fn make_earning_wallet_info(token: &str) -> EarningWalletInfo {
    let address = format!(
        "0x{}{}",
        token.to_string().as_bytes().to_hex::<String>(),
        "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
    );
    EarningWalletInfo::Address(address[0..42].to_string().to_lowercase())
}

#[derive(PartialEq, Clone, Debug)]
pub enum ConsumingWalletInfo {
    None,
    PrivateKey(String), // private address in string form, 64 hex characters
    DerivationPath(String, String), // mnemonic phrase, derivation path
}

pub fn default_consuming_wallet_info() -> ConsumingWalletInfo {
    ConsumingWalletInfo::PrivateKey(
        "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC".to_string(),
    )
}

pub fn meaningless_consuming_derivation_path_info() -> ConsumingWalletInfo {
    ConsumingWalletInfo::DerivationPath(
        DEFAULT_MNEMONIC_PHRASE.to_string(),
        DEFAULT_CONSUMING_DERIVATION_PATH.to_string(),
    )
}

pub fn make_consuming_wallet_info(token: &str) -> ConsumingWalletInfo {
    let address = format!(
        "{}{}",
        token.to_string().as_bytes().to_hex::<String>(),
        "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
    );
    ConsumingWalletInfo::PrivateKey(address[0..64].to_string())
}

#[derive(PartialEq, Clone, Debug)]
pub struct NodeStartupConfig {
    pub neighborhood_mode: String,
    pub ip_info: LocalIpInfo,
    pub dns_servers_opt: Option<Vec<IpAddr>>,
    pub neighbors: Vec<NodeReference>,
    pub clandestine_port_opt: Option<u16>,
    pub dns_target: IpAddr,
    pub dns_port: u16,
    pub earning_wallet_info: EarningWalletInfo,
    pub consuming_wallet_info: ConsumingWalletInfo,
    pub rate_pack: RatePack,
    pub firewall_opt: Option<Firewall>,
    pub memory_opt: Option<String>,
    pub fake_public_key_opt: Option<PublicKey>,
    pub blockchain_service_url_opt: Option<String>,
    pub chain_opt: Option<String>,
    pub db_password_opt: Option<String>,
}

impl Default for NodeStartupConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl NodeStartupConfig {
    pub fn new() -> NodeStartupConfig {
        NodeStartupConfig {
            neighborhood_mode: "standard".to_string(),
            ip_info: LocalIpInfo::ZeroHop,
            dns_servers_opt: None,
            neighbors: Vec::new(),
            clandestine_port_opt: None,
            dns_target: IpAddr::V4(Ipv4Addr::BROADCAST),
            dns_port: 0,
            earning_wallet_info: EarningWalletInfo::None,
            consuming_wallet_info: ConsumingWalletInfo::None,
            rate_pack: DEFAULT_RATE_PACK,
            firewall_opt: None,
            memory_opt: None,
            fake_public_key_opt: None,
            blockchain_service_url_opt: None,
            chain_opt: Some(TEST_DEFAULT_CHAIN_NAME.to_string()),
            db_password_opt: Some("password".to_string()),
        }
    }

    pub fn firewall(&self) -> Option<Firewall> {
        self.firewall_opt.clone()
    }

    fn make_args(&self) -> Vec<String> {
        let mut args = vec![];
        args.push("--neighborhood-mode".to_string());
        args.push(self.neighborhood_mode.clone());
        if let LocalIpInfo::DistributedKnown(ip_addr) = self.ip_info {
            args.push("--ip".to_string());
            args.push(ip_addr.to_string());
        }
        if let Some(ref dns_servers) = &self.dns_servers_opt {
            args.push("--dns-servers".to_string());
            args.push(Self::join_strings(dns_servers));
        }
        if !self.neighbors.is_empty() {
            args.push("--neighbors".to_string());
            args.push(Self::join_strings(&self.neighbors));
        }
        if let Some(clandestine_port) = self.clandestine_port_opt {
            args.push("--clandestine-port".to_string());
            args.push(clandestine_port.to_string());
        }
        args.push("--log-level".to_string());
        args.push("trace".to_string());
        args.push("--data-directory".to_string());
        args.push(DATA_DIRECTORY.to_string());
        if let EarningWalletInfo::Address(ref address) = self.earning_wallet_info {
            args.push("--earning-wallet".to_string());
            args.push(address.to_string());
        }
        if let ConsumingWalletInfo::PrivateKey(ref key) = self.consuming_wallet_info {
            args.push("--consuming-private-key".to_string());
            args.push(key.to_string());
        }
        if let Some(ref public_key) = self.fake_public_key_opt {
            args.push("--fake-public-key".to_string());
            args.push(public_key.to_string());
        }
        if let Some(ref blockchain_service_url) = self.blockchain_service_url_opt {
            args.push("--blockchain-service-url".to_string());
            args.push(blockchain_service_url.to_string());
        }
        if let Some(ref chain) = self.chain_opt {
            args.push("--chain".to_string());
            args.push(chain.to_string());
        }
        if let Some(ref db_password) = self.db_password_opt {
            args.push("--db-password".to_string());
            args.push(db_password.to_string());
        }
        args
    }

    fn make_establish_wallet_args(&self) -> Option<Vec<String>> {
        fn to_strings(strs: Vec<&str>) -> Vec<String> {
            strs.into_iter().map(|x| x.to_string()).collect()
        };
        let args = match (&self.earning_wallet_info, &self.consuming_wallet_info) {
            (EarningWalletInfo::None, ConsumingWalletInfo::None) => return None,
            (EarningWalletInfo::None, ConsumingWalletInfo::PrivateKey(_)) => return None,
            (EarningWalletInfo::None, ConsumingWalletInfo::DerivationPath(phrase, path)) => {
                to_strings(vec![
                    "--recover-wallet",
                    "--data-directory",
                    DATA_DIRECTORY,
                    "--mnemonic",
                    &format!("\"{}\"", &phrase),
                    "--mnemonic-passphrase",
                    "passphrase",
                    "--consuming-wallet",
                    &path,
                    "--db-password",
                    "password",
                ])
            }
            (EarningWalletInfo::Address(_), ConsumingWalletInfo::None) => return None,
            (EarningWalletInfo::Address(_), ConsumingWalletInfo::PrivateKey(_)) => return None,
            (
                EarningWalletInfo::Address(address),
                ConsumingWalletInfo::DerivationPath(phrase, path),
            ) => to_strings(vec![
                "--recover-wallet",
                "--data-directory",
                DATA_DIRECTORY,
                "--mnemonic",
                &format!("\"{}\"", &phrase),
                "--mnemonic-passphrase",
                "passphrase",
                "--consuming-wallet",
                &path,
                "--db-password",
                "password",
                "--earning-wallet",
                &address,
            ]),
            (EarningWalletInfo::DerivationPath(phrase, path), ConsumingWalletInfo::None) => {
                to_strings(vec![
                    "--recover-wallet",
                    "--data-directory",
                    DATA_DIRECTORY,
                    "--mnemonic",
                    &format!("\"{}\"", &phrase),
                    "--mnemonic-passphrase",
                    "passphrase",
                    "--db-password",
                    "password",
                    "--earning-wallet",
                    &path,
                ])
            }
            (
                EarningWalletInfo::DerivationPath(phrase, path),
                ConsumingWalletInfo::PrivateKey(_),
            ) => to_strings(vec![
                "--recover-wallet",
                "--data-directory",
                DATA_DIRECTORY,
                "--mnemonic",
                &format!("\"{}\"", &phrase),
                "--mnemonic-passphrase",
                "passphrase",
                "--db-password",
                "password",
                "--earning-wallet",
                &path,
            ]),
            (
                EarningWalletInfo::DerivationPath(ephrase, epath),
                ConsumingWalletInfo::DerivationPath(cphrase, cpath),
            ) => {
                if ephrase != cphrase {
                    panic!(
                        "{:?} does not match {:?}",
                        self.earning_wallet_info, self.consuming_wallet_info
                    )
                }
                to_strings(vec![
                    "--recover-wallet",
                    "--data-directory",
                    DATA_DIRECTORY,
                    "--mnemonic",
                    &format!("\"{}\"", &ephrase),
                    "--mnemonic-passphrase",
                    "passphrase",
                    "--db-password",
                    "password",
                    "--earning-wallet",
                    &epath,
                    "--consuming-wallet",
                    &cpath,
                ])
            }
        };
        Some(args)
    }

    fn join_strings<T: Display>(items: &[T]) -> String {
        items
            .iter()
            .map(|item| format!("{}", item))
            .collect::<Vec<String>>()
            .join(",")
    }

    fn get_earning_wallet(&self) -> Wallet {
        match &self.earning_wallet_info {
            EarningWalletInfo::None => DEFAULT_EARNING_WALLET.clone(),
            EarningWalletInfo::Address(address) => Wallet::from_str(address).unwrap(),
            EarningWalletInfo::DerivationPath(phrase, derivation_path) => {
                let mnemonic = Mnemonic::from_phrase(phrase.as_str(), Language::English).unwrap();
                let keypair = Bip32ECKeyPair::from_raw(
                    Seed::new(&mnemonic, "passphrase").as_ref(),
                    derivation_path,
                )
                .unwrap();
                Wallet::from(keypair)
            }
        }
    }

    fn get_consuming_wallet(&self) -> Option<Wallet> {
        match &self.consuming_wallet_info {
            ConsumingWalletInfo::None => None,
            ConsumingWalletInfo::PrivateKey(key) => {
                let key_bytes = key.from_hex::<Vec<u8>>().unwrap();
                let keypair = Bip32ECKeyPair::from_raw_secret(&key_bytes).unwrap();
                Some(Wallet::from(keypair))
            }
            ConsumingWalletInfo::DerivationPath(phrase, derivation_path) => {
                let mnemonic =
                    Mnemonic::from_phrase(phrase.to_string(), Language::English).unwrap();
                let keypair = Bip32ECKeyPair::from_raw(
                    Seed::new(&mnemonic, "passphrase").as_ref(),
                    derivation_path,
                )
                .unwrap();
                Some(Wallet::from(keypair))
            }
        }
    }
}

pub struct NodeStartupConfigBuilder {
    neighborhood_mode: String,
    ip_info: LocalIpInfo,
    dns_servers_opt: Option<Vec<IpAddr>>,
    neighbors: Vec<NodeReference>,
    clandestine_port_opt: Option<u16>,
    dns_target: IpAddr,
    dns_port: u16,
    earning_wallet_info: EarningWalletInfo,
    consuming_wallet_info: ConsumingWalletInfo,
    rate_pack: RatePack,
    firewall: Option<Firewall>,
    memory: Option<String>,
    fake_public_key: Option<PublicKey>,
    blockchain_service_url: Option<String>,
    chain: Option<String>,
    db_password: Option<String>,
}

impl NodeStartupConfigBuilder {
    pub fn zero_hop() -> Self {
        Self {
            neighborhood_mode: "zero-hop".to_string(),
            ip_info: LocalIpInfo::ZeroHop,
            dns_servers_opt: None,
            neighbors: vec![],
            clandestine_port_opt: None,
            dns_target: localhost(),
            dns_port: 53,
            earning_wallet_info: EarningWalletInfo::None,
            consuming_wallet_info: ConsumingWalletInfo::None,
            rate_pack: ZERO_RATE_PACK.clone(),
            firewall: None,
            memory: None,
            fake_public_key: None,
            blockchain_service_url: None,
            chain: Some(TEST_DEFAULT_CHAIN_NAME.to_string()),
            db_password: None,
        }
    }

    pub fn consume_only() -> Self {
        Self {
            neighborhood_mode: "consume-only".to_string(),
            ip_info: LocalIpInfo::DistributedUnknown,
            dns_servers_opt: None,
            neighbors: vec![],
            clandestine_port_opt: None,
            dns_target: localhost(),
            dns_port: 53,
            earning_wallet_info: EarningWalletInfo::Address(
                "0xEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE".to_string(),
            ),
            consuming_wallet_info: ConsumingWalletInfo::PrivateKey(
                "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC".to_string(),
            ),
            rate_pack: ZERO_RATE_PACK.clone(),
            firewall: None,
            memory: None,
            fake_public_key: None,
            blockchain_service_url: None,
            chain: Some(TEST_DEFAULT_CHAIN_NAME.to_string()),
            db_password: Some("password".to_string()),
        }
    }

    pub fn originate_only() -> Self {
        Self {
            neighborhood_mode: "originate-only".to_string(),
            ip_info: LocalIpInfo::DistributedUnknown,
            dns_servers_opt: None,
            neighbors: vec![],
            clandestine_port_opt: None,
            dns_target: localhost(),
            dns_port: 53,
            earning_wallet_info: EarningWalletInfo::Address(
                "0xEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE".to_string(),
            ),
            consuming_wallet_info: ConsumingWalletInfo::PrivateKey(
                "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC".to_string(),
            ),
            rate_pack: DEFAULT_RATE_PACK.clone(),
            firewall: None,
            memory: None,
            fake_public_key: None,
            blockchain_service_url: None,
            chain: Some(TEST_DEFAULT_CHAIN_NAME.to_string()),
            db_password: Some("password".to_string()),
        }
    }

    pub fn standard() -> Self {
        Self {
            neighborhood_mode: "standard".to_string(),
            ip_info: LocalIpInfo::DistributedUnknown,
            dns_servers_opt: None,
            neighbors: vec![],
            clandestine_port_opt: None,
            dns_target: localhost(),
            dns_port: 53,
            earning_wallet_info: EarningWalletInfo::None,
            consuming_wallet_info: ConsumingWalletInfo::None,
            rate_pack: DEFAULT_RATE_PACK.clone(),
            firewall: None,
            memory: None,
            fake_public_key: None,
            blockchain_service_url: None,
            chain: Some(TEST_DEFAULT_CHAIN_NAME.to_string()),
            db_password: Some("password".to_string()),
        }
    }

    pub fn copy(config: &NodeStartupConfig) -> Self {
        Self {
            neighborhood_mode: config.neighborhood_mode.clone(),
            ip_info: config.ip_info,
            dns_servers_opt: config.dns_servers_opt.clone(),
            neighbors: config.neighbors.clone(),
            clandestine_port_opt: config.clandestine_port_opt,
            dns_target: config.dns_target,
            dns_port: config.dns_port,
            earning_wallet_info: config.earning_wallet_info.clone(),
            consuming_wallet_info: config.consuming_wallet_info.clone(),
            rate_pack: config.rate_pack.clone(),
            firewall: config.firewall_opt.clone(),
            memory: config.memory_opt.clone(),
            fake_public_key: config.fake_public_key_opt.clone(),
            blockchain_service_url: config.blockchain_service_url_opt.clone(),
            chain: config.chain_opt.clone(),
            db_password: config.db_password_opt.clone(),
        }
    }

    pub fn neighborhood_mode(mut self, value: &str) -> Self {
        if vec![
            "zero-hop".to_string(),
            "consume-only".to_string(),
            "originate-only".to_string(),
            "standard".to_string(),
        ]
        .contains(&value.to_string())
        {
            self.neighborhood_mode = value.to_string();
            self
        } else {
            panic!("Unrecognized --neighborhood-mode: '{}'", value)
        }
    }

    pub fn ip(mut self, value: IpAddr) -> Self {
        self.ip_info = LocalIpInfo::DistributedKnown(value);
        self
    }

    pub fn dns_servers(mut self, value: Vec<IpAddr>) -> Self {
        self.dns_servers_opt = Some(value);
        self
    }

    pub fn memory(mut self, value: &str) -> Self {
        self.memory = Some(value.to_string());
        self
    }

    pub fn neighbor(mut self, value: NodeReference) -> Self {
        self.neighbors.push(value);
        self
    }

    pub fn neighbors(mut self, value: Vec<NodeReference>) -> Self {
        self.neighbors = value;
        self
    }

    pub fn clandestine_port(mut self, value: u16) -> Self {
        self.clandestine_port_opt = Some(value);
        self
    }

    pub fn dns_target(mut self, value: IpAddr) -> Self {
        self.dns_target = value;
        self
    }

    pub fn dns_port(mut self, value: u16) -> Self {
        self.dns_port = value;
        self
    }

    pub fn earning_wallet_info(mut self, value: EarningWalletInfo) -> Self {
        self.earning_wallet_info = value;
        self
    }

    pub fn consuming_wallet_info(mut self, value: ConsumingWalletInfo) -> Self {
        self.consuming_wallet_info = value;
        self
    }

    pub fn rate_pack(mut self, value: RatePack) -> Self {
        self.rate_pack = value;
        self
    }

    pub fn open_firewall_port(mut self, port: u16) -> Self {
        if self.firewall.is_none() {
            self.firewall = Some(Firewall {
                ports_to_open: vec![],
            })
        }
        self.firewall
            .as_mut()
            .expect("Firewall magically disappeared")
            .ports_to_open
            .push(port);
        self
    }

    pub fn fake_public_key(mut self, public_key: &PublicKey) -> Self {
        self.fake_public_key = Some(public_key.clone());
        self
    }

    pub fn blockchain_service_url(mut self, blockchain_service_url: String) -> Self {
        self.blockchain_service_url = Some(blockchain_service_url);
        self
    }

    pub fn chain(mut self, chain: &str) -> Self {
        self.chain = Some(chain.into());
        self
    }

    pub fn db_password(mut self, value: Option<&str>) -> Self {
        self.db_password = match value {
            Some(s) => Some(s.to_string()),
            None => None,
        };
        self
    }

    pub fn build(self) -> NodeStartupConfig {
        NodeStartupConfig {
            neighborhood_mode: self.neighborhood_mode,
            ip_info: self.ip_info,
            dns_servers_opt: self.dns_servers_opt,
            neighbors: self.neighbors,
            clandestine_port_opt: self.clandestine_port_opt,
            dns_target: self.dns_target,
            dns_port: self.dns_port,
            earning_wallet_info: self.earning_wallet_info,
            consuming_wallet_info: self.consuming_wallet_info,
            rate_pack: self.rate_pack,
            firewall_opt: self.firewall,
            memory_opt: self.memory,
            fake_public_key_opt: self.fake_public_key,
            blockchain_service_url_opt: self.blockchain_service_url,
            chain_opt: self.chain,
            db_password_opt: self.db_password,
        }
    }
}

#[derive(Clone, Debug)]
pub struct MASQRealNode {
    guts: Rc<MASQRealNodeGuts>,
}

impl MASQNode for MASQRealNode {
    fn name(&self) -> &str {
        &self.guts.name
    }

    fn node_reference(&self) -> NodeReference {
        self.guts.node_reference.clone()
    }

    fn main_cryptde_null(&self) -> Option<&CryptDENull> {
        self.guts
            .cryptde_null_pair_opt
            .as_ref()
            .map(|pair| &pair.main)
    }

    fn alias_cryptde_null(&self) -> Option<&CryptDENull> {
        self.guts
            .cryptde_null_pair_opt
            .as_ref()
            .map(|pair| &pair.alias)
    }

    fn signing_cryptde(&self) -> Option<&dyn CryptDE> {
        match self.main_cryptde_null() {
            Some(cryptde_null) => Some(cryptde_null),
            None => None,
        }
    }

    fn main_public_key(&self) -> &PublicKey {
        &self.guts.node_reference.public_key
    }

    fn ip_address(&self) -> IpAddr {
        self.guts.container_ip
    }

    fn port_list(&self) -> Vec<u16> {
        match self.node_reference().node_addr_opt {
            Some(node_addr) => node_addr.ports(),
            None => vec![],
        }
    }

    fn node_addr(&self) -> NodeAddr {
        NodeAddr::new(&self.ip_address(), &self.port_list())
    }

    fn socket_addr(&self, port_selector: PortSelector) -> SocketAddr {
        MASQNodeUtils::socket_addr(&self.node_addr(), port_selector, self.name())
    }

    fn earning_wallet(&self) -> Wallet {
        self.guts.earning_wallet.clone()
    }

    fn consuming_wallet(&self) -> Option<Wallet> {
        self.guts.consuming_wallet_opt.clone()
    }

    fn rate_pack(&self) -> RatePack {
        self.guts.rate_pack.clone()
    }

    fn chain(&self) -> Option<String> {
        self.guts.chain.clone()
    }

    fn accepts_connections(&self) -> bool {
        self.guts.accepts_connections
    }

    fn routes_data(&self) -> bool {
        self.guts.routes_data
    }
}

impl MASQRealNode {
    pub fn prepare(name: &str) {
        Self::do_prepare_for_docker_run(name).unwrap();
    }

    pub fn make_name(index: usize) -> String {
        format!("test_node_{}", index)
    }

    pub fn start(
        startup_config: NodeStartupConfig,
        index: usize,
        host_node_parent_dir: Option<String>,
    ) -> Self {
        let name = Self::make_name(index);
        Self::start_with(
            name,
            startup_config,
            index,
            host_node_parent_dir,
            Box::new(Self::do_docker_run),
        )
    }

    pub fn start_prepared(
        name: String,
        startup_config: NodeStartupConfig,
        index: usize,
        host_node_parent_dir: Option<String>,
    ) -> Self {
        Self::start_with(
            name,
            startup_config,
            index,
            host_node_parent_dir,
            Box::new(Self::do_preprepared_docker_run),
        )
    }

    pub fn start_with(
        name: String,
        startup_config: NodeStartupConfig,
        index: usize,
        host_node_parent_dir: Option<String>,
        docker_run_fn: Box<dyn Fn(&str, IpAddr, &str) -> Result<(), String>>,
    ) -> Self {
        let ip_addr = IpAddr::V4(Ipv4Addr::new(172, 18, 1, index as u8));
        MASQNodeUtils::clean_up_existing_container(&name[..]);
        let real_startup_config = match startup_config.ip_info {
            LocalIpInfo::ZeroHop => startup_config,
            LocalIpInfo::DistributedUnknown => NodeStartupConfigBuilder::copy(&startup_config)
                .ip(ip_addr)
                .build(),
            LocalIpInfo::DistributedKnown(ip_addr) => panic!(
                "Can't pre-specify the IP address of a MASQRealNode: {}",
                ip_addr
            ),
        };
        let root_dir = match host_node_parent_dir {
            Some(dir) => dir,
            None => MASQNodeUtils::find_project_root(),
        };

        docker_run_fn(&root_dir, ip_addr, &name).expect("docker run");

        Self::exec_command_on_container_and_detach(
            &name,
            vec!["/usr/local/bin/port_exposer", "80:8080", "443:8443"],
        )
        .expect("port_exposer wouldn't run");
        match &real_startup_config.firewall_opt {
            None => (),
            Some(firewall) => {
                Self::create_impenetrable_firewall(&name);
                firewall.ports_to_open.iter().for_each(|port| {
                    Self::open_firewall_port(&name, *port)
                        .unwrap_or_else(|_| panic!("Can't open port {}", *port))
                });
            }
        }
        Self::establish_wallet_info(&name, &real_startup_config);
        let chain_id = real_startup_config
            .clone()
            .chain_opt
            .map(|chain_name| chain_id_from_name(chain_name.as_str()))
            .unwrap_or(DEFAULT_CHAIN_ID);
        let cryptde_null_opt = real_startup_config
            .fake_public_key_opt
            .clone()
            .map(|public_key| CryptDENull::from(&public_key, chain_id));
        let restart_startup_config = real_startup_config.clone();
        let guts = Rc::new(MASQRealNodeGuts {
            startup_config: real_startup_config.clone(),
            name: name.clone(),
            container_ip: ip_addr,
            node_reference: NodeReference::new(PublicKey::new(&[]), None, vec![]), // placeholder
            earning_wallet: real_startup_config.get_earning_wallet(),
            consuming_wallet_opt: real_startup_config.get_consuming_wallet(),
            rate_pack: DEFAULT_RATE_PACK.clone(), // replace with this when rate packs are configurable: startup_config.rate_pack.clone()
            root_dir,
            cryptde_null_pair_opt: match cryptde_null_opt {
                None => None,
                Some(main_cdn) => {
                    let mut key = main_cdn.public_key().as_slice().to_vec();
                    key.reverse();
                    let alias_cdn = CryptDENull::from(&PublicKey::new(&key), chain_id);
                    Some(CryptDENullPair {
                        main: main_cdn,
                        alias: alias_cdn,
                    })
                }
            },
            chain: real_startup_config.chain_opt,
            accepts_connections: vec!["standard"]
                .contains(&real_startup_config.neighborhood_mode.as_str()),
            routes_data: vec!["standard", "originate-only"]
                .contains(&real_startup_config.neighborhood_mode.as_str()),
        });
        let mut result = Self { guts };
        result.restart_node(restart_startup_config);
        let node_reference =
            Self::extract_node_reference(&name).expect("extracting node reference");
        Rc::get_mut(&mut result.guts).unwrap().node_reference = node_reference;
        result
    }

    pub fn get_startup_config(&self) -> NodeStartupConfig {
        self.guts.startup_config.clone()
    }

    pub fn kill_node(&self) {
        let _ =
            Self::exec_command_on_container_and_wait(&self.guts.name, vec!["pkill", "MASQNode"]);
    }

    pub fn restart_node(&self, startup_config: NodeStartupConfig) {
        let node_args = startup_config.make_args();
        let node_command = Self::create_node_command(node_args, startup_config);
        let mut bash_command_parts = vec!["/bin/bash", "-c"];
        bash_command_parts.extend(vec![node_command.as_str()]);
        Self::exec_command_on_container_and_detach(&self.guts.name, bash_command_parts)
            .expect("Couldn't start MASQNode");
    }

    pub fn root_dir(&self) -> String {
        self.guts.root_dir.clone()
    }

    pub fn node_home_dir(root_dir: &str, name: &str) -> String {
        format!(
            "{}/multinode_integration_tests/generated/node_homes/{}",
            root_dir, name
        )
    }

    pub fn home_dir(&self) -> String {
        Self::node_home_dir(&self.root_dir(), &String::from(self.name()))
    }

    pub fn open_firewall_port(name: &str, port: u16) -> Result<(), ()> {
        let port_str = format!("{}", port);
        match Self::exec_command_on_container_and_wait(
            name,
            vec![
                "iptables", "-A", "INPUT", "-p", "tcp", "--dport", &port_str, "-j", "ACCEPT",
            ],
        ) {
            Err(_) => Err(()),
            Ok(_) => Ok(()),
        }
    }

    pub fn make_client(&self, port: u16) -> MASQNodeClient {
        let socket_addr = SocketAddr::new(self.ip_address(), port);
        MASQNodeClient::new(socket_addr)
    }

    pub fn make_server(&self, port: u16) -> MASQNodeServer {
        MASQNodeServer::new(port)
    }

    fn establish_wallet_info(name: &str, startup_config: &NodeStartupConfig) {
        let args = match startup_config.make_establish_wallet_args() {
            None => return,
            Some(args) => args.join(" "),
        };
        let node_command = format!("/node_root/node/MASQNode {}", args);
        let mut bash_command_parts = vec!["/bin/bash", "-c"];
        bash_command_parts.extend(vec![node_command.as_str()]);
        Self::exec_command_on_container_and_wait(name, bash_command_parts)
            .expect("Couldn't establish wallet info");
    }

    fn create_node_command(node_args: Vec<String>, startup_config: NodeStartupConfig) -> String {
        let mut node_command_parts: Vec<String> = match startup_config.memory_opt {
            Some(kbytes) => vec![format!(
                "ulimit -v {} -m {} && /node_root/node/MASQNode",
                kbytes, kbytes
            )],
            None => vec!["/node_root/node/MASQNode".to_string()],
        };
        node_command_parts.extend(node_args);
        node_command_parts.join(" ")
    }

    fn do_docker_run(
        root_dir: &str,
        ip_addr: IpAddr,
        container_name_ref: &str,
    ) -> Result<(), String> {
        let container_name = container_name_ref.to_string();
        let node_command_dir = format!("{}/node/target/release", root_dir);
        let host_node_home_dir = Self::node_home_dir(root_dir, container_name_ref);
        let test_runner_node_home_dir =
            Self::node_home_dir(&MASQNodeUtils::find_project_root(), container_name_ref);
        Self::remove_test_runner_node_home_dir(&test_runner_node_home_dir);
        Self::create_test_runner_node_home_dir(&container_name, &test_runner_node_home_dir);
        Self::set_permissions_test_runner_node_home_dir(&container_name, test_runner_node_home_dir);
        let ip_addr_string = format!("{}", ip_addr);
        let node_binary_v_param = format!("{}:/node_root/node", node_command_dir);
        let home_v_param = format!("{}:{}", host_node_home_dir, DATA_DIRECTORY);

        let mut args = vec![
            "run",
            "--detach",
            "--ip",
            ip_addr_string.as_str(),
            "--dns",
            "127.0.0.1",
            "--name",
            container_name.as_str(),
            "--net",
            "integration_net",
            "-v",
            node_binary_v_param.as_str(),
            "-v",
            home_v_param.as_str(),
            "-e",
            "RUST_BACKTRACE=full",
            "--cap-add=NET_ADMIN",
        ];

        args.push("test_node_image");
        let mut command = Command::new("docker", Command::strings(args));
        command.stdout_or_stderr()?;
        Ok(())
    }

    fn do_prepare_for_docker_run(container_name_ref: &str) -> Result<(), String> {
        let container_name = container_name_ref.to_string();
        let test_runner_node_home_dir =
            Self::node_home_dir(&MASQNodeUtils::find_project_root(), container_name_ref);
        Self::remove_test_runner_node_home_dir(&test_runner_node_home_dir);
        Self::create_test_runner_node_home_dir(&container_name, &test_runner_node_home_dir);
        Self::set_permissions_test_runner_node_home_dir(&container_name, test_runner_node_home_dir);
        Ok(())
    }

    fn do_preprepared_docker_run(
        root_dir: &str,
        ip_addr: IpAddr,
        container_name_ref: &str,
    ) -> Result<(), String> {
        let container_name = container_name_ref.to_string();
        let node_command_dir = format!("{}/node/target/release", root_dir);
        let host_node_home_dir = Self::node_home_dir(root_dir, container_name_ref);
        let ip_addr_string = format!("{}", ip_addr);
        let node_binary_v_param = format!("{}:/node_root/node", node_command_dir);
        let home_v_param = format!("{}:{}", host_node_home_dir, DATA_DIRECTORY);

        let mut args = vec![
            "run",
            "--detach",
            "--ip",
            ip_addr_string.as_str(),
            "--dns",
            "127.0.0.1",
            "--name",
            container_name.as_str(),
            "--net",
            "integration_net",
            "-v",
            node_binary_v_param.as_str(),
            "-v",
            home_v_param.as_str(),
            "-e",
            "RUST_BACKTRACE=full",
            "--cap-add=NET_ADMIN",
        ];

        args.push("test_node_image");
        let mut command = Command::new("docker", Command::strings(args));
        command.stdout_or_stderr()?;
        Ok(())
    }

    fn set_permissions_test_runner_node_home_dir(
        container_name: &str,
        test_runner_node_home_dir: String,
    ) {
        match Command::new(
            "chmod",
            Command::strings(vec!["777", test_runner_node_home_dir.as_str()]),
        )
        .wait_for_exit()
        {
            0 => (),
            _ => panic!(
                "Couldn't chmod 777 home directory for node {} at {}",
                container_name, test_runner_node_home_dir
            ),
        }
    }

    fn create_test_runner_node_home_dir(container_name: &str, test_runner_node_home_dir: &str) {
        match Command::new(
            "mkdir",
            Command::strings(vec!["-p", test_runner_node_home_dir]),
        )
        .wait_for_exit()
        {
            0 => (),
            _ => panic!(
                "Couldn't create home directory for node {} at {}",
                container_name, test_runner_node_home_dir
            ),
        }
    }

    fn remove_test_runner_node_home_dir(test_runner_node_home_dir: &str) {
        Command::new(
            "rm",
            Command::strings(vec!["-r", test_runner_node_home_dir]),
        )
        .wait_for_exit();
    }

    pub fn exec_command_on_container_and_detach(
        name: &str,
        command_parts: Vec<&str>,
    ) -> Result<String, String> {
        Self::do_docker_exec(name, command_parts, "-d")
    }

    fn exec_command_on_container_and_wait(
        name: &str,
        command_parts: Vec<&str>,
    ) -> Result<String, String> {
        Self::do_docker_exec(name, command_parts, "-t")
    }

    fn do_docker_exec(
        name: &str,
        command_parts: Vec<&str>,
        exec_type: &str,
    ) -> Result<String, String> {
        let mut params = vec!["exec", exec_type, name];
        params.extend(command_parts);
        let mut command = Command::new("docker", Command::strings(params));
        command.stdout_or_stderr()
    }

    fn create_impenetrable_firewall(name: &str) {
        Self::exec_command_on_container_and_wait(name, vec!["iptables", "-P", "INPUT", "DROP"])
            .expect("Can't completely reject all incoming data by default");
        Self::exec_command_on_container_and_wait(
            name,
            vec!["iptables", "-A", "INPUT", "-i", "lo", "-j", "ACCEPT"],
        )
        .expect("Can't add exception to allow incoming data from loopback interface");
        Self::exec_command_on_container_and_wait(
            name,
            vec![
                "iptables",
                "-A",
                "INPUT",
                "-m",
                "conntrack",
                "--ctstate",
                "RELATED,ESTABLISHED",
                "-j",
                "ACCEPT",
            ],
        )
        .expect("Can't add exception to allow input that is respondent to past output");
    }

    fn extract_node_reference(name: &str) -> Result<NodeReference, String> {
        let regex = Regex::new(r"MASQ Node local descriptor: ([^:]+[:@][\d.]*:[\d,]*)").unwrap();
        let mut retries_left = 10;
        loop {
            println!("Checking for {} startup", name);
            thread::sleep(Duration::from_millis(100));
            let output = Self::exec_command_on_container_and_wait(
                name,
                vec!["cat", &format!("{}/MASQNode_rCURRENT.log", DATA_DIRECTORY)],
            )
            .unwrap_or_else(|e| {
                panic!(
                    "Failed to read {}/MASQNode_rCURRENT.log: {}",
                    DATA_DIRECTORY, e
                )
            });
            match regex.captures(output.as_str()) {
                Some(captures) => {
                    let node_reference =
                        NodeReference::from_str(captures.get(1).unwrap().as_str()).unwrap();
                    println!("{} startup detected at {}", name, node_reference);
                    return Ok(node_reference);
                }
                None => {
                    if retries_left <= 0 {
                        return Err(format!("Node {} never started:\n{}", name, output));
                    } else {
                        retries_left -= 1;
                    }
                }
            }
        }
    }
}

#[derive(Debug, Clone)]
struct CryptDENullPair {
    main: CryptDENull,
    alias: CryptDENull,
}

#[derive(Debug)]
struct MASQRealNodeGuts {
    startup_config: NodeStartupConfig,
    name: String,
    container_ip: IpAddr,
    node_reference: NodeReference,
    earning_wallet: Wallet,
    consuming_wallet_opt: Option<Wallet>,
    rate_pack: RatePack,
    root_dir: String,
    cryptde_null_pair_opt: Option<CryptDENullPair>,
    chain: Option<String>,
    accepts_connections: bool,
    routes_data: bool,
}

impl Drop for MASQRealNodeGuts {
    fn drop(&mut self) {
        MASQNodeUtils::stop(self.name.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use masq_lib::constants::{HTTP_PORT, TLS_PORT};
    use masq_lib::test_utils::utils::TEST_DEFAULT_CHAIN_NAME;
    use masq_lib::utils::localhost;

    #[test]
    fn node_startup_config_builder_zero_hop() {
        let result = NodeStartupConfigBuilder::zero_hop().build();

        assert_eq!(result.ip_info, LocalIpInfo::ZeroHop);
        assert_eq!(result.dns_servers_opt, None);
        assert_eq!(result.neighbors, vec!());
        assert_eq!(result.clandestine_port_opt, None);
        assert_eq!(result.dns_target, localhost());
        assert_eq!(result.dns_port, 53);
        assert_eq!(result.neighborhood_mode, "zero-hop".to_string());
    }

    #[test]
    fn node_max_memory_can_be_configured() {
        let memory = "50mb";
        let result = NodeStartupConfigBuilder::zero_hop().memory(memory).build();

        assert_eq!(Some(memory.to_string()), result.memory_opt);
    }

    #[test]
    fn node_startup_config_builder_standard() {
        let result = NodeStartupConfigBuilder::standard().build();

        assert_eq!(result.ip_info, LocalIpInfo::DistributedUnknown);
        assert_eq!(result.dns_servers_opt, None);
        assert_eq!(result.neighbors, vec!());
        assert_eq!(result.clandestine_port_opt, None);
        assert_eq!(result.dns_target, localhost());
        assert_eq!(result.dns_port, 53);
        assert_eq!(result.neighborhood_mode, "standard".to_string());
    }

    #[test]
    fn node_startup_config_builder_originate_only() {
        let result = NodeStartupConfigBuilder::originate_only().build();

        assert_eq!(result.ip_info, LocalIpInfo::DistributedUnknown);
        assert_eq!(result.dns_servers_opt, None);
        assert_eq!(result.neighbors, vec!());
        assert_eq!(result.clandestine_port_opt, None);
        assert_eq!(result.dns_target, localhost());
        assert_eq!(result.dns_port, 53);
        assert_eq!(result.neighborhood_mode, "originate-only".to_string());
    }

    #[test]
    fn node_startup_config_builder_settings() {
        let ip_addr = IpAddr::from_str("1.2.3.4").unwrap();
        let one_neighbor_key = PublicKey::new(&[1, 2, 3, 4]);
        let one_neighbor_ip_addr = IpAddr::from_str("4.5.6.7").unwrap();
        let one_neighbor_ports = vec![1234, 2345];
        let another_neighbor_key = PublicKey::new(&[2, 3, 4, 5]);
        let another_neighbor_ip_addr = IpAddr::from_str("5.6.7.8").unwrap();
        let another_neighbor_ports = vec![3456, 4567];
        let dns_servers = vec![
            IpAddr::from_str("2.3.4.5").unwrap(),
            IpAddr::from_str("3.4.5.6").unwrap(),
        ];
        let neighbors = vec![
            NodeReference::new(
                one_neighbor_key.clone(),
                Some(one_neighbor_ip_addr.clone()),
                one_neighbor_ports.clone(),
            ),
            NodeReference::new(
                another_neighbor_key.clone(),
                Some(another_neighbor_ip_addr.clone()),
                another_neighbor_ports.clone(),
            ),
        ];
        let dns_target = IpAddr::from_str("8.9.10.11").unwrap();

        let result = NodeStartupConfigBuilder::standard()
            .ip(ip_addr)
            .dns_servers(dns_servers.clone())
            .neighbor(neighbors[0].clone())
            .neighbor(neighbors[1].clone())
            .dns_target(dns_target)
            .dns_port(35)
            .build();

        assert_eq!(result.ip_info, LocalIpInfo::DistributedKnown(ip_addr));
        assert_eq!(result.dns_servers_opt, Some(dns_servers));
        assert_eq!(result.neighbors, neighbors);
        assert_eq!(result.clandestine_port_opt, None);
        assert_eq!(result.dns_target, dns_target);
        assert_eq!(result.dns_port, 35);
    }

    #[test]
    fn node_startup_config_builder_copy() {
        let original = NodeStartupConfig {
            neighborhood_mode: "consume-only".to_string(),
            ip_info: LocalIpInfo::DistributedUnknown,
            dns_servers_opt: Some(vec![IpAddr::from_str("255.255.255.255").unwrap()]),
            neighbors: vec![NodeReference::new(
                PublicKey::new(&[255]),
                Some(IpAddr::from_str("255.255.255.255").unwrap()),
                vec![255],
            )],
            clandestine_port_opt: Some(1234),
            dns_target: IpAddr::from_str("255.255.255.255").unwrap(),
            dns_port: 54,
            earning_wallet_info: make_earning_wallet_info("booga"),
            consuming_wallet_info: make_consuming_wallet_info("booga"),
            rate_pack: RatePack {
                routing_byte_rate: 10,
                routing_service_rate: 20,
                exit_byte_rate: 30,
                exit_service_rate: 40,
            },
            firewall_opt: Some(Firewall {
                ports_to_open: vec![HTTP_PORT, TLS_PORT],
            }),
            memory_opt: Some("32m".to_string()),
            fake_public_key_opt: Some(PublicKey::new(&[1, 2, 3, 4])),
            blockchain_service_url_opt: None,
            chain_opt: None,
            db_password_opt: Some("booga".to_string()),
        };
        let neighborhood_mode = "standard".to_string();
        let ip_addr = IpAddr::from_str("1.2.3.4").unwrap();
        let one_neighbor_key = PublicKey::new(&[1, 2, 3, 4]);
        let one_neighbor_ip_addr = IpAddr::from_str("4.5.6.7").unwrap();
        let one_neighbor_ports = vec![1234, 2345];
        let another_neighbor_key = PublicKey::new(&[2, 3, 4, 5]);
        let another_neighbor_ip_addr = IpAddr::from_str("5.6.7.8").unwrap();
        let another_neighbor_ports = vec![3456, 4567];
        let dns_servers = vec![
            IpAddr::from_str("2.3.4.5").unwrap(),
            IpAddr::from_str("3.4.5.6").unwrap(),
        ];
        let neighbors = vec![
            NodeReference::new(
                one_neighbor_key.clone(),
                Some(one_neighbor_ip_addr.clone()),
                one_neighbor_ports.clone(),
            ),
            NodeReference::new(
                another_neighbor_key.clone(),
                Some(another_neighbor_ip_addr.clone()),
                another_neighbor_ports.clone(),
            ),
        ];
        let dns_target = IpAddr::from_str("8.9.10.11").unwrap();

        let result = NodeStartupConfigBuilder::copy(&original)
            .neighborhood_mode(&neighborhood_mode)
            .ip(ip_addr)
            .dns_servers(dns_servers.clone())
            .neighbors(neighbors.clone())
            .clandestine_port(1234)
            .dns_target(dns_target)
            .dns_port(35)
            .build();

        assert_eq!(result.neighborhood_mode, neighborhood_mode);
        assert_eq!(result.ip_info, LocalIpInfo::DistributedKnown(ip_addr));
        assert_eq!(result.dns_servers_opt, Some(dns_servers));
        assert_eq!(result.neighbors, neighbors);
        assert_eq!(result.clandestine_port_opt, Some(1234));
        assert_eq!(result.dns_target, dns_target);
        assert_eq!(result.dns_port, 35);
        assert_eq!(
            result.earning_wallet_info,
            make_earning_wallet_info("booga")
        );
        assert_eq!(
            result.consuming_wallet_info,
            make_consuming_wallet_info("booga")
        );
        assert_eq!(
            result.fake_public_key_opt,
            Some(PublicKey::new(&[1, 2, 3, 4]))
        );
        assert_eq!(result.db_password_opt, Some("booga".to_string()))
    }

    #[test]
    fn can_make_args() {
        let one_neighbor = NodeReference::new(
            PublicKey::new(&[1, 2, 3, 4]),
            Some(IpAddr::from_str("4.5.6.7").unwrap()),
            vec![1234, 2345],
        );
        let another_neighbor = NodeReference::new(
            PublicKey::new(&[2, 3, 4, 5]),
            Some(IpAddr::from_str("5.6.7.8").unwrap()),
            vec![3456, 4567],
        );

        let subject = NodeStartupConfigBuilder::standard()
            .neighborhood_mode("consume-only")
            .ip(IpAddr::from_str("1.3.5.7").unwrap())
            .neighbor(one_neighbor.clone())
            .neighbor(another_neighbor.clone())
            .consuming_wallet_info(default_consuming_wallet_info())
            .build();

        let result = subject.make_args();

        assert_eq!(
            result,
            Command::strings(vec!(
                "--neighborhood-mode",
                "consume-only",
                "--ip",
                "1.3.5.7",
                "--neighbors",
                format!("{},{}", one_neighbor, another_neighbor).as_str(),
                "--log-level",
                "trace",
                "--data-directory",
                DATA_DIRECTORY,
                "--consuming-private-key",
                "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
                "--chain",
                TEST_DEFAULT_CHAIN_NAME,
                "--db-password",
                "password",
            ))
        );
    }
}
