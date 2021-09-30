// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use crate::command::Command;
use base64::STANDARD_NO_PAD;
use masq_lib::constants::{CURRENT_LOGFILE_NAME, HIGHEST_USABLE_PORT, MASQ_URL_PREFIX};
use node_lib::blockchain::blockchains::{
    blockchain_from_chain_id, blockchain_from_label_opt, chain_id_from_blockchain,
    label_from_blockchain, CHAIN_LABEL_DELIMITER, KEY_VS_IP_DELIMITER,
};
use node_lib::sub_lib::cryptde::{CryptDE, PublicKey};
use node_lib::sub_lib::cryptde_null::CryptDENull;
use node_lib::sub_lib::neighborhood::RatePack;
use node_lib::sub_lib::node_addr::NodeAddr;
use node_lib::sub_lib::wallet::Wallet;
use regex::Regex;
use std::any::Any;
use std::env;
use std::ffi::OsStr;
use std::fmt;
use std::fs;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::path::Path;
use std::path::PathBuf;
use std::str::FromStr;
use std::thread;
use std::time::Duration;
use std::time::Instant;

#[derive(PartialEq, Clone, Debug)]
pub struct NodeReference {
    pub public_key: PublicKey,
    pub node_addr_opt: Option<NodeAddr>,
    pub chain_id: u8,
}

impl FromStr for NodeReference {
    type Err = String;

    //TODO inaccurate - this works only as long as we don't parse the real Node descriptor including its URL prefix which we don't now, see extract_node_reference()
    fn from_str(string_rep: &str) -> Result<Self, <Self as FromStr>::Err> {
        let pieces: Vec<&str> = string_rep.split(':').collect();
        if pieces.len() != 3 {
            return Err(format!("A NodeReference must have the form <chain label>.<public_key>:<IP address>:<port list>, not '{}'", string_rep));
        }
        let (label, key_encoded) = Self::extract_label_and_encoded_public_key(pieces[0])?;
        let public_key = Self::extract_public_key(key_encoded)?;
        let ip_addr = Self::extract_ip_addr(pieces[1])?;
        let port_list = Self::extract_port_list(pieces[2])?;
        Ok(NodeReference::new(
            public_key,
            ip_addr,
            port_list,
            chain_id_from_blockchain(
                blockchain_from_label_opt(label).expect("chain outside the bounds; unknown"),
            ),
        ))
    }
}

impl From<&dyn MASQNode> for NodeReference {
    fn from(masq_node: &dyn MASQNode) -> Self {
        NodeReference {
            public_key: masq_node.main_public_key().clone(),
            node_addr_opt: Some(masq_node.node_addr()),
            chain_id: masq_node.chain_id(),
        }
    }
}

impl fmt::Display for NodeReference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let public_key_string = base64::encode_config(&self.public_key.as_slice(), STANDARD_NO_PAD);
        let ip_addr_string = match &self.node_addr_opt {
            Some(node_addr) => format!("{}", node_addr.ip_addr()),
            None => String::new(),
        };
        let port_list_string = match &self.node_addr_opt {
            Some(node_addr) => node_addr
                .ports()
                .iter()
                .map(|port| port.to_string())
                .collect::<Vec<String>>()
                .join(","),
            None => String::new(),
        };
        write!(
            f,
            "{}{}{}{}{}{}:{}",
            MASQ_URL_PREFIX,
            label_from_blockchain(blockchain_from_chain_id(self.chain_id)),
            CHAIN_LABEL_DELIMITER,
            public_key_string,
            KEY_VS_IP_DELIMITER,
            ip_addr_string,
            port_list_string
        )
        .unwrap();
        Ok(())
    }
}

impl NodeReference {
    pub fn new(
        public_key: PublicKey,
        ip_addr_opt: Option<IpAddr>,
        ports: Vec<u16>,
        chain_id: u8,
    ) -> NodeReference {
        match ip_addr_opt {
            Some(ip_addr) => NodeReference {
                public_key,
                node_addr_opt: Some(NodeAddr::new(&ip_addr, &ports)),
                chain_id: chain_id,
            },
            None => NodeReference {
                public_key,
                node_addr_opt: None,
                chain_id: chain_id,
            },
        }
    }

    fn extract_public_key(slice: &str) -> Result<PublicKey, String> {
        match base64::decode(slice) {
            Ok (data) => Ok (PublicKey::new (&data[..])),
            Err (_) => Err (format!("The public key of a NodeReference must be represented as a valid Base64 string, not '{}'", slice))
        }
    }

    fn extract_label_and_encoded_public_key(slice: &str) -> Result<(&str, &str), String> {
        let pieces: Vec<&str> = slice.split(CHAIN_LABEL_DELIMITER).collect();
        if pieces.len() != 2 {
            return Err(format!(
                "The chain label in the descriptor isn't properly set: '{}'",
                slice
            ));
        }
        Ok((pieces[0], pieces[1]))
    }

    fn extract_ip_addr(slice: &str) -> Result<Option<IpAddr>, String> {
        if slice.is_empty() {
            Ok(None)
        } else {
            match IpAddr::from_str(slice) {
                Ok(ip_addr) => Ok(Some(ip_addr)),
                Err(_) => Err(format!(
                    "The IP address of a NodeReference must be valid, not '{}'",
                    slice
                )),
            }
        }
    }

    fn extract_port_list(slice: &str) -> Result<Vec<u16>, String> {
        let port_list_numbers: Vec<i64> = if slice.is_empty() {
            vec![]
        } else {
            String::from(slice)
                .split(',')
                .map(|x| x.parse::<i64>().unwrap_or(-1))
                .collect()
        };
        if port_list_numbers.contains(&-1) {
            return Err(format!(
                "The port list must be a comma-separated sequence of valid numbers, not '{}'",
                slice
            ));
        }
        if let Some(x) = port_list_numbers
            .iter()
            .find(|x| x > &&(HIGHEST_USABLE_PORT as i64))
        {
            return Err(format!(
                "Each port number must be {} or less, not '{}'",
                HIGHEST_USABLE_PORT, x
            ));
        }
        Ok(port_list_numbers.into_iter().map(|x| x as u16).collect())
    }
}

pub enum PortSelector {
    First,
    Last,
    Index(usize),
}

pub trait MASQNode: Any {
    fn name(&self) -> &str;
    // This is the NodeReference stated by the Node in the console. Its IP address won't be accurate if it's a zero-hop Node.
    fn node_reference(&self) -> NodeReference;
    // If this MASQNode has a main CryptDENull instead of a CryptDEReal, you can get it here.
    fn main_cryptde_null(&self) -> Option<&CryptDENull>;
    // If this MASQNode has an alias CryptDENull instead of a CryptDEReal, you can get it here.
    fn alias_cryptde_null(&self) -> Option<&CryptDENull>;
    // The CryptDE that can be used for signing for this Node, if any. (None if it's a MASQRealNode with a CryptDEReal.)
    fn signing_cryptde(&self) -> Option<&dyn CryptDE>;
    // A reference to this MASQNode's main public key.
    fn main_public_key(&self) -> &PublicKey;
    // This is the IP address of the container in which the Node is running.
    fn ip_address(&self) -> IpAddr;
    fn port_list(&self) -> Vec<u16>;
    // This contains the IP address of the container in which the Node is running.
    fn node_addr(&self) -> NodeAddr;
    // This contains the IP address of the container in which the Node is running.
    fn socket_addr(&self, port_selector: PortSelector) -> SocketAddr;
    // This is the wallet address at which this Node expects to be paid.
    fn earning_wallet(&self) -> Wallet;
    // This is the wallet address from which this Node expects to pay bills, or None if the Node is earn-only.
    fn consuming_wallet(&self) -> Option<Wallet>;
    // The RatePack this Node will use to charge fees.
    fn rate_pack(&self) -> RatePack;
    // Valid values are "dev, "ropsten", "rinkeby" for now. Add "mainnet" when it's time.
    fn chain_id(&self) -> u8;
    fn accepts_connections(&self) -> bool;
    fn routes_data(&self) -> bool;
}

pub struct MASQNodeUtils {}

impl MASQNodeUtils {
    pub fn clean_up_existing_container(name: &str) {
        let mut command = Command::new("docker", Command::strings(vec!["rm", name]));
        command.wait_for_exit(); // success, failure, don't care
    }

    pub fn find_project_root() -> String {
        let path_buf = Self::start_from(Path::new(&env::var("PWD").unwrap()));
        path_buf.as_path().to_str().unwrap().to_string()
    }

    pub fn stop(name: &str) {
        let mut command = Command::new("docker", Command::strings(vec!["stop", "-t", "0", name]));
        command.stdout_or_stderr().unwrap();
    }

    pub fn socket_addr(
        node_addr: &NodeAddr,
        port_selector: PortSelector,
        name: &str,
    ) -> SocketAddr {
        let port_list = node_addr.ports();
        if port_list.is_empty() {
            panic!("{} has no clandestine ports; can't make SocketAddr", name)
        }
        let idx = match port_selector {
            PortSelector::First => 0,
            PortSelector::Last => port_list.len() - 1,
            PortSelector::Index(i) => i,
        };
        SocketAddr::new(node_addr.ip_addr(), port_list[idx])
    }

    pub fn wrote_log_containing(name: &str, pattern: &str, timeout: Duration) {
        let time_limit = Instant::now() + timeout;
        let mut entire_log = String::new();
        while Instant::now() < time_limit {
            entire_log = MASQNodeUtils::retrieve_logs(name);
            let regex = Regex::new(pattern).unwrap();
            if regex.is_match(&entire_log) {
                return;
            } else {
                thread::sleep(Duration::from_millis(250))
            }
        }
        panic!(
            "After {:?}, this pattern\n\n{}\n\ndid not match anything in this log:\n\n{}",
            timeout, pattern, entire_log
        );
    }

    pub fn retrieve_logs(name: &str) -> String {
        let mut command = Command::new(
            "docker",
            Command::strings(vec![
                "exec",
                "-t",
                name,
                "cat",
                &format!("/node_root/home/{}", CURRENT_LOGFILE_NAME),
            ]),
        );
        command.stdout_and_stderr()
    }

    fn start_from(start: &Path) -> PathBuf {
        if fs::read_dir(start)
            .unwrap()
            .filter(|entry| {
                let file_name = match entry {
                    Ok(dir_entry) => dir_entry.file_name(),
                    Err(e) => panic!("Should never happen: {}", e),
                };
                file_name == OsStr::new("multinode_integration_tests")
                    || file_name == OsStr::new("node")
            })
            .count()
            == 2
        {
            PathBuf::from(start)
        } else {
            Self::start_from(start.parent().unwrap())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cut_off_label_happy_path() {
        let key_including_label = "dev.AQIDBAUGBwg";

        let (label, key_part) =
            NodeReference::extract_label_and_encoded_public_key(key_including_label).unwrap();

        assert_eq!(label, "dev");
        assert_eq!(key_part, "AQIDBAUGBwg");
    }

    #[test]
    fn cut_off_label_sad_path() {
        let key_including_label = "devAQIDBAUGBwg";

        let result = NodeReference::extract_label_and_encoded_public_key(key_including_label);

        assert_eq!(
            result,
            Err(
                "The chain label in the descriptor isn't properly set: 'devAQIDBAUGBwg'"
                    .to_string()
            )
        )
    }

    #[test]
    fn node_reference_from_string_fails_if_there_are_not_three_fields() {
        let string = String::from("Only two:fields");

        let result = NodeReference::from_str(string.as_str());

        assert_eq! (result, Err (String::from ("A NodeReference must have the form <chain label>.<public_key>:<IP address>:<port list>, not 'Only two:fields'")));
    }

    #[test]
    fn node_reference_from_string_fails_if_key_is_not_valid_base64() {
        let string = String::from("dev.;;;:12.34.56.78:1234,2345");

        let result = NodeReference::from_str(string.as_str());

        assert_eq! (result, Err (String::from ("The public key of a NodeReference must be represented as a valid Base64 string, not ';;;'")));
    }

    #[test]
    fn node_reference_from_string_fails_if_ip_address_is_not_valid() {
        let key = PublicKey::new(&b"Booga"[..]);
        let string = format!("dev.{}:blippy:1234,2345", key);

        let result = NodeReference::from_str(string.as_str());

        assert_eq!(
            result,
            Err(String::from(
                "The IP address of a NodeReference must be valid, not 'blippy'"
            ))
        );
    }

    #[test]
    fn node_reference_from_string_fails_if_a_port_number_is_not_valid() {
        let key = PublicKey::new(&b"Booga"[..]);
        let string = format!("dev.{}:12.34.56.78:weeble,frud", key);

        let result = NodeReference::from_str(string.as_str());

        assert_eq! (result, Err (String::from ("The port list must be a comma-separated sequence of valid numbers, not 'weeble,frud'")));
    }

    #[test]
    fn node_reference_from_string_fails_if_a_port_number_is_too_big() {
        let key = PublicKey::new(&b"Booga"[..]);
        let string = format!("dev.{}:12.34.56.78:1234,65536", key);

        let result = NodeReference::from_str(string.as_str());

        assert_eq!(
            result,
            Err(String::from(
                "Each port number must be 65535 or less, not '65536'"
            ))
        );
    }

    #[test]
    fn node_reference_from_string_happy() {
        let key = PublicKey::new(&b"Booga"[..]);
        let string = format!("dev.{}:12.34.56.78:1234,2345", key);

        let result = NodeReference::from_str(string.as_str()).unwrap();

        assert_eq!(result.public_key, key);
        assert_eq!(
            result.node_addr_opt,
            Some(NodeAddr::new(
                &IpAddr::from_str("12.34.56.78").unwrap(),
                &[1234, 2345]
            ))
        );
    }

    #[test]
    fn node_reference_from_string_works_if_there_are_no_ports() {
        let key = PublicKey::new(&b"Booga"[..]);
        let string = format!("dev.{}:12.34.56.78:", key);

        let result = NodeReference::from_str(string.as_str()).unwrap();

        assert_eq!(result.public_key, key);
        assert_eq!(
            result.node_addr_opt,
            Some(NodeAddr::new(
                &IpAddr::from_str("12.34.56.78").unwrap(),
                &[]
            ))
        );
    }

    #[test]
    fn node_reference_can_display_itself() {
        let chain_id = 4;
        let subject = NodeReference::new(
            PublicKey::new(&b"Booga"[..]),
            Some(IpAddr::from_str("12.34.56.78").unwrap()),
            vec![1234, 5678],
            chain_id,
        );

        let result = format!("{}", subject);

        assert_eq!(
            result,
            String::from("masq://dev.Qm9vZ2E:12.34.56.78:1234,5678")
        );
    }
}
