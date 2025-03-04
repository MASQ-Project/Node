// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
use crate::command::Command;
use base64::URL_SAFE_NO_PAD;
use masq_lib::blockchains::chains::Chain;
use masq_lib::constants::{
    CENTRAL_DELIMITER, CHAIN_IDENTIFIER_DELIMITER, CURRENT_LOGFILE_NAME, HIGHEST_USABLE_PORT,
    MASQ_URL_PREFIX,
};
use masq_lib::utils::to_string;
use node_lib::sub_lib::cryptde::{CryptDE, PublicKey};
use node_lib::sub_lib::cryptde_null::CryptDENull;
use node_lib::sub_lib::neighborhood::{NodeDescriptor, RatePack};
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
use node_lib::neighborhood::node_location::get_node_location;

#[derive(PartialEq, Eq, Clone, Debug)]
pub struct NodeReference {
    pub public_key: PublicKey,
    pub node_addr_opt: Option<NodeAddr>,
    pub chain: Chain,
}

impl FromStr for NodeReference {
    type Err = String;

    fn from_str(node_ref_str: &str) -> Result<Self, <Self as FromStr>::Err> {
        let (chain, key, tail) = NodeDescriptor::parse_url(node_ref_str)?;
        let public_key = Self::extract_public_key(key)?;
        let (ip_addr_str, ports) = strip_ports(tail);
        let ip_addr = Self::extract_ip_addr(ip_addr_str.as_str())?;
        let port_list = Self::extract_port_list(ports.as_str())?;
        Ok(NodeReference::new(public_key, ip_addr, port_list, chain))
    }
}

fn strip_ports(tail_half: &str) -> (String, String) {
    let idx_opt = tail_half.chars().rev().position(|char| char == ':');
    if let Some(idx) = idx_opt {
        let lenght = tail_half.len();
        let reversed_idx = lenght - idx;
        (
            tail_half[..reversed_idx - 1].to_string(),
            tail_half[reversed_idx..].to_string(),
        )
    } else {
        (tail_half.to_string(), String::new())
    }
}

impl From<&dyn MASQNode> for NodeReference {
    fn from(masq_node: &dyn MASQNode) -> Self {
        NodeReference {
            public_key: masq_node.main_public_key().clone(),
            node_addr_opt: Some(masq_node.node_addr()),
            chain: masq_node.chain(),
        }
    }
}

impl fmt::Display for NodeReference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let public_key_string = base64::encode_config(&self.public_key.as_slice(), URL_SAFE_NO_PAD);
        let ip_addr_string = match &self.node_addr_opt {
            Some(node_addr) => format!("{}", node_addr.ip_addr()),
            None => String::new(),
        };
        let port_list_string = match &self.node_addr_opt {
            Some(node_addr) => node_addr
                .ports()
                .iter()
                .map(to_string)
                .collect::<Vec<String>>()
                .join(NodeAddr::PORTS_SEPARATOR),
            None => String::new(),
        };
        write!(
            f,
            "{}{}{}{}{}{}:{}",
            MASQ_URL_PREFIX,
            self.chain.rec().literal_identifier,
            CHAIN_IDENTIFIER_DELIMITER,
            public_key_string,
            CENTRAL_DELIMITER,
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
        chain: Chain,
    ) -> NodeReference {
        match ip_addr_opt {
            Some(ip_addr) => NodeReference {
                public_key,
                node_addr_opt: Some(NodeAddr::new(&ip_addr, &ports)),
                chain,
            },
            None => NodeReference {
                public_key,
                node_addr_opt: None,
                chain,
            },
        }
    }

    fn extract_public_key(slice: &str) -> Result<PublicKey, String> {
        match base64::decode_config(slice,URL_SAFE_NO_PAD) {
            Ok (data) => Ok (PublicKey::new (&data[..])),
            Err (_) => Err (format!("The public key of a NodeReference must be represented as a valid Base64 string, not '{}'", slice))
        }
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
                .split(NodeAddr::PORTS_SEPARATOR)
                .map(|x| x.parse::<i64>().unwrap_or(-1))
                .collect()
        };
        if port_list_numbers.contains(&-1) {
            return Err(format!(
                "The port list must be a sequence of valid numbers separated by slashes, not '{}'",
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
    // This is the name of the Docker container on which this MASQNode will run.
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
    // A reference to this MASQNode's alias public key.
    fn alias_public_key(&self) -> &PublicKey;
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
    fn chain(&self) -> Chain;
    fn accepts_connections(&self) -> bool;
    fn routes_data(&self) -> bool;
    fn country_code_opt(&self) -> Option<String>;
}

pub struct MASQNodeUtils {}

impl MASQNodeUtils {
    pub fn clean_up_existing_container(name: &str) {
        let mut command = Command::new("docker", Command::strings(vec!["stop", "-t", "0", name]));
        command.stdout_and_stderr(); // success, failure, don't care
        let mut command = Command::new("docker", Command::strings(vec!["rm", "-f", name]));
        command.stdout_and_stderr(); // success, failure, don't care
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

    pub fn assert_node_wrote_log_containing(name: &str, pattern: &str, timeout: Duration) {
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
    
    pub fn derive_country_code_opt(node_addr: &NodeAddr) -> Option<String> {
        let country_code = get_node_location(Some(node_addr.ip_addr()));
        if let Some(cc) = country_code {
            Some(cc.country_code)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{decode_config, STANDARD_NO_PAD};
    use masq_lib::test_utils::utils::TEST_DEFAULT_MULTINODE_CHAIN;

    #[test]
    fn strip_ports_works_single_port() {
        let tail = "1.2.3.4:4444";

        let result = strip_ports(tail);

        assert_eq!(result, ("1.2.3.4".to_string(), "4444".to_string()))
    }

    #[test]
    fn strip_ports_works_multiple_ports() {
        let tail = "4.3.2.9:4444/1212/11133";

        let result = strip_ports(tail);

        assert_eq!(
            result,
            ("4.3.2.9".to_string(), "4444/1212/11133".to_string())
        )
    }

    #[test]
    fn node_reference_from_str_fails_if_there_are_not_two_fields_to_divide_to() {
        let string = String::from("masq://two@fields@nope");

        let result = NodeReference::from_str(string.as_str());

        assert_eq! (result, Err (String::from ("Either '@' delimiter position or format of node address is wrong. Should be 'masq://<chain identifier>:<public key>@<node address>', not 'masq://two@fields@nope'\nNodeAddr should be expressed as '<IP address>:<port>/<port>/...', probably not as 'fields@nope'")));
    }

    #[test]
    fn node_reference_from_str_fails_if_key_is_not_valid_base64() {
        let string = String::from("masq://dev:;;;@12.34.56.78:1234/2345");

        let result = NodeReference::from_str(string.as_str());

        assert_eq! (result, Err (String::from ("The public key of a NodeReference must be represented as a valid Base64 string, not ';;;'")));
    }

    #[test]
    fn node_reference_from_str_fails_if_ip_address_is_not_valid() {
        let key = PublicKey::new(&b"Booga"[..]);
        let string = format!("masq://dev:{}@blippy:1234/2345", key);

        let result = NodeReference::from_str(string.as_str());

        assert_eq!(
            result,
            Err(String::from(
                "Either '@' delimiter position or format of node address is wrong. Should be 'masq://<chain identifier>:<public key>@<node address>', not 'masq://dev:Qm9vZ2E@blippy:1234/2345'\nNodeAddr should be expressed as '<IP address>:<port>/<port>/...', probably not as 'blippy:1234/2345'"
            ))
        );
    }

    #[test]
    fn node_reference_from_str_fails_if_a_port_number_is_not_valid() {
        let key = PublicKey::new(&b"Booga"[..]);
        let string = format!("masq://dev:{}@12.34.56.78:weeble/frud", key);

        let result = NodeReference::from_str(string.as_str());

        assert_eq! (result, Err (String::from("Either '@' delimiter position or format of node address is wrong. Should be 'masq://<chain identifier>:<public key>@<node address>', not 'masq://dev:Qm9vZ2E@12.34.56.78:weeble/frud'\nNodeAddr should be expressed as '<IP address>:<port>/<port>/...', probably not as '12.34.56.78:weeble/frud'")));
    }

    #[test]
    fn node_reference_from_str_fails_if_a_port_number_is_too_big() {
        let key = PublicKey::new(&b"Booga"[..]);
        let string = format!("masq://dev:{}@12.34.56.78:1234/65536", key);

        let result = NodeReference::from_str(string.as_str());

        assert_eq!(
            result,
            Err(String::from(
                "Each port number must be 65535 or less, not '65536'"
            ))
        );
    }

    #[test]
    fn node_reference_from_str_happy_path() {
        let key = PublicKey::new(&b"Booga"[..]);
        let string = format!("masq://dev:{}@12.34.56.78:1234/2345", key);

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
    fn node_reference_from_str_complains_about_slash_in_the_key() {
        let result = NodeReference::from_str(
            "masq://dev:abJ5XvhVbmVyGejkYUkmftF09pmGZGKg/PzRNnWQxFw@12.23.34.45:5678",
        );

        assert_eq!(
            result,
            Err(String::from(
                "The public key of a NodeReference must be represented as a valid Base64 string, not 'abJ5XvhVbmVyGejkYUkmftF09pmGZGKg/PzRNnWQxFw'"
            ))
        );
    }

    #[test]
    fn node_reference_from_str_complains_about_plus_in_the_key() {
        let result = NodeReference::from_str(
            "masq://dev:abJ5XvhVbmVy+GejkYUmftF09pmGZGKgkPzRNnWQxFw@12.23.34.45:5678",
        );

        assert_eq!(
            result,
            Err(String::from(
                "The public key of a NodeReference must be represented as a valid Base64 string, not 'abJ5XvhVbmVy+GejkYUmftF09pmGZGKgkPzRNnWQxFw'"
            ))
        );
    }

    #[test]
    fn node_reference_from_string_works_if_there_are_no_ports() {
        let key = PublicKey::new(&b"Booga"[..]);
        let string = format!("masq://dev:{}@12.34.56.78:", key);

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
        let chain = TEST_DEFAULT_MULTINODE_CHAIN;
        let subject = NodeReference::new(
            PublicKey::new(&b"Booga"[..]),
            Some(IpAddr::from_str("12.34.56.78").unwrap()),
            vec![1234, 5678],
            chain,
        );

        let result = format!("{}", subject);

        assert_eq!(
            result,
            String::from("masq://dev:Qm9vZ2E@12.34.56.78:1234/5678")
        );
    }

    #[test]
    fn display_works_with_base64_as_url_safe_no_pad() {
        let public_key_badly_encoded = "abJ5XvhVbmVy+GejkYUmftF/9pmGZGKgkPzRNnWQxFw";
        let decoded_key_bytes = decode_config(public_key_badly_encoded, STANDARD_NO_PAD).unwrap();
        let decoded_key = PublicKey::new(&decoded_key_bytes);
        let node_reference = NodeReference::new(decoded_key, None, vec![], Chain::Dev);

        let str_form = node_reference.to_string();

        assert!(str_form.contains("abJ5XvhVbmVy-GejkYUmftF_9pmGZGKgkPzRNnWQxFw"))
    }
}
