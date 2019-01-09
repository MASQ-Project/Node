// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use base64;
use base64::STANDARD_NO_PAD;
use command::Command;
use std::any::Any;
use std::env;
use std::ffi::OsStr;
use std::fmt;
use std::fs;
use std::fs::DirEntry;
use std::io;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::path::Path;
use std::path::PathBuf;
use std::str::FromStr;
use std::thread;
use std::time::Duration;
use std::time::Instant;
use sub_lib::cryptde::Key;
use sub_lib::node_addr::NodeAddr;
use substratum_client::SubstratumNodeClient;

#[derive(PartialEq, Clone, Debug)]
pub struct NodeReference {
    pub public_key: Key,
    pub node_addr: NodeAddr,
}

impl FromStr for NodeReference {
    type Err = String;

    fn from_str(string_rep: &str) -> Result<Self, <Self as FromStr>::Err> {
        let pieces: Vec<&str> = string_rep.split(":").collect();
        if pieces.len() != 3 {
            return Err(format!("A NodeReference must have the form <public_key>:<IP address>:<port list>, not '{}'", string_rep));
        }
        let public_key = Self::extract_public_key(pieces[0])?;
        let ip_addr = Self::extract_ip_addr(pieces[1])?;
        let port_list = Self::extract_port_list(pieces[2])?;
        Ok(NodeReference::new(public_key, ip_addr, port_list))
    }
}

impl fmt::Display for NodeReference {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let public_key_string = base64::encode_config(&self.public_key.data, STANDARD_NO_PAD);
        let ip_addr_string = format!("{}", self.node_addr.ip_addr());
        let port_list_string = self
            .node_addr
            .ports()
            .iter()
            .map(|port| port.to_string())
            .collect::<Vec<String>>()
            .join(",");
        write!(
            f,
            "{}:{}:{}",
            public_key_string, ip_addr_string, port_list_string
        )
        .unwrap();
        Ok(())
    }
}

impl NodeReference {
    pub fn new(public_key: Key, ip_addr: IpAddr, ports: Vec<u16>) -> NodeReference {
        NodeReference {
            public_key,
            node_addr: NodeAddr::new(&ip_addr, &ports),
        }
    }

    fn extract_public_key(slice: &str) -> Result<Key, String> {
        match base64::decode(slice) {
            Ok (data) => Ok (Key::new (&data[..])),
            Err (_) => return Err (format!("The public key of a NodeReference must be represented as a valid Base64 string, not '{}'", slice))
        }
    }

    fn extract_ip_addr(slice: &str) -> Result<IpAddr, String> {
        match IpAddr::from_str(slice) {
            Ok(ip_addr) => Ok(ip_addr),
            Err(_) => {
                return Err(format!(
                    "The IP address of a NodeReference must be valid, not '{}'",
                    slice
                ))
            }
        }
    }

    fn extract_port_list(slice: &str) -> Result<Vec<u16>, String> {
        let port_list_numbers: Vec<i64> = if slice.is_empty() {
            vec![]
        } else {
            String::from(slice)
                .split(",")
                .map(|x| match x.parse::<i64>() {
                    Ok(n) => n,
                    Err(_) => -1,
                })
                .collect()
        };
        if port_list_numbers.contains(&-1) {
            return Err(format!(
                "The port list must be a comma-separated sequence of valid numbers, not '{}'",
                slice
            ));
        }
        match port_list_numbers.iter().find(|x| x > &&65535) {
            Some(x) => {
                return Err(format!(
                    "Each port number must be 65535 or less, not '{}'",
                    x
                ))
            }
            None => (),
        }
        Ok(port_list_numbers.into_iter().map(|x| x as u16).collect())
    }
}

pub enum PortSelector {
    First,
    Last,
    Index(usize),
}

pub trait SubstratumNode: Any {
    fn name(&self) -> &str;
    // This is the NodeReference stated by the Node in the console. Its IP address won't be accurate if it's a zero-hop Node.
    fn node_reference(&self) -> NodeReference;
    fn public_key(&self) -> Key;
    // This is the IP address of the container in which the Node is running.
    fn ip_address(&self) -> IpAddr;
    fn port_list(&self) -> Vec<u16>;
    // This contains the IP address of the container in which the Node is running.
    fn node_addr(&self) -> NodeAddr;
    // This contains the IP address of the container in which the Node is running.
    fn socket_addr(&self, port_selector: PortSelector) -> SocketAddr;
    fn make_client(&self, port: u16) -> SubstratumNodeClient;
}

pub struct SubstratumNodeUtils {}

impl SubstratumNodeUtils {
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

    pub fn wrote_log_containing(name: &str, substring: &str, timeout: Duration) {
        let time_limit = Instant::now() + timeout;
        let mut entire_log = String::new();
        while Instant::now() < time_limit {
            entire_log = SubstratumNodeUtils::retrieve_logs(name);
            if entire_log.contains(substring) {
                return;
            } else {
                thread::sleep(Duration::from_millis(250))
            }
        }
        panic!(
            "After {:?}, this substring\n\n{}\n\ndid not appear in this log:\n\n{}",
            timeout, substring, entire_log
        );
    }

    fn start_from(start: &Path) -> PathBuf {
        let recognized: Vec<Result<DirEntry, io::Error>> = fs::read_dir(start)
            .unwrap()
            .filter(|entry| {
                let file_name = match entry {
                    Ok(dir_entry) => dir_entry.file_name(),
                    Err(e) => panic!("Should never happen: {}", e),
                };
                file_name == OsStr::new("multinode_integration_tests")
                    || file_name == OsStr::new("node")
            })
            .collect();
        if recognized.len() == 2 {
            PathBuf::from(start)
        } else {
            Self::start_from(start.parent().unwrap())
        }
    }

    fn retrieve_logs(name: &str) -> String {
        let mut command = Command::new("docker", Command::strings(vec!["logs", name]));
        command.stdout_and_stderr()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_reference_from_string_fails_if_there_are_not_three_fields() {
        let string = String::from("Only two:fields");

        let result = NodeReference::from_str(string.as_str());

        assert_eq! (result, Err (String::from ("A NodeReference must have the form <public_key>:<IP address>:<port list>, not 'Only two:fields'")));
    }

    #[test]
    fn node_reference_from_string_fails_if_key_is_not_valid_base64() {
        let string = String::from(";;;:12.34.56.78:1234,2345");

        let result = NodeReference::from_str(string.as_str());

        assert_eq! (result, Err (String::from ("The public key of a NodeReference must be represented as a valid Base64 string, not ';;;'")));
    }

    #[test]
    fn node_reference_from_string_fails_if_ip_address_is_not_valid() {
        let key = Key::new(&b"Booga"[..]);
        let string = format!("{}:blippy:1234,2345", key);

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
        let key = Key::new(&b"Booga"[..]);
        let string = format!("{}:12.34.56.78:weeble,frud", key);

        let result = NodeReference::from_str(string.as_str());

        assert_eq! (result, Err (String::from ("The port list must be a comma-separated sequence of valid numbers, not 'weeble,frud'")));
    }

    #[test]
    fn node_reference_from_string_fails_if_a_port_number_is_too_big() {
        let key = Key::new(&b"Booga"[..]);
        let string = format!("{}:12.34.56.78:1234,65536", key);

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
        let key = Key::new(&b"Booga"[..]);
        let string = format!("{}:12.34.56.78:1234,2345", key);

        let result = NodeReference::from_str(string.as_str()).unwrap();

        assert_eq!(result.public_key, key);
        assert_eq!(
            result.node_addr,
            NodeAddr::new(&IpAddr::from_str("12.34.56.78").unwrap(), &vec!(1234, 2345))
        );
    }

    #[test]
    fn node_reference_from_string_works_if_there_are_no_ports() {
        let key = Key::new(&b"Booga"[..]);
        let string = format!("{}:12.34.56.78:", key);

        let result = NodeReference::from_str(string.as_str()).unwrap();

        assert_eq!(result.public_key, key);
        assert_eq!(
            result.node_addr,
            NodeAddr::new(&IpAddr::from_str("12.34.56.78").unwrap(), &vec!())
        );
    }

    #[test]
    fn node_reference_can_display_itself() {
        let subject = NodeReference::new(
            Key::new(&b"Booga"[..]),
            IpAddr::from_str("12.34.56.78").unwrap(),
            vec![1234, 5678],
        );

        let result = format!("{}", subject);

        assert_eq!(result, String::from("Qm9vZ2E:12.34.56.78:1234,5678"));
    }
}
