// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use std::net::IpAddr;
use std::net::SocketAddr;
use std::str::FromStr;
use base64;
use substratum_client::SubstratumNodeClient;
use sub_lib::cryptde::Key;
use command::Command;

pub struct NodeStartupConfig {
    port_numbers: Vec<u16>,
    neighborhood_config: Vec<NeighborConfig>
}

pub struct NeighborConfig {
    public_key: Key,
    ip: IpAddr,
    ports: Vec<u16>,
}

impl NeighborConfig {
   pub fn new(public_key: Key, ip: IpAddr, ports: Vec<u16>) -> NeighborConfig {
       NeighborConfig {
           public_key,
           ip,
           ports,
       }
   }
}

impl NodeStartupConfig {
    pub fn new (port_numbers: Vec<u16>, neighborhood_config: Vec<NeighborConfig>) -> NodeStartupConfig {
        NodeStartupConfig {
            port_numbers,
            neighborhood_config
        }
    }

    pub fn get_port_numbers (&self) -> &Vec<u16> {
        &self.port_numbers
    }

    pub fn as_command_line_parameter<'a> (&'a self) -> String {
        let args = NodeStartupConfig::join(&self.port_numbers, ",");

        if self.neighborhood_config.is_empty() {
            args
        } else {
            self.neighborhood_config.iter().fold(args, |new_args, config| {
                format!("{} --neighbor {}:{}:{}", new_args, base64::encode(&config.public_key.data), config.ip, NodeStartupConfig::join(&config.ports, ","))
            })
        }
    }

    fn join(strings: &Vec<u16>, joiner: &str) -> String {
        strings.iter().fold(String::new(), |acc, val| {
            if acc.is_empty() {
                format!("{}", val)
            } else {
                format!("{}{}{}", acc, joiner, val)
            }
        })
    }
}

pub struct SubstratumNode {
    startup_config: NodeStartupConfig,
    name: String,
    ip_address: IpAddr,
    public_key: Key,
}

impl SubstratumNode {
    pub fn new (startup_config: NodeStartupConfig, index: usize) -> SubstratumNode {
        let name = format! ("test_node_{}", index);

        SubstratumNode {
            startup_config,
            name: name.clone(),
            ip_address: IpAddr::from_str (&format! ("172.18.1.{}", index)).unwrap (),
            public_key: SubstratumNode::public_key_from_docker(&name),
        }
    }

    pub fn get_name (&self) -> &str {
        &self.name
    }

    pub fn get_ip_address (&self) -> IpAddr {
        self.ip_address
    }

    pub fn get_startup_config (&self) -> &NodeStartupConfig {
        &self.startup_config
    }

    pub fn get_public_key(&self) -> Key {
        self.public_key.clone()
    }

    pub fn make_client (&self, port: u16) -> SubstratumNodeClient {
        let socket_addr = SocketAddr::new(self.ip_address, port);
        SubstratumNodeClient::new(socket_addr)
    }

    fn public_key_from_docker(node_name: &str) -> Key {
        let parameters = vec!("logs", node_name);
        let script_name = "docker";
        let mut command = Command::new(script_name, parameters.clone());
        let exit_code = command.wait_for_exit();
        if exit_code != 0 {
            panic!("{}: Script failed:\n{} {:?}\n{}", exit_code, script_name, parameters, command.stderr_as_string())
        }

        let stdout = command.stdout_as_string();
        let mut output_lines = stdout.lines();
        output_lines.next();
        let public_key_line = output_lines.next();
        match public_key_line {
            Some(key) => Key::new(&base64::decode(&key.replace("Substratum Node public key: ", "").as_bytes()[..]).unwrap()),
            None => panic!("no public key found for node {}", node_name)
        }
    }
}

#[cfg (test)]
mod tests {
    use super::*;

    #[test]
    fn node_startup_config_stringification () {
        let subject = NodeStartupConfig::new (vec! (1234, 2345, 3456), vec!());

        let result = subject.as_command_line_parameter();

        assert_eq! (result, "1234,2345,3456");
    }

    #[test]
    fn node_startup_config_may_include_neighbors() {
        let key = Key::new(b"my secret key");
        let neighbor = NeighborConfig {
            public_key: key.clone(),
            ip: IpAddr::from_str("127.0.0.1").unwrap(),
            ports: vec!(123, 345)
        };

        let subject = NodeStartupConfig::new(vec!(1234), vec!(neighbor));

        let result = subject.as_command_line_parameter();
        assert_eq!(result, format!("1234 --neighbor {}:127.0.0.1:123,345", base64::encode(&key.data)))
    }
}