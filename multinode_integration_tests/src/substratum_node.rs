// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use std::net::IpAddr;
use std::net::SocketAddr;
use std::str::FromStr;
use substratum_client::SubstratumNodeClient;

pub struct NodeStartupConfig {
    port_numbers: Vec<u16>
}

impl NodeStartupConfig {
    pub fn new (port_numbers: Vec<u16>) -> NodeStartupConfig {
        NodeStartupConfig {
            port_numbers
        }
    }

    pub fn get_port_numbers (&self) -> &Vec<u16> {
        &self.port_numbers
    }

    pub fn as_command_line_parameter<'a> (&'a self) -> String {
        self.port_numbers.iter().fold(String::new (), |acc, val| {
            if acc.is_empty () {
                format! ("{}", val)
            }
            else {
                format! ("{},{}", acc, val)
            }
        })
    }
}

pub struct SubstratumNode {
    startup_config: NodeStartupConfig,
    name: String,
    ip_address: IpAddr,
}

impl SubstratumNode {
    pub fn new (startup_config: NodeStartupConfig, index: usize) -> SubstratumNode {
        SubstratumNode {
            startup_config,
            name: format! ("test_node_{}", index),
            ip_address: IpAddr::from_str (&format! ("172.18.1.{}", index)).unwrap (),
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

    pub fn make_client (&self, port: u16) -> SubstratumNodeClient {
        let socket_addr = SocketAddr::new(self.ip_address, port);
        SubstratumNodeClient::new(socket_addr)
    }
}

#[cfg (test)]
mod tests {
    use super::*;

    #[test]
    fn node_startup_config_stringification () {
        let subject = NodeStartupConfig::new (vec! (1234, 2345, 3456));

        let result = subject.as_command_line_parameter();

        assert_eq! (result, "1234,2345,3456");
    }
}