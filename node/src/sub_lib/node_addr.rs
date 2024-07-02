// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
use masq_lib::constants::{HIGHEST_USABLE_PORT, LOWEST_USABLE_INSECURE_PORT};
use masq_lib::utils::plus;
use serde_derive::{Deserialize, Serialize};
use std::fmt;
use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;
use std::net::SocketAddr;
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;

#[derive(PartialEq, Eq, Hash, Deserialize, Serialize)]
pub struct NodeAddr {
    pub(crate) ip_addr: IpAddr,
    ports: Vec<u16>,
}

impl NodeAddr {
    pub const PORTS_SEPARATOR: &'static str = "/";

    pub fn new(ip_addr: &IpAddr, ports: &[u16]) -> NodeAddr {
        let mut ports = ports.to_owned();
        ports.sort_unstable();
        ports.dedup();

        NodeAddr {
            ip_addr: *ip_addr,
            ports,
        }
    }

    pub fn ip_addr(&self) -> IpAddr {
        self.ip_addr
    }

    pub fn ports(&self) -> Vec<u16> {
        self.ports.clone()
    }
}

impl Default for NodeAddr {
    fn default() -> Self {
        NodeAddr::new(&IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), &[])
    }
}

impl<'a> From<&'a SocketAddr> for NodeAddr {
    fn from(socket_addr: &'a SocketAddr) -> Self {
        NodeAddr::new(&socket_addr.ip(), &[socket_addr.port()])
    }
}

impl From<NodeAddr> for SocketAddr {
    fn from(node_addr: NodeAddr) -> Self {
        let all: Vec<SocketAddr> = node_addr.into();
        all[0]
    }
}

impl From<NodeAddr> for Vec<SocketAddr> {
    fn from(node_addr: NodeAddr) -> Self {
        node_addr
            .ports()
            .iter()
            .map(|port| SocketAddr::new(node_addr.ip_addr(), *port))
            .collect()
    }
}

impl Clone for NodeAddr {
    fn clone(&self) -> Self {
        NodeAddr::new(&self.ip_addr(), &self.ports())
    }
}

impl Debug for NodeAddr {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{:?}", self.ip_addr(), self.ports())
    }
}

impl Display for NodeAddr {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let port_list = self
            .ports
            .iter()
            .map(|x| format!("{}", x))
            .collect::<Vec<String>>();
        write!(
            f,
            "{}:{}",
            self.ip_addr(),
            port_list.join(Self::PORTS_SEPARATOR)
        )
    }
}

impl FromStr for NodeAddr {
    type Err = String;

    fn from_str(input: &str) -> Result<NodeAddr, String> {
        let pieces: Vec<&str> = input.split(':').collect();
        if pieces.len() != 2 || pieces[0].is_empty() {
            return Err(format!(
                "NodeAddr should be expressed as '<IP address>:<port>/<port>/...', not '{}'",
                input
            ));
        }
        let ip_addr = match IpAddr::from_str(pieces[0]) {
            Err(_) => {
                return Err(format!(
                    "NodeAddr must have a valid IP address, not '{}'",
                    pieces[0]
                ));
            }
            Ok(ip_addr) => ip_addr,
        };
        let ports: Vec<u16> = match pieces[1]
            .split(Self::PORTS_SEPARATOR)
            .map(|s| match s.parse::<u16>() {
                Err(_) => Err(format!(
                    "NodeAddr must have port numbers between {} and {}, not '{}'",
                    LOWEST_USABLE_INSECURE_PORT, HIGHEST_USABLE_PORT, s
                )),
                Ok(port) if port < LOWEST_USABLE_INSECURE_PORT => Err(format!(
                    "NodeAddr must have port numbers between {} and {}, not '{}'",
                    LOWEST_USABLE_INSECURE_PORT, HIGHEST_USABLE_PORT, s
                )),
                Ok(port) => Ok(port),
            })
            .fold(Ok(vec![]), |so_far, parse_result| {
                match (so_far, parse_result) {
                    (Err(e), _) => Err(e),
                    (Ok(_), Err(e)) => Err(e),
                    (Ok(ports), Ok(port)) => Ok(plus(ports, port)),
                }
            }) {
            Ok(ports) => ports,
            Err(msg) => return Err(msg),
        };
        Ok(NodeAddr::new(&ip_addr, &ports))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn constants_have_correct_values() {
        assert_eq!(NodeAddr::PORTS_SEPARATOR, "/");
    }

    #[test]
    fn can_create_from_socket_addr() {
        let subject = NodeAddr::from(&SocketAddr::from_str("9.8.7.6:543").unwrap());

        assert_eq!(subject.ip_addr(), IpAddr::from_str("9.8.7.6").unwrap());
        assert_eq!(subject.ports(), vec![543]);
    }

    #[test]
    fn can_convert_to_vector_of_socket_addrs() {
        let ip_addr = IpAddr::from_str("2.5.8.1").unwrap();
        let ports = vec![9, 6];
        let subject = NodeAddr::new(&ip_addr, &ports);

        let result: Vec<SocketAddr> = subject.into();

        assert_eq!(
            result,
            vec!(
                SocketAddr::from_str("2.5.8.1:6").unwrap(),
                SocketAddr::from_str("2.5.8.1:9").unwrap()
            )
        );
    }

    #[test]
    fn can_clone_node_addr() {
        let ip_addr = IpAddr::from_str("2.5.8.1").unwrap();
        let ports = vec![9, 6];
        let subject = NodeAddr::new(&ip_addr, &ports);

        let result = subject.clone();

        assert_eq!(result.ip_addr(), ip_addr);
        assert_eq!(result.ports(), vec![6, 9]);
    }

    #[test]
    fn node_addrs_can_be_compared() {
        let a = NodeAddr::new(&IpAddr::from_str("1.2.3.4").unwrap(), &[5, 6]);
        let b = NodeAddr::new(&IpAddr::from_str("1.2.3.4").unwrap(), &[5, 6]);
        let c = NodeAddr::new(&IpAddr::from_str("1.2.3.4").unwrap(), &[6, 5]);
        let d = NodeAddr::new(&IpAddr::from_str("1.2.3.5").unwrap(), &[5, 6]);
        let e = NodeAddr::new(&IpAddr::from_str("1.2.3.4").unwrap(), &[9]);
        let f = NodeAddr::new(&IpAddr::from_str("1.2.3.4").unwrap(), &[5, 6, 5]);

        assert_eq!(a.eq(&a), true);
        assert_eq!(a.eq(&b), true);
        assert_eq!(a.eq(&c), true);
        assert_eq!(a.eq(&d), false);
        assert_eq!(a.eq(&e), false);
        assert_eq!(a.eq(&f), true);
    }

    #[test]
    fn node_addrs_produces_debug_string() {
        let ip_addr = IpAddr::from_str("2.5.8.1").unwrap();
        let ports = vec![9, 6];
        let subject = NodeAddr::new(&ip_addr, &ports);

        let result = format!("{:?}", subject);

        assert_eq!(result, "2.5.8.1:[6, 9]");
    }

    #[test]
    fn node_addrs_produces_display_string() {
        let ip_addr = IpAddr::from_str("2.5.8.1").unwrap();
        let ports = vec![9, 6];
        let subject = NodeAddr::new(&ip_addr, &ports);

        let result = format!("{}", subject);

        assert_eq!(result, "2.5.8.1:6/9");
    }

    #[test]
    fn node_addrs_from_str_needs_two_pieces() {
        let result = NodeAddr::from_str("Booga");

        assert_eq!(
            result,
            Err(String::from(
                "NodeAddr should be expressed as '<IP address>:<port>/<port>/...', not 'Booga'"
            ))
        );
    }

    #[test]
    fn node_addrs_from_str_complains_about_confusing_situation_with_a_starting_colon_and_no_ports()
    {
        let result = NodeAddr::from_str(":192.45.35.8");

        assert_eq!(
            result,
            Err(String::from(
                "NodeAddr should be expressed as '<IP address>:<port>/<port>/...', not ':192.45.35.8'"
            ))
        );
    }

    #[test]
    fn node_addrs_from_str_needs_good_ip_address() {
        let result = NodeAddr::from_str("253.254.255.256:1234/2345/3456");

        assert_eq!(
            result,
            Err(String::from(
                "NodeAddr must have a valid IP address, not '253.254.255.256'"
            ))
        );
    }

    #[test]
    fn node_addrs_from_str_complains_about_low_port_number() {
        let result = NodeAddr::from_str("1.2.3.4:1023");

        assert_eq!(
            result,
            Err(String::from(
                "NodeAddr must have port numbers between 1025 and 65535, not '1023'"
            ))
        );
    }

    #[test]
    fn node_addrs_from_str_complains_about_high_port_number() {
        let result = NodeAddr::from_str("1.2.3.4:65536");

        assert_eq!(
            result,
            Err(String::from(
                "NodeAddr must have port numbers between 1025 and 65535, not '65536'"
            ))
        );
    }

    #[test]
    fn node_addrs_from_str_follows_the_happy_path() {
        let result = NodeAddr::from_str("1.2.3.4:1234/2345/3456");

        assert_eq!(
            result,
            Ok(NodeAddr::new(
                &IpAddr::from_str("1.2.3.4").unwrap(),
                &[1234, 2345, 3456]
            ))
        );
    }
}
