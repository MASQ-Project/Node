// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
#![cfg(target_os = "linux")]

use crate::comm_layer::pcp_pmp_common::FindRoutersCommand;
use crate::comm_layer::AutomapError;
use std::net::IpAddr;
use std::str::FromStr;

pub fn linux_find_routers(command: &dyn FindRoutersCommand) -> Result<Vec<IpAddr>, AutomapError> {
    let output = match command.execute() {
        Ok(stdout) => stdout,
        Err(stderr) => return Err(AutomapError::ProtocolError(stderr)),
    };
    let init: Result<Vec<IpAddr>, AutomapError> = Ok(vec![]);
    output
        .split('\n')
        .take_while(|line| line.trim_start().starts_with("default "))
        .fold(init, |acc, line| match acc {
            Ok(mut ip_addr_vec) => {
                let ip_str: String = line
                    .chars()
                    .skip_while(|char| !char.is_numeric())
                    .take_while(|char| !char.is_whitespace())
                    .collect();

                match IpAddr::from_str(&ip_str) {
                    Ok(ip_addr) => {
                        ip_addr_vec.push(ip_addr);
                        Ok(ip_addr_vec)
                    }
                    Err(e) => Err(AutomapError::FindRouterError(format!(
                        "Failed to parse an IP from \"ip route\": {:?} Line: {}",
                        e, line
                    ))),
                }
            }
            Err(e) => Err(e),
        })
}

pub struct LinuxFindRoutersCommand {}

impl FindRoutersCommand for LinuxFindRoutersCommand {
    fn execute(&self) -> Result<String, String> {
        self.execute_command("ip route")
    }
}

impl Default for LinuxFindRoutersCommand {
    fn default() -> Self {
        Self::new()
    }
}

impl LinuxFindRoutersCommand {
    pub fn new() -> Self {
        Self {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mocks::FindRoutersCommandMock;
    use regex::Regex;
    use std::str::FromStr;

    #[test]
    fn find_routers_works_when_there_is_a_router_to_find() {
        let ip_route_output = "\
        default via 192.168.0.1 dev enp4s0 proto dhcp src 192.168.0.100 metric 100\n\
        169.254.0.0/16 dev enp4s0 scope link metric 1000\n\
        172.17.0.0/16 dev docker0 proto kernel scope link src 172.17.0.1 linkdown\n\
        172.18.0.0/16 dev br-85f38f356a58 proto kernel scope link src 172.18.0.1 linkdown\n\
        192.168.0.0/24 dev enp4s0 proto kernel scope link src 192.168.0.100 metric 100";
        let find_routers_command = FindRoutersCommandMock::new(Ok(&ip_route_output));

        let result = linux_find_routers(&find_routers_command).unwrap();

        assert_eq!(result, vec![IpAddr::from_str("192.168.0.1").unwrap()])
    }

    #[test]
    fn find_routers_works_when_there_are_multiple_routers_to_find() {
        let ip_route_output = "\
        default via 192.168.0.1 dev enp0s8 proto dhcp metric 101\n\
        default via 192.168.0.2 dev enp0s3 proto dhcp metric 102\n\
        10.0.2.0/24 dev enp0s3 proto kernel scope link src 10.0.2.15 metric 102\n\
        169.254.0.0/16 dev enp0s3 scope link metric 1000\n\
        192.168.1.0/24 dev enp0s8 proto kernel scope link src 192.168.1.64 metric 101\n\
        192.168.1.1 via 10.0.2.15 dev enp0s3";
        let find_routers_command = FindRoutersCommandMock::new(Ok(&ip_route_output));

        let result = linux_find_routers(&find_routers_command).unwrap();

        assert_eq!(
            result,
            vec![
                IpAddr::from_str("192.168.0.1").unwrap(),
                IpAddr::from_str("192.168.0.2").unwrap()
            ]
        )
    }

    #[test]
    fn find_routers_supports_ip_address_of_ipv6() {
        let route_n_output = "\
        default via 2001:1:2:3:4:5:6:7 dev enX0 proto kernel metric 256 pref medium\n\
        fe80::/64 dev docker0 proto kernel metric 256 pref medium";

        let find_routers_command = FindRoutersCommandMock::new(Ok(&route_n_output));

        let result = linux_find_routers(&find_routers_command);

        assert_eq!(
            result,
            Ok(vec![IpAddr::from_str("2001:1:2:3:4:5:6:7").unwrap()])
        )
    }

    #[test]
    fn find_routers_works_when_there_is_no_router_to_find() {
        let route_n_output = "\
        10.1.0.0/16 dev eth0 proto kernel scope link src 10.1.0.84 metric 100\n\
        0.1.0.1 dev eth0 proto dhcp scope link src 10.1.0.84 metric 100\n\
        168.63.129.16 via 10.1.0.1 dev eth0 proto dhcp src 10.1.0.84 metric 100\n\
        169.254.169.254 via 10.1.0.1 dev eth0 proto dhcp src 10.1.0.84 metric 100\n\
        172.17.0.0/16 dev docker0 proto kernel scope link src 172.17.0.1 linkdown";
        let find_routers_command = FindRoutersCommandMock::new(Ok(&route_n_output));

        let result = linux_find_routers(&find_routers_command).unwrap();

        assert_eq!(result.is_empty(), true)
    }

    #[test]
    fn find_routers_works_when_command_writes_to_stderr() {
        let find_routers_command = FindRoutersCommandMock::new(Err("Booga!"));

        let result = linux_find_routers(&find_routers_command);

        assert_eq!(
            result,
            Err(AutomapError::ProtocolError("Booga!".to_string()))
        )
    }

    #[test]
    fn find_routers_returns_error_if_ip_addresses_can_not_be_parsed() {
        let route_n_output = "\
        default via 192.168.0.1 dev enp4s0 proto dhcp src 192.168.0.100 metric 100\n\
        default via 192.168.0 dev enp0s3 proto dhcp metric 102\n\
        169.254.0.0/16 dev enp4s0 scope link metric 1000";
        let find_routers_command = FindRoutersCommandMock::new(Ok(&route_n_output));

        let result = linux_find_routers(&find_routers_command);

        eprintln!("{:?}", result);

        assert_eq!(
            result,
            Err(AutomapError::FindRouterError(
                "Failed to parse an IP from \"ip route\": AddrParseError(Ip) Line: default via 192.168.0 dev enp0s3 proto dhcp metric 102".to_string()
            ))
        )
    }

    #[test]
    fn find_routers_command_produces_output_that_looks_right() {
        let subject = LinuxFindRoutersCommand::new();

        let result = subject.execute().unwrap();

        let mut lines = result.split('\n').collect::<Vec<&str>>();
        let len = lines.len();
        if lines[len - 1].is_empty() {
            lines.remove(len - 1);
        }
        let reg = ip_route_regex();
        lines.iter().for_each(|line| {
            assert!(reg.is_match(line), "Lines: {:?} line: {}", lines, line);
        });
    }

    fn ip_route_regex() -> Regex {
        let reg_for_ip = r"((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}";
        Regex::new(&format!(
            r#"^(default via )?{}(/\d+)?\s(dev|via)(\s.+){{3,}}"#,
            reg_for_ip
        ))
        .unwrap()
    }

    #[test]
    fn reg_for_ip_route_command_output_good_and_bad_ip() {
        let route_n_output = vec![
            (
                "default via 0.1.0.1 dev eth0 proto dhcp scope link src 10.1.0.84 metric 100",
                true,
                "Example of good IPv4",
            ),
            (
                "10.1.0.0/16 dev eth0 proto kernel scope link src 10.1.0.84 metric 100",
                true,
                "Example of good IPv4",
            ),
            (
                "168.63.129.16 via 10.1.0.1 dev eth0 proto dhcp src 10.1.0.84 metric 100",
                true,
                "Example of good IPv4",
            ),
            (
                "169.254.169.254 via 10.1.0.1 dev eth0 proto dhcp src 10.1.0.84 metric 100",
                true,
                "Example of good IPv4",
            ),
            (
                "172.17.0.0/16 dev docker0 proto kernel scope link src 172.17.0.1 linkdown",
                true,
                "Example of good IPv4",
            ),
            (
                "10.1.0.0/16 dev eth0 proto kernel scope link src 10.1.0.84 metric 100",
                true,
                "Example of good IPv4",
            ),
            (
                "0.1.255.1 dev eth0 proto dhcp",
                true,
                "Example of good IPv4",
            ),
            (
                "0.1.0 dev eth0 proto dhcp scope link src 10.1.0.84 metric 100",
                false,
                "IPv4 address has only three elements",
            ),
            (
                "0.1.256.1 dev eth0 proto dhcp",
                false,
                "IPv4 address is malformed",
            ),
            (
                "0.1.b.1 dev eth0 proto dhcp",
                false,
                "IPv4 address contains a letter",
            ),
            (
                "0.1.0.1/ dev eth0 proto dhcp",
                false,
                "IPv4 Subnet is missing a netmask",
            ),
            (
                "2001:0db8:0000:0000:0000:ff00:0042:8329 dev eth0 proto dhcp",
                false,
                "Should be IPv4 not IPv6",
            ),
        ];

        let regex = ip_route_regex();

        route_n_output.iter().for_each(|line| {
            assert_eq!(
                regex.is_match(line.0),
                line.1,
                "{}: Line: {}",
                line.2,
                line.0
            );
        });
    }
}
