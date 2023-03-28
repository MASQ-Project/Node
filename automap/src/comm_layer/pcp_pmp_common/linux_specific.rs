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
    let addresses = output
        .split('\n')
        .take_while(|line| line.trim_start().starts_with("default "))
        .map(|line| {
            let ip_str: String = line
                .chars()
                .skip_while(|char| !char.is_numeric())
                .take_while(|char| !char.is_whitespace())
                .collect();

            IpAddr::from_str(&ip_str).expect("Bad syntax from ip route")
        })
        .collect::<Vec<IpAddr>>();
    Ok(addresses)
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
        let ip_route_output =
            "default via 192.168.0.1 dev enp4s0 proto dhcp src 192.168.0.100 metric 100
169.254.0.0/16 dev enp4s0 scope link metric 1000
172.17.0.0/16 dev docker0 proto kernel scope link src 172.17.0.1 linkdown
172.18.0.0/16 dev br-85f38f356a58 proto kernel scope link src 172.18.0.1 linkdown
192.168.0.0/24 dev enp4s0 proto kernel scope link src 192.168.0.100 metric 100";
        let find_routers_command = FindRoutersCommandMock::new(Ok(&ip_route_output));

        let result = linux_find_routers(&find_routers_command).unwrap();

        assert_eq!(result, vec![IpAddr::from_str("192.168.0.1").unwrap()])
    }

    #[test]
    fn find_routers_works_when_there_are_multiple_routers_to_find() {
        let ip_route_output = "default via 192.168.0.1 dev enp0s8 proto dhcp metric 101
default via 192.168.0.2 dev enp0s3 proto dhcp metric 102
10.0.2.0/24 dev enp0s3 proto kernel scope link src 10.0.2.15 metric 102
169.254.0.0/16 dev enp0s3 scope link metric 1000
192.168.1.0/24 dev enp0s8 proto kernel scope link src 192.168.1.64 metric 101
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
    fn find_routers_works_when_command_writes_to_stderr() {
        let find_routers_command = FindRoutersCommandMock::new(Err("Booga!"));

        let result = linux_find_routers(&find_routers_command);

        assert_eq!(
            result,
            Err(AutomapError::ProtocolError("Booga!".to_string()))
        )
    }

    #[test]
    fn find_routers_command_produces_output_that_looks_right() {
        let subject = LinuxFindRoutersCommand::new();

        let result = subject.execute().unwrap();

        let mut lines = result.split('\n').collect::<Vec<&str>>();
        assert!(
            lines.len() > 1,
            "Did not find more than two lines in this vector {:?}",
            lines
        );
        let reg_for_ip = r"((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}";
        let reg_for_mandatory = Regex::new(&format!("^default via {} dev", reg_for_ip)).unwrap();
        let mandatory_default_gateway = lines.remove(0);
        assert!(
            reg_for_mandatory.is_match(mandatory_default_gateway),
            "Comment output: first line {} the rest {:?}",
            mandatory_default_gateway,
            lines
        );
        let reg_for_any_other_line = Regex::new(&format!(
            "{}|^{}(/\\d+)?\\s(dev|via) ",
            reg_for_mandatory, reg_for_ip
        ))
        .unwrap();
        lines.iter().for_each(|line| {
            assert!(
                reg_for_any_other_line.is_match(line),
                "Lines: {:?} line: {}",
                lines,
                line
            );
        });
    }
}
