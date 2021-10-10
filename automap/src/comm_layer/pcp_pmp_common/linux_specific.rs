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
        .map(|line| {
            line.split(' ')
                .filter(|piece| !piece.is_empty())
                .collect::<Vec<&str>>()
        })
        .filter(|line_vec| (line_vec.len() >= 4) && (line_vec[3] == "UG"))
        .map(|line_vec| IpAddr::from_str(line_vec[1]).expect("Bad syntax from route -n"))
        .collect::<Vec<IpAddr>>();
    Ok(addresses)
}

pub struct LinuxFindRoutersCommand {}

impl FindRoutersCommand for LinuxFindRoutersCommand {
    fn execute(&self) -> Result<String, String> {
        self.execute_command("route -n")
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
    use std::str::FromStr;

    #[test]
    fn find_routers_works_when_there_is_a_router_to_find() {
        let route_n_output = "Kernel IP routing table
Destination     Gateway         Genmask         Flags Metric Ref    Use Iface
0.0.0.0         192.168.0.1     0.0.0.0         UG    100    0        0 enp4s0
169.254.0.0     0.0.0.0         255.255.0.0     U     1000   0        0 enp4s0
172.17.0.0      0.0.0.0         255.255.0.0     U     0      0        0 docker0
172.18.0.0      0.0.0.0         255.255.0.0     U     0      0        0 br-2c4b4b668d71
192.168.0.0     0.0.0.0         255.255.255.0   U     100    0        0 enp4s0
";
        let find_routers_command = FindRoutersCommandMock::new(Ok(&route_n_output));

        let result = linux_find_routers(&find_routers_command).unwrap();

        assert_eq!(result, vec![IpAddr::from_str("192.168.0.1").unwrap()])
    }

    #[test]
    fn find_routers_works_when_there_are_multiple_routers_to_find() {
        let route_n_output = "Kernel IP routing table
Destination     Gateway         Genmask         Flags Metric Ref    Use Iface
0.0.0.0         192.168.0.1     0.0.0.0         UG    100    0        0 enp4s0
0.0.0.0         192.168.0.2     0.0.0.0         UG    100    0        0 enp4s0
169.254.0.0     0.0.0.0         255.255.0.0     U     1000   0        0 enp4s0
172.17.0.0      0.0.0.0         255.255.0.0     U     0      0        0 docker0
172.18.0.0      0.0.0.0         255.255.0.0     U     0      0        0 br-2c4b4b668d71
192.168.0.0     0.0.0.0         255.255.255.0   U     100    0        0 enp4s0
";
        let find_routers_command = FindRoutersCommandMock::new(Ok(&route_n_output));

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
    fn find_routers_works_when_there_is_no_router_to_find() {
        let route_n_output = "Kernel IP routing table
Destination     Gateway         Genmask         Flags Metric Ref    Use Iface
0.0.0.0         192.168.0.1     0.0.0.0         U     100    0        0 enp4s0
169.254.0.0     0.0.0.0         255.255.0.0     U     1000   0        0 enp4s0
172.17.0.0      0.0.0.0         255.255.0.0     U     0      0        0 docker0
172.18.0.0      0.0.0.0         255.255.0.0     U     0      0        0 br-2c4b4b668d71
192.168.0.0     0.0.0.0         255.255.255.0   U     100    0        0 enp4s0
";
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
    fn find_routers_command_produces_output_that_looks_right() {
        let subject = LinuxFindRoutersCommand::new();

        let result = subject.execute().unwrap();

        let lines = result.split('\n').collect::<Vec<&str>>();
        assert_eq!("Kernel IP routing table", lines[0]);
        let headings = lines[1]
            .split(' ')
            .filter(|s| s.len() > 0)
            .collect::<Vec<&str>>();
        assert_eq!(
            headings,
            vec![
                "Destination",
                "Gateway",
                "Genmask",
                "Flags",
                "Metric",
                "Ref",
                "Use",
                "Iface",
            ]
        );
        for line in &lines[3..] {
            if line.len() == 0 {
                continue;
            }
            let columns = line
                .split(' ')
                .filter(|s| s.len() > 0)
                .collect::<Vec<&str>>();
            for idx in 0..3 {
                if IpAddr::from_str(columns[idx]).is_err() {
                    panic!(
                        "Column {} should have been an IP address but wasn't: {}",
                        idx, columns[idx]
                    )
                }
            }
            for idx in 4..7 {
                if columns[idx].parse::<u64>().is_err() {
                    panic!(
                        "Column {} should have been numeric but wasn't: {}",
                        idx, columns[idx]
                    )
                }
            }
        }
    }
}
