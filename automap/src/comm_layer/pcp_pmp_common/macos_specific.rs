// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
#![cfg(target_os = "macos")]

use crate::comm_layer::pcp_pmp_common::FindRoutersCommand;
use crate::comm_layer::AutomapError;
use std::net::IpAddr;
use std::str::FromStr;

pub fn macos_find_routers(command: &dyn FindRoutersCommand) -> Result<Vec<IpAddr>, AutomapError> {
    let output = match command.execute() {
        Ok(stdout) => stdout,
        Err(stderr) => return Err(AutomapError::OSCommandError(stderr)),
    };
    let gateway_line_opt = output
        .split('\n')
        .map(|line_ref| line_ref.to_string())
        .find(|line| line.contains("gateway:"))
        .map(|line| {
            line.split(": ")
                .map(|piece| piece.to_string())
                .collect::<Vec<String>>()
        });
    match gateway_line_opt {
        Some(pieces) if pieces.len() > 1 => Ok(vec![
            IpAddr::from_str(&pieces[1]).expect("Bad syntax from route -n get default")
        ]),
        _ => Ok(vec![]),
    }
}

pub struct MacOsFindRoutersCommand {}

impl FindRoutersCommand for MacOsFindRoutersCommand {
    fn execute(&self) -> Result<String, String> {
        self.execute_command("route -n get default")
    }
}

impl MacOsFindRoutersCommand {
    pub fn new() -> Self {
        Self {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::comm_layer::pcp_pmp_common::mocks::FindRoutersCommandMock;
    use std::str::FromStr;

    #[test]
    fn find_routers_works_when_there_is_a_router_to_find() {
        let route_n_output = "   route to: default
destination: default
       mask: default
    gateway: 192.168.0.1
  interface: en0
      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING>
 recvpipe  sendpipe  ssthresh  rtt,msec    rttvar  hopcount      mtu     expire
       0         0         0         0         0         0      1500         0
";
        let find_routers_command = FindRoutersCommandMock::new(Ok(&route_n_output));

        let result = macos_find_routers(&find_routers_command).unwrap();

        assert_eq!(result, vec![IpAddr::from_str("192.168.0.1").unwrap()])
    }

    #[test]
    fn find_routers_works_when_there_is_no_router_to_find() {
        let route_n_output = "   route to: default
destination: default
       mask: default
      belch: 192.168.0.1
  interface: en0
      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING>
 recvpipe  sendpipe  ssthresh  rtt,msec    rttvar  hopcount      mtu     expire
       0         0         0         0         0         0      1500         0
";
        let find_routers_command = FindRoutersCommandMock::new(Ok(&route_n_output));

        let result = macos_find_routers(&find_routers_command).unwrap();

        assert_eq!(result.is_empty(), true)
    }

    #[test]
    fn find_routers_works_when_command_writes_to_stderr() {
        let find_routers_command = FindRoutersCommandMock::new(Err("Booga!"));

        let result = macos_find_routers(&find_routers_command);

        assert_eq!(
            result,
            Err(AutomapError::OSCommandError("Booga!".to_string()))
        )
    }

    #[test]
    fn find_routers_command_produces_output_that_looks_right() {
        let subject = MacOsFindRoutersCommand::new();

        let result = subject.execute().unwrap();

        let lines = result
            .split('\n')
            .flat_map(|line| {
                let columns = line.split(": ").collect::<Vec<&str>>();
                if columns.len() == 2 {
                    Some(columns[0])
                } else {
                    None
                }
            })
            .map(|header| header.trim())
            .collect::<Vec<&str>>();
        assert_eq!(
            lines,
            vec![
                "route to",
                "destination",
                "mask",
                "gateway",
                "interface",
                "flags"
            ]
        );
    }
}
