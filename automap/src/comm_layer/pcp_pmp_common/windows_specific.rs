// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
#![cfg(target_os = "windows")]

use crate::comm_layer::pcp_pmp_common::FindRoutersCommand;
use crate::comm_layer::AutomapError;
use std::net::IpAddr;
use std::str::FromStr;

pub fn windows_find_routers(command: &dyn FindRoutersCommand) -> Result<Vec<IpAddr>, AutomapError> {
    match command.execute() {
        Ok(stdout) => {
            match stdout
                .split(&['\n', '\r'][..])
                .find(|line| line.to_string().contains("Default Gateway"))
                .map(|line| {
                    line.split(' ')
                        .filter(|s| s.len() >= 2)
                        .collect::<Vec<&str>>()
                }) {
                Some(elements) => Ok(vec![IpAddr::from_str(&elements[2]).expect(&format!(
                    "Invalid IP syntax from ipconfig: '{}'",
                    &elements[2]
                ))]),
                None => Ok(vec![]),
            }
        }
        Err(stderr) => Err(AutomapError::OSCommandError(stderr)),
    }
}

pub struct WindowsFindRoutersCommand {}

impl FindRoutersCommand for WindowsFindRoutersCommand {
    fn execute(&self) -> Result<String, String> {
        self.execute_command("ipconfig /all")
    }
}

impl WindowsFindRoutersCommand {
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
        let route_n_output = "
Windows IP Configuration

   Host Name . . . . . . . . . . . . : DESKTOP-EULPUP3
   Primary Dns Suffix  . . . . . . . :
   Node Type . . . . . . . . . . . . : Hybrid
   IP Routing Enabled. . . . . . . . : No
   WINS Proxy Enabled. . . . . . . . : No

Ethernet adapter Ethernet:

   Connection-specific DNS Suffix  . :
   Description . . . . . . . . . . . : Intel(R) PRO/1000 MT Desktop Adapter
   Physical Address. . . . . . . . . : 08-00-27-4B-EB-0D
   DHCP Enabled. . . . . . . . . . . : Yes
   Autoconfiguration Enabled . . . . : Yes
   Link-local IPv6 Address . . . . . : fe80::a06b:7e59:8cb5:e82f%6(Preferred)
   IPv4 Address. . . . . . . . . . . : 10.0.2.15(Preferred)
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Lease Obtained. . . . . . . . . . : Sunday, February 14, 2021 5:21:59 PM
   Lease Expires . . . . . . . . . . : Monday, February 15, 2021 2:45:20 PM
   Default Gateway . . . . . . . . . : 10.0.2.2
   DHCP Server . . . . . . . . . . . : 10.0.2.3
   DHCPv6 IAID . . . . . . . . . . . : 101187623
   DHCPv6 Client DUID. . . . . . . . : 00-01-00-01-26-49-5A-82-08-00-27-4B-EB-0D
   DNS Servers . . . . . . . . . . . : 192.168.0.1
   NetBIOS over Tcpip. . . . . . . . : Enabled
";
        let find_routers_command = FindRoutersCommandMock::new(Ok(&route_n_output));

        let result = windows_find_routers(&find_routers_command).unwrap();

        assert_eq!(result, vec![IpAddr::from_str("10.0.2.2").unwrap()])
    }

    #[test]
    fn find_routers_works_when_there_is_no_router_to_find() {
        let route_n_output = "
Windows IP Configuration

   Host Name . . . . . . . . . . . . : DESKTOP-EULPUP3
   Primary Dns Suffix  . . . . . . . :
   Node Type . . . . . . . . . . . . : Hybrid
   IP Routing Enabled. . . . . . . . : No
   WINS Proxy Enabled. . . . . . . . : No

Ethernet adapter Ethernet:

   Connection-specific DNS Suffix  . :
   Description . . . . . . . . . . . : Intel(R) PRO/1000 MT Desktop Adapter
   Physical Address. . . . . . . . . : 08-00-27-4B-EB-0D
   DHCP Enabled. . . . . . . . . . . : Yes
   Autoconfiguration Enabled . . . . : Yes
   Link-local IPv6 Address . . . . . : fe80::a06b:7e59:8cb5:e82f%6(Preferred)
   IPv4 Address. . . . . . . . . . . : 10.0.2.15(Preferred)
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Lease Obtained. . . . . . . . . . : Sunday, February 14, 2021 5:21:59 PM
   Lease Expires . . . . . . . . . . : Monday, February 15, 2021 2:45:20 PM
   Defart Gateway. . . . . . . . . . : 10.0.2.2
   DHCP Server . . . . . . . . . . . : 10.0.2.3
   DHCPv6 IAID . . . . . . . . . . . : 101187623
   DHCPv6 Client DUID. . . . . . . . : 00-01-00-01-26-49-5A-82-08-00-27-4B-EB-0D
   DNS Servers . . . . . . . . . . . : 192.168.0.1
   NetBIOS over Tcpip. . . . . . . . : Enabled
";
        let find_routers_command = FindRoutersCommandMock::new(Ok(&route_n_output));

        let result = windows_find_routers(&find_routers_command).unwrap();

        assert_eq!(result.is_empty(), true)
    }

    #[test]
    fn find_routers_command_handles_bad_command() {
        let find_routers_command = FindRoutersCommandMock::new(Err("Booga!"));

        let result = windows_find_routers(&find_routers_command);

        assert_eq!(
            result,
            Err(AutomapError::OSCommandError("Booga!".to_string()))
        )
    }

    #[test]
    fn find_routers_command_produces_output_that_looks_right() {
        let subject = WindowsFindRoutersCommand::new();

        let result = subject.execute().unwrap();

        assert_eq!(result.contains("Windows IP Configuration"), true);
        assert_eq!(result.contains("Ethernet adapter"), true);
        assert_eq!(result.contains("Default Gateway"), true);
    }
}
