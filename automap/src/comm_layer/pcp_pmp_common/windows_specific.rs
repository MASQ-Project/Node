// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
#![cfg(target_os = "windows")]

use crate::comm_layer::pcp_pmp_common::FindRoutersCommand;
use crate::comm_layer::AutomapError;
use std::net::IpAddr;
use std::str::FromStr;

pub fn windows_find_routers(command: &dyn FindRoutersCommand) -> Result<Vec<IpAddr>, AutomapError> {
    match command.execute() {
        Ok(stdout) => {
            // Arrange to split output into line pairs that we can zip together
            let mut firsts = stdout.split(&['\n', '\r'][..]).collect::<Vec<&str>>();
            firsts.push("");
            let mut seconds = vec![""];
            seconds.extend(firsts.clone());
            let addresses = firsts
                .into_iter()
                .zip(seconds)
                .filter(|(_, first)| first.contains("Default Gateway"))
                .map(|(second, first)| {
                    let first_line_strs = first
                        .split(' ')
                        .filter(|s| s.len() >= 2)
                        .collect::<Vec<&str>>();
                    let second_addr_opt = match IpAddr::from_str(second.trim()) {
                        Ok(addr) => Some(addr),
                        Err(_) => None,
                    };
                    (first_line_strs, second_addr_opt)
                })
                .filter(|(first_line_strs, _)| first_line_strs.len() > 2)
                .flat_map(
                    |(first_elements, ip_addr_opt)| match (first_elements, ip_addr_opt) {
                        (_, Some(IpAddr::V4(ipv4_addr))) => Some(IpAddr::V4(ipv4_addr)),
                        (first_elements, _) => {
                            let ip_addr_maybe_with_scope_id = first_elements[2];
                            let ip_addr_str =
                                ip_addr_maybe_with_scope_id.split('%').collect::<Vec<_>>()[0];
                            Some(
                                IpAddr::from_str(ip_addr_str)
                                    .expect("Bad syntax from ipconfig /all"),
                            )
                        }
                    },
                )
                .collect::<Vec<IpAddr>>();
            Ok(addresses)
        }
        Err(stderr) => Err(AutomapError::ProtocolError(stderr)),
    }
}

pub struct WindowsFindRoutersCommand {}

impl FindRoutersCommand for WindowsFindRoutersCommand {
    fn execute(&self) -> Result<String, String> {
        self.execute_command("ipconfig /all")
    }
}

impl Default for WindowsFindRoutersCommand {
    fn default() -> Self {
        Self::new()
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
    use crate::mocks::FindRoutersCommandMock;
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
    fn find_routers_works_when_there_are_multiple_routers_to_find() {
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

Ethernet adapter Ethernet 2:

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
   Default Gateway . . . . . . . . . : 10.0.2.0
   DHCP Server . . . . . . . . . . . : 10.0.2.3
   DHCPv6 IAID . . . . . . . . . . . : 101187623
   DHCPv6 Client DUID. . . . . . . . : 00-01-00-01-26-49-5A-82-08-00-27-4B-EB-0D
   DNS Servers . . . . . . . . . . . : 192.168.0.1
   NetBIOS over Tcpip. . . . . . . . : Enabled
";
        let find_routers_command = FindRoutersCommandMock::new(Ok(&route_n_output));

        let result = windows_find_routers(&find_routers_command).unwrap();

        assert_eq!(
            result,
            vec![
                IpAddr::from_str("10.0.2.2").unwrap(),
                IpAddr::from_str("10.0.2.0").unwrap(),
            ]
        )
    }

    #[test]
    fn find_routers_works_on_another_specific_machine() {
        // Several adapters without a Default Gateway, then one with
        let route_n_output = "
Windows IP Configuration

   Host Name . . . . . . . . . . . . : DESKTOP
   Primary Dns Suffix  . . . . . . . :
   Node Type . . . . . . . . . . . . : Hybrid
   IP Routing Enabled. . . . . . . . : No
   WINS Proxy Enabled. . . . . . . . : No

Ethernet adapter Ethernet 3:

   Connection-specific DNS Suffix  . :
   Description . . . . . . . . . . . : VirtualBox Host-Only Ethernet Adapter
   DHCP Enabled. . . . . . . . . . . : No
   Autoconfiguration Enabled . . . . : Yes
   Link-local IPv6 Address . . . . . : fi60::3011:4121:5c3b:f131%11(Preferred)
   IPv4 Address. . . . . . . . . . . : 192.168.56.1(Preferred)
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . :
   NetBIOS over Tcpip. . . . . . . . : Enabled

Wireless LAN adapter Local Network* 4:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . :

Wireless LAN adapter Local Network* 9:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . :

Ethernet adapter Ethernet 2:

   Connection-specific DNS Suffix  . : domain
   DHCP Enabled. . . . . . . . . . . : Yes
   Autoconfiguration Enabled . . . . : Yes
   Link-local IPv6 Address . . . . . : fd50::ed11:2c61:6111:f02e%10(Preferred)
   IPv4 Address. . . . . . . . . . . : 192.168.10.10(Preferred)
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.10.5
   DHCP Server . . . . . . . . . . . : 192.168.1.1
";
        let find_routers_command = FindRoutersCommandMock::new(Ok(&route_n_output));

        let result = windows_find_routers(&find_routers_command).unwrap();

        assert_eq!(result, vec![IpAddr::from_str("192.168.10.5").unwrap()])
    }

    #[test]
    fn find_routers_works_on_galactic_overlords_machine() {
        // Default gateway has an IPv6 address followed by an IPv4 address
        let route_n_output = "
Ethernet adapter Ethernet:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . :

Ethernet adapter Ethernet 2:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . :

Unknown adapter OpenVPN Wintun:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . :

Unknown adapter Local Area Connection:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . :

Wireless LAN adapter Local Area Connection* 1:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . :

Wireless LAN adapter Local Area Connection* 2:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . :

Wireless LAN adapter WiFi:

   Connection-specific DNS Suffix  . :
   IPv6 Address. . . . . . . . . . . : 2002:aaaa:bbbb:0:ccc:dddd:42c2:bae4
   Temporary IPv6 Address. . . . . . : 2002:aaaa:bbbb:0:cccc:eeee:cfe7:730e
   Link-local IPv6 Address . . . . . : fe80::111:2222:3333:4444%21
   IPv4 Address. . . . . . . . . . . : 192.168.1.28
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : fe80::5555:6666:7777:8888%21
                                       192.168.1.1
";
        let find_routers_command = FindRoutersCommandMock::new(Ok(&route_n_output));

        let result = windows_find_routers(&find_routers_command).unwrap();

        assert_eq!(result, vec![IpAddr::from_str("192.168.1.1").unwrap()])
    }

    #[test]
    fn find_routers_works_on_galactic_overlords_machine_without_ipv4() {
        let route_n_output = "
Ethernet adapter Ethernet:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . :

Ethernet adapter Ethernet 2:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . :

Unknown adapter OpenVPN Wintun:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . :

Unknown adapter Local Area Connection:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . :

Wireless LAN adapter Local Area Connection* 1:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . :

Wireless LAN adapter Local Area Connection* 2:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . :

Wireless LAN adapter WiFi:

   Connection-specific DNS Suffix  . :
   IPv6 Address. . . . . . . . . . . : 2002:aaaa:bbbb:0:ccc:dddd:42c2:bae4
   Temporary IPv6 Address. . . . . . : 2002:aaaa:bbbb:0:cccc:eeee:cfe7:730e
   Link-local IPv6 Address . . . . . : fe80::111:2222:3333:4444%21
   IPv4 Address. . . . . . . . . . . : 192.168.1.28
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : fe80::5555:6666:7777:8888%21
";
        let find_routers_command = FindRoutersCommandMock::new(Ok(&route_n_output));

        let result = windows_find_routers(&find_routers_command).unwrap();

        assert_eq!(
            result,
            vec![IpAddr::from_str("fe80::5555:6666:7777:8888").unwrap()]
        )
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
    #[should_panic(expected = "Bad syntax from ipconfig /all")]
    fn find_routers_works_when_ipconfig_output_cant_be_parsed() {
        let route_n_output = "
   Booga
   Default Gateway. . . . . . . . . . : wibblety-poo
   Booga
";
        let find_routers_command = FindRoutersCommandMock::new(Ok(&route_n_output));

        let _ = windows_find_routers(&find_routers_command);
    }

    #[test]
    fn find_routers_command_handles_bad_command() {
        let find_routers_command = FindRoutersCommandMock::new(Err("Booga!"));

        let result = windows_find_routers(&find_routers_command);

        assert_eq!(
            result,
            Err(AutomapError::ProtocolError("Booga!".to_string()))
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
