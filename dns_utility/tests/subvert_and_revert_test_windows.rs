// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
#![cfg(target_os = "windows")]
extern crate dns_utility_lib;

mod utils;

use std::io;
use utils::TestCommand;
use winreg::enums::*;
use winreg::RegKey;

#[test]
// Any integration tests that should be run as root should have names ending in '_sudo_integration'
fn windows_subvert_and_revert_sudo_integration() {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let interfaces = hklm
        .open_subkey("SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces")
        .unwrap();
    let gateway_interfaces: Vec<RegKey> = interfaces
        .enum_keys()
        .map(|interface_name| {
            let key: RegKey = interfaces.open_subkey(interface_name.unwrap()).unwrap();
            key
        })
        .filter(|interface| {
            let default_gateway_res: io::Result<String> = interface.get_value("DefaultGateway");
            let dhcp_default_gateway_res: io::Result<String> =
                interface.get_value("DhcpDefaultGateway");
            match (default_gateway_res, dhcp_default_gateway_res) {
                (Err(_), Err(_)) => false,
                _ => true,
            }
        })
        .collect();
    if gateway_interfaces.is_empty() || (gateway_interfaces.len() > 1) {
        println!("---INTEGRATION TEST CANNOT RUN IN THIS ENVIRONMENT---");
        return;
    }
    let interface = gateway_interfaces.first().unwrap();
    let name_server: String = interface.get_value("NameServer").unwrap();
    assert_eq!(
        name_server,
        String::new(),
        "NameServer for {:?} was not blank",
        interface
    );

    let mut subvert_command = TestCommand::start("dns_utility", vec!["subvert"]);
    let exit_status = subvert_command.wait();
    assert_eq!(exit_status, Some(0), "{}", subvert_command.output());

    let name_server: String = interface.get_value("NameServer").unwrap();
    assert_eq!(
        name_server,
        String::from("127.0.0.1"),
        "NameServer for {:?} was not set",
        interface
    );

    let mut revert_command = TestCommand::start("dns_utility", vec!["revert"]);
    let exit_status = revert_command.wait();
    assert_eq!(exit_status, Some(0), "{}", revert_command.output());

    let name_server: String = interface.get_value("NameServer").unwrap();
    assert_eq!(
        name_server,
        String::new(),
        "NameServer for {:?} was not blank",
        interface
    );
}
