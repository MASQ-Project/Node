// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
extern crate sub_lib;
extern crate dns_utility_lib;

#[cfg (windows)]
extern crate winreg;

mod utils;

use std::io;
use utils::TestCommand;

#[cfg (unix)]
use std::fs::File;
#[cfg (unix)]
use std::io::Read;
#[cfg (unix)]
use std::path::Path;

#[cfg (unix)]
use dns_utility_lib::resolv_conf_dns_modifier::ResolvConfDnsModifier;

#[cfg (windows)]
use winreg::RegKey;
#[cfg (windows)]
use winreg::enums::*;

#[test]
#[cfg (unix)]
fn resolv_conf_subvert_and_revert_integration () {
    let contents = match get_file_contents () {
        Ok (c) => c,
        Err (_) => {println! ("---INTEGRATION TEST CANNOT YET RUN IN THIS ENVIRONMENT---"); return}
    };
    let active_nameservers: Vec<String> = ResolvConfDnsModifier::new ().active_nameservers (contents.as_str ()).iter ()
        .map (|entry| entry.0.clone ()).collect ();
    assert_eq! (contents.contains ("\nnameserver 127.0.0.1"), false, "Already contains '\\n#nameserver 127.0.0.1':\n{}", contents);

    let mut subvert_command = TestCommand::start ("dns_utility", vec! ("subvert"));
    let exit_status = subvert_command.wait ();
    assert_eq! (exit_status, Some (0), "{}", subvert_command.output ());

    let contents = get_file_contents ().expect ("Couldn't get file contents after subversion");
    assert_eq! (contents.contains ("\nnameserver 127.0.0.1"), true, "Doesn't contain '\\n#nameserver 127.0.0.1':\n{}", contents);
    active_nameservers.iter ().for_each (|entry| {
        assert_eq! (contents.contains (&format! ("\n#{}", entry)[..]), true, "Doesn't contain '\\n#{}':\n{}", entry, contents)
    });

    let mut revert_command = TestCommand::start ("dns_utility", vec! ("revert"));
    let exit_status = revert_command.wait ();
    assert_eq! (exit_status, Some (0), "{}", revert_command.output ());

    let contents = get_file_contents ().expect ("Couldn't get file contents after reversion");
    assert_eq! (contents.contains ("\nnameserver 127.0.0.1"), false, "Still contains '\\n#nameserver 127.0.0.1':\n{}", contents);
    active_nameservers.iter ().for_each (|entry| {
        assert_eq! (contents.contains (&format! ("\n{}", entry)[..]), true, "Doesn't contain '\\n{}':\n{}", entry, contents)
    });

}

#[test]
#[cfg (windows)]
fn windows_subvert_and_revert_integration () {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let interfaces = hklm.open_subkey("SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces").unwrap();
    let gateway_interfaces: Vec<RegKey> = interfaces.enum_keys ()
        .map (| interface_name | {
            let key: RegKey = interfaces.open_subkey (interface_name.unwrap ()).unwrap ();
            key
        })
        .filter (| interface | {
            let default_gateway_res: io::Result<String> = interface.get_value ("DefaultGateway");
            let dhcp_default_gateway_res: io::Result<String> = interface.get_value ("DhcpDefaultGateway");
            match (default_gateway_res, dhcp_default_gateway_res) {
                (Err(_), Err(_)) => false,
                _ => true
            }
        })
        .collect ();
    if gateway_interfaces.is_empty () || (gateway_interfaces.len () > 1) {
        println! ("---INTEGRATION TEST CANNOT RUN IN THIS ENVIRONMENT---");
        return
    }
    let interface = gateway_interfaces.first ().unwrap ();
    let name_server: String = interface.get_value("NameServer").unwrap();
    assert_eq!(name_server, String::new(), "NameServer for {:?} was not blank", interface);

    let mut subvert_command = TestCommand::start ("dns_utility", vec! ("subvert"));
    let exit_status = subvert_command.wait ();
    assert_eq! (exit_status, Some (0), "{}", subvert_command.output ());

    let name_server: String = interface.get_value("NameServer").unwrap();
    assert_eq!(name_server, String::from("127.0.0.1"), "NameServer for {:?} was not set", interface);

    let mut revert_command = TestCommand::start ("dns_utility", vec! ("revert"));
    let exit_status = revert_command.wait ();
    assert_eq! (exit_status, Some (0), "{}", revert_command.output ());

    let name_server: String = interface.get_value("NameServer").unwrap();
    assert_eq!(name_server, String::new(), "NameServer for {:?} was not blank", interface);
}

#[cfg (unix)]
fn get_file_contents () -> io::Result<String> {
    let path = Path::new ("/").join (Path::new ("etc")).join (Path::new ("resolv.conf"));
    let mut file = File::open (path)?;
    let mut contents = String::new ();
    file.read_to_string (&mut contents)?;
    Ok (contents)
}
