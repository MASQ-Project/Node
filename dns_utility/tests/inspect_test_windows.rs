// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
#![cfg (target_os = "windows")]
extern crate sub_lib;
extern crate dns_utility_lib;
extern crate winreg;

mod utils;

use utils::TestCommand;
use dns_utility_lib::winreg_dns_modifier::WinRegDnsModifier;

#[test]
// Any integration tests that should be run without root should have names ending in '_user_integration'
fn winreg_inspect_user_integration () {
    let modifier = WinRegDnsModifier::new ();
    let interfaces = modifier.find_interfaces_to_inspect ().unwrap ();
    let dns_server_list_csv = modifier.find_dns_server_list (interfaces).unwrap ();
    let dns_server_list = dns_server_list_csv.split (",");
    let expected_inspect_output = dns_server_list.into_iter ()
        .fold (String::new (), |so_far, dns_server| format! ("{}{}\n", so_far, dns_server));

    let mut inspect_command = TestCommand::start ("dns_utility", vec! ("inspect"));
    let exit_status = inspect_command.wait ();
    let output = inspect_command.output ();
    assert_eq! (exit_status, Some (0), "{}", output);
    assert_eq! (output, format! ("STANDARD OUTPUT:\n{}\nSTANDARD ERROR:\n\n", expected_inspect_output));
}
