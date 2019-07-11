// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
#![cfg(target_os = "windows")]
extern crate dns_utility_lib;

mod utils;

use dns_utility_lib::win_dns_modifier::WinDnsModifier;
use utils::TestCommand;

#[test]
// Any integration tests that should be run without root should have names ending in '_user_integration'
fn winreg_inspect_and_status_user_integration() {
    let modifier = WinDnsModifier::default();
    let interfaces = modifier.find_interfaces_to_inspect().unwrap();
    let dns_server_list_csv = modifier.find_dns_server_list(interfaces).unwrap();
    let dns_server_list = dns_server_list_csv.split(",");
    let expected_inspect_output = dns_server_list
        .into_iter()
        .fold(String::new(), |so_far, dns_server| {
            format!("{}{}\n", so_far, dns_server)
        });
    let expected_status_output = if expected_inspect_output == "127.0.0.1\n" {
        "subverted\n".to_string()
    } else {
        "reverted\n".to_string()
    };

    let mut inspect_command = TestCommand::start("dns_utility", vec!["inspect"]);
    let exit_status = inspect_command.wait();
    let output = inspect_command.output();
    assert_eq!(exit_status, Some(0), "{}", output);
    assert_eq!(
        output,
        format!(
            "STANDARD OUTPUT:\n{}\nSTANDARD ERROR:\n\n",
            expected_inspect_output
        )
    );

    let mut status_command = TestCommand::start("dns_utility", vec!["status"]);
    let exit_status = status_command.wait();
    let output = status_command.output();
    assert_eq!(exit_status, Some(0), "{}", output);
    assert_eq!(
        output,
        format!(
            "STANDARD OUTPUT:\n{}\nSTANDARD ERROR:\n\n",
            expected_status_output
        )
    );
}
