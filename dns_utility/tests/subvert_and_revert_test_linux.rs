// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
#![cfg(target_os = "linux")]

mod linux_utils;
mod utils;

use crate::linux_utils::get_file_contents;
use crate::linux_utils::get_nameserver_entries;
use crate::linux_utils::is_subverted;
use crate::utils::TestCommand;

#[test]
// Any integration tests that should be run as root should have names ending in '_sudo_integration'
fn resolv_conf_subvert_and_revert_sudo_integration() {
    let file_contents = match get_file_contents() {
        Ok(s) => s,
        Err(_) => {
            println!("---INTEGRATION TEST CANNOT YET RUN IN THIS ENVIRONMENT---");
            return;
        }
    };
    check_for_subversion(&file_contents, false, "Already subverted");
    let mut subvert_command = TestCommand::start("dns_utility", vec!["subvert"]);
    let exit_status = subvert_command.wait();
    assert_eq!(exit_status, Some(0), "{}", subvert_command.output());

    let file_contents = get_file_contents().unwrap();
    check_for_subversion(&file_contents, true, "Subversion didn't work");

    let mut revert_command = TestCommand::start("dns_utility", vec!["revert"]);
    let exit_status = revert_command.wait();
    assert_eq!(exit_status, Some(0), "{}", revert_command.output());

    let file_contents = get_file_contents().unwrap();
    check_for_subversion(
        &file_contents,
        false,
        "DANGER! Reversion didn't work! DNS settings are corrupt!",
    );
}

fn check_for_subversion(file_contents: &String, subversion_expected: bool, error_message: &str) {
    let entries = get_nameserver_entries(file_contents);
    assert_eq!(
        is_subverted(&entries),
        subversion_expected,
        "{}:\n{}",
        error_message,
        file_contents
    );
}
