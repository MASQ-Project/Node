// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
#![cfg (target_os = "linux")]
extern crate sub_lib;
extern crate dns_utility_lib;

mod utils;

use std::io;
use std::io::Read;
use std::path::Path;

use dns_utility_lib::resolv_conf_dns_modifier::ResolvConfDnsModifier;
use utils::TestCommand;
use std::fs::File;

#[test]
fn resolv_conf_subvert_and_revert_integration () {
    if get_file_contents ().is_err () {
        println! ("---INTEGRATION TEST CANNOT YET RUN IN THIS ENVIRONMENT---");
        return
    };
    check_for_subversion (false, "Already subverted");

    let mut subvert_command = TestCommand::start ("dns_utility", vec! ("subvert"));
    let exit_status = subvert_command.wait ();
    assert_eq! (exit_status, Some (0), "{}", subvert_command.output ());

    check_for_subversion (true, "Subversion didn't work");

    let mut revert_command = TestCommand::start ("dns_utility", vec! ("revert"));
    let exit_status = revert_command.wait ();
    assert_eq! (exit_status, Some (0), "{}", revert_command.output ());

    check_for_subversion (false, "DANGER! Reversion didn't work! DNS settings are corrupt!");
}

fn check_for_subversion (desired_state: bool, error_message: &str) {
    let contents = get_file_contents ().unwrap ();
    let entries = get_nameserver_entries (&contents);
    assert_eq! (is_subverted (&entries), desired_state, "{}:\n{}", error_message, contents);
}

fn is_subverted (entries: &Vec<String>) -> bool {
    let first_entry = match entries.first () {
        None => return false,
        Some (x) => x
    };
    ResolvConfDnsModifier::is_substratum_ip(&first_entry)
}

fn get_nameserver_entries (contents: &str) -> Vec<String> {
    let active_nameservers: Vec<String> = ResolvConfDnsModifier::new ().active_nameservers (contents).iter ()
        .map (|entry| entry.0.clone ())
        .collect ();
    active_nameservers
}

fn get_file_contents () -> io::Result<String> {
    let path = Path::new ("/").join (Path::new ("etc")).join (Path::new ("resolv.conf"));
    let mut file = File::open (path)?;
    let mut contents = String::new ();
    file.read_to_string (&mut contents)?;
    Ok (contents)
}
