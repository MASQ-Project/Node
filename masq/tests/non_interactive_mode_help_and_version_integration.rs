// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::utils::MasqProcess;
use regex::Regex;

mod utils;

#[test]
fn masq_non_interactive_help_command_integration() {
    let masq_handle = MasqProcess::new().start_noninteractive(vec!["--help"]);

    let (stdout, stderr, exit_code) = masq_handle.stop();

    assert_eq!(stderr, "");
    assert!(
        stdout.contains(
            "MASQ\n\
masq is a command-line user interface to the MASQ Daemon and the MASQ Node"
        ) && stdout.contains("SUBCOMMANDS"),
        "Should see a clippings out of the help for masq, but got this: {}",
        stdout,
    );
    assert_eq!(exit_code.unwrap(), 0);
}

#[test]
fn masq_non_interactive_version_command_integration() {
    let masq_handle = MasqProcess::new().start_noninteractive(vec!["--version"]);

    let (stdout, stderr, exit_code) = masq_handle.stop();

    assert_eq!(stderr, "");
    let regex = Regex::new(r"masq \d+\.\d+\.\d+\n").unwrap();
    assert!(
        regex.is_match(&stdout),
        "Should see the version of masq printed to stdout, but got this: {}",
        stdout
    );
    assert_eq!(exit_code.unwrap(), 0);
}
