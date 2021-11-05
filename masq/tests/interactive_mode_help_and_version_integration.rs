// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::utils::DaemonProcess;
use crate::utils::MasqProcess;
use masq_lib::utils::find_free_port;
use regex::Regex;
use std::thread;
use std::time::Duration;

mod utils;

#[test]
fn interactive_mode_allows_a_help_call_integration() {
    let port = find_free_port();
    let daemon_handle = DaemonProcess::new().start(port);
    thread::sleep(Duration::from_millis(200));
    let mut masq_handle = MasqProcess::new().start_interactive(port, true);
    let mut stdin_handle = masq_handle.create_stdin_handle();

    stdin_handle.type_command("help");

    thread::sleep(Duration::from_millis(300));
    stdin_handle.type_command("exit");
    let (stdout, _stderr, _) = masq_handle.stop();
    daemon_handle.kill();
    //TODO put this assertion back when GH-446 is played out - paired with the test below
    //assert_eq!(stderr, "");
    assert!(
        stdout.contains(
            "MASQ
masq is a command-line user interface to the MASQ Daemon and the MASQ Node
"
        ),
        "Should see a printed message of the help for masq, but got this: {}",
        stdout,
    );
    let mut ending_part = stdout.lines().rev().take(2);
    let last_line = ending_part.next().unwrap();
    let line_before_the_last_one = ending_part.next().unwrap();
    let regex = Regex::new(r"\w{5,}?").unwrap();
    assert!(
        regex.is_match(line_before_the_last_one),
        "Should find the very end of the help for \
     masq in a correct form, but got this: {}",
        stdout,
    );
    assert_eq!(
        last_line, "masq> ",
        "Should find masq prompt on the last line but got this: {}",
        stdout,
    )
}

#[test]
fn interactive_mode_allows_a_version_call_integration() {
    let port = find_free_port();
    let daemon_handle = DaemonProcess::new().start(port);
    thread::sleep(Duration::from_millis(200));
    let mut masq_handle = MasqProcess::new().start_interactive(port, true);
    let mut stdin_handle = masq_handle.create_stdin_handle();

    stdin_handle.type_command("version");

    thread::sleep(Duration::from_millis(300));
    stdin_handle.type_command("exit");
    let (stdout, _stderr, _) = masq_handle.stop();
    daemon_handle.kill();
    //TODO put this assertion back when GH-446 is played out - paired with the test above
    //assert_eq!(stderr, "");
    let regex = Regex::new(r"masq> \nmasq \d+\.\d+\.\d+\nmasq> ").unwrap();
    assert!(
        regex.is_match(&stdout),
        "Should see a printed message of the current version of masq, but got this: {}",
        stdout,
    );
}
