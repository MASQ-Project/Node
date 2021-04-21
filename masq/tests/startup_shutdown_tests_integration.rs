// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::utils::DaemonProcess;
use crate::utils::MasqProcess;
use masq_lib::utils::find_free_port;
use std::thread;
use std::time::Duration;
use regex::Regex;

mod utils;

#[test]
fn masq_without_daemon_integration() {
    let masq_handle = MasqProcess::new().start_noninteractive(vec!["setup"]);

    let (stdout, stderr, exit_code) = masq_handle.stop();

    assert_eq!(&stdout, "", "{}", stdout);
    assert_eq!(
        stderr.contains("Can't connect to Daemon or Node"),
        true,
        "{}",
        stderr
    );
    assert_eq!(exit_code, 1);
}

#[test]
fn masq_propagates_errors_related_to_default_terminal_integration() {
    //the port is irrelevant; it hits the error before it gets to trying to connect to the Daemon
    let masq_handle = MasqProcess::new().start_interactive(22222, false);

    let (stdout, stderr, exit_code) = masq_handle.stop();

    assert_eq!(exit_code, 1);
    let regex = Regex::new(r"\x1B\[\?\d\d[lh]").unwrap();
    assert_eq!(regex.replace_all( &stdout,""), "", "{}", stdout);

    #[cfg(not(target_os = "windows"))]
    let expected_error_message = "Pre-configuration error: Preparing terminal interface:";

    #[cfg(target_os = "windows")]
    let expected_error_message = "Pre-configuration error: Local terminal: ";

    assert!(
        stderr.contains(expected_error_message),
        "stderr was: {}",
        stderr
    );
}

#[test]
fn handles_startup_and_shutdown_integration() {
    let port = find_free_port();
    let daemon_handle = DaemonProcess::new().start(port);

    thread::sleep(Duration::from_millis(300));

    let masq_handle = MasqProcess::new().start_noninteractive(vec![
        "--ui-port",
        &port.to_string(),
        "setup",
        "--log-level",
        "error",
        "--neighborhood-mode",
        "zero-hop",
    ]);

    let (stdout, stderr, exit_code) = masq_handle.stop();

    assert_eq!(&stderr, "", "ln. 70: {}", stderr);
    assert_eq!(
        stdout.contains("neighborhood-mode      zero-hop"),
        true,
        "{}",
        stdout
    );
    assert_eq!(exit_code, 0);

    let masq_handle =
        MasqProcess::new().start_noninteractive(vec!["--ui-port", &port.to_string(), "start"]);

    let (stdout, stderr, exit_code) = masq_handle.stop();

    assert_eq!(&stderr, "", "ln. 83: {}", stderr);
    assert_eq!(
        stdout.contains("MASQNode successfully started in process"),
        true,
        "{}",
        stdout
    );
    assert_eq!(exit_code, 0);

    let masq_handle =
        MasqProcess::new().start_noninteractive(vec!["--ui-port", &port.to_string(), "shutdown"]);

    let (stdout, stderr, exit_code) = masq_handle.stop();

    assert_eq!(&stderr, "", "ln. 96: {}", stderr);
    assert_eq!(
        stdout.contains("MASQNode was instructed to shut down and has broken its connection"),
        true,
        "{}",
        stdout
    );
    assert_eq!(exit_code, 0);

    daemon_handle.kill();
}
