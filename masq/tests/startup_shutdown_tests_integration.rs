// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::utils::DaemonProcess;
use crate::utils::MasqProcess;
use masq_lib::utils::find_free_port;
use std::thread;
use std::time::Duration;

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
fn masq_propagates_errors_related_to_default_terminal() {
    let child = MasqProcess::new().start_interactive(22222); //the port is irrelevant; it hits the error before it gets to trying to connect to the Daemon

    let output = child.wait_with_output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    assert_eq!(output.status.code().unwrap(), 1);
    assert_eq!(stdout, "", "{}", stdout);
    assert!(
        stderr.contains("Pre-configuration error: Local terminal recognition: "),
        "stderr was: {}",
        stderr
    );
}

#[test]
fn handles_startup_and_shutdown_integration() {
    let port = find_free_port();
    let daemon_handle = DaemonProcess::new().start(port);

    thread::sleep(Duration::from_millis(500));

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
