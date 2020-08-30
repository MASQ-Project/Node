// Copyright (c) 2019-2020, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

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
        stderr.starts_with("Can't connect to Daemon or Node"),
        true,
        "{}",
        stderr
    );
    assert_eq!(exit_code, 1);
}

#[test]
#[ignore]
fn handles_startup_and_shutdown_integration() {
    let port = find_free_port();
    let daemon_handle = DaemonProcess::new().start(port);

    thread::sleep(Duration::from_millis(500));

    let masq_handle = MasqProcess::new().start_noninteractive(vec![
        "setup",
        "--log-level",
        "error",
        "--neighborhood-mode",
        "zero-hop",
        "--chain",
    ]);

    let (stdout, stderr, exit_code) = masq_handle.stop();

    assert_eq!(&stderr, "", "{}", stderr);
    assert_eq!(
        stdout.contains("neighborhood-mode         zero-hop"),
        true,
        "{}",
        stdout
    );
    assert_eq!(exit_code, 0);

    let masq_handle = MasqProcess::new().start_noninteractive(vec!["start"]);

    let (stdout, stderr, exit_code) = masq_handle.stop();

    assert_eq!(&stderr, "", "{}", stderr);
    assert_eq!(
        stdout.contains("MASQNode successfully started as process"),
        true,
        "{}",
        stdout
    );
    assert_eq!(exit_code, 0);

    let masq_handle = MasqProcess::new().start_noninteractive(vec!["shutdown"]);

    let (stdout, stderr, exit_code) = masq_handle.stop();

    assert_eq!(&stderr, "", "{}", stderr);
    assert_eq!(
        stdout.contains("MASQNode was instructed to shut down and has broken its connection"),
        true,
        "{}",
        stdout
    );
    assert_eq!(exit_code, 0);

    daemon_handle.kill();
}
