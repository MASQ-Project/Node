// Copyright (c) 2019-2020, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::utils::DaemonProcess;
use crate::utils::MasqProcess;
use masq_lib::utils::find_free_port;
use std::thread;
use std::time::Duration;

mod utils;

#[test]
#[ignore] // Why doesn't this work?
fn setup_results_are_broadcast_to_all_uis() {
    let port = find_free_port();
    let daemon_handle = DaemonProcess::new().start(port);
    thread::sleep(Duration::from_millis(1000));
    let mut setupper_handle = MasqProcess::new().start_interactive();
    let mut receiver_handle = MasqProcess::new().start_interactive();
    let pair = (setupper_handle.get_stdout(), setupper_handle.get_stderr());
    assert_eq!(pair, ("masq> ".to_string(), "".to_string()));
    let pair = (receiver_handle.get_stdout(), receiver_handle.get_stderr());
    assert_eq!(pair, ("masq> ".to_string(), "".to_string()));

    setupper_handle.type_command("setup --neighborhood-mode zero-hop");

    let stdout = receiver_handle.get_stdout();
    let stderr = setupper_handle.get_stderr();
    setupper_handle.type_command("exit");
    receiver_handle.type_command("exit");
    daemon_handle.kill();
    assert_eq!(
        stdout.contains("Daemon setup has changed:"),
        true,
        "Should see 'Daemon setup has changed' at the receiver; instead, saw '{}' at the receiver and '{}' at the setupper.",
        stdout,
        stderr
    );
}
