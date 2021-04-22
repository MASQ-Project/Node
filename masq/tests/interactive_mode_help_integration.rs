// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::utils::DaemonProcess;
use crate::utils::MasqProcess;
use masq_lib::utils::find_free_port;
use std::thread;
use std::time::Duration;

mod utils;

#[test]
fn interactive_mode_allows_a_help_call_integration() {
    let port = find_free_port();
    let daemon_handle = DaemonProcess::new().start(port);
    thread::sleep(Duration::from_millis(300));
    let mut masq_handle = MasqProcess::new().start_interactive(port, true);
    let mut stdin_handle = masq_handle.create_stdin_handle();

    stdin_handle.type_command("help");

    thread::sleep(Duration::from_millis(300));

    stdin_handle.type_command("exit");
    let (stdout, stderr, _) = masq_handle.stop();
    daemon_handle.kill();
    assert_eq!(stderr, "");
    assert!(
        stdout.contains(
            "MASQ
masq is a command-line user interface to the MASQ Daemon and the MASQ Node
"
        ),
        "Should see a printed message of the help for masq, but got this: {}",
        stdout,
    )
}
