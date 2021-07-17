// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

#![cfg(not(target_os = "windows"))]
//sadly enough, I cannot come up with an idea of how to simulate the Windows ctrl-c event
//it should be handled by an event handler embedded within linefeed though, so we can believe they can provide what they say
//the other lines don't have signs of cross-platform code

use crate::utils::DaemonProcess;
use crate::utils::MasqProcess;
use masq_lib::utils::find_free_port;
use std::thread;
use std::time::Duration;

mod utils;

#[test]
fn masq_terminates_because_of_an_interrupt_signal_integration() {
    let port = find_free_port();
    let daemon_handle = DaemonProcess::new().start(port);
    thread::sleep(Duration::from_millis(300));
    let masq_handle = MasqProcess::new().start_interactive(port, true);
    thread::sleep(Duration::from_millis(300));
    let masq_process_id = masq_handle.child_id();

    unsafe {
        libc::kill(masq_process_id as i32, libc::SIGINT);
    }

    thread::sleep(Duration::from_millis(300));
    let (stdout, stderr, exit_code) = masq_handle.stop();
    assert_eq!(exit_code, Some(0));
    assert_eq!(stderr, "".to_string());
    assert_eq!(
        stdout,
        "masq> \nmasq> /*user's unfinished line to be here*/\n\nTerminated\n\n".to_string()
    );
    daemon_handle.kill()
}
