// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

#![cfg(not(target_os = "windows"))]
//sadly enough, I cannot come up with an idea of how to simulate the Windows ctrl-c event
//it should be handled by an event handler embedded within linefeed though, so we can believe they can provide what they say
//the other lines don't have signs of cross-platform code

use crate::utils::DaemonProcess;
use crate::utils::MasqProcess;
use masq_lib::utils::find_free_port;
use nix::libc::{kill, pid_t, SIGINT};
use std::env::current_dir;
use std::fs::File;
use std::io::Read;
use std::ops::Not;
use std::thread;
use std::time::Duration;

mod utils;

#[test]
fn masq_terminates_because_of_an_interrupt_signal_integration() {
    // TODO this might be a problem with FallingBehing....
    {
        // let file_path = current_dir().unwrap().join("Cargo.toml");
        // let mut cargo_file_handle = File::open(file_path).unwrap();
        // let mut buffer = String::new();
        // cargo_file_handle.read_to_string(&mut buffer).unwrap();
        // let desired_line = buffer
        //     .lines()
        //     .find(|line| line.contains("linefeed"))
        //     .unwrap();
        // let linefeed_version =
        //     desired_line.replace(|char: char| char != '.' && char.is_numeric().not(), "");
        // if linefeed_version != "0.6.0" {
        //     panic!("This test must be reconsidered when the version becomes different;\
        // the exampled output I test against fully depends on what human eyes see at the real masq version;\
        // here linefeed is just mimicked by a mock that could hypothetically diverge from the way linefeed \
        // behaved when the feature tested here was written")
        // }
    }
    let port = find_free_port();
    let daemon_handle = DaemonProcess::new().start(port);
    let masq_handle = MasqProcess::new().start_interactive(port, true);
    thread::sleep(Duration::from_millis(300));
    let masq_process_id = masq_handle.child_id();

    let kill_result = unsafe { kill(pid_t::from(masq_process_id as i32), SIGINT) };

    thread::sleep(Duration::from_millis(300));
    assert_eq!(kill_result, 0);
    let (stdout, stderr, exit_code) = masq_handle.stop();
    assert_eq!(exit_code, Some(0));
    assert_eq!(stderr, "".to_string());
    assert_eq!(
        stdout,
        "masq> ***user's command line here***\n\nTerminated\n\n".to_string(),
        //____________________________________
        //the underlined piece of this string shows what linefeed would print
    );
    daemon_handle.kill()
}
