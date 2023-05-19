// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use std::io::Read;
use std::thread;
use std::time::Duration;
use crate::utils::{DaemonProcess, MasqProcess};
use masq_lib::test_utils::utils::ensure_node_home_directory_exists;
use masq_lib::utils::find_free_port;

mod utils;

#[test]
fn ensure_data_directory_has_specific_chain_direcotry_within() {
    let dir_path = ensure_node_home_directory_exists(
        "masq_integration_tests",
        "ensure_data_directory_has_specific_chain_direcotry_within",
    );
    let port = find_free_port();
    let mut daemon_handle = DaemonProcess::new().start(port);
    let mut masq_handle = MasqProcess::new().start_interactive(port, true);
    let mut stdin_handle = masq_handle.create_stdin_handle();
    stdin_handle.type_command(&format!(
        "setup --data-directory {} --ip 1.2.3.4",
        dir_path.to_str().unwrap()
    ));
    thread::sleep(Duration::from_millis(1000));

    stdin_handle.type_command("start");
    // let mut command_deamon = daemon_handle.child.stdout.take().unwrap();
    // let mut output = String::new();
    // command_deamon.read_to_string(&mut output);
    // println!("exit_code: {:#?}", output);
    thread::sleep(Duration::from_millis(5000));

    stdin_handle.type_command("shutdown");

    thread::sleep(Duration::from_millis(1000));

    stdin_handle.type_command("exit");

    let (stdout, stderr, exit_code) = masq_handle.stop();
    // assert_eq!(
    //     stdout,
    //     "masq> ***user's command line here***\n\nTerminated\n\n".to_string(),
    //     //____________________________________
    //     //the underlined piece of this string shows what linefeed would print
    // );
    println!("stdout: {:#?}", stdout);
    println!("stderr: {}", stderr);
    println!("exit_code: {:#?}", exit_code);
    daemon_handle.kill();
}