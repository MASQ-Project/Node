// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::utils::DaemonProcess;
use crate::utils::MasqProcess;
use masq_lib::test_utils::utils::ensure_node_home_directory_exists;
use masq_lib::utils::find_free_port;
use std::thread;
use std::time::Duration;

mod utils;

#[test]
fn setup_results_are_broadcast_to_all_uis_integration() {
    let dir_path = ensure_node_home_directory_exists(
        "masq_integration_tests",
        "setup_results_are_broadcast_to_all_uis_integration",
    );
    let port = find_free_port();
    let daemon_handle = DaemonProcess::new().start(port);
    thread::sleep(Duration::from_millis(300));
    let mut setupper_handle = MasqProcess::new().start_interactive(port, true);
    let mut receiver_handle = MasqProcess::new().start_interactive(port, true);
    let mut stdin_handle_setupper = setupper_handle.create_stdin_handle();
    let mut stdin_handle_receiver = receiver_handle.create_stdin_handle();

    //TODO This first "setup" call shouldn't be necessary. We want only one call here. Will be investigated within GH-438
    stdin_handle_setupper.type_command(&format!(
        "setup --dns-servers 4.5.6.5 --data-directory {}",
        dir_path.to_str().unwrap()
    ));

    thread::sleep(Duration::from_millis(300));

    stdin_handle_setupper.type_command("setup --log-level error");

    thread::sleep(Duration::from_millis(300));
    stdin_handle_setupper.type_command("exit");
    stdin_handle_receiver.type_command("exit");
    let (stdout_setupper, _, _) = setupper_handle.stop();
    let (stdout_receiver, _, _) = receiver_handle.stop();
    daemon_handle.kill();
    assert_eq!(
         stdout_receiver.contains("Daemon setup has changed:"),
         true,
         "Should see 'Daemon setup has changed' at the receiver; instead, saw '{}' at the receiver and '{}' at the setupper.",
         stdout_receiver,
         stdout_setupper
    );
    //TODO the following lines are here to drag attention of somebody.
    // They'll cause an alarm if somebody fixed the bug described in GH-438 without knowing about this test.
    // Remove them in that case.
    // This is associated with the TO-DO above.
    let full_output_length = stdout_receiver.len();
    let wanted_line_length = "Daemon setup has changed".len();
    let stdout_receiver_without_the_message =
        stdout_receiver.replace("Daemon setup has changed", "");
    assert_eq!(
        stdout_receiver_without_the_message.len(),
        full_output_length - wanted_line_length
    )
}
