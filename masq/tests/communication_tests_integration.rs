// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::utils::DaemonProcess;
use crate::utils::MasqProcess;
use masq_lib::utils::find_free_port;
use std::thread;
use std::time::Duration;

mod utils;

#[test]
fn setup_results_are_broadcast_to_all_uis_integration() {
    let port = find_free_port();
    let daemon_handle = DaemonProcess::new().start(port);
    thread::sleep(Duration::from_millis(300));
    let mut setupper_handle = MasqProcess::new().start_interactive(port, true);
    let mut receiver_handle = MasqProcess::new().start_interactive(port, true);

    let mut stdin_handle_setupper = setupper_handle.create_stdin_handle();
    let mut stdin_handle_receiver = receiver_handle.create_stdin_handle();

    //TODO This first "setup" call shouldn't be necessary. Will be investigated within GH-438
    stdin_handle_setupper.type_command("setup --dns-servers 4.5.6.5");

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

    //TODO the following lines are here to cause a failure once GH-438 fixes what it should fix; Please, remove them then
    let full_output_length = stdout_receiver.len();
    let wanted_line_length = "Daemon setup has changed".len();
    let stdout_receiver_without_the_message =
        stdout_receiver.replace("Daemon setup has changed", "");
    assert_eq!(
        stdout_receiver_without_the_message.len(),
        full_output_length - wanted_line_length
    )
}
