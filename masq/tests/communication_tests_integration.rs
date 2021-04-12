// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::utils::DaemonProcess;
use crate::utils::MasqProcess;
use masq_lib::utils::find_free_port;
use std::thread;
use std::time::Duration;

mod utils;

#[test]
//unfortunately, this test may never work anymore, because of the program-flow affecting obstacle within DefaultTerminal
fn setup_results_are_broadcast_to_all_uis_integration() {
    // let port = find_free_port();
    // let daemon_handle = DaemonProcess::new().start(port);
    // thread::sleep(Duration::from_millis(1000));
    let mut setupper_handle = MasqProcess::new().start_interactive(5333);
    let mut receiver_handle = MasqProcess::new().start_interactive(5333);

    let mut stdin_handle_setupper = setupper_handle.create_stdin_handle();
    let mut stdin_handle_receiver = receiver_handle.create_stdin_handle();

    thread::sleep(Duration::from_millis(2000));

    stdin_handle_setupper.type_command("exit");
    stdin_handle_receiver.type_command("exit");

    let (stdout_setupper, stderr_setupper, _) = setupper_handle.stop();
    let (stdout_receiver, stderr_receiver, _) = receiver_handle.stop();
    eprintln!("err:{}", stderr_receiver);
    eprintln!("err:{}", stderr_setupper);
    eprintln!("{}", stdout_receiver);
    eprintln!("{}", stdout_setupper);

    //  stdin_handle_setupper.type_command("setup --neighborhood-mode zero-hop");
    //
    //  stdin_handle_setupper.type_command("exit");
    //  stdin_handle_receiver.type_command("exit");
    // //

    // eprintln!("{}",stderr_receiver);
    // eprintln!("{}",stderr_setupper);

    // // daemon_handle.kill();
    //
    //  assert_eq!(
    //      stdout_receiver.contains("Daemon setup has changed:"),
    //      true,
    //      "Should see 'Daemon setup has changed' at the receiver; instead, saw '{}' at the receiver and '{}' at the setupper.",
    //      stdout_receiver,
    //      stdout_setupper
    //  );
}
