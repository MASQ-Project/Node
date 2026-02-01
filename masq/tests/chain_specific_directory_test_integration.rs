// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::utils::{DaemonProcess, MasqProcess};
use masq_lib::utils::find_free_port;
use std::thread;
use std::time::Duration;

mod utils;

#[test]
fn ensure_data_directory_has_specific_chain_directory_within_integration() {
    let port = find_free_port();
    let daemon_handle = DaemonProcess::new().start(port.clone());
    let masq_handle = MasqProcess::new().start_noninteractive(vec![
        "--ui-port",
        *&port.to_string().to_owned().as_str(),
        "setup",
    ]);
    let (stdout, _stderr, _exit_code) = masq_handle.stop();
    let mut masq_handle2 = MasqProcess::new().start_interactive(port, true);
    let mut stdin_handle = masq_handle2.create_stdin_handle();

    stdin_handle.type_command("setup --data-directory /home/booga/masqhome/base-mainnet");

    thread::sleep(Duration::from_millis(1000));

    stdin_handle.type_command("exit");

    let (stdout2, _stderr2, _exit_code2) = masq_handle2.stop();
    let expected = format!(
        "{:29} {:64} {}",
        "data-directory", "/home/booga/masqhome/base-mainnet", "Set"
    );

    assert!(
        !stdout.contains("MASQ/base-mainnet/MASQ/base-mainnet Default"),
        "Wrong directory: duplication of /MASQ/base-mainnet when Default"
    );
    assert!(
        stdout2.contains(&expected),
        "Wrong directory: missing chain specific directory when Set:\nstdout: {}\n",
        stdout2
    );

    daemon_handle.kill();
}
