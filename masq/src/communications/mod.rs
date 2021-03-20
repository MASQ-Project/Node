// Copyright (c) 2019-2021, MASQ (https://masq.ai). All rights reserved.
pub mod broadcast_handler;
mod client_listener_thread;
pub mod connection_manager;
pub mod node_conversation;

use masq_lib::messages::UiUndeliveredFireAndForget;
use std::io::Write;
use std::sync::{Arc, Mutex};

fn handle_node_not_running_for_fire_and_forget(
    body: UiUndeliveredFireAndForget,
    stdout: &mut dyn Write,
    synchronizer: Arc<Mutex<()>>
) {
    let _lock = synchronizer.lock().unwrap();
    write!(
        stdout,
        "\nCannot handle {} request: Node is not running\nmasq> ",
        body.opcode
    )
    .expect("write! failed");
    stdout.flush().expect("flush failed");
    drop(_lock);
}
