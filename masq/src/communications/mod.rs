// Copyright (c) 2019-2021, MASQ (https://masq.ai). All rights reserved.
pub mod broadcast_handler;
mod client_listener_thread;
pub mod connection_manager;
pub mod node_conversation;

use masq_lib::messages::UiUndeliveredFireAndForget;
use std::io::Write;
//must wait until the right time comes (GH-415?); no real ffm from UI to N so far;
//there is an unresolved problem with synchronization of this print as nobody expects it to come;
//can collide with work with other output such as in line_reader.rs
fn handle_node_not_running_for_fire_and_forget(
    body: UiUndeliveredFireAndForget,
    stdout: &mut dyn Write,
) {
    write!(
        stdout,
        "\nCannot handle {} request: Node is not running\nmasq> ",
        body.opcode
    )
    .expect("write! failed");
    stdout.flush().expect("flush failed");
}
