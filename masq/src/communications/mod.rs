// Copyright (c) 2019-2021, MASQ (https://masq.ai). All rights reserved.
pub mod broadcast_handler;
mod client_listener_thread;
pub mod connection_manager;
pub mod node_conversation;

use crate::terminal_interface::TerminalWrapper;
use masq_lib::messages::UiUndeliveredFireAndForget;
use std::io::Write;

fn handle_node_not_running_for_fire_and_forget_on_the_way(
    body: UiUndeliveredFireAndForget,
    stdout: &mut dyn Write,
    term_interface: TerminalWrapper,
) {
    let _lock = term_interface.lock();
    write!(
        stdout,
        "\nCannot handle {} request: Node is not running.\n\nmasq> ",
        body.opcode
    )
    .expect("write! failed");
    stdout.flush().expect("flush failed");
}
