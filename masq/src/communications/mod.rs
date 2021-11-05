// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
pub mod broadcast_handler;
mod client_listener_thread;
pub mod connection_manager;
pub mod node_conversation;

use crate::terminal::terminal_interface::TerminalWrapper;
use masq_lib::messages::UiUndeliveredFireAndForget;
use masq_lib::short_writeln;
use masq_lib::ui_gateway::MessageBody;
use std::io::Write;

fn handle_node_is_dead_while_f_f_on_the_way_broadcast(
    body: UiUndeliveredFireAndForget,
    stdout: &mut dyn Write,
    term_interface: &TerminalWrapper,
) {
    let _lock = term_interface.lock();
    short_writeln!(
        stdout,
        "\nCannot handle {} request: Node is not running.\n",
        body.opcode
    );
    stdout.flush().expect("flush failed");
}

fn handle_unrecognized_broadcast(
    message_body: MessageBody,
    stderr: &mut dyn Write,
    term_interface: &TerminalWrapper,
) {
    let _lock = term_interface.lock();
    short_writeln!(
        stderr,
        "Discarding unrecognized broadcast with opcode '{}'\n",
        message_body.opcode
    )
}
