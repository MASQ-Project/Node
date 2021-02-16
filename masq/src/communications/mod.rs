// Copyright (c) 2019-2020, MASQ (https://masq.ai). All rights reserved.
pub mod broadcast_handler;
mod client_listener_thread;
pub mod connection_manager;
pub mod node_conversation;

use masq_lib::messages::UiUndeliveredBroadcast;
use std::io::Write;
//must wait until the right time comes (GH-415?); no real ffm from UI to N so far;
//there is an unresolved problem with synchronization of this print as nobody expects it to come;
//can collide with work with other output such as in line_reader.rs
fn handle_broadcast_for_undelivered_ffm(_body: UiUndeliveredBroadcast, _stdout: &mut dyn Write) {
    //     write!(
    //         stdout,"\
    // The Node is not running but the Daemon received a one-way message addressed to it\n\
    // Opcode: '{}'\n\
    // {}\n\
    // masq> ",
    //         body.opcode, body.original_payload
    //     )
    //     .expect("writeln! failed");
    //     stdout.flush().expect("flush failed");
}
