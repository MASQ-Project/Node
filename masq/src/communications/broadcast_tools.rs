// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

pub(in crate::communications) mod tools {
    use crate::terminal::terminal_interface::TerminalWrapper;
    use masq_lib::messages::{UiLogBroadcast, UiUndeliveredFireAndForget};
    use masq_lib::short_writeln;
    use masq_lib::ui_gateway::MessageBody;
    use std::io::Write;

    //tested in broadcast_handler.rs

    pub fn handle_node_is_dead_while_f_f_on_the_way_broadcast(
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

    pub fn handle_unrecognized_broadcast(
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

    pub fn handle_ui_log_broadcast(
        body: UiLogBroadcast,
        stdout: &mut dyn Write,
        term_interface: &TerminalWrapper,
    ) {
        let _lock = term_interface.lock();
        write!(stdout, "\n\n>>  {:?}: {}\n\n", body.log_level, body.msg).expect("write! failed");
        stdout.flush().expect("flush failed");
    }
}
