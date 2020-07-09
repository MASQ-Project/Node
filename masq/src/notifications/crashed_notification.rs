// Copyright (c) 2019-2020, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use std::io::Write;
use masq_lib::ui_gateway::MessageBody;
use masq_lib::messages::UiNodeCrashedBroadcast;
use masq_lib::messages::FromMessageBody;

pub struct CrashedNotification {}

impl CrashedNotification {
    pub fn handle_broadcast(msg: MessageBody, stdout: &mut dyn Write, _stderr: &mut dyn Write) {
        let (response, _) = UiNodeCrashedBroadcast::fmb(msg).expect("Bad UiNodeCrashedBroadcast");
        writeln!(stdout, "\nThe Node running as process {} crashed;\nthe Daemon is once more accepting setup changes.\n", response.process_id).expect("writeln! failed");
        write!(stdout, "masq> ").expect("write! failed");
        stdout.flush().expect("flush failed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use masq_lib::test_utils::fake_stream_holder::{ByteArrayWriter};
    use masq_lib::ui_gateway::MessagePath;

    #[test]
    #[should_panic(expected = "Bad UiNodeCrashedBroadcast: UnexpectedMessage(\"booga\", Conversation(1234))")]
    pub fn must_have_real_ui_node_crashed_broadcast () {
        let mut stdout = ByteArrayWriter::new();
        let mut stderr = ByteArrayWriter::new();
        let bad_msg = MessageBody {
            opcode: "booga".to_string(),
            path: MessagePath::Conversation(1234),
            payload: Ok("booga".to_string()),
        };

        CrashedNotification::handle_broadcast(bad_msg, &mut stdout, &mut stderr)
    }
}