// Copyright (c) 2019-2020, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use masq_lib::messages::FromMessageBody;
use masq_lib::messages::{CrashReason, UiNodeCrashedBroadcast};
use masq_lib::ui_gateway::MessageBody;
use std::io::Write;

pub struct CrashedNotification {}

impl CrashedNotification {
    pub fn handle_broadcast(msg: MessageBody, stdout: &mut dyn Write, _stderr: &mut dyn Write) {
        let (response, _) = UiNodeCrashedBroadcast::fmb(msg).expect("Bad UiNodeCrashedBroadcast");
        writeln!(
            stdout,
            "\nThe Node running as process {} crashed\n({});\nthe Daemon is once more accepting setup changes.\n",
            response.process_id,
            Self::interpret_reason(response.crash_reason)
        )
            .expect("writeln! failed");
        write!(stdout, "masq> ").expect("write! failed");
        stdout.flush().expect("flush failed");
    }

    fn interpret_reason(reason: CrashReason) -> String {
        match reason {
            CrashReason::ChildWaitFailure(msg) => {
                format!("the Daemon couldn't wait on the child process: {}", msg)
            }
            CrashReason::Unknown(msg) => msg,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use masq_lib::messages::ToMessageBody;
    use masq_lib::test_utils::fake_stream_holder::ByteArrayWriter;
    use masq_lib::ui_gateway::MessagePath;

    #[test]
    #[should_panic(
        expected = "Bad UiNodeCrashedBroadcast: UnexpectedMessage(\"booga\", Conversation(1234))"
    )]
    pub fn must_have_real_ui_node_crashed_broadcast() {
        let mut stdout = ByteArrayWriter::new();
        let mut stderr = ByteArrayWriter::new();
        let bad_msg = MessageBody {
            opcode: "booga".to_string(),
            path: MessagePath::Conversation(1234),
            payload: Ok("booga".to_string()),
        };

        CrashedNotification::handle_broadcast(bad_msg, &mut stdout, &mut stderr)
    }

    #[test]
    pub fn handles_child_wait_failure() {
        let mut stdout = ByteArrayWriter::new();
        let mut stderr = ByteArrayWriter::new();
        let msg = UiNodeCrashedBroadcast {
            process_id: 12345,
            crash_reason: CrashReason::ChildWaitFailure("Couldn't wait".to_string()),
        }
        .tmb(0);

        CrashedNotification::handle_broadcast(msg, &mut stdout, &mut stderr);

        assert_eq! (stdout.get_string(), "\nThe Node running as process 12345 crashed\n(the Daemon couldn't wait on the child process: Couldn't wait);\nthe Daemon is once more accepting setup changes.\n\nmasq> ".to_string());
        assert_eq!(stderr.get_string(), "".to_string());
    }

    #[test]
    pub fn handles_unknown_failure() {
        let mut stdout = ByteArrayWriter::new();
        let mut stderr = ByteArrayWriter::new();
        let msg = UiNodeCrashedBroadcast {
            process_id: 12345,
            crash_reason: CrashReason::Unknown("Just...failed!".to_string()),
        }
        .tmb(0);

        CrashedNotification::handle_broadcast(msg, &mut stdout, &mut stderr);

        assert_eq! (stdout.get_string(), "\nThe Node running as process 12345 crashed\n(Just...failed!);\nthe Daemon is once more accepting setup changes.\n\nmasq> ".to_string());
        assert_eq!(stderr.get_string(), "".to_string());
    }
}
