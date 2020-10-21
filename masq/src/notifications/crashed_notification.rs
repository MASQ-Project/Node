// Copyright (c) 2019-2020, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use masq_lib::messages::FromMessageBody;
use masq_lib::messages::{CrashReason, UiNodeCrashedBroadcast};
use masq_lib::ui_gateway::MessageBody;
use masq_lib::utils::exit_process;
use std::io::Write;

pub struct CrashNotifier {}

impl CrashNotifier {
    pub fn handle_broadcast(msg: MessageBody, stdout: &mut dyn Write, _stderr: &mut dyn Write) {
        let (response, _) = UiNodeCrashedBroadcast::fmb(msg.clone())
            .unwrap_or_else(|_| panic!("Bad UiNodeCrashedBroadcast:\n{:?}", msg));
        if response.crash_reason == CrashReason::DaemonCrashed {
            exit_process(1, "The Daemon is no longer running; masq is terminating.\n");
        }
        writeln!(
            stdout,
            "\nThe Node running as process {} terminated{}\nThe Daemon is once more accepting setup changes.\n",
            response.process_id,
            Self::dress_message (response.crash_reason)
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
            CrashReason::NoInformation => panic!("Should never get here"),
            CrashReason::Unrecognized(msg) => msg,
            CrashReason::DaemonCrashed => panic!("Should never get here"),
        }
    }

    fn dress_message(crash_reason: CrashReason) -> String {
        match crash_reason {
            CrashReason::NoInformation => ".".to_string(),
            reason => format!(
                ":\n------\n{}\n------",
                Self::interpret_reason(reason).trim_end().to_string()
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use masq_lib::messages::ToMessageBody;
    use masq_lib::test_utils::fake_stream_holder::ByteArrayWriter;
    use masq_lib::ui_gateway::MessagePath;
    use masq_lib::utils::running_test;

    #[test]
    #[should_panic(
        expected = "Bad UiNodeCrashedBroadcast:\nMessageBody { opcode: \"booga\", path: Conversation(1234), payload: Ok(\"booga\") }"
    )]
    pub fn must_have_real_ui_node_crashed_broadcast() {
        running_test();
        let mut stdout = ByteArrayWriter::new();
        let mut stderr = ByteArrayWriter::new();
        let bad_msg = MessageBody {
            opcode: "booga".to_string(),
            path: MessagePath::Conversation(1234),
            payload: Ok("booga".to_string()),
        };

        CrashNotifier::handle_broadcast(bad_msg, &mut stdout, &mut stderr)
    }

    #[test]
    pub fn handles_child_wait_failure() {
        running_test();
        let mut stdout = ByteArrayWriter::new();
        let mut stderr = ByteArrayWriter::new();
        let msg = UiNodeCrashedBroadcast {
            process_id: 12345,
            crash_reason: CrashReason::ChildWaitFailure("Couldn't wait".to_string()),
        }
        .tmb(0);

        CrashNotifier::handle_broadcast(msg, &mut stdout, &mut stderr);

        assert_eq! (stdout.get_string(), "\nThe Node running as process 12345 terminated:\n------\nthe Daemon couldn't wait on the child process: Couldn't wait\n------\nThe Daemon is once more accepting setup changes.\n\nmasq> ".to_string());
        assert_eq!(stderr.get_string(), "".to_string());
    }

    #[test]
    pub fn handles_unknown_failure() {
        running_test();
        let mut stdout = ByteArrayWriter::new();
        let mut stderr = ByteArrayWriter::new();
        let msg = UiNodeCrashedBroadcast {
            process_id: 12345,
            crash_reason: CrashReason::Unrecognized("Just...failed!\n\n".to_string()),
        }
        .tmb(0);

        CrashNotifier::handle_broadcast(msg, &mut stdout, &mut stderr);

        assert_eq! (stdout.get_string(), "\nThe Node running as process 12345 terminated:\n------\nJust...failed!\n------\nThe Daemon is once more accepting setup changes.\n\nmasq> ".to_string());
        assert_eq!(stderr.get_string(), "".to_string());
    }

    #[test]
    pub fn handles_no_information_failure() {
        running_test();
        let mut stdout = ByteArrayWriter::new();
        let mut stderr = ByteArrayWriter::new();
        let msg = UiNodeCrashedBroadcast {
            process_id: 12345,
            crash_reason: CrashReason::NoInformation,
        }
        .tmb(0);

        CrashNotifier::handle_broadcast(msg, &mut stdout, &mut stderr);

        assert_eq! (stdout.get_string(), "\nThe Node running as process 12345 terminated.\nThe Daemon is once more accepting setup changes.\n\nmasq> ".to_string());
        assert_eq!(stderr.get_string(), "".to_string());
    }

    #[test]
    #[should_panic(expected = "1: The Daemon is no longer running; masq is terminating.")]
    pub fn handles_daemon_crash() {
        running_test();
        let mut stdout = ByteArrayWriter::new();
        let mut stderr = ByteArrayWriter::new();
        let msg = UiNodeCrashedBroadcast {
            process_id: 12345,
            crash_reason: CrashReason::DaemonCrashed,
        }
        .tmb(0);

        CrashNotifier::handle_broadcast(msg, &mut stdout, &mut stderr);
    }
}
