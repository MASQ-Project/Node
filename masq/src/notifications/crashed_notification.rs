// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::terminal::terminal_interface::TerminalWrapper;
use masq_lib::messages::{CrashReason, UiNodeCrashedBroadcast};
use masq_lib::short_writeln;
#[cfg(target_os = "windows")]
use masq_lib::utils::exit_process;
#[cfg(not(target_os = "windows"))]
use masq_lib::utils::exit_process_with_sigterm;
use std::io::Write;

pub struct CrashNotifier {}

impl CrashNotifier {
    pub fn handle_broadcast(
        response: UiNodeCrashedBroadcast,
        stdout: &mut dyn Write,
        term_interface: &TerminalWrapper,
    ) {
        let _lock = term_interface.lock();
        if response.crash_reason == CrashReason::DaemonCrashed {
            #[cfg(target_os = "windows")]
            exit_process(
                1,
                "\nThe Daemon is no longer running; masq is terminating.\n",
            );

            #[cfg(not(target_os = "windows"))]
            exit_process_with_sigterm("\nThe Daemon is no longer running; masq is terminating.\n")
        }
        short_writeln!(
            stdout,
            "\nThe Node running as process {} terminated{}\nThe Daemon is once more accepting setup changes.\n",
            response.process_id,
            Self::dress_message (response.crash_reason)
        );
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
                Self::interpret_reason(reason).trim_end()
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::mocks::TerminalPassiveMock;
    use masq_lib::test_utils::fake_stream_holder::ByteArrayWriter;
    use masq_lib::utils::running_test;
    use std::sync::Arc;

    #[test]
    pub fn handles_child_wait_failure() {
        running_test();
        let mut stdout = ByteArrayWriter::new();
        let stderr = ByteArrayWriter::new();
        let msg = UiNodeCrashedBroadcast {
            process_id: 12345,
            crash_reason: CrashReason::ChildWaitFailure("Couldn't wait".to_string()),
        };
        let term_interface = TerminalWrapper::new(Arc::new(TerminalPassiveMock::new()));

        CrashNotifier::handle_broadcast(msg, &mut stdout, &term_interface);

        assert_eq! (stdout.get_string(), "\nThe Node running as process 12345 terminated:\n------\nthe Daemon couldn't wait on the child process: Couldn't wait\n------\nThe Daemon is once more accepting setup changes.\n\n".to_string());
        assert_eq!(stderr.get_string(), "".to_string());
    }

    #[test]
    pub fn handles_unknown_failure() {
        running_test();
        let mut stdout = ByteArrayWriter::new();
        let stderr = ByteArrayWriter::new();
        let msg = UiNodeCrashedBroadcast {
            process_id: 12345,
            crash_reason: CrashReason::Unrecognized("Just...failed!\n\n".to_string()),
        };
        let term_interface = TerminalWrapper::new(Arc::new(TerminalPassiveMock::new()));

        CrashNotifier::handle_broadcast(msg, &mut stdout, &term_interface);

        assert_eq! (stdout.get_string(), "\nThe Node running as process 12345 terminated:\n------\nJust...failed!\n------\nThe Daemon is once more accepting setup changes.\n\n".to_string());
        assert_eq!(stderr.get_string(), "".to_string());
    }

    #[test]
    pub fn handles_no_information_failure() {
        running_test();
        let mut stdout = ByteArrayWriter::new();
        let stderr = ByteArrayWriter::new();
        let msg = UiNodeCrashedBroadcast {
            process_id: 12345,
            crash_reason: CrashReason::NoInformation,
        };
        let term_interface = TerminalWrapper::new(Arc::new(TerminalPassiveMock::new()));

        CrashNotifier::handle_broadcast(msg, &mut stdout, &term_interface);

        assert_eq! (stdout.get_string(), "\nThe Node running as process 12345 terminated.\nThe Daemon is once more accepting setup changes.\n\n".to_string());
        assert_eq!(stderr.get_string(), "".to_string());
    }

    #[test]
    #[should_panic(expected = "The Daemon is no longer running; masq is terminating.")]
    pub fn handles_daemon_crash() {
        running_test();
        let mut stdout = ByteArrayWriter::new();
        let msg = UiNodeCrashedBroadcast {
            process_id: 12345,
            crash_reason: CrashReason::DaemonCrashed,
        };
        let term_interface = TerminalWrapper::new(Arc::new(TerminalPassiveMock::new()));

        CrashNotifier::handle_broadcast(msg, &mut stdout, &term_interface);
    }
}
