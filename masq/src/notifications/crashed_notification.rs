// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::masq_short_writeln;
use crate::terminal::TerminalWriter;
use masq_lib::messages::{CrashReason, UiNodeCrashedBroadcast};
#[cfg(target_os = "windows")]
use masq_lib::utils::exit_process;
#[cfg(not(target_os = "windows"))]
use masq_lib::utils::exit_process_with_sigterm;
use std::fmt::format;
use std::io::Write;

pub struct CrashNotifier {}

impl CrashNotifier {
    pub async fn handle_broadcast(
        response: UiNodeCrashedBroadcast,
        stdout: &TerminalWriter,
        stderr: &TerminalWriter,
    ) {
        if response.crash_reason == CrashReason::DaemonCrashed {
            #[cfg(target_os = "windows")]
            exit_process(
                1,
                "\nThe Daemon is no longer running; masq is terminating.\n",
            );

            #[cfg(not(target_os = "windows"))]
            exit_process_with_sigterm("\nThe Daemon is no longer running; masq is terminating.\n")
        }
        masq_short_writeln!(stdout,
            "\nThe Node running as process {} terminated{}\nThe Daemon is once more accepting setup changes.\n",
            response.process_id,
            Self::dress_message (response.crash_reason)
        );
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
    use crate::test_utils::mocks::make_terminal_writer;
    use masq_lib::test_utils::fake_stream_holder::ByteArrayWriter;
    use masq_lib::utils::running_test;
    use std::sync::Arc;

    #[tokio::test]
    async fn handles_child_wait_failure() {
        running_test();
        let msg = UiNodeCrashedBroadcast {
            process_id: 12345,
            crash_reason: CrashReason::ChildWaitFailure("Couldn't wait".to_string()),
        };
        let (stdout, mut stdout_handle) = make_terminal_writer();
        let (stderr, mut stderr_handle) = make_terminal_writer();

        CrashNotifier::handle_broadcast(msg, &stdout, &stderr).await;

        assert_eq! (stdout_handle.drain_test_output(), "\nThe Node running as process 12345 terminated:\n------\nthe Daemon couldn't wait on the child process: Couldn't wait\n------\nThe Daemon is once more accepting setup changes.\n\n".to_string());
        assert_eq!(stderr_handle.drain_test_output(), "".to_string());
    }

    #[tokio::test]
    async fn handles_unknown_failure() {
        running_test();
        let msg = UiNodeCrashedBroadcast {
            process_id: 12345,
            crash_reason: CrashReason::Unrecognized("Just...failed!\n\n".to_string()),
        };
        let (stdout, mut stdout_handle) = make_terminal_writer();
        let (stderr, mut stderr_handle) = make_terminal_writer();

        CrashNotifier::handle_broadcast(msg, &stdout, &stderr).await;

        assert_eq! (stdout_handle.drain_test_output(), "\nThe Node running as process 12345 terminated:\n------\nJust...failed!\n------\nThe Daemon is once more accepting setup changes.\n\n".to_string());
        assert_eq!(stderr_handle.drain_test_output(), "".to_string());
    }

    #[tokio::test]
    async fn handles_no_information_failure() {
        running_test();
        let msg = UiNodeCrashedBroadcast {
            process_id: 12345,
            crash_reason: CrashReason::NoInformation,
        };
        let (stdout, mut stdout_handle) = make_terminal_writer();
        let (stderr, mut stderr_handle) = make_terminal_writer();

        CrashNotifier::handle_broadcast(msg, &stdout, &stderr).await;

        assert_eq! (stdout_handle.drain_test_output(), "\nThe Node running as process 12345 terminated.\nThe Daemon is once more accepting setup changes.\n\n".to_string());
        assert_eq!(stderr_handle.drain_test_output(), "".to_string());
    }

    #[tokio::test]
    #[should_panic(expected = "The Daemon is no longer running; masq is terminating.")]
    async fn handles_daemon_crash() {
        running_test();
        let msg = UiNodeCrashedBroadcast {
            process_id: 12345,
            crash_reason: CrashReason::DaemonCrashed,
        };
        let (stdout, _stdout_handle) = make_terminal_writer();
        let (stderr, _stderr_handle) = make_terminal_writer();

        CrashNotifier::handle_broadcast(msg, &stdout, &stderr).await;
    }
}
