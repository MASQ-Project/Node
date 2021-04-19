// Copyright (c) 2019-2021, MASQ (https://masq.ai). All rights reserved.

use crate::commands::change_password_command::ChangePasswordCommand;
use crate::commands::setup_command::SetupCommand;
use crate::communications::handle_node_not_running_for_fire_and_forget_on_the_way;
use crate::notifications::crashed_notification::CrashNotifier;
use crate::terminal_interface::TerminalWrapper;
use crossbeam_channel::{unbounded, Receiver, RecvError, Sender};
use masq_lib::messages::{
    FromMessageBody, UiNewPasswordBroadcast, UiNodeCrashedBroadcast, UiSetupBroadcast,
    UiUndeliveredFireAndForget,
};
use masq_lib::ui_gateway::MessageBody;
use std::fmt::Debug;
use std::io::Write;
use std::thread;

pub trait BroadcastHandle: Send {
    fn send(&self, message_body: MessageBody);
}

pub struct BroadcastHandleInactive {}

impl BroadcastHandle for BroadcastHandleInactive {
    //simply dropped (unless we find a better use for such a message)
    fn send(&self, _message_body: MessageBody) {}
}

#[allow(clippy::new_without_default)]
impl BroadcastHandleInactive {
    pub fn new() -> Self {
        Self {}
    }
}

pub struct BroadcastHandleGeneric {
    message_tx: Sender<MessageBody>,
}

impl BroadcastHandle for BroadcastHandleGeneric {
    fn send(&self, message_body: MessageBody) {
        self.message_tx
            .send(message_body)
            .expect("Message send failed")
    }
}

pub trait BroadcastHandler {
    fn start(self, stream_factory: Box<dyn StreamFactory>) -> Box<dyn BroadcastHandle>;
}

pub struct BroadcastHandlerReal {
    terminal_interface: Option<TerminalWrapper>,
}

impl BroadcastHandler for BroadcastHandlerReal {
    fn start(mut self, stream_factory: Box<dyn StreamFactory>) -> Box<dyn BroadcastHandle> {
        let (message_tx, message_rx) = unbounded();
        thread::spawn(move || {
            let (mut stdout, mut stderr) = stream_factory.make();
            let terminal_interface = self
                .terminal_interface
                .take()
                .expect("BroadcastHandlerReal: start: some was expected");
            loop {
                Self::thread_loop_guts(
                    &message_rx,
                    stdout.as_mut(),
                    stderr.as_mut(),
                    terminal_interface.clone(),
                )
            }
        });
        Box::new(BroadcastHandleGeneric { message_tx })
    }
}

impl BroadcastHandlerReal {
    pub fn new(terminal_interface: Option<TerminalWrapper>) -> Self {
        Self { terminal_interface }
    }

    fn handle_message_body(
        message_body_result: Result<MessageBody, RecvError>,
        stdout: &mut dyn Write,
        stderr: &mut dyn Write,
        terminal_interface: TerminalWrapper,
    ) {
        match message_body_result {
            Err(_) => (), // Receiver died; masq is going down
            Ok(message_body) => {
                if let Ok((body, _)) = UiSetupBroadcast::fmb(message_body.clone()) {
                    SetupCommand::handle_broadcast(body, stdout, terminal_interface);
                } else if let Ok((body, _)) = UiNodeCrashedBroadcast::fmb(message_body.clone()) {
                    CrashNotifier::handle_broadcast(body, stdout, terminal_interface);
                } else if let Ok((body, _)) = UiNewPasswordBroadcast::fmb(message_body.clone()) {
                    ChangePasswordCommand::handle_broadcast(body, stdout, terminal_interface);
                } else if let Ok((body, _)) = UiUndeliveredFireAndForget::fmb(message_body.clone())
                {
                    handle_node_not_running_for_fire_and_forget_on_the_way(
                        body,
                        stdout,
                        terminal_interface,
                    );
                } else {
                    write!(
                        stderr,
                        "Discarding unrecognized broadcast with opcode '{}'\n\nmasq> ",
                        message_body.opcode
                    )
                    .expect("write! failed");
                }
            }
        }
    }

    fn thread_loop_guts(
        message_rx: &Receiver<MessageBody>,
        stdout: &mut dyn Write,
        stderr: &mut dyn Write,
        terminal_interface: TerminalWrapper,
    ) {
        select! {
            recv(message_rx) -> message_body_result => Self::handle_message_body (message_body_result, stdout, stderr,terminal_interface)
        }
    }
}

pub trait StreamFactory: Send + Debug {
    fn make(&self) -> (Box<dyn Write>, Box<dyn Write>);
}

#[derive(Clone, PartialEq, Debug)]
pub struct StreamFactoryReal;

impl StreamFactory for StreamFactoryReal {
    fn make(&self) -> (Box<dyn Write>, Box<dyn Write>) {
        (Box::new(std::io::stdout()), Box::new(std::io::stderr()))
    }
}

impl Default for StreamFactoryReal {
    fn default() -> Self {
        Self::new()
    }
}

impl StreamFactoryReal {
    pub fn new() -> Self {
        Self {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::mocks::{MixingStdout, TerminalActiveMock, TestStreamFactory};
    use masq_lib::messages::{CrashReason, ToMessageBody, UiNodeCrashedBroadcast};
    use masq_lib::messages::{UiSetupBroadcast, UiSetupResponseValue, UiSetupResponseValueStatus};
    use masq_lib::ui_gateway::MessagePath;
    use std::time::Duration;

    #[test]
    fn broadcast_of_setup_triggers_correct_handler() {
        let (factory, handle) = TestStreamFactory::new();
        // This thread will leak, and will only stop when the tests stop running.
        let subject = BroadcastHandlerReal::new(Some(TerminalWrapper::new(Box::new(
            TerminalActiveMock::new(),
        ))))
        .start(Box::new(factory));
        let message = UiSetupBroadcast {
            running: true,
            values: vec![],
            errors: vec![],
        }
        .tmb(0);

        subject.send(message);

        let stdout = handle.stdout_so_far();
        assert_eq!(
            stdout.contains("the Node is currently running"),
            true,
            "stdout: '{}' doesn't contain 'the Node is currently running'",
            stdout
        );

        assert_eq!(
            handle.stderr_so_far(),
            "".to_string(),
            "stderr: '{}'",
            stdout
        );
    }

    #[test]
    fn broadcast_of_crashed_triggers_correct_handler() {
        let (factory, handle) = TestStreamFactory::new();
        // This thread will leak, and will only stop when the tests stop running.
        let subject = BroadcastHandlerReal::new(Some(TerminalWrapper::new(Box::new(
            TerminalActiveMock::new(),
        ))))
        .start(Box::new(factory));
        let message = UiNodeCrashedBroadcast {
            process_id: 1234,
            crash_reason: CrashReason::Unrecognized("Unknown crash reason".to_string()),
        }
        .tmb(0);

        subject.send(message);

        let stdout = handle.stdout_so_far();
        assert_eq!(
            stdout,
            "\nThe Node running as process 1234 terminated:\n------\nUnknown crash reason\n\
            ------\nThe Daemon is once more accepting setup changes.\n\n"
                .to_string()
        );
        assert_eq!(
            handle.stderr_so_far(),
            "".to_string(),
            "stderr: '{}'",
            stdout
        );
    }

    #[test]
    fn broadcast_of_new_password_triggers_correct_handler() {
        let (factory, handle) = TestStreamFactory::new();
        // This thread will leak, and will only stop when the tests stop running.
        let subject = BroadcastHandlerReal::new(Some(TerminalWrapper::new(Box::new(
            TerminalActiveMock::new(),
        ))))
        .start(Box::new(factory));
        let message = UiNewPasswordBroadcast {}.tmb(0);

        subject.send(message);

        let stdout = handle.stdout_so_far();
        assert_eq!(
            stdout,
            "\nThe Node's database password has changed.\n\n".to_string()
        );
        assert_eq!(
            handle.stderr_so_far(),
            "".to_string(),
            "stderr: '{}'",
            stdout
        );
    }

    #[test]
    fn broadcast_of_undelivered_ff_message_triggers_correct_handler() {
        let (factory, handle) = TestStreamFactory::new();
        // This thread will leak, and will only stop when the tests stop running.
        let subject = BroadcastHandlerReal::new(Some(TerminalWrapper::new(Box::new(
            TerminalActiveMock::new(),
        ))))
        .start(Box::new(factory));
        let message = UiUndeliveredFireAndForget {
            opcode: "uninventedMessage".to_string(),
        }
        .tmb(0);

        subject.send(message);

        let stdout = handle.stdout_so_far();
        assert_eq!(
            stdout,
            "\nCannot handle uninventedMessage request: Node is not running.\n\n".to_string()
        );
        assert_eq!(
            handle.stderr_so_far(),
            "".to_string(),
            "stderr: '{}'",
            stdout
        );
    }

    #[test]
    fn unexpected_broadcasts_are_ineffectual_but_dont_kill_the_handler() {
        let (factory, handle) = TestStreamFactory::new();
        // This thread will leak, and will only stop when the tests stop running.
        let subject = BroadcastHandlerReal::new(Some(TerminalWrapper::new(Box::new(
            TerminalActiveMock::new(),
        ))))
        .start(Box::new(factory));
        let bad_message = MessageBody {
            opcode: "unrecognized".to_string(),
            path: MessagePath::FireAndForget,
            payload: (Ok("".to_string())),
        };
        let good_message = UiSetupBroadcast {
            running: true,
            values: vec![],
            errors: vec![],
        }
        .tmb(0);

        subject.send(bad_message);

        assert_eq!(handle.stdout_so_far(), String::new());
        assert_eq!(
            handle.stderr_so_far(),
            ("Discarding unrecognized broadcast with opcode 'unrecognized'\n\nmasq> ")
        );

        subject.send(good_message);

        let stdout = handle.stdout_so_far();
        assert_eq!(
            stdout.contains("the Node is currently running"),
            true,
            "stdout: '{}' doesn't contain 'the Node is currently running'",
            stdout
        );
        assert_eq!(handle.stderr_so_far(), String::new());
    }

    #[test]
    fn setup_command_handle_broadcast_has_a_synchronizer_correctly_implemented() {
        let setup_body = UiSetupBroadcast {
            running: false,
            values: vec![
                UiSetupResponseValue {
                    name: "ip".to_string(),
                    value: "4.4.4.4".to_string(),
                    status: UiSetupResponseValueStatus::Set,
                },
                UiSetupResponseValue {
                    name: "neighborhood-mode".to_string(),
                    value: "standard".to_string(),
                    status: UiSetupResponseValueStatus::Default,
                },
                UiSetupResponseValue {
                    name: "chain".to_string(),
                    value: "ropsten".to_string(),
                    status: UiSetupResponseValueStatus::Configured,
                },
                UiSetupResponseValue {
                    name: "log-level".to_string(),
                    value: "error".to_string(),
                    status: UiSetupResponseValueStatus::Set,
                },
            ],
            errors: vec![],
        };

        //for the sake of simplification, tested on a small sample of setup parameters
        //(the message is composed out of those entries in the vector above)
        let broadcast_output = "Daemon setup has changed:

NAME                   VALUE                                                            STATUS
chain                  ropsten                                                          Configured
ip                     4.4.4.4                                                          Set
log-level              error                                                            Set
neighborhood-mode      standard                                                         Default
";

        test_generic_for_handle_broadcast(
            SetupCommand::handle_broadcast,
            setup_body,
            broadcast_output,
        )
    }

    #[test]
    fn crash_notifier_handle_broadcast_has_a_synchronizer_correctly_implemented() {
        let crash_notifier_body = UiNodeCrashedBroadcast {
            process_id: 100,
            crash_reason: CrashReason::NoInformation,
        };

        let broadcast_output = "\
The Node running as process 100 terminated.
The Daemon is once more accepting setup changes.

";

        test_generic_for_handle_broadcast(
            CrashNotifier::handle_broadcast,
            crash_notifier_body,
            broadcast_output,
        )
    }

    #[test]
    fn change_password_handle_broadcast_has_a_synchronizer_correctly_implemented() {
        let change_password_body = UiNewPasswordBroadcast {};

        let broadcast_output = "\
The Node's database password has changed.

";

        test_generic_for_handle_broadcast(
            ChangePasswordCommand::handle_broadcast,
            change_password_body,
            broadcast_output,
        )
    }

    #[test]
    fn ffm_undelivered_as_node_not_running_handle_broadcast_has_a_synchronizer_correctly_implemented(
    ) {
        let ffm_undelivered_body = UiUndeliveredFireAndForget {
            opcode: "crash".to_string(),
        };

        let broadcast_output = "\
Cannot handle crash request: Node is not running.

";

        test_generic_for_handle_broadcast(
            handle_node_not_running_for_fire_and_forget_on_the_way,
            ffm_undelivered_body,
            broadcast_output,
        )
    }

    fn test_generic_for_handle_broadcast<F, U>(
        broadcast_handler: F,
        broadcast_message_body: U,
        broadcast_desired_output: &str,
    ) where
        F: FnOnce(U, &mut dyn Write, TerminalWrapper) + Copy,
        U: Debug + PartialEq + Clone,
    {
        let (tx, rx) = unbounded();
        let mut stdout = MixingStdout::new(tx);
        let stdout_clone = stdout.clone();
        let stdout_second_clone = stdout.clone();

        let synchronizer = TerminalWrapper::new(Box::new(TerminalActiveMock::new()));

        let synchronizer_clone_idle = synchronizer.clone();

        //synchronized part proving that the broadcast print is synchronized
        let full_stdout_output_sync = background_thread_making_interferences(
            true,
            &mut stdout,
            Box::new(stdout_clone),
            synchronizer,
            broadcast_handler,
            broadcast_message_body.clone(),
            rx.clone(),
        );

        assert!(
            full_stdout_output_sync.contains(broadcast_desired_output),
            "The message from the broadcast handle isn't correct or entire: {}",
            full_stdout_output_sync
        );
        assert!(
            full_stdout_output_sync.contains(&format!("{}", "*".repeat(40))),
            "Each group of 40 asterisks must keep together: {}",
            full_stdout_output_sync
        );

        //unsynchronized part proving that the broadcast print would be messed without synchronization
        let full_stdout_output_without_sync = background_thread_making_interferences(
            false,
            &mut stdout,
            Box::new(stdout_second_clone),
            synchronizer_clone_idle,
            broadcast_handler,
            broadcast_message_body,
            rx,
        );

        let prefabricated_string = full_stdout_output_without_sync
            .chars()
            .filter(|char| *char == '*' || *char == ' ')
            .collect::<String>();
        let incomplete_row = prefabricated_string
            .split(' ')
            .find(|row| !row.contains(&"*".repeat(40)) && row.contains("*"));
        assert!(
            incomplete_row.is_some(),
            "There mustn't be 40 asterisks together at one of these: {}",
            full_stdout_output_without_sync
        );
        let asterisks_count = full_stdout_output_without_sync
            .chars()
            .filter(|char| *char == '*')
            .count();
        assert_eq!(
            asterisks_count, 40,
            "The count of asterisks isn't 40 but: {}",
            asterisks_count
        );
    }

    fn background_thread_making_interferences<F, U>(
        sync: bool,
        stdout: &mut dyn Write,
        mut stdout_clone: Box<dyn Write + Send>,
        synchronizer: TerminalWrapper,
        broadcast_handler: F,
        broadcast_message_body: U,
        mixed_stdout_receiver: Receiver<String>,
    ) -> String
    where
        F: FnOnce(U, &mut dyn Write, TerminalWrapper) + Copy,
        U: Debug + PartialEq + Clone,
    {
        let synchronizer_clone = synchronizer.clone();
        let (sync_tx, sync_rx) = std::sync::mpsc::channel();
        let interference_thread_handle = thread::spawn(move || {
            let _lock = if sync {
                Some(synchronizer.lock())
            } else {
                None
            };
            (0..40).into_iter().for_each(|i| {
                stdout_clone.write(b"*").unwrap();
                thread::sleep(Duration::from_millis(1));
                if i == 5 {
                    sync_tx.send(()).unwrap()
                };
            });
            drop(_lock)
        });
        sync_rx.recv().unwrap();
        broadcast_handler(broadcast_message_body.clone(), stdout, synchronizer_clone);

        interference_thread_handle.join().unwrap();

        let mut buffer = String::new();
        let full_stdout_output = loop {
            match mixed_stdout_receiver.try_recv() {
                Ok(string) => buffer.push_str(&string),
                Err(_) => break buffer,
            }
        };
        full_stdout_output
    }
}
