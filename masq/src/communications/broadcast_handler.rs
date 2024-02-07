// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::commands::change_password_command::ChangePasswordCommand;
use crate::commands::setup_command::SetupCommand;
use crate::notifications::crashed_notification::CrashNotifier;
use crate::terminal::terminal_interface::TerminalWrapper;
use crossbeam_channel::{unbounded, RecvError, Sender};
use masq_lib::messages::{
    FromMessageBody, UiConnectionChangeBroadcast, UiLogBroadcast, UiNewPasswordBroadcast,
    UiNodeCrashedBroadcast, UiSetupBroadcast, UiUndeliveredFireAndForget,
};
use masq_lib::ui_gateway::MessageBody;
use masq_lib::utils::ExpectValue;
use masq_lib::{as_any_ref_in_trait, as_any_ref_in_trait_impl, short_writeln};
use std::fmt::Debug;
use std::io::Write;
use std::thread;

use crate::notifications::connection_change_notification::ConnectionChangeNotification;

pub trait BroadcastHandle: Send {
    fn send(&self, message_body: MessageBody);
    as_any_ref_in_trait!();
}

pub struct BroadcastHandleInactive;

impl BroadcastHandle for BroadcastHandleInactive {
    //simply dropped (unless we find a better use for such a message)
    fn send(&self, _message_body: MessageBody) {}
    as_any_ref_in_trait_impl!();
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
                .expectv("Some(TerminalWrapper)");
            //release the loop if masq has died (testing concerns)
            let mut flag = true;
            while flag {
                flag = Self::handle_message_body(
                    message_rx.recv(),
                    stdout.as_mut(),
                    stderr.as_mut(),
                    &terminal_interface,
                );
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
        terminal_interface: &TerminalWrapper,
    ) -> bool {
        match message_body_result {
            Err(_) => false, // Receiver died; masq is going down
            Ok(message_body) => {
                if let Ok((body, _)) = UiLogBroadcast::fmb(message_body.clone()) {
                    handle_ui_log_broadcast(body, stdout, terminal_interface)
                } else if let Ok((body, _)) = UiSetupBroadcast::fmb(message_body.clone()) {
                    SetupCommand::handle_broadcast(body, stdout, terminal_interface);
                } else if let Ok((body, _)) = UiNodeCrashedBroadcast::fmb(message_body.clone()) {
                    CrashNotifier::handle_broadcast(body, stdout, terminal_interface);
                } else if let Ok((body, _)) = UiNewPasswordBroadcast::fmb(message_body.clone()) {
                    ChangePasswordCommand::handle_broadcast(body, stdout, terminal_interface);
                } else if let Ok((body, _)) = UiUndeliveredFireAndForget::fmb(message_body.clone())
                {
                    handle_node_is_dead_while_f_f_on_the_way_broadcast(
                        body,
                        stdout,
                        terminal_interface,
                    );
                } else if let Ok((body, _)) = UiConnectionChangeBroadcast::fmb(message_body.clone())
                {
                    ConnectionChangeNotification::handle_broadcast(
                        body,
                        stdout,
                        terminal_interface,
                    );
                } else {
                    handle_unrecognized_broadcast(message_body, stderr, terminal_interface)
                }
                true
            }
        }
    }
}

pub trait StreamFactory: Send + Debug {
    fn make(&self) -> (Box<dyn Write>, Box<dyn Write>);
}

#[derive(Clone, PartialEq, Eq, Debug)]
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
    );
    stderr.flush().expect("flush failed");
}

pub fn handle_ui_log_broadcast(
    body: UiLogBroadcast,
    stdout: &mut dyn Write,
    term_interface: &TerminalWrapper,
) {
    let _lock = term_interface.lock();
    short_writeln!(stdout, "\n\n>>  {:?}: {}\n", body.log_level, body.msg);
    stdout.flush().expect("flush failed");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::mocks::{
        make_tools_for_test_streams_with_thread_life_checker, StdoutBlender, TerminalActiveMock,
        TerminalPassiveMock, TestStreamFactory,
    };
    use crossbeam_channel::{bounded, unbounded, Receiver};
    use masq_lib::messages::UiSetupResponseValueStatus::{Configured, Default};
    use masq_lib::messages::{
        CrashReason, SerializableLogLevel, ToMessageBody, UiConnectionChangeBroadcast,
        UiConnectionStage, UiLogBroadcast, UiNodeCrashedBroadcast,
    };
    use masq_lib::messages::{UiSetupBroadcast, UiSetupResponseValue, UiSetupResponseValueStatus};
    use masq_lib::ui_gateway::MessagePath;
    use std::sync::Arc;
    use std::time::Duration;

    #[test]
    fn broadcast_of_setup_triggers_correct_handler() {
        let (factory, handle) = TestStreamFactory::new();
        let subject = BroadcastHandlerReal::new(Some(TerminalWrapper::new(Arc::new(
            TerminalPassiveMock::new(),
        ))))
        .start(Box::new(factory));
        let message = UiSetupBroadcast {
            running: true,
            values: vec![
                UiSetupResponseValue::new("chain", "eth-ropsten", Configured),
                UiSetupResponseValue::new("data-directory", "/home/booga", Default),
            ],
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
    fn broadcast_of_ui_log_was_successful() {
        let (factory, handle) = TestStreamFactory::new();
        let subject = BroadcastHandlerReal::new(Some(TerminalWrapper::new(Arc::new(
            TerminalPassiveMock::new(),
        ))))
        .start(Box::new(factory));
        let message = masq_lib::messages::UiLogBroadcast {
            msg: "Empty. No Nodes to report to; continuing".to_string(),
            log_level: SerializableLogLevel::Info,
        }
        .tmb(0);

        subject.send(message);

        let stdout = handle.stdout_so_far();
        assert_eq!(
            stdout,
            "\n\n>>  Info: Empty. No Nodes to report to; continuing\n\n",
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
        let subject = BroadcastHandlerReal::new(Some(TerminalWrapper::new(Arc::new(
            TerminalPassiveMock::new(),
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
        let subject = BroadcastHandlerReal::new(Some(TerminalWrapper::new(Arc::new(
            TerminalPassiveMock::new(),
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
        let subject = BroadcastHandlerReal::new(Some(TerminalWrapper::new(Arc::new(
            TerminalPassiveMock::new(),
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
    fn ui_connection_change_broadcast_is_handled_properly() {
        let (factory, handle) = TestStreamFactory::new();
        let (mut stdout, mut stderr) = factory.make();
        let terminal_interface = TerminalWrapper::new(Arc::new(TerminalPassiveMock::new()));

        let message_body = UiConnectionChangeBroadcast {
            stage: UiConnectionStage::ConnectedToNeighbor,
        }
        .tmb(0);

        let result = BroadcastHandlerReal::handle_message_body(
            Ok(message_body),
            &mut stdout,
            &mut stderr,
            &terminal_interface,
        );

        assert_eq!(result, true);
        let stdout = handle.stdout_so_far();
        assert_eq!(
            stdout,
            "\nConnectedToNeighbor: Established neighborship with an external node.\n\n"
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
    fn unexpected_broadcasts_are_ineffectual_but_dont_kill_the_handler() {
        let (factory, handle) = TestStreamFactory::new();
        let subject = BroadcastHandlerReal::new(Some(TerminalWrapper::new(Arc::new(
            TerminalPassiveMock::new(),
        ))))
        .start(Box::new(factory));
        let bad_message = MessageBody {
            opcode: "unrecognized".to_string(),
            path: MessagePath::FireAndForget,
            payload: (Ok("".to_string())),
        };
        let good_message = UiSetupBroadcast {
            running: true,
            values: vec![
                UiSetupResponseValue::new("chain", "eth-ropsten", Configured),
                UiSetupResponseValue::new("data-directory", "/home/booga", Default),
            ],
            errors: vec![],
        }
        .tmb(0);

        subject.send(bad_message);

        assert_eq!(handle.stdout_so_far(), String::new());
        assert_eq!(
            handle.stderr_so_far(),
            ("Discarding unrecognized broadcast with opcode 'unrecognized'\n\n")
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
    fn broadcast_handler_thread_terminates_immediately_if_it_senses_that_masq_is_gone() {
        let (life_checker_handle, stream_factory, stream_handle) =
            make_tools_for_test_streams_with_thread_life_checker();
        let broadcast_handler_real = BroadcastHandlerReal::new(Some(TerminalWrapper::new(
            Arc::new(TerminalPassiveMock::new()),
        )));
        let broadcast_handle = broadcast_handler_real.start(Box::new(stream_factory));
        let example_broadcast = UiNewPasswordBroadcast {}.tmb(0);
        broadcast_handle.send(example_broadcast);

        let stdout_content = stream_handle.stdout_so_far();

        assert_eq!(
            stdout_content,
            "\
       \nThe Node's database password has changed.\n\n"
        );

        //I'm dropping this handle...handler should next terminate.
        drop(broadcast_handle);

        //we should get a message meaning that objects in the background thread were dropped before the thread stopped to exist
        let result = life_checker_handle.recv_timeout(Duration::from_millis(100));

        assert!(result.is_ok())
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
                UiSetupResponseValue {
                    name: "data-directory".to_string(),
                    value: "/home/booga".to_string(),
                    status: UiSetupResponseValueStatus::Default,
                },
            ],
            errors: vec![],
        };

        //for the sake of simplification, tested on a small sample of setup parameters
        //(the message is composed out of those entries in the vector above)
        let broadcast_output = "Daemon setup has changed:

NAME                          VALUE                                                            STATUS
chain                         ropsten                                                          Configured
data-directory                /home/booga                                                      Default
ip                            4.4.4.4                                                          Set
log-level                     error                                                            Set
neighborhood-mode             standard                                                         Default
";

        assertion_for_handle_broadcast(SetupCommand::handle_broadcast, setup_body, broadcast_output)
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

        assertion_for_handle_broadcast(
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

        assertion_for_handle_broadcast(
            ChangePasswordCommand::handle_broadcast,
            change_password_body,
            broadcast_output,
        )
    }

    #[test]
    fn ffm_undelivered_since_node_not_running_has_a_synchronizer_correctly_implemented() {
        let ffm_undelivered_body = UiUndeliveredFireAndForget {
            opcode: "crash".to_string(),
        };

        let broadcast_output = "\
Cannot handle crash request: Node is not running.

";

        assertion_for_handle_broadcast(
            handle_node_is_dead_while_f_f_on_the_way_broadcast,
            ffm_undelivered_body,
            broadcast_output,
        )
    }

    #[test]
    fn unrecognized_broadcast_handle_has_a_synchronizer_correctly_implemented() {
        let unrecognizable_broadcast = MessageBody {
            opcode: "messageFromMars".to_string(),
            path: MessagePath::FireAndForget,
            payload: (Ok("".to_string())),
        };

        let broadcast_output = "Discarding unrecognized broadcast with opcode 'messageFromMars'\n";

        assertion_for_handle_broadcast(
            handle_unrecognized_broadcast,
            unrecognizable_broadcast,
            broadcast_output,
        )
    }

    #[test]
    fn ui_log_broadcast_handle_has_a_synchronizer_correctly_implemented() {
        let ui_log_broadcast = UiLogBroadcast {
            msg: "Empty. No Nodes to report to; continuing".to_string(),
            log_level: SerializableLogLevel::Info,
        };

        let broadcast_output = "\n\n>>  Info: Empty. No Nodes to report to; continuing\n\n";

        assertion_for_handle_broadcast(handle_ui_log_broadcast, ui_log_broadcast, broadcast_output)
    }

    fn assertion_for_handle_broadcast<F, U>(
        broadcast_handler: F,
        broadcast_msg: U,
        broadcast_desired_output: &str,
    ) where
        F: FnOnce(U, &mut dyn Write, &TerminalWrapper) + Copy,
        U: Debug + PartialEq + Clone,
    {
        let (tx, rx) = unbounded();
        let mut stdout = StdoutBlender::new(tx);
        let stdout_clone = stdout.clone();
        let stdout_second_clone = stdout.clone();
        let synchronizer = TerminalWrapper::new(Arc::new(TerminalActiveMock::new()));
        let synchronizer_clone_idle = synchronizer.clone();

        //synchronized part proving that the broadcast print is synchronized
        let full_stdout_output_sync = background_thread_making_interferences(
            true,
            &mut stdout,
            Box::new(stdout_clone),
            synchronizer,
            broadcast_handler,
            broadcast_msg.clone(),
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
            broadcast_msg,
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
        F: FnOnce(U, &mut dyn Write, &TerminalWrapper) + Copy,
        U: Debug + PartialEq + Clone,
    {
        let synchronizer_clone = synchronizer.clone();
        let (sync_tx, sync_rx) = bounded(1);
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
        broadcast_handler(broadcast_message_body.clone(), stdout, &synchronizer_clone);

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
