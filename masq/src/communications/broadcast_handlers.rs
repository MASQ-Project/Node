// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::commands::change_password_command::ChangePasswordCommand;
use crate::commands::setup_command::SetupCommand;
use crate::communications::connection_manager::{RedirectOrder, REDIRECT_TIMEOUT_MILLIS};
use crate::notifications::connection_change_notification::ConnectionChangeNotification;
use crate::notifications::crashed_notification::CrashNotifier;
use crate::terminal::terminal_interface::{TerminalWriter, WTermInterface};
use crossbeam_channel::{unbounded, RecvError, Sender};
use masq_lib::messages::{
    FromMessageBody, ToMessageBody, UiConnectionChangeBroadcast, UiLogBroadcast,
    UiNewPasswordBroadcast, UiNodeCrashedBroadcast, UiRedirect, UiSetupBroadcast,
    UiUndeliveredFireAndForget,
};
use masq_lib::ui_gateway::MessageBody;
use masq_lib::utils::ExpectValue;
use masq_lib::{declare_as_any, implement_as_any, intentionally_blank, short_writeln};
#[cfg(test)]
use std::any::Any;
use std::fmt::Debug;
use std::io::Write;
use std::thread;
use async_trait::async_trait;
use tokio::runtime::Runtime;
use tokio::sync::mpsc::UnboundedSender;

pub struct BroadcastHandles {
    pub standard: Box<dyn BroadcastHandle<MessageBody>>,
    pub redirect: Box<dyn BroadcastHandle<RedirectOrder>>,
}

impl BroadcastHandles {
    pub fn new(
        standard: Box<dyn BroadcastHandle<MessageBody>>,
        redirect: Box<dyn BroadcastHandle<RedirectOrder>>,
    ) -> Self {
        Self { standard, redirect }
    }

    pub fn handle_broadcast(&self, message_body: MessageBody) {
        todo!()
        // match UiRedirect::fmb(message_body.clone()) {
        //     Ok((redirect, _)) => {
        //         let context_id = redirect.context_id.unwrap_or(0);
        //         self.redirect_order_tx
        //             .send(RedirectOrder::new(
        //                 redirect.port,
        //                 context_id,
        //                 REDIRECT_TIMEOUT_MILLIS,
        //             ))
        //             .expect("ConnectionManagerThread is dead");
        //     }
        //     Err(_) => {
        //         self.next_handle.send(message_body);
        //     }
        // };
    }

    pub fn notify<Broadcast>(&self, notification: Broadcast)
    where
        Broadcast: ToMessageBody,
    {
        todo!();
        self.standard.send(notification.tmb(0))
    }
}

pub trait BroadcastHandle<Message>: Send {
    fn send(&self, message: Message);
    declare_as_any!();
}

pub struct BroadcastHandleInactive;

impl BroadcastHandle<MessageBody> for BroadcastHandleInactive {
    fn send(&self, _message_body: MessageBody) {}
    implement_as_any!();
}

pub struct StandardBroadcastHandle {
    message_tx: Sender<MessageBody>,
}

impl BroadcastHandle<MessageBody> for StandardBroadcastHandle {
    fn send(&self, message_body: MessageBody) {
        self.message_tx
            .send(message_body)
            .expect("Message send failed")
    }
}

pub trait StandardBroadcastHandlerFactory: Send + Sync{
    fn make(
        &self,
        terminal_interface_opt: Option<Box<dyn WTermInterface>>,
    ) -> Box<dyn BroadcastHandler<MessageBody>>;
}

pub struct StandardBroadcastHandlerFactoryReal {
    pub stream_factory: Box<dyn StreamFactory>,
}

impl StandardBroadcastHandlerFactoryReal {
    pub fn new(stream_factory: Box<dyn StreamFactory>) -> Self {
        todo!()
    }
}

impl StandardBroadcastHandlerFactory for StandardBroadcastHandlerFactoryReal {
    fn make(
        &self,
        terminal_interface_opt: Option<Box<dyn WTermInterface>>,
    ) -> Box<dyn BroadcastHandler<MessageBody>> {
        todo!()
    }
}

pub trait BroadcastHandler<Message>: Send {
    fn spawn(&mut self) -> Box<dyn BroadcastHandle<Message>>;
}

pub struct StandardBroadcastHandlerReal {
    interactive_mode_dependencies_opt: Option<Box<dyn WTermInterface>>,
}

impl BroadcastHandler<MessageBody> for StandardBroadcastHandlerReal {
    fn spawn(&mut self) -> Box<dyn BroadcastHandle<MessageBody>> {
        match self.interactive_mode_dependencies_opt.take() {
            Some(dependencies) => {
                todo!()
                // let (message_tx, message_rx) = unbounded();
                // let terminal_interface = self
                //     .terminal_interface
                //     .take()
                //     .expectv("Some(TerminalWrapper)");
                //
                // // TODO Grr, I can't use Async because I'd have to deal with all the places where we write
                // // into the std streams, and those are a lot out there
                // thread::spawn(move || {
                //     let (mut stdout, mut stderr) = stream_factory.make();
                //
                //     let mut flag = true;
                //     while flag {
                //         flag = Self::handle_message_body(
                //             message_rx.recv(),
                //             stdout.as_mut(),
                //             stderr.as_mut(),
                //             &terminal_interface,
                //         );
                //     }
                // });
                //
                // Box::new(StandardBroadcastHandle { message_tx })
            }
            None => todo!(),
        }
    }
}

impl StandardBroadcastHandlerReal {
    pub fn new(interactive_mode_dependencies_opt: Option<Box<dyn WTermInterface>>) -> Self {
        Self {
            interactive_mode_dependencies_opt,
        }
    }

    async fn handle_message_body(
        message_body_result: Result<MessageBody, RecvError>,
        terminal_interface: &mut dyn WTermInterface,
    ) -> bool {
        let (stdout, _stdout_flush_handle) = terminal_interface.stdout();
        let (stderr, _stderr_flush_handle) = terminal_interface.stderr();
        match message_body_result {
            Err(_) => false, // Receiver died; masq is going down
            Ok(message_body) => {
                if let Ok((body, _)) = UiLogBroadcast::fmb(message_body.clone()) {
                    handle_ui_log_broadcast(body, stdout, stderr).await
                } else if let Ok((body, _)) = UiSetupBroadcast::fmb(message_body.clone()) {
                    SetupCommand::handle_broadcast(body, stdout, stderr).await;
                } else if let Ok((body, _)) = UiNodeCrashedBroadcast::fmb(message_body.clone()) {
                    CrashNotifier::handle_broadcast(body, stdout, stderr).await;
                } else if let Ok((body, _)) = UiNewPasswordBroadcast::fmb(message_body.clone()) {
                    ChangePasswordCommand::handle_broadcast(body, stdout, stderr).await;
                } else if let Ok((body, _)) = UiUndeliveredFireAndForget::fmb(message_body.clone())
                {
                    handle_node_is_dead_while_f_f_on_the_way_broadcast(body, stdout, stderr).await;
                } else if let Ok((body, _)) = UiConnectionChangeBroadcast::fmb(message_body.clone())
                {
                    ConnectionChangeNotification::handle_broadcast(body, stdout, stderr).await;
                } else {
                    handle_unrecognized_broadcast(message_body, stdout, stderr).await
                }
                true
            }
        }
    }
}

pub struct BroadcastHandlerNull {}

impl BroadcastHandler<MessageBody> for BroadcastHandlerNull {
    fn spawn(&mut self) -> Box<dyn BroadcastHandle<MessageBody>> {
        todo!() // Box<dyn BroadcastHandleNull>
    }
}

pub trait StreamFactory: Send +  Sync + Debug {
    fn make(&self) -> (Box<dyn Write>, Box<dyn Write>);
}

#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct StreamFactoryReal;


impl StreamFactory for StreamFactoryReal {
    fn make(&self) -> (Box<dyn Write>, Box<dyn Write>) {
        (Box::new(std::io::stdout()), Box::new(std::io::stderr()))
    }
}

async fn handle_node_is_dead_while_f_f_on_the_way_broadcast(
    body: UiUndeliveredFireAndForget,
    _stdout: &TerminalWriter,
    stderr: &TerminalWriter,
) {
    short_writeln!(
        stderr,
        "\nCannot handle {} request: Node is not running.\n",
        body.opcode
    )
}

async fn handle_unrecognized_broadcast(
    message_body: MessageBody,
    stdout: &TerminalWriter,
    _stderr: &TerminalWriter,
) {
    short_writeln!(
        stdout,
        "Discarding unrecognized broadcast with opcode '{}'\n",
        message_body.opcode
    )
}

async fn handle_ui_log_broadcast(
    body: UiLogBroadcast,
    stdout: &TerminalWriter,
    _stderr: &TerminalWriter,
) {
    short_writeln!(stdout, "\n\n>>  {:?}: {}\n", body.log_level, body.msg)
}

pub struct RedirectBroadcastHandle {
    redirect_order_tx: UnboundedSender<RedirectOrder>,
}

impl BroadcastHandle<RedirectOrder> for RedirectBroadcastHandle {
    fn send(&self, message_body: RedirectOrder) {
        self.redirect_order_tx
            .send(message_body)
            .expect("Connection manager is dead");
    }
}

impl RedirectBroadcastHandle {
    pub fn new(redirect_order_tx: UnboundedSender<RedirectOrder>) -> Self {
        Self { redirect_order_tx }
    }
}
//
// pub struct RedirectBroadcastHandler {
//     redirect_order_tx_opt: Option<UnboundedSender<RedirectOrder>>,
// }
//
// impl BroadcastHandler<RedirectOrder> for RedirectBroadcastHandler {
//     fn spawn(
//         &mut self,
//         _stream_factory: Box<dyn StreamFactory>,
//     ) -> Box<dyn BroadcastHandle<RedirectOrder>> {
//         Box::new(BroadcastHandleRedirect {
//             redirect_order_tx: self
//                 .redirect_order_tx_opt
//                 .take()
//                 .expect("Sender is missing"),
//         })
//     }
// }
//
// impl RedirectBroadcastHandler {
//     pub fn new(redirect_order_tx: UnboundedSender<RedirectOrder>) -> Self {
//         Self {
//             redirect_order_tx_opt: Some(redirect_order_tx),
//         }
//     }
// }

pub trait RedirectBroadcastHandleFactory: Send + Sync{
    fn make(
        &self,
        redirect_order_tx: UnboundedSender<RedirectOrder>,
    ) -> Box<dyn BroadcastHandle<RedirectOrder>>;
}

#[derive(Default)]
pub struct RedirectBroadcastHandleFactoryReal {}

impl RedirectBroadcastHandleFactory for RedirectBroadcastHandleFactoryReal {
    fn make(
        &self,
        redirect_order_tx: UnboundedSender<RedirectOrder>,
    ) -> Box<dyn BroadcastHandle<RedirectOrder>> {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use std::default::Default;
    use std::future::Future;
    use std::process::Output;
    use super::*;
    use crate::test_utils::mocks::{make_tools_for_test_streams_with_thread_life_checker, StdoutBlender, TerminalActiveMock, TerminalPassiveMock, TestStreamFactory, WTermInterfaceMock};
    use crossbeam_channel::{bounded, unbounded, Receiver};
    use masq_lib::messages::UiSetupResponseValueStatus::{Configured};
    use masq_lib::messages::{
        CrashReason, SerializableLogLevel, ToMessageBody, UiConnectionChangeBroadcast,
        UiConnectionStage, UiLogBroadcast, UiNodeCrashedBroadcast,
    };
    use masq_lib::messages::{UiSetupBroadcast, UiSetupResponseValue, UiSetupResponseValueStatus};
    use masq_lib::ui_gateway::MessagePath;
    use std::sync::Arc;
    use std::time::Duration;
    use masq_lib::test_utils::fake_stream_holder::ByteArrayHelperMethods;
    use crate::terminal::terminal_interface::NonInteractiveWTermInterface;

    fn make_subject(
        test_stream_factory: Box<(dyn StreamFactory)>,
    ) -> Box<dyn BroadcastHandle<MessageBody>> {
        let terminal_interface = NonInteractiveWTermInterface::new();
        StandardBroadcastHandlerReal::new(Some(Box::new(terminal_interface))).spawn()
    }

    #[test]
    fn broadcast_of_setup_triggers_correct_handler() {
        let (factory, handle) = TestStreamFactory::new();
        let subject = make_subject(Box::new(factory));
        let message = UiSetupBroadcast {
            running: true,
            values: vec![
                UiSetupResponseValue::new("chain", "eth-ropsten", Configured),
                UiSetupResponseValue::new("data-directory", "/home/booga", UiSetupResponseValueStatus::Default),
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
        let subject = make_subject(Box::new(factory));
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
        let subject = make_subject(Box::new(factory));
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
        let subject = make_subject(Box::new(factory));
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
        let subject = make_subject(Box::new(factory));
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

    #[tokio::test]
    async fn ui_connection_change_broadcast_is_handled_properly() {
        let (factory, handle) = TestStreamFactory::new();
        let mut term_interface = WTermInterfaceMock::default();
        let stdout_arc = term_interface.stdout_arc().clone();
        let stderr_arc = term_interface.stderr_arc().clone();
        let message_body = UiConnectionChangeBroadcast {
            stage: UiConnectionStage::ConnectedToNeighbor,
        }
        .tmb(0);

        let result = StandardBroadcastHandlerReal::handle_message_body(
            Ok(message_body),
            &mut term_interface
        ).await;

        assert_eq!(result, true);
        let stdout = stdout_arc.lock().unwrap().get_string();
        assert_eq!(
            stdout,
            "\nConnectedToNeighbor: Established neighborship with an external node.\n\n"
                .to_string()
        );
        let stderr = stderr_arc.lock().unwrap().get_string();
        assert_eq!(
            stderr,
            "".to_string(),
            "stderr: '{}'",
            stdout
        );
    }

    #[test]
    fn unexpected_broadcasts_are_ineffectual_but_dont_kill_the_handler() {
        let (factory, handle) = TestStreamFactory::new();
        let subject = make_subject(Box::new(factory));
        let bad_message = MessageBody {
            opcode: "unrecognized".to_string(),
            path: MessagePath::FireAndForget,
            payload: (Ok("".to_string())),
        };
        let good_message = UiSetupBroadcast {
            running: true,
            values: vec![
                UiSetupResponseValue::new("chain", "eth-ropsten", Configured),
                UiSetupResponseValue::new("data-directory", "/home/booga", UiSetupResponseValueStatus::Default),
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
        let mut broadcast_handle = make_subject(Box::new(stream_factory));
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

    macro_rules! as_generic_broadcast {
        ($broadcast_handler: expr) => {
            |broadcast, stdout, stderr|Box::new($broadcast_handler(broadcast, stdout, stderr))
        };
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

        assertion_for_handle_broadcast(as_generic_broadcast!(SetupCommand::handle_broadcast), setup_body, broadcast_output)
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
            as_generic_broadcast!(CrashNotifier::handle_broadcast),
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
            as_generic_broadcast!(ChangePasswordCommand::handle_broadcast),
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
            as_generic_broadcast!(handle_node_is_dead_while_f_f_on_the_way_broadcast),
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
            as_generic_broadcast!(handle_unrecognized_broadcast),
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

        assertion_for_handle_broadcast(as_generic_broadcast!(handle_ui_log_broadcast), ui_log_broadcast, broadcast_output)
    }

    fn assertion_for_handle_broadcast<F, U>(
        broadcast_handler: F,
        broadcast_msg: U,
        broadcast_desired_output: &str,
    ) where
        F: for <'a> FnOnce(U, &'a TerminalWriter, &'a TerminalWriter) -> Box<dyn Future<Output=()> + 'a> + Copy,
        U: Debug + PartialEq + Clone,
    {
        todo!()
        // let (tx, rx) = unbounded();
        // let mut stdout = StdoutBlender::new(tx);
        // let stdout_clone = stdout.clone();
        // let stdout_second_clone = stdout.clone();
        // let synchronizer = TerminalWrapper::new(Arc::new(TerminalActiveMock::new()));
        // let synchronizer_clone_idle = synchronizer.clone();
        //
        // //synchronized part proving that the broadcast print is synchronized
        // let full_stdout_output_sync = background_thread_making_interferences(
        //     true,
        //     &mut stdout,
        //     Box::new(stdout_clone),
        //     synchronizer,
        //     broadcast_handler,
        //     broadcast_msg.clone(),
        //     rx.clone(),
        // );
        //
        // assert!(
        //     full_stdout_output_sync.contains(broadcast_desired_output),
        //     "The message from the broadcast handle isn't correct or entire: {}",
        //     full_stdout_output_sync
        // );
        // assert!(
        //     full_stdout_output_sync.contains(&format!("{}", "*".repeat(40))),
        //     "Each group of 40 asterisks must keep together: {}",
        //     full_stdout_output_sync
        // );
        //
        // //unsynchronized part proving that the broadcast print would be messed without synchronization
        // let full_stdout_output_without_sync = background_thread_making_interferences(
        //     false,
        //     &mut stdout,
        //     Box::new(stdout_second_clone),
        //     synchronizer_clone_idle,
        //     broadcast_handler,
        //     broadcast_msg,
        //     rx,
        // );
        //
        // let prefabricated_string = full_stdout_output_without_sync
        //     .chars()
        //     .filter(|char| *char == '*' || *char == ' ')
        //     .collect::<String>();
        // let incomplete_row = prefabricated_string
        //     .split(' ')
        //     .find(|row| !row.contains(&"*".repeat(40)) && row.contains("*"));
        // assert!(
        //     incomplete_row.is_some(),
        //     "There mustn't be 40 asterisks together at one of these: {}",
        //     full_stdout_output_without_sync
        // );
        // let asterisks_count = full_stdout_output_without_sync
        //     .chars()
        //     .filter(|char| *char == '*')
        //     .count();
        // assert_eq!(
        //     asterisks_count, 40,
        //     "The count of asterisks isn't 40 but: {}",
        //     asterisks_count
        // );
    }

    // fn background_thread_making_interferences<F, U>(
    //     sync: bool,
    //     stdout: &mut dyn Write,
    //     mut stdout_clone: Box<dyn Write + Send>,
    //     synchronizer: TerminalWrapper,
    //     broadcast_handler: F,
    //     broadcast_message_body: U,
    //     mixed_stdout_receiver: Receiver<String>,
    // ) -> String
    // where
    //     F: FnOnce(U, &mut dyn WTermInterface) + Copy,
    //     U: Debug + PartialEq + Clone,
    // {
    //     let synchronizer_clone = synchronizer.clone();
    //     let (sync_tx, sync_rx) = bounded(1);
    //     let interference_thread_handle = thread::spawn(move || {
    //         let _lock = if sync {
    //             Some(synchronizer.lock())
    //         } else {
    //             None
    //         };
    //         (0..40).into_iter().for_each(|i| {
    //             stdout_clone.write(b"*").unwrap();
    //             thread::sleep(Duration::from_millis(1));
    //             if i == 5 {
    //                 sync_tx.send(()).unwrap()
    //             };
    //         });
    //         drop(_lock)
    //     });
    //     sync_rx.recv().unwrap();
    //     broadcast_handler(broadcast_message_body.clone(), stdout, &synchronizer_clone);
    //
    //     interference_thread_handle.join().unwrap();
    //
    //     let mut buffer = String::new();
    //     let full_stdout_output = loop {
    //         match mixed_stdout_receiver.try_recv() {
    //             Ok(string) => buffer.push_str(&string),
    //             Err(_) => break buffer,
    //         }
    //     };
    //     full_stdout_output
    // }
}
