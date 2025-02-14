// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::commands::change_password_command::ChangePasswordCommand;
use crate::commands::setup_command::SetupCommand;
use crate::communications::connection_manager::{
    BroadcastReceiver, ClosingStageDetector, RedirectOrder,
};
use crate::masq_short_writeln;
use crate::notifications::connection_change_notification::ConnectionChangeNotification;
use crate::notifications::crashed_notification::CrashNotifier;
use crate::terminal::{TerminalWriter, WTermInterfaceDupAndSend};
use async_trait::async_trait;
use masq_lib::messages::{FromMessageBody, ToMessageBody, UiConnectionChangeBroadcast, UiLogBroadcast, UiNewPasswordBroadcast, UiNodeCrashedBroadcast, UiRedirect, UiSetupBroadcast, UiUndeliveredFireAndForget};
use masq_lib::ui_gateway::MessageBody;
use std::cell::RefCell;
use tokio::sync::mpsc::{unbounded_channel, UnboundedSender};
use tokio::task::{JoinError, JoinHandle};

pub const REDIRECT_TIMEOUT_MILLIS: u64 = 500;

pub struct BroadcastHandles {
    standard: Box<dyn BroadcastHandle<MessageBody>>,
    redirect: Box<dyn BroadcastHandle<RedirectOrder>>,
}

impl BroadcastHandles {
    pub fn new(
        standard: Box<dyn BroadcastHandle<MessageBody>>,
        redirect: Box<dyn BroadcastHandle<RedirectOrder>>,
    ) -> Self {
        Self { standard, redirect }
    }

    pub fn handle_broadcast(&self, message_body: MessageBody) {
        match UiRedirect::type_opcode() == message_body.opcode {
            true => {
                let (redirect,_) = match UiRedirect::fmb(message_body) {
                    Ok(broadcast) => broadcast,
                    Err(_) => todo!()
                };
                let context_id = redirect.context_id.unwrap_or(0);
                self.redirect.send(RedirectOrder::new(
                    redirect.port,
                    context_id,
                    REDIRECT_TIMEOUT_MILLIS,
                ))
            }
            false => {
                self.standard.send(message_body);
            }
        };
    }

    pub fn notify<Broadcast>(&self, notification: Broadcast)
    where
        Broadcast: ToMessageBody,
    {
        self.standard.send(notification.tmb(0))
    }
}

#[async_trait(?Send)]
pub trait BroadcastHandle<Message>: Send {
    fn send(&self, message: Message);
    #[cfg(test)]
    async fn wait_to_finish(&self) -> Result<(), JoinError>;
}

#[derive(Default)]
pub struct StandardBroadcastHandleInactive {}

#[async_trait(?Send)]
impl BroadcastHandle<MessageBody> for StandardBroadcastHandleInactive {
    fn send(&self, _message_body: MessageBody) {}

    #[cfg(test)]
    async fn wait_to_finish(&self) -> Result<(), JoinError> {
        Ok(())
    }
}

pub struct StandardBroadcastHandle {
    message_tx: UnboundedSender<MessageBody>,
    spawn_join_handle_opt: RefCell<Option<JoinHandle<()>>>,
}

#[async_trait(?Send)]
impl BroadcastHandle<MessageBody> for StandardBroadcastHandle {
    fn send(&self, message_body: MessageBody) {
        self.message_tx
            .send(message_body)
            .expect("Message send failed")
    }

    #[cfg(test)]
    async fn wait_to_finish(&self) -> Result<(), JoinError> {
        self.spawn_join_handle_opt
            .borrow_mut()
            .take()
            .expect("Join handle is missing")
            .await
    }
}

pub trait StandardBroadcastHandlerFactory: Send + Sync {
    fn make(
        &self,
        terminal_interface_opt: Option<Box<dyn WTermInterfaceDupAndSend>>,
        close_sig: BroadcastReceiver<()>,
    ) -> Box<dyn BroadcastHandler<MessageBody>>;
}

pub struct StandardBroadcastHandlerFactoryReal {}

impl Default for StandardBroadcastHandlerFactoryReal {
    fn default() -> Self {
        Self::new()
    }
}

impl StandardBroadcastHandlerFactoryReal {
    pub fn new() -> Self {
        StandardBroadcastHandlerFactoryReal {}
    }
}

impl StandardBroadcastHandlerFactory for StandardBroadcastHandlerFactoryReal {
    fn make(
        &self,
        terminal_interface_opt: Option<Box<dyn WTermInterfaceDupAndSend>>,
        close_sig: BroadcastReceiver<()>,
    ) -> Box<dyn BroadcastHandler<MessageBody>> {
        match terminal_interface_opt {
            Some(background_term_interface) => Box::new(StandardBroadcastHandlerReal::new(
                background_term_interface,
                close_sig,
            )),
            None => Box::new(StandardBroadcastHandlerInactive::default()),
        }
    }
}

pub trait BroadcastHandler<Message>: Send {
    fn spawn(&mut self) -> Box<dyn BroadcastHandle<Message>>;
}

pub struct StandardBroadcastHandlerReal {
    interactive_mode_dependencies_opt: Option<Box<dyn WTermInterfaceDupAndSend>>,
    close_sig: BroadcastReceiver<()>,
}

impl BroadcastHandler<MessageBody> for StandardBroadcastHandlerReal {
    fn spawn(&mut self) -> Box<dyn BroadcastHandle<MessageBody>> {
        match self.interactive_mode_dependencies_opt.take() {
            Some(mut term_interface) => {
                let (message_tx, mut message_rx) = unbounded_channel();
                let mut close_sig = self.close_sig.resubscribe();

                let spawn_join_handle = tokio::task::spawn(async move {
                    loop {
                        let close_sig_rcv = close_sig.recv();

                        tokio::select! {
                            biased;

                            _ = close_sig_rcv => {
                                break
                            }

                            msg = message_rx.recv() => {
                                Self::handle_message_body(msg, term_interface.as_mut()).await
                            }
                        }
                    }
                });

                Box::new(StandardBroadcastHandle {
                    message_tx,
                    spawn_join_handle_opt: RefCell::new(Some(spawn_join_handle)),
                })
            }
            None => Box::new(StandardBroadcastHandleInactive::default()),
        }
    }
}

impl StandardBroadcastHandlerReal {
    pub fn new(
        interactive_mode_dependencies: Box<dyn WTermInterfaceDupAndSend>,
        close_sig: BroadcastReceiver<()>,
    ) -> Self {
        Self {
            interactive_mode_dependencies_opt: Some(interactive_mode_dependencies),
            close_sig,
        }
    }

    async fn handle_message_body(
        message_body_result: Option<MessageBody>,
        terminal_interface: &mut dyn WTermInterfaceDupAndSend,
    ) {
        let (stdout, _stdout_flush_handle) = terminal_interface.stdout();
        let (stderr, _stderr_flush_handle) = terminal_interface.stderr();
        match message_body_result {
            None => panic!("Broadcasts channel died for other reason than closing the app"),
            Some(message_body) => {
                if let Ok((body, _)) = UiLogBroadcast::fmb(message_body.clone()) {
                    handle_ui_log_broadcast(body, &stdout, &stderr).await
                } else if let Ok((body, _)) = UiSetupBroadcast::fmb(message_body.clone()) {
                    SetupCommand::handle_broadcast(body, &stdout, &stderr).await;
                } else if let Ok((body, _)) = UiNodeCrashedBroadcast::fmb(message_body.clone()) {
                    CrashNotifier::handle_broadcast(body, &stdout, &stderr).await;
                } else if let Ok((body, _)) = UiNewPasswordBroadcast::fmb(message_body.clone()) {
                    ChangePasswordCommand::handle_broadcast(body, &stdout, &stderr).await;
                } else if let Ok((body, _)) = UiUndeliveredFireAndForget::fmb(message_body.clone())
                {
                    handle_node_is_dead_while_f_f_on_the_way_broadcast(body, &stdout, &stderr)
                        .await;
                } else if let Ok((body, _)) = UiConnectionChangeBroadcast::fmb(message_body.clone())
                {
                    ConnectionChangeNotification::handle_broadcast(body, &stdout, &stderr).await;
                } else {
                    handle_unrecognized_broadcast(message_body, &stdout, &stderr).await
                }
            }
        }
    }
}

#[derive(Default)]
pub struct StandardBroadcastHandlerInactive {}

impl BroadcastHandler<MessageBody> for StandardBroadcastHandlerInactive {
    fn spawn(&mut self) -> Box<dyn BroadcastHandle<MessageBody>> {
        Box::new(StandardBroadcastHandleInactive::default())
    }
}

async fn handle_node_is_dead_while_f_f_on_the_way_broadcast(
    body: UiUndeliveredFireAndForget,
    _stdout: &TerminalWriter,
    stderr: &TerminalWriter,
) {
    masq_short_writeln!(
        stderr,
        "\nCannot handle {} request: Node is not running.\n",
        body.opcode
    )
}

async fn handle_unrecognized_broadcast(
    message_body: MessageBody,
    _stdout: &TerminalWriter,
    stderr: &TerminalWriter,
) {
    masq_short_writeln!(
        stderr,
        "Discarding unrecognized broadcast with opcode '{}'\n",
        message_body.opcode
    )
}

async fn handle_ui_log_broadcast(
    body: UiLogBroadcast,
    stdout: &TerminalWriter,
    _stderr: &TerminalWriter,
) {
    masq_short_writeln!(stdout, "\n\n>>  {:?}: {}\n", body.log_level, body.msg)
}

pub struct RedirectBroadcastHandle {
    redirect_order_tx: UnboundedSender<RedirectOrder>,
}

#[async_trait(?Send)]
impl BroadcastHandle<RedirectOrder> for RedirectBroadcastHandle {
    fn send(&self, message_body: RedirectOrder) {
        self.redirect_order_tx
            .send(message_body)
            .expect("Connection manager is dead");
    }

    #[cfg(test)]
    async fn wait_to_finish(&self) -> Result<(), JoinError> {
        unimplemented!("not yet needed")
    }
}

impl RedirectBroadcastHandle {
    pub fn new(redirect_order_tx: UnboundedSender<RedirectOrder>) -> Self {
        Self { redirect_order_tx }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::communications::broadcast_handlers::tests::StreamTypeAndTestHandles::{
        Stderr, Stdout,
    };
    use crate::test_utils::mocks::{AsyncTestStreamHandles, TermInterfaceMock};
    use masq_lib::messages::UiSetupResponseValueStatus::Configured;
    use masq_lib::messages::{
        CrashReason, SerializableLogLevel, ToMessageBody, UiConnectionChangeBroadcast,
        UiConnectionStage, UiNodeCrashedBroadcast,
    };
    use masq_lib::messages::{UiSetupBroadcast, UiSetupResponseValue, UiSetupResponseValueStatus};
    use masq_lib::test_utils::utils::make_rt;
    use masq_lib::ui_gateway::MessagePath;
    use std::default::Default;
    use std::sync::Arc;
    use std::time::Duration;

    #[test]
    fn constants_are_correct() {
        assert_eq!(REDIRECT_TIMEOUT_MILLIS, 500);
    }

    #[tokio::test]
    async fn broadcast_of_setup_triggers_correct_handler() {
        let (term_interface, stream_handles) = TermInterfaceMock::new_non_interactive();
        let (close_signaler, close_sig) = ClosingStageDetector::make_for_test();
        let subject =
            StandardBroadcastHandlerReal::new(Box::new(term_interface), close_sig.dup_receiver())
                .spawn();
        let message = UiSetupBroadcast {
            running: true,
            values: vec![
                UiSetupResponseValue::new("chain", "eth-ropsten", Configured),
                UiSetupResponseValue::new(
                    "data-directory",
                    "/home/booga",
                    UiSetupResponseValueStatus::Default,
                ),
            ],
            errors: vec![],
        }
        .tmb(0);

        subject.send(message);

        stream_handles.await_stdout_is_not_empty().await;
        close_signaler.signalize_close();
        let expected_stdout = "\n\
Daemon setup has changed:

NAME                          VALUE                                                            STATUS
chain                         eth-ropsten                                                      Configured
data-directory                /home/booga                                                      Default

NOTE: no changes were made to the setup because the Node is currently running.

NOTE: your data directory was modified to match the chain parameter.\n\n";
        assert_homogeneous_output_made_via_single_flush(Stdout(&stream_handles), expected_stdout);
        stream_handles.assert_empty_stderr();
    }

    #[tokio::test]
    async fn broadcast_of_ui_log_was_successful() {
        let (term_interface, stream_handles) = TermInterfaceMock::new_non_interactive();
        let (close_signaler, close_sig) = ClosingStageDetector::make_for_test();
        let subject =
            StandardBroadcastHandlerReal::new(Box::new(term_interface), close_sig.dup_receiver())
                .spawn();
        let message = masq_lib::messages::UiLogBroadcast {
            msg: "Empty. No Nodes to report to; continuing".to_string(),
            log_level: SerializableLogLevel::Info,
        }
        .tmb(0);

        subject.send(message);

        stream_handles.await_stdout_is_not_empty().await;
        close_signaler.signalize_close();
        assert_homogeneous_output_made_via_single_flush(
            Stdout(&stream_handles),
            "\n\n>>  Info: Empty. No Nodes to report to; continuing\n\n",
        );
        stream_handles.assert_empty_stderr();
    }

    #[tokio::test]
    async fn broadcast_of_crashed_triggers_correct_handler() {
        let (term_interface, stream_handles) = TermInterfaceMock::new_non_interactive();
        let (close_signaler, close_sig) = ClosingStageDetector::make_for_test();
        let subject =
            StandardBroadcastHandlerReal::new(Box::new(term_interface), close_sig.dup_receiver())
                .spawn();
        let message = UiNodeCrashedBroadcast {
            process_id: 1234,
            crash_reason: CrashReason::Unrecognized("Unknown crash reason".to_string()),
        }
        .tmb(0);

        subject.send(message);

        stream_handles.await_stdout_is_not_empty().await;
        close_signaler.signalize_close();
        assert_homogeneous_output_made_via_single_flush(
            Stdout(&stream_handles),
            "\nThe Node running as process 1234 terminated:\n------\nUnknown crash reason\n\
            ------\nThe Daemon is once more accepting setup changes.\n\n",
        );
        stream_handles.assert_empty_stderr();
    }

    #[tokio::test]
    async fn broadcast_of_new_password_triggers_correct_handler() {
        let (term_interface, stream_handles) = TermInterfaceMock::new_non_interactive();
        let (close_signaler, close_sig) = ClosingStageDetector::make_for_test();
        let subject =
            StandardBroadcastHandlerReal::new(Box::new(term_interface), close_sig.dup_receiver())
                .spawn();
        let message = UiNewPasswordBroadcast {}.tmb(0);

        subject.send(message);

        stream_handles.await_stdout_is_not_empty().await;
        close_signaler.signalize_close();
        subject.wait_to_finish().await.unwrap();
        assert_homogeneous_output_made_via_single_flush(
            Stdout(&stream_handles),
            "\nThe Node's database password has changed.\n\n",
        );
        stream_handles.assert_empty_stderr();
    }

    #[tokio::test]
    async fn broadcast_of_undelivered_ff_message_triggers_correct_handler() {
        let (term_interface, stream_handles) = TermInterfaceMock::new_non_interactive();
        let (close_signaler, close_sig) = ClosingStageDetector::make_for_test();
        let subject =
            StandardBroadcastHandlerReal::new(Box::new(term_interface), close_sig.dup_receiver())
                .spawn();
        let message = UiUndeliveredFireAndForget {
            opcode: "uninventedMessage".to_string(),
        }
        .tmb(0);

        subject.send(message);

        stream_handles.await_stderr_is_not_empty().await;
        close_signaler.signalize_close();
        assert_homogeneous_output_made_via_single_flush(
            Stderr(&stream_handles),
            "\nCannot handle uninventedMessage request: Node is not running.\n\n",
        );
        stream_handles.assert_empty_stdout();
    }

    #[tokio::test]
    async fn ui_connection_change_broadcast_is_handled_properly() {
        let (term_interface, stream_handles) = TermInterfaceMock::new_non_interactive();
        let (close_signaler, close_sig) = ClosingStageDetector::make_for_test();
        let subject =
            StandardBroadcastHandlerReal::new(Box::new(term_interface), close_sig.dup_receiver())
                .spawn();
        let message = UiConnectionChangeBroadcast {
            stage: UiConnectionStage::ConnectedToNeighbor,
        }
        .tmb(0);

        subject.send(message);

        stream_handles.await_stdout_is_not_empty().await;
        close_signaler.signalize_close();
        assert_homogeneous_output_made_via_single_flush(
            Stdout(&stream_handles),
            "\nConnectedToNeighbor: Established neighborship with an external node.\n\n",
        );
        stream_handles.assert_empty_stderr()
    }

    #[tokio::test]
    async fn unexpected_broadcasts_are_ineffectual_but_dont_kill_the_handler() {
        let (term_interface, stream_handles) = TermInterfaceMock::new_non_interactive();
        let (close_signaler, close_sig) = ClosingStageDetector::make_for_test();
        let subject =
            StandardBroadcastHandlerReal::new(Box::new(term_interface), close_sig.dup_receiver())
                .spawn();
        let bad_message = MessageBody {
            opcode: "unrecognized".to_string(),
            path: MessagePath::FireAndForget,
            payload: Ok("".to_string()),
        };
        let good_message = UiSetupBroadcast {
            running: true,
            values: vec![
                UiSetupResponseValue::new("chain", "eth-ropsten", Configured),
                UiSetupResponseValue::new(
                    "data-directory",
                    "/home/booga",
                    UiSetupResponseValueStatus::Default,
                ),
            ],
            errors: vec![],
        }
        .tmb(0);

        subject.send(bad_message);

        stream_handles.await_stderr_is_not_empty().await;
        assert_homogeneous_output_made_via_single_flush(
            Stderr(&stream_handles),
            "Discarding unrecognized broadcast with opcode 'unrecognized'\n\n",
        );
        stream_handles.assert_empty_stdout();

        subject.send(good_message);

        stream_handles.await_stdout_is_not_empty().await;
        close_signaler.signalize_close();
        subject.wait_to_finish().await.unwrap();
        let stdout = stream_handles.stdout_all_in_one();
        assert_eq!(
            stdout.contains("the Node is currently running"),
            true,
            "stdout: '{}' doesn't contain 'the Node is currently running'",
            stdout
        );
        stream_handles.assert_empty_stderr();
    }

    #[tokio::test]
    async fn broadcast_handler_event_loop_terminates_immediately_at_close() {
        let (term_interface, stream_handles) = TermInterfaceMock::new_non_interactive();
        let (close_signaler, close_sig) = ClosingStageDetector::make_for_test();
        let broadcast_handle =
            StandardBroadcastHandlerReal::new(Box::new(term_interface), close_sig.dup_receiver())
                .spawn();
        let example_broadcast = UiNewPasswordBroadcast {}.tmb(0);
        broadcast_handle.send(example_broadcast);
        stream_handles.await_stdout_is_not_empty().await;
        // Taking advantage of the TermInterface containing and Arc, and therefore if the background loop finishes
        // the objects being used by this spawned task are dropped, which is when the count of the references on this
        // Arc decrements
        let count_before_close =
            Arc::strong_count(&stream_handles.stdout.as_ref().right().unwrap());

        close_signaler.signalize_close();

        broadcast_handle.wait_to_finish().await.unwrap();
        let count_after_close = Arc::strong_count(&stream_handles.stdout.as_ref().right().unwrap());
        assert_eq!(count_before_close, 2);
        assert_eq!(count_after_close, 1);
        assert_homogeneous_output_made_via_single_flush(
            Stdout(&stream_handles),
            "\nThe Node's database password has changed.\n\n",
        );
        stream_handles.assert_empty_stderr()
    }

    #[tokio::test]
    #[should_panic(expected = "Broadcasts channel died for other reason than closing the app")]
    async fn handle_message_body_panics_if_its_channel_dies_too_early() {
        let (mut terminal_interface, _) = TermInterfaceMock::new_non_interactive();

        let _ =
            StandardBroadcastHandlerReal::handle_message_body(None, &mut terminal_interface).await;
    }

    #[test]
    fn standard_broadcast_handle_real_or_inactive_depends_on_optionality_of_terminal_interface() {
        let subject = StandardBroadcastHandlerFactoryReal::default();
        let (tx, rx) = tokio::sync::broadcast::channel(10);
        let (term_interface, _) = TermInterfaceMock::new_non_interactive();
        let rt = make_rt();
        let _runtime_context_guard = rt.enter();
        let metrics = rt.metrics();
        let tasks_before_for_real_one = metrics.num_alive_tasks();

        let standard_broadcast_handler_real = subject
            .make(Some(Box::new(term_interface)), rx.resubscribe())
            .spawn();

        rt.block_on(tokio::time::sleep(Duration::from_millis(1)));
        let tasks_after_for_real_one = metrics.num_alive_tasks();
        tx.send(()).unwrap();
        rt.block_on(standard_broadcast_handler_real.wait_to_finish())
            .unwrap();
        let tasks_before_for_the_inactive_one = metrics.num_alive_tasks();

        let standard_broadcast_handler_inactive = subject.make(None, rx).spawn();

        rt.block_on(tokio::time::sleep(Duration::from_millis(1)));
        let tasks_after_for_the_inactive_one = metrics.num_alive_tasks();
        rt.block_on(standard_broadcast_handler_inactive.wait_to_finish())
            .unwrap();
        assert_eq!(tasks_before_for_real_one, 0);
        assert_eq!(tasks_after_for_real_one, 1);
        assert_eq!(tasks_before_for_the_inactive_one, 0);
        assert_eq!(tasks_after_for_the_inactive_one, 0)
    }

    fn assert_homogeneous_output_made_via_single_flush(
        named_handles: StreamTypeAndTestHandles,
        expected_output: &str,
    ) {
        let (stream_flushes, stream_name) = match named_handles {
            Stdout(handles) => (handles.stdout_flushed_strings(), "stdout"),
            Stderr(handles) => (handles.stderr_flushed_strings(), "stderr"),
        };
        assert_eq!(
            stream_flushes,
            vec![expected_output],
         "Expected {} output written into the stream in one piece: {} \nBut found these discrepant flushes: {:?}", stream_name, expected_output, stream_flushes
        );
    }

    enum StreamTypeAndTestHandles<'handles> {
        Stdout(&'handles AsyncTestStreamHandles),
        Stderr(&'handles AsyncTestStreamHandles),
    }
}
