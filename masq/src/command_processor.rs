// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use std::pin::Pin;
use crate::command_context::CommandContextReal;
use crate::command_context::{CommandContext, ContextError};
use crate::commands::commands_common::{Command, CommandError};
use crate::communications::broadcast_handlers::BroadcastHandle;
use crate::communications::connection_manager::ConnectionManagerBootstrapper;
use async_trait::async_trait;
use masq_lib::utils::ExpectValue;
use std::sync::Arc;
use tokio::runtime::Runtime;
use crate::terminal::terminal_interface::WTermInterface;

#[async_trait]
pub trait CommandProcessorFactory: Send + Sync{
    async fn make(
        self: Arc<Self>,
        is_interactive: bool,
        ui_port: u16,
    ) -> Result<Box<dyn CommandProcessor>, CommandError>;
}

pub struct CommandProcessorFactoryReal {
    bootstrapper: ConnectionManagerBootstrapper,
}

#[async_trait]
impl CommandProcessorFactory for CommandProcessorFactoryReal {
    async fn make(
        self: Arc<Self>,
        is_interactive: bool,
        ui_port: u16,
    ) -> Result<Box<dyn CommandProcessor>, CommandError> {
        //TODO is CommandError proper?

        let make_context = |term_interface_opt| async {
            match CommandContextReal::new(ui_port, term_interface_opt, &self.bootstrapper).await {
                Ok(context) => Ok(context),
                Err(ContextError::ConnectionRefused(s)) => Err(CommandError::ConnectionProblem(s)),
                Err(e) => panic!("Unexpected error: {:?}", e),
            }
        };

        if is_interactive {
            todo!()
        } else {
            todo!()
        };



    }
}

impl Default for CommandProcessorFactoryReal {
    fn default() -> Self {
        Self::new(Default::default())
    }
}

impl CommandProcessorFactoryReal {
    pub fn new(bootstrapper: ConnectionManagerBootstrapper) -> Self {
        Self { bootstrapper }
    }
}

#[async_trait]
pub trait CommandProcessor: Send {
    async fn process(&mut self, init_args_opt: Option<&[String]>) -> Result<(), CommandError>;
    fn close(&mut self);
}

pub struct CommandProcessorNonInteractive {
    context: CommandContextReal,
}

#[async_trait]
impl CommandProcessor for CommandProcessorNonInteractive {
    async fn process(&mut self, init_args_opt: Option<&[String]>) -> Result<(), CommandError> {
        // if let Some(synchronizer) = self.context.terminal_interface_opt.clone() {
        //     let _lock = synchronizer.lock();
        //     return command.execute(&mut self.context);
        // }
        todo!()
        // command.execute(&mut self.context)
    }

    fn close(&mut self) {
        //self.context.close();
    }
}

pub struct CommandProcessorInteractive {
    context: CommandContextReal,
}

#[async_trait]
impl CommandProcessor for CommandProcessorInteractive {
    async fn process(&mut self, init_args_opt: Option<&[String]>) -> Result<(), CommandError> {
        // if let Some(synchronizer) = self.context.terminal_interface_opt.clone() {
        //     let _lock = synchronizer.lock();
        //     return command.execute(&mut self.context);
        // }
        //command.execute(&mut self.context)
        todo!()
    }

    fn close(&mut self) {
        todo!();
        //self.context.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command_context::CommandContext;
    use crate::commands::check_password_command::CheckPasswordCommand;
    use crate::communications::broadcast_handlers::{
        BroadcastHandleInactive, BroadcastHandler, StandardBroadcastHandlerReal,
    };
    use crate::terminal::terminal_interface::WTermInterface;
    use crate::test_utils::mocks::{
        StandardBroadcastHandlerFactoryMock, StandardBroadcastHandlerMock, TestStreamFactory,
    };
    use async_trait::async_trait;
    use crossbeam_channel::{bounded, Sender};
    use masq_lib::messages::{ToMessageBody, UiCheckPasswordResponse, UiUndeliveredFireAndForget};
    use masq_lib::test_utils::mock_websockets_server::MockWebSocketsServer;
    use masq_lib::test_utils::utils::{make_multi_thread_rt, make_rt};
    use masq_lib::utils::{find_free_port, running_test};
    use std::pin::Pin;
    use std::thread;
    use std::time::Duration;

    async fn test_handles_nonexistent_server(is_interactive: bool) {
        let ui_port = find_free_port();
        let subject = CommandProcessorFactoryReal::default();

        let result = Arc::new(subject).make(is_interactive, ui_port).await;

        match result.err() {
            Some(CommandError::ConnectionProblem(_)) => (),
            x => panic!(
                "Expected Some(CommandError::ConnectionProblem(_); got {:?} instead",
                x
            ),
        }
    }

    #[tokio::test]
    async fn non_interactive_processor_handles_nonexistent_server() {
        test_handles_nonexistent_server(false).await
    }

    #[tokio::test]
    async fn interactive_processor_handles_nonexistent_server() {
        test_handles_nonexistent_server(true).await
    }

    #[test]
    fn process_locks_writing_and_prevents_interferences_from_unexpected_broadcast_messages() {
        todo!("should I transform this into a new test???")
        // running_test();
        // let ui_port = find_free_port();
        // let broadcast = UiUndeliveredFireAndForget {
        //     opcode: "whateverTheOpcodeIs".to_string(),
        // }
        // .tmb(0);
        // let rt = make_multi_thread_rt();
        // let (tx, rx) = bounded(1);
        // let server = MockWebSocketsServer::new(ui_port)
        //     //This message serves to release the broadcasts so that they can start coming.
        //     .queue_response(UiCheckPasswordResponse { matches: false }.tmb(1))
        //     .queue_response(broadcast.clone())
        //     .queue_response(broadcast.clone())
        //     .queue_response(broadcast.clone())
        //     .queue_response(broadcast.clone())
        //     .queue_response(broadcast)
        //     .inject_signal_sender(tx);
        // let (stream_factory, stream_factory_handle) = TestStreamFactory::new();
        // //The following two senders stands for stdout stream handles here - we want to get all written to them by receiving it from a single receiver
        // //so that some input sent from two different threads will mix in one piece of literal data;
        // //that's how the real program's stdout output presents itself to one's eyes.
        // //At the line below, we get a sender for the TameCommand; will serve to the 'main thread'.
        // let cloned_writer = stream_factory.clone_stdout_writer();
        // let terminal_interface = TerminalWrapper::configure_interface().unwrap();
        // let background_terminal_interface = terminal_interface.clone();
        // // Spawning a real broadcast handler "outside"
        // let dependencies = InteractiveModeDependencies::new(
        //     background_terminal_interface,
        //     Box::new(stream_factory),
        // );
        // let mut standard_broadcast_handler = StandardBroadcastHandlerReal::new(Some(dependencies));
        // let standard_broadcast_handle = standard_broadcast_handler.spawn();
        // let standard_broadcast_handler_mock =
        //     StandardBroadcastHandlerMock::default().spawn_result(standard_broadcast_handle);
        // let mut bootstrapper = ConnectionManagerBootstrapper::default();
        // bootstrapper.standard_broadcast_handler_factory = Box::new(
        //     StandardBroadcastHandlerFactoryMock::default()
        //         .make_result(Box::new(standard_broadcast_handler)),
        // );
        // let mut c_p_f = CommandProcessorFactoryReal::default();
        // c_p_f.bootstrapper = bootstrapper;
        // let stop_handle = rt.block_on(server.start());
        // let mut processor = c_p_f.make(&rt, Some(terminal_interface), ui_port).unwrap();
        // processor
        //     .process(Box::new(CheckPasswordCommand {
        //         db_password_opt: None,
        //     }))
        //     .unwrap();
        // // Waiting for a signal from the MockWebSocket server meaning that the queued broadcasts started coming out.
        // rx.recv_timeout(Duration::from_millis(200)).unwrap();
        //
        // processor
        //     .process(Box::new(TameCommand {
        //         stdout_writer: cloned_writer,
        //     }))
        //     .unwrap();
        //
        // let whole_tame_message = TameCommand::whole_message();
        // let received_output = stream_factory_handle.stdout_so_far();
        // assert!(
        //     received_output.contains(&whole_tame_message),
        //     "Message wasn't printed uninterrupted: {}",
        //     received_output
        // );
        // let output_with_broadcasts_only = received_output.replace(&whole_tame_message, "");
        // let number_of_broadcast_received = output_with_broadcasts_only
        //     .clone()
        //     .lines()
        //     .filter(|line| {
        //         line.contains("Cannot handle whateverTheOpcodeIs request: Node is not running")
        //     })
        //     .count();
        // assert_eq!(number_of_broadcast_received, 5);
        // stop_handle.stop();
    }

    #[derive(Debug)]
    struct TameCommand {
        stdout_writer: Sender<String>,
    }

    impl<'a> TameCommand {
        const MESSAGE_IN_PIECES: &'a [&'a str] = &[
            "This is a message ",
            "which must be delivered in one piece; ",
            "we'll do all possible for that. ",
            "If only we have enough strength and spirit ",
            "and determination and support and... snacks. ",
            "Roger.",
        ];

        fn send_small_piece_of_message(&self, piece: &str) {
            self.stdout_writer.send(piece.to_string()).unwrap();
            thread::sleep(Duration::from_millis(1));
        }

        fn whole_message() -> String {
            TameCommand::MESSAGE_IN_PIECES
                .iter()
                .map(|str| str.to_string())
                .collect()
        }
    }

    #[async_trait]
    impl Command for TameCommand {
        async fn execute(
            self: Box<Self>,
            _context: &mut dyn CommandContext,
            term_interface: &mut dyn WTermInterface,
        ) -> Result<(), CommandError> {
            Self::MESSAGE_IN_PIECES
                .iter()
                .for_each(|piece| self.send_small_piece_of_message(piece));
            Ok(())
        }
    }
}
