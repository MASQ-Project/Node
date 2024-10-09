// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::command_context::CommandContextReal;
use crate::command_context::{CommandContext, ContextError};
use crate::command_context_factory::CommandContextFactory;
use crate::command_factory::CommandFactory;
use crate::command_factory::CommandFactoryError::{CommandSyntax, UnrecognizedSubcommand};
use crate::command_factory_factory::CommandFactoryFactory;
use crate::commands::commands_common::{Command, CommandError};
use crate::communications::broadcast_handlers::BroadcastHandle;
use crate::communications::connection_manager::ConnectionManagerBootstrapper;
use crate::masq_short_writeln;
use crate::terminal::{FlushHandleInner, RWTermInterface, TerminalWriter, WTermInterface};
use async_trait::async_trait;
use itertools::Either;
use masq_lib::utils::ExpectValue;
use std::pin::Pin;
use std::sync::Arc;
use tokio::io::AsyncWrite;
use tokio::runtime::Runtime;

pub struct CommandProcessorFactory {
    bootstrapper: ConnectionManagerBootstrapper,
}

impl CommandProcessorFactory {
    pub async fn make(
        &self,
        term_interface: Either<Box<dyn WTermInterface>, Box<dyn RWTermInterface>>,
        command_context_factory: &dyn CommandContextFactory,
        command_execution_helper_factory: &dyn CommandExecutionHelperFactory,
        command_factory_factory: &dyn CommandFactoryFactory,
        ui_port: u16,
    ) -> Result<Box<dyn CommandProcessor>, CommandError> {
        //TODO is CommandError proper?
        let background_term_interface_opt = match &term_interface {
            Either::Left(write_only) => None,
            Either::Right(read_write) => todo!(),
        };

        let command_context =
            command_context_factory
            .make(ui_port, background_term_interface_opt)
            .await?;
        // let command_context = match CommandContextReal::new(ui_port, background_term_interface_opt, &self.bootstrapper).await {
        //     Ok(context) => Ok(context),
        //     Err(ContextError::ConnectionRefused(s)) => Err(CommandError::ConnectionProblem(s)),
        //     Err(e) => panic!("Unexpected error: {:?}", e),
        // };

        let command_execution_helper = command_execution_helper_factory.make();

        let command_factory = command_factory_factory.make();

        match term_interface {
            Either::Left(write_only_ti) => Ok(Box::new(CommandProcessorNonInteractive::new(
                command_context,
                command_factory,
                command_execution_helper,
                write_only_ti,
            ))),
            Either::Right(read_write_ti) => todo!(),
        }
    }
}

impl Default for CommandProcessorFactory {
    fn default() -> Self {
        Self::new(Default::default())
    }
}

impl CommandProcessorFactory {
    pub fn new(bootstrapper: ConnectionManagerBootstrapper) -> Self {
        Self { bootstrapper }
    }
}

#[async_trait(?Send)]
pub trait CommandProcessor: ProcessorProvidingCommonComponents {
    async fn process(&mut self, initial_subcommand_opt: Option<&[String]>) -> Result<(), ()>;

    async fn handle_command_common(&mut self, command_parts: &[String]) -> Result<(), ()> {
        let components = self.components();
        let term_interface = components.term_interface.as_ref();
        let command_factory = components.command_factory.as_ref();
        let command_execution_helper = components.command_execution_helper.as_ref();
        let command_context = components.command_context.as_ref();
        let (stderr, _flush_handle) = term_interface.stderr();
        let command = match command_factory.make(command_parts) {
            Ok(c) => c,
            Err(UnrecognizedSubcommand(msg)) => {
                masq_short_writeln!(stderr, "Unrecognized command: '{}'", msg);
                return Err(());
            }
            Err(CommandSyntax(msg)) => {
                //masq_short_writeln!(stderr, "Wrong command syntax: '{}'", msg);
                todo!() //return false;
            }
        };

        let res =
            command_execution_helper.execute_command(command, command_context, term_interface);

        match res {
            Ok(_) => Ok(()),
            Err(e) => {
                masq_short_writeln!(stderr, "{}", e);
                Err(())
            }
        }
    }

    fn stdout(&self) -> (&TerminalWriter, Arc<dyn FlushHandleInner>);

    fn stderr(&self) -> (&TerminalWriter, Arc<dyn FlushHandleInner>);

    fn close(&mut self);
}

pub trait ProcessorProvidingCommonComponents {
    fn components(&mut self) -> &mut CommandProcessorCommon;
}

pub struct CommandProcessorCommon {
    term_interface: Box<dyn WTermInterface>,
    command_context: Box<dyn CommandContext>,
    command_factory: Box<dyn CommandFactory>,
    command_execution_helper: Box<dyn CommandExecutionHelper>,
}

pub struct CommandProcessorNonInteractive {
    command_processor_common: CommandProcessorCommon,
}

#[async_trait(?Send)]
impl CommandProcessor for CommandProcessorNonInteractive {
    async fn process(&mut self, initial_subcommand_opt: Option<&[String]>) -> Result<(), ()> {
        let command_args =
            initial_subcommand_opt.expect("Missing command args in non-interactive mode");
        self.handle_command_common(command_args).await
    }

    fn stdout(&self) -> (&TerminalWriter, Arc<dyn FlushHandleInner>) {
        todo!()
    }

    fn stderr(&self) -> (&TerminalWriter, Arc<dyn FlushHandleInner>) {
        todo!()
    }

    fn close(&mut self) {
        self.command_processor_common.command_context.close();
    }
}

impl ProcessorProvidingCommonComponents for CommandProcessorNonInteractive {
    fn components(&mut self) -> &mut CommandProcessorCommon {
        &mut self.command_processor_common
    }
}

impl CommandProcessorNonInteractive {
    fn new(
        command_context: Box<dyn CommandContext>,
        command_factory: Box<dyn CommandFactory>,
        command_execution_helper: Box<dyn CommandExecutionHelper>,
        term_interface: Box<dyn WTermInterface>,
    ) -> Self {
        let command_processor_common = CommandProcessorCommon {
            term_interface,
            command_context,
            command_factory,
            command_execution_helper,
        };
        Self {
            command_processor_common,
        }
    }
}

pub struct CommandProcessorInteractive {
    context: Box<dyn CommandContext>,
    command_execution_helper: Box<dyn CommandExecutionHelper>,
}

#[async_trait(?Send)]
impl CommandProcessor for CommandProcessorInteractive {
    async fn process(&mut self, initial_subcommand_opt: Option<&[String]>) -> Result<(), ()> {
        // if let Some(synchronizer) = self.context.terminal_interface_opt.clone() {
        //     let _lock = synchronizer.lock();
        //     return command.execute(&mut self.context);
        // }
        //command.execute(&mut self.context)
        todo!()
    }

    fn stdout(&self) -> (&TerminalWriter, Arc<dyn FlushHandleInner>) {
        todo!()
    }

    fn stderr(&self) -> (&TerminalWriter, Arc<dyn FlushHandleInner>) {
        todo!()
    }

    fn close(&mut self) {
        todo!("you can print something like \"MASQ is terminating\"");
        //self.context.close();
    }
}

impl ProcessorProvidingCommonComponents for CommandProcessorInteractive {
    fn components(&mut self) -> &mut CommandProcessorCommon {
        todo!()
    }
}

pub trait CommandExecutionHelperFactory {
    fn make(&self) -> Box<dyn CommandExecutionHelper>;
}

pub struct CommandExecutionHelperFactoryReal {}

impl CommandExecutionHelperFactory for CommandExecutionHelperFactoryReal {
    fn make(&self) -> Box<dyn CommandExecutionHelper> {
        todo!()
    }
}

impl Default for CommandExecutionHelperFactoryReal {
    fn default() -> Self {
        todo!()
    }
}

pub trait CommandExecutionHelper {
    fn execute_command(
        &self,
        command: Box<dyn Command>,
        context: &dyn CommandContext,
        term_interface: &dyn WTermInterface,
    ) -> Result<(), CommandError>;
}

pub struct CommandExecutionHelperReal {}

impl CommandExecutionHelper for CommandExecutionHelperReal {
    fn execute_command(
        &self,
        command: Box<dyn Command>,
        context: &dyn CommandContext,
        term_interface: &dyn WTermInterface,
    ) -> Result<(), CommandError> {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command_context::CommandContext;
    use crate::command_context_factory::CommandContextFactoryReal;
    use crate::command_factory_factory::CommandFactoryFactoryReal;
    use crate::commands::check_password_command::CheckPasswordCommand;
    use crate::communications::broadcast_handlers::{
        BroadcastHandleInactive, BroadcastHandler, StandardBroadcastHandlerReal,
    };
    use crate::test_utils::mocks::{
        StandardBroadcastHandlerFactoryMock, StandardBroadcastHandlerMock, TermInterfaceMock,
    };
    use async_trait::async_trait;
    use masq_lib::messages::{ToMessageBody, UiCheckPasswordResponse, UiUndeliveredFireAndForget};
    use masq_lib::test_utils::mock_websockets_server::MockWebSocketsServer;
    use masq_lib::test_utils::utils::{make_multi_thread_rt, make_rt};
    use masq_lib::utils::{find_free_port, running_test};
    use std::pin::Pin;
    use std::thread;
    use std::time::Duration;
    use tokio::sync::mpsc::UnboundedSender;

    async fn test_handles_nonexistent_server(is_interactive: bool) {
        let ui_port = find_free_port();
        let subject = CommandProcessorFactory::default();
        let (term_interface, _) = TermInterfaceMock::new(None);
        let command_context_factory = CommandContextFactoryReal::default();
        let command_execution_helper_factory = CommandExecutionHelperFactoryReal::default();
        let command_factory_factory = CommandFactoryFactoryReal::default();

        let result = Arc::new(subject)
            .make(
                Either::Left(Box::new(term_interface)),
                &command_context_factory,
                &command_execution_helper_factory,
                &command_factory_factory,
                ui_port,
            )
            .await;

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
        stdout_writer: UnboundedSender<String>,
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

    #[async_trait(?Send)]
    impl Command for TameCommand {
        async fn execute(
            self: Box<Self>,
            _context: &dyn CommandContext,
            term_interface: &dyn WTermInterface,
        ) -> Result<(), CommandError> {
            Self::MESSAGE_IN_PIECES
                .iter()
                .for_each(|piece| self.send_small_piece_of_message(piece));
            Ok(())
        }
    }
}
