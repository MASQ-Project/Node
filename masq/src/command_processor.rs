// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::command_context::CommandContextReal;
use crate::command_context::{CommandContext, ContextError};
use crate::command_context_factory::CommandContextFactory;
use crate::command_factory::CommandFactory;
use crate::command_factory::CommandFactoryError::{CommandSyntax, UnrecognizedSubcommand};
use crate::commands::commands_common::{Command, CommandError};
use crate::communications::broadcast_handlers::BroadcastHandle;
use crate::communications::connection_manager::ConnectionManagerBootstrapper;
use crate::masq_short_writeln;
use crate::terminal::{FlushHandleInner, RWTermInterface, ReadInput, TerminalWriter, WTermInterface};
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
        command_factory: Box<dyn CommandFactory>,
        ui_port: u16,
    ) -> Result<Box<dyn CommandProcessor>, CommandError> {
        //TODO is CommandError proper?
        let background_term_interface_opt = match &term_interface {
            Either::Left(_) => None,
            Either::Right(read_write) => Some(read_write.write_only_clone()),
        };

        let command_context = command_context_factory
            .make(ui_port, background_term_interface_opt)
            .await?;
        // let command_context = match CommandContextReal::new(ui_port, background_term_interface_opt, &self.bootstrapper).await {
        //     Ok(context) => Ok(context),
        //     Err(ContextError::ConnectionRefused(s)) => Err(CommandError::ConnectionProblem(s)),
        //     Err(e) => panic!("Unexpected error: {:?}", e),
        // };

        let command_execution_helper = command_execution_helper_factory.make();

        let command_processor_common = CommandProcessorCommon::new(    command_context,
                                                                       command_factory,
                                                                       command_execution_helper);
        match term_interface {
            Either::Left(write_only_ti) => Ok(Box::new(CommandProcessorNonInteractive::new(command_processor_common, write_only_ti))),
            Either::Right(read_write_ti) => Ok(Box::new(CommandProcessorInteractive::new(command_processor_common, read_write_ti))),
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
        let terminal_interface = self.write_only_term_interface();
        let command_factory = components.command_factory.as_ref();
        let command_execution_helper = components.command_execution_helper.as_ref();
        let command_context = components.command_context.as_ref();
        let (stderr, _flush_handle) = terminal_interface.stderr();

        let command = match command_factory.make(command_parts) {
            Ok(c) => c,
            Err(e) => {
                masq_short_writeln!(stderr, "{}", e);
                return Err(())
            }
        };

        let res =
            command_execution_helper.execute_command(command, command_context, terminal_interface).await;

        match res {
            Ok(_) => Ok(()),
            Err(e) => {
                masq_short_writeln!(stderr, "{}", e);
                Err(())
            }
        }
    }

    fn write_only_term_interface(&self)-> &dyn WTermInterface;

    fn stdout(&self) -> (&TerminalWriter, Arc<dyn FlushHandleInner>);

    fn stderr(&self) -> (&TerminalWriter, Arc<dyn FlushHandleInner>);

    async fn close(&mut self);
}

pub trait ProcessorProvidingCommonComponents {
    fn components(&self) -> &CommandProcessorCommon;
}

pub struct CommandProcessorCommon {
    command_context: Box<dyn CommandContext>,
    command_factory: Box<dyn CommandFactory>,
    command_execution_helper: Box<dyn CommandExecutionHelper>,
}

impl CommandProcessorCommon {
    fn new(
        command_context: Box<dyn CommandContext>,
        command_factory: Box<dyn CommandFactory>,
        command_execution_helper: Box<dyn crate::command_processor::CommandExecutionHelper>,
    ) -> Self {
        Self {
            command_context,
            command_factory,
            command_execution_helper,
        }
    }
}

pub struct CommandProcessorNonInteractive {
    command_processor_common: CommandProcessorCommon,
    terminal_interface: Box<dyn WTermInterface>
}

#[async_trait(?Send)]
impl CommandProcessor for CommandProcessorNonInteractive {
    async fn process(&mut self, initial_subcommand_opt: Option<&[String]>) -> Result<(), ()> {
        let command_args =
            initial_subcommand_opt.expect("Missing command args in non-interactive mode");
        self.handle_command_common(command_args).await
    }

    fn write_only_term_interface(&self) -> &dyn WTermInterface {
        self.terminal_interface.as_ref()
    }

    fn stdout(&self) -> (&TerminalWriter, Arc<dyn FlushHandleInner>) {
        todo!()
    }

    fn stderr(&self) -> (&TerminalWriter, Arc<dyn FlushHandleInner>) {
        todo!()
    }

    async fn close(&mut self) {
        self.command_processor_common.command_context.close();
    }
}

impl ProcessorProvidingCommonComponents for CommandProcessorNonInteractive {
    fn components(&self) -> &CommandProcessorCommon {
        &self.command_processor_common
    }
}

impl CommandProcessorNonInteractive {
    fn new(
        command_processor_common: CommandProcessorCommon,
        terminal_interface: Box<dyn WTermInterface>
    ) -> Self {
        Self {
            command_processor_common,
            terminal_interface
        }
    }
}

pub struct CommandProcessorInteractive {
    command_processor_common: CommandProcessorCommon,
    terminal_interface: Box<dyn RWTermInterface>
}

impl CommandProcessorInteractive {
    fn new(command_processor_common: CommandProcessorCommon, terminal_interface: Box<dyn RWTermInterface>) -> CommandProcessorInteractive {
        Self {
            command_processor_common,
            terminal_interface
        }
    }
}

#[async_trait(?Send)]
impl CommandProcessor for CommandProcessorInteractive {
    async fn process(&mut self, _initial_subcommand_opt: Option<&[String]>) -> Result<(), ()> {
        loop {
            let args = match self.terminal_interface.read_line().await {
                Ok(read_input) => match read_input {
                    ReadInput::Line(cmd) => {split_possibly_quoted_cml(cmd)}
                    ReadInput::Quit => todo!(),
                    ReadInput::Ignored { .. } => todo!()
                }
                Err(e) => todo!()
            };

            if let [single_arg] = args[..].as_ref() {
                if single_arg == "exit" {
                    return Ok(())
                }
            }

            match self.handle_command_common(&args).await {
                Ok(_) => (),
                Err(_) => todo!()
            }
        }
    }

    fn write_only_term_interface(&self) -> &dyn WTermInterface {
        self.terminal_interface.write_only_ref()
    }

    fn stdout(&self) -> (&TerminalWriter, Arc<dyn FlushHandleInner>) {
        todo!()
    }

    fn stderr(&self) -> (&TerminalWriter, Arc<dyn FlushHandleInner>) {
        todo!()
    }

    async fn close(&mut self) {
        let (writer, flush_handle) = self.terminal_interface.write_only_ref().stdout();

        masq_short_writeln!(writer, "Exiting MASQ...");

        self.command_processor_common.command_context.close();
    }
}

impl ProcessorProvidingCommonComponents for CommandProcessorInteractive {
    fn components(&self) -> &CommandProcessorCommon {
        &self.command_processor_common
    }
}

pub trait CommandExecutionHelperFactory {
    fn make(&self) -> Box<dyn CommandExecutionHelper>;
}

#[derive(Default)]
pub struct CommandExecutionHelperFactoryReal {}

impl CommandExecutionHelperFactory for CommandExecutionHelperFactoryReal {
    fn make(&self) -> Box<dyn CommandExecutionHelper> {
        Box::new(CommandExecutionHelperReal{})
    }
}

#[async_trait(?Send)]
pub trait CommandExecutionHelper {
    async fn execute_command(
        &self,
        command: Box<dyn Command>,
        context: &dyn CommandContext,
        term_interface: &dyn WTermInterface,
    ) -> Result<(), CommandError>;
}

pub struct CommandExecutionHelperReal {}

#[async_trait(?Send)]
impl CommandExecutionHelper for CommandExecutionHelperReal {
    async fn execute_command(
        &self,
        command: Box<dyn Command>,
        context: &dyn CommandContext,
        term_interface: &dyn WTermInterface,
    ) -> Result<(), CommandError> {
        command.execute(context, term_interface).await
    }
}

fn split_possibly_quoted_cml(input: String) -> Vec<String> {
    let mut active_single = false;
    let mut active_double = false;
    let mut pieces: Vec<String> = vec![];
    let mut current_piece = String::new();
    input.chars().for_each(|c| {
        if c.is_whitespace() && !active_double && !active_single {
            if !current_piece.is_empty() {
                pieces.push(current_piece.clone());
                current_piece.clear();
            }
        } else if c == '"' && !active_single {
            active_double = !active_double;
        } else if c == '\'' && !active_double {
            active_single = !active_single;
        } else {
            current_piece.push(c);
        }
    });
    if !current_piece.is_empty() {
        pieces.push(current_piece)
    }
    pieces
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command_context::CommandContext;
    use crate::command_context_factory::CommandContextFactoryReal;
    use crate::command_factory::CommandFactoryReal;
    use crate::commands::check_password_command::CheckPasswordCommand;
    use crate::communications::broadcast_handlers::{
        BroadcastHandleInactive, BroadcastHandler, StandardBroadcastHandlerReal,
    };
    use crate::test_utils::mocks::{
        MockTerminalMode, StandardBroadcastHandlerFactoryMock, StandardBroadcastHandlerMock,
        TermInterfaceMock,
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
        let (term_interface,_) = TermInterfaceMock::new_non_interactive();
        let command_context_factory = CommandContextFactoryReal::default();
        let command_execution_helper_factory = CommandExecutionHelperFactoryReal::default();
        let command_factory = Box::new(CommandFactoryReal::default());

        let result = Arc::new(subject)
            .make(
                Either::Left(Box::new(term_interface)),
                &command_context_factory,
                &command_execution_helper_factory,
                command_factory,
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
    fn split_possibly_quoted_cml_handles_balanced_double_quotes() {
        let command_line =
            "  first \"second\" third  \"fourth'fifth\" \t sixth \"seventh eighth\tninth\" "
                .to_string();

        let result = split_possibly_quoted_cml(command_line);

        assert_eq!(
            result,
            vec![
                "first".to_string(),
                "second".to_string(),
                "third".to_string(),
                "fourth'fifth".to_string(),
                "sixth".to_string(),
                "seventh eighth\tninth".to_string(),
            ]
        )
    }

    #[test]
    fn split_possibly_quoted_cml_handles_unbalanced_double_quotes() {
        let command_line =
            "  first \"second\" third  \"fourth'fifth\" \t sixth \"seventh eighth\tninth  "
                .to_string();

        let result = split_possibly_quoted_cml(command_line);

        assert_eq!(
            result,
            vec![
                "first".to_string(),
                "second".to_string(),
                "third".to_string(),
                "fourth'fifth".to_string(),
                "sixth".to_string(),
                "seventh eighth\tninth  ".to_string(),
            ]
        )
    }

    #[test]
    fn split_possibly_quoted_cml_handles_balanced_single_quotes() {
        let command_line =
            "  first \n 'second' \n third \n 'fourth\"fifth' \t sixth 'seventh eighth\tninth' "
                .to_string();

        let result = split_possibly_quoted_cml(command_line);

        assert_eq!(
            result,
            vec![
                "first".to_string(),
                "second".to_string(),
                "third".to_string(),
                "fourth\"fifth".to_string(),
                "sixth".to_string(),
                "seventh eighth\tninth".to_string(),
            ]
        )
    }

    #[test]
    fn split_possibly_quoted_cml_handles_unbalanced_single_quotes() {
        let command_line =
            "  first 'second' third  'fourth\"fifth' \t sixth 'seventh eighth\tninth  ".to_string();
        let result = split_possibly_quoted_cml(command_line);

        assert_eq!(
            result,
            vec![
                "first".to_string(),
                "second".to_string(),
                "third".to_string(),
                "fourth\"fifth".to_string(),
                "sixth".to_string(),
                "seventh eighth\tninth  ".to_string(),
            ]
        )
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
