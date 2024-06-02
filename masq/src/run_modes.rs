// Copyright (c) 2024, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::command_context_factory::{CommandContextFactory, CommandContextFactoryReal};
use crate::command_factory::CommandFactoryError::{CommandSyntax, UnrecognizedSubcommand};
use crate::command_factory::{CommandFactory, CommandFactoryReal};
use crate::command_processor::{
    CommandExecutionHelperFactory, CommandExecutionHelperFactoryReal, CommandProcessor,
    CommandProcessorFactory,
};
use crate::communications::broadcast_handlers::{
    BroadcastHandle, BroadcastHandleInactive, BroadcastHandler, StandardBroadcastHandlerReal,
};
use crate::non_interactive_clap::{InitialArgsParser, InitialArgsParserReal, InitializationArgs};
use crate::terminal::async_streams::{
    AsyncStdStreams, AsyncStdStreamsFactory, AsyncStdStreamsFactoryReal,
};
use crate::terminal::terminal_interface_factory::{
    TerminalInterfaceFactory, TerminalInterfaceFactoryReal,
};
use crate::terminal::{RWTermInterface, TerminalWriter, WTermInterface};
use async_trait::async_trait;
use itertools::Either;
use std::io::Write;
use std::ops::Not;
use std::sync::Arc;
use tokio::io::{AsyncWrite, AsyncWriteExt};

pub struct Main {
    std_streams_factory_opt: Option<Box<dyn AsyncStdStreamsFactory>>,
    initial_args_parser: Box<dyn InitialArgsParser>,
    term_interface_factory: Box<dyn TerminalInterfaceFactory>,
    command_factory: Box<dyn CommandFactory>,
    command_context_factory: Box<dyn CommandContextFactory>,
    command_execution_helper_factory: Box<dyn CommandExecutionHelperFactory>,
    command_processor_static_factory: CommandProcessorFactory,
}

impl Default for Main {
    fn default() -> Self {
        Main::new()
    }
}

impl Main {
    pub async fn go(&mut self, args: &[String]) -> u8 {
        let std_streams_factory = self.acquire_stream_factory();
        let incidental_streams = std_streams_factory.make();
        let initialization_args = self
            .initial_args_parser
            .parse_initialization_args(args, &incidental_streams);
        let initial_subcommand_opt = Self::extract_subcommand(args);
        let term_interface = self
            .term_interface_factory
            .make(initial_subcommand_opt.is_none(), std_streams_factory);

        match self
            .see_about_this_labour(
                initialization_args.ui_port,
                term_interface,
                initial_subcommand_opt.as_deref(),
            )
            .await
        {
            Ok(_) => todo!(),
            Err(e) => {
                // let mut streams = self.std_streams_factory.make();
                //         streams.stderr.write(format!(
                //             "Can't connect to Daemon or Node ({:?}). Probably this means the Daemon \
                //             isn't running.\n",
                //             error
                //         ).as_bytes()).await.expect("Error writing failed");
                //         return Self::bool_into_numeric_code(false);

                //self.write_err()
                todo!()
            }
        }
    }

    pub fn new() -> Self {
        Self {
            std_streams_factory_opt: Some(Box::new(AsyncStdStreamsFactoryReal::default())),
            initial_args_parser: Box::new(InitialArgsParserReal::default()),
            term_interface_factory: Box::new(TerminalInterfaceFactoryReal::default()),
            command_factory: Box::new(CommandFactoryReal::default()),
            command_context_factory: Box::new(CommandContextFactoryReal::default()),
            command_execution_helper_factory: Box::new(CommandExecutionHelperFactoryReal::default()),
            command_processor_static_factory: Default::default(),
        }
    }

    pub fn acquire_stream_factory(&mut self) -> Box<dyn AsyncStdStreamsFactory> {
        self.std_streams_factory_opt
            .take()
            .expect("Streams factory wasn't properly initialized")
    }

    async fn see_about_this_labour(
        &mut self,
        ui_port: u16,
        term_interface: Either<Box<dyn WTermInterface>, Box<dyn RWTermInterface>>,
        initial_subcommand_opt: Option<&[String]>,
    ) -> Result<(), String> {
        let command_context_factory = self.command_context_factory.as_ref();
        let execution_helper_factory = self.command_execution_helper_factory.as_ref();
        let mut command_processor = match self
            .command_processor_static_factory
            .make(
                term_interface,
                command_context_factory,
                execution_helper_factory,
                ui_port,
            )
            .await
        {
            Ok(processor) => processor,
            Err(error) => {
                todo!()
            }
        };

        let result = match command_processor
            .process(initial_subcommand_opt.as_deref())
            .await
        {
            Ok(_) => todo!(),
            Err(e) => todo!(),
        };

        command_processor.close();

        result
    }

    fn write_err(&self, stderr: &mut (dyn AsyncWrite + Send + Unpin), msg: &str) {
        todo!()
    }

    fn extract_subcommand(args: &[String]) -> Option<Vec<String>> {
        fn both_do_not_start_with_two_dashes(
            one_program_arg: &&String,
            program_arg_next_to_the_previous: &&String,
        ) -> bool {
            [one_program_arg, program_arg_next_to_the_previous]
                .iter()
                .any(|arg| arg.starts_with("--"))
                .not()
        }

        let original_args = args.iter();
        let one_item_shifted_forth = args.iter().skip(1);
        original_args
            .zip(one_item_shifted_forth)
            .enumerate()
            .find(|(_index, (left, right))| both_do_not_start_with_two_dashes(left, right))
            .map(|(index, _)| args.iter().skip(index + 1).cloned().collect())
    }

    fn bool_into_numeric_code(bool_flag: bool) -> u8 {
        if bool_flag {
            0
        } else {
            1
        }
    }
}

pub async fn handle_command_common(
    command_factory: &dyn CommandFactory,
    processor: &mut dyn CommandProcessor,
    command_parts: &[String],
    stderr: &TerminalWriter,
) -> Result<(), String> {
    todo!()
    // let command = match command_factory.make(command_parts) {
    //     Ok(c) => c,
    //     Err(UnrecognizedSubcommand(msg)) => {
    //         short_writeln!(stderr, "Unrecognized command: '{}'", msg);
    //         return false;
    //     }
    //     Err(CommandSyntax(msg)) => {
    //         short_writeln!(stderr, "{}", msg);
    //         return false;
    //     }
    // };
    // if let Err(e) = processor.process(command) {
    //     short_writeln!(stderr, "{}", e);
    //     false
    // } else {
    //     true
    // }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command_context::CommandContext;
    use crate::command_context::ContextError::Other;
    use crate::commands::commands_common;
    use crate::commands::commands_common::CommandError;
    use crate::commands::commands_common::CommandError::Transmission;
    use crate::commands::setup_command::SetupCommand;
    use crate::terminal::{ReadError, ReadInput, WTermInterfaceImplementingSend};
    use crate::test_utils::mocks::{
        make_async_std_streams, make_terminal_writer, AsyncStdStreamsFactoryMock,
        AsyncTestStreamHandles, CommandContextFactoryMock, CommandContextMock,
        CommandExecutionHelperFactoryMock, CommandExecutionHelperMock, CommandFactoryMock,
        CommandProcessorMock, InitialArgsParserMock, MockCommand, StdinMock, StdinMockBuilder,
        TermInterfaceMock, TerminalInterfaceFactoryMock,
    };
    use masq_lib::intentionally_blank;
    use masq_lib::messages::{ToMessageBody, UiNewPasswordBroadcast, UiShutdownRequest};
    use std::any::Any;
    use std::fmt::Debug;
    use std::sync::{Arc, Mutex};

    #[cfg(target_os = "windows")]
    mod win_test_import {
        pub use std::thread;
        pub use std::time::Duration;
    }

    #[tokio::test]
    async fn noninteractive_mode_works_when_everything_is_copacetic() {
        let (processor_aspiring_std_streams, processor_aspiring_std_stream_handles) =
            make_async_std_streams(vec![]);
        let (incidental_std_streams, incidental_std_stream_handles) =
            make_async_std_streams(vec![]);
        let make_std_streams_params_arc = Arc::new(Mutex::new(vec![]));
        let std_streams_factory = AsyncStdStreamsFactoryMock::default()
            .make_params(&make_std_streams_params_arc)
            .make_result(incidental_std_streams)
            .make_result(processor_aspiring_std_streams);
        let make_term_interface_params_arc = Arc::new(Mutex::new(vec![]));
        let (w_term_interface, term_interface_stream_handles) = TermInterfaceMock::new(None);
        let terminal_interface_factory = TerminalInterfaceFactoryMock::default()
            .make_params(&make_term_interface_params_arc)
            .make_result(Either::Left(Box::new(w_term_interface)));
        let command = MockCommand::new(UiShutdownRequest {}.tmb(1));
        let c_make_params_arc = Arc::new(Mutex::new(vec![]));
        let command_factory = CommandFactoryMock::default()
            .make_params(&c_make_params_arc)
            .make_result(Ok(Box::new(command)));
        let close_params_arc = Arc::new(Mutex::new(vec![]));
        let command_context = CommandContextMock::default().close_params(&close_params_arc);
        let make_command_context_params_arc = Arc::new(Mutex::new(vec![]));
        let command_context_factory = CommandContextFactoryMock::default()
            .make_params(&make_command_context_params_arc)
            .make_result(Ok(Box::new(command_context)));
        let execute_command_params_arc = Arc::new(Mutex::new(vec![]));
        let command_execution_helper = CommandExecutionHelperMock::default()
            .execute_command_params(&execute_command_params_arc)
            .execute_command_result(Ok(()));
        let command_execution_helper_factory = CommandExecutionHelperFactoryMock::default();
        let mut subject = Main {
            std_streams_factory_opt: Some(Box::new(std_streams_factory)),
            initial_args_parser: Box::new(InitialArgsParserMock::default()),
            term_interface_factory: Box::new(terminal_interface_factory),
            command_factory: Box::new(command_factory),
            command_context_factory: Box::new(command_context_factory),
            command_execution_helper_factory: Box::new(command_execution_helper_factory),
            command_processor_static_factory: Default::default(),
        };

        let result = subject
            .go(&[
                "command",
                "subcommand",
                "--param1",
                "value1",
                "--param2",
                "--param3",
            ]
            .iter()
            .map(|str| str.to_string())
            .collect::<Vec<String>>())
            .await;

        assert_eq!(result, 0);
        let make_std_streams_params = make_std_streams_params_arc.lock().unwrap();
        // Only once because there isn't an error to display from other than inside the processor and
        // so the single set of streams is enough
        assert_eq!(*make_std_streams_params, vec![()]);
        let mut make_command_context_params = make_command_context_params_arc.lock().unwrap();
        let (ui_port, broadcast_handle_term_interface_opt) =
            make_command_context_params.pop().unwrap();
        assert_eq!(ui_port, 5333);
        StdStreamsAssertionMatrix::compose(
            &incidental_std_stream_handles,
            &processor_aspiring_std_stream_handles,
            &term_interface_stream_handles,
            None,
            None,
            None,
            None,
            None,
        )
        .assert()
        .await;
        let c_make_params = c_make_params_arc.lock().unwrap();
        assert_eq!(
            *c_make_params,
            vec![
                vec!["subcommand", "--param1", "value1", "--param2", "--param3"]
                    .iter()
                    .map(|str| str.to_string())
                    .collect::<Vec<String>>(),
            ]
        );
        let mut execute_command_params = execute_command_params_arc.lock().unwrap();
        let command = execute_command_params.remove(0);
        assert!(execute_command_params.is_empty());
        let transact_params_arc = Arc::new(Mutex::new(vec![]));
        let mut context = CommandContextMock::new()
            .transact_params(&transact_params_arc)
            .transact_result(Err(Other("not really an error".to_string())));
        let (mut term_interface, term_interface_stream_handles) = TermInterfaceMock::new(None);

        let result = command.execute(&mut context, &mut term_interface).await;

        assert_eq!(
            result,
            Err(Transmission("Other(\"not really an error\")".to_string()))
        );
        let transact_params = transact_params_arc.lock().unwrap();
        assert_eq!(*transact_params, vec![(UiShutdownRequest {}.tmb(1), 1000)]);
        assert_eq!(
            term_interface_stream_handles.stdout_all_in_one(),
            "MockCommand output"
        );
        assert_eq!(
            term_interface_stream_handles.stderr_all_in_one(),
            "MockCommand error"
        );
        let close_params = close_params_arc.lock().unwrap();
        assert_eq!(*close_params, vec![()]);
    }

    #[tokio::test]
    async fn go_works_when_command_is_unrecognized() {
        let (incidental_std_streams, incidental_std_stream_handles) =
            make_async_std_streams(vec![]);
        let (processor_aspiring_std_streams, processor_aspiring_std_stream_handles) =
            make_async_std_streams(vec![]);
        let make_std_streams_params_arc = Arc::new(Mutex::new(vec![]));
        let std_streams_factory = AsyncStdStreamsFactoryMock::default()
            .make_params(&make_std_streams_params_arc)
            .make_result(incidental_std_streams)
            .make_result(processor_aspiring_std_streams);
        let make_term_interface_params_arc = Arc::new(Mutex::new(vec![]));
        let (w_term_interface, term_interface_stream_handles) = TermInterfaceMock::new(None);
        let terminal_interface_factory = TerminalInterfaceFactoryMock::default()
            .make_params(&make_term_interface_params_arc)
            .make_result(Either::Left(Box::new(w_term_interface)));
        let c_make_params_arc = Arc::new(Mutex::new(vec![]));
        let command_factory = CommandFactoryMock::default()
            .make_params(&c_make_params_arc)
            .make_result(Err(UnrecognizedSubcommand("booga".to_string())));
        let close_params_arc = Arc::new(Mutex::new(vec![]));
        let processor = CommandContextMock::default().close_params(&close_params_arc);
        let make_command_context_params_arc = Arc::new(Mutex::new(vec![]));
        let command_context_factory = CommandContextFactoryMock::default()
            .make_params(&make_command_context_params_arc)
            .make_result(Ok(Box::new(processor)));
        let command_execution_helper_factory = CommandExecutionHelperFactoryMock::default();
        let mut subject = Main {
            std_streams_factory_opt: Some(Box::new(std_streams_factory)),
            initial_args_parser: Box::new(InitialArgsParserMock::default()),
            term_interface_factory: Box::new(terminal_interface_factory),
            command_factory: Box::new(command_factory),
            command_context_factory: Box::new(command_context_factory),
            command_execution_helper_factory: Box::new(command_execution_helper_factory),
            command_processor_static_factory: Default::default(),
        };

        let result = subject
            .go(&["command".to_string(), "subcommand".to_string()])
            .await;

        let make_std_streams_params = make_std_streams_params_arc.lock().unwrap();
        assert_eq!(*make_std_streams_params, vec![(), ()]);
        let mut make_processor_params = make_command_context_params_arc.lock().unwrap();
        let (ui_port, broadcast_handle_term_interface_opt) = make_processor_params.pop().unwrap();
        assert_eq!(ui_port, 5333);
        StdStreamsAssertionMatrix::compose(
            &incidental_std_stream_handles,
            &processor_aspiring_std_stream_handles,
            &term_interface_stream_handles,
            None,
            Some(StreamFactoryStreamsAssertionMatrix {
                write_streams: WriteStreamsAssertion::with_one_piece_output("", "glum glum"),
                reading_attempts: vec![],
            }),
            None,
            Some(ProcessorTerminalInterfaceAssertionMatrix {
                standard_assertions: TerminalInterfaceAssertionMatrix {
                    term_interface_stream_handles: &term_interface_stream_handles,
                    write_streams: WriteStreamsAssertion::with_one_piece_output(
                        "",
                        "Unrecognized command: 'booga'\n",
                    ),
                },
                read_attempts_opt: None,
            }),
            None,
        )
        .assert()
        .await;
        let c_make_params = c_make_params_arc.lock().unwrap();
        assert_eq!(*c_make_params, vec![vec!["subcommand".to_string()],]);
        let close_params = close_params_arc.lock().unwrap();
        assert_eq!(*close_params, vec![()]);
        assert_eq!(result, 1);
    }

    // TODO seems like doubling the previous test
    // #[tokio::test]
    // async fn go_works_when_command_has_bad_syntax() {
    //     let c_make_params_arc = Arc::new(Mutex::new(vec![]));
    //     let command_factory = CommandFactoryMock::new()
    //         .make_params(&c_make_params_arc)
    //         .make_result(Err(CommandSyntax("Unknown syntax booga".to_string())));
    //     let (incidental_std_streams, incidental_std_stream_handles) = make_async_std_streams(vec![]).await;
    //     let (processor_aspiring_std_streams, processor_aspiring_std_stream_handles) = make_async_std_streams(vec![]).await;
    //     let std_streams_factory = AsyncStdStreamFactoryMock::default()
    //         .make_result(incidental_std_streams)
    //         .make_result(processor_aspiring_std_streams);
    //     let (w_term_interface, term_interface_stream_handles) = TermInterfaceMock::new(None).await;
    //     let terminal_interface_factory = TerminalInterfaceFactoryMock::default()
    //         .make_result(Either::Left(Box::new(w_term_interface)));
    //     let command_context = CommandContextMock::default();
    //     let make_command_context_params_arc = Arc::new(Mutex::new(vec![]));
    //     let command_context_factory =
    //         CommandContextFactoryMock::new()
    //             .make_params(&make_command_context_params_arc)
    //             .make_result(Ok(Box::new(command_context)));
    //     let command_execution_helper = CommandExecutionHelperMock::default();
    //     let command_execution_helper_factory = CommandExecutionHelperFactoryMock::default()
    //         .make_result(Box::new(command_execution_helper));
    //     let mut subject = Main {
    //         std_streams_factory: Box::new(std_streams_factory),
    //         initial_args_parser: Box::new(InitialArgsParserMock::default()),
    //         term_interface_factory: Box::new(terminal_interface_factory),
    //         command_factory: Box::new(command_factory),
    //         command_context_factory: Box::new(command_context_factory),
    //         command_execution_helper_factory: Box::new(()),
    //         command_processor_static_factory: Default::default(),
    //     };
    //
    //     let result = subject
    //         .go(&["command".to_string(), "subcommand".to_string()])
    //         .await;
    //
    //     assert_eq!(result, 1);
    //     let c_make_params = c_make_params_arc.lock().unwrap();
    //     assert_eq!(*c_make_params, vec![vec!["subcommand".to_string()],]);
    //     let mut make_command_context_params = make_command_context_params_arc.lock().unwrap();
    //     let (ui_port, broadcast_handler_term_interface_opt) = make_command_context_params.pop().unwrap();
    //     assert_eq!(ui_port, 5333);
    //     StdStreamsAssertionMatrix::compose(
    //         &incidental_std_stream_handles,
    //         &processor_aspiring_std_stream_handles,
    //         &term_interface_stream_handles,
    //         None,
    //         None,
    //         None,
    //         Some(ProcessorTerminalInterfaceAssertionMatrix{ standard_assertions: TerminalInterfaceAssertionMatrix { term_interface_stream_handles: &term_interface_stream_handles, write_streams: WriteStreamsAssertion::with_one_piece_output("", "Unknown syntax booga\n")}, read_attempts_opt: None }),
    //         None
    //     ).assert().await;
    // }

    #[tokio::test]
    async fn go_works_when_command_execution_fails() {
        let command = MockCommand::new(UiShutdownRequest {}.tmb(1));
        let command_factory =
            CommandFactoryMock::default().make_result(Ok(Box::new(command.clone())));
        let (incidental_std_streams, incidental_std_stream_handles) =
            make_async_std_streams(vec![]);
        let (processor_aspiring_std_streams, processor_aspiring_std_stream_handles) =
            make_async_std_streams(vec![]);
        let std_streams_factory = AsyncStdStreamsFactoryMock::default()
            .make_result(incidental_std_streams)
            .make_result(processor_aspiring_std_streams);
        let (w_term_interface, term_interface_stream_handles) = TermInterfaceMock::new(None);
        let terminal_interface_factory = TerminalInterfaceFactoryMock::default()
            .make_result(Either::Left(Box::new(w_term_interface)));
        let command_context = CommandContextMock::default();
        let make_command_context_factory_params_arc = Arc::new(Mutex::new(vec![]));
        let command_context_factory = CommandContextFactoryMock::new()
            .make_params(&make_command_context_factory_params_arc)
            .make_result(Ok(Box::new(command_context)));
        let execute_command_params_arc = Arc::new(Mutex::new(vec![]));
        let command_execution_helper = CommandExecutionHelperMock::default()
            .execute_command_params(&execute_command_params_arc)
            .execute_command_result(Err(Transmission("Booga!".to_string())));
        let command_execution_helper_factory = CommandExecutionHelperFactoryMock::default()
            .make_result(Box::new(command_execution_helper));
        let mut subject = Main {
            std_streams_factory_opt: Some(Box::new(std_streams_factory)),
            initial_args_parser: Box::new(InitialArgsParserMock::default()),
            term_interface_factory: Box::new(terminal_interface_factory),
            command_factory: Box::new(command_factory),
            command_context_factory: Box::new(command_context_factory),
            command_execution_helper_factory: Box::new(command_execution_helper_factory),
            command_processor_static_factory: Default::default(),
        };

        let result = subject
            .go(&["command".to_string(), "subcommand".to_string()])
            .await;

        let mut make_processor_params = make_command_context_factory_params_arc.lock().unwrap();
        let (ui_port, broadcast_handler_term_interface_opt) = make_processor_params.pop().unwrap();
        assert_eq!(ui_port, 5333);
        StdStreamsAssertionMatrix::compose(
            &incidental_std_stream_handles,
            &processor_aspiring_std_stream_handles,
            &term_interface_stream_handles,
            broadcast_handler_term_interface_opt.as_deref(),
            Some(StreamFactoryStreamsAssertionMatrix {
                write_streams: WriteStreamsAssertion::with_one_piece_output("", "grrrrrr"),
                reading_attempts: vec![],
            }),
            None,
            Some(ProcessorTerminalInterfaceAssertionMatrix {
                standard_assertions: TerminalInterfaceAssertionMatrix {
                    term_interface_stream_handles: &term_interface_stream_handles,
                    write_streams: WriteStreamsAssertion::with_one_piece_output(
                        "",
                        "Transmission problem: Booga!\n",
                    ),
                },
                read_attempts_opt: None,
            }),
            None,
        )
        .assert()
        .await;
        let mut execute_command_params = execute_command_params_arc.lock().unwrap();
        let dyn_command = execute_command_params.remove(0);
        let actual_command = dyn_command.as_any().downcast_ref::<MockCommand>().unwrap();
        assert_eq!(actual_command.message, command.message);
        assert!(execute_command_params.is_empty());
        assert_eq!(result, 1);
    }

    #[tokio::test]
    async fn go_works_when_daemon_is_not_running() {
        let (processor_aspiring_std_streams, processor_aspiring_std_stream_handles) =
            make_async_std_streams(vec![]);
        let (incidental_std_streams, incidental_std_stream_handles) =
            make_async_std_streams(vec![]);
        let std_streams_factory = AsyncStdStreamsFactoryMock::default()
            .make_result(incidental_std_streams)
            .make_result(processor_aspiring_std_streams);
        let (w_term_interface, term_interface_stream_handles) = TermInterfaceMock::new(None);
        let terminal_interface_factory = TerminalInterfaceFactoryMock::default()
            .make_result(Either::Left(Box::new(w_term_interface)));
        let make_command_context_params_arc = Arc::new(Mutex::new(vec![]));
        let command_context_factory = CommandContextFactoryMock::new()
            .make_params(&make_command_context_params_arc)
            .make_result(Err(CommandError::ConnectionProblem("booga".to_string())));
        let command_execution_helper_factory = CommandExecutionHelperFactoryMock::default();
        let mut subject = Main {
            std_streams_factory_opt: Some(Box::new(std_streams_factory)),
            initial_args_parser: Box::new(InitialArgsParserMock::default()),
            term_interface_factory: Box::new(terminal_interface_factory),
            command_factory: Box::new(CommandFactoryMock::default()),
            command_context_factory: Box::new(command_context_factory),
            command_execution_helper_factory: Box::new(command_execution_helper_factory),
            command_processor_static_factory: Default::default(),
        };

        let result = subject
            .go(&["command".to_string(), "subcommand".to_string()])
            .await;

        let mut make_command_context_params = make_command_context_params_arc.lock().unwrap();
        let (ui_port, broadcast_handler_term_interface_opt) =
            make_command_context_params.pop().unwrap();
        StdStreamsAssertionMatrix::compose(
            &incidental_std_stream_handles,
            &processor_aspiring_std_stream_handles,
            &term_interface_stream_handles,
            broadcast_handler_term_interface_opt.as_deref(),
            Some(StreamFactoryStreamsAssertionMatrix {
                write_streams: WriteStreamsAssertion::with_one_piece_output("", "grrrghghghghrrr"),
                reading_attempts: vec![],
            }),
            None,
            Some(ProcessorTerminalInterfaceAssertionMatrix {
                standard_assertions: TerminalInterfaceAssertionMatrix {
                    term_interface_stream_handles: &term_interface_stream_handles,
                    write_streams: WriteStreamsAssertion::with_one_piece_output(
                        "",
                        "Can't connect to Daemon or Node \
            (ConnectionProblem(\"booga\")). Probably this means the Daemon isn't running.\n",
                    ),
                },
                read_attempts_opt: None,
            }),
            None,
        )
        .assert()
        .await;
        assert_eq!(result, 1);
    }

    #[test]
    fn populate_interactive_dependencies_produces_all_needed_to_block_printing_from_another_thread_when_the_lock_is_acquired(
    ) {
        //TODO rewrite me
        // let (test_stream_factory, test_stream_handle) = TestStreamFactory::new();
        // let (broadcast_handle, terminal_interface) =
        //     CommandContextDependencies::populate_interactive_dependencies(test_stream_factory)
        //         .unwrap();
        // {
        //     let _lock = terminal_interface.as_ref().unwrap().lock();
        //     broadcast_handle.send(UiNewPasswordBroadcast {}.tmb(0));
        //
        //     let output = test_stream_handle.stdout_so_far();
        //
        //     assert_eq!(output, "")
        // }
        // // Because of Win from Actions
        // #[cfg(target_os = "windows")]
        // win_test_import::thread::sleep(win_test_import::Duration::from_millis(200));
        //
        // let output_when_unlocked = test_stream_handle.stdout_so_far();
        //
        // assert_eq!(
        //     output_when_unlocked,
        //     "\nThe Node\'s database password has changed.\n\n"
        // )
    }

    #[tokio::test]
    async fn noninteractive_mode_works_when_special_ui_port_is_required() {
        let (processor_aspiring_std_streams, processor_aspiring_std_stream_handles) =
            make_async_std_streams(vec![]);
        let (incidental_std_streams, incidental_std_stream_handles) =
            make_async_std_streams(vec![]);
        let std_streams_factory = AsyncStdStreamsFactoryMock::default()
            .make_result(incidental_std_streams)
            .make_result(processor_aspiring_std_streams);
        let (w_term_interface, term_interface_stream_handles) = TermInterfaceMock::new(None);
        let terminal_interface_factory = TerminalInterfaceFactoryMock::default()
            .make_result(Either::Left(Box::new(w_term_interface)));
        let c_make_params_arc = Arc::new(Mutex::new(vec![]));
        let command_factory = CommandFactoryMock::default()
            .make_params(&c_make_params_arc)
            .make_result(Ok(Box::new(SetupCommand::new(&[]).unwrap())));
        let command_context = CommandContextMock::default();
        let make_command_context_params_arc = Arc::new(Mutex::new(vec![]));
        let command_context_factory = CommandContextFactoryMock::new()
            .make_params(&make_command_context_params_arc)
            .make_result(Ok(Box::new(command_context)));
        let command_execution_params_arc = Arc::new(Mutex::new(vec![]));
        let command_execution_helper = CommandExecutionHelperMock::default()
            .execute_command_params(&command_execution_params_arc)
            .execute_command_result(Ok(()));
        let command_execution_helper_factory = CommandExecutionHelperFactoryMock::default()
            .make_result(Box::new(command_execution_helper));
        let mut subject = Main {
            std_streams_factory_opt: Some(Box::new(std_streams_factory)),
            initial_args_parser: Box::new(InitialArgsParserReal::default()),
            term_interface_factory: Box::new(terminal_interface_factory),
            command_factory: Box::new(command_factory),
            command_context_factory: Box::new(command_context_factory),
            command_execution_helper_factory: Box::new(command_execution_helper_factory),
            command_processor_static_factory: Default::default(),
        };

        let result = subject
            .go(&[
                "masq".to_string(),
                "--ui-port".to_string(),
                "10000".to_string(),
                "setup".to_string(),
            ])
            .await;

        assert_eq!(result, 0);
        let c_make_params = c_make_params_arc.lock().unwrap();
        assert_eq!(*c_make_params, vec![vec!["setup".to_string(),],]);
        let mut make_command_context_params = make_command_context_params_arc.lock().unwrap();
        let (ui_port, broadcast_handler_term_interface_opt) =
            make_command_context_params.pop().unwrap();
        assert_eq!(ui_port, 10000);
        StdStreamsAssertionMatrix::compose(
            &incidental_std_stream_handles,
            &processor_aspiring_std_stream_handles,
            &term_interface_stream_handles,
            broadcast_handler_term_interface_opt.as_deref(),
            None,
            None,
            None,
            None,
        )
        .assert()
        .await;
        let mut command_execution_params = command_execution_params_arc.lock().unwrap();
        assert_eq!(
            *(*command_execution_params)
                .pop()
                .unwrap()
                .as_any()
                .downcast_ref::<SetupCommand>()
                .unwrap(),
            SetupCommand { values: vec![] }
        )
    }

    #[test]
    fn extract_subcommands_can_process_interactive_mode_request() {
        let args = vec!["masq".to_string()];

        let result = Main::extract_subcommand(&args);

        assert_eq!(result, None)
    }

    #[test]
    fn extract_subcommands_can_process_normal_non_interactive_request() {
        let args = vec!["masq", "setup", "--log-level", "off"]
            .iter()
            .map(|str| str.to_string())
            .collect::<Vec<String>>();

        let result = Main::extract_subcommand(&args);

        assert_eq!(
            result,
            Some(vec![
                "setup".to_string(),
                "--log-level".to_string(),
                "off".to_string()
            ])
        )
    }

    #[test]
    fn extract_subcommands_can_process_non_interactive_request_including_special_port() {
        let args = vec!["masq", "--ui-port", "10000", "setup", "--log-level", "off"]
            .iter()
            .map(|str| str.to_string())
            .collect::<Vec<String>>();

        let result = Main::extract_subcommand(&args);

        assert_eq!(
            result,
            Some(vec![
                "setup".to_string(),
                "--log-level".to_string(),
                "off".to_string()
            ])
        )
    }

    #[derive(Debug)]
    struct FakeCommand {
        output: String,
    }

    #[async_trait(?Send)]
    impl commands_common::Command for FakeCommand {
        async fn execute(
            self: Box<Self>,
            _context: &dyn CommandContext,
            term_interface: &dyn WTermInterface,
        ) -> Result<(), CommandError> {
            intentionally_blank!()
        }
        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    impl FakeCommand {
        pub fn new(output: &str) -> Self {
            Self {
                output: output.to_string(),
            }
        }
    }

    #[tokio::test]
    async fn interactive_mode_works_when_everything_is_copacetic() {
        let (processor_aspiring_std_streams, processor_aspiring_std_stream_handles) =
            make_async_std_streams(vec![]);
        let (incidental_std_streams, incidental_std_stream_handles) =
            make_async_std_streams(vec![]);
        let std_streams_factory = AsyncStdStreamsFactoryMock::default()
            .make_result(incidental_std_streams)
            .make_result(processor_aspiring_std_streams);
        let make_term_interface_params_arc = Arc::new(Mutex::new(vec![]));
        let stdin_mock = StdinMockBuilder::default()
            .read_line_result(Ok(ReadInput::Line("setup".to_string())))
            .read_line_result(Ok(ReadInput::Line("start".to_string())))
            .read_line_result(Ok(ReadInput::Line("exit".to_string())))
            .build();
        let (rw_term_interface, term_interface_stream_handles) =
            TermInterfaceMock::new(Some(stdin_mock));
        let terminal_interface_factory = TerminalInterfaceFactoryMock::default()
            .make_params(&make_term_interface_params_arc)
            .make_result(Either::Right(Box::new(rw_term_interface)));
        let make_command_params_arc = Arc::new(Mutex::new(vec![]));
        let command_factory = CommandFactoryMock::default()
            .make_params(&make_command_params_arc)
            .make_result(Ok(Box::new(FakeCommand::new("setup command"))))
            .make_result(Ok(Box::new(FakeCommand::new("start command"))));
        let command_context = CommandContextMock::new();
        let make_command_context_params_arc = Arc::new(Mutex::new(vec![]));
        let command_context_factory = CommandContextFactoryMock::new()
            .make_params(&make_command_context_params_arc)
            .make_result(Ok(Box::new(command_context)));
        let command_execution_params_arc = Arc::new(Mutex::new(vec![]));
        let command_execution_helper = CommandExecutionHelperMock::default()
            .execute_command_params(&command_execution_params_arc)
            .execute_command_result(Ok(()))
            .execute_command_result(Ok(()))
            .execute_command_result(Ok(()));
        let command_execution_helper_factory = CommandExecutionHelperFactoryMock::default()
            .make_result(Box::new(command_execution_helper));
        let mut subject = Main {
            std_streams_factory_opt: Some(Box::new(std_streams_factory)),
            initial_args_parser: Box::new(InitialArgsParserMock::default()),
            term_interface_factory: Box::new(terminal_interface_factory),
            command_factory: Box::new(command_factory),
            command_context_factory: Box::new(command_context_factory),
            command_execution_helper_factory: Box::new(command_execution_helper_factory),
            command_processor_static_factory: Default::default(),
        };

        let result = subject
            .go(&[
                "command".to_string(),
                "--param".to_string(),
                "value".to_string(),
            ])
            .await;

        assert_eq!(result, 0);
        let mut make_term_interface_params = make_term_interface_params_arc.lock().unwrap();
        let (is_interactive, passed_streams) = make_term_interface_params.remove(0);
        assert_eq!(is_interactive, true);
        let mut make_command_context_params = make_command_context_params_arc.lock().unwrap();
        let (ui_port, broadcast_handler_term_interface_opt) =
            make_command_context_params.pop().unwrap();
        assert_eq!(ui_port, 5333);
        let make_command_params = make_command_params_arc.lock().unwrap();
        assert_eq!(
            *make_command_params,
            vec![vec!["setup".to_string()], vec!["start".to_string()]]
        );
        StdStreamsAssertionMatrix::compose(
            &incidental_std_stream_handles,
            &processor_aspiring_std_stream_handles,
            &term_interface_stream_handles,
            broadcast_handler_term_interface_opt.as_deref(),
            None,
            None,
            Some(ProcessorTerminalInterfaceAssertionMatrix {
                standard_assertions: TerminalInterfaceAssertionMatrix {
                    term_interface_stream_handles: &term_interface_stream_handles,
                    write_streams: WriteStreamsAssertion::with_flushed_strings(
                        vec!["setup command", "start command"],
                        vec![""],
                    ),
                },
                read_attempts_opt: Some(vec![(), (), ()]),
            }),
            Some(TerminalInterfaceAssertionMatrix {
                term_interface_stream_handles: &term_interface_stream_handles,
                write_streams: WriteStreamsAssertion::with_one_piece_output("", ""),
            }),
        )
        .assert()
        .await;
        let command_execution_helper = command_execution_params_arc.lock().unwrap();
        assert_eq!(command_execution_helper.len(), 3)
    }

    #[tokio::test]
    async fn interactive_mode_works_for_stdin_read_error() {
        let (incidental_std_streams, incidental_std_stream_handles) =
            make_async_std_streams(vec![]);
        let (processor_aspiring_std_streams, processor_aspiring_std_stream_handles) =
            make_async_std_streams(vec![]);
        let std_streams_factory = AsyncStdStreamsFactoryMock::default()
            .make_result(incidental_std_streams)
            .make_result(processor_aspiring_std_streams);
        let make_term_interface_params_arc = Arc::new(Mutex::new(vec![]));
        let stdin_mock = StdinMockBuilder::default()
            .read_line_result(Err(ReadError::ConnectionRefused))
            .build();
        let (rw_term_interface, term_interface_stream_handles) =
            TermInterfaceMock::new(Some(stdin_mock));
        let terminal_interface_factory = TerminalInterfaceFactoryMock::default()
            .make_params(&make_term_interface_params_arc)
            .make_result(Either::Right(Box::new(rw_term_interface)));
        let command_factory = CommandFactoryMock::default();
        let close_params_arc = Arc::new(Mutex::new(vec![]));
        let command_context = CommandContextMock::default().close_params(&close_params_arc);
        let make_command_context_params_arc = Arc::new(Mutex::new(vec![]));
        let command_context_factory = CommandContextFactoryMock::new()
            .make_params(&make_command_context_params_arc)
            .make_result(Ok(Box::new(command_context)));
        let command_execution_helper_factory = CommandExecutionHelperFactoryMock::default();
        let mut subject = Main {
            std_streams_factory_opt: Some(Box::new(std_streams_factory)),
            initial_args_parser: Box::new(InitialArgsParserMock::default()),
            term_interface_factory: Box::new(terminal_interface_factory),
            command_factory: Box::new(command_factory),
            command_context_factory: Box::new(command_context_factory),
            command_execution_helper_factory: Box::new(command_execution_helper_factory),
            command_processor_static_factory: Default::default(),
        };

        let result = subject.go(&["command".to_string()]).await;

        assert_eq!(result, 1);
        let mut make_term_interface_params = make_term_interface_params_arc.lock().unwrap();
        let (is_interactive, passed_streams) = make_term_interface_params.remove(0);
        assert_eq!(is_interactive, true);
        assert!(make_term_interface_params.is_empty());
        assert_eq!(
            term_interface_stream_handles.stderr_all_in_one(),
            "ConnectionRefused\n".to_string()
        );
        let mut make_command_context_params = make_command_context_params_arc.lock().unwrap();
        let (ui_port, broadcast_handler_term_interface_opt) =
            make_command_context_params.pop().unwrap();
        StdStreamsAssertionMatrix::compose(
            &incidental_std_stream_handles,
            &processor_aspiring_std_stream_handles,
            &term_interface_stream_handles,
            broadcast_handler_term_interface_opt.as_deref(),
            None,
            None,
            Some(ProcessorTerminalInterfaceAssertionMatrix {
                standard_assertions: TerminalInterfaceAssertionMatrix {
                    term_interface_stream_handles: &term_interface_stream_handles,
                    write_streams: WriteStreamsAssertion::with_one_piece_output(
                        "",
                        "ConnectionRefused\n",
                    ),
                },
                read_attempts_opt: Some(vec![]),
            }),
            Some(TerminalInterfaceAssertionMatrix {
                term_interface_stream_handles: &term_interface_stream_handles,
                write_streams: WriteStreamsAssertion::with_one_piece_output("", ""),
            }),
        )
        .assert()
        .await;
        let close_params = close_params_arc.lock().unwrap();
        assert_eq!(*close_params, vec![()])
    }

    struct StdStreamsAssertionMatrix<'test> {
        processor_std_streams: AssertionUnit<'test, StreamFactoryStreamsAssertionMatrix<'test>>,
        incidental_std_streams: AssertionUnit<'test, StreamFactoryStreamsAssertionMatrix<'test>>,
        processor_term_interface:
            AssertionUnit<'test, ProcessorTerminalInterfaceAssertionMatrix<'test>>,
        broadcast_handler_term_interface: BroadcastHandlerTerminalInterfaceAssertionMatrix<'test>,
    }

    struct AssertionUnit<'test, AssertionValues> {
        handles: &'test AsyncTestStreamHandles,
        assertions_opt: Option<AssertionValues>,
    }

    impl<'test, AssertionValues> AssertionUnit<'test, AssertionValues> {
        fn new(
            handles: &'test AsyncTestStreamHandles,
            assertions_opt: Option<AssertionValues>,
        ) -> Self {
            Self {
                handles,
                assertions_opt,
            }
        }
    }

    type EitherOnePieceOrFlushedStrings<'test> = Either<&'test str, Vec<&'test str>>;

    struct WriteStreamsAssertion<'test> {
        expected_stdout: EitherOnePieceOrFlushedStrings<'test>,
        expected_stderr: EitherOnePieceOrFlushedStrings<'test>,
    }

    impl<'test> WriteStreamsAssertion<'test> {
        fn with_one_piece_output(
            stdout_concatenated: &'test str,
            stderr_concatenated: &'test str,
        ) -> WriteStreamsAssertion<'test> {
            Self {
                expected_stdout: Either::Left(stdout_concatenated),
                expected_stderr: Either::Left(stderr_concatenated),
            }
        }
        fn with_flushed_strings(
            stdout_flushed_expected: Vec<&'test str>,
            stderr_flushed_expected: Vec<&'test str>,
        ) -> WriteStreamsAssertion<'test> {
            Self {
                expected_stdout: Either::Right(stdout_flushed_expected),
                expected_stderr: Either::Right(stderr_flushed_expected),
            }
        }
    }

    struct StreamFactoryStreamsAssertionMatrix<'test> {
        write_streams: WriteStreamsAssertion<'test>,
        reading_attempts: Vec<()>,
    }

    struct TerminalInterfaceAssertionMatrix<'test> {
        term_interface_stream_handles: &'test AsyncTestStreamHandles,
        write_streams: WriteStreamsAssertion<'test>,
    }

    struct ProcessorTerminalInterfaceAssertionMatrix<'test> {
        standard_assertions: TerminalInterfaceAssertionMatrix<'test>,
        // None ... non-interactive mode,
        // Some ... interactive mode
        read_attempts_opt: Option<Vec<()>>,
    }

    struct BroadcastHandlerTerminalInterfaceAssertionMatrix<'test> {
        w_term_interface_opt: Option<&'test dyn WTermInterfaceImplementingSend>,
        expected_std_streams_usage_opt: Option<TerminalInterfaceAssertionMatrix<'test>>,
    }

    impl<'test> StdStreamsAssertionMatrix<'test> {
        pub fn compose(
            incidental_std_stream_handles: &'test AsyncTestStreamHandles,
            processor_aspiring_std_stream_handles: &'test AsyncTestStreamHandles,
            processor_term_interface_stream_handles: &'test AsyncTestStreamHandles,
            // Caution, this one should also always be supplied despite it is an option
            broadcast_handler_term_interface_opt: Option<&'test dyn WTermInterfaceImplementingSend>,
            expected_usage_of_incidental_std_streams_opt: Option<
                StreamFactoryStreamsAssertionMatrix<'test>,
            >,
            expected_usage_of_processor_aspiring_std_streams_opt: Option<
                StreamFactoryStreamsAssertionMatrix<'test>,
            >,
            expected_processor_term_interface_usage_opt: Option<
                ProcessorTerminalInterfaceAssertionMatrix<'test>,
            >,
            expected_broadcast_handler_term_interface_usage_opt: Option<
                TerminalInterfaceAssertionMatrix<'test>,
            >,
        ) -> Self {
            Self {
                processor_std_streams: AssertionUnit::new(
                    incidental_std_stream_handles,
                    expected_usage_of_incidental_std_streams_opt,
                ),
                incidental_std_streams: AssertionUnit::new(
                    processor_aspiring_std_stream_handles,
                    expected_usage_of_processor_aspiring_std_streams_opt,
                ),
                processor_term_interface: AssertionUnit::new(
                    processor_term_interface_stream_handles,
                    expected_processor_term_interface_usage_opt,
                ),
                broadcast_handler_term_interface:
                    BroadcastHandlerTerminalInterfaceAssertionMatrix {
                        w_term_interface_opt: broadcast_handler_term_interface_opt,
                        expected_std_streams_usage_opt:
                            expected_broadcast_handler_term_interface_usage_opt,
                    },
            }
        }

        async fn assert(self) {
            let processor_streams = self.processor_std_streams;
            let (expected_stdout, expected_stderr, expected_read_attempts_opt) =
                Self::prepare_assertion_values_of_simple_streams(processor_streams.assertions_opt);
            assert_stream_writes(processor_streams.handles, expected_stdout, expected_stderr);
            assert_stream_reads(processor_streams.handles, expected_read_attempts_opt);
            let incidental_streams = self.incidental_std_streams;
            let (expected_stdout, expected_stderr, expected_read_attempts_opt) =
                Self::prepare_assertion_values_of_simple_streams(incidental_streams.assertions_opt);
            assert_stream_writes(processor_streams.handles, expected_stdout, expected_stderr);
            assert_stream_reads(processor_streams.handles, expected_read_attempts_opt);
            let processor_term_interface = self.processor_term_interface;
            let (expected_stdout, expected_stderr, expected_read_attempts_opt) =
                match processor_term_interface.assertions_opt {
                    Some(assertion_values) => (
                        assertion_values
                            .standard_assertions
                            .write_streams
                            .expected_stdout,
                        assertion_values
                            .standard_assertions
                            .write_streams
                            .expected_stderr,
                        assertion_values.read_attempts_opt,
                    ),
                    None => Self::null_expected(),
                };
            assert_stream_writes(
                processor_term_interface.handles,
                expected_stdout,
                expected_stderr,
            );
            assert_stream_reads(processor_term_interface.handles, expected_read_attempts_opt);
            let broadcast_term_interface = self.broadcast_handler_term_interface;
            assert_broadcast_term_interface_outputs(
                broadcast_term_interface.w_term_interface_opt,
                broadcast_term_interface.expected_std_streams_usage_opt,
            )
            .await;
        }

        fn prepare_assertion_values_of_simple_streams(
            matrix_opt: Option<StreamFactoryStreamsAssertionMatrix>,
        ) -> (
            EitherOnePieceOrFlushedStrings,
            EitherOnePieceOrFlushedStrings,
            Option<Vec<()>>,
        ) {
            match matrix_opt {
                Some(assertion_values) => (
                    assertion_values.write_streams.expected_stdout,
                    assertion_values.write_streams.expected_stderr,
                    Some(assertion_values.reading_attempts),
                ),
                None => Self::null_expected(),
            }
        }

        fn null_expected() -> (
            EitherOnePieceOrFlushedStrings<'static>,
            EitherOnePieceOrFlushedStrings<'static>,
            Option<Vec<()>>,
        ) {
            (Either::Left(""), Either::Left(""), None)
        }
    }

    async fn assert_broadcast_term_interface_outputs<'test>(
        term_interface_opt: Option<&dyn WTermInterfaceImplementingSend>,
        expected_std_streams_usage_opt: Option<TerminalInterfaceAssertionMatrix<'test>>,
    ) {
        match (term_interface_opt, expected_std_streams_usage_opt) {
            (Some(w_terminal), Some(expected_usage)) => {
               assert_stream_writes(expected_usage.term_interface_stream_handles, expected_usage.write_streams.expected_stdout, expected_usage.write_streams.expected_stderr);
                let (mut stdout, mut stdout_flusher) = w_terminal.stdout();
                let (mut stderr, mut stderr_flusher) = w_terminal.stderr();
                stdout.write("AbCdEfG").await;
                drop(stdout_flusher);
                assert_eq!(
                    expected_usage.term_interface_stream_handles.stdout_all_in_one(),
                    "AbCdEfG"
                );
                stderr.write("1a2b3c4").await;
                drop(stderr_flusher);
                assert_eq!(
                    expected_usage.term_interface_stream_handles.stderr_all_in_one(),
                    "1a2b3c4"
                )}
            (None, None) => (),
            (actual_opt, expected_opt) => panic!("Interactive mode was expected: {}. But broadcast terminal interface was created and supplied: {}. (Non-interactive mode is not supposed to have one)", expected_opt.is_some(), actual_opt.is_some())
        }
    }

    fn assert_stream_writes(
        original_stream_handles: &AsyncTestStreamHandles,
        stdout_expected: EitherOnePieceOrFlushedStrings<'_>,
        stderr_expected: EitherOnePieceOrFlushedStrings<'_>,
    ) {
        fn owned_strings(strings: Vec<&str>) -> Vec<String> {
            strings.into_iter().map(|s| s.to_string()).collect()
        }

        match stdout_expected {
            Either::Left(one_piece) => assert_single_stream(
                "Stdout",
                original_stream_handles.stdout_all_in_one(),
                one_piece.to_string(),
            ),
            Either::Right(flushed_strings) => assert_single_stream(
                "Stdout",
                original_stream_handles.stdout_flushed_strings(),
                owned_strings(flushed_strings),
            ),
        }

        match stderr_expected {
            Either::Left(one_piece) => assert_single_stream(
                "Stderr",
                original_stream_handles.stderr_all_in_one(),
                one_piece.to_string(),
            ),
            Either::Right(flushed_strings) => assert_single_stream(
                "Stderr",
                original_stream_handles.stderr_flushed_strings(),
                owned_strings(flushed_strings),
            ),
        }
    }

    fn assert_single_stream<ExpectedValues>(
        std_stream_name: &str,
        actual_output: ExpectedValues,
        expected_output: ExpectedValues,
    ) where
        ExpectedValues: Debug + PartialEq,
    {
        assert_eq!(
            actual_output, expected_output,
            "We expected this printed by {} {:?} but was {:?}",
            std_stream_name, expected_output, actual_output
        );
    }

    // enum FetchersAndExpectedValues<'stream_handles>{
    //     StdoutOnePiece{fetcher: Box<&'stream_handles (dyn Future<Output = String>)>, expected_output: String},
    //     StderrOnePiece{fetcher: Box<&'stream_handles (dyn Future<Output = String>)>, expected_output: String},
    //     StdoutFlushedStrings{fetcher: Box<&'stream_handles (dyn Future<Output = Vec<String>>)>, expected_output: Vec<String>},
    //     StderrFlushedStrings{fetcher: Box<&'stream_handles (dyn Future<Output = Vec<String>>)>, expected_output: Vec<String>}
    // }
    //
    // impl FetchersAndExpectedValues<'_> {
    //     async fn assert(self){
    //         match self {
    //             FetchersAndExpectedValues::StdoutOnePiece {fetcher, expected_output} => {
    //                 Self::assert_single_stream("Stdout", fetcher, expected_output).await
    //             }
    //             FetchersAndExpectedValues::StderrOnePiece { fetcher, expected_output } => {
    //                 Self::assert_single_stream("Stderr", fetcher, expected_output).await
    //             }
    //             FetchersAndExpectedValues::StdoutFlushedStrings { fetcher, expected_output } => {
    //                 Self::assert_single_stream("Stdout", fetcher, expected_output).await
    //             }
    //             FetchersAndExpectedValues::StderrFlushedStrings { fetcher, expected_output } => {
    //                 Self::assert_single_stream("Stderr", fetcher, expected_output).await
    //             }
    //         }
    //     }
    //
    //     fn assert_single_stream<ExpectedValues>(std_stream_name: &str, actual_output: ExpectedValues, expected_output: ExpectedValues)where ExpectedValues: Debug + PartialEq{
    //         assert_eq!(
    //             actual_output,
    //             expected_output,
    //             "We expected this printed by {} {:?} but was {:?}",
    //             std_stream_name,
    //             expected_output,
    //             actual_output
    //         );
    //     }
    // }

    fn assert_stream_reads(
        original_stream_handles: &AsyncTestStreamHandles,
        expected_reads_opt: Option<Vec<()>>,
    ) {
        todo!()
    }
}
