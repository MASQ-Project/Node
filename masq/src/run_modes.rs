// Copyright (c) 2024, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::command_context_factory::{CommandContextFactory, CommandContextFactoryReal};
use crate::command_factory::CommandFactoryError::UnrecognizedSubcommand;
use crate::command_factory::{CommandFactory, CommandFactoryReal};
use crate::command_processor::{
    CommandExecutionHelperFactory, CommandExecutionHelperFactoryReal, CommandProcessor,
    CommandProcessorFactory,
};
use crate::commands::commands_common::CommandError;
use crate::communications::broadcast_handlers::{BroadcastHandle, BroadcastHandler};
use crate::non_interactive_clap::{InitialArgsParser, InitialArgsParserReal};
use crate::terminal::async_streams::{
    AsyncStdStreams, AsyncStdStreamsFactory, AsyncStdStreamsFactoryReal,
};
use crate::terminal::terminal_interface_factory::{
    TerminalInterfaceFactory, TerminalInterfaceFactoryReal,
};
use crate::terminal::{RWTermInterface, WTermInterface};
use crate::write_async_stream_and_flush;
use async_trait::async_trait;
use itertools::Either;
use std::io::Write;
use std::ops::Not;
use std::sync::Arc;
use tokio::io::{AsyncWrite, AsyncWriteExt};

pub struct Main {
    std_streams_factory: Box<dyn AsyncStdStreamsFactory>,
    initial_args_parser: Box<dyn InitialArgsParser>,
    term_interface_factory: Box<dyn TerminalInterfaceFactory>,
    // Optional in order to allow a vacancy after pulling the value out
    command_factory_opt: Option<Box<dyn CommandFactory>>,
    command_context_factory: Box<dyn CommandContextFactory>,
    command_execution_helper_factory: Box<dyn CommandExecutionHelperFactory>,
    command_processor_factory: CommandProcessorFactory,
}

impl Default for Main {
    fn default() -> Self {
        Self {
            std_streams_factory: Box::new(AsyncStdStreamsFactoryReal::default()),
            initial_args_parser: Box::new(InitialArgsParserReal::default()),
            term_interface_factory: Box::new(TerminalInterfaceFactoryReal::default()),
            command_factory_opt: Some(Box::new(CommandFactoryReal::default())),
            command_context_factory: Box::new(CommandContextFactoryReal::default()),
            command_execution_helper_factory: Box::new(CommandExecutionHelperFactoryReal::default()),
            command_processor_factory: Default::default(),
        }
    }
}

impl Main {
    pub async fn go(&mut self, args: &[String]) -> u8 {
        let std_streams_factory = &self.std_streams_factory;
        let mut incidental_streams = std_streams_factory.make();
        let initialization_args = self
            .initial_args_parser
            .parse_initialization_args(args, &incidental_streams);
        let initial_subcommand_opt = Self::extract_subcommand(args);
        let term_interface = self.term_interface_factory.make(
            initial_subcommand_opt.is_none(),
            std_streams_factory.as_ref(),
        );

        match self
            .do_this_work(
                initialization_args.ui_port,
                &mut incidental_streams,
                term_interface,
                initial_subcommand_opt.as_deref(),
            )
            .await
        {
            Ok(_) => 0,
            Err(_) => 1,
        }
    }

    async fn do_this_work(
        &mut self,
        ui_port: u16,
        incidental_streams: &mut AsyncStdStreams,
        term_interface: Either<Box<dyn WTermInterface>, Box<dyn RWTermInterface>>,
        initial_subcommand_opt: Option<&[String]>,
    ) -> Result<(), ()> {
        let mut command_processor = self.initialize_processor(ui_port, incidental_streams, term_interface).await?;

        let result = command_processor
            .process_command_line(initial_subcommand_opt.as_deref())
            .await;

        command_processor.close().await;

        result
    }

    async fn initialize_processor(
        &mut self,
        ui_port: u16,
        incidental_streams: &mut AsyncStdStreams,
        term_interface: Either<Box<dyn WTermInterface>, Box<dyn RWTermInterface>>,
    ) -> Result<Box<dyn CommandProcessor>, ()>{
        let command_context_factory = self.command_context_factory.as_ref();
        let execution_helper_factory = self.command_execution_helper_factory.as_ref();
        let command_factory = self
            .command_factory_opt
            .take()
            .expect("CommandFactory wasn't prepared properly");

        match self
            .command_processor_factory
            .make(
                term_interface,
                command_context_factory,
                execution_helper_factory,
                command_factory,
                ui_port,
            )
            .await
        {
            Ok(processor) => Ok(processor),
            Err(e) => {
                write_async_stream_and_flush!(
                    &mut incidental_streams.stderr,
                    "Processor initialization failed: {}",
                    e
                );
                Err(())
            }
        }
    }

    fn extract_subcommand(args: &[String]) -> Option<Vec<String>> {
        fn none_starts_with_two_dashes(
            (_, (one_program_arg, program_arg_next_to_the_previous)): &(usize, (&String, &String)),
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
            .find(none_starts_with_two_dashes)
            .map(|(index, _)| args.iter().skip(index + 1).cloned().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command_context::CommandContext;
    use crate::command_context::ContextError::Other;
    use crate::command_factory::CommandFactoryError::CommandSyntax;
    use crate::commands::commands_common;
    use crate::commands::commands_common::CommandError;
    use crate::commands::commands_common::CommandError::Transmission;
    use crate::commands::setup_command::SetupCommand;
    use crate::masq_short_writeln;
    use crate::run_modes::tests::StreamType::{Stderr, Stdout};
    use crate::terminal::{
        FlushHandle, ReadError, ReadInput, TerminalWriter, WTermInterfaceDupAndSend,
    };
    use crate::test_utils::mocks::{
        make_async_std_streams, make_terminal_writer, AsyncStdStreamsFactoryMock,
        AsyncTestStreamHandles, CommandContextFactoryMock, CommandContextMock,
        CommandExecutionHelperFactoryMock, CommandExecutionHelperMock, CommandFactoryMock,
        CommandProcessorMock, InitialArgsParserMock, MockCommand, MockTerminalMode, StdinMock,
        TermInterfaceMock, TerminalInterfaceFactoryMock,
    };
    use masq_lib::intentionally_blank;
    use masq_lib::messages::{ToMessageBody, UiNewPasswordBroadcast, UiShutdownRequest};
    use masq_lib::test_utils::fake_stream_holder::StdinReadCounter;
    use std::any::Any;
    use std::fmt::Debug;
    use std::sync::{Arc, Mutex};

    #[cfg(target_os = "windows")]
    mod win_test_import {
        pub use std::thread;
        pub use std::time::Duration;
    }

    #[tokio::test]
    async fn non_interactive_mode_works_when_everything_is_copacetic() {
        let make_std_streams_params_arc = Arc::new(Mutex::new(vec![]));
        let make_term_interface_params_arc = Arc::new(Mutex::new(vec![]));
        let make_command_context_params_arc = Arc::new(Mutex::new(vec![]));
        let execute_command_params_arc = Arc::new(Mutex::new(vec![]));
        let make_command_params_arc = Arc::new(Mutex::new(vec![]));
        let close_params_arc = Arc::new(Mutex::new(vec![]));
        let (processor_aspiring_std_streams, processor_aspiring_std_stream_handles) =
            make_async_std_streams(vec![]);
        let (incidental_std_streams, incidental_std_stream_handles) =
            make_async_std_streams(vec![]);
        let std_streams_factory = AsyncStdStreamsFactoryMock::default()
            .make_params(&make_std_streams_params_arc)
            .make_result(incidental_std_streams)
            .make_result(processor_aspiring_std_streams);
        let (w_term_interface, term_interface_stream_handles) =
            TermInterfaceMock::new_non_interactive();
        let terminal_interface_factory = TerminalInterfaceFactoryMock::default()
            .make_params(&make_term_interface_params_arc)
            .make_result(Either::Left(Box::new(w_term_interface)));
        let command = MockCommand::new(UiShutdownRequest {}.tmb(1));
        let command_factory = CommandFactoryMock::default()
            .make_params(&make_command_params_arc)
            .make_result(Ok(Box::new(command)));
        let command_context = CommandContextMock::default().close_params(&close_params_arc);
        let command_context_factory = CommandContextFactoryMock::default()
            .make_params(&make_command_context_params_arc)
            .make_result(Ok(Box::new(command_context)));
        let command_execution_helper = CommandExecutionHelperMock::default()
            .execute_command_params(&execute_command_params_arc)
            .execute_command_result(Ok(()));
        let command_execution_helper_factory = CommandExecutionHelperFactoryMock::default()
            .make_result(Box::new(command_execution_helper));
        let mut subject = Main {
            std_streams_factory: Box::new(std_streams_factory),
            initial_args_parser: Box::new(InitialArgsParserMock::default()),
            term_interface_factory: Box::new(terminal_interface_factory),
            command_factory_opt: Some(Box::new(command_factory)),
            command_context_factory: Box::new(command_context_factory),
            command_execution_helper_factory: Box::new(command_execution_helper_factory),
            command_processor_factory: Default::default(),
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
            BareStreamsFromStreamFactoryAssertionMatrix::assert_streams_not_used(
                &incidental_std_stream_handles,
            ),
            BareStreamsFromStreamFactoryAssertionMatrix::assert_streams_not_used(
                &processor_aspiring_std_stream_handles,
            ),
            ProcessorTerminalInterfaceAssertionMatrix::assert_terminal_not_used(&term_interface_stream_handles),
            BroadcastHandlerTerminalInterfaceAssertionMatrix::assert_terminal_not_created(
                broadcast_handle_term_interface_opt.as_ref(),
            ),
        )
            .assert()
            .await;
        let c_make_params = make_command_params_arc.lock().unwrap();
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
        let (command, captured_command_context_id, captured_terminal_interface_id) =
            execute_command_params.remove(0);
        assert!(execute_command_params.is_empty());
        let transact_params_arc = Arc::new(Mutex::new(vec![]));
        let mut context = CommandContextMock::new()
            .transact_params(&transact_params_arc)
            .transact_result(Err(Other("not really an error".to_string())));
        let (mut w_term_interface, term_interface_stream_handles) =
            TermInterfaceMock::new_non_interactive();

        let result = command.execute(&mut context, &mut w_term_interface).await;

        assert_eq!(
            result,
            Err(Transmission("Other(\"not really an error\")".to_string()))
        );
        let transact_params = transact_params_arc.lock().unwrap();
        assert_eq!(*transact_params, vec![(UiShutdownRequest {}.tmb(1), 1000)]);
        StdStreamsAssertionMatrix::compose(
            BareStreamsFromStreamFactoryAssertionMatrix::assert_streams_not_used(
                &incidental_std_stream_handles,
            ),
            BareStreamsFromStreamFactoryAssertionMatrix::assert_streams_not_used(
                &processor_aspiring_std_stream_handles,
            ),
            ProcessorTerminalInterfaceAssertionMatrix {
                standard_assertions: TerminalInterfaceAssertionMatrix {
                    term_interface_stream_handles: &term_interface_stream_handles,
                    expected_writes: FlushesWriteStreamsAssertion {
                        stdout: vec!["MockCommand output"],
                        stderr: vec!["MockCommand error"],
                    }
                        .into(),
                    read_attempts_opt: None,
                },
            },
            BroadcastHandlerTerminalInterfaceAssertionMatrix::assert_terminal_not_created(
                broadcast_handle_term_interface_opt.as_ref(),
            ),
        )
            .assert()
            .await;
        let close_params = close_params_arc.lock().unwrap();
        assert_eq!(*close_params, vec![()]);
    }

    #[tokio::test]
    async fn go_works_when_command_is_invalid() {
        let make_std_streams_params_arc = Arc::new(Mutex::new(vec![]));
        let make_term_interface_params_arc = Arc::new(Mutex::new(vec![]));
        let make_command_context_params_arc = Arc::new(Mutex::new(vec![]));
        let make_command_params_arc = Arc::new(Mutex::new(vec![]));;
        let close_params_arc = Arc::new(Mutex::new(vec![]));
        let (incidental_std_streams, incidental_std_stream_handles) =
            make_async_std_streams(vec![]);
        let (processor_aspiring_std_streams, processor_aspiring_std_stream_handles) =
            make_async_std_streams(vec![]);
        let std_streams_factory = AsyncStdStreamsFactoryMock::default()
            .make_params(&make_std_streams_params_arc)
            .make_result(incidental_std_streams)
            .make_result(processor_aspiring_std_streams);
        let (w_term_interface, term_interface_stream_handles) =
            TermInterfaceMock::new_non_interactive();
        let terminal_interface_factory = TerminalInterfaceFactoryMock::default()
            .make_params(&make_term_interface_params_arc)
            .make_result(Either::Left(Box::new(w_term_interface)));
        let command_factory = CommandFactoryMock::default()
            .make_params(&make_command_params_arc)
            .make_result(Err(UnrecognizedSubcommand("booga".to_string())));
        let processor = CommandContextMock::default().close_params(&close_params_arc);
        let command_context_factory = CommandContextFactoryMock::default()
            .make_params(&make_command_context_params_arc)
            .make_result(Ok(Box::new(processor)));
        let command_execution_helper = CommandExecutionHelperMock::default();
        let command_execution_helper_factory = CommandExecutionHelperFactoryMock::default()
            .make_result(Box::new(command_execution_helper));
        let mut subject = Main {
            std_streams_factory: Box::new(std_streams_factory),
            initial_args_parser: Box::new(InitialArgsParserMock::default()),
            term_interface_factory: Box::new(terminal_interface_factory),
            command_factory_opt: Some(Box::new(command_factory)),
            command_context_factory: Box::new(command_context_factory),
            command_execution_helper_factory: Box::new(command_execution_helper_factory),
            command_processor_factory: Default::default(),
        };

        let result = subject
            .go(&["command".to_string(), "subcommand".to_string()])
            .await;

        let make_std_streams_params = make_std_streams_params_arc.lock().unwrap();
        // Only one, because the write-only terminal interface is mocked (it requires one set of
        // these streams otherwise)
        assert_eq!(*make_std_streams_params, vec![()]);
        let mut make_processor_params = make_command_context_params_arc.lock().unwrap();
        let (ui_port, broadcast_handle_term_interface_opt) = make_processor_params.pop().unwrap();
        assert_eq!(ui_port, 5333);
        StdStreamsAssertionMatrix::compose(
            BareStreamsFromStreamFactoryAssertionMatrix::assert_streams_not_used(
                &incidental_std_stream_handles,
            ),
            BareStreamsFromStreamFactoryAssertionMatrix::assert_streams_not_used(
                &processor_aspiring_std_stream_handles,
            ),
            ProcessorTerminalInterfaceAssertionMatrix {
                standard_assertions: TerminalInterfaceAssertionMatrix {
                    term_interface_stream_handles: &term_interface_stream_handles,
                    expected_writes: OnePieceWriteStreamsAssertion {
                        stdout_opt: None,
                        stderr_opt: Some("Unrecognized command: 'booga'\n"),
                    }
                    .into(),
                    read_attempts_opt: None,
                },
            },
            BroadcastHandlerTerminalInterfaceAssertionMatrix::assert_terminal_not_created(
                broadcast_handle_term_interface_opt.as_ref(),
            ),
        )
        .assert()
        .await;
        let c_make_params = make_command_params_arc.lock().unwrap();
        assert_eq!(*c_make_params, vec![vec!["subcommand".to_string()],]);
        let close_params = close_params_arc.lock().unwrap();
        assert_eq!(*close_params, vec![()]);
        assert_eq!(result, 1);
    }

    #[tokio::test]
    async fn go_works_when_command_execution_fails() {
        let make_command_context_factory_params_arc = Arc::new(Mutex::new(vec![]));
        let execute_command_params_arc = Arc::new(Mutex::new(vec![]));
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
        let (w_term_interface, term_interface_stream_handles) =
            TermInterfaceMock::new_non_interactive();
        let terminal_interface_factory = TerminalInterfaceFactoryMock::default()
            .make_result(Either::Left(Box::new(w_term_interface)));
        let command_context = CommandContextMock::default();
        let command_context_factory = CommandContextFactoryMock::new()
            .make_params(&make_command_context_factory_params_arc)
            .make_result(Ok(Box::new(command_context)));
        let command_execution_helper = CommandExecutionHelperMock::default()
            .execute_command_params(&execute_command_params_arc)
            .execute_command_result(Err(Transmission("Booga!".to_string())));
        let command_execution_helper_factory = CommandExecutionHelperFactoryMock::default()
            .make_result(Box::new(command_execution_helper));
        let mut subject = Main {
            std_streams_factory: Box::new(std_streams_factory),
            initial_args_parser: Box::new(InitialArgsParserMock::default()),
            term_interface_factory: Box::new(terminal_interface_factory),
            command_factory_opt: Some(Box::new(command_factory)),
            command_context_factory: Box::new(command_context_factory),
            command_execution_helper_factory: Box::new(command_execution_helper_factory),
            command_processor_factory: Default::default(),
        };

        let result = subject
            .go(&["command".to_string(), "subcommand".to_string()])
            .await;

        let mut make_processor_params = make_command_context_factory_params_arc.lock().unwrap();
        let (ui_port, broadcast_handler_term_interface_opt) = make_processor_params.pop().unwrap();
        assert_eq!(ui_port, 5333);
        StdStreamsAssertionMatrix::compose(
            BareStreamsFromStreamFactoryAssertionMatrix::assert_streams_not_used(
                &incidental_std_stream_handles,
            ),
            BareStreamsFromStreamFactoryAssertionMatrix::assert_streams_not_used(
                &processor_aspiring_std_stream_handles,
            ),
            ProcessorTerminalInterfaceAssertionMatrix {
                standard_assertions: TerminalInterfaceAssertionMatrix {
                    term_interface_stream_handles: &term_interface_stream_handles,
                    expected_writes: OnePieceWriteStreamsAssertion {
                        stdout_opt: None,
                        stderr_opt: Some("Transmission problem: Booga!\n"),
                    }
                    .into(),
                    read_attempts_opt: None,
                },
            },
            BroadcastHandlerTerminalInterfaceAssertionMatrix::assert_terminal_not_created(
                broadcast_handler_term_interface_opt.as_ref(),
            ),
        )
        .assert()
        .await;
        let mut execute_command_params = execute_command_params_arc.lock().unwrap();
        let (dyn_command, captured_command_context_id, captured_term_interface_id) =
            execute_command_params.remove(0);
        let actual_command = dyn_command.as_any().downcast_ref::<MockCommand>().unwrap();
        assert_eq!(actual_command.message, command.message);
        assert!(execute_command_params.is_empty());
        assert_eq!(result, 1);
    }

    #[tokio::test]
    async fn go_works_when_daemon_is_not_running() {
        let make_command_context_params_arc = Arc::new(Mutex::new(vec![]));
        let (processor_aspiring_std_streams, processor_aspiring_std_stream_handles) =
            make_async_std_streams(vec![]);
        let (incidental_std_streams, incidental_std_stream_handles) =
            make_async_std_streams(vec![]);
        let std_streams_factory = AsyncStdStreamsFactoryMock::default()
            .make_result(incidental_std_streams)
            .make_result(processor_aspiring_std_streams);
        let (w_term_interface, term_interface_stream_handles) =
            TermInterfaceMock::new_non_interactive();
        let terminal_interface_factory = TerminalInterfaceFactoryMock::default()
            .make_result(Either::Left(Box::new(w_term_interface)));
        let command_context_factory = CommandContextFactoryMock::new()
            .make_params(&make_command_context_params_arc)
            .make_result(Err(CommandError::ConnectionProblem("booga".to_string())));
        let command_execution_helper_factory = CommandExecutionHelperFactoryMock::default();
        let mut subject = Main {
            std_streams_factory: Box::new(std_streams_factory),
            initial_args_parser: Box::new(InitialArgsParserMock::default()),
            term_interface_factory: Box::new(terminal_interface_factory),
            command_factory_opt: Some(Box::new(CommandFactoryMock::default())),
            command_context_factory: Box::new(command_context_factory),
            command_execution_helper_factory: Box::new(command_execution_helper_factory),
            command_processor_factory: Default::default(),
        };

        let result = subject
            .go(&["command".to_string(), "subcommand".to_string()])
            .await;

        let mut make_command_context_params = make_command_context_params_arc.lock().unwrap();
        let (ui_port, broadcast_handler_term_interface_opt) =
            make_command_context_params.pop().unwrap();
        StdStreamsAssertionMatrix::compose(
            // TODO this seems like it should belong to the aspiring handles instead
            BareStreamsFromStreamFactoryAssertionMatrix {
                stream_handles: &incidental_std_stream_handles,
                write_streams: OnePieceWriteStreamsAssertion {
                    stdout_opt: None,
                    stderr_opt: Some(
                        "Processor initialization failed: Can't connect to Daemon or Node: \
                    \"booga\". Probably this means the Daemon isn't running.\n",
                    ),
                }
                .into(),
            },
            BareStreamsFromStreamFactoryAssertionMatrix::assert_streams_not_used(
                &processor_aspiring_std_stream_handles,
            ),
            ProcessorTerminalInterfaceAssertionMatrix::assert_terminal_not_used(
                &term_interface_stream_handles,
            ),
            BroadcastHandlerTerminalInterfaceAssertionMatrix::assert_terminal_not_created(
                broadcast_handler_term_interface_opt.as_ref(),
            ),
        )
        .assert()
        .await;
        assert_eq!(result, 1);
    }

    #[tokio::test]
    async fn non_interactive_mode_works_when_special_ui_port_is_required() {
        let c_make_params_arc = Arc::new(Mutex::new(vec![]));
        let make_command_context_params_arc = Arc::new(Mutex::new(vec![]));
        let command_execution_params_arc = Arc::new(Mutex::new(vec![]));
        let (processor_aspiring_std_streams, processor_aspiring_std_stream_handles) =
            make_async_std_streams(vec![]);
        let (incidental_std_streams, incidental_std_stream_handles) =
            make_async_std_streams(vec![]);
        let std_streams_factory = AsyncStdStreamsFactoryMock::default()
            .make_result(incidental_std_streams)
            .make_result(processor_aspiring_std_streams);
        let (w_term_interface, term_interface_stream_handles) =
            TermInterfaceMock::new_non_interactive();
        let terminal_interface_factory = TerminalInterfaceFactoryMock::default()
            .make_result(Either::Left(Box::new(w_term_interface)));
        let command_factory = CommandFactoryMock::default()
            .make_params(&c_make_params_arc)
            .make_result(Ok(Box::new(SetupCommand::new(&[]).unwrap())));
        let command_context = CommandContextMock::default();
        let command_context_factory = CommandContextFactoryMock::new()
            .make_params(&make_command_context_params_arc)
            .make_result(Ok(Box::new(command_context)));
        let command_execution_helper = CommandExecutionHelperMock::default()
            .execute_command_params(&command_execution_params_arc)
            .execute_command_result(Ok(()));
        let command_execution_helper_factory = CommandExecutionHelperFactoryMock::default()
            .make_result(Box::new(command_execution_helper));
        let mut subject = Main {
            std_streams_factory: Box::new(std_streams_factory),
            initial_args_parser: Box::new(InitialArgsParserReal::default()),
            term_interface_factory: Box::new(terminal_interface_factory),
            command_factory_opt: Some(Box::new(command_factory)),
            command_context_factory: Box::new(command_context_factory),
            command_execution_helper_factory: Box::new(command_execution_helper_factory),
            command_processor_factory: Default::default(),
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
            BareStreamsFromStreamFactoryAssertionMatrix::assert_streams_not_used(
                &incidental_std_stream_handles,
            ),
            BareStreamsFromStreamFactoryAssertionMatrix::assert_streams_not_used(
                &processor_aspiring_std_stream_handles,
            ),
            // We say that no output is expected only because we intercept the command's execution
            // by mocking the CommandExecutionHelper
            ProcessorTerminalInterfaceAssertionMatrix::assert_terminal_not_used(
                &term_interface_stream_handles,
            ),
            BroadcastHandlerTerminalInterfaceAssertionMatrix::assert_terminal_not_created(
                broadcast_handler_term_interface_opt.as_ref(),
            ),
        )
        .assert()
        .await;
        let mut command_execution_params = command_execution_params_arc.lock().unwrap();
        let (command, captured_command_context_id, captured_term_interface_id) =
            command_execution_params.remove(0);
        assert_eq!(
            *command.as_any().downcast_ref::<SetupCommand>().unwrap(),
            SetupCommand { values: vec![] }
        );
        assert!(command_execution_params.is_empty())
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
            let (writer, flush_handle) = term_interface.stdout();
            masq_short_writeln!(writer, "{}", self.output);
            Ok(())
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
        let make_term_interface_params_arc = Arc::new(Mutex::new(vec![]));
        let make_command_params_arc = Arc::new(Mutex::new(vec![]));
        let make_command_context_params_arc = Arc::new(Mutex::new(vec![]));
        let (processor_aspiring_std_streams, processor_aspiring_std_stream_handles) =
            make_async_std_streams(vec![]);
        let (incidental_std_streams, incidental_std_stream_handles) =
            make_async_std_streams(vec![]);
        let std_streams_factory = AsyncStdStreamsFactoryMock::default()
            .make_result(incidental_std_streams)
            .make_result(processor_aspiring_std_streams);
        let stdin_read_line_results = vec![
            Ok(ReadInput::Line("setup".to_string())),
            Ok(ReadInput::Line("start".to_string())),
            Ok(ReadInput::Line("exit".to_string())),
        ];
        let (
            rw_term_interface,
            prime_term_interface_stream_handles,
            background_term_interface_stream_handles,
        ) = TermInterfaceMock::new_interactive(stdin_read_line_results);
        let terminal_interface_factory = TerminalInterfaceFactoryMock::default()
            .make_params(&make_term_interface_params_arc)
            .make_result(Either::Right(Box::new(rw_term_interface)));
        let command_factory = CommandFactoryMock::default()
            .make_params(&make_command_params_arc)
            .make_result(Ok(Box::new(FakeCommand::new("setup command"))))
            .make_result(Ok(Box::new(FakeCommand::new("start command"))));
        let command_context = CommandContextMock::new();
        let command_context_factory = CommandContextFactoryMock::new()
            .make_params(&make_command_context_params_arc)
            .make_result(Ok(Box::new(command_context)));
        let mut subject = Main {
            std_streams_factory: Box::new(std_streams_factory),
            initial_args_parser: Box::new(InitialArgsParserMock::default()),
            term_interface_factory: Box::new(terminal_interface_factory),
            command_factory_opt: Some(Box::new(command_factory)),
            command_context_factory: Box::new(command_context_factory),
            command_execution_helper_factory: Box::new(CommandExecutionHelperFactoryReal::default()),
            command_processor_factory: Default::default(),
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
            BareStreamsFromStreamFactoryAssertionMatrix::assert_streams_not_used(
                &incidental_std_stream_handles,
            ),
            BareStreamsFromStreamFactoryAssertionMatrix::assert_streams_not_used(
                &processor_aspiring_std_stream_handles,
            ),
            ProcessorTerminalInterfaceAssertionMatrix {
                standard_assertions: TerminalInterfaceAssertionMatrix {
                    term_interface_stream_handles: &prime_term_interface_stream_handles,
                    expected_writes: FlushesWriteStreamsAssertion {
                        stdout: vec![
                            "setup command\n",
                            "start command\n",
                            "MASQ is terminating...\n",
                        ],
                        stderr: vec![],
                    }
                    .into(),
                    read_attempts_opt: Some(3),
                },
            },
            BroadcastHandlerTerminalInterfaceAssertionMatrix::assert_terminal_not_used(
                broadcast_handler_term_interface_opt.as_ref(),
                &background_term_interface_stream_handles,
            ),
        )
        .assert()
        .await;
    }

    #[tokio::test]
    async fn interactive_mode_works_for_stdin_read_error() {
        let make_term_interface_params_arc = Arc::new(Mutex::new(vec![]));
        let make_command_context_params_arc = Arc::new(Mutex::new(vec![]));
        let close_params_arc = Arc::new(Mutex::new(vec![]));
        let (incidental_std_streams, incidental_std_stream_handles) =
            make_async_std_streams(vec![]);
        let (processor_aspiring_std_streams, processor_aspiring_std_stream_handles) =
            make_async_std_streams(vec![]);
        let std_streams_factory = AsyncStdStreamsFactoryMock::default()
            .make_result(incidental_std_streams)
            .make_result(processor_aspiring_std_streams);
        let stdin_read_line_results = vec![Err(ReadError::TerminalOutputInputDisconnected)];
        let (
            rw_term_interface,
            prime_term_interface_stream_handles,
            background_term_interface_stream_handles,
        ) = TermInterfaceMock::new_interactive(stdin_read_line_results);
        let terminal_interface_factory = TerminalInterfaceFactoryMock::default()
            .make_params(&make_term_interface_params_arc)
            .make_result(Either::Right(Box::new(rw_term_interface)));
        let command_context = CommandContextMock::default().close_params(&close_params_arc);
        let command_context_factory = CommandContextFactoryMock::new()
            .make_params(&make_command_context_params_arc)
            .make_result(Ok(Box::new(command_context)));
        let command_execution_helper_factory = CommandExecutionHelperFactoryMock::default()
            .make_result(Box::new(CommandExecutionHelperMock::default()));
        let mut subject = Main {
            std_streams_factory: Box::new(std_streams_factory),
            initial_args_parser: Box::new(InitialArgsParserMock::default()),
            term_interface_factory: Box::new(terminal_interface_factory),
            command_factory_opt: Some(Box::new(CommandFactoryMock::default())),
            command_context_factory: Box::new(command_context_factory),
            command_execution_helper_factory: Box::new(command_execution_helper_factory),
            command_processor_factory: Default::default(),
        };

        let result = subject.go(&["command".to_string()]).await;

        assert_eq!(result, 1);
        let mut make_term_interface_params = make_term_interface_params_arc.lock().unwrap();
        let (is_interactive, passed_streams) = make_term_interface_params.remove(0);
        assert_eq!(is_interactive, true);
        assert!(make_term_interface_params.is_empty());
        let mut make_command_context_params = make_command_context_params_arc.lock().unwrap();
        let (ui_port, broadcast_handler_term_interface_opt) =
            make_command_context_params.pop().unwrap();
        StdStreamsAssertionMatrix::compose(
            BareStreamsFromStreamFactoryAssertionMatrix::assert_streams_not_used(
                &incidental_std_stream_handles,
            ),
            BareStreamsFromStreamFactoryAssertionMatrix::assert_streams_not_used(
                &processor_aspiring_std_stream_handles,
            ),
            ProcessorTerminalInterfaceAssertionMatrix {
                standard_assertions: TerminalInterfaceAssertionMatrix {
                    term_interface_stream_handles: &prime_term_interface_stream_handles,
                    expected_writes: OnePieceWriteStreamsAssertion {
                        stdout_opt: None,
                        stderr_opt: Some("Terminal read error: IO disconnected\n"),
                    }
                    .into(),
                    read_attempts_opt: Some(1),
                },
            },
            BroadcastHandlerTerminalInterfaceAssertionMatrix::assert_terminal_not_used(
                broadcast_handler_term_interface_opt.as_ref(),
                &background_term_interface_stream_handles,
            ),
        )
        .assert()
        .await;
        let close_params = close_params_arc.lock().unwrap();
        assert_eq!(*close_params, vec![()])
    }

    #[tokio::test]
    async fn broadcast_is_received_from_node() {
        todo!("Write me up: Send a broadcast from the MockWebsocketServer")
    }

    struct StdStreamsAssertionMatrix<'test> {
        incidental_std_streams: BareStreamsFromStreamFactoryAssertionMatrix<'test>,
        processor_std_streams: BareStreamsFromStreamFactoryAssertionMatrix<'test>,
        processor_term_interface: ProcessorTerminalInterfaceAssertionMatrix<'test>,
        broadcast_handler_term_interface: BroadcastHandlerTerminalInterfaceAssertionMatrix<'test>,
    }

    #[derive(Debug)]
    enum StreamType {
        Stdout,
        Stderr,
    }

    trait AssertionValuesWithTestableExpectedStreamOutputEmptiness {
        fn is_empty_stdout_output_expected(&self) -> bool;
        fn is_empty_stderr_output_expected(&self) -> bool;
    }

    struct OnePieceWriteStreamsAssertion<'test> {
        stdout_opt: Option<&'test str>,
        stderr_opt: Option<&'test str>,
    }

    impl AssertionValuesWithTestableExpectedStreamOutputEmptiness
        for OnePieceWriteStreamsAssertion<'_>
    {
        fn is_empty_stdout_output_expected(&self) -> bool {
            self.stdout_opt.is_none()
        }

        fn is_empty_stderr_output_expected(&self) -> bool {
            self.stderr_opt.is_none()
        }
    }

    struct FlushesWriteStreamsAssertion<'test> {
        stdout: Vec<&'test str>,
        stderr: Vec<&'test str>,
    }

    impl AssertionValuesWithTestableExpectedStreamOutputEmptiness for FlushesWriteStreamsAssertion<'_> {
        fn is_empty_stdout_output_expected(&self) -> bool {
            self.stdout.is_empty()
        }

        fn is_empty_stderr_output_expected(&self) -> bool {
            self.stderr.is_empty()
        }
    }

    struct WriteStreamsAssertion<'test> {
        one_piece_or_distinct_flushes:
            Either<OnePieceWriteStreamsAssertion<'test>, FlushesWriteStreamsAssertion<'test>>,
    }

    impl<'test> From<OnePieceWriteStreamsAssertion<'test>> for WriteStreamsAssertion<'test> {
        fn from(assertions: OnePieceWriteStreamsAssertion<'test>) -> Self {
            WriteStreamsAssertion {
                one_piece_or_distinct_flushes: Either::Left(assertions),
            }
        }
    }

    impl<'test> From<FlushesWriteStreamsAssertion<'test>> for WriteStreamsAssertion<'test> {
        fn from(assertions: FlushesWriteStreamsAssertion<'test>) -> Self {
            WriteStreamsAssertion {
                one_piece_or_distinct_flushes: Either::Right(assertions),
            }
        }
    }

    struct BareStreamsFromStreamFactoryAssertionMatrix<'test> {
        stream_handles: &'test AsyncTestStreamHandles,
        write_streams: WriteStreamsAssertion<'test>,
        // Reading should be forbidden in these streams
    }

    impl<'test> BareStreamsFromStreamFactoryAssertionMatrix<'test> {
        fn assert_streams_not_used(stream_handles: &'test AsyncTestStreamHandles) -> Self {
            Self {
                stream_handles,
                write_streams: WriteStreamsAssertion {
                    one_piece_or_distinct_flushes: Either::Left(OnePieceWriteStreamsAssertion {
                        stdout_opt: None,
                        stderr_opt: None,
                    }),
                },
            }
        }
    }

    struct TerminalInterfaceAssertionMatrix<'test> {
        term_interface_stream_handles: &'test AsyncTestStreamHandles,
        expected_writes: WriteStreamsAssertion<'test>,
        // None ... non-interactive mode,
        // Some ... interactive mode
        read_attempts_opt: Option<usize>,
    }

    struct ProcessorTerminalInterfaceAssertionMatrix<'test> {
        standard_assertions: TerminalInterfaceAssertionMatrix<'test>,
    }

    impl<'test> ProcessorTerminalInterfaceAssertionMatrix<'test> {
        fn assert_terminal_not_used(stream_handles: &'test AsyncTestStreamHandles) -> Self {
            Self {
                standard_assertions: TerminalInterfaceAssertionMatrix {
                    term_interface_stream_handles: stream_handles,
                    expected_writes: WriteStreamsAssertion {
                        one_piece_or_distinct_flushes: Either::Left(
                            OnePieceWriteStreamsAssertion {
                                stdout_opt: None,
                                stderr_opt: None,
                            },
                        ),
                    },
                    read_attempts_opt: None,
                },
            }
        }
    }

    struct BroadcastHandlerTerminalInterfaceAssertionMatrix<'test> {
        w_term_interface_opt: Option<&'test Box<dyn WTermInterfaceDupAndSend>>,
        // None means the terminal is not even considered as existing, we therefore suspect
        // the non-interactive mode
        expected_std_streams_usage_opt: Option<TerminalInterfaceAssertionMatrix<'test>>,
    }

    impl<'test> BroadcastHandlerTerminalInterfaceAssertionMatrix<'test> {
        fn assert_terminal_not_created(
            w_term_interface_opt: Option<&'test Box<dyn WTermInterfaceDupAndSend>>,
        ) -> Self {
            Self {
                w_term_interface_opt,
                expected_std_streams_usage_opt: None,
            }
        }

        fn assert_terminal_not_used(
            w_term_interface_opt: Option<&'test Box<dyn WTermInterfaceDupAndSend>>,
            stream_handles: &'test AsyncTestStreamHandles,
        ) -> Self {
            Self {
                w_term_interface_opt,
                expected_std_streams_usage_opt: Some(TerminalInterfaceAssertionMatrix {
                    term_interface_stream_handles: stream_handles,
                    expected_writes: WriteStreamsAssertion {
                        one_piece_or_distinct_flushes: Either::Left(
                            OnePieceWriteStreamsAssertion {
                                stdout_opt: None,
                                stderr_opt: None,
                            },
                        ),
                    },
                    read_attempts_opt: None,
                }),
            }
        }
    }

    impl<'test> StdStreamsAssertionMatrix<'test> {
        pub fn compose(
            incidental_std_streams_assertion_matrix: BareStreamsFromStreamFactoryAssertionMatrix<
                'test,
            >,
            processor_aspiring_std_streams_assertions_matrix: BareStreamsFromStreamFactoryAssertionMatrix<'test>,
            processor_term_interface_assertion_matrix: ProcessorTerminalInterfaceAssertionMatrix<
                'test,
            >,
            broadcast_handler_term_interface_assertion_matrix: BroadcastHandlerTerminalInterfaceAssertionMatrix<'test>,
        ) -> Self {
            Self {
                incidental_std_streams: incidental_std_streams_assertion_matrix,
                processor_std_streams: processor_aspiring_std_streams_assertions_matrix,
                processor_term_interface: processor_term_interface_assertion_matrix,
                broadcast_handler_term_interface: broadcast_handler_term_interface_assertion_matrix,
            }
        }

        async fn assert(self) {
            let incidental_streams = self.incidental_std_streams;
            assert_stream_writes(
                incidental_streams.stream_handles,
                incidental_streams.write_streams,
            )
            .await;
            assert_stream_reads(&incidental_streams.stream_handles, Some(0));

            let processor_aspiring_streams = self.processor_std_streams;
            assert_stream_writes(
                processor_aspiring_streams.stream_handles,
                processor_aspiring_streams.write_streams,
            )
            .await;
            assert_stream_reads(&processor_aspiring_streams.stream_handles, Some(0));

            let processor_term_interface = self.processor_term_interface;
            let processor_term_interface_stream_handles = processor_term_interface
                .standard_assertions
                .term_interface_stream_handles;
            let processor_term_interface_expected_writes =
                processor_term_interface.standard_assertions.expected_writes;
            let processor_term_interface_expected_read_attempts_opt = processor_term_interface
                .standard_assertions
                .read_attempts_opt;

            assert_stream_writes(
                processor_term_interface_stream_handles,
                processor_term_interface_expected_writes,
            )
            .await;
            assert_stream_reads(
                &processor_term_interface_stream_handles,
                processor_term_interface_expected_read_attempts_opt,
            );

            let broadcast_term_interface = self.broadcast_handler_term_interface;
            assert_broadcast_term_interface_outputs(
                broadcast_term_interface.w_term_interface_opt,
                broadcast_term_interface.expected_std_streams_usage_opt,
            )
            .await;
        }
    }

    async fn assert_broadcast_term_interface_outputs<'test>(
        term_interface_opt: Option<&'test Box<dyn WTermInterfaceDupAndSend>>,
        expected_std_streams_usage_opt: Option<TerminalInterfaceAssertionMatrix<'test>>,
    ) {
        macro_rules! assert_terminal_output_stream_and_its_stream_handle_are_connected {
            ($fetch_write_utils: expr, $await_non_empty_output: expr, $fetch_written_data_all_in_one: expr, $literals_to_test_it_with: literal) => {
                let (mut std_stream_writer, flush_handle) = $fetch_write_utils;
                std_stream_writer.write($literals_to_test_it_with).await;
                drop(flush_handle);
                $await_non_empty_output.await;
                assert_eq!($fetch_written_data_all_in_one, $literals_to_test_it_with)
            };
        }

        match (term_interface_opt, expected_std_streams_usage_opt) {
            (Some(w_terminal), Some(expected_usage)) => {
                assert_stream_writes(expected_usage.term_interface_stream_handles, expected_usage.expected_writes).await;
                assert_terminal_output_stream_and_its_stream_handle_are_connected!(
                    term_interface_opt.as_ref().unwrap().stdout(),
                    expected_usage.term_interface_stream_handles.await_stdout_is_not_empty(),
                    expected_usage.term_interface_stream_handles.stdout_all_in_one(),
                    "AbCdEfG"
                );
                assert_terminal_output_stream_and_its_stream_handle_are_connected!(
                    term_interface_opt.as_ref().unwrap().stderr(),
                    expected_usage.term_interface_stream_handles.await_stderr_is_not_empty(),
                    expected_usage.term_interface_stream_handles.stderr_all_in_one(),
                    "1a2b3c4"
                );
                let reads_opt = expected_usage.term_interface_stream_handles.reads_opt();
                assert_eq!(reads_opt, None)
            }
            (None, None) => (),
            (actual_opt, expected_opt) => panic!("Interactive mode was expected: {}. But broadcast terminal interface was created and supplied: {}. (Non-interactive mode is not supposed to have one)", expected_opt.is_some(), actual_opt.is_some())
        }
    }

    async fn assert_stream_writes<'test>(
        original_stream_handles: &AsyncTestStreamHandles,
        expected_writes: WriteStreamsAssertion<'test>,
    ) {
        fn optional_into_empty_or_populated_string(string_opt: Option<&str>) -> String {
            string_opt.map(|s| s.to_string()).unwrap_or_default()
        }
        fn owned_strings(strings: &[&str]) -> Vec<String> {
            strings.into_iter().map(|s| s.to_string()).collect()
        }

        match expected_writes.one_piece_or_distinct_flushes {
            Either::Left(one_piece) => {
                assert_single_write_stream(
                    Stdout,
                    original_stream_handles,
                    &one_piece,
                    |original_stream_handles| original_stream_handles.stdout_all_in_one(),
                    |one_piece| optional_into_empty_or_populated_string(one_piece.stdout_opt),
                )
                .await;
                assert_single_write_stream(
                    Stderr,
                    original_stream_handles,
                    &one_piece,
                    |original_stream_handles| original_stream_handles.stderr_all_in_one(),
                    |one_piece| optional_into_empty_or_populated_string(one_piece.stderr_opt),
                )
                .await
            }
            Either::Right(flushes) => {
                assert_single_write_stream(
                    Stdout,
                    original_stream_handles,
                    &flushes,
                    |original_stream_handles| original_stream_handles.stdout_flushed_strings(),
                    |flushes| owned_strings(&flushes.stdout),
                )
                .await;
                assert_single_write_stream(
                    Stderr,
                    original_stream_handles,
                    &flushes,
                    |original_stream_handles| original_stream_handles.stderr_flushed_strings(),
                    |flushes| owned_strings(&flushes.stderr),
                )
                .await
            }
        }
    }

    async fn assert_single_write_stream<ExpectedValue, Fn1, Fn2, AssertionValues>(
        std_stream: StreamType,
        original_stream_handles: &AsyncTestStreamHandles,
        preliminarily_examinable_assertion: &AssertionValues,
        actual_value_fetcher: Fn1,
        expected_value_extractor: Fn2,
    ) where
        ExpectedValue: Debug + PartialEq,
        Fn1: Fn(&AsyncTestStreamHandles) -> ExpectedValue,
        Fn2: Fn(&AssertionValues) -> ExpectedValue,
        AssertionValues: AssertionValuesWithTestableExpectedStreamOutputEmptiness,
    {
        let is_emptiness_expected = match std_stream {
            Stdout => preliminarily_examinable_assertion.is_empty_stdout_output_expected(),
            Stderr => preliminarily_examinable_assertion.is_empty_stderr_output_expected(),
        };

        match is_emptiness_expected {
            true => (),
            false => {
                let expected_value_debug = || {
                    format!(
                        "{:?}",
                        expected_value_extractor(preliminarily_examinable_assertion)
                    )
                };

                match std_stream {
                    Stdout => {
                        original_stream_handles
                            .await_stdout_is_not_empty_or_panic_with_expected(
                                &expected_value_debug(),
                            )
                            .await
                    }
                    Stderr => {
                        original_stream_handles
                            .await_stderr_is_not_empty_or_panic_with_expected(
                                &expected_value_debug(),
                            )
                            .await
                    }
                }
            }
        }

        let actual_output = actual_value_fetcher(original_stream_handles);
        let expected_output = expected_value_extractor(preliminarily_examinable_assertion);

        assert_eq!(
            actual_output, expected_output,
            "We expected this printed by {:?} {:?} but was {:?}",
            std_stream, expected_output, actual_output
        );
    }

    fn assert_stream_reads(
        std_stream_handles: &AsyncTestStreamHandles,
        // None means that the stdin was not provided (as in the write-only terminal interface)
        expected_read_attempts_opt: Option<usize>,
    ) {
        let actual_reads_opt = std_stream_handles.reads_opt();
        match (actual_reads_opt, expected_read_attempts_opt) {
            (Some(actual), Some(expected)) => assert_eq!(
                actual, expected,
                "Expected read attempts {} don't match the actual {}",
                expected, actual
            ),
            (None, None) => (),
            (actual_opt, expected_opt) => panic!(
                "Expected {:?} doesn't match the actual {:?}",
                expected_opt, actual_opt
            ),
        }
    }
}
