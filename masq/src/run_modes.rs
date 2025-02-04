// Copyright (c) 2024, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::clap_before_entrance::{InitialArgsParser, InitialArgsParserReal, InitializationArgs};
use crate::command_context_factory::{CommandContextFactory, CommandContextFactoryReal};
use crate::command_factory::CommandFactoryError::UnrecognizedSubcommand;
use crate::command_factory::{CommandFactory, CommandFactoryReal};
use crate::command_processor::{
    CommandExecutionHelperFactory, CommandExecutionHelperFactoryReal, CommandProcessor,
    CommandProcessorFactory,
};
use crate::commands::commands_common::CommandError;
use crate::communications::broadcast_handlers::{BroadcastHandle, BroadcastHandler};
use crate::masq_short_writeln;
use crate::terminal::terminal_interface_factory::{
    TerminalInterfaceFactory, TerminalInterfaceFactoryReal,
};
use crate::terminal::{RWTermInterface, WTermInterface};
use async_trait::async_trait;
use itertools::Either;
use masq_lib::async_streams::{
    AsyncStdStreams, AsyncStdStreamsFactory, AsyncStdStreamsFactoryReal,
};
use masq_lib::write_async_stream_and_flush;
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
        let initialization_args = match self
            .initial_args_parser
            .parse_initialization_args(args, &mut incidental_streams)
            .await
        {
            CLIProgramEntering::Enter(init_args) => init_args,
            CLIProgramEntering::Leave(exit_code) => {
                write_async_stream_and_flush!(
                    incidental_streams.stderr,
                    "Incorrect arguments for MASQ, it is terminating...\n"
                );
                return exit_code;
            }
        };
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
        let mut command_processor = self
            .initialize_processor(ui_port, incidental_streams, term_interface)
            .await?;

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
    ) -> Result<Box<dyn CommandProcessor>, ()> {
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
            (_, (one_arg, arg_next_to_the_previous)): &(usize, (&String, &String)),
        ) -> bool {
            [one_arg, arg_next_to_the_previous]
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

#[derive(Debug)]
pub enum CLIProgramEntering {
    Enter(InitializationArgs),
    Leave(u8),
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
    use crate::masq_short_writeln;
    use crate::terminal::test_utils::allow_writings_to_finish;
    use crate::terminal::{ReadError, ReadInput};
    use crate::test_utils::mocks::{
        make_async_std_streams, AsyncStdStreamsFactoryMock, CommandContextFactoryMock,
        CommandContextMock, CommandExecutionHelperFactoryMock, CommandExecutionHelperMock,
        CommandFactoryMock, InitialArgsParserMock, MockCommand, TermInterfaceMock,
        TerminalInterfaceFactoryMock,
    };
    use crate::test_utils::run_modes_utils::{
        Assert, AssertBroadcastHandler, BareStreamsFromStreamFactoryAssertionMatrix,
        FlushesWriteStreamsAssertion, OnePieceWriteStreamsAssertion,
        ProcessorTerminalInterfaceAssertionMatrix, StdStreamsAssertionMatrix,
        TerminalInterfaceAssertionMatrix,
    };
    use masq_lib::constants::DEFAULT_UI_PORT;
    use masq_lib::messages::{
        ToMessageBody, UiConnectionChangeBroadcast, UiConnectionStage, UiDescriptorResponse,
        UiShutdownRequest, UiStartResponse,
    };
    use masq_lib::test_utils::mock_websockets_server::MockWebSocketsServer;
    use masq_lib::utils::find_free_port;
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
        let initial_args_parser_mock = InitialArgsParserMock::default()
            .parse_initialization_args_result(CLIProgramEntering::Enter(InitializationArgs::new(
                DEFAULT_UI_PORT,
            )));
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
            initial_args_parser: Box::new(initial_args_parser_mock),
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
        let (ui_port, broadcast_handler_term_interface_opt) =
            make_command_context_params.pop().unwrap();
        assert_eq!(ui_port, 5333);
        StdStreamsAssertionMatrix::default()
            .incidental_std_streams(Assert::NotUsed(&incidental_std_stream_handles))
            .processor_aspiring_std_streams(Assert::NotUsed(&processor_aspiring_std_stream_handles))
            .processor_term_interface(Assert::NotUsed(&term_interface_stream_handles))
            .broadcast_handler_term_interface(
                AssertBroadcastHandler::MissingAsItIsNonInteractiveMode(
                    broadcast_handler_term_interface_opt.as_ref(),
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
        StdStreamsAssertionMatrix::default()
            .incidental_std_streams(Assert::NotUsed(&incidental_std_stream_handles))
            .processor_aspiring_std_streams(Assert::NotUsed(&processor_aspiring_std_stream_handles))
            .processor_term_interface(Assert::Expected(
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
            ))
            .broadcast_handler_term_interface(
                AssertBroadcastHandler::MissingAsItIsNonInteractiveMode(
                    broadcast_handler_term_interface_opt.as_ref(),
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
        let make_command_params_arc = Arc::new(Mutex::new(vec![]));
        let close_params_arc = Arc::new(Mutex::new(vec![]));
        let initial_args_parser_mock = InitialArgsParserMock::default()
            .parse_initialization_args_result(CLIProgramEntering::Enter(InitializationArgs::new(
                DEFAULT_UI_PORT,
            )));
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
            .make_result(Err(UnrecognizedSubcommand {
                from_cml: "booga".to_string(),
            }));
        let processor = CommandContextMock::default().close_params(&close_params_arc);
        let command_context_factory = CommandContextFactoryMock::default()
            .make_params(&make_command_context_params_arc)
            .make_result(Ok(Box::new(processor)));
        let command_execution_helper = CommandExecutionHelperMock::default();
        let command_execution_helper_factory = CommandExecutionHelperFactoryMock::default()
            .make_result(Box::new(command_execution_helper));
        let mut subject = Main {
            std_streams_factory: Box::new(std_streams_factory),
            initial_args_parser: Box::new(initial_args_parser_mock),
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
        let (ui_port, broadcast_handler_term_interface_opt) = make_processor_params.pop().unwrap();
        assert_eq!(ui_port, 5333);
        StdStreamsAssertionMatrix::default()
            .incidental_std_streams(Assert::NotUsed(&incidental_std_stream_handles))
            .processor_aspiring_std_streams(Assert::NotUsed(&processor_aspiring_std_stream_handles))
            .processor_term_interface(Assert::Expected(
                ProcessorTerminalInterfaceAssertionMatrix {
                    standard_assertions: TerminalInterfaceAssertionMatrix {
                        term_interface_stream_handles: &term_interface_stream_handles,
                        expected_writes: OnePieceWriteStreamsAssertion {
                            stdout_opt: None,
                            stderr_opt: Some("Unrecognized command: \"booga\"\n"),
                        }
                        .into(),
                        read_attempts_opt: None,
                    },
                },
            ))
            .broadcast_handler_term_interface(
                AssertBroadcastHandler::MissingAsItIsNonInteractiveMode(
                    broadcast_handler_term_interface_opt.as_ref(),
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
        let initial_args_parser_mock = InitialArgsParserMock::default()
            .parse_initialization_args_result(CLIProgramEntering::Enter(InitializationArgs::new(
                DEFAULT_UI_PORT,
            )));
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
            initial_args_parser: Box::new(initial_args_parser_mock),
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
        StdStreamsAssertionMatrix::default()
            .incidental_std_streams(Assert::NotUsed(&incidental_std_stream_handles))
            .processor_aspiring_std_streams(Assert::NotUsed(&processor_aspiring_std_stream_handles))
            .processor_term_interface(Assert::Expected(
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
            ))
            .broadcast_handler_term_interface(
                AssertBroadcastHandler::MissingAsItIsNonInteractiveMode(
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
        let initial_args_parser_mock = InitialArgsParserMock::default()
            .parse_initialization_args_result(CLIProgramEntering::Enter(InitializationArgs::new(
                DEFAULT_UI_PORT,
            )));
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
            initial_args_parser: Box::new(initial_args_parser_mock),
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
        StdStreamsAssertionMatrix::default()
            .incidental_std_streams(Assert::Expected(
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
            ))
            .processor_aspiring_std_streams(Assert::NotUsed(&processor_aspiring_std_stream_handles))
            .processor_term_interface(Assert::NotUsed(&term_interface_stream_handles))
            .broadcast_handler_term_interface(
                AssertBroadcastHandler::MissingAsItIsNonInteractiveMode(
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
        StdStreamsAssertionMatrix::default()
            .incidental_std_streams(Assert::NotUsed(&incidental_std_stream_handles))
            .processor_aspiring_std_streams(Assert::NotUsed(&processor_aspiring_std_stream_handles))
            // We say that no output is expected only because we intercept the command's execution
            // by mocking the CommandExecutionHelper
            .processor_term_interface(Assert::NotUsed(&processor_aspiring_std_stream_handles))
            .broadcast_handler_term_interface(
                AssertBroadcastHandler::MissingAsItIsNonInteractiveMode(
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

    #[tokio::test]
    async fn masq_terminates_because_wrong_initial_args_cause_immediate_halt() {
        let (incidental_std_streams, incidental_std_stream_handles) =
            make_async_std_streams(vec![]);
        let std_streams_factory =
            AsyncStdStreamsFactoryMock::default().make_result(incidental_std_streams);
        let mut subject = Main {
            std_streams_factory: Box::new(std_streams_factory),
            initial_args_parser: Box::new(InitialArgsParserReal::default()),
            term_interface_factory: Box::new(TerminalInterfaceFactoryMock::default()),
            command_factory_opt: Some(Box::new(CommandFactoryMock::default())),
            command_context_factory: Box::new(CommandContextFactoryMock::default()),
            command_execution_helper_factory: Box::new(CommandExecutionHelperFactoryMock::default()),
            command_processor_factory: Default::default(),
        };

        let result = subject
            .go(&[
                "masq".to_string(),
                "--ui-puerto-rico".to_string(),
                "10000".to_string(),
            ])
            .await;

        assert_eq!(result, 1);
        incidental_std_stream_handles.assert_empty_stdout();
        let mut stderr_flushes = incidental_std_stream_handles.stderr_flushed_strings();
        let first_msg = stderr_flushes.remove(0);
        assert!(first_msg.contains("unexpected argument '--ui-puerto-rico' found"));
        let second_msg = stderr_flushes.remove(0);
        assert_eq!(
            second_msg,
            "Incorrect arguments for MASQ, it is terminating...\n"
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
        let initial_args_parser_mock = InitialArgsParserMock::default()
            .parse_initialization_args_result(CLIProgramEntering::Enter(InitializationArgs::new(
                DEFAULT_UI_PORT,
            )));
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
            initial_args_parser: Box::new(initial_args_parser_mock),
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
        let is_interactive = make_term_interface_params.remove(0);
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
        StdStreamsAssertionMatrix::default()
            .incidental_std_streams(Assert::NotUsed(&incidental_std_stream_handles))
            .processor_aspiring_std_streams(Assert::NotUsed(&processor_aspiring_std_stream_handles))
            .processor_term_interface(Assert::Expected(
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
            ))
            .broadcast_handler_term_interface(AssertBroadcastHandler::NotUsed {
                intercepted_broadcast_handler_term_interface_opt:
                    broadcast_handler_term_interface_opt.as_ref(),
                stream_handles: &background_term_interface_stream_handles,
            })
            .assert()
            .await;
    }

    #[tokio::test]
    async fn interactive_mode_works_for_stdin_read_error() {
        let make_term_interface_params_arc = Arc::new(Mutex::new(vec![]));
        let make_command_context_params_arc = Arc::new(Mutex::new(vec![]));
        let close_params_arc = Arc::new(Mutex::new(vec![]));
        let initial_args_parser_mock = InitialArgsParserMock::default()
            .parse_initialization_args_result(CLIProgramEntering::Enter(InitializationArgs::new(
                DEFAULT_UI_PORT,
            )));
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
            initial_args_parser: Box::new(initial_args_parser_mock),
            term_interface_factory: Box::new(terminal_interface_factory),
            command_factory_opt: Some(Box::new(CommandFactoryMock::default())),
            command_context_factory: Box::new(command_context_factory),
            command_execution_helper_factory: Box::new(command_execution_helper_factory),
            command_processor_factory: Default::default(),
        };

        let result = subject.go(&["command".to_string()]).await;

        assert_eq!(result, 1);
        let mut make_term_interface_params = make_term_interface_params_arc.lock().unwrap();
        let is_interactive = make_term_interface_params.remove(0);
        assert_eq!(is_interactive, true);
        assert!(make_term_interface_params.is_empty());
        let mut make_command_context_params = make_command_context_params_arc.lock().unwrap();
        let (ui_port, broadcast_handler_term_interface_opt) =
            make_command_context_params.pop().unwrap();
        assert_eq!(ui_port, 5333);
        StdStreamsAssertionMatrix::default()
            .incidental_std_streams(Assert::NotUsed(&incidental_std_stream_handles))
            .processor_aspiring_std_streams(Assert::NotUsed(&processor_aspiring_std_stream_handles))
            .processor_term_interface(Assert::Expected(
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
            ))
            .broadcast_handler_term_interface(AssertBroadcastHandler::NotUsed {
                intercepted_broadcast_handler_term_interface_opt:
                    broadcast_handler_term_interface_opt.as_ref(),
                stream_handles: &background_term_interface_stream_handles,
            })
            .assert()
            .await;
        let close_params = close_params_arc.lock().unwrap();
        assert_eq!(*close_params, vec![()])
    }

    #[tokio::test]
    async fn broadcast_is_received_from_node() {
        // This test is hacky, we admit that, but its focus should be on the broadcast side and that
        // one is exercised well this way.
        // We send a start request just to unclog the broadcast to come here from the server.
        // We look away that the following sequence then doesn't include the Node's shutdown phase
        // for looking realistic. The reason why we don't is we simply cannot present it so clean:
        // even if we configure the server to send a UiShutdownResponse, MASQ will deny a success
        // because it will sense an ongoing connection on its 'active port'. The mock server, though,
        // cannot be make abruptly break up.
        let node_ui_port = find_free_port();
        let start_response = UiStartResponse {
            new_process_id: 1234,
            redirect_ui_port: node_ui_port,
        }
        .tmb(1);
        let broadcast = UiConnectionChangeBroadcast {
            stage: UiConnectionStage::RouteFound,
        }
        .tmb(0);
        let descriptor_response = UiDescriptorResponse {
            node_descriptor_opt: Some("perfect-masq-node-descriptor".to_string()),
        }
        .tmb(2);
        let node = MockWebSocketsServer::new(node_ui_port)
            .queue_response(start_response)
            .queue_response(broadcast)
            .queue_response(descriptor_response);
        let server_handle = node.start().await;
        let initial_args_parser_mock = InitialArgsParserMock::default()
            .parse_initialization_args_result(CLIProgramEntering::Enter(InitializationArgs::new(
                node_ui_port,
            )));
        let (processor_aspiring_std_streams, processor_aspiring_std_stream_handles) =
            make_async_std_streams(vec![]);
        let (incidental_std_streams, incidental_std_stream_handles) =
            make_async_std_streams(vec![]);
        let std_streams_factory = AsyncStdStreamsFactoryMock::default()
            .make_result(incidental_std_streams)
            .make_result(processor_aspiring_std_streams);
        let stdin_read_line_results = vec![
            Ok(ReadInput::Line("start".to_string())),
            Ok(ReadInput::Line("descriptor".to_string())),
            Ok(ReadInput::Line("exit".to_string())),
        ];
        let (
            rw_term_interface,
            prime_term_interface_stream_handles,
            background_term_interface_stream_handles,
        ) = TermInterfaceMock::new_interactive(stdin_read_line_results);
        let terminal_interface_factory = TerminalInterfaceFactoryMock::default()
            .make_result(Either::Right(Box::new(rw_term_interface)));
        let mut subject = Main {
            std_streams_factory: Box::new(std_streams_factory),
            initial_args_parser: Box::new(initial_args_parser_mock),
            term_interface_factory: Box::new(terminal_interface_factory),
            command_factory_opt: Some(Box::new(CommandFactoryReal::default())),
            command_context_factory: Box::new(CommandContextFactoryReal::default()),
            command_execution_helper_factory: Box::new(CommandExecutionHelperFactoryReal::default()),
            command_processor_factory: Default::default(),
        };

        let result = subject.go(&["masq".to_string()]).await;

        allow_writings_to_finish().await;
        StdStreamsAssertionMatrix::default()
            .incidental_std_streams(Assert::NotUsed(&incidental_std_stream_handles))
            .processor_aspiring_std_streams(Assert::NotUsed(&processor_aspiring_std_stream_handles))
            .processor_term_interface(Assert::Expected(
                ProcessorTerminalInterfaceAssertionMatrix {
                    standard_assertions: TerminalInterfaceAssertionMatrix {
                        term_interface_stream_handles: &prime_term_interface_stream_handles,
                        expected_writes: FlushesWriteStreamsAssertion {
                            stdout: vec![
                                &format!(
                                    "MASQNode successfully started in process 1234 on port {}\n",
                                    node_ui_port
                                ),
                                "perfect-masq-node-descriptor\n",
                                "MASQ is terminating...\n",
                            ],
                            stderr: vec![],
                        }
                        .into(),
                        read_attempts_opt: Some(3),
                    },
                },
            ))
            .assert()
            .await;
        background_term_interface_stream_handles.assert_empty_stderr();
        assert_eq!(
            background_term_interface_stream_handles.stdout_flushed_strings(),
            vec!["\nRouteFound: You can now relay data over the network.\n\n".to_string()]
        );
        assert_eq!(result, 0);
    }
}
