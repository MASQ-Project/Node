// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::command_context::CommandContext;
use crate::command_context_factory::CommandContextFactory;
use crate::command_factory::CommandFactory;
use crate::commands::commands_common::{Command, CommandError};
use crate::masq_short_writeln;
use crate::terminal::{
    FlushHandle, RWTermInterface, ReadInput, TerminalWriter, WTermInterface,
};
use async_trait::async_trait;
use itertools::Either;
use masq_lib::utils::{exit_process};
use std::sync::Arc;

pub struct CommandProcessorFactory {}

impl CommandProcessorFactory {
    pub async fn make(
        &self,
        term_interface: Either<Box<dyn WTermInterface>, Box<dyn RWTermInterface>>,
        command_context_factory: &dyn CommandContextFactory,
        command_execution_helper_factory: &dyn CommandExecutionHelperFactory,
        command_factory: Box<dyn CommandFactory>,
        ui_port: u16,
    ) -> Result<Box<dyn CommandProcessor>, CommandError> {
        let background_term_interface_opt = match &term_interface {
            Either::Left(_) => None,
            Either::Right(read_write) => Some(read_write.write_only_clone()),
        };

        let command_context = command_context_factory
            .make(ui_port, background_term_interface_opt)
            .await?;

        let command_execution_helper = command_execution_helper_factory.make();

        let command_processor_common =
            CommandProcessorCommon::new(command_context, command_factory, command_execution_helper);
        match term_interface {
            Either::Left(write_only_ti) => Ok(Box::new(CommandProcessorNonInteractive::new(
                command_processor_common,
                write_only_ti,
            ))),
            Either::Right(read_write_ti) => Ok(Box::new(CommandProcessorInteractive::new(
                command_processor_common,
                read_write_ti,
            ))),
        }
    }
}

impl Default for CommandProcessorFactory {
    fn default() -> Self {
        Self::new()
    }
}

impl CommandProcessorFactory {
    pub fn new() -> Self {
        Self {}
    }
}

#[async_trait(?Send)]
pub trait CommandProcessor: ProcessorProvidingCommonComponents {
    async fn process_command_line(
        &mut self,
        initial_subcommand_opt: Option<&[String]>,
    ) -> Result<(), ()>;

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
                return Err(());
            }
        };

        let res = command_execution_helper
            .execute_command(command, command_context, terminal_interface)
            .await;

        match res {
            Ok(_) => Ok(()),
            Err(e) => {
                masq_short_writeln!(stderr, "{}", e);
                Err(())
            }
        }
    }

    fn write_only_term_interface(&self) -> &dyn WTermInterface;

    fn stdout(&self) -> (TerminalWriter, FlushHandle);

    fn stderr(&self) -> (TerminalWriter, FlushHandle);

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
    terminal_interface: Box<dyn WTermInterface>,
}

#[async_trait(?Send)]
impl CommandProcessor for CommandProcessorNonInteractive {
    async fn process_command_line(
        &mut self,
        initial_subcommand_opt: Option<&[String]>,
    ) -> Result<(), ()> {
        let command_args = initial_subcommand_opt.expect("Missing args in non-interactive mode");
        self.handle_command_common(command_args).await
    }

    fn write_only_term_interface(&self) -> &dyn WTermInterface {
        self.terminal_interface.as_ref()
    }

    fn stdout(&self) -> (TerminalWriter, FlushHandle) {
        self.terminal_interface.stdout()
    }

    fn stderr(&self) -> (TerminalWriter, FlushHandle) {
        self.terminal_interface.stderr()
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
        terminal_interface: Box<dyn WTermInterface>,
    ) -> Self {
        Self {
            command_processor_common,
            terminal_interface,
        }
    }
}

pub struct CommandProcessorInteractive {
    command_processor_common: CommandProcessorCommon,
    terminal_interface: Box<dyn RWTermInterface>,
}

impl CommandProcessorInteractive {
    fn new(
        command_processor_common: CommandProcessorCommon,
        terminal_interface: Box<dyn RWTermInterface>,
    ) -> CommandProcessorInteractive {
        Self {
            command_processor_common,
            terminal_interface,
        }
    }
}

#[async_trait(?Send)]
impl CommandProcessor for CommandProcessorInteractive {
    async fn process_command_line(
        &mut self,
        _initial_subcommand_opt: Option<&[String]>,
    ) -> Result<(), ()> {
        loop {
            let args = match self.terminal_interface.read_line().await {
                Ok(read_input) => match read_input {
                    ReadInput::Line(cmd) => split_possibly_quoted_cml(cmd),
                    ReadInput::Quit => {
                        let (stderr, stderr_flush_handle) =
                            self.terminal_interface.write_only_ref().stderr();

                        masq_short_writeln!(stderr, "MASQ interrupted");
                        // Flushing the err msg
                        drop(stderr_flush_handle);

                        exit_process(1, "")
                    }
                    ReadInput::Ignored { msg_opt } => {
                        let (stdout, _stdout_flush_handle) =
                            self.terminal_interface.write_only_ref().stdout();

                        let description = match msg_opt {
                            Some(msg) => format!(" ({})", msg),
                            None => "".to_string(),
                        };
                        masq_short_writeln!(stdout, "Ignored instruction{}", description);

                        continue;
                    }
                },
                Err(e) => {
                    let (stderr, _stderr_flush_handle) =
                        self.terminal_interface.write_only_ref().stderr();

                    masq_short_writeln!(stderr, "Terminal read error: {}", e);

                    break Err(());
                }
            };

            if let [single_arg] = args[..].as_ref() {
                if single_arg == "exit" {
                    return Ok(());
                }
            }

            if let Err(_) = self.handle_command_common(&args).await {
                return Err(());
            }
        }
    }

    fn write_only_term_interface(&self) -> &dyn WTermInterface {
        self.terminal_interface.write_only_ref()
    }

    fn stdout(&self) -> (TerminalWriter, FlushHandle) {
        self.write_only_term_interface().stdout()
    }

    fn stderr(&self) -> (TerminalWriter, FlushHandle) {
        self.write_only_term_interface().stderr()
    }

    async fn close(&mut self) {
        let (writer, _flush_handle) = self.terminal_interface.write_only_ref().stdout();

        masq_short_writeln!(writer, "MASQ is terminating...");

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
        Box::new(CommandExecutionHelperReal {})
    }
}

#[async_trait(?Send)]
pub trait CommandExecutionHelper {
    async fn execute_command(
        &self,
        command: Box<dyn Command>,
        context: &dyn CommandContext,
        // Consider sticking in only the streams, dropping the handles outside the actual 'execute()'
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
    use crate::command_context_factory::CommandContextFactoryReal;
    use crate::command_factory::CommandFactoryReal;
    use crate::terminal::test_utils::allow_flushed_writings_to_finish;
    use crate::test_utils::mocks::{
        AsyncTestStreamHandles,
        CommandContextMock, CommandExecutionHelperMock, CommandFactoryMock, TermInterfaceMock,
    };
    use futures::FutureExt;
    use masq_lib::utils::{find_free_port, running_test};
    use std::panic::AssertUnwindSafe;

    async fn test_handles_nonexistent_server(is_interactive: bool) {
        let ui_port = find_free_port();
        let subject = CommandProcessorFactory::default();
        let terminal_interface_in_either = if !is_interactive {
            let (term_interface, _) = TermInterfaceMock::new_non_interactive();
            Either::Left(Box::new(term_interface) as Box<dyn WTermInterface>)
        } else {
            let (term_interface, _,_) = TermInterfaceMock::new_interactive(vec![]);
            Either::Right(Box::new(term_interface) as Box<dyn RWTermInterface>)
        };
        let command_context_factory = CommandContextFactoryReal::default();
        let command_execution_helper_factory = CommandExecutionHelperFactoryReal::default();
        let command_factory = Box::new(CommandFactoryReal::default());

        let result = Arc::new(subject)
            .make(
                terminal_interface_in_either,
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

    #[tokio::test]
    async fn interactive_command_processor_handles_quit_signals() {
        running_test();
        let command_context = Box::new(CommandContextMock::default());
        let command_factory = Box::new(CommandFactoryReal::new());
        let command_execution_helper = Box::new(CommandExecutionHelperMock::default());
        let command_processor_common =
            CommandProcessorCommon::new(command_context, command_factory, command_execution_helper);
        let (terminal_interface, stream_handles, _) =
            TermInterfaceMock::new_interactive(vec![Ok(ReadInput::Quit)]);
        let mut subject = CommandProcessorInteractive::new(
            command_processor_common,
            Box::new(terminal_interface),
        );

        let caught_fictional_panic = AssertUnwindSafe(subject.process_command_line(None))
            .catch_unwind()
            .await
            .unwrap_err();

        allow_flushed_writings_to_finish().await;
        assert_eq!(stream_handles.stdout_all_in_one(), "");
        assert_eq!(stream_handles.stderr_all_in_one(), "MASQ interrupted\n");
        let exiting_msg = caught_fictional_panic.downcast_ref::<String>().unwrap();
        assert_eq!(exiting_msg, "1: ")
    }

    #[tokio::test]
    async fn interactive_command_processor_handles_ignored_instruction_without_description() {
        interactive_command_processor_handles_ignored_instruction(
            ReadInput::Ignored { msg_opt: None },
            "Ignored instruction\n",
        )
        .await
    }

    #[tokio::test]
    async fn interactive_command_processor_handles_ignored_instruction_with_description() {
        interactive_command_processor_handles_ignored_instruction(
            ReadInput::Ignored {
                msg_opt: Some("Event description".to_string()),
            },
            "Ignored instruction (Event description)\n",
        )
        .await
    }

    async fn interactive_command_processor_handles_ignored_instruction(
        tested_read: ReadInput,
        expected_stdout_msg: &str,
    ) {
        running_test();
        let command_context = Box::new(CommandContextMock::default());
        let command_factory = Box::new(CommandFactoryReal::new());
        let command_execution_helper = Box::new(CommandExecutionHelperMock::default());
        let command_processor_common =
            CommandProcessorCommon::new(command_context, command_factory, command_execution_helper);
        let (terminal_interface, stream_handles, _) = TermInterfaceMock::new_interactive(vec![
            Ok(tested_read),
            Ok(ReadInput::Line("exit".to_string())),
        ]);
        let mut subject = CommandProcessorInteractive::new(
            command_processor_common,
            Box::new(terminal_interface),
        );

        let result = subject.process_command_line(None).await;

        allow_flushed_writings_to_finish().await;
        assert_eq!(stream_handles.stdout_all_in_one(), expected_stdout_msg);
        assert_eq!(stream_handles.stderr_all_in_one(), "");
        assert_eq!(result, Ok(()))
    }

    #[tokio::test]
    async fn handling_command_line_in_interactive_command_processor_handles_error() {
        let command_context = Box::new(CommandContextMock::default());
        let command_factory = Box::new(CommandFactoryReal::new());
        let command_execution_helper = Box::new(CommandExecutionHelperMock::default());
        let command_processor_common =
            CommandProcessorCommon::new(command_context, command_factory, command_execution_helper);
        let (terminal_interface, stream_handles, _) =
            TermInterfaceMock::new_interactive(vec![Ok(ReadInput::Line("bluh".to_string()))]);
        let mut subject = CommandProcessorInteractive::new(
            command_processor_common,
            Box::new(terminal_interface),
        );

        let result = subject.process_command_line(None).await;

        allow_flushed_writings_to_finish().await;
        assert_eq!(result, Err(()));
        assert_eq!(stream_handles.stdout_all_in_one(), "");
        assert_eq!(
            stream_handles.stderr_all_in_one(),
            "Unrecognized command: \"bluh\"\n"
        )
    }

    fn make_command_processor_common() -> CommandProcessorCommon {
        CommandProcessorCommon::new(
            Box::new(CommandContextMock::default()),
            Box::new(CommandFactoryMock::default()),
            Box::new(CommandExecutionHelperMock::default()),
        )
    }

    #[tokio::test]
    async fn write_streams_work_fine_for_non_interactive_terminal() {
        let (interface, stream_handles) = TermInterfaceMock::new_non_interactive();
        let subject = CommandProcessorNonInteractive::new(
            make_command_processor_common(),
            Box::new(interface),
        );

        test_write_streams_work_fine_for_command_processor(&subject, stream_handles).await
    }

    #[tokio::test]
    async fn write_streams_work_fine_for_interactive_terminal() {
        let (interface, stream_handles, _) = TermInterfaceMock::new_interactive(vec![]);
        let subject =
            CommandProcessorInteractive::new(make_command_processor_common(), Box::new(interface));

        test_write_streams_work_fine_for_command_processor(&subject, stream_handles).await
    }

    async fn test_write_streams_work_fine_for_command_processor(
        subject: &dyn CommandProcessor,
        stream_handles: AsyncTestStreamHandles,
    ) {
        let (stdout, stdout_flush_handle) = subject.stdout();
        stdout.writeln("a1b2c3").await;
        let (stderr, stderr_flush_handle) = subject.stderr();
        stderr.writeln("3a2b1c").await;

        drop(stdout_flush_handle);
        drop(stderr_flush_handle);
        allow_flushed_writings_to_finish().await;
        assert_eq!(stream_handles.stdout_all_in_one(), "a1b2c3\n");
        assert_eq!(stream_handles.stderr_all_in_one(), "3a2b1c\n")
    }
}
