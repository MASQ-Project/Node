// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::command_factory::CommandFactory;
use crate::command_processor::CommandProcessor;
use crate::line_reader::TerminalEvent::{
    Break, CommandLine, Continue, Error as TerminalEventError,
};
use masq_lib::command::StdStreams;
use masq_lib::short_writeln;
use std::io::Write;

fn split_quoted_line(input: String) -> Vec<String> {
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

pub fn go_interactive<A, B, F>(
    handle_command: Box<F>,
    command_factory: &A,
    processor: &mut B,
    streams: &mut StdStreams<'_>,
) -> u8
where
    F: Fn(&A, &mut B, Vec<String>, &mut (dyn Write + Send)) -> Result<(), ()>,
    A: CommandFactory + ?Sized + 'static,
    B: CommandProcessor + ?Sized + 'static,
{
    loop {
        let args = match processor.clone_terminal_interface().read_line() {
            CommandLine(line) => split_quoted_line(line),
            Break => unimplemented!(),    //Break
            Continue => unimplemented!(), //Continue
            TerminalEventError(msg) => {
                short_writeln!(streams.stderr, "{}", msg);
                return 1;
            }
        };
        if args.is_empty() {
            continue;
        }
        if args[0] == "exit" {
            break;
        }
        match handle_command(command_factory, processor, args, streams.stderr) {
            Ok(_) => (),
            Err(_) => continue,
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use crate::command_context::CommandContext;
    use crate::command_factory::CommandFactoryError;
    use crate::commands::commands_common;
    use crate::commands::commands_common::CommandError;
    use crate::interactive_mode::split_quoted_line;
    use crate::line_reader::{TerminalEvent, TerminalReal};
    use crate::non_interactive_mode::Main;
    use crate::terminal_interface::TerminalWrapper;
    use crate::test_utils::mocks::{
        CommandFactoryMock, CommandProcessorFactoryMock, CommandProcessorMock, InterfaceMock,
        InterfaceRawMock, TerminalPassiveMock,
    };
    use masq_lib::command::Command;
    use masq_lib::intentionally_blank;
    use masq_lib::test_utils::fake_stream_holder::FakeStreamHolder;
    use std::sync::{Arc, Mutex};

    #[test]
    fn accept_subcommand_handles_balanced_double_quotes() {
        let command_line =
            "  first \"second\" third  \"fourth'fifth\" \t sixth \"seventh eighth\tninth\" "
                .to_string();

        let result = split_quoted_line(command_line);

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
    fn accept_subcommand_handles_unbalanced_double_quotes() {
        let command_line =
            "  first \"second\" third  \"fourth'fifth\" \t sixth \"seventh eighth\tninth  "
                .to_string();

        let result = split_quoted_line(command_line);

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
    fn accept_subcommand_handles_balanced_single_quotes() {
        let command_line =
            "  first \n 'second' \n third \n 'fourth\"fifth' \t sixth 'seventh eighth\tninth' "
                .to_string();

        let result = split_quoted_line(command_line);

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
    fn accept_subcommand_handles_unbalanced_single_quotes() {
        let command_line =
            "  first 'second' third  'fourth\"fifth' \t sixth 'seventh eighth\tninth  ".to_string();
        let result = split_quoted_line(command_line);

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

    #[derive(Debug)]
    struct FakeCommand {
        output: String,
    }

    impl commands_common::Command for FakeCommand {
        fn execute(&self, _context: &mut dyn CommandContext) -> Result<(), CommandError> {
            intentionally_blank!()
        }
    }

    impl FakeCommand {
        pub fn new(output: &str) -> Self {
            Self {
                output: output.to_string(),
            }
        }
    }

    #[test]
    fn interactive_mode_works_when_everything_is_copacetic() {
        let make_params_arc = Arc::new(Mutex::new(vec![]));
        let command_factory = CommandFactoryMock::new()
            .make_params(&make_params_arc)
            .make_result(Ok(Box::new(FakeCommand::new("setup command"))))
            .make_result(Ok(Box::new(FakeCommand::new("start command"))));
        let terminal_mock = TerminalPassiveMock::new()
            .read_line_result(TerminalEvent::CommandLine("setup".to_string()))
            .read_line_result(TerminalEvent::CommandLine("start".to_string()))
            .read_line_result(TerminalEvent::CommandLine("exit".to_string()));
        let interface = InterfaceMock::new()
            .make_result(Ok(TerminalReal::new(Box::new(InterfaceRawMock::new()))));
        let processor = CommandProcessorMock::new()
            .process_result(Ok(()))
            .process_result(Ok(()))
            .insert_terminal_interface(
                TerminalWrapper::new().set_interactive_for_test_purposes(Box::new(terminal_mock)),
            );
        let processor_factory =
            CommandProcessorFactoryMock::new().make_result(Ok(Box::new(processor)));
        let mut subject = Main::test_only_new(
            Box::new(command_factory),
            Box::new(processor_factory),
            Box::new(interface),
        );
        let mut stream_holder = FakeStreamHolder::new();

        let result = subject.go(
            &mut stream_holder.streams(),
            &[
                "command".to_string(),
                "--param1".to_string(),
                "value1".to_string(),
            ],
        );

        assert_eq!(result, 0);
        let make_params = make_params_arc.lock().unwrap();
        assert_eq!(
            *make_params,
            vec![vec!["setup".to_string()], vec!["start".to_string()]]
        );
    }

    #[test]
    fn interactive_mode_works_for_stdin_read_error() {
        let command_factory = CommandFactoryMock::new();
        let close_params_arc = Arc::new(Mutex::new(vec![]));
        let processor = CommandProcessorMock::new()
            .close_params(&close_params_arc)
            .insert_terminal_interface(
                TerminalWrapper::new().set_interactive_for_test_purposes(Box::new(
                    TerminalPassiveMock::new()
                        .read_line_result(TerminalEvent::Error("ConnectionRefused".to_string())),
                )),
            );
        let processor_factory =
            CommandProcessorFactoryMock::new().make_result(Ok(Box::new(processor)));
        let interface = InterfaceMock::new()
            .make_result(Ok(TerminalReal::new(Box::new(InterfaceRawMock::new()))));
        let mut subject = Main::test_only_new(
            Box::new(command_factory),
            Box::new(processor_factory),
            Box::new(interface),
        );
        let mut stream_holder = FakeStreamHolder::new();

        let result = subject.go(&mut stream_holder.streams(), &["command".to_string()]);

        assert_eq!(result, 1);
        assert_eq!(
            stream_holder.stderr.get_string(),
            "ConnectionRefused\n".to_string()
        );
        let close_params = close_params_arc.lock().unwrap();
        assert_eq!(close_params.len(), 1);
    }

    #[test]
    fn interactive_mode_works_for_unrecognized_command() {
        let make_params_arc = Arc::new(Mutex::new(vec![]));
        let command_factory = CommandFactoryMock::new()
            .make_params(&make_params_arc)
            .make_result(Err(CommandFactoryError::UnrecognizedSubcommand(
                "Booga!".to_string(),
            )));
        let interface = InterfaceMock::new()
            .make_result(Ok(TerminalReal::new(Box::new(InterfaceRawMock::new()))));
        let processor = CommandProcessorMock::new().insert_terminal_interface(
            TerminalWrapper::new().set_interactive_for_test_purposes(Box::new(
                TerminalPassiveMock::new()
                    .read_line_result(TerminalEvent::CommandLine("error command\n".to_string()))
                    .read_line_result(TerminalEvent::CommandLine("exit\n".to_string())),
            )),
        );
        let processor_factory =
            CommandProcessorFactoryMock::new().make_result(Ok(Box::new(processor)));
        let mut subject = Main::test_only_new(
            Box::new(command_factory),
            Box::new(processor_factory),
            Box::new(interface),
        );
        let mut stream_holder = FakeStreamHolder::new();

        let result = subject.go(&mut stream_holder.streams(), &["command".to_string()]);

        assert_eq!(result, 0);
        let make_params = make_params_arc.lock().unwrap();
        assert_eq!(
            *make_params,
            vec![vec!["error".to_string(), "command".to_string()]]
        );
        assert_eq!(
            stream_holder.stderr.get_string(),
            "Unrecognized command: 'Booga!'\n".to_string()
        );
    }

    #[test]
    fn interactive_mode_works_for_command_with_bad_syntax() {
        let make_params_arc = Arc::new(Mutex::new(vec![]));
        let command_factory = CommandFactoryMock::new()
            .make_params(&make_params_arc)
            .make_result(Err(CommandFactoryError::CommandSyntax(
                "Booga!".to_string(),
            )));
        let interface = InterfaceMock::new()
            .make_result(Ok(TerminalReal::new(Box::new(InterfaceRawMock::new()))));
        let processor = CommandProcessorMock::new().insert_terminal_interface(
            TerminalWrapper::new().set_interactive_for_test_purposes(Box::new(
                TerminalPassiveMock::new()
                    .read_line_result(TerminalEvent::CommandLine("error command\n".to_string()))
                    .read_line_result(TerminalEvent::CommandLine("exit\n".to_string())),
            )),
        );
        let processor_factory =
            CommandProcessorFactoryMock::new().make_result(Ok(Box::new(processor)));
        let mut subject = Main::test_only_new(
            Box::new(command_factory),
            Box::new(processor_factory),
            Box::new(interface),
        );
        let mut stream_holder = FakeStreamHolder::new();

        let result = subject.go(&mut stream_holder.streams(), &["command".to_string()]);

        assert_eq!(result, 0);
        let make_params = make_params_arc.lock().unwrap();
        assert_eq!(
            *make_params,
            vec![vec!["error".to_string(), "command".to_string()]]
        );
        assert_eq!(stream_holder.stderr.get_string(), "Booga!\n".to_string());
    }

    #[test]
    fn clone_of_terminal_is_shared_along_and_passed_on_properly() {
        let make_params_arc = Arc::new(Mutex::new(vec![]));
        let command_factory = CommandFactoryMock::new()
            .make_params(&make_params_arc)
            .make_result(Ok(Box::new(FakeCommand::new("setup command"))));
        let interface = InterfaceMock::new()
            .make_result(Ok(TerminalReal::new(Box::new(InterfaceRawMock::new()))));
        let terminal_interface_reference_for_inner = TerminalWrapper::new()
            .set_interactive_for_test_purposes(Box::new(
                TerminalPassiveMock::new()
                    .read_line_result(TerminalEvent::CommandLine("setup\n".to_string()))
                    .read_line_result(TerminalEvent::CommandLine("exit\n".to_string())),
            ));
        let reference_for_counting = Arc::new(Mutex::new(0));
        let processor = CommandProcessorMock::new()
            .insert_terminal_interface(terminal_interface_reference_for_inner.clone())
            .insert_terminal_wrapper_shared_counter(reference_for_counting.clone())
            .process_result(Ok(()));

        assert_eq!(*reference_for_counting.lock().unwrap(), 0);

        let processor_factory =
            CommandProcessorFactoryMock::new().make_result(Ok(Box::new(processor)));
        let mut subject = Main::test_only_new(
            Box::new(command_factory),
            Box::new(processor_factory),
            Box::new(interface),
        );
        let mut stream_holder = FakeStreamHolder::new();

        let result = subject.go(
            &mut stream_holder.streams(),
            &[
                "command".to_string(),
                "--param1".to_string(),
                "value1".to_string(),
            ],
        );

        //cloned once for each command, so twice in total
        assert_eq!(*reference_for_counting.lock().unwrap(), 2);

        assert_eq!(result, 0);
        let make_params = make_params_arc.lock().unwrap();
        assert_eq!(*make_params, vec![vec!["setup".to_string()]]);
    }
}
