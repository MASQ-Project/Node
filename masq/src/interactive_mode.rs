// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::command_factory::CommandFactory;
use crate::command_processor::CommandProcessor;
use crate::line_reader::TerminalEvent;
use crate::line_reader::TerminalEvent::{
    Break, CommandLine, Continue, Error as TerminalEventError,
};
use crate::schema::app;
use crate::terminal_interface::TerminalWrapper;
use masq_lib::command::StdStreams;
use masq_lib::short_writeln;
use std::io::Write;

pub fn go_interactive<CF: ?Sized, CP: ?Sized, HC>(
    handle_command: Box<HC>,
    command_factory: &CF,
    processor: &mut CP,
    streams: &mut StdStreams<'_>,
) -> u8
where
    HC: Fn(&CF, &mut CP, Vec<String>, &mut dyn Write) -> Result<(), ()>,
    CF: CommandFactory,
    CP: CommandProcessor,
{
    loop {
        let read_line_result = processor.terminal_wrapper_ref().read_line();
        let args = match pass_on_args_or_print_messages(streams, read_line_result) {
            CommandLine(args) => args,
            Break => break,
            Continue => continue,
            TerminalEventError(_) => return 1,
        };
        if args.is_empty() {
            continue;
        }
        if args[0] == "exit" {
            break;
        }
        if handle_help_or_version(&args[0], streams.stdout, processor.terminal_wrapper_ref()) {
            continue;
        }
        let _ = handle_command(command_factory, processor, args, streams.stderr);
    }
    0
}

fn handle_help_or_version(
    arg: &str,
    mut stdout: &mut dyn Write,
    terminal_interface: &TerminalWrapper,
) -> bool {
    let _lock = terminal_interface.lock();
    match arg {
        "help" => app()
            .write_help(&mut stdout)
            .expect("masq help set incorrectly"),
        "version" => app()
            .write_version(&mut stdout)
            .expect("masq version set incorrectly"),
        _ => return false,
    }
    short_writeln!(stdout, "");
    true
}

fn pass_on_args_or_print_messages(
    streams: &mut StdStreams<'_>,
    read_line_result: TerminalEvent,
) -> TerminalEvent {
    match read_line_result {
        CommandLine(args) => CommandLine(args),

        Continue => {
            short_writeln!(
                streams.stdout,
                "Received a signal interpretable as continue"
            );
            Continue
        }

        Break => {
            short_writeln!(streams.stdout, "Terminated");
            Break
        }

        TerminalEventError(e) => {
            short_writeln!(streams.stderr, "{}", e.expect("expected Some()"));
            TerminalEventError(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::command_context::CommandContext;
    use crate::command_factory::CommandFactoryError;
    use crate::commands::commands_common;
    use crate::commands::commands_common::CommandError;
    use crate::interactive_mode::{handle_help_or_version, pass_on_args_or_print_messages};
    use crate::line_reader::TerminalEvent;
    use crate::line_reader::TerminalEvent::{Break, Continue, Error};
    use crate::non_interactive_mode::Main;
    use crate::terminal_interface::TerminalWrapper;
    use crate::test_utils::mocks::{
        CommandFactoryMock, CommandProcessorFactoryMock, CommandProcessorMock, NIClapFactoryMock,
        TerminalActiveMock, TerminalPassiveMock,
    };
    use crossbeam_channel::bounded;
    use masq_lib::command::Command;
    use masq_lib::intentionally_blank;
    use masq_lib::test_utils::fake_stream_holder::{ByteArrayWriter, FakeStreamHolder};
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::Instant;

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
            .read_line_result(TerminalEvent::CommandLine(vec!["setup".to_string()]))
            .read_line_result(TerminalEvent::CommandLine(vec!["start".to_string()]))
            .read_line_result(TerminalEvent::CommandLine(vec!["exit".to_string()]));
        let processor = CommandProcessorMock::new()
            .process_result(Ok(()))
            .process_result(Ok(()))
            .inject_terminal_interface(TerminalWrapper::new(Box::new(terminal_mock)));
        let processor_factory =
            CommandProcessorFactoryMock::new().make_result(Ok(Box::new(processor)));
        let mut subject = Main::test_only_new(
            Box::new(NIClapFactoryMock {}),
            Box::new(command_factory),
            Box::new(processor_factory),
        );
        let mut stream_holder = FakeStreamHolder::new();

        let result = subject.go(
            &mut stream_holder.streams(),
            &[
                "command".to_string(),
                "--param".to_string(),
                "value".to_string(),
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
    fn interactive_mode_works_for_unrecognized_command() {
        let make_params_arc = Arc::new(Mutex::new(vec![]));
        let command_factory = CommandFactoryMock::new()
            .make_params(&make_params_arc)
            .make_result(Err(CommandFactoryError::UnrecognizedSubcommand(
                "Booga!".to_string(),
            )));
        let processor =
            CommandProcessorMock::new().inject_terminal_interface(TerminalWrapper::new(Box::new(
                TerminalPassiveMock::new()
                    .read_line_result(TerminalEvent::CommandLine(vec![
                        "error".to_string(),
                        "command".to_string(),
                    ]))
                    .read_line_result(TerminalEvent::CommandLine(vec!["exit".to_string()])),
            )));
        let processor_factory =
            CommandProcessorFactoryMock::new().make_result(Ok(Box::new(processor)));
        let mut subject = Main::test_only_new(
            Box::new(NIClapFactoryMock {}),
            Box::new(command_factory),
            Box::new(processor_factory),
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
        let processor =
            CommandProcessorMock::new().inject_terminal_interface(TerminalWrapper::new(Box::new(
                TerminalPassiveMock::new()
                    .read_line_result(TerminalEvent::CommandLine(vec![
                        "error".to_string(),
                        "command".to_string(),
                    ]))
                    .read_line_result(TerminalEvent::CommandLine(vec!["exit".to_string()])),
            )));
        let processor_factory =
            CommandProcessorFactoryMock::new().make_result(Ok(Box::new(processor)));
        let mut subject = Main::test_only_new(
            Box::new(NIClapFactoryMock {}),
            Box::new(command_factory),
            Box::new(processor_factory),
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
    fn interactive_mode_works_for_stdin_read_error() {
        let command_factory = CommandFactoryMock::new();
        let close_params_arc = Arc::new(Mutex::new(vec![]));
        let processor = CommandProcessorMock::new()
            .close_params(&close_params_arc)
            .inject_terminal_interface(TerminalWrapper::new(Box::new(
                TerminalPassiveMock::new()
                    .read_line_result(TerminalEvent::Error(Some("ConnectionRefused".to_string()))),
            )));
        let processor_factory =
            CommandProcessorFactoryMock::new().make_result(Ok(Box::new(processor)));
        let mut subject = Main::test_only_new(
            Box::new(NIClapFactoryMock {}),
            Box::new(command_factory),
            Box::new(processor_factory),
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
    fn pass_on_args_or_print_messages_announces_break_signal_from_line_reader() {
        let mut stream_holder = FakeStreamHolder::new();

        let result = pass_on_args_or_print_messages(&mut stream_holder.streams(), Break);

        assert_eq!(result, Break);
        assert_eq!(stream_holder.stderr.get_string(), "");
        assert_eq!(stream_holder.stdout.get_string(), "Terminated\n");
    }

    #[test]
    fn pass_on_args_or_print_messages_announces_continue_signal_from_line_reader() {
        let mut stream_holder = FakeStreamHolder::new();

        let result = pass_on_args_or_print_messages(&mut stream_holder.streams(), Continue);

        assert_eq!(result, Continue);
        assert_eq!(stream_holder.stderr.get_string(), "");
        assert_eq!(
            stream_holder.stdout.get_string(),
            "Received a signal interpretable as continue\n"
        );
    }

    #[test]
    fn pass_on_args_or_print_messages_announces_error_from_line_reader() {
        let mut stream_holder = FakeStreamHolder::new();

        let result = pass_on_args_or_print_messages(
            &mut stream_holder.streams(),
            Error(Some("Invalid Input\n".to_string())),
        );

        assert_eq!(result, Error(None));
        assert_eq!(stream_holder.stderr.get_string(), "Invalid Input\n\n");
        assert_eq!(stream_holder.stdout.get_string(), "");
    }

    //help and version commands are also tested in integration tests with a focus on a bigger context

    #[test]
    fn handle_help_or_version_ignores_uninteresting_entries() {
        let terminal_interface = TerminalWrapper::new(Box::new(TerminalPassiveMock::new()));
        let mut stdout = ByteArrayWriter::new();

        let result = handle_help_or_version("something", &mut stdout, &terminal_interface);

        assert_eq!(result, false);
        assert_eq!(stdout.get_string(), "")
    }

    #[test]
    fn handle_help_or_version_provides_fine_lock_for_questioning_the_current_version() {
        let terminal_interface = TerminalWrapper::new(Box::new(TerminalActiveMock::new()));
        let background_interface_clone = terminal_interface.clone();
        let mut stdout = ByteArrayWriter::new();
        let (tx, rx) = bounded(1);
        let now = Instant::now();

        let _ = handle_help_or_version("help", &mut stdout, &terminal_interface);

        let time_period_when_loosen = now.elapsed();
        let handle = thread::spawn(move || {
            let _lock = background_interface_clone.lock();
            tx.send(()).unwrap();
            thread::sleep(time_period_when_loosen * 15);
        });
        rx.recv().unwrap();
        let now = Instant::now();

        let result = handle_help_or_version("help", &mut stdout, &terminal_interface);

        let time_period_when_locked = now.elapsed();
        handle.join().unwrap();
        assert!(
            time_period_when_locked > 3 * time_period_when_loosen,
            "{:?} is not longer than {:?}",
            time_period_when_locked,
            time_period_when_loosen
        );
        assert_eq!(result, true)
    }
}
