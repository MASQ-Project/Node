// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::command_factory::CommandFactory;
use crate::command_processor::CommandProcessor;
use crate::interactive_mode::CustomTrioForGoInteractive::{Break, Continue, Return};
use crate::line_reader::TerminalEvent;
use crate::line_reader::TerminalEvent::{CLBreak, CLContinue, CLError, CommandLine};
use crate::non_interactive_mode::handle_command_common;
use crate::schema::app;
use crate::terminal_interface::TerminalWrapper;
use masq_lib::command::StdStreams;
use masq_lib::short_writeln;
use std::io::Write;

enum CustomTrioForGoInteractive {
    Break,
    Continue,
    Return(bool),
}

pub fn go_interactive(
    command_factory: &dyn CommandFactory,
    command_processor: &mut dyn CommandProcessor,
    streams: &mut StdStreams<'_>,
) -> bool {
    loop {
        let read_line_result = command_processor.terminal_wrapper_ref().read_line();
        match handle_terminal_event(
            streams,
            command_factory,
            command_processor,
            read_line_result,
        ) {
            Continue => continue,
            Break => break,
            Return(ending_flag) => return ending_flag,
        }
    }
    true
}

fn handle_terminal_event(
    streams: &mut StdStreams<'_>,
    command_factory: &dyn CommandFactory,
    command_processor: &mut dyn CommandProcessor,
    read_line_result: TerminalEvent,
) -> CustomTrioForGoInteractive {
    match pass_args_or_print_messages(streams, read_line_result) {
        CommandLine(args) => handle_args(args, streams, command_factory, command_processor),
        CLBreak => Break,
        CLContinue => Continue,
        CLError(_) => Return(false),
    }
}

fn handle_args(
    args: Vec<String>,
    streams: &mut StdStreams<'_>,
    command_factory: &dyn CommandFactory,
    command_processor: &mut dyn CommandProcessor,
) -> CustomTrioForGoInteractive {
    if args.is_empty() {
        return Continue;
    }
    if args[0] == "exit" {
        return Break;
    }
    if handle_help_or_version(
        &args[0],
        streams.stdout,
        command_processor.terminal_wrapper_ref(),
    ) {
        return Continue;
    }
    let _ = handle_command_common(command_factory, command_processor, args, streams.stderr);
    Continue
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

fn pass_args_or_print_messages(
    streams: &mut StdStreams<'_>,
    read_line_result: TerminalEvent,
) -> TerminalEvent {
    match read_line_result {
        CommandLine(args) => CommandLine(args),
        CLContinue => {
            short_writeln!(
                streams.stdout,
                "Received a signal interpretable as continue"
            );
            CLContinue
        }
        CLBreak => {
            short_writeln!(streams.stdout, "Terminated");
            CLBreak
        }
        CLError(e) => {
            short_writeln!(streams.stderr, "{}", e.expect("expected Some()"));
            CLError(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::command_factory::CommandFactoryError;
    use crate::interactive_mode::{
        go_interactive, handle_help_or_version, pass_args_or_print_messages,
    };
    use crate::line_reader::TerminalEvent;
    use crate::line_reader::TerminalEvent::{CLBreak, CLContinue, CLError};
    use crate::terminal_interface::TerminalWrapper;
    use crate::test_utils::mocks::{
        CommandFactoryMock, CommandProcessorMock, TerminalActiveMock, TerminalPassiveMock,
    };
    use crossbeam_channel::bounded;
    use masq_lib::test_utils::fake_stream_holder::{ByteArrayWriter, FakeStreamHolder};
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::Instant;

    #[test]
    fn interactive_mode_works_for_unrecognized_command() {
        let make_params_arc = Arc::new(Mutex::new(vec![]));
        let mut stream_holder = FakeStreamHolder::new();
        let mut streams = stream_holder.streams();
        let terminal_interface = TerminalWrapper::new(Box::new(
            TerminalPassiveMock::new()
                .read_line_result(TerminalEvent::CommandLine(vec![
                    "error".to_string(),
                    "command".to_string(),
                ]))
                .read_line_result(TerminalEvent::CommandLine(vec!["exit".to_string()])),
        ));
        let command_factory = CommandFactoryMock::new()
            .make_params(&make_params_arc)
            .make_result(Err(CommandFactoryError::UnrecognizedSubcommand(
                "Booga!".to_string(),
            )));
        let mut processor =
            CommandProcessorMock::new().inject_terminal_interface(terminal_interface);

        let result = go_interactive(&command_factory, &mut processor, &mut streams);

        assert_eq!(result, true);
        let make_params = make_params_arc.lock().unwrap();
        assert_eq!(
            *make_params,
            vec![vec!["error".to_string(), "command".to_string()]]
        );
        assert_eq!(
            stream_holder.stderr.get_string(),
            "Unrecognized command: 'Booga!'\n".to_string()
        )
    }

    #[test]
    fn interactive_mode_works_for_command_with_bad_syntax() {
        let make_params_arc = Arc::new(Mutex::new(vec![]));
        let mut stream_holder = FakeStreamHolder::new();
        let mut streams = stream_holder.streams();
        let terminal_interface = TerminalWrapper::new(Box::new(
            TerminalPassiveMock::new()
                .read_line_result(TerminalEvent::CommandLine(vec![
                    "error".to_string(),
                    "command".to_string(),
                ]))
                .read_line_result(TerminalEvent::CommandLine(vec!["exit".to_string()])),
        ));
        let command_factory = CommandFactoryMock::new()
            .make_params(&make_params_arc)
            .make_result(Err(CommandFactoryError::CommandSyntax(
                "Booga!".to_string(),
            )));
        let mut processor =
            CommandProcessorMock::new().inject_terminal_interface(terminal_interface);

        let result = go_interactive(&command_factory, &mut processor, &mut streams);

        assert_eq!(result, true);
        let make_params = make_params_arc.lock().unwrap();
        assert_eq!(
            *make_params,
            vec![vec!["error".to_string(), "command".to_string()]]
        );
        assert_eq!(stream_holder.stderr.get_string(), "Booga!\n".to_string());
    }

    #[test]
    fn continue_and_break_orders_work_for_interactive_mode() {
        let mut stream_holder = FakeStreamHolder::new();
        let mut streams = stream_holder.streams();
        let terminal_interface = TerminalWrapper::new(Box::new(
            TerminalPassiveMock::new()
                .read_line_result(TerminalEvent::CLContinue)
                .read_line_result(TerminalEvent::CLBreak),
        ));
        let command_factory = CommandFactoryMock::new();
        let mut processor =
            CommandProcessorMock::new().inject_terminal_interface(terminal_interface);

        let result = go_interactive(&command_factory, &mut processor, &mut streams);

        assert_eq!(result, true);
        assert_eq!(stream_holder.stderr.get_string(), "".to_string());
        assert_eq!(
            stream_holder.stdout.get_string(),
            "Received a signal interpretable as continue\nTerminated\n".to_string()
        )
    }

    #[test]
    fn pass_on_args_or_print_messages_announces_break_signal_from_line_reader() {
        let mut stream_holder = FakeStreamHolder::new();

        let result = pass_args_or_print_messages(&mut stream_holder.streams(), CLBreak);

        assert_eq!(result, CLBreak);
        assert_eq!(stream_holder.stderr.get_string(), "");
        assert_eq!(stream_holder.stdout.get_string(), "Terminated\n");
    }

    #[test]
    fn pass_on_args_or_print_messages_announces_continue_signal_from_line_reader() {
        let mut stream_holder = FakeStreamHolder::new();

        let result = pass_args_or_print_messages(&mut stream_holder.streams(), CLContinue);

        assert_eq!(result, CLContinue);
        assert_eq!(stream_holder.stderr.get_string(), "");
        assert_eq!(
            stream_holder.stdout.get_string(),
            "Received a signal interpretable as continue\n"
        );
    }

    #[test]
    fn pass_on_args_or_print_messages_announces_error_from_line_reader() {
        let mut stream_holder = FakeStreamHolder::new();

        let result = pass_args_or_print_messages(
            &mut stream_holder.streams(),
            CLError(Some("Invalid Input\n".to_string())),
        );

        assert_eq!(result, CLError(None));
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
