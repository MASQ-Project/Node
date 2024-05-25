// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::command_factory::CommandFactory;
use crate::command_processor::CommandProcessor;
use crate::schema::app;
use masq_lib::command::StdStreams;
use masq_lib::short_writeln;
use masq_lib::utils::ExpectValue;
use std::io::Write;

#[derive(Debug, PartialEq, Eq)]
enum InteractiveEvent {
    Break(bool), //exit code 0 vs 1
    Continue,
}

pub fn go_interactive(
    command_factory: &dyn CommandFactory,
    command_processor: &mut dyn CommandProcessor,
    streams: &mut StdStreams<'_>,
) -> bool {
    todo!()
    // loop {
    //     let read_line_result = command_processor.terminal_wrapper_ref().read_line();
    //     match handle_terminal_event(
    //         streams,
    //         command_factory,
    //         command_processor,
    //         read_line_result,
    //     ) {
    //         InteractiveEvent::Continue => continue,
    //         InteractiveEvent::Break(exit_flag) => break exit_flag,
    //     }
    // }
}
//
// fn handle_terminal_event(
//     streams: &mut StdStreams<'_>,
//     command_factory: &dyn CommandFactory,
//     command_processor: &mut dyn CommandProcessor,
//     read_line_result: TerminalEvent,
// ) -> InteractiveEvent {
//     match pass_args_or_print_messages(
//         streams,
//         read_line_result,
//         command_processor.terminal_wrapper_ref(),
//     ) {
//         CommandLine(args) => handle_args(&args, streams, command_factory, command_processor),
//         Break | EoF => InteractiveEvent::Break(true),
//         Error(_) => InteractiveEvent::Break(false),
//         Continue => InteractiveEvent::Continue,
//     }
// }
//
// fn handle_args(
//     args: &[String],
//     streams: &mut StdStreams<'_>,
//     command_factory: &dyn CommandFactory,
//     command_processor: &mut dyn CommandProcessor,
// ) -> InteractiveEvent {
//     match args {
//         [] => return InteractiveEvent::Continue,
//         [arg] => {
//             if let Some(event) = handle_special_args(arg, streams, command_processor) {
//                 return event;
//             }
//         }
//         _ => (),
//     }
//     let _ = handle_command_common(command_factory, command_processor, args, streams.stderr);
//     InteractiveEvent::Continue
// }
//
// fn handle_special_args(
//     arg: &str,
//     streams: &mut StdStreams<'_>,
//     command_processor: &mut dyn CommandProcessor,
// ) -> Option<InteractiveEvent> {
//     match arg {
//         "exit" => Some(InteractiveEvent::Break(true)),
//         //tested by integration tests
//         "help" | "version" => Some(handle_help_or_version(
//             arg,
//             streams.stdout,
//             command_processor.terminal_wrapper_ref(),
//         )),
//         _ => None,
//     }
// }
//
// fn handle_help_or_version(
//     arg: &str,
//     mut stdout: &mut dyn Write,
//     terminal_interface: &TerminalWrapper,
// ) -> InteractiveEvent {
//     let _lock = terminal_interface.lock();
//     match arg {
//         "help" => short_writeln!(&mut stdout, "{}", app().render_help()),
//         "version" => short_writeln!(&mut stdout, "{}", app().render_version()),
//         _ => unreachable!("should have been treated before"),
//     }
//     short_writeln!(stdout, "");
//     InteractiveEvent::Continue
// }
//
// fn pass_args_or_print_messages(
//     streams: &mut StdStreams<'_>,
//     read_line_result: TerminalEvent,
//     terminal_interface: &TerminalWrapper,
// ) -> TerminalEvent {
//     match read_line_result {
//         CommandLine(args) => CommandLine(args),
//         others => print_protected(others, terminal_interface, streams),
//     }
// }
//
// fn print_protected(
//     event_with_message: TerminalEvent,
//     terminal_interface: &TerminalWrapper,
//     streams: &mut StdStreams<'_>,
// ) -> TerminalEvent {
//     match event_with_message {
//         Break => {
//             let _lock = terminal_interface.lock_ultimately(streams, false);
//             short_writeln!(streams.stdout, "\nTerminated");
//             Break
//         }
//         Continue => {
//             let _lock = terminal_interface.lock();
//             short_writeln!(
//                 streams.stdout,
//                 "Received a signal interpretable as continue"
//             );
//             Continue
//         }
//         Error(e) => {
//             let _lock = terminal_interface.lock_ultimately(streams, true);
//             short_writeln!(streams.stderr, "{}", e.expectv("Some(String)"));
//             Error(None)
//         }
//         EoF => {
//             let _lock = terminal_interface.lock();
//             short_writeln!(streams.stdout, "\nTerminated\n");
//             EoF
//         }
//         _ => unreachable!("was to be matched elsewhere"),
//     }
// }
//
// #[cfg(test)]
// mod tests {
//     use crate::command_factory::CommandFactoryError;
//     use crate::interactive_mode::{
//         go_interactive, handle_args, handle_help_or_version, handle_terminal_event,
//         pass_args_or_print_messages, InteractiveEvent,
//     };
//     use crate::terminal::line_reader::TerminalEvent;
//     use crate::terminal::line_reader::TerminalEvent::{Break, Continue, Error};
//     use crate::test_utils::mocks::{
//         CommandFactoryMock, CommandProcessorMock, TerminalActiveMock, TerminalPassiveMock,
//     };
//     use crossbeam_channel::bounded;
//     use masq_lib::test_utils::fake_stream_holder::{ByteArrayWriter, FakeStreamHolder};
//     use std::sync::{Arc, Mutex};
//     use std::thread;
//     use std::time::{Duration, Instant};
//
//     #[test]
//     fn interactive_mode_works_for_unrecognized_command() {
//         let make_params_arc = Arc::new(Mutex::new(vec![]));
//         let mut stream_holder = FakeStreamHolder::new();
//         let mut streams = stream_holder.streams();
//         let terminal_interface = make_terminal_interface();
//         let command_factory = CommandFactoryMock::new()
//             .make_params(&make_params_arc)
//             .make_result(Err(CommandFactoryError::UnrecognizedSubcommand(
//                 "Booga!".to_string(),
//             )));
//         let mut processor =
//             CommandProcessorMock::new().inject_terminal_interface(terminal_interface);
//
//         let result = go_interactive(&command_factory, &mut processor, &mut streams);
//
//         assert_eq!(result, true);
//         let make_params = make_params_arc.lock().unwrap();
//         assert_eq!(
//             *make_params,
//             vec![vec!["error".to_string(), "command".to_string()]]
//         );
//         assert_eq!(
//             stream_holder.stderr.get_string(),
//             "Unrecognized command: 'Booga!'\n".to_string()
//         )
//     }
//
//     fn make_terminal_interface() -> TerminalWrapper {
//         TerminalWrapper::new(Arc::new(
//             TerminalPassiveMock::new()
//                 .read_line_result(TerminalEvent::CommandLine(vec![
//                     "error".to_string(),
//                     "command".to_string(),
//                 ]))
//                 .read_line_result(TerminalEvent::CommandLine(vec!["exit".to_string()])),
//         ))
//     }
//
//     #[test]
//     fn interactive_mode_works_for_command_with_bad_syntax() {
//         let make_params_arc = Arc::new(Mutex::new(vec![]));
//         let mut stream_holder = FakeStreamHolder::new();
//         let mut streams = stream_holder.streams();
//         let terminal_interface = make_terminal_interface();
//         let command_factory = CommandFactoryMock::new()
//             .make_params(&make_params_arc)
//             .make_result(Err(CommandFactoryError::CommandSyntax(
//                 "Booga!".to_string(),
//             )));
//         let mut processor =
//             CommandProcessorMock::new().inject_terminal_interface(terminal_interface);
//
//         let result = go_interactive(&command_factory, &mut processor, &mut streams);
//
//         assert_eq!(result, true);
//         let make_params = make_params_arc.lock().unwrap();
//         assert_eq!(
//             *make_params,
//             vec![vec!["error".to_string(), "command".to_string()]]
//         );
//         assert_eq!(stream_holder.stderr.get_string(), "Booga!\n".to_string());
//     }
//
//     #[test]
//     fn handle_args_process_empty_args_short_circuit() {
//         let args = &[];
//         let mut stream_holder = FakeStreamHolder::new();
//         let mut streams = stream_holder.streams();
//
//         let result = handle_args(
//             args,
//             &mut streams,
//             &CommandFactoryMock::new(),
//             &mut CommandProcessorMock::default(),
//         );
//
//         assert_eq!(result, InteractiveEvent::Continue);
//         assert!(stream_holder.stdout.get_string().is_empty());
//         assert!(stream_holder.stderr.get_string().is_empty())
//     }
//
//     #[test]
//     fn continue_and_break_orders_work_for_interactive_mode() {
//         let mut stream_holder = FakeStreamHolder::new();
//         let mut streams = stream_holder.streams();
//         let terminal_interface = TerminalWrapper::new(Arc::new(
//             TerminalPassiveMock::new()
//                 .read_line_result(TerminalEvent::Continue)
//                 .read_line_result(TerminalEvent::Break),
//         ));
//         let command_factory = CommandFactoryMock::new();
//         let mut processor =
//             CommandProcessorMock::new().inject_terminal_interface(terminal_interface);
//
//         let result = go_interactive(&command_factory, &mut processor, &mut streams);
//
//         assert_eq!(result, true);
//         assert_eq!(stream_holder.stderr.get_string(), "".to_string());
//         assert_eq!(
//             stream_holder.stdout.get_string(),
//             "Received a signal interpretable as continue\n\nTerminated\n".to_string()
//         )
//     }
//
//     #[test]
//     fn pass_args_or_print_messages_announces_break_signal_from_line_reader() {
//         let mut stream_holder = FakeStreamHolder::new();
//         let interface = TerminalWrapper::new(Arc::new(TerminalPassiveMock::new()));
//
//         let result = pass_args_or_print_messages(&mut stream_holder.streams(), Break, &interface);
//
//         assert_eq!(result, Break);
//         assert_eq!(stream_holder.stderr.get_string(), "");
//         assert_eq!(stream_holder.stdout.get_string(), "\nTerminated\n");
//     }
//
//     #[test]
//     fn pass_args_or_print_messages_announces_continue_signal_from_line_reader() {
//         let mut stream_holder = FakeStreamHolder::new();
//         let interface = TerminalWrapper::new(Arc::new(TerminalPassiveMock::new()));
//
//         let result =
//             pass_args_or_print_messages(&mut stream_holder.streams(), Continue, &interface);
//
//         assert_eq!(result, Continue);
//         assert_eq!(stream_holder.stderr.get_string(), "");
//         assert_eq!(
//             stream_holder.stdout.get_string(),
//             "Received a signal interpretable as continue\n"
//         );
//     }
//
//     #[test]
//     fn pass_args_or_print_messages_announces_error_from_line_reader() {
//         let mut stream_holder = FakeStreamHolder::new();
//         let interface = TerminalWrapper::new(Arc::new(TerminalPassiveMock::new()));
//
//         let result = pass_args_or_print_messages(
//             &mut stream_holder.streams(),
//             Error(Some("Invalid Input\n".to_string())),
//             &interface,
//         );
//
//         assert_eq!(result, Error(None));
//         assert_eq!(stream_holder.stderr.get_string(), "Invalid Input\n\n");
//         assert_eq!(stream_holder.stdout.get_string(), "");
//     }
//
//     #[test]
//     fn handle_terminal_event_process_eof_correctly_as_break() {
//         let mut stream_holder = FakeStreamHolder::new();
//         let command_factory = CommandFactoryMock::default();
//         let mut command_processor = CommandProcessorMock::default()
//             .inject_terminal_interface(TerminalWrapper::new(Arc::new(TerminalPassiveMock::new())));
//         let readline_result = TerminalEvent::EoF;
//
//         let result = handle_terminal_event(
//             &mut stream_holder.streams(),
//             &command_factory,
//             &mut command_processor,
//             readline_result,
//         );
//
//         assert_eq!(result, InteractiveEvent::Break(true));
//         assert_eq!(stream_holder.stdout.get_string(), "\nTerminated\n\n")
//     }
//
//     //help and version commands are tested in integration tests with focus on a bigger context
//
//     #[test]
//     fn handle_help_or_version_provides_fine_lock_for_help_text() {
//         let terminal_interface = TerminalWrapper::new(Arc::new(TerminalActiveMock::new()));
//         let background_interface_clone = terminal_interface.clone();
//         let mut stdout = ByteArrayWriter::new();
//         let (tx, rx) = bounded(1);
//         let now = Instant::now();
//
//         let _ = handle_help_or_version("help", &mut stdout, &terminal_interface);
//
//         let time_period_when_unblocked = now.elapsed();
//         let handle = thread::spawn(move || {
//             let _lock = background_interface_clone.lock();
//             tx.send(()).unwrap();
//             thread::sleep((time_period_when_unblocked + Duration::from_millis(1)) * 15);
//         });
//         rx.recv().unwrap();
//         let now = Instant::now();
//
//         let _ = handle_help_or_version("help", &mut stdout, &terminal_interface);
//
//         let time_period_when_blocked = now.elapsed();
//         handle.join().unwrap();
//         assert!(
//             time_period_when_blocked > 3 * time_period_when_unblocked,
//             "{:?} is not longer than 3 * {:?}",
//             time_period_when_blocked,
//             time_period_when_unblocked
//         );
//     }
//
//     #[test]
//     fn pass_args_or_print_messages_work_under_fine_lock_for_continue() {
//         test_body_for_testing_the_classic_lock(TerminalEvent::Continue)
//     }
//
//     #[test]
//     fn pass_args_or_print_messages_work_under_fine_lock_for_eof() {
//         test_body_for_testing_the_classic_lock(TerminalEvent::EoF)
//     }
//
//     fn test_body_for_testing_the_classic_lock(tested_variant: TerminalEvent) {
//         let terminal_interface = TerminalWrapper::new(Arc::new(TerminalActiveMock::new()));
//         let background_interface_clone = terminal_interface.clone();
//         let mut stream_holder = FakeStreamHolder::new();
//         let mut streams = stream_holder.streams();
//         let (tx, rx) = bounded(1);
//         // Time pass_args_or_print_messages to see how long it takes with these parameters
//         // without a block
//         let now = Instant::now();
//
//         let _ =
//             pass_args_or_print_messages(&mut streams, tested_variant.clone(), &terminal_interface);
//
//         let time_period_when_unblocked = now.elapsed();
//         // Establish a block for 40 times that long
//         let handle = thread::spawn(move || {
//             let _lock = background_interface_clone.lock();
//             tx.send(()).unwrap();
//             // Add a millisecond just in case the trial above started in one millisecond and
//             // finished later in the same millisecond, meaning its length would evaluate to 0ms
//             thread::sleep((time_period_when_unblocked + Duration::from_millis(1)) * 40);
//         });
//         rx.recv().unwrap();
//         // Time pass_args_or_print_messages again when running against the block above
//         let now = Instant::now();
//
//         let _ = pass_args_or_print_messages(&mut streams, tested_variant, &terminal_interface);
//
//         let time_period_when_blocked = now.elapsed();
//         handle.join().unwrap();
//         // It should have taken significantly longer when waiting for the 40x block to end
//         assert!(
//             time_period_when_blocked > 2 * time_period_when_unblocked,
//             "{:?} is not longer than 2 * {:?}",
//             time_period_when_blocked,
//             time_period_when_unblocked
//         );
//     }
// }
