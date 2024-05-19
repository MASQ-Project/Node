// // Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
//
// use crate::terminal::secondary_infrastructure::{InterfaceWrapper, MasqTerminal, WriterLock};
// use linefeed::{ReadResult, Signal};
// use masq_lib::command::StdStreams;
// use masq_lib::constants::MASQ_PROMPT;
// use masq_lib::short_writeln;
// use std::error::Error;
// use std::fmt::Debug;
// use std::io::Write;
//
//most of the events depend on the default linefeed signal handlers which ignore them unless you explicitly set the opposite
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum TerminalEvent {
    CommandLine(Vec<String>),
    Error(Option<String>), //'None' when already processed by printing out
    Continue,              //as ignore
    Break,
    EoF,
}

// pub struct TerminalReal {
//     interface: Box<dyn InterfaceWrapper>,
// }
//
// impl MasqTerminal for TerminalReal {
//     fn read_line(&self) -> TerminalEvent {
//         match self.interface.read_line() {
//             Ok(ReadResult::Input(line)) => self.process_command_line(line),
//             Err(e) => Self::dispatch_error_msg(e),
//             Ok(ReadResult::Signal(Signal::Resize)) | Ok(ReadResult::Signal(Signal::Continue)) => {
//                 TerminalEvent::Continue
//             }
//             Ok(ReadResult::Eof) => TerminalEvent::EoF,
//             _ => TerminalEvent::Break,
//         }
//     }
//
//     fn lock(&self) -> Box<dyn WriterLock + '_> {
//         self.interface
//             .lock_writer_append()
//             .expect("lock writer append failed")
//     }
//
//     //used because we don't want to see the prompt show up again after this last-second printing operation;
//     //to assure a decent screen appearance while the whole app's going down
//     fn lock_without_prompt(
//         &self,
//         streams: &mut StdStreams,
//         stderr: bool,
//     ) -> Box<dyn WriterLock + '_> {
//         let kept_buffer = self.interface.get_buffer();
//         self.make_prompt_vanish();
//         let lock = self
//             .interface
//             .lock_writer_append()
//             .expect("lock writer append failed");
//         short_writeln!(
//             if !stderr {
//                 &mut streams.stdout
//             } else {
//                 &mut streams.stderr
//             },
//             "{}{}",
//             MASQ_PROMPT,
//             kept_buffer
//         );
//         lock
//     }
//
//     #[cfg(test)]
//     fn improvised_struct_id(&self) -> String {
//         format!(
//             "TerminalReal<{}>",
//             self.interface
//                 .lock_writer_append()
//                 .unwrap()
//                 .improvised_struct_id()
//         )
//     }
// }
//
// impl TerminalReal {
//     pub fn new(interface: Box<dyn InterfaceWrapper>) -> Self {
//         Self { interface }
//     }
//
//     fn process_command_line(&self, line: String) -> TerminalEvent {
//         self.add_history(line.clone());
//         let args = split_quoted_line(line);
//         TerminalEvent::CommandLine(args)
//     }
//
//     fn make_prompt_vanish(&self) {
//         self.interface
//             .set_prompt("")
//             .expect("unsetting the prompt failed");
//         self.interface
//             .set_buffer("")
//             .expect("clearing the buffer failed");
//     }
//
//     fn add_history(&self, line: String) {
//         self.interface.add_history(line)
//     }
//
//     fn dispatch_error_msg<E: Error>(error: E) -> TerminalEvent {
//         TerminalEvent::Error(Some(format!("Reading from the terminal: {}", error)))
//     }
// }
//
// fn split_quoted_line(input: String) -> Vec<String> {
//     let mut active_single = false;
//     let mut active_double = false;
//     let mut pieces: Vec<String> = vec![];
//     let mut current_piece = String::new();
//     input.chars().for_each(|c| {
//         if c.is_whitespace() && !active_double && !active_single {
//             if !current_piece.is_empty() {
//                 pieces.push(current_piece.clone());
//                 current_piece.clear();
//             }
//         } else if c == '"' && !active_single {
//             active_double = !active_double;
//         } else if c == '\'' && !active_double {
//             active_single = !active_single;
//         } else {
//             current_piece.push(c);
//         }
//     });
//     if !current_piece.is_empty() {
//         pieces.push(current_piece)
//     }
//     pieces
// }
//
// pub fn split_quoted_line_for_fake_terminals_in_tests(input: String) -> Vec<String> {
//     split_quoted_line(input)
// }
//
// #[cfg(test)]
// mod tests {
//     use super::*;
//     use crate::test_utils::mocks::{InterfaceRawMock, WriterInactive};
//     use masq_lib::test_utils::fake_stream_holder::FakeStreamHolder;
//     use std::io::ErrorKind;
//     use std::sync::{Arc, Mutex};
//
//     #[test]
//     fn read_line_works_when_signal_interrupted_is_hit() {
//         let subject = TerminalReal::new(Box::new(
//             InterfaceRawMock::new().read_line_result(Ok(ReadResult::Signal(Signal::Break))),
//         ));
//
//         let result = subject.read_line();
//
//         assert_eq!(result, TerminalEvent::Break);
//     }
//
//     #[test]
//     fn read_line_works_when_signal_break_is_hit() {
//         let subject = TerminalReal::new(Box::new(
//             InterfaceRawMock::new().read_line_result(Ok(ReadResult::Signal(Signal::Interrupt))),
//         ));
//
//         let result = subject.read_line();
//
//         assert_eq!(result, TerminalEvent::Break);
//     }
//
//     #[test]
//     fn read_line_works_when_a_valid_string_comes_from_the_command_line() {
//         let add_history_unique_params_arc = Arc::new(Mutex::new(vec![]));
//         let subject = TerminalReal::new(Box::new(
//             InterfaceRawMock::new()
//                 .read_line_result(Ok(ReadResult::Input("setup --ip 4.4.4.4".to_string())))
//                 .add_history_unique_params(&add_history_unique_params_arc),
//         ));
//
//         let result = subject.read_line();
//
//         assert_eq!(
//             result,
//             TerminalEvent::CommandLine(vec![
//                 "setup".to_string(),
//                 "--ip".to_string(),
//                 "4.4.4.4".to_string()
//             ])
//         );
//
//         let add_history_unique_params = add_history_unique_params_arc.lock().unwrap();
//         assert_eq!(
//             *add_history_unique_params[0],
//             "setup --ip 4.4.4.4".to_string()
//         )
//     }
//
//     #[test]
//     fn read_line_works_when_signal_quit_is_hit() {
//         let subject = TerminalReal::new(Box::new(
//             InterfaceRawMock::new().read_line_result(Ok(ReadResult::Signal(Signal::Quit))),
//         ));
//
//         let result = subject.read_line();
//
//         assert_eq!(result, TerminalEvent::Break)
//     }
//
//     #[test]
//     fn read_line_works_when_signal_suspend_is_hit() {
//         let subject = TerminalReal::new(Box::new(
//             InterfaceRawMock::new().read_line_result(Ok(ReadResult::Signal(Signal::Suspend))),
//         ));
//
//         let result = subject.read_line();
//
//         assert_eq!(result, TerminalEvent::Break)
//     }
//
//     #[test]
//     fn read_line_works_when_signal_continue_is_hit() {
//         let subject = TerminalReal::new(Box::new(
//             InterfaceRawMock::new().read_line_result(Ok(ReadResult::Signal(Signal::Continue))),
//         ));
//
//         let result = subject.read_line();
//
//         assert_eq!(result, TerminalEvent::Continue);
//     }
//
//     #[test]
//     fn read_line_works_when_signal_resize_is_hit() {
//         let subject = TerminalReal::new(Box::new(
//             InterfaceRawMock::new().read_line_result(Ok(ReadResult::Signal(Signal::Resize))),
//         ));
//
//         let result = subject.read_line();
//
//         assert_eq!(result, TerminalEvent::Continue);
//     }
//
//     #[test]
//     fn read_line_receives_an_error_and_sends_it_forward() {
//         let subject = TerminalReal::new(Box::new(
//             InterfaceRawMock::new()
//                 .read_line_result(Err(std::io::Error::from(ErrorKind::InvalidInput))),
//         ));
//
//         let result = subject.read_line();
//
//         assert_eq!(
//             result,
//             TerminalEvent::Error(Some(
//                 "Reading from the terminal: invalid input parameter".to_string()
//             ))
//         );
//     }
//
//     #[test]
//     fn read_line_responds_well_to_end_of_file() {
//         let subject = TerminalReal::new(Box::new(
//             InterfaceRawMock::new().read_line_result(Ok(ReadResult::Eof)),
//         ));
//
//         let result = subject.read_line();
//
//         assert_eq!(result, TerminalEvent::EoF);
//     }
//
//     #[test]
//     //unfortunately, I haven't been able to write a stronger test for this
//     fn lock_without_prompt_utilizes_inner_components_properly() {
//         let set_buffer_params_arc = Arc::new(Mutex::new(vec![]));
//         let set_prompt_params_arc = Arc::new(Mutex::new(vec![]));
//         let terminal = InterfaceRawMock::default()
//             .set_buffer_params(&set_buffer_params_arc)
//             .set_buffer_result(Ok(()))
//             .set_prompt_params(&set_prompt_params_arc)
//             .set_prompt_result(Ok(()))
//             .get_buffer_result("my once opened writing".to_string())
//             .lock_writer_append_result(Ok(Box::new(WriterInactive {})));
//         let subject = TerminalReal::new(Box::new(terminal));
//         let mut streams_holder = FakeStreamHolder::default();
//         let mut streams = streams_holder.streams();
//
//         let _ = subject.lock_without_prompt(&mut streams, false);
//
//         assert_eq!(
//             streams_holder.stdout.get_string(),
//             "masq> my once opened writing\n".to_string()
//         );
//         assert!(streams_holder.stderr.get_string().is_empty());
//         let set_buffer_params = set_buffer_params_arc.lock().unwrap();
//         assert_eq!(*set_buffer_params, vec!["".to_string()]);
//         let set_prompt_params = set_prompt_params_arc.lock().unwrap();
//         assert_eq!(*set_prompt_params, vec!["".to_string()])
//     }
//
//     #[test]
//     fn lock_without_prompt_writes_in_stderr_if_specified_so() {
//         let terminal = InterfaceRawMock::default()
//             .set_prompt_result(Ok(()))
//             .set_buffer_result(Ok(()))
//             .get_buffer_result("my once opened writing".to_string())
//             .lock_writer_append_result(Ok(Box::new(WriterInactive {})));
//         let subject = TerminalReal::new(Box::new(terminal));
//         let mut streams_holder = FakeStreamHolder::default();
//         let mut streams = streams_holder.streams();
//
//         let _ = subject.lock_without_prompt(&mut streams, true);
//
//         assert!(streams_holder.stdout.get_string().is_empty());
//         assert_eq!(
//             streams_holder.stderr.get_string(),
//             "masq> my once opened writing\n".to_string()
//         )
//     }
//
//     #[test]
//     fn accept_subcommand_handles_balanced_double_quotes() {
//         let command_line =
//             "  first \"second\" third  \"fourth'fifth\" \t sixth \"seventh eighth\tninth\" "
//                 .to_string();
//
//         let result = split_quoted_line(command_line);
//
//         assert_eq!(
//             result,
//             vec![
//                 "first".to_string(),
//                 "second".to_string(),
//                 "third".to_string(),
//                 "fourth'fifth".to_string(),
//                 "sixth".to_string(),
//                 "seventh eighth\tninth".to_string(),
//             ]
//         )
//     }
//
//     #[test]
//     fn accept_subcommand_handles_unbalanced_double_quotes() {
//         let command_line =
//             "  first \"second\" third  \"fourth'fifth\" \t sixth \"seventh eighth\tninth  "
//                 .to_string();
//
//         let result = split_quoted_line(command_line);
//
//         assert_eq!(
//             result,
//             vec![
//                 "first".to_string(),
//                 "second".to_string(),
//                 "third".to_string(),
//                 "fourth'fifth".to_string(),
//                 "sixth".to_string(),
//                 "seventh eighth\tninth  ".to_string(),
//             ]
//         )
//     }
//
//     #[test]
//     fn accept_subcommand_handles_balanced_single_quotes() {
//         let command_line =
//             "  first \n 'second' \n third \n 'fourth\"fifth' \t sixth 'seventh eighth\tninth' "
//                 .to_string();
//
//         let result = split_quoted_line(command_line);
//
//         assert_eq!(
//             result,
//             vec![
//                 "first".to_string(),
//                 "second".to_string(),
//                 "third".to_string(),
//                 "fourth\"fifth".to_string(),
//                 "sixth".to_string(),
//                 "seventh eighth\tninth".to_string(),
//             ]
//         )
//     }
//
//     #[test]
//     fn accept_subcommand_handles_unbalanced_single_quotes() {
//         let command_line =
//             "  first 'second' third  'fourth\"fifth' \t sixth 'seventh eighth\tninth  ".to_string();
//         let result = split_quoted_line(command_line);
//
//         assert_eq!(
//             result,
//             vec![
//                 "first".to_string(),
//                 "second".to_string(),
//                 "third".to_string(),
//                 "fourth\"fifth".to_string(),
//                 "sixth".to_string(),
//                 "seventh eighth\tninth  ".to_string(),
//             ]
//         )
//     }
// }
