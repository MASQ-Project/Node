// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::terminal::secondary_infrastructure::{InterfaceWrapper, MasqTerminal, WriterLock};
use linefeed::{ReadResult, Signal};
use masq_lib::constants::MASQ_PROMPT;
use masq_lib::short_writeln;
use std::fmt::Debug;
use std::io::{stdout, Write};

//most of these events depends on the default signal handler which ignores them so that these are never signaled
#[derive(Debug, PartialEq)]
pub enum TerminalEvent {
    CommandLine(Vec<String>),
    Error(Option<String>), //'None' when already consumed by printing out
    Continue,              //as ignore
    Break,
    EoF,
}

pub struct TerminalReal {
    interface: Box<dyn InterfaceWrapper>,
}

impl TerminalReal {
    pub fn new(interface: Box<dyn InterfaceWrapper>) -> Self {
        Self { interface }
    }

    fn process_captured_command_line(&self, line: String) -> TerminalEvent {
        self.add_history(line.clone());
        let args = split_quoted_line(line);
        TerminalEvent::CommandLine(args)
    }

    fn add_history(&self, line: String) {
        self.interface.add_history(line)
    }
}

impl MasqTerminal for TerminalReal {
    fn read_line(&self) -> TerminalEvent {
        match self.interface.read_line() {
            Ok(ReadResult::Input(line)) => self.process_captured_command_line(line),
            Err(e) => TerminalEvent::Error(Some(format!("Reading from the terminal: {}", e))),
            Ok(ReadResult::Signal(Signal::Resize)) | Ok(ReadResult::Signal(Signal::Continue)) => {
                TerminalEvent::Continue
            }
            Ok(ReadResult::Eof) => TerminalEvent::EoF,
            _ => TerminalEvent::Break,
        }
    }

    fn lock(&self) -> Box<dyn WriterLock + '_> {
        self.interface.lock_writer_append().expect("l_w_a failed")
    }

    //used because we don't want to see the prompt show up after this last-second printing operation;
    //to assure a decent screen appearance while the whole app's going down
    fn lock_ultimately(&self) -> Box<dyn WriterLock + '_> {
        //TODO test drive this out
        let kept_buffer = self.interface.get_buffer();
        self.interface
            .set_prompt("")
            .expect("unsetting the prompt failed");
        self.interface.clear_buffer();
        let lock = self.interface.lock_writer_append().expect("l_w_a failed");
        short_writeln!(stdout(), "{}", format!("{}{}", MASQ_PROMPT, kept_buffer));
        lock
    }

    #[cfg(test)]
    fn struct_id(&self) -> String {
        format!(
            "TerminalReal<{}>",
            self.interface.lock_writer_append().unwrap().struct_id()
        )
    }
}

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

pub fn split_quoted_line_for_integration_tests(input: String) -> Vec<String> {
    split_quoted_line(input)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::mocks::InterfaceRawMock;
    use std::io::ErrorKind;
    use std::sync::{Arc, Mutex};

    #[test]
    fn read_line_works_when_signal_interrupted_is_hit() {
        let subject = TerminalReal::new(Box::new(
            InterfaceRawMock::new().read_line_result(Ok(ReadResult::Signal(Signal::Break))),
        ));

        let result = subject.read_line();

        assert_eq!(result, TerminalEvent::Break);
    }

    #[test]
    fn read_line_works_when_signal_break_is_hit() {
        let subject = TerminalReal::new(Box::new(
            InterfaceRawMock::new().read_line_result(Ok(ReadResult::Signal(Signal::Interrupt))),
        ));

        let result = subject.read_line();

        assert_eq!(result, TerminalEvent::Break);
    }

    #[test]
    fn read_line_works_when_a_valid_string_comes_from_the_command_line() {
        let add_history_unique_params_arc = Arc::new(Mutex::new(vec![]));
        let subject = TerminalReal::new(Box::new(
            InterfaceRawMock::new()
                .read_line_result(Ok(ReadResult::Input("setup --ip 4.4.4.4".to_string())))
                .add_history_unique_params(&add_history_unique_params_arc),
        ));

        let result = subject.read_line();

        assert_eq!(
            result,
            TerminalEvent::CommandLine(vec![
                "setup".to_string(),
                "--ip".to_string(),
                "4.4.4.4".to_string()
            ])
        );

        let add_history_unique_params = add_history_unique_params_arc.lock().unwrap();
        assert_eq!(
            *add_history_unique_params[0],
            "setup --ip 4.4.4.4".to_string()
        )
    }

    #[test]
    fn read_line_works_when_signal_quit_is_hit() {
        let subject = TerminalReal::new(Box::new(
            InterfaceRawMock::new().read_line_result(Ok(ReadResult::Signal(Signal::Quit))),
        ));

        let result = subject.read_line();

        assert_eq!(result, TerminalEvent::Break)
    }

    #[test]
    fn read_line_works_when_signal_suspend_is_hit() {
        let subject = TerminalReal::new(Box::new(
            InterfaceRawMock::new().read_line_result(Ok(ReadResult::Signal(Signal::Suspend))),
        ));

        let result = subject.read_line();

        assert_eq!(result, TerminalEvent::Break)
    }

    #[test]
    fn read_line_works_when_signal_continue_is_hit() {
        let subject = TerminalReal::new(Box::new(
            InterfaceRawMock::new().read_line_result(Ok(ReadResult::Signal(Signal::Continue))),
        ));

        let result = subject.read_line();

        assert_eq!(result, TerminalEvent::Continue);
    }

    #[test]
    fn read_line_works_when_signal_resize_is_hit() {
        let subject = TerminalReal::new(Box::new(
            InterfaceRawMock::new().read_line_result(Ok(ReadResult::Signal(Signal::Resize))),
        ));

        let result = subject.read_line();

        assert_eq!(result, TerminalEvent::Continue);
    }

    #[test]
    fn read_line_receives_an_error_and_sends_it_forward() {
        let subject = TerminalReal::new(Box::new(
            InterfaceRawMock::new()
                .read_line_result(Err(std::io::Error::from(ErrorKind::InvalidInput))),
        ));

        let result = subject.read_line();

        assert_eq!(
            result,
            TerminalEvent::Error(Some(
                "Reading from the terminal: invalid input parameter".to_string()
            ))
        );
    }

    #[test]
    fn read_line_responds_well_to_end_of_file() {
        let subject = TerminalReal::new(Box::new(
            InterfaceRawMock::new().read_line_result(Ok(ReadResult::Eof)),
        ));

        let result = subject.read_line();

        assert_eq!(result, TerminalEvent::EoF);
    }

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
}
