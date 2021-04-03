// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::terminal_interface::{InterfaceRaw, Terminal, WriterGeneric};
use linefeed::{ReadResult, Signal};
use std::fmt::Debug;

#[derive(Debug, PartialEq)]
pub enum TerminalEvent {
    CommandLine(String),
    Error(String),
    Continue, //as ignore
    Break,
}

pub struct TerminalReal {
    pub interface: Box<dyn InterfaceRaw + Send + Sync>,
}

impl Terminal for TerminalReal {
    fn provide_lock(&self) -> Box<dyn WriterGeneric + '_> {
        self.interface
            .lock_writer_append()
            .expect("lock writer append failed")
    }

    fn read_line(&self) -> TerminalEvent {
        match self.interface.read_line() {
            //TODO redirect this to inner_active
            Ok(ReadResult::Input(line)) => {
                self.add_history_unique(line.clone());
                TerminalEvent::CommandLine(line)
            }
            Err(e) => TerminalEvent::Error(format!("Reading from the terminal: {}", e)),
            Ok(ReadResult::Signal(Signal::Resize)) | Ok(ReadResult::Signal(Signal::Continue)) => {
                TerminalEvent::Continue
            }
            _ => TerminalEvent::Break,
        }
    }

    fn add_history_unique(&self, line: String) {
        self.interface.add_history_unique(line)
    }

    fn tell_me_who_you_are(&self) -> String {
        format!(
            "TerminalReal<{}>",
            self.interface
                .lock_writer_append()
                .unwrap()
                .tell_me_who_you_are()
        )
    }
}

impl TerminalReal {
    pub fn new(interface: Box<dyn InterfaceRaw + Send + Sync>) -> Self {
        Self { interface }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::mocks::InterfaceRawMock;
    use std::io::ErrorKind;
    use std::sync::{Arc, Mutex};

    #[test]
    fn read_line_works_when_eof_is_hit() {
        let subject = TerminalReal::new(Box::new(
            InterfaceRawMock::new().read_line_result(Ok(ReadResult::Eof)),
        ));

        let result = subject.read_line();

        assert_eq!(result, TerminalEvent::Break);
    }

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
    fn read_line_works_when_a_valid_string_line_comes_from_the_terminal() {
        let add_history_unique_params_arc = Arc::new(Mutex::new(vec![]));
        let subject = TerminalReal::new(Box::new(
            InterfaceRawMock::new()
                .read_line_result(Ok(ReadResult::Input("setup --ip 4.4.4.4".to_string())))
                .add_history_unique_params(add_history_unique_params_arc.clone()),
        ));

        let result = subject.read_line();

        assert_eq!(
            result,
            TerminalEvent::CommandLine("setup --ip 4.4.4.4".to_string())
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
            TerminalEvent::Error("Reading from the terminal: invalid input parameter".to_string())
        );
    }

    //     #[test]
    //     fn read_line_synchronization_works() {
    //         let synchronizer_arc = Arc::new(Mutex::new(()));
    //         let synchronizer_arc_clone = synchronizer_arc.clone();
    //
    //         let (tx, rx) = unbounded();
    //
    //         let thread_handle = thread::spawn(move || {
    //             let mut subject = LineReader::new(synchronizer_arc_clone);
    //             let buffer_arc = Box::new(MixingStdout::new(tx));
    //             let editor =
    //                 EditorMock::new().stdout_result(Rc::new(RefCell::new(Box::new(buffer_arc))));
    //             subject.delegate = Box::new(editor);
    //             subject.print_prompt_synchronized();
    //         });
    //         let printed_string = rx.recv().unwrap();
    //
    //         thread_handle.join().unwrap();
    //
    //         assert_eq!(printed_string, "masq> ".to_string())
    //     }
}
