// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::terminal_interface::{InterfaceRaw, Terminal, WriterGeneric};
use lazy_static::lazy_static;
use linefeed::{ReadResult, Signal};
use masq_lib::constants::MASQ_PROMPT;
use std::fmt::Debug;
use std::io::{stdin, stdout, Read, Write};
use std::sync::{Arc, Mutex, MutexGuard};

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

    #[cfg(test)]
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

////////////////////////////////////////////////////////////////////////////////////////////////////

//utils for integration tests run in the interactive mode

lazy_static! {
    static ref FAKE_STREAM: Mutex<String> = Mutex::new(String::new());
}

struct IntegrationTestTerminal {
    lock: Arc<Mutex<()>>,
}

impl Default for IntegrationTestTerminal {
    fn default() -> Self {
        IntegrationTestTerminal {
            lock: Arc::new(Mutex::new(())),
        }
    }
}

impl Terminal for IntegrationTestTerminal {
    fn provide_lock(&self) -> Box<dyn WriterGeneric + '_> {
        Box::new(IntegrationTestWriter {
            temporary_mutex_guard: self.lock.lock().expect("providing MutexGuard failed"),
        })
    }

    fn read_line(&self) -> TerminalEvent {
        let _lock = self
            .lock
            .lock()
            .expect("poisoned mutex in IntegrationTestTerminal");

        let test_input: Option<String> = if cfg!(test) {
            Some(String::from("Some command"))
        } else {
            None
        };

        let used_input = if test_input.is_some() {
            FAKE_STREAM
                .lock()
                .expect("poisoned mutex in IntegrationTestTerminal")
                .push_str("PROMPT>");
            test_input.unwrap()
        } else {
            let mut buffer = String::new();
            std::io::stdin().read_to_string(&mut buffer);
            writeln!(stdout(), "{}", MASQ_PROMPT).expect("writeln failed");
            buffer
        };

        TerminalEvent::CommandLine(used_input)
    }
}

struct IntegrationTestWriter<'a> {
    temporary_mutex_guard: MutexGuard<'a, ()>,
}

impl WriterGeneric for IntegrationTestWriter<'_> {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::terminal_interface::TerminalWrapper;
    use crate::test_utils::mocks::InterfaceRawMock;
    use std::io::ErrorKind;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::Duration;

    #[test]
    fn integration_test_terminal_provides_functional_synchronization() {
        let mut terminal = TerminalWrapper::new(Box::new(IntegrationTestTerminal::default()));
        let mut terminal_clone = terminal.clone();
        let (tx, rx) = std::sync::mpsc::channel();
        let handle = thread::spawn(move || {
            tx.send(()).unwrap();
            (0..3).for_each(|_| write_one_cycle(&mut terminal_clone));
        });
        rx.recv().unwrap();
        let quite_irrelevant = terminal.read_line();

        handle.join().unwrap();

        assert_eq!(
            quite_irrelevant,
            TerminalEvent::CommandLine(String::from("Some command"))
        );
        let written_in_a_whole = FAKE_STREAM.lock().unwrap().clone();
        assert!(!written_in_a_whole.starts_with("PRO"));
        assert!(!written_in_a_whole.ends_with("MPT>"));
        assert_eq!(written_in_a_whole.len(), 97); // 30*3 + 7
        let filtered_string = written_in_a_whole.replace("012345678910111213141516171819", ""); //this has length of 30 chars
        assert_eq!(filtered_string, "PROMPT>");
    }

    fn write_one_cycle(interface: &mut TerminalWrapper) {
        let _lock = interface.lock();
        (0..20).for_each(|num| {
            FAKE_STREAM
                .lock()
                .unwrap()
                .push_str(num.to_string().as_str());
            thread::sleep(Duration::from_millis(1))
        })
    }

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
}
