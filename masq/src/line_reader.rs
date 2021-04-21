// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::terminal_interface::{InterfaceRaw, MasqTerminal, WriterLock};
use linefeed::{ReadResult, Signal};
use masq_lib::constants::MASQ_PROMPT;
use masq_lib::short_writeln;
use std::fmt::Debug;
use std::io::{stdin, stdout, Read, Write};
use std::sync::{Arc, Mutex, MutexGuard};

#[derive(Debug, PartialEq)]
pub enum TerminalEvent {
    CommandLine(Vec<String>),
    Error(String),
    Continue, //as ignore
    Break,
}

pub struct TerminalReal {
    pub interface: Box<dyn InterfaceRaw + Send + Sync>,
}

impl TerminalReal {
    pub fn new(interface: Box<dyn InterfaceRaw + Send + Sync>) -> Self {
        Self { interface }
    }
}

impl MasqTerminal for TerminalReal {
    fn provide_lock(&self) -> Box<dyn WriterLock + '_> {
        self.interface
            .lock_writer_append()
            .expect("lock writer append failed")
    }

    fn read_line(&self) -> TerminalEvent {
        match self.interface.read_line() {
            Ok(ReadResult::Input(line)) => {
                add_history_unique(self, line.clone());
                let args = split_quoted_line(line);
                TerminalEvent::CommandLine(args)
            }
            Err(e) => TerminalEvent::Error(format!("Reading from the terminal: {}", e)),
            Ok(ReadResult::Signal(Signal::Resize)) | Ok(ReadResult::Signal(Signal::Continue)) => {
                TerminalEvent::Continue
            }
            _ => TerminalEvent::Break,
        }
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

fn add_history_unique(terminal: &TerminalReal, line: String) {
    terminal.interface.add_history_unique(line)
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

////////////////////////////////////////////////////////////////////////////////////////////////////

//utils for integration tests run in the interactive mode

pub struct IntegrationTestTerminal {
    lock: Arc<Mutex<()>>,
    stdin: Arc<Mutex<Box<dyn Read + Send + 'static>>>,
    stdout: Arc<Mutex<Box<dyn Write + Send + 'static>>>,
}

impl Default for IntegrationTestTerminal {
    fn default() -> Self {
        IntegrationTestTerminal {
            lock: Arc::new(Mutex::new(())),
            stdin: Arc::new(Mutex::new(Box::new(stdin()))),
            stdout: Arc::new(Mutex::new(Box::new(stdout()))),
        }
    }
}

impl MasqTerminal for IntegrationTestTerminal {
    fn provide_lock(&self) -> Box<dyn WriterLock + '_> {
        Box::new(IntegrationTestWriter {
            temporary_mutex_guard: self.lock.lock().expect("providing MutexGuard failed"),
        })
    }

    fn read_line(&self) -> TerminalEvent {
        let mut buffer = [0; 1024];
        let number_of_bytes = self
            .stdin
            .lock()
            .expect("poisoned mutex")
            .read(&mut buffer)
            .expect("reading failed");
        let _lock = self
            .lock
            .lock()
            .expect("poisoned mutex in IntegrationTestTerminal: lock");
        short_writeln!(
            self.stdout
                .lock()
                .expect("poisoned mutex in IntegrationTestTerminal: stdout"),
            "{}",
            MASQ_PROMPT
        );
        drop(_lock);
        let finalized_command_line = std::str::from_utf8(&buffer[0..number_of_bytes])
            .expect("conversion into str failed")
            .to_string();
        TerminalEvent::CommandLine(split_quoted_line(finalized_command_line))
    }
}

struct IntegrationTestWriter<'a> {
    #[allow(dead_code)]
    temporary_mutex_guard: MutexGuard<'a, ()>,
}

impl WriterLock for IntegrationTestWriter<'_> {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::terminal_interface::TerminalWrapper;
    use crate::test_utils::mocks::{InterfaceRawMock, StdoutBlender};
    use crossbeam_channel::unbounded;
    use masq_lib::test_utils::fake_stream_holder::ByteArrayReader;
    use std::io::ErrorKind;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::Duration;

    #[test]
    fn integration_test_terminal_provides_functional_synchronization() {
        let (tx_cb, rx_cb) = unbounded();
        let mut terminal_interface = IntegrationTestTerminal::default();
        terminal_interface.stdin =
            Arc::new(Mutex::new(Box::new(ByteArrayReader::new(b"Some command"))));
        terminal_interface.stdout =
            Arc::new(Mutex::new(Box::new(StdoutBlender::new(tx_cb.clone()))));
        let terminal = TerminalWrapper::new(Box::new(terminal_interface));
        let mut terminal_clone = terminal.clone();
        let (tx, rx) = std::sync::mpsc::channel();
        let handle = thread::spawn(move || {
            let mut background_thread_stdout = StdoutBlender::new(tx_cb);
            tx.send(()).unwrap();
            (0..3).for_each(|_| {
                write_one_cycle(&mut background_thread_stdout, &mut terminal_clone);
                thread::sleep(Duration::from_millis(1))
            })
        });
        rx.recv().unwrap();
        thread::sleep(Duration::from_millis(5));
        let quite_irrelevant = terminal.read_line();

        handle.join().unwrap();

        assert_eq!(
            quite_irrelevant,
            TerminalEvent::CommandLine(vec!["Some".to_string(), ("command").to_string()])
        );
        let mut written_in_a_whole = String::new();
        loop {
            match rx_cb.try_recv() {
                Ok(string) => written_in_a_whole.push_str(&string),
                Err(_) => break,
            }
        }
        assert!(!written_in_a_whole.starts_with("mas"));
        assert!(!written_in_a_whole.ends_with("asq> \n"));
        assert_eq!(written_in_a_whole.len(), 97);
        let filtered_string = written_in_a_whole.replace("012345678910111213141516171819", "");
        assert_eq!(filtered_string, "masq> \n");
    }

    fn write_one_cycle(stdout: &mut StdoutBlender, interface: &mut TerminalWrapper) {
        let _lock = interface.lock();
        (0..20).for_each(|num: u8| {
            stdout.write(num.to_string().as_bytes()).unwrap();
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
            TerminalEvent::Error("Reading from the terminal: invalid input parameter".to_string())
        );
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
