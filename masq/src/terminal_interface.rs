// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use linefeed::{DefaultTerminal, Writer, ReadResult, Interface};
use std::sync::{Arc, Mutex};
use linefeed::memory::{MemoryTerminal, Lines};
use std::borrow::BorrowMut;



trait WriterGeneric {
    fn write_str(&mut self, str: &str) -> std::io::Result<()>;
}

impl WriterGeneric for Writer<'_, '_, DefaultTerminal> {
    fn write_str(&mut self, str: &str) -> std::io::Result<()> {
        self.write_str(str)
    }
}

impl WriterGeneric for Writer<'_, '_, MemoryTerminal> {
    fn write_str(&mut self, str: &str) -> std::io::Result<()> {
        self.write_str(&format!("{}\n*/-", str))
    }
}

///////////////////////////////////////////////////////////////////////////////////////////////////

impl Clone for TerminalWrapper {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

pub struct TerminalWrapper {
    inner: Arc<Box<dyn Terminal + Send + Sync>>,
}

impl TerminalWrapper {
    fn new(inner: Box<dyn Terminal + Send + Sync>) -> Self {
        Self {
            inner: Arc::new(inner),
        }
    }

    fn lock(&self) -> Box<dyn WriterGeneric + '_> {
        self.inner.provide_lock()
    }

    fn read_line(&self) -> std::io::Result<ReadResult> {
        self.inner.read_line()
    }
    fn add_history_unique(&self, line: String) {
        self.inner.add_history_unique(line)
    }

    #[cfg(test)]
    fn test_interface(&self) -> MemoryTerminal {
        let object = self.inner.clone().to_owned();
        object.test_interface()
    }
}

//////////////////////////////////////////////////////////////////////////////////////////////////

trait Terminal {
    fn provide_lock(&self) -> Box<dyn WriterGeneric + '_>;
    fn read_line(&self) -> std::io::Result<ReadResult>;
    fn add_history_unique(&self, line: String);
    fn test_interface(&self) -> MemoryTerminal;
}

struct TerminalReal {
    interface: Interface<DefaultTerminal>,
}

impl Terminal for TerminalReal {
    fn provide_lock(&self) -> Box<dyn WriterGeneric + '_> {
        Box::new(
            self.interface
                .lock_writer_append()
                .expect("lock writer append failed"),
        )
    }

    fn read_line(&self) -> std::io::Result<ReadResult> {
        self.interface.read_line()
    }

    fn add_history_unique(&self, line: String) {
        self.interface.add_history_unique(line)
    }

    fn test_interface(&self) -> MemoryTerminal {
        panic!("this should never be called")
    }
}

impl TerminalReal {
    fn new(interface: Interface<DefaultTerminal>) -> Self {
        Self { interface }
    }
}

///////////////////////////////////////////////////////////////////////////////////////////////////

struct TerminalMock {
    in_memory_terminal: Interface<MemoryTerminal>,
    reference: MemoryTerminal,
    user_input: Arc<Mutex<Vec<String>>>,
}

impl Terminal for TerminalMock {
    fn provide_lock(&self) -> Box<dyn WriterGeneric + '_> {
        Box::new(self.in_memory_terminal.lock_writer_append().unwrap())
    }

    fn read_line(&self) -> std::io::Result<ReadResult> {
        let line = self.user_input.lock().unwrap().borrow_mut().remove(0);
        self.reference.write(&format!("{}*/-", line));
        Ok(ReadResult::Input(line))
    }

    fn add_history_unique(&self, line: String) {
        self.in_memory_terminal.add_history_unique(line)
    }

    fn test_interface(&self) -> MemoryTerminal {
        self.reference.clone()
    }
}

impl TerminalMock {
    fn new() -> Self {
        let memory_terminal_instance = MemoryTerminal::new();
        Self {
            in_memory_terminal: Interface::with_term(
                "test only terminal",
                memory_terminal_instance.clone(),
            )
                .unwrap(),
            reference: memory_terminal_instance,
            user_input: Arc::new(Mutex::new(vec![])),
        }
    }
    fn read_line_result(self, line: String) -> Self {
        self.user_input
            .lock()
            .unwrap()
            .borrow_mut()
            .push(format!("{}\n", line));
        self
    }
}

fn written_input_by_line_number(mut lines_from_memory: Lines, line_number: usize) -> String {
    //Lines aren't an iterator unfortunately
    if line_number < 1 || 24 < line_number {
        panic!("The number must be between 1 and 24")
    }
    for _ in 0..line_number - 1 {
        lines_from_memory.next();
    }
    one_line_collector(lines_from_memory.next().unwrap()).replace("*/-", "")
}

fn written_input_all_lines(mut lines_from_memory: Lines, separator: bool) -> String {
    (0..24)
        .flat_map(|_| {
            lines_from_memory
                .next()
                .map(|chars| one_line_collector(chars))
        })
        .collect::<String>()
        .replace("*/-", if separator { " | " } else { " " })
        .trim_end()
        .to_string()
}

fn one_line_collector(line_chars: &[char]) -> String {
    let string_raw = line_chars
        .iter()
        .map(|char| char)
        .collect::<String>()
        .split(' ')
        .map(|word| {
            if word != "" {
                format!("{} ", word)
            } else {
                "".to_string()
            }
        })
        .collect::<String>();
    (0..1)
        .map(|_| string_raw.strip_suffix("*/- ").unwrap_or(&string_raw))
        .map(|str| str.strip_suffix(" ").unwrap_or(&string_raw).to_string())
        .collect::<String>()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use crate::test_utils::mocks::MixingStdout;
    use crossbeam_channel::unbounded;
    use std::sync::mpsc::channel;
    use std::time::Duration;

    #[test]
    fn terminal_mock_and_test_tools_write_and_read() {
        let mock = TerminalMock::new()
            .read_line_result("Rocket, go to Mars, go, go".to_string())
            .read_line_result("And once again...nothing".to_string());

        let terminal = TerminalWrapper::new(Box::new(mock));
        let terminal_clone = terminal.clone();
        let terminal_reference = terminal.clone();

        terminal.lock().write_str("first attempt").unwrap();

        let handle = thread::spawn(move || {
            terminal_clone.lock().write_str("hello world").unwrap();
            terminal_clone.lock().write_str("that's enough").unwrap()
        });

        handle.join().unwrap();

        terminal.read_line().unwrap();

        terminal.read_line().unwrap();

        let lines_remaining = terminal_reference
            .test_interface()
            .lines()
            .lines_remaining();
        assert_eq!(lines_remaining, 24);

        let written_output =
            written_input_all_lines(terminal_reference.test_interface().lines(), true);
        assert_eq!(written_output, "first attempt | hello world | that's enough | Rocket, go to Mars, go, go | And once again...nothing |");

        let single_line =
            written_input_by_line_number(terminal_reference.test_interface().lines(), 1);
        assert_eq!(single_line, "first attempt");

        let single_line =
            written_input_by_line_number(terminal_reference.test_interface().lines(), 2);
        assert_eq!(single_line, "hello world")
    }

    #[test]
    fn terminal_wrapper_s_lock_blocks_others_to_write() {
        // let interface = TerminalWrapper::new(Box::new(TerminalMock::new()));
        // let interface_clone = interface.clone();
        //
        // let (sync_tx, sync_rx) = channel();
        //
        // let handle = thread::spawn(move || {
        //     sync_tx.send(()).unwrap();
        //     thread::park_timeout(Duration::from_millis(200));
        //     sync_tx.send(()).unwrap()
        // });
        //
        // sync_rx.recv().unwrap();
        // (0..1000).for_each()
        //
        // handle.join().unwrap();
    }


    #[test]
    fn test_of_locking_with_multiple_threads() {
        //
        // let (tx,rx) = unbounded();
        //
        // let shared_stdout =   MixingStdout::new(tx);
        //
        // let thread_one = thread::spawn(move||{
        // });
        //
        // let thread_two;
        //
        // //barrier
    }
}
