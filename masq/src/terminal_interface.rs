// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::line_reader::{TerminalReal, MASQ_PROMPT};
use linefeed::memory::MemoryTerminal;
use linefeed::{Interface, ReadResult, Writer};
use std::any::Any;
use std::borrow::BorrowMut;
use std::sync::{Arc, Mutex};

pub struct TerminalWrapper {
    inner: Arc<Box<dyn Terminal + Send + Sync>>,
}

impl TerminalWrapper {
    pub fn new(inner: Box<dyn Terminal + Send + Sync>) -> Self {
        Self {
            inner: Arc::new(inner),
        }
    }

    pub fn lock(&self) -> Box<dyn WriterGeneric + '_> {
        self.inner.provide_lock()
    }

    pub fn read_line(&self) -> std::io::Result<ReadResult> {
        self.inner.read_line()
    }

    pub fn add_history_unique(&self, line: String) {
        self.inner.add_history_unique(line)
    }

    #[cfg(test)]
    pub fn test_interface(&self) -> MemoryTerminal {
        let object = self.inner.clone().to_owned();
        object.test_interface()
    }

    #[cfg(test)]
    pub fn inner(&self) -> &Arc<Box<dyn Terminal + Send + Sync>> {
        &self.inner
    }
}

pub fn configure_interface<F, U, E>(
    interface_raw: Box<F>,
    terminal_type: Box<E>,
) -> Result<Box<TerminalReal>, String>
where
    F: FnOnce(&'static str, U) -> std::io::Result<Interface<U>>,
    E: FnOnce() -> std::io::Result<U>,
    U: linefeed::Terminal + 'static,
{
    let terminal: U = match terminal_type() {
        Ok(term) => term,
        Err(e) => return Err(format!("Terminal interface error: {}", e)),
    };
    let interface: Interface<U> = match interface_raw("masq", terminal) {
        Ok(interface) => interface,
        //untested
        Err(e) => return Err(format!("Getting terminal parameters: {}", e)),
    };

    //untested
    if let Err(e) = interface.set_prompt(MASQ_PROMPT) {
        return Err(format!("Setting prompt: {}", e));
    };
    //possibly other parameters to be configured such as "completer" (see linefeed library)

    Ok(Box::new(TerminalReal::new(interface)))
}

impl Clone for TerminalWrapper {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////

//TerminalReal is in line_reader.rs

pub trait Terminal {
    fn provide_lock(&self) -> Box<dyn WriterGeneric + '_>;
    fn read_line(&self) -> std::io::Result<ReadResult>; //change result to String
    fn add_history_unique(&self, line: String);
    #[cfg(test)]
    fn test_interface(&self) -> MemoryTerminal;
}

////////////////////////////////////////////////////////////////////////////////////////////////////

pub struct TerminalPassiveMock {
    read_line_result_line_or_eof: Arc<Mutex<Vec<std::io::Result<ReadResult>>>>,
}

impl Terminal for TerminalPassiveMock {
    fn provide_lock(&self) -> Box<dyn WriterGeneric> {
        unimplemented!()
    }

    fn read_line(&self) -> std::io::Result<ReadResult> {
        //return string
        self.read_line_result_line_or_eof.lock().unwrap().remove(0)
    }

    fn add_history_unique(&self, line: String) {
        unimplemented!()
    }
    #[cfg(test)]
    fn test_interface(&self) -> MemoryTerminal {
        unimplemented!()
    }
}

impl TerminalPassiveMock {
    pub fn new() -> Self {
        Self {
            read_line_result_line_or_eof: Arc::new(Mutex::new(vec![])),
        }
    }

    pub fn read_line_result(self, result: std::io::Result<ReadResult>) -> Self {
        self.read_line_result_line_or_eof
            .lock()
            .unwrap()
            .push(result);
        self
    }
}

pub struct TerminalActiveMock {
    in_memory_terminal: Interface<MemoryTerminal>,
    reference: MemoryTerminal,
    user_input: Arc<Mutex<Vec<String>>>,
}

impl Terminal for TerminalActiveMock {
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

    #[cfg(test)]
    fn test_interface(&self) -> MemoryTerminal {
        self.reference.clone()
    }
}

impl TerminalActiveMock {
    pub fn new() -> Self {
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
    #[allow(dead_code)] //TODO: think about this
    fn read_line_result(self, line: String) -> Self {
        self.user_input
            .lock()
            .unwrap()
            .borrow_mut()
            .push(format!("{}\n", line));
        self
    }
}

pub trait WriterGeneric {
    fn write_str(&mut self, str: &str) -> std::io::Result<()>;
}

impl<U: linefeed::Terminal> WriterGeneric for Writer<'_, '_, U> {
    fn write_str(&mut self, str: &str) -> std::io::Result<()> {
        self.write_str(&format!("{}\n*/-", str))
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////

pub trait InterfaceRaw {
    fn read_line(&self) -> std::io::Result<ReadResult>;
    fn add_history_unique(&self, line: String);
    fn lock_writer_append(&self) -> std::io::Result<Box<dyn WriterGeneric + '_>>;
    fn set_prompt(&self, prompt: &str) -> std::io::Result<()>;
    fn downcast(&self) -> &dyn Any;
}

impl<U: linefeed::Terminal + 'static> InterfaceRaw for Interface<U> {
    fn read_line(&self) -> std::io::Result<ReadResult> {
        self.read_line()
    }

    fn add_history_unique(&self, line: String) {
        self.add_history_unique(line);
    }

    fn lock_writer_append(&self) -> std::io::Result<Box<dyn WriterGeneric + '_>> {
        match self.lock_writer_append() {
            Ok(writer) => Ok(Box::new(writer)),
            Err(error) => unimplemented!("{}", error),
        }
    }

    fn set_prompt(&self, prompt: &str) -> std::io::Result<()> {
        self.set_prompt(prompt)
    }

    fn downcast(&self) -> &dyn Any {
        self
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::mocks::MixingStdout;
    use crossbeam_channel::unbounded;
    use linefeed::memory::Lines;
    use linefeed::DefaultTerminal;
    use std::io::Write;
    use std::sync::Barrier;
    use std::thread;
    use std::time::Duration;

    fn written_output_by_line_number(mut lines_from_memory: Lines, line_number: usize) -> String {
        //Lines isn't an iterator unfortunately
        if line_number < 1 || 24 < line_number {
            panic!("The number must be between 1 and 24")
        }
        for _ in 0..line_number - 1 {
            lines_from_memory.next();
        }
        one_line_collector(lines_from_memory.next().unwrap()).replace("*/-", "")
    }

    fn written_output_all_lines(mut lines_from_memory: Lines, separator: bool) -> String {
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

    #[test]
    fn terminal_mock_and_test_tools_write_and_read() {
        let mock = TerminalActiveMock::new()
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
            written_output_all_lines(terminal_reference.test_interface().lines(), true);
        assert_eq!(written_output, "first attempt | hello world | that's enough | Rocket, go to Mars, go, go | And once again...nothing |");

        let single_line =
            written_output_by_line_number(terminal_reference.test_interface().lines(), 1);
        assert_eq!(single_line, "first attempt");

        let single_line =
            written_output_by_line_number(terminal_reference.test_interface().lines(), 2);
        assert_eq!(single_line, "hello world")
    }

    #[test]
    //Here I use the system stdout handles, which is the standard way in the project, but thanks to the lock from TerminalWrapper,
    // it will be protected
    //The core of the test consists of two halves where the first shows unprotected writing in the second locks are actively called in both concurrent threads
    fn terminal_wrapper_s_lock_blocks_others_to_write_into_stdout() {
        let interface = TerminalWrapper::new(Box::new(TerminalActiveMock::new()));

        let barrier = Arc::new(Barrier::new(2));
        let mut handles = Vec::new();

        let (tx, rx) = unbounded();
        let mut stdout_c1 = MixingStdout::new(tx);
        let mut stdout_c2 = stdout_c1.clone();

        let closure1: Box<dyn FnMut(TerminalWrapper) + Sync + Send> =
            Box::new(move |interface: TerminalWrapper| {
                //here without a lock in the first half -- printing in BOTH is unprotected
                let mut stdout = &mut stdout_c1;
                write_in_cycles("AAA", &mut stdout);
                //printing whitespace, where the two halves part
                write!(&mut stdout, "   ").unwrap();
                let _lock = interface.lock();
                write_in_cycles("AAA", &mut stdout)
            });

        let closure2: Box<dyn FnMut(TerminalWrapper) + Sync + Send> =
            Box::new(move |interface: TerminalWrapper| {
                // lock from the very beginning of this thread...still it can have no effect
                let mut stdout = &mut stdout_c2;
                let _lock = interface.lock();
                write_in_cycles("BBB", &mut stdout);
                write!(&mut stdout, "   ").unwrap();
                write_in_cycles("BBB", &mut stdout)
            });

        vec![closure1, closure2].into_iter().for_each(
            |mut closure: Box<dyn FnMut(TerminalWrapper) + Sync + Send>| {
                let barrier_handle = Arc::clone(&barrier);
                let thread_interface = interface.clone();

                handles.push(thread::spawn(move || {
                    barrier_handle.wait();
                    closure(thread_interface)
                }));
            },
        );

        handles
            .into_iter()
            .for_each(|handle| handle.join().unwrap());

        let mut buffer = String::new();
        let given_output = loop {
            match rx.try_recv() {
                Ok(string) => buffer.push_str(&string),
                Err(_) => break buffer,
            }
        };

        assert!(
            !&given_output[0..180].contains(&"A".repeat(50)),
            "without synchronization: {}",
            given_output
        );
        assert!(
            !&given_output[0..180].contains(&"B".repeat(50)),
            "without synchronization: {}",
            given_output
        );

        assert!(
            //for some looseness not 90 but 80...sometimes a few letters from the 90 can be apart
            &given_output[185..].contains(&"A".repeat(80)),
            "synchronized: {}",
            given_output
        );
        assert!(
            //for some looseness not 90 but 80...sometimes a few letters from the 90 can be apart
            &given_output[185..].contains(&"B".repeat(80)),
            "synchronized: {}",
            given_output
        );
    }

    fn write_in_cycles(written_signal: &str, stdout: &mut dyn Write) {
        (0..30).for_each(|_| {
            write!(stdout, "{}", written_signal).unwrap();
            thread::sleep(Duration::from_millis(1))
        })
    }

    #[test]
    fn configure_interface_complains_that_there_is_no_real_terminal() {
        let subject = configure_interface(
            Box::new(Interface::with_term),
            Box::new(DefaultTerminal::new),
        );
        let result = match subject {
            Ok(_) => panic!("should have been an error, got OK"),
            Err(e) => e,
        };

        assert_eq!(
            result,
            "Terminal interface error: The handle is invalid. (os error 6)"
        )
    }

    #[test]
    fn configure_interface_allows_us_starting_in_memory_terminal() {
        let term_mock = MemoryTerminal::new();
        let term_mock_clone = term_mock.clone();
        let terminal_type = move || -> std::io::Result<MemoryTerminal> { Ok(term_mock_clone) };
        let subject = configure_interface(Box::new(Interface::with_term), Box::new(terminal_type));
        let result = match subject {
            Err(e) => panic!("should have been OK, got Err: {}", e),
            Ok(val) => val,
        };

        let wrapper = TerminalWrapper::new(Box::new(*result));
        wrapper.lock().write_str("hallelujah").unwrap();

        let written = written_output_all_lines(term_mock.lines(), false);

        assert_eq!(written, "hallelujah");
    }
}
