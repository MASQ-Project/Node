// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::terminal::line_reader::{split_quoted_line_for_fake_terminals_in_tests, TerminalEvent};
use crate::terminal::secondary_infrastructure::{MasqTerminal, WriterLock};
use crossbeam_channel::{bounded, Sender, TryRecvError};
use ctrlc;
use masq_lib::command::StdStreams;
use masq_lib::constants::MASQ_PROMPT;
use masq_lib::short_writeln;
use masq_lib::utils::ExpectValue;
use std::io::{stderr, stdin, stdout, Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread;
use std::thread::sleep;
use std::time::Duration;

pub const MASQ_TEST_INTEGRATION_KEY: &str = "MASQ_TEST_INTEGRATION";
pub const MASQ_TEST_INTEGRATION_VALUE: &str =
    "3aad217a9b9fa6d41487aef22bf678b1aee3282d884eeb74b2eac7b8a3be8xzt";

#[derive(Clone)]
pub struct IntegrationTestTerminal {
    lock: Arc<Mutex<()>>,

    console: Arc<Mutex<IntegrationTestTerminalConsole>>,

    write_handles: Arc<Mutex<WriterStreamHandles>>,

    ctrl_c_flag: Arc<AtomicBool>,
}

struct IntegrationTestTerminalConsole {
    lock: Arc<Mutex<()>>,
    stdin: Box<dyn Read + Send>,
    stdout: Box<dyn Write + Send>,
}

struct WriterStreamHandles {
    stderr: Box<dyn Write + Send>,
    stdout: Box<dyn Write + Send>,
}

impl Default for IntegrationTestTerminal {
    fn default() -> Self {
        let running = Arc::new(AtomicBool::new(true));
        let r = Arc::clone(&running);
        ctrlc::set_handler(move || {
            r.store(false, Ordering::SeqCst);
        })
        .expect("Error when setting Ctrl-C handler");

        let main_sync_lock = Arc::new(Mutex::new(()));

        IntegrationTestTerminal {
            console: Arc::new(Mutex::new(IntegrationTestTerminalConsole {
                lock: main_sync_lock.clone(),
                stdin: Box::new(stdin()),
                stdout: Box::new(stdout()),
            })),
            lock: main_sync_lock,
            write_handles: Arc::new(Mutex::new(WriterStreamHandles {
                stdout: Box::new(stdout()),
                stderr: Box::new(stderr()),
            })),
            ctrl_c_flag: running,
        }
    }
}

impl IntegrationTestTerminalConsole {
    fn input_reader(&mut self, result_sender: Sender<TerminalEvent>) {
        self.write_with_sync(MASQ_PROMPT);
        //the lock must not surround the read point
        let captured_command_line = self.read_input();
        //because of specific arrangement based on the combination of linefeed + Clap
        if captured_command_line.trim() == "version" || captured_command_line.trim() == "help" {
            self.write_with_sync("\n");
        }
        let _ = result_sender.send(TerminalEvent::CommandLine(
            split_quoted_line_for_fake_terminals_in_tests(captured_command_line),
        ));
    }

    fn write_with_sync(&mut self, text: &str) {
        let _lock = self
            .lock
            .lock()
            .expect("poisoned mutex IntegrationTestTerminalConsole: lock");
        write!(self.stdout, "{}", text).unwrap()
    }

    fn read_input(&mut self) -> String {
        let mut buffer = [0; 1024];
        let number_of_bytes = self.stdin.read(&mut buffer).expect("reading failed");
        std::str::from_utf8(&buffer[..number_of_bytes])
            .expectv("converted str")
            .to_string()
    }
}

impl MasqTerminal for IntegrationTestTerminal {
    //combines two activities of the real Linefeed, handles user's input and Ctrl+C signal
    fn read_line(&self) -> TerminalEvent {
        //mocked linefeed
        let (tx_terminal, rx_terminal) = bounded(1);
        let inner = self.console.clone();
        thread::spawn(move || {
            inner
                .lock()
                .expect("IntegrationTestTerminal: inner poisoned")
                .input_reader(tx_terminal)
        });
        loop {
            if !self.ctrl_c_flag.load(Ordering::SeqCst) {
                return TerminalEvent::Break;
            }
            match rx_terminal.try_recv() {
                Ok(terminal_event) => break terminal_event,
                Err(e) if e == TryRecvError::Disconnected => {
                    panic!("test failed: background thread with the input reader died")
                }
                _ => sleep(Duration::from_millis(10)),
            }
        }
    }

    fn lock(&self) -> Box<dyn WriterLock + '_> {
        Box::new(IntegrationTestWriter {
            mutex_guard_that_simulates_the_core_locking: self.lock.lock().expectv("MutexGuard"),
            ultimate_drop_behavior: false,
            stderr: false,
        })
    }

    fn lock_without_prompt(
        &self,
        _streams: &mut StdStreams,
        stderr: bool,
    ) -> Box<dyn WriterLock + '_> {
        let lock = Box::new(IntegrationTestWriter {
            mutex_guard_that_simulates_the_core_locking: self.lock.lock().expectv("MutexGuard"),
            ultimate_drop_behavior: true,
            stderr,
        });
        let mut writers = self.write_handles.lock().expect("write handles poisoned");
        let handle = if !stderr {
            &mut writers.stdout
        } else {
            &mut writers.stderr
        };
        short_writeln!(handle, "***user's command line here***");
        lock
    }
}

struct IntegrationTestWriter<'a> {
    #[allow(dead_code)]
    mutex_guard_that_simulates_the_core_locking: MutexGuard<'a, ()>,
    ultimate_drop_behavior: bool,
    stderr: bool,
}

impl IntegrationTestWriter<'_> {
    fn provide_correct_handle(std_err: bool) -> Box<dyn Write> {
        if std_err {
            Box::new(stderr())
        } else {
            Box::new(stdout())
        }
    }
}

impl WriterLock for IntegrationTestWriter<'_> {}

impl Drop for IntegrationTestWriter<'_> {
    fn drop(&mut self) {
        if self.ultimate_drop_behavior {
            short_writeln!(Self::provide_correct_handle(self.stderr), "")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::terminal::terminal_interface::TerminalWrapper;
    use crate::test_utils::mocks::StdoutBlender;
    use crossbeam_channel::{bounded, unbounded};
    use std::thread;
    use std::time::Duration;
    use test_utilities::byte_array_reader_writer::ByteArrayReader;

    #[test]
    fn constants_have_correct_values() {
        assert_eq!(MASQ_TEST_INTEGRATION_KEY, "MASQ_TEST_INTEGRATION");
    }

    #[test]
    fn integration_test_terminal_provides_synchronization() {
        let (tx_cb, rx_cb) = unbounded();
        let mut terminal_interface = IntegrationTestTerminal::default();
        let lock = Arc::new(Mutex::new(()));
        let console = IntegrationTestTerminalConsole {
            lock: lock.clone(),
            stdin: Box::new(ByteArrayReader::new(b"Some command")),
            stdout: Box::new(StdoutBlender::new(tx_cb.clone())),
        };
        terminal_interface.console = Arc::new(Mutex::new(console));
        terminal_interface.lock = lock;
        let terminal = TerminalWrapper::new(Arc::new(terminal_interface));
        let mut terminal_clone = terminal.clone();
        let (tx, rx) = bounded(1);
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
        assert!(!written_in_a_whole.ends_with("asq> "));
        assert_eq!(written_in_a_whole.len(), 96);
        let filtered_string = written_in_a_whole.replace("012345678910111213141516171819", "");
        assert_eq!(filtered_string, "masq> ");
    }

    fn write_one_cycle(stdout: &mut StdoutBlender, interface: &mut TerminalWrapper) {
        let _lock = interface.lock();
        (0..20).for_each(|num: u8| {
            stdout.write(num.to_string().as_bytes()).unwrap();
            thread::sleep(Duration::from_millis(1))
        })
    }
}
