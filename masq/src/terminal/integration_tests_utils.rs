// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::terminal::line_reader::{split_quoted_line_for_integration_tests, TerminalEvent};
use crate::terminal::secondary_infrastructure::{MasqTerminal, WriterLock};
use crossbeam_channel::{bounded, Sender};
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

#[derive(Clone)]
pub struct IntegrationTestTerminal {
    lock: Arc<Mutex<()>>,
    stdin: Arc<Mutex<Box<dyn Read + Send>>>,
    stderr: Arc<Mutex<Box<dyn Write + Send>>>,
    stdout: Arc<Mutex<Box<dyn Write + Send>>>,
    ctrl_c_flag: Arc<AtomicBool>,
}

impl Default for IntegrationTestTerminal {
    fn default() -> Self {
        let running = Arc::new(AtomicBool::new(true));
        let r = Arc::clone(&running);
        ctrlc::set_handler(move || {
            r.store(false, Ordering::SeqCst);
        })
        .expect("Error setting Ctrl-C handler");

        IntegrationTestTerminal {
            lock: Arc::new(Mutex::new(())),
            stdin: Arc::new(Mutex::new(Box::new(stdin()))),
            stderr: Arc::new(Mutex::new(Box::new(stderr()))),
            stdout: Arc::new(Mutex::new(Box::new(stdout()))),
            ctrl_c_flag: running,
        }
    }
}

impl IntegrationTestTerminal {
    fn input_reader(&self, result_sender: Sender<TerminalEvent>) {
        let _lock = self
            .lock
            .lock()
            .expect("poisoned mutex IntegrationTestTerminal: lock");
        let mut stdout_handle = self.stdout.lock().unwrap();
        write!(stdout_handle, "{}", MASQ_PROMPT).unwrap();
        stdout_handle.flush().unwrap();
        //the lock must not be around the read point
        drop(_lock);
        drop(stdout_handle);
        let mut buffer = [0; 1024];
        let number_of_bytes = self
            .stdin
            .lock()
            .expect("poisoned mutex")
            .read(&mut buffer)
            .expect("reading failed");
        let finalized_command_line = std::str::from_utf8(&buffer[..number_of_bytes])
            .expect_v("converted str")
            .to_string();
        //because of specific arrangement based on the combination of linefeed + Clap
        //TODO what the hell does version have more than just 'version' that I cannot use an equality assertion
        let mut stdout_handle = self.stdout.lock().unwrap();
        if finalized_command_line.contains("version") || finalized_command_line == "help" {
            short_writeln!(stdout_handle, "")
        };
        drop(stdout_handle);
        let _ = result_sender.send(TerminalEvent::CommandLine(
            split_quoted_line_for_integration_tests(finalized_command_line),
        ));
    }
}

impl MasqTerminal for IntegrationTestTerminal {
    //combines two features of real Linefeed, handles user's input and Ctrl+C signal
    fn read_line(&self) -> TerminalEvent {
        //mocked linefeed
        let (tx_terminal, rx_terminal) = bounded(1);
        let cloned = self.clone();
        thread::spawn(move || cloned.input_reader(tx_terminal));
        loop {
            if !self.ctrl_c_flag.load(Ordering::SeqCst) {
                return TerminalEvent::Break;
            }
            if let Ok(terminal_event) = rx_terminal.try_recv() {
                break terminal_event;
            } else {
                sleep(Duration::from_millis(10))
            }
        }
    }

    fn lock(&self) -> Box<dyn WriterLock + '_> {
        Box::new(IntegrationTestWriter {
            mutex_guard_that_simulates_the_core_locking: self.lock.lock().expect_v("MutexGuard"),
            ultimate_drop_behavior: false,
        })
    }

    fn lock_ultimately(&self, _streams: &mut StdStreams, stderr: bool) -> Box<dyn WriterLock + '_> {
        let lock = Box::new(IntegrationTestWriter {
            mutex_guard_that_simulates_the_core_locking: self.lock.lock().expect_v("MutexGuard"),
            ultimate_drop_behavior: true,
        });
        short_writeln!(
            if !stderr {
                self.stdout.lock().unwrap()
            } else {
                self.stderr.lock().unwrap()
            },
            "\n{}/*user's unfinished line to be here*/",
            MASQ_PROMPT
        );
        lock
    }
}

struct IntegrationTestWriter<'a> {
    #[allow(dead_code)]
    mutex_guard_that_simulates_the_core_locking: MutexGuard<'a, ()>,
    ultimate_drop_behavior: bool,
}

impl WriterLock for IntegrationTestWriter<'_> {}

impl Drop for IntegrationTestWriter<'_> {
    fn drop(&mut self) {
        if self.ultimate_drop_behavior {
            short_writeln!(stdout(), "")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::terminal::terminal_interface::TerminalWrapper;
    use crate::test_utils::mocks::StdoutBlender;
    use crossbeam_channel::{bounded, unbounded};
    use masq_lib::test_utils::fake_stream_holder::ByteArrayReader;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn integration_test_terminal_provides_synchronization() {
        let (tx_cb, rx_cb) = unbounded();
        let mut terminal_interface = IntegrationTestTerminal::default();
        terminal_interface.stdin =
            Arc::new(Mutex::new(Box::new(ByteArrayReader::new(b"Some command"))));
        terminal_interface.stdout =
            Arc::new(Mutex::new(Box::new(StdoutBlender::new(tx_cb.clone()))));
        let terminal = TerminalWrapper::new(Box::new(terminal_interface));
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
