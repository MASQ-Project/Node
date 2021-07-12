// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::terminal::line_reader::{split_quoted_line_for_integration_tests, TerminalEvent};
use crate::terminal::secondary_infrastructure::{MasqTerminal, WriterLock};
use masq_lib::constants::MASQ_PROMPT;
use masq_lib::short_writeln;
use masq_lib::utils::ExpectValue;
use std::io::{stdin, stdout, Read, Write};
use std::sync::{Arc, Mutex, MutexGuard};

pub struct IntegrationTestTerminal {
    lock: Arc<Mutex<()>>,
    stdin: Arc<Mutex<Box<dyn Read + Send>>>,
    stdout: Arc<Mutex<Box<dyn Write + Send>>>,
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
            .expect("poisoned mutex IntegrationTestTerminal: lock");
        short_writeln!(
            self.stdout
                .lock()
                .expect("poisoned mutex IntegrationTestTerminal: stdout"),
            "{}",
            MASQ_PROMPT
        );
        drop(_lock);
        let finalized_command_line = std::str::from_utf8(&buffer[..number_of_bytes])
            .expect_v("converted str")
            .to_string();
        TerminalEvent::CommandLine(split_quoted_line_for_integration_tests(
            finalized_command_line,
        ))
    }

    fn lock(&self) -> Box<dyn WriterLock + '_> {
        Box::new(IntegrationTestWriter {
            mutex_guard_simulating_locking: self.lock.lock().expect_v("MutexGuard"),
        })
    }

    fn lock_ultimately(&self) -> Box<dyn WriterLock> {
        todo!()
    }
}

struct IntegrationTestWriter<'a> {
    #[allow(dead_code)]
    mutex_guard_simulating_locking: MutexGuard<'a, ()>,
}

impl WriterLock for IntegrationTestWriter<'_> {}

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
    fn integration_test_terminal_provides_functional_synchronization() {
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
}
