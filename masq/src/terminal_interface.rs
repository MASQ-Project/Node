// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::line_reader::{TerminalEvent, TerminalReal};
use linefeed::memory::MemoryTerminal;
use linefeed::{DefaultTerminal, Interface, ReadResult, Writer};
use masq_lib::constants::MASQ_PROMPT;
use masq_lib::intentionally_blank;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

//this is the most functional layer, an object which is intended for you to usually work with at other
//places in the code

#[allow(clippy::type_complexity)]
pub struct TerminalWrapper {
    inner_idle: TerminalIdle,
    inner_active: Option<Arc<Box<dyn Terminal + Send + Sync>>>,
    share_point: Arc<Mutex<Option<Arc<Box<dyn Terminal + Send + Sync>>>>>,
    interactive_flag: Arc<AtomicBool>,
}

impl Default for TerminalWrapper {
    fn default() -> Self {
        Self::new()
    }
}

impl TerminalWrapper {
    pub fn new() -> Self {
        Self {
            inner_idle: TerminalIdle {},
            inner_active: None,
            share_point: Arc::new(Mutex::new(None)),
            interactive_flag: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn lock(&mut self) -> Box<dyn WriterGeneric + '_> {
        match self.check_update() {
            true => self
                .inner_active
                .as_ref()
                .expect("some was expected")
                .provide_lock(),
            false => self.inner_idle.provide_lock(),
        }
    }

    pub fn read_line(&self) -> TerminalEvent {
        self.inner_active
            .as_ref()
            .expect("some was expected")
            .read_line()
    }

    pub fn add_history_unique(&self, line: String) {
        self.inner_active
            .as_ref()
            .expect("some was expected")
            .add_history_unique(line)
    }

    pub fn upgrade(&mut self) -> Result<(), String> {
        let upgraded_terminal = if cfg!(test) {
            configure_interface(
                Box::new(Interface::with_term),
                Box::new(Self::result_wrapper_for_in_memory_terminal),
            )
        } else {
            //no automatic test for this; tested with the fact that people are able to run masq in interactive mode
            configure_interface(
                Box::new(Interface::with_term),
                Box::new(DefaultTerminal::new),
            )
        }?;
        *self
            .share_point
            .lock()
            .expect("TerminalWrapper: Upgrade: share-point: poisoned Mutex") =
            Some(Arc::new(Box::new(upgraded_terminal)));
        self.interactive_flag.store(true, Ordering::Relaxed);

        Ok(())
    }

    #[allow(clippy::unnecessary_wraps)]
    fn result_wrapper_for_in_memory_terminal() -> std::io::Result<MemoryTerminal> {
        Ok(MemoryTerminal::new())
    }

    pub fn check_update(&mut self) -> bool {
        match self.inner_active.is_some() {
            true => true,
            false => match self.interactive_flag.load(Ordering::Relaxed) {
                true => {
                    self.inner_active = Some(Arc::clone(
                        &*self
                            .share_point
                            .lock()
                            .expect("TerminalWrapper: CheckUpdate: share-point: poisoned Mutex")
                            .as_ref()
                            .expect("share point: some wasn't at its place"),
                    ));
                    true
                }
                false => false,
            },
        }
    }

    #[cfg(test)]
    pub fn inspect_inner_active(&mut self) -> &mut Option<Arc<Box<dyn Terminal + Send + Sync>>> {
        &mut self.inner_active
    }

    #[cfg(test)]
    pub fn inspect_share_point(
        &mut self,
    ) -> &mut Arc<Mutex<Option<Arc<Box<dyn Terminal + Send + Sync>>>>> {
        &mut self.share_point
    }

    #[cfg(test)]
    pub fn inspect_interactive_flag(&self) -> &Arc<AtomicBool> {
        &self.interactive_flag
    }

    #[cfg(test)]
    pub fn test_interface(&self) -> MemoryTerminal {
        self.inner_active
            .as_ref()
            .expect("some was expected")
            .clone()
            .to_owned()
            .test_interface()
    }

    #[cfg(test)]
    pub fn set_interactive_for_test_purposes(
        mut self,
        active_interface: Box<dyn Terminal + Send + Sync>,
    ) -> Self {
        self.inner_active = Some(Arc::new(active_interface));
        self.interactive_flag.store(true, Ordering::Relaxed);
        self
    }
}

impl Clone for TerminalWrapper {
    fn clone(&self) -> Self {
        Self {
            inner_idle: TerminalIdle {},
            inner_active: self.inner_active.as_ref().map(|val| Arc::clone(&val)),
            share_point: Arc::clone(&self.share_point),
            interactive_flag: Arc::clone(&self.interactive_flag),
        }
    }
}

pub fn configure_interface<F, U, E: ?Sized>(
    interface_raw: Box<F>,
    terminal_type: Box<E>,
) -> Result<TerminalReal, String>
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

    //here we can add some other parameter to be configured,
    //such as "completer" (see linefeed library)

    Ok(TerminalReal::new(Box::new(interface)))
}

////////////////////////////////////////////////////////////////////////////////////////////////////

//declaration of TerminalReal is in line_reader.rs

pub trait Terminal {
    fn provide_lock(&self) -> Box<dyn WriterGeneric + '_> {
        intentionally_blank!()
    }
    fn read_line(&self) -> TerminalEvent {
        intentionally_blank!()
    }
    fn add_history_unique(&self, _line: String) {}

    #[cfg(test)]
    fn test_interface(&self) -> MemoryTerminal {
        intentionally_blank!()
    }
    #[cfg(test)]
    fn tell_me_who_you_are(&self) -> String {
        intentionally_blank!()
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////

pub struct TerminalIdle {}

impl Terminal for TerminalIdle {
    fn provide_lock(&self) -> Box<dyn WriterGeneric + '_> {
        Box::new(WriterIdle {})
    }
    #[cfg(test)]
    fn tell_me_who_you_are(&self) -> String {
        "TerminalIdle".to_string()
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////

pub trait WriterGeneric {
    fn write_str(&mut self, _str: &str) -> std::io::Result<()> {
        intentionally_blank!()
    }

    //I failed in attempts to use Any and dynamical casting from Box<dyn WriterGeneric>
    //because: Writer doesn't implement Clone and many if not all methods of Any require
    //'static, that is, it must be an owned object and I cannot get anything else but reference
    //of Writer.
    //For delivering at least some test I decided to use this unusual hack
    #[cfg(test)]
    fn tell_me_who_you_are(&self) -> String {
        intentionally_blank!()
    }
}

impl<U: linefeed::Terminal> WriterGeneric for Writer<'_, '_, U> {
    fn write_str(&mut self, str: &str) -> std::io::Result<()> {
        self.write_str(&format!("{}\n*/-", str))
    }

    #[cfg(test)]
    fn tell_me_who_you_are(&self) -> String {
        "linefeed::Writer<_>".to_string()
    }
}

#[derive(Clone)]
pub struct WriterIdle {}

impl WriterGeneric for WriterIdle {
    #[cfg(test)]
    fn tell_me_who_you_are(&self) -> String {
        "WriterIdle".to_string()
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////

pub trait InterfaceRaw {
    fn read_line(&self) -> std::io::Result<ReadResult>;
    fn add_history_unique(&self, line: String);
    fn lock_writer_append(&self) -> std::io::Result<Box<dyn WriterGeneric + '_>>;
    fn set_prompt(&self, _prompt: &str) -> std::io::Result<()> {
        intentionally_blank!()
    }
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
            //untested ...dunno how to trigger any error here
            Err(error) => Err(error),
        }
    }

    fn set_prompt(&self, prompt: &str) -> std::io::Result<()> {
        self.set_prompt(prompt)
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::mocks::{MixingStdout, TerminalActiveMock};
    use crate::test_utils::{written_output_all_lines, written_output_by_line_number};
    use crossbeam_channel::unbounded;
    use linefeed::DefaultTerminal;
    use std::io::Write;
    use std::sync::Barrier;
    use std::thread;
    use std::time::{Duration, Instant};

    #[test]
    fn terminal_mock_and_test_tools_write_and_read() {
        let mock = TerminalActiveMock::new()
            .read_line_result("Rocket, go to Mars, go, go".to_string())
            .read_line_result("And once again...nothing".to_string());

        let mut terminal = TerminalWrapper::new().set_interactive_for_test_purposes(Box::new(mock));
        let mut terminal_clone = terminal.clone();
        let terminal_reference = terminal.clone();

        terminal.lock().write_str("first attempt").unwrap();

        let handle = thread::spawn(move || {
            terminal_clone.lock().write_str("hello world").unwrap();
            terminal_clone.lock().write_str("that's enough").unwrap()
        });

        handle.join().unwrap();

        terminal.read_line();

        terminal.read_line();

        let lines_remaining = terminal_reference
            .test_interface()
            .lines()
            .lines_remaining();
        assert_eq!(lines_remaining, 24);

        let written_output =
            written_output_all_lines(terminal_reference.test_interface().lines(), true);
        assert_eq!(
            written_output,
            "first attempt | hello world | that's enough | \
         Rocket, go to Mars, go, go | And once again...nothing |"
        );

        let single_line =
            written_output_by_line_number(terminal_reference.test_interface().lines(), 1);
        assert_eq!(single_line, "first attempt");

        let single_line =
            written_output_by_line_number(terminal_reference.test_interface().lines(), 2);
        assert_eq!(single_line, "hello world")
    }

    #[test]
    //Here I use the system stdout handles, which is the standard way in the project, but thanks to
    //the lock from TerminalWrapper, it will be protected.
    //The core of the test consists of two halves where the first shows unprotected writing while
    //in the second locks are actively being used in both concurrent threads
    fn terminal_wrapper_s_lock_blocks_others_to_write_into_stdout() {
        let interface = TerminalWrapper::new()
            .set_interactive_for_test_purposes(Box::new(TerminalActiveMock::new()));

        let barrier = Arc::new(Barrier::new(2));
        let mut handles = Vec::new();

        let (tx, rx) = unbounded();
        let mut stdout_c1 = MixingStdout::new(tx);
        let mut stdout_c2 = stdout_c1.clone();

        let closure1: Box<dyn FnMut(TerminalWrapper) + Sync + Send> =
            Box::new(move |mut interface: TerminalWrapper| {
                //here without a lock in the first half -- printing in BOTH is unprotected
                let mut stdout = &mut stdout_c1;
                write_in_cycles("AAA", &mut stdout);
                //printing whitespace, where the two halves part
                write!(&mut stdout, "   ").unwrap();
                let _lock = interface.lock();
                write_in_cycles("AAA", &mut stdout)
            });

        let closure2: Box<dyn FnMut(TerminalWrapper) + Sync + Send> =
            Box::new(move |mut interface: TerminalWrapper| {
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
        let mut wrapper =
            TerminalWrapper::new().set_interactive_for_test_purposes(Box::new(result));
        wrapper.lock().write_str("hallelujah").unwrap();

        let checking_if_operational = written_output_all_lines(term_mock.lines(), false);

        assert_eq!(checking_if_operational, "hallelujah");
    }

    #[test]
    fn terminal_wrapper_new_produces_writer_idle() {
        let mut subject = TerminalWrapper::new();
        let lock = subject.lock();

        assert_eq!(lock.tell_me_who_you_are(), "WriterIdle")
    }

    #[test]
    fn terminal_wrapper_new_provides_correctly_set_values() {
        let subject = TerminalWrapper::new();

        assert_eq!(subject.interactive_flag.load(Ordering::Relaxed), false);
        assert!((*subject.share_point.lock().unwrap()).is_none());
        assert!(subject.inner_active.is_none());
        assert_eq!(subject.inner_idle.tell_me_who_you_are(), "TerminalIdle")
    }

    #[test]
    fn share_point_is_shared_between_threads_properly_when_its_clone_was_created_before() {
        let terminal = TerminalWrapper::new();
        assert!(terminal.share_point.lock().unwrap().is_none());
        let mut terminal_background = terminal.clone();

        let handle = thread::spawn(move || {
            assert!(terminal_background.share_point.lock().unwrap().is_none());
            terminal_background.upgrade().unwrap()
        });
        handle.join().unwrap();

        assert!(terminal.share_point.lock().unwrap().is_some());
    }

    #[test]
    fn share_point_is_shared_between_threads_properly_even_along_those_clones_created_afterwards() {
        let mut terminal = TerminalWrapper::new();
        assert!(terminal.share_point.lock().unwrap().is_none());

        terminal.upgrade().unwrap();

        assert!(terminal.share_point.lock().unwrap().is_some());
        let terminal_new_clone = terminal.clone();

        assert!(terminal_new_clone.share_point.lock().unwrap().is_some());
    }

    #[test]
    fn share_point_is_shared_between_threads_properly_cloning_new_instances_from_an_instance_left_behind_in_upgrade(
    ) {
        let mut terminal = TerminalWrapper::new();
        let terminal_background = terminal.clone();

        let (tx, rx) = std::sync::mpsc::channel();
        let handle = thread::spawn(move || {
            assert!(terminal_background.share_point.lock().unwrap().is_none());
            assert_eq!(
                terminal_background.interactive_flag.load(Ordering::Relaxed),
                false
            );
            let local_main_instance = terminal_background;
            tx.send(0usize).unwrap();
            thread::sleep(Duration::from_millis(300));
            let now = Instant::now();
            loop {
                let temporary_clone = local_main_instance.clone();
                match temporary_clone.share_point.lock().unwrap().is_some() {
                    true => {
                        assert_eq!(
                            temporary_clone.interactive_flag.load(Ordering::Relaxed),
                            true
                        );
                        break;
                    }
                    false => match now.elapsed() > Duration::from_millis(400) {
                        true => panic!("we are out of patience"),
                        false => continue,
                    },
                };
            }
        });
        rx.recv().unwrap();
        terminal.upgrade().unwrap();
        handle.join().unwrap(); //would panic if something wrong
    }
}
