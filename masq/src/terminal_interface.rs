// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

#[cfg(not(test))]
use crate::line_reader::IntegrationTestTerminal;
use crate::line_reader::{TerminalEvent, TerminalReal};
#[cfg(test)]
use linefeed::memory::MemoryTerminal;
#[cfg(not(test))]
use linefeed::DefaultTerminal;
use linefeed::{Interface, ReadResult, Writer};
use masq_lib::constants::MASQ_PROMPT;
use masq_lib::intentionally_blank;
use std::sync::Arc;

pub const MASQ_TEST_INTEGRATION_KEY: &str = "MASQ_TEST_INTEGRATION";
pub const MASQ_TEST_INTEGRATION_VALUE: &str =
    "3aad217a9b9fa6d41487aef22bf678b1aee3282d884eeb74b2eac7b8a3be8xzt";

//this is a layer with the broadest functionality, an object which is intended for you to usually work with at other
//places in the code

pub struct TerminalWrapper {
    interface: Arc<Box<dyn MasqTerminal + Send + Sync>>,
}

impl TerminalWrapper {
    pub fn new(interface: Box<dyn MasqTerminal + Send + Sync>) -> Self {
        Self {
            interface: Arc::new(interface),
        }
    }
    pub fn lock(&self) -> Box<dyn WriterLock + '_> {
        self.interface.provide_lock()
    }

    pub fn read_line(&self) -> TerminalEvent {
        self.interface.read_line()
    }

    #[cfg(not(test))]
    pub fn configure_interface() -> Result<Self, String> {
        //tested only for a negative result (an integration test)
        //no positive automatic test aimed on this
        if std::env::var(MASQ_TEST_INTEGRATION_KEY).eq(&Ok(MASQ_TEST_INTEGRATION_VALUE.to_string()))
        {
            Ok(TerminalWrapper::new(Box::new(
                IntegrationTestTerminal::default(),
            )))
        } else {
            Self::configure_interface_generic(Box::new(DefaultTerminal::new))
        }
    }

    fn configure_interface_generic<F, U>(terminal_creator_by_type: Box<F>) -> Result<Self, String>
    where
        F: FnOnce() -> std::io::Result<U>,
        U: linefeed::Terminal + 'static,
    {
        let interface =
            interface_configurator(Box::new(Interface::with_term), terminal_creator_by_type)?;
        Ok(Self::new(Box::new(interface)))
    }

    #[cfg(test)]
    pub fn configure_interface() -> Result<Self, String> {
        Self::configure_interface_generic(Box::new(result_wrapper_for_in_memory_terminal))
    }

    #[cfg(test)]
    pub fn test_interface(&self) -> MemoryTerminal {
        self.interface.test_interface()
    }
}

#[cfg(test)]
#[allow(clippy::unnecessary_wraps)]
fn result_wrapper_for_in_memory_terminal() -> std::io::Result<MemoryTerminal> {
    Ok(MemoryTerminal::new())
}

impl Clone for TerminalWrapper {
    fn clone(&self) -> Self {
        Self {
            interface: Arc::clone(&self.interface),
        }
    }
}

fn interface_configurator<F, U, E: ?Sized, D>(
    interface_raw: Box<F>,
    terminal_type: Box<E>,
) -> Result<TerminalReal, String>
where
    F: FnOnce(&'static str, U) -> std::io::Result<D>,
    E: FnOnce() -> std::io::Result<U>,
    U: linefeed::Terminal + 'static,
    D: InterfaceRaw + Send + Sync + 'static,
{
    let terminal: U = match terminal_type() {
        Ok(term) => term,
        Err(e) => return Err(format!("Local terminal: {}", e)),
    };
    let mut interface: Box<dyn InterfaceRaw + Send + Sync + 'static> =
        match interface_raw("masq", terminal) {
            Ok(interface) => Box::new(interface),
            Err(e) => return Err(format!("Preparing terminal interface: {}", e)),
        };

    if let Err(e) = set_all_settable_or_give_an_error(&mut *interface) {
        return Err(e);
    };

    Ok(TerminalReal::new(interface))
}

fn set_all_settable_or_give_an_error<U>(interface: &mut U) -> Result<(), String>
where
    U: InterfaceRaw + Send + Sync + 'static + ?Sized,
{
    if let Err(e) = interface.set_prompt(MASQ_PROMPT) {
        return Err(format!("Setting prompt: {}", e));
    }

    //here we can add another parameter to be configured,
    //such as "completer" (see linefeed library)

    Ok(())
}

////////////////////////////////////////////////////////////////////////////////////////////////////

pub trait MasqTerminal {
    fn provide_lock(&self) -> Box<dyn WriterLock + '_>;
    fn read_line(&self) -> TerminalEvent;
    #[cfg(test)]
    fn test_interface(&self) -> MemoryTerminal {intentionally_blank!()}
    #[cfg(test)]
    fn tell_me_who_you_are(&self) -> String {intentionally_blank!()}
}

//you may look for the declaration of TerminalReal which is another file

#[derive(Default)]
pub struct TerminalNonInteractive {}

impl MasqTerminal for TerminalNonInteractive {
    fn provide_lock(&self) -> Box<dyn WriterLock + '_> {
        Box::new(WriterInactive {})
    }
    fn read_line(&self) -> TerminalEvent {
        panic!("should never be called; since never come in to the body of go_interactive()")
    }
    #[cfg(test)]
    fn tell_me_who_you_are(&self) -> String {
        "TerminalNonInteractive".to_string()
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////
//writer in a passive mock has no functionality but still must be provided because such an object is required in certain procedures;
//look at that like a method of a different object returns something what is in the production code, doesn't need its own method calls
//but most importunately cannot be reconstructed because of lack of a public constructor or public character in the external library. No way.
pub trait WriterLock {
    #[cfg(test)]
    fn tell_me_who_you_are(&self) -> String {
        intentionally_blank!()
    }
}

impl<U: linefeed::Terminal> WriterLock for Writer<'_, '_, U> {
    #[cfg(test)]
    fn tell_me_who_you_are(&self) -> String {
        "linefeed::Writer<_>".to_string()
    }
}

#[derive(Clone)]
pub struct WriterInactive {}

impl WriterLock for WriterInactive {
    #[cfg(test)]
    fn tell_me_who_you_are(&self) -> String {
        "WriterInactive".to_string()
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////
//though this looks like a wast; it is needed for good coverage of certain tests...
//there is another possible way, to create our own 'terminal type', an object implementing
//linefeed::Terminal and then to use Interface<T>, where T (within our tests) is our terminal type.
//Sadly, that would require much longer implementation than this here, forced by the nature of linefeed::Terminal
pub trait InterfaceRaw {
    fn read_line(&self) -> std::io::Result<ReadResult>;
    fn add_history_unique(&self, line: String);
    fn lock_writer_append(&self) -> std::io::Result<Box<dyn WriterLock + '_>>;
    fn set_prompt(&self, prompt: &str) -> std::io::Result<()>;
}

impl<U: linefeed::Terminal + 'static> InterfaceRaw for Interface<U> {
    fn read_line(&self) -> std::io::Result<ReadResult> {
        self.read_line()
    }

    fn add_history_unique(&self, line: String) {
        self.add_history_unique(line);
    }

    fn lock_writer_append(&self) -> std::io::Result<Box<dyn WriterLock + '_>> {
        match self.lock_writer_append() {
            Ok(writer) => Ok(Box::new(writer)),
            //untested ...mocking here would require own definition of a terminal type; it isn't worth it (see above)
            Err(error) => Err(error),
        }
    }

    fn set_prompt(&self, prompt: &str) -> std::io::Result<()> {
        self.set_prompt(prompt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::mocks::{InterfaceRawMock, StdoutBlender, TerminalActiveMock};
    use crossbeam_channel::unbounded;
    use linefeed::DefaultTerminal;
    use std::io::{Error, Write};
    use std::sync::Barrier;
    use std::thread;
    use std::time::Duration;

    //In those two following tests I'm using the system stdout handles which is the standard way in the project but thanks to
    //the lock provided by TerminalWrapper it'll protect one stream from any influence of another.

    #[test]
    fn terminal_wrapper_without_lock_does_not_block_others_from_writing_into_stdout() {
        let closure1: Box<dyn FnMut(TerminalWrapper, StdoutBlender) + Sync + Send> =
            Box::new(move |_interface: TerminalWrapper, mut stdout_c| {
                write_in_cycles("AAA", &mut stdout_c);
            });

        let closure2: Box<dyn FnMut(TerminalWrapper, StdoutBlender) + Sync + Send> =
            Box::new(move |_interface: TerminalWrapper, mut stdout_c| {
                write_in_cycles("BBB", &mut stdout_c);
            });

        let given_output = test_terminal_collision(Box::new(closure1), Box::new(closure2));

        //in an extreme case it may be printed like one group is complete and the other is divided
        let results = [
            given_output.contains(&"A".repeat(90)),
            given_output.contains(&"B".repeat(90)),
        ];

        assert!(results.iter().any(|bool_result| *bool_result == false))
    }

    #[test]
    fn terminal_wrapper_s_lock_blocks_others_to_write_into_stdout() {
        let closure1: Box<dyn FnMut(TerminalWrapper, StdoutBlender) + Sync + Send> = Box::new(
            move |interface: TerminalWrapper, mut stdout_c: StdoutBlender| {
                let _lock = interface.lock();
                write_in_cycles("AAA", &mut stdout_c);
            },
        );

        let closure2: Box<dyn FnMut(TerminalWrapper, StdoutBlender) + Sync + Send> = Box::new(
            move |interface: TerminalWrapper, mut stdout_c: StdoutBlender| {
                let _lock = interface.lock();
                write_in_cycles("BBB", &mut stdout_c);
            },
        );

        let given_output = test_terminal_collision(Box::new(closure1), Box::new(closure2));

        assert!(
            given_output.contains(&"A".repeat(90)),
            "synchronized: {}",
            given_output
        );
        assert!(
            given_output.contains(&"B".repeat(90)),
            "synchronized: {}",
            given_output
        );
    }

    fn test_terminal_collision<C>(closure1: Box<C>, closure2: Box<C>) -> String
    where
        C: FnMut(TerminalWrapper, StdoutBlender) -> () + Sync + Send + 'static,
    {
        let interface = TerminalWrapper::new(Box::new(TerminalActiveMock::new()));

        let barrier = Arc::new(Barrier::new(2));

        let (tx, rx) = unbounded();
        let stdout_c1 = StdoutBlender::new(tx);
        let stdout_c2 = stdout_c1.clone();

        let handles: Vec<_> = vec![(closure1, stdout_c1), (closure2, stdout_c2)]
            .into_iter()
            .map(|pair| {
                let (mut closure, stdout): (Box<C>, StdoutBlender) = pair;
                let barrier_handle = Arc::clone(&barrier);
                let thread_interface = interface.clone();

                thread::spawn(move || {
                    barrier_handle.wait();
                    closure(thread_interface, stdout)
                })
            })
            .collect();

        handles
            .into_iter()
            .for_each(|handle| handle.join().unwrap());

        let mut buffer = String::new();
        loop {
            match rx.try_recv() {
                Ok(string) => buffer.push_str(&string),
                Err(_) => break buffer,
            }
        }
    }

    fn write_in_cycles(written_signal: &str, stdout: &mut dyn Write) {
        (0..30).for_each(|_| {
            write!(stdout, "{}", written_signal).unwrap();
            thread::sleep(Duration::from_millis(1))
        })
    }

    #[test]
    fn configure_interface_complains_that_there_is_no_real_terminal() {
        let subject = interface_configurator(
            Box::new(Interface::with_term),
            Box::new(DefaultTerminal::new),
        );

        let result = match subject {
            Ok(_) => panic!("should have been an error, got OK"),
            Err(e) => e,
        };

        #[cfg(target_os = "windows")]
        assert!(result.contains("Local terminal:"), "{}", result);
        #[cfg(not(windows))]
        assert!(
            result.contains("Preparing terminal interface: "),
            "{}",
            result
        );
        //Windows: The handle is invalid. (os error 6)
        //Linux: "Getting terminal parameters: Inappropriate ioctl for device (os error 25)"
    }

    #[test]
    fn configure_interface_allows_us_starting_in_memory_terminal() {
        let term_mock = MemoryTerminal::new();
        let term_mock_clone = term_mock.clone();
        let terminal_type = move || -> std::io::Result<MemoryTerminal> { Ok(term_mock_clone) };

        let result =
            interface_configurator(Box::new(Interface::with_term), Box::new(terminal_type));

        assert!(result.is_ok())
    }

    #[test]
    fn configure_interface_catches_an_error_when_creating_an_interface_instance() {
        let subject = interface_configurator(
            Box::new(producer_of_interface_raw_resulting_in_an_early_error),
            Box::new(result_wrapper_for_in_memory_terminal),
        );

        let result = match subject {
            Err(e) => e,
            Ok(_) => panic!("should have been Err, got Ok with TerminalReal"),
        };

        assert_eq!(
            result,
            format!(
                "Preparing terminal interface: {}",
                Error::from_raw_os_error(1)
            )
        )
    }

    fn producer_of_interface_raw_resulting_in_an_early_error(
        _name: &str,
        _terminal: impl linefeed::Terminal + 'static,
    ) -> std::io::Result<impl InterfaceRaw + Send + Sync + 'static> {
        Err(Error::from_raw_os_error(1)) as std::io::Result<InterfaceRawMock>
    }

    #[test]
    fn configure_interface_catches_an_error_when_setting_the_prompt() {
        let subject = interface_configurator(
            Box::new(producer_of_interface_raw_causing_set_prompt_error),
            Box::new(result_wrapper_for_in_memory_terminal),
        );
        let result = match subject {
            Err(e) => e,
            Ok(_) => panic!("should have been Err, got Ok with TerminalReal"),
        };

        assert_eq!(
            result,
            format!("Setting prompt: {}", Error::from_raw_os_error(10))
        )
    }

    fn producer_of_interface_raw_causing_set_prompt_error(
        _name: &str,
        _terminal: impl linefeed::Terminal + 'static,
    ) -> std::io::Result<impl InterfaceRaw + Send + Sync + 'static> {
        Ok(InterfaceRawMock::new().set_prompt_result(Err(Error::from_raw_os_error(10))))
    }

    #[test]
    fn terminal_wrapper_armed_with_terminal_inactive_produces_writer_inactive() {
        let subject = TerminalWrapper::new(Box::new(TerminalNonInteractive::default()));

        let lock = subject.lock();

        assert_eq!(lock.tell_me_who_you_are(), "WriterInactive")
    }

    #[test]
    #[should_panic="should never be called; since never come in to the body of go_interactive()"]
    fn terminal_non_interactive_triggers_clear_panic_if_read_line_called_on_it(){
        TerminalNonInteractive::default().read_line();
    }
}
