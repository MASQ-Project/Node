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
#[cfg(test)]
use masq_lib::intentionally_blank;
use std::sync::Arc;

pub const MASQ_TEST_INTEGRATION_KEY: &str = "MASQ_TEST_INTEGRATION";
pub const MASQ_TEST_INTEGRATION_VALUE: &str = "3aad217a9b9fa6d41487aef22bf678b1aee3282d884eeb\
74b2eac7b8a3be8xzt";

//This is the outermost layer which is intended for you to usually work with at other places.

pub struct TerminalWrapper {
    interface: Arc<Box<dyn MasqTerminal + Send + Sync>>,
}

impl Clone for TerminalWrapper {
    fn clone(&self) -> Self {
        Self {
            interface: Arc::clone(&self.interface),
        }
    }
}

impl TerminalWrapper {
    pub fn new(interface: Box<dyn MasqTerminal + Send + Sync>) -> Self {
        Self {
            interface: Arc::new(interface),
        }
    }
    pub fn lock(&self) -> Box<dyn WriterLock + '_> {
        self.interface.lock()
    }
    pub fn read_line(&self) -> TerminalEvent {
        self.interface.read_line()
    }

    #[cfg(not(test))]
    pub fn configure_interface() -> Result<Self, String> {
        if std::env::var(MASQ_TEST_INTEGRATION_KEY).eq(&Ok(MASQ_TEST_INTEGRATION_VALUE.to_string()))
        {
            Ok(TerminalWrapper::new(Box::new(
                IntegrationTestTerminal::default(),
            )))
        } else {
            //we have no positive automatic test aimed on this (only negative and as an integration test)
            Self::configure_interface_generic(Box::new(DefaultTerminal::new))
        }
    }

    fn configure_interface_generic<F, TerminalType>(
        terminal_creator_of_certain_type: Box<F>,
    ) -> Result<Self, String>
    where
        F: FnOnce() -> std::io::Result<TerminalType>,
        TerminalType: linefeed::Terminal + 'static,
    {
        let interface = interface_configurator(
            Box::new(Interface::with_term),
            terminal_creator_of_certain_type,
        )?;
        Ok(Self::new(Box::new(interface)))
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //test only

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
////////////////////////////////////////////////////////////////////////////////////////////////////
//so to say skeleton which takes injections of closures where I can exactly say how the mocked, injected
//function shall behave and what it shall produce. Like so, all possible situations can be finally
//covered.

fn interface_configurator<InterfaceConstructor, TerminalConstructor: ?Sized, Terminal, Interface>(
    interface_raw: Box<InterfaceConstructor>,
    terminal_type: Box<TerminalConstructor>,
) -> Result<TerminalReal, String>
where
    InterfaceConstructor: FnOnce(&'static str, Terminal) -> std::io::Result<Interface>,
    TerminalConstructor: FnOnce() -> std::io::Result<Terminal>,
    Terminal: linefeed::Terminal + 'static,
    Interface: InterfaceWrapper + Send + Sync + 'static,
{
    let terminal: Terminal = match terminal_type() {
        Ok(term) => term,
        Err(e) => return Err(format!("Local terminal recognition: {}", e)),
    };
    let mut interface: Box<dyn InterfaceWrapper + Send + Sync + 'static> =
        match interface_raw("masq", terminal) {
            Ok(interface) => Box::new(interface),
            Err(e) => return Err(format!("Preparing terminal interface: {}", e)),
        };
    if let Err(e) = set_all_settable_parameters(&mut *interface) {
        return Err(e);
    };
    Ok(TerminalReal::new(interface))
}

fn set_all_settable_parameters<I>(interface: &mut I) -> Result<(), String>
where
    I: InterfaceWrapper + Send + Sync + 'static + ?Sized,
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
    fn lock(&self) -> Box<dyn WriterLock + '_>;
    fn read_line(&self) -> TerminalEvent;
    #[cfg(test)]
    fn test_interface(&self) -> MemoryTerminal {
        intentionally_blank!()
    }
    #[cfg(test)]
    fn tell_me_who_you_are(&self) -> String {
        intentionally_blank!()
    }
}
//you may be looking for the declaration of TerminalReal which is in another file

////////////////////////////////////////////////////////////////////////////////////////////////////
//needed for being able to use both DefaultTerminal and MemoryTerminal (synchronization tests)
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

////////////////////////////////////////////////////////////////////////////////////////////////////
//complication caused by the fact that linefeed::Interface cannot be mocked easily - thus I use little
//abstraction with the real "Interface" object using generic terminals in it

pub trait InterfaceWrapper {
    fn read_line(&self) -> std::io::Result<ReadResult>;
    fn add_history_unique(&self, line: String);
    fn lock_writer_append(&self) -> std::io::Result<Box<dyn WriterLock + '_>>;
    fn set_prompt(&self, prompt: &str) -> std::io::Result<()>;
}

impl<U: linefeed::Terminal + 'static> InterfaceWrapper for Interface<U> {
    fn read_line(&self) -> std::io::Result<ReadResult> {
        self.read_line()
    }

    fn add_history_unique(&self, line: String) {
        self.add_history_unique(line);
    }

    fn lock_writer_append(&self) -> std::io::Result<Box<dyn WriterLock + '_>> {
        match self.lock_writer_append() {
            Ok(writer) => Ok(Box::new(writer)),
            //untested ...mocking here would require own definition of a terminal type;
            //it isn't worth it (see above)
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
    //the lock provided by TerminalWrapper it'll protect one writing to the stream from any influence of another.

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
        assert!(!given_output.contains(&"A".repeat(90)) || !given_output.contains(&"B".repeat(90)))
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
    fn configure_interface_catches_an_error_at_the_first_level_of_result_matching() {
        let subject = interface_configurator(
                Box::new(Interface::with_term),
                Box::new(producer_of_terminal_type_initializer_simulating_default_terminal_and_resulting_in_immediate_error),
            );

        let result = match subject {
            Ok(_) => panic!("should have been an error, got OK"),
            Err(e) => e,
        };

        assert_eq!(
            result,
            format!(
                "Local terminal recognition: {}",
                Error::from_raw_os_error(1)
            )
        )
    }

    fn producer_of_terminal_type_initializer_simulating_default_terminal_and_resulting_in_immediate_error(
    ) -> std::io::Result<impl linefeed::Terminal + 'static> {
        Err(Error::from_raw_os_error(1)) as std::io::Result<DefaultTerminal>
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
    ) -> std::io::Result<impl InterfaceWrapper + Send + Sync + 'static> {
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
    ) -> std::io::Result<impl InterfaceWrapper + Send + Sync + 'static> {
        Ok(InterfaceRawMock::new().set_prompt_result(Err(Error::from_raw_os_error(10))))
    }
}
