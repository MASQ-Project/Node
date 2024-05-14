// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::terminal::line_reader::{TerminalEvent, TerminalReal};
use crate::terminal::secondary_infrastructure::{
    ChainedConstructors, InterfaceWrapper, MasqTerminal, WriterLock,
};
use linefeed::{Interface, Signal};
use masq_lib::command::StdStreams;
use masq_lib::constants::MASQ_PROMPT;
use std::sync::Arc;

#[cfg(not(test))]
mod prod_cfg {
    pub use crate::terminal::integration_test_utils::{
        IntegrationTestTerminal, MASQ_TEST_INTEGRATION_KEY, MASQ_TEST_INTEGRATION_VALUE,
    };
    pub use linefeed::DefaultTerminal;
}

#[cfg(test)]
mod test_cfg {
    pub use linefeed::memory::MemoryTerminal;
}

//Unlike the linefeed library is designed to be used, I stick with using the system stdout handles for writing into them instead of the custom handles provided from linefeed.
//I take benefits from linefeed's synchronization abilities, and other handy stuff it offers, while the implementation stays simpler than if I'd had to
//distribute the nonstandard, custom handles over a lot of places in our code.

pub struct TerminalWrapper {
    interface: Arc<dyn MasqTerminal>,
}

impl Clone for TerminalWrapper {
    fn clone(&self) -> Self {
        Self {
            interface: Arc::clone(&self.interface),
        }
    }
}

impl TerminalWrapper {
    pub fn new(interface: Arc<dyn MasqTerminal>) -> Self {
        Self { interface }
    }
    pub fn lock(&self) -> Box<dyn WriterLock + '_> {
        self.interface.lock()
    }

    pub fn lock_ultimately(
        &self,
        streams: &mut StdStreams,
        stderr: bool,
    ) -> Box<dyn WriterLock + '_> {
        self.interface.lock_without_prompt(streams, stderr)
    }

    pub fn read_line(&self) -> TerminalEvent {
        self.interface.read_line()
    }

    #[cfg(not(test))]
    pub fn configure_interface() -> Result<Self, String> {
        if std::env::var(prod_cfg::MASQ_TEST_INTEGRATION_KEY)
            .eq(&Ok(prod_cfg::MASQ_TEST_INTEGRATION_VALUE.to_string()))
        {
            Ok(TerminalWrapper::new(Arc::new(
                prod_cfg::IntegrationTestTerminal::default(),
            )))
        } else {
            //we have no positive test aimed at this (only negative and as an integration test)
            Self::configure_interface_generic(Box::new(prod_cfg::DefaultTerminal::new))
        }
    }

    fn configure_interface_generic<F, TerminalType>(
        terminal_creator_of_certain_type: Box<F>,
    ) -> Result<Self, String>
    where
        F: FnOnce() -> std::io::Result<TerminalType>,
        TerminalType: linefeed::Terminal + 'static,
    {
        Ok(Self::new(Arc::new(interface_configurator(
            terminal_creator_of_certain_type,
            Box::new(Interface::with_term),
        )?)))
    }
}

//so to say skeleton which accepts injections of closures where I can exactly say how these mocked, injected
//constructors shall behave and what it shall produce

fn interface_configurator<Term, Itf, TermConstructor, ItfConstructor>(
    construct_typed_terminal: Box<TermConstructor>,
    construct_interface: Box<ItfConstructor>,
) -> Result<TerminalReal, String>
where
    TermConstructor: FnOnce() -> std::io::Result<Term>,
    ItfConstructor: FnOnce(&'static str, Term) -> std::io::Result<Itf>,
    Term: linefeed::Terminal,
    Itf: InterfaceWrapper + 'static,
{
    let mut interface: Box<Itf> = construct_typed_terminal()
        .map_err(|e| format!("Local terminal recognition: {}", e))?
        .chain_constructors(construct_interface)
        .map(Box::new)
        .map_err(|e| format!("Preparing terminal interface: {}", e))?;

    set_all_settable_parameters(interface.as_mut())?;

    Ok(TerminalReal::new(interface))
}

fn set_all_settable_parameters<I>(interface: &mut I) -> Result<(), String>
where
    I: InterfaceWrapper + ?Sized,
{
    interface
        .set_prompt(MASQ_PROMPT)
        .map_err(|e| format!("Setting prompt: {}", e))?;

    //according to linefeed's docs we await no failure here
    interface.set_report_signal(Signal::Interrupt, true);

    //here we can add another parameter to be configured,
    //such as "completer" (see linefeed library)

    Ok(())
}

#[cfg(test)]
impl TerminalWrapper {
    pub fn configure_interface() -> Result<Self, String> {
        Self::configure_interface_generic(Box::new(Self::result_wrapper_for_in_memory_terminal))
    }

    pub fn result_wrapper_for_in_memory_terminal() -> std::io::Result<test_cfg::MemoryTerminal> {
        Ok(test_cfg::MemoryTerminal::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::mocks::{InterfaceRawMock, StdoutBlender, TerminalActiveMock};
    use crossbeam_channel::unbounded;
    use linefeed::DefaultTerminal;
    use std::io::{Error, Write};
    use std::sync::{Barrier, Mutex};
    use std::thread;
    use std::time::Duration;

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
        let interface = TerminalWrapper::new(Arc::new(TerminalActiveMock::new()));
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
    fn configure_interface_catches_an_error_at_initiating_a_terminal_of_a_certain_type() {
        let result = interface_configurator(
            Box::new(constructor_of_default_terminal_resulting_in_immediate_error),
            Box::new(Interface::with_term),
        );

        let err_message = if let Err(e) = result {
            e
        } else {
            panic!("should have been an error, got Ok")
        };
        assert_eq!(
            err_message,
            format!(
                "Local terminal recognition: {}",
                Error::from_raw_os_error(1)
            )
        )
    }

    fn constructor_of_default_terminal_resulting_in_immediate_error(
    ) -> std::io::Result<impl linefeed::Terminal> {
        Err(Error::from_raw_os_error(1)) as std::io::Result<DefaultTerminal>
    }

    #[test]
    fn configure_interface_allows_us_starting_in_memory_terminal() {
        let term_mock = test_cfg::MemoryTerminal::new();
        let term_mock_clone = term_mock.clone();
        let terminal_type =
            move || -> std::io::Result<test_cfg::MemoryTerminal> { Ok(term_mock_clone) };

        let result =
            interface_configurator(Box::new(terminal_type), Box::new(Interface::with_term));

        assert!(result.is_ok())
    }

    #[test]
    fn configure_interface_catches_an_error_when_creating_an_interface_instance() {
        let result = interface_configurator(
            Box::new(TerminalWrapper::result_wrapper_for_in_memory_terminal),
            Box::new(constructor_of_interface_raw_resulting_in_early_error),
        );

        let err_message = if let Err(e) = result {
            e
        } else {
            panic!("should have been an error, got Ok")
        };
        assert_eq!(
            err_message,
            format!(
                "Preparing terminal interface: {}",
                Error::from_raw_os_error(1)
            )
        )
    }

    fn constructor_of_interface_raw_resulting_in_early_error(
        _name: &str,
        _terminal: impl linefeed::Terminal,
    ) -> std::io::Result<impl InterfaceWrapper + Send + Sync + 'static> {
        Err(Error::from_raw_os_error(1)) as std::io::Result<InterfaceRawMock>
    }

    #[test]
    fn configure_interface_catches_an_error_when_setting_the_prompt() {
        let set_prompt_params_arc = Arc::new(Mutex::new(vec![]));

        let result = interface_configurator(
            Box::new(TerminalWrapper::result_wrapper_for_in_memory_terminal),
            Box::new(|_name, _terminal| {
                Ok(InterfaceRawMock::new()
                    .set_prompt_params(&set_prompt_params_arc)
                    .set_prompt_result(Err(Error::from_raw_os_error(10))))
            }),
        );

        let err_message = if let Err(e) = result {
            e
        } else {
            panic!("should have been an error, got Ok")
        };
        assert_eq!(
            err_message,
            format!("Setting prompt: {}", Error::from_raw_os_error(10))
        );
        let set_prompt_params = set_prompt_params_arc.lock().unwrap();
        assert_eq!(*set_prompt_params, vec![MASQ_PROMPT.to_string()])
    }

    #[test]
    fn configure_interface_with_set_report_signal_works() {
        let set_report_signal_arc = Arc::new(Mutex::new(vec![]));

        let result = interface_configurator(
            Box::new(TerminalWrapper::result_wrapper_for_in_memory_terminal),
            Box::new(|_name, _terminal| {
                Ok(InterfaceRawMock::new()
                    .set_report_signal_params(&set_report_signal_arc)
                    .set_prompt_result(Ok(())))
            }),
        );

        assert!(result.is_ok());
        let set_report_signal = set_report_signal_arc.lock().unwrap();
        assert_eq!(*set_report_signal, vec![(Signal::Interrupt, true)])
    }
}
