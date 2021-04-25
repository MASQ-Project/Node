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

//This is the outermost layer which is intended for you to usually work with at other places in the codebase.

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
        self.interface.provide_lock()
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
            //we have no positive automatic test aimed on this (only negative, an integration test)
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
//This construction, including those functions with closures above that are strongly affected by the way how interface_configurator()
//is written, is so complicated because there are tough obstacles to write simple tests here.
//interface_configurator() substitutes something that may otherwise look, in the production code, simplified, like:
//let terminal = match DefaultTerminal::new() {*something*};
//let interface = match Interface::start_with("masq",terminal){*something*};
//if let Err(e) = interface.set_prompt(){*something*};
//Ok(TerminalReal::new(interface))
//
//However, since we want to write tests we have to face here the following:
//1) DefaultTerminal alone is a part which can be theoretically tested outside, with certain troubles, but because of the other
//lines of codes in interface_configurator() it makes sense for it to stay there.
//2) It's quite hard to simulate a failure at Interface::start_with, though possible; you have to implement your own "terminal
//type", which you'll then instruct to cause an error during a call of the function below. It requires an implementation
//of linefeed::Terminal and creation of some other objects, hanged on it and dependant on each other, which leads up to an extremely
//long sequence of declarations written from zero.
//3) Sadly, when you're finally done with the previous you'll find that point 3 is even impossible because unlike the previous case
//you are about to hit an external struct, named 'Reader', with a private constructor (and also declared publicly but with private
//fields) and which doesn't share its traits - and that's the end of the line.
//
//We decided that some day in the future we'll probably want to properly react on errors that are possible on set_prompt(). Thus this
//"silly play with closures" may be justifiable.
//
//In short, I created a so to say skeleton which takes injections of closures where I can exactly say how the mock, the injected
//function shall behave and what it shall produce. Like so, all problems can be finally covered.

fn interface_configurator<FN1, FN2: ?Sized, T, I>(
    interface_raw: Box<FN1>,
    terminal_type: Box<FN2>,
) -> Result<TerminalReal, String>
where
    FN1: FnOnce(&'static str, T) -> std::io::Result<I>,
    FN2: FnOnce() -> std::io::Result<T>,
    T: linefeed::Terminal + 'static,
    I: InterfaceRaw + Send + Sync + 'static,
{
    let terminal: T = match terminal_type() {
        Ok(term) => term,
        Err(e) => return Err(format!("Local terminal: {}", e)),
    };
    let mut interface: Box<dyn InterfaceRaw + Send + Sync + 'static> =
        match interface_raw("masq", terminal) {
            Ok(interface) => Box::new(interface),
            Err(e) => return Err(format!("Preparing terminal interface: {}", e)),
        };
    if let Err(e) = set_all_settable(&mut *interface) {
        return Err(e);
    };
    Ok(TerminalReal::new(interface))
}

fn set_all_settable<I>(interface: &mut I) -> Result<(), String>
where
    I: InterfaceRaw + Send + Sync + 'static + ?Sized,
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
//Writer in the context of a passive mock has no functionality but still must be provided because such an object is required by
//certain procedures. Look at that like a method of a different object returns a struct that is in the production code, doesn't
//need its own method calls but most importantly cannot be reconstructed because of the lack of a public constructor or public
//trait in the external library. No way.

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
//Though this looks like a wast; it is needed for good coverage of certain tests...
//There is another possible way, to create our own 'terminal type', an object implementing
//linefeed::Terminal and then to use Interface<T>, where T (within our tests) is our terminal type.
//Sadly, that would require much longer implementation than this here, forced by the nature
//of linefeed::Terminal

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
    use crate::test_utils::mocks::{
        InterfaceRawMock, StdoutBlender, TerminalActiveMock, MASQ_TESTS_RUN_IN_TERMINAL_KEY,
    };
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
        let pre_check = std::env::var(MASQ_TESTS_RUN_IN_TERMINAL_KEY);
        if pre_check.is_ok() && pre_check.unwrap() == "true" {
            eprintln!(
                r#"test "configure_interface_complains_that_there_is_no_real_terminal" was skipped because was about to be run in a terminal"#
            )
        } else {
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
}
