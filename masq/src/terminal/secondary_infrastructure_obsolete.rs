// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::terminal::line_reader::TerminalEvent;
use masq_lib::command::StdStreams;
//
// #[cfg(test)]
// mod test_cfg {
//     pub use masq_lib::intentionally_blank;
// }
//
// macro_rules! improvised_struct_id {
//     () => {
//         #[cfg(test)]
//         fn improvised_struct_id(&self) -> String {
//             test_cfg::intentionally_blank!()
//         }
//     };
//     ($struct_name:literal) => {
//         #[cfg(test)]
//         fn improvised_struct_id(&self) -> String {
//             $struct_name.to_string()
//         }
//     };
// }
//
// pub trait MasqTerminal: Send + Sync {
//     fn read_line(&self) -> TerminalEvent;
//     fn lock(&self) -> Box<dyn WriterLock + '_>;
//     fn lock_without_prompt(
//         &self,
//         streams: &mut StdStreams,
//         stderr: bool,
//     ) -> Box<dyn WriterLock + '_>;
//     improvised_struct_id!();
// }
//
// //needed for being able to use both DefaultTerminal and MemoryTerminal (synchronization tests)
// pub trait WriterLock {
//     improvised_struct_id!();
// }
//
// impl<U: linefeed::Terminal> WriterLock for Writer<'_, '_, U> {
//     improvised_struct_id!("linefeed::Writer<_>");
// }
//
// //complication caused by the fact that linefeed::Interface cannot be mocked directly, so I created a superordinate
// //trait that finally allows me to have a full mock
//
// pub trait InterfaceWrapper: Send + Sync {
//     fn read_line(&self) -> std::io::Result<ReadResult>;
//     fn add_history(&self, line: String);
//     fn lock_writer_append(&self) -> std::io::Result<Box<dyn WriterLock + '_>>;
//     fn get_buffer(&self) -> String;
//     fn set_buffer(&self, text: &str) -> std::io::Result<()>;
//     fn set_prompt(&self, prompt: &str) -> std::io::Result<()>;
//     fn set_report_signal(&self, signal: Signal, set: bool);
// }
//
// impl<U: linefeed::Terminal> InterfaceWrapper for Interface<U> {
//     fn read_line(&self) -> std::io::Result<ReadResult> {
//         self.read_line()
//     }
//
//     fn add_history(&self, line: String) {
//         self.add_history(line);
//     }
//
//     fn lock_writer_append(&self) -> std::io::Result<Box<dyn WriterLock + '_>> {
//         match self.lock_writer_append() {
//             Ok(writer) => Ok(Box::new(writer)),
//             //untested ...mocking here would require own definition of a terminal type;
//             //it isn't worth it due to its complexity
//             Err(error) => Err(error),
//         }
//     }
//
//     fn get_buffer(&self) -> String {
//         self.buffer()
//     }
//
//     fn set_buffer(&self, text: &str) -> std::io::Result<()> {
//         self.set_buffer(text)
//     }
//
//     fn set_prompt(&self, prompt: &str) -> std::io::Result<()> {
//         self.set_prompt(prompt)
//     }
//
//     fn set_report_signal(&self, signal: Signal, set: bool) {
//         self.set_report_signal(signal, set)
//     }
// }
//
// pub trait ChainedConstructors {
//     fn chain_constructors<Closure, Itf>(
//         self,
//         constructor_interface: Box<Closure>,
//     ) -> std::io::Result<Itf>
//     where
//         Closure: FnOnce(&'static str, Self) -> std::io::Result<Itf>,
//         Itf: InterfaceWrapper + 'static,
//         Self: Sized,
//     {
//         constructor_interface("masq", self)
//     }
// }
//
// impl<T: linefeed::Terminal> ChainedConstructors for T {}
