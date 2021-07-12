// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::terminal::line_reader::TerminalEvent;
use linefeed::{Interface, ReadResult, Signal, Writer};

#[cfg(test)]
mod test_cfg {
    pub use linefeed::memory::MemoryTerminal;
    pub use masq_lib::intentionally_blank;
}

pub trait MasqTerminal: Send + Sync {
    fn read_line(&self) -> TerminalEvent;
    fn lock(&self) -> Box<dyn WriterLock + '_>;
    fn lock_ultimately(&self) -> Box<dyn WriterLock + '_>;
    #[cfg(test)]
    fn test_interface(&self) -> test_cfg::MemoryTerminal {
        test_cfg::intentionally_blank!()
    }
    #[cfg(test)]
    fn struct_id(&self) -> String {
        test_cfg::intentionally_blank!()
    }
}
//you may be looking for the declaration of TerminalReal which is in another file

//needed for being able to use both DefaultTerminal and MemoryTerminal (synchronization tests)
pub trait WriterLock {
    #[cfg(test)]
    fn struct_id(&self) -> String {
        test_cfg::intentionally_blank!()
    }
}

impl<U: linefeed::Terminal> WriterLock for Writer<'_, '_, U> {
    #[cfg(test)]
    fn struct_id(&self) -> String {
        "linefeed::Writer<_>".to_string()
    }
}

//complication caused by the fact that linefeed::Interface cannot be mocked directly so I created a superior
//trait that finally allows me to have a full mock

pub trait InterfaceWrapper: Send + Sync {
    fn read_line(&self) -> std::io::Result<ReadResult>;
    fn add_history(&self, line: String);
    fn lock_writer_append(&self) -> std::io::Result<Box<dyn WriterLock + '_>>;
    fn get_buffer(&self) -> String; //TODO untested
    fn clear_buffer(&self); //TODO add the proper result
    fn set_prompt(&self, prompt: &str) -> std::io::Result<()>;
    fn set_report_signal(&self, signal: Signal, set: bool);
}

impl<U: linefeed::Terminal> InterfaceWrapper for Interface<U> {
    fn read_line(&self) -> std::io::Result<ReadResult> {
        self.read_line()
    }

    fn add_history(&self, line: String) {
        self.add_history(line);
    }

    fn lock_writer_append(&self) -> std::io::Result<Box<dyn WriterLock + '_>> {
        match self.lock_writer_append() {
            Ok(writer) => Ok(Box::new(writer)),
            //untested ...mocking here would require own definition of a terminal type;
            //it isn't worth it due to its complexity
            Err(error) => Err(error),
        }
    }

    fn get_buffer(&self) -> String {
        self.buffer()
    }

    fn clear_buffer(&self) {
        let _ = self.set_buffer("");
    }

    fn set_prompt(&self, prompt: &str) -> std::io::Result<()> {
        self.set_prompt(prompt)
    }

    fn set_report_signal(&self, signal: Signal, set: bool) {
        self.set_report_signal(signal, set)
    }
}
