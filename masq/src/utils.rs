// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::line_reader::LineReader;
use crate::terminal_interface::TerminalWrapper;
use std::io::BufRead;
use std::sync::{Arc, Mutex};

pub trait BufReadFactory {
    fn make(&self, term_interface: TerminalWrapper) -> Box<()>;
}

pub struct BufReadFactoryReal {}

impl BufReadFactory for BufReadFactoryReal {
    fn make(&self, term_interface: TerminalWrapper) -> Box<()> {
        // cut off
        Box::new(())
    }
}

impl Default for BufReadFactoryReal {
    fn default() -> Self {
        BufReadFactoryReal::new()
    }
}

impl BufReadFactoryReal {
    pub fn new() -> BufReadFactoryReal {
        BufReadFactoryReal {}
    }
}
