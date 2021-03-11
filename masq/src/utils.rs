// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::line_reader::LineReader;
use std::io::BufRead;
use std::sync::{Arc, Mutex};

pub const MASQ_PROMPT: &str = "masq> ";

pub trait BufReadFactory {
    fn make(&self, output_synchronizer: Arc<Mutex<()>>) -> Box<dyn BufRead>;
}

pub struct BufReadFactoryReal {}

impl BufReadFactory for BufReadFactoryReal {
    fn make(&self, output_synchronizer: Arc<Mutex<()>>) -> Box<dyn BufRead> {
        Box::new(LineReader::new(output_synchronizer))
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
