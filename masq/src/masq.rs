// Copyright (c) 2019, MASQ (https://masq.ai). All rights reserved.
use crate::main_tools::Command;
use crate::main_tools::StdStreams;

pub struct Masq {}

impl Default for Masq {
    fn default() -> Self {
        Self {}
    }
}

impl Command for Masq {
    fn go(&mut self, streams: &mut StdStreams<'_>, _args: &[String]) -> u8 {
        writeln!(streams.stdout, "go() called").unwrap();
        0
    }
}

impl Masq {
    pub fn new() -> Self {
        Self{}
    }
}

#[cfg(test)]
mod tests {
//    use super::*;

    #[test]
    fn nothing () {
        assert_eq! (0, 1)
    }
}
