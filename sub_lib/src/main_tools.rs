// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use std::io;

#[allow(dead_code)]
pub struct StdStreams<'a> {
    pub stdin: &'a mut io::Read,
    pub stdout: &'a mut io::Write,
    pub stderr: &'a mut io::Write
}

pub trait Command {
    fn go<'a>(&mut self, streams: &'a mut StdStreams<'a>, args: &Vec<String>) -> u8;
}
