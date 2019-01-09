// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use std::io;

#[allow(dead_code)]
pub struct StdStreams<'a> {
    pub stdin: &'a mut (io::Read + Send),
    pub stdout: &'a mut (io::Write + Send),
    pub stderr: &'a mut (io::Write + Send),
}

pub trait Command {
    fn go(&mut self, streams: &mut StdStreams, args: &Vec<String>) -> u8;
}
