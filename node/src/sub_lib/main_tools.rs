// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use std::io;

pub struct StdStreams<'a> {
    pub stdin: &'a mut (dyn io::Read + Send),
    pub stdout: &'a mut (dyn io::Write + Send),
    pub stderr: &'a mut (dyn io::Write + Send),
}

pub trait Command {
    fn go(&mut self, streams: &mut StdStreams<'_>, args: &Vec<String>) -> u8;
}
