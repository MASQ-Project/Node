// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
use std::io;

pub struct StdStreams<'a> {
    pub stdin: &'a mut (dyn io::Read + Send),
    pub stdout: &'a mut (dyn io::Write + Send),
    pub stderr: &'a mut (dyn io::Write + Send),
}

pub trait Command {
    fn go(&mut self, streams: &mut StdStreams<'_>, args: &[String]) -> u8;
}
