// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use crate::run_modes;
use std::io;

pub struct StdStreams<'a> {
    pub stdin: &'a mut (dyn io::Read + Send),
    pub stdout: &'a mut (dyn io::Write + Send),
    pub stderr: &'a mut (dyn io::Write + Send),
}

pub trait Command {
    fn go(&mut self, streams: &mut StdStreams<'_>, args: &Vec<String>) -> u8;
}

pub fn main_with_args(args: &Vec<String>) -> i32 {
    let mut streams: StdStreams<'_> = StdStreams {
        stdin: &mut io::stdin(),
        stdout: &mut io::stdout(),
        stderr: &mut io::stderr(),
    };

    let streams_ref: &mut StdStreams<'_> = &mut streams;

eprintln! ("main_with_args with args: {:?}", args);
    run_modes::go(args, streams_ref)
}
