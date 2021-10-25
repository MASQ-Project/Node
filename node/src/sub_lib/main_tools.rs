// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
use crate::run_modes::RunModes;
use masq_lib::command::StdStreams;
use std::io;

pub fn main_with_args(args: &[String]) -> i32 {
    let mut streams: StdStreams<'_> = StdStreams {
        stdin: &mut io::stdin(),
        stdout: &mut io::stdout(),
        stderr: &mut io::stderr(),
    };

    let streams_ref: &mut StdStreams<'_> = &mut streams;

    RunModes::new().go(args, streams_ref)
}
