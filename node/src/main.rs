// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use node_lib::run_modes;
use node_lib::sub_lib::main_tools::StdStreams;
use std::io;

pub fn main() {
    let args = &std::env::args().collect();
    let exit_code = main_with_args (args);
    ::std::process::exit(exit_code);
}

pub fn main_with_args(args: &Vec<String>) -> i32 {
    let mut streams: StdStreams<'_> = StdStreams {
        stdin: &mut io::stdin(),
        stdout: &mut io::stdout(),
        stderr: &mut io::stderr(),
    };

    let streams_ref: &mut StdStreams<'_> = &mut streams;

    run_modes::go(args, streams_ref)
}
