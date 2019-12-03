// Copyright (c) 2019, MASQ (https://masq.ai). All rights reserved.

use masq_lib::main_tools::StdStreams;
use masq_lib::masq::Masq;
use masq_lib::main_tools::Command;
use std::io;

pub fn main() {
    let mut streams: StdStreams<'_> = StdStreams {
        stdin: &mut io::stdin(),
        stdout: &mut io::stdout(),
        stderr: &mut io::stderr(),
    };

    let mut command = Masq::new();
    let streams_ref: &mut StdStreams<'_> = &mut streams;
    let args: Vec<String> = std::env::args().collect();
    let exit_code = command.go(streams_ref, &args);
    ::std::process::exit(exit_code as i32);
}
