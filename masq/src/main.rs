// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use masq_cli_lib::non_interactive_mode::Main;
use masq_lib::command::{Command, StdStreams};
use std::io;

fn main() {
    let mut streams: StdStreams<'_> = StdStreams {
        stdin: &mut io::stdin(),
        stdout: &mut io::stdout(),
        stderr: &mut io::stderr(),
    };

    let args: Vec<String> = std::env::args().collect();
    let streams_ref: &mut StdStreams<'_> = &mut streams;
    let exit_code = Main::default().go(streams_ref, &args);
    ::std::process::exit(i32::from(exit_code));
}
