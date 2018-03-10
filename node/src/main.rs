// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
#![windows_subsystem = "windows"]
extern crate sub_lib;
extern crate node_lib;

use std::io;
use sub_lib::main_tools::StdStreams;
use sub_lib::main_tools::Command;
use node_lib::server_initializer::ServerInitializer;

pub fn main() {
    let mut streams: StdStreams = StdStreams {
        stdin: &mut io::stdin (),
        stdout: &mut io::stdout (),
        stderr: &mut io::stderr ()
    };

    let mut command = ServerInitializer::new ();
    let streams_ref: &mut StdStreams = &mut streams;
    let exit_code = command.go (streams_ref, &std::env::args ().collect ());
    ::std::process::exit (exit_code as i32);
}
