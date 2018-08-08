// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
#![windows_subsystem = "windows"]
extern crate sub_lib;
extern crate node_lib;
extern crate tokio;
extern crate futures;

use std::io;
use futures::future::lazy;
use node_lib::server_initializer::ServerInitializer;
use sub_lib::main_tools::StdStreams;
use sub_lib::main_tools::Command;

pub fn main() {

    let main_fn = move || {
        let mut streams: StdStreams = StdStreams {
            stdin: &mut io::stdin(),
            stdout: &mut io::stdout(),
            stderr: &mut io::stderr(),
        };

        let mut command = ServerInitializer::new();
        let streams_ref: &mut StdStreams = &mut streams;
        command.go(streams_ref, &std::env::args().collect());

        tokio::spawn(command);
        Ok(())
    };


    tokio::run(lazy(main_fn));
    ::std::process::exit(1 as i32);
}
