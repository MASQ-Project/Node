// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
#![windows_subsystem = "windows"]

use tokio;

use futures::future::lazy;
use node_lib::server_initializer::ServerInitializer;
use node_lib::sub_lib::main_tools::Command;
use node_lib::sub_lib::main_tools::StdStreams;
use std::io;

pub fn main() {
    let main_fn = move || {
        let mut streams: StdStreams<'_> = StdStreams {
            stdin: &mut io::stdin(),
            stdout: &mut io::stdout(),
            stderr: &mut io::stderr(),
        };

        let mut command = ServerInitializer::new();
        let streams_ref: &mut StdStreams<'_> = &mut streams;
        command.go(streams_ref, &std::env::args().collect());

        tokio::spawn(command);
        Ok(())
    };

    tokio::run(lazy(main_fn));
    ::std::process::exit(1 as i32);
}
