// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
#![windows_subsystem = "windows"]
use actix;
use actix::System;
use futures::future::Future;
use node_lib::server_initializer::ServerInitializer;
use node_lib::sub_lib::main_tools::Command;
use node_lib::sub_lib::main_tools::StdStreams;
use std::io;

pub fn main() {
    let system = System::new("main");
    let mut streams: StdStreams<'_> = StdStreams {
        stdin: &mut io::stdin(),
        stdout: &mut io::stdout(),
        stderr: &mut io::stderr(),
    };

    let streams_ref: &mut StdStreams<'_> = &mut streams;
    let args = &std::env::args().collect();
    let mut server_initializer = ServerInitializer::new(args, streams_ref);
    server_initializer.go(streams_ref, args);

    actix::spawn(server_initializer.map_err(|_| {
        System::current().stop();
    }));

    system.run();
    ::std::process::exit(1 as i32);
}
