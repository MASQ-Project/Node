// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
extern crate sub_lib;
extern crate dns_utility_lib;

use std::io;
use sub_lib::main_tools::StdStreams;
use sub_lib::main_tools::Command;
use dns_utility_lib::dns_utility::DnsUtility;

pub fn main() {
    let mut streams: StdStreams = StdStreams {
        stdin: &mut io::stdin (),
        stdout: &mut io::stdout (),
        stderr: &mut io::stderr ()
    };

    let mut command = DnsUtility::new ();
    let streams_ref: &mut StdStreams = &mut streams;
    let exit_code = command.go (streams_ref, &std::env::args ().collect ());
    ::std::process::exit (exit_code as i32);
}
