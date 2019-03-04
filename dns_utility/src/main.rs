// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

use dns_utility_lib::dns_utility::DnsUtility;
use std::io;
use dns_utility_lib::main_tools::Command;
use dns_utility_lib::main_tools::StdStreams;

pub fn main() {
    let mut streams: StdStreams<'_> = StdStreams {
        stdin: &mut io::stdin(),
        stdout: &mut io::stdout(),
        stderr: &mut io::stderr(),
    };

    let mut command = DnsUtility::new();
    let streams_ref: &mut StdStreams<'_> = &mut streams;
    let exit_code = command.go(streams_ref, &std::env::args().collect());
    ::std::process::exit(exit_code as i32);
}
