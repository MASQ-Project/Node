// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use dns_utility_lib::dns_utility::DnsUtility;
use masq_lib::command::{Command, StdStreams};
use std::io;

pub fn main() {
    let mut streams: StdStreams<'_> = StdStreams {
        stdin: &mut io::stdin(),
        stdout: &mut io::stdout(),
        stderr: &mut io::stderr(),
    };

    let mut command = DnsUtility::new();
    let streams_ref: &mut StdStreams<'_> = &mut streams;
    let args: Vec<String> = std::env::args().collect();
    let exit_code = command.go(streams_ref, &args);
    ::std::process::exit(i32::from(exit_code));
}
