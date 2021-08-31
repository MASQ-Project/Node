// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

use crate::port_exposer::PortExposer;

pub mod port_exposer;

fn main() {
    eprintln!("port_exposer started");

    let command = PortExposer::new();
    let exit_code = command.go(std::env::args().collect());
    ::std::process::exit(exit_code as i32);
}
