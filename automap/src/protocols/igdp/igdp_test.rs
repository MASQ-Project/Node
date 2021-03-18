// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::protocols::utils::IGDP_HEADER;
use igd::{search_gateway, SearchOptions};
use port_scanner::local_port_available;

pub fn test_igdp() {
    println!("{}", IGDP_HEADER);
    if !local_port_available(1900) {
        println!(
            "\
There are other applications running on the port 1900 which is needed for this test.\n
Exit their processes or try just right after the booting of your system. "
        );
        return;
    }
    let gate_way = search_gateway(SearchOptions::default());
    match gate_way
        .expect("unwrapping failed - should not happen")
        .get_external_ip()
    {
        Ok(ip) => println!(
            "\
Success
We probably got an echo of the ip address of your router: {}; check if that address is yours.",
            ip
        ),
        Err(error) => println!(
            "\n
Failure
Your device probably does not operate on this protocol or
the following error occurred: {:?}",
            error
        ),
    };
}
