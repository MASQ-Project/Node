// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use automap_lib::automap_core_functions::{test_igdp, test_pcp, test_pmp};
use automap_lib::probe_researcher::{
    close_exposed_port, prepare_router_or_report_failure, probe_researcher,
};
use std::io;
use std::io::Write;
use std::net::SocketAddr;
use std::str::FromStr;

const SERVER_SOCKET_ADDRESS: &str = "1.2.3.4:5000";

pub fn main() {
    let mut stdout = io::stdout();
    let mut stderr = io::stderr();

    match prepare_router_or_report_failure(
        Box::new(test_pcp),
        Box::new(test_pmp),
        Box::new(test_igdp),
    ) {
        Ok(mut first_level) => {
            let server_address =
                SocketAddr::from_str(SERVER_SOCKET_ADDRESS).expect("server address in bad format");
            let success = probe_researcher(
                &mut stdout,
                &mut stderr,
                server_address,
                &mut first_level,
                5000,
            );
            let closing_result = close_exposed_port(&mut stdout, &mut stderr, first_level);
            match (success, closing_result) {
                (true, Ok(_)) => std::process::exit(0),
                (true, Err(_)) => std::process::exit(1),
                (false, Ok(_)) => std::process::exit(1),
                (false, Err(_)) => std::process::exit(1),
            }
        }

        Err(e) => {
            e.into_iter()
                .for_each(|s| stderr.write_all(s.as_bytes()).expect("write_all failed"));
            stderr.flush().expect("failed to flush stderr");
            std::process::exit(1)
        }
    }
}
