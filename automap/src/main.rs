// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use std::{io, process};
use std::io::Write;
use std::net::SocketAddr;
use std::str::FromStr;

use automap_lib::automap_core_functions::{test_igdp, test_pcp, test_pmp};
use automap_lib::logger::initiate_logger;
use automap_lib::probe_researcher::{close_exposed_port, prepare_router_or_report_failure, researcher_with_probe};
use masq_lib::utils::find_free_port;

const SERVER_SOCKET_ADDRESS: &str = "54.212.109.41:8081";

pub fn main() {
    let mut stdout = io::stdout();
    let mut stderr = io::stderr();

    let (test_port, manual_port) = if let Some(value) = std::env::args().skip(1).take(1).find(|_| true)
    {
        match value.parse::<u16>() {
            Ok(num) => (num, true),
            Err(e) => {
                println!("invalid value ({}) for a port: {}", value, e);
                process::exit(1)
            }
        }
    } else {
        (find_free_port(), false)
    };

    println!(
        "\nFor more detailed information of the course of this test, look inside the log.\n\
     You can also find warnings or recommendations in it if something is wrong. \n"
    );

    initiate_logger();

    let cumulative_success = match prepare_router_or_report_failure(
        test_port,
        manual_port,
        vec![
            Box::new(test_pcp),
            Box::new(test_pmp),
            Box::new(test_igdp),
        ],
    ) {
        Ok(parameter_clusters) => {
            let server_address =
                SocketAddr::from_str(SERVER_SOCKET_ADDRESS).expect("server address in bad format");
            parameter_clusters.into_iter().map (|mut parameter_cluster| {
                let success = researcher_with_probe(
                    &mut stdout,
                    &mut stderr,
                    server_address,
                    &mut parameter_cluster,
                    5000,
                );
                let closing_result = close_exposed_port(&mut stdout, &mut stderr, parameter_cluster);
                match (success, closing_result) {
                    (true, Ok(_)) => true,
                    _ => false,
                }
            })
            .any (|flag| flag)
        }

        Err(e) => {
            e.into_iter()
                .for_each(|s| stderr.write_all(s.as_bytes()).expect("write_all failed"));
            stderr.flush().expect("failed to flush stderr");
            false
        }
    };

    std::process::exit (if cumulative_success {0} else {1})
}
