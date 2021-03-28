// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use automap_lib::automap_core_functions::{AutomapParameters, tester_for, TestStatus};
use automap_lib::logger::initiate_logger;
use automap_lib::comm_layer::{Method, AutomapErrorCause};
use log::{info};

const SERVER_SOCKET_ADDRESS: &str = "54.212.109.41:8081";

pub fn main() {
    let parameters = AutomapParameters::new (std::env::args(), SERVER_SOCKET_ADDRESS);

    println!(
        "\nFor more detailed information about the course of this test, look inside the log.\n\
     You can also find warnings or recommendations in it if something is wrong. \n"
    );

    initiate_logger();

    let results = parameters.protocols.iter().map (|method| {
        let tester = tester_for(method);
        tester (TestStatus::new(), &parameters.test_parameters)
    })
    .collect::<Vec<Result<(), AutomapErrorCause>>>();
    let cumulative_success = results.iter().any(|r| r.is_ok());

    info!("Verdict{}:\n", if results.len() == 1 {""} else {"s"});
    parameters.protocols.iter().zip(results.into_iter()).for_each(|(method, result)| {
        report_on_method (method, result)
    });

    std::process::exit (if cumulative_success {0} else {1})
}

fn report_on_method(method: &Method, result: Result<(), AutomapErrorCause>) {
    let msg = match result {
        Ok(_) => "Fully operational".to_string(),
        Err(e) => format! ("{:?}", e),
    };
    info!("{}: {}", method, msg);
}
