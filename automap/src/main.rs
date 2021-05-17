// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use automap_lib::automap_core_functions::{tester_for, AutomapParameters, TestStatus};
use automap_lib::comm_layer::AutomapErrorCause;
use automap_lib::logger::initiate_logger;
use log::info;
use masq_lib::utils::AutomapProtocol;

const SERVER_SOCKET_ADDRESS: &str = "54.212.109.41:8081";

pub fn main() {
    let parameters = AutomapParameters::new(std::env::args(), SERVER_SOCKET_ADDRESS);

    println!("\nDetailed information about this run will appear in the log.");

    initiate_logger();

    let results = parameters
        .protocols
        .iter()
        .map(|method| {
            let tester = tester_for(method);
            tester(TestStatus::new(), &parameters.test_parameters)
        })
        .collect::<Vec<Result<(), AutomapErrorCause>>>();
    let cumulative_success = results.iter().any(|r| r.is_ok());

    info!("");
    info!("Verdict{}:", if results.len() == 1 { "" } else { "s" });
    parameters
        .protocols
        .iter()
        .zip(results.into_iter())
        .for_each(|(method, result)| report_on_method(method, result, &parameters));

    std::process::exit(if cumulative_success { 0 } else { 1 })
}

fn report_on_method(
    method: &AutomapProtocol,
    result: Result<(), AutomapErrorCause>,
    parameters: &AutomapParameters,
) {
    let tps = &parameters.test_parameters;
    let msg = match result {
        Ok(_) => {
            if tps.nopoke || tps.noremove || tps.user_specified_hole_port || tps.permanent {
                "Operational within specified limits".to_string()
            } else {
                "Fully operational".to_string()
            }
        }
        Err(e) => format!("{:?}", e),
    };
    info!("{}: {}", method, msg);
}
