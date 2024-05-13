// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use automap_lib::automap_core_functions::{
    change_handler, run_probe_test, tester_for, AutomapParameters, TestStatus,
};
use automap_lib::comm_layer::AutomapErrorCause;
use automap_lib::control_layer::automap_control::{AutomapControl, AutomapControlReal};
use automap_lib::logger::initiate_logger;
use log::info;
use masq_lib::utils::AutomapProtocol;

const SERVER_SOCKET_ADDRESS: &str = "54.212.109.41:8081";
/*
If the probe server's virtual machine isn't running, get @BrianSoCal to start it. If it comes up
on an IP address different from the one above, change SERVER_SOCKET_ADDRESS to contain the IP
address where the VM lives. If the VM is running, but the probe server isn't, get hold of the
.pem file for the server, set its permissions to 700, and log onto the probe server's VM like this:

ssh -i masq-sandbox-bert.pem ubuntu@54.212.109.41

where `masq-sandbox-bert.pem` is the path to and name of the .pem file. You may need to correct the
IP address.

Once you're logged in, start the probe server like this:

nohup ./automap_server 0.0.0.0:8081 &

and log out.

If you decide to change the port the probe server runs on, be sure to open that port through the
AWS firewall.
 */

pub fn main() {
    let parameters = AutomapParameters::new(std::env::args(), SERVER_SOCKET_ADDRESS);

    println!("\nDetailed information about this run will appear in the log.");

    initiate_logger();

    if parameters.test_parameters.auto {
        automatic(parameters)
    } else {
        manual(parameters);
    }
}

fn manual(parameters: AutomapParameters) {
    let results = parameters
        .protocols
        .iter()
        .map(|method| {
            let tester = tester_for(method);
            tester(TestStatus::new(), &parameters.test_parameters)
        })
        .collect::<Vec<Result<(), AutomapErrorCause>>>();
    let cumulative_success = results.iter().any(|r| r.is_ok());

    info!("\nVerdict{}:", if results.len() == 1 { "" } else { "s" });
    parameters
        .protocols
        .iter()
        .zip(results)
        .for_each(|(method, result)| report_on_method(method, result, &parameters));

    std::process::exit(if cumulative_success { 0 } else { 1 })
}

fn automatic(parameters: AutomapParameters) {
    let status = TestStatus::new();
    let status = status.begin_attempt("Creating AutomapControl object".to_string());
    let mut automap_control = AutomapControlReal::new(None, Box::new(change_handler));
    let status = status.succeed();
    let status = status.begin_attempt("Seeking public IP".to_string());
    let public_ip = match automap_control.get_public_ip() {
        Ok(ip) => ip,
        Err(e) => {
            status.abort(e);
            return;
        }
    };
    let status = status.succeed();
    let status = status.begin_attempt(format!(
        "Adding a mapping through public IP {} for port {} using protocol {}",
        public_ip,
        parameters.test_parameters.hole_port,
        automap_control.get_mapping_protocol().unwrap()
    ));
    match automap_control.add_mapping(parameters.test_parameters.hole_port) {
        Ok(_) => (),
        Err(e) => {
            status.abort(e);
            return;
        }
    };
    let status = status.succeed();
    let status = run_probe_test(status, &parameters.test_parameters, public_ip);
    let status = status.begin_attempt("Removing all mappings".to_string());
    let _ = match automap_control.delete_mappings() {
        Ok(_) => status.succeed(),
        Err(e) => status.fail(e),
    };
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
