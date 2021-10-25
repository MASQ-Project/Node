// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
#![cfg(target_os = "macos")]
extern crate dns_utility_lib;

mod utils;

use dns_utility_lib::dynamic_store_dns_modifier::StoreWrapper;
use dns_utility_lib::dynamic_store_dns_modifier::StoreWrapperReal;
use utils::TestCommand;

#[test]
fn macos_inspect_and_status_user_integration() {
    let store_wrapper = StoreWrapperReal::new("integration-test");
    let current_dns_ips = get_current_dns_ips(&store_wrapper);
    let expected_inspect_output = current_dns_ips.join("\n");
    let expected_status_output = if expected_inspect_output == "127.0.0.1" {
        "subverted".to_string()
    } else {
        "reverted".to_string()
    };

    let mut inspect_command = TestCommand::start("dns_utility", vec!["inspect"]);
    let exit_status = inspect_command.wait();
    let output = inspect_command.output();
    assert_eq!(exit_status, Some(0), "{}", output);
    assert_eq!(
        output,
        format!(
            "STANDARD OUTPUT:\n{}\n\nSTANDARD ERROR:\n\n",
            expected_inspect_output
        )
    );

    let mut status_command = TestCommand::start("dns_utility", vec!["status"]);
    let exit_status = status_command.wait();
    let output = status_command.output();
    assert_eq!(exit_status, Some(0), "{}", output);
    assert_eq!(
        output,
        format!(
            "STANDARD OUTPUT:\n{}\n\nSTANDARD ERROR:\n\n",
            expected_status_output
        )
    );
}

fn get_current_dns_ips(store_wrapper: &dyn StoreWrapper) -> Vec<String> {
    let state_global_network_ipv4 = store_wrapper
        .get_dictionary_string_cfpl("State:/Network/Global/IPv4")
        .unwrap();
    let primary_service_cfpl = state_global_network_ipv4.get("PrimaryService").unwrap();
    let primary_service_uuid = store_wrapper.cfpl_to_string(primary_service_cfpl).unwrap();
    let primary_service_path = format!("State:/Network/Service/{}/DNS", primary_service_uuid);

    let state_network_service_uuid_dns = store_wrapper
        .get_dictionary_string_cfpl(primary_service_path.as_str())
        .unwrap();
    let server_addresses_cfpl = state_network_service_uuid_dns
        .get("ServerAddresses")
        .unwrap();
    store_wrapper
        .cfpl_to_vec(server_addresses_cfpl)
        .unwrap()
        .iter()
        .map(|cfpl| store_wrapper.cfpl_to_string(cfpl).unwrap())
        .collect::<Vec<String>>()
}
