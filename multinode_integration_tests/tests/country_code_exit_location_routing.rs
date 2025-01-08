// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use std::collections::HashMap;
use masq_lib::messages::{CountryCodes, ToMessageBody, UiSetExitLocationRequest};
use masq_lib::utils::index_of;
use multinode_integration_tests_lib::masq_node::MASQNode;
use multinode_integration_tests_lib::masq_node_cluster::MASQNodeCluster;
use multinode_integration_tests_lib::masq_real_node::{CountryNetworkPack, make_consuming_wallet_info, MASQRealNode, NodeStartupConfigBuilder};
use std::net::Ipv4Addr;
use std::thread;
use std::time::Duration;

#[test]
fn http_end_to_end_routing_test_with_exit_location() {
    let mut countries = HashMap::from([
        ("czechia", CountryNetworkPack {
            name: "czechia".to_string(),
            subnet: Ipv4Addr::new(197, 198, 0, 0),
            dns_target: Ipv4Addr::new(197, 198, 0, 1),
        }),
        ("germany", CountryNetworkPack {
            name: "germany".to_string(),
            subnet: Ipv4Addr::new(57, 57, 0, 0),
            dns_target: Ipv4Addr::new(57, 57, 0, 1),
        })
    ]);
    let mut cluster = MASQNodeCluster::start_world(countries.clone()).unwrap();
    let cz_country_pack = countries.remove("czechia").unwrap();
    let de_country_pack = countries.remove("germany").unwrap();
    let first_node = cluster.start_real_node(
        NodeStartupConfigBuilder::standard()
            .chain(cluster.chain)
            .country_network(Some((cz_country_pack.clone(), Ipv4Addr::new(197, 198, 0, 2))))
            .build(),
    );
    let nodes = (0..6)
        .map(|index| {
            let country = match index <= 2 {
                true => Some((
                        cz_country_pack.clone(),
                        Ipv4Addr::new(197, 198, 0, index * 3 + 1u8),
                    )),
                false => Some((de_country_pack.clone(), Ipv4Addr::new(57, 57, 0, index * 3 + 1u8))),
            };
            cluster.start_real_node(
                NodeStartupConfigBuilder::standard()
                    .neighbor(first_node.node_reference())
                    .chain(cluster.chain)
                    .country_network(country)
                    .build(),
            )
        })
        .collect::<Vec<MASQRealNode>>();

    thread::sleep(Duration::from_millis(500 * (nodes.len() as u64)));

    let last_node = cluster.start_real_node(
        NodeStartupConfigBuilder::standard()
            .neighbor(nodes.last().unwrap().node_reference())
            .consuming_wallet_info(make_consuming_wallet_info("last_node"))
            .chain(cluster.chain)
            .country_network(None)
            // This line is commented out because for some reason the installation of iptables-persistent hangs forever on
            // bullseye-slim. Its absence means that the NodeStartupConfigBuilder::open_firewall_port() function won't work, but
            // at the time of this comment it's used only in this one place, where it adds no value. So we decided to
            // comment it out and continue adding value rather than spending time getting this to work for no profit.
            //            .open_firewall_port(8080)
            .build(),
    );
    MASQNodeCluster::interconnect_world_network("gemany", "test_node_7").unwrap();

    thread::sleep(Duration::from_millis(500));

    let ui = last_node.make_ui(51883);
    ui.send_request(
        UiSetExitLocationRequest {
            fallback_routing: false,
            exit_locations: vec![CountryCodes {
                country_codes: vec!["DE".to_string()],
                priority: 1,
            }],
            show_countries: false,
        }
        .tmb(0),
    );
    thread::sleep(Duration::from_millis(500));
    let mut client = last_node.make_client(8080, 5000);
    client.send_chunk(b"GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n");
    let response = client.wait_for_chunk();

    assert_eq!(
        index_of(&response, &b"57.57.0"[..]).is_some(),
        true,
        "Actual response:\n{}",
        String::from_utf8(response).unwrap()
    );
}
