// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use std::collections::HashMap;

use masq_lib::utils::index_of;
use multinode_integration_tests_lib::masq_node::{MASQNode, MASQNodeUtils};
use multinode_integration_tests_lib::masq_node_cluster::MASQNodeCluster;
use multinode_integration_tests_lib::masq_real_node::{CountryNetworkPack, make_consuming_wallet_info, MASQRealNode, NodeStartupConfigBuilder};
use std::net::Ipv4Addr;
use std::thread;
use std::time::Duration;
use masq_lib::messages::{CountryCodes, ToMessageBody, UiSetExitLocationRequest};
use multinode_integration_tests_lib::neighborhood_constructor::{construct_neighborhood, do_not_modify_config};
use node_lib::neighborhood::node_record::NodeRecord;
use node_lib::sub_lib::cryptde::PublicKey;
use node_lib::test_utils::neighborhood_test_utils::{db_from_node, make_node_record};

#[test]
fn http_end_to_end_routing_test_with_exit_location() {
    let mut countries = HashMap::from([
        ("czechia", CountryNetworkPack {
            name: "czechia".to_string(),
            subnet: Ipv4Addr::new(146, 102, 0, 0),
            dns_target: Ipv4Addr::new(1, 1, 1, 1),
            connect: "france".to_string(),
            subnet_connect: Ipv4Addr::new(57, 30, 0, 0),
            networks: HashMap::new(),
        }),
        ("france", CountryNetworkPack {
            name: "france".to_string(),
            subnet: Ipv4Addr::new(57, 30, 0, 0),
            dns_target: Ipv4Addr::new(1, 1, 1, 1),
            connect: "czechia".to_string(),
            subnet_connect: Ipv4Addr::new(146, 102, 0, 0),
            networks: HashMap::new(),
        })
    ]);
    MASQNodeUtils::clean_up_existing_container("router");
    let mut cluster = MASQNodeCluster::start_world(countries.clone()).unwrap();
    let _ = MASQNodeCluster::start_router_container(&mut countries).unwrap();
    let cz_country_pack = countries.remove("czechia").unwrap();
    let fr_country_pack = countries.remove("france").unwrap();
    let first_node = cluster.start_real_node(
        NodeStartupConfigBuilder::standard()
            .chain(cluster.chain)
            .country_network(Some((cz_country_pack.clone(), Ipv4Addr::new(146, 102, 0, 3))))
            .build(),
    );
    let nodes = (0..6)
        .map(|index| {
            let country = match index <= 2 {
                true => Some((
                        cz_country_pack.clone(),
                        Ipv4Addr::new(146, 102, 0, 3 + index + 1u8),
                    )),
                false => Some((fr_country_pack.clone(), Ipv4Addr::new(57, 30, 0, 3 + index + 1u8))),
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

    let last_node = cluster.start_real_node(
        NodeStartupConfigBuilder::standard()
            .neighbor(nodes.last().unwrap().node_reference())
            .consuming_wallet_info(make_consuming_wallet_info("last_node"))
            .chain(cluster.chain)
            .ui_port(51883)
            .country_network(Some((fr_country_pack.clone(), Ipv4Addr::new(57, 30, 0, 22))))
            // This line is commented out because for some reason the installation of iptables-persistent hangs forever on
            // bullseye-slim. Its absence means that the NodeStartupConfigBuilder::open_firewall_port() function won't work, but
            // at the time of this comment it's used only in this one place, where it adds no value. So we decided to
            // comment it out and continue adding value rather than spending time getting this to work for no profit.
            //            .open_firewall_port(8080)
            .build(),
    );

    thread::sleep(Duration::from_millis(5000 * (nodes.len() as u64)));

    let ui = last_node.make_ui(51883);
    ui.send_request(
        UiSetExitLocationRequest {
            fallback_routing: false,
            exit_locations: vec![CountryCodes {
                country_codes: vec!["CZ".to_string()],
                priority: 1,
            }],
            show_countries: false,
        }
        .tmb(0),
    );
    thread::sleep(Duration::from_millis(500));
    let mut client = last_node.make_client(8080, 5000);
    client.send_chunk(b"GET /ip HTTP/1.1\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7\r\nAccept-Language: cs-CZ,cs;q=0.9,en;q=0.8,sk;q=0.7\r\nCache-Control: max-age=0\r\nConnection: keep-alive\r\nHost: httpbin.org\r\nUpgrade-Insecure-Requests: 1\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36\r\n\r\n");
    let response = client.wait_for_chunk();

    assert_eq!(
        index_of(&response, &b"57.30.0"[..]).is_some(),
        true,
        "Actual response:\n{}",
        String::from_utf8(response).unwrap()
    );
}
