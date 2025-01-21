// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use std::thread;
use std::time::Duration;

use masq_lib::messages::{CountryCodes, ToMessageBody, UiSetConfigurationRequest, UiSetExitLocationRequest};
use masq_lib::test_utils::utils::TEST_DEFAULT_MULTINODE_CHAIN;
use multinode_integration_tests_lib::masq_node::{MASQNode, PortSelector};
use multinode_integration_tests_lib::masq_node_cluster::MASQNodeCluster;
use multinode_integration_tests_lib::neighborhood_constructor::construct_neighborhood;
use node_lib::sub_lib::cryptde_null::CryptDENull;
use node_lib::sub_lib::hopper::MessageTypeLite;
use node_lib::sub_lib::neighborhood::RatePack;
use node_lib::test_utils::neighborhood_test_utils::{db_from_node, make_node_record};

#[test]
fn http_end_to_end_routing_test_with_exit_location() {
    let mut cluster = MASQNodeCluster::start().unwrap();
    let first_neighbor = make_node_record(2345, true);
    let mut exit_fr = make_node_record(3456, false);
    exit_fr.inner.country_code_opt = Some("FR".to_string());
    exit_fr.inner.rate_pack = RatePack {
        routing_byte_rate: 100,
        routing_service_rate: 100,
        exit_byte_rate: 100,
        exit_service_rate: 100,
    };
    let mut exit_de = make_node_record(4567, false);
    exit_de.inner.country_code_opt = Some("DE".to_string());
    exit_de.inner.rate_pack = RatePack {
        routing_byte_rate: 1,
        routing_service_rate: 1,
        exit_byte_rate: 1,
        exit_service_rate: 1,
    };
    exit_fr.resign();
    exit_de.resign();

    let dest_db = {
        let subject_node_record = make_node_record(1234, true);
        let mut dest_db = db_from_node(&subject_node_record);
        dest_db.add_node(first_neighbor.clone()).unwrap();
        dest_db.add_arbitrary_full_neighbor(
            subject_node_record.public_key(),
            first_neighbor.public_key(),
        );
        dest_db.add_node(exit_fr.clone()).unwrap();
        dest_db.add_arbitrary_full_neighbor(
            first_neighbor.public_key(),
            exit_fr.public_key()
        );
        dest_db.add_node(exit_de.clone()).unwrap();
        dest_db.add_arbitrary_full_neighbor(
            first_neighbor.public_key(),
            exit_de.public_key()
        );
        dest_db
    };

    let (_, subject_real_node, mut mock_nodes) =
        construct_neighborhood(&mut cluster, dest_db, vec![], |config_builder|{
            config_builder.ui_port(51883).build()
        });

    thread::sleep(Duration::from_millis(500 * 6u64));

    let ui = subject_real_node.make_ui(51883);
    ui.send_request(
      UiSetConfigurationRequest {
          name: "min-hops".to_string(),
          value: "2".to_string(),
      }.tmb(0)
    );
    ui.send_request(
        UiSetExitLocationRequest {
            fallback_routing: false,
            exit_locations: vec![CountryCodes {
                country_codes: vec!["FR".to_string()],
                priority: 1,
            }],
            show_countries: false,
        }
        .tmb(1),
    );
    thread::sleep(Duration::from_millis(500));
    let mut client = subject_real_node.make_client(8080, 5000);
    client.send_chunk(b"GET /ip HTTP/1.1\r\nHost: httpbin.org\r\n\r\n");

    let neighbor_mock = mock_nodes.remove(first_neighbor.public_key()).unwrap();
    let mut expired_cores_package = neighbor_mock
        .wait_for_specific_package(
            MessageTypeLite::ClientRequest,
            subject_real_node.socket_addr(PortSelector::First),
            Some(CryptDENull::from(exit_fr.public_key(), TEST_DEFAULT_MULTINODE_CHAIN))
        ).unwrap();

    let last_hop = expired_cores_package.remaining_route.shift(&CryptDENull::from(neighbor_mock.main_public_key(), TEST_DEFAULT_MULTINODE_CHAIN)).unwrap();
    assert_eq!(last_hop.public_key, exit_fr.inner.public_key)
    //println!("{:#?}", last_hop.public_key);
}
