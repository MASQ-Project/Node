// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

use multinode_integration_tests_lib::masq_node::MASQNode;
use multinode_integration_tests_lib::masq_node_cluster::MASQNodeCluster;
use multinode_integration_tests_lib::masq_real_node::{
    make_consuming_wallet_info, MASQRealNode, NodeStartupConfigBuilder,
};
use multinode_integration_tests_lib::rest_utils::RestServer;
use std::thread;
use std::time::Duration;

const MAXIMUM_KBYTES: &'static str = "148480";
const REQUEST_BYTES: u64 = 157_286_400;

#[test]
#[ignore]
fn downloading_a_file_larger_than_available_memory_doesnt_kill_node_but_makes_it_stronger() {
    let mut cluster = MASQNodeCluster::start().expect("starting cluster");
    let originating_node = cluster.start_real_node(
        NodeStartupConfigBuilder::standard()
            .memory(MAXIMUM_KBYTES)
            .consuming_wallet_info(make_consuming_wallet_info(MAXIMUM_KBYTES))
            .build(),
    );

    let nodes = (0..6)
        .map(|_| {
            cluster.start_real_node(
                NodeStartupConfigBuilder::standard()
                    .neighbor(originating_node.node_reference())
                    .memory(MAXIMUM_KBYTES)
                    .build(),
            )
        })
        .collect::<Vec<MASQRealNode>>();

    let rest_server = RestServer { name: "ptolemy" };
    rest_server.start();

    thread::sleep(Duration::from_millis(500 * (nodes.len() as u64)));

    let address = format!(
        "http://{}/bytes/{}",
        rest_server.ip().unwrap(),
        REQUEST_BYTES
    );
    let response = reqwest::get(&address).unwrap();
    assert_eq!(response.content_length(), Some(REQUEST_BYTES));
}
