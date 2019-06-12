// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

use multinode_integration_tests_lib::rest_utils::RestServer;
use multinode_integration_tests_lib::substratum_node::SubstratumNode;
use multinode_integration_tests_lib::substratum_node_cluster::SubstratumNodeCluster;
use multinode_integration_tests_lib::substratum_real_node::{
    NodeStartupConfigBuilder, SubstratumRealNode,
};
use node_lib::test_utils::test_utils::read_until_timeout;
use std::thread;
use std::time::Duration;

#[test]
fn downloading_a_file_larger_than_available_memory_doesnt_kill_node_but_makes_it_stronger() {
    let mut cluster = SubstratumNodeCluster::start().expect("starting cluster");
    let maximum_kbytes = "51200";
    let originating_node = cluster.start_real_node(
        NodeStartupConfigBuilder::standard()
            .memory(maximum_kbytes)
            .build(),
    );

    let nodes = (0..6)
        .map(|_| {
            cluster.start_real_node(
                NodeStartupConfigBuilder::standard()
                    .neighbor(originating_node.node_reference())
                    .memory(maximum_kbytes)
                    .build(),
            )
        })
        .collect::<Vec<SubstratumRealNode>>();

    let rest_server = RestServer { name: "ptolemy" };
    rest_server.start();

    thread::sleep(Duration::from_millis(500 * (nodes.len() as u64)));

    let get = format!(
        "GET /bytes/1307200 HTTP/1.1\r\nHost: {}\r\n\r\n",
        rest_server.ip().unwrap().trim()
    );

    let mut client = originating_node.make_client(8080);
    client.send_chunk(Vec::from(get.as_bytes()));
    let response = read_until_timeout(client.get_stream());

    assert!(
        response.len() > 1_307_200,
        format!(
            "Response length of {} was less than 1307200",
            response.len()
        )
    );
}
