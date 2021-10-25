// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use multinode_integration_tests_lib::big_data_server::BigDataServer;
use multinode_integration_tests_lib::masq_node_cluster::MASQNodeCluster;
use multinode_integration_tests_lib::masq_real_node::NodeStartupConfigBuilder;
use node_lib::privilege_drop::{PrivilegeDropper, PrivilegeDropperReal};
use std::net::SocketAddr;
use std::time::Duration;

const NODE_MEMORY_REQUIRED: usize = 148_480 * 1024;

#[test]
fn downloading_a_file_larger_than_available_memory_doesnt_kill_node_but_makes_it_stronger() {
    if PrivilegeDropperReal::new().expect_privilege(false) {
        eprintln!("Skipping big-data test because we can't start a server without root privilege");
        return;
    }
    let mut cluster = MASQNodeCluster::start().expect("starting cluster");
    let maximum_kbytes_str = format!("{}", NODE_MEMORY_REQUIRED / 1024);
    let originating_node = cluster.start_real_node(
        NodeStartupConfigBuilder::zero_hop()
            .memory(&maximum_kbytes_str)
            .build(),
    );
    let socket_addr = SocketAddr::new(MASQNodeCluster::host_ip_addr(), 80);
    let _server = BigDataServer::start(socket_addr, NODE_MEMORY_REQUIRED);

    let mut client = originating_node.make_client(8080);
    client.set_timeout(Duration::from_secs(600)); // Lots of data; may take awhile
    let request = format!(
        "GET / HTTP/1.1\r\nHost: {}\r\n\r\n",
        MASQNodeCluster::host_ip_addr()
    );
    client.send_chunk(request.as_bytes());
    let len = client.wait_for_chunk().len();

    assert_eq!(len, 0); // data thrown away
}
