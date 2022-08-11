// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use std::time::Duration;

use masq_lib::messages::{
    FromMessageBody, ToMessageBody, UiConnectionChangeBroadcast, UiConnectionStage,
    UiConnectionStatusRequest, UiConnectionStatusResponse,
};
use masq_lib::utils::find_free_port;
use multinode_integration_tests_lib::masq_node::MASQNode;
use multinode_integration_tests_lib::masq_node_cluster::MASQNodeCluster;
use multinode_integration_tests_lib::masq_real_node::NodeStartupConfigBuilder;

#[test]
fn connection_progress_is_properly_broadcast() {
    let ui_port = find_free_port();
    let mut cluster = MASQNodeCluster::start().unwrap();
    // Set up small preexisting network that is much too small to route
    let relay_2 = cluster.start_real_node(NodeStartupConfigBuilder::standard().build());
    let relay_1 = cluster.start_real_node(
        NodeStartupConfigBuilder::standard()
            .neighbor(relay_2.node_reference())
            .build(),
    );
    // Set up Node from which we will get connection-progress information
    // and hook a UI to it
    let subject = cluster.start_real_node(
        NodeStartupConfigBuilder::standard()
            .neighbor(relay_1.node_reference())
            .ui_port(ui_port)
            .build(),
    );
    let ui_client = subject.make_ui(ui_port);

    // Hook up an exit Node to make the Node fully connected
    let _exit_node = cluster.start_real_node(
        NodeStartupConfigBuilder::standard()
            .neighbor(relay_2.node_reference())
            .build(),
    );

    let message_body =
        ui_client.wait_for_specific_broadcast(vec!["connectionChange"], Duration::from_secs(5));
    let (ccb, _) = UiConnectionChangeBroadcast::fmb(message_body).unwrap();
    if ccb.stage == UiConnectionStage::ConnectedToNeighbor {
        let message_body =
            ui_client.wait_for_specific_broadcast(vec!["connectionChange"], Duration::from_secs(5));
        let (ccb, _) = UiConnectionChangeBroadcast::fmb(message_body).unwrap();
        assert_eq!(ccb.stage, UiConnectionStage::ThreeHopsRouteFound);
    } else {
        assert_eq!(ccb.stage, UiConnectionStage::ThreeHopsRouteFound);
    }
}

#[test]
fn connection_progress_can_be_requested() {
    let ui_port = find_free_port();
    let mut cluster = MASQNodeCluster::start().unwrap();
    // Set up Node from which we will get connection-progress information
    // and hook a UI to it
    let subject = cluster.start_real_node(
        NodeStartupConfigBuilder::standard()
            .ui_port(ui_port)
            .build(),
    );
    let ui_client = subject.make_ui(ui_port);

    ui_client.send_request(UiConnectionStatusRequest {}.tmb(1));
    let message_body = ui_client.wait_for_response(1, Duration::from_secs(1));

    let (message, context_id) = UiConnectionStatusResponse::fmb(message_body).unwrap();
    assert_eq!(message.stage, UiConnectionStage::NotConnected);
    assert_eq!(context_id, 1);
}
