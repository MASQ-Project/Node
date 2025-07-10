// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use std::time::Duration;

use masq_lib::messages::{
    FromMessageBody, ToMessageBody, UiConnectionChangeBroadcast, UiConnectionStage,
    UiConnectionStatusRequest, UiConnectionStatusResponse,
};
use masq_lib::utils::find_free_port;
use multinode_integration_tests_lib::masq_node::MASQNode;
use multinode_integration_tests_lib::masq_node_cluster::MASQNodeCluster;
use multinode_integration_tests_lib::masq_real_node::{
    ConsumingWalletInfo, MASQRealNode, NodeStartupConfigBuilder,
};

#[test]
fn connection_progress_is_properly_broadcast() {
    let ui_port = find_free_port();
    let mut cluster = MASQNodeCluster::start().unwrap();
    // Set up small preexisting network that is much too small to route
    let relay_2 = cluster.start_real_node(
        NodeStartupConfigBuilder::standard()
            .db_password(Some("relay_2"))
            .build()
    );
    let relay_1 = cluster.start_real_node(
        NodeStartupConfigBuilder::standard()
            .neighbor(relay_2.node_reference())
            .db_password(Some("relay_1"))
            .build(),
    );
    // Set up Node from which we will get connection-progress information
    // and hook a UI to it
    let subject = cluster.start_real_node(
        NodeStartupConfigBuilder::standard()
            .consuming_wallet_info(ConsumingWalletInfo::PrivateKey(
                "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF".to_string(),
            ))
            .neighbor(relay_1.node_reference())
            .db_password(Some("subject"))
            .ui_port(ui_port)
            .build(),
    );
    let ui_client = subject.make_ui(ui_port);

    // Hook up enough new Nodes to make the subject fully connected
    let _additional_nodes = (0..3)
        .into_iter()
        .map(|i| {
            cluster.start_real_node(
                NodeStartupConfigBuilder::standard()
                    .neighbor(relay_2.node_reference())
                    .db_password(Some(format!("additional_{}", i).as_str()))
                    .build(),
            )
        })
        .collect::<Vec<MASQRealNode>>();

    let message_body =
        ui_client.wait_for_specific_broadcast(vec!["connectionChange"], Duration::from_secs(5));
    let (ccb, _) = UiConnectionChangeBroadcast::fmb(message_body).unwrap();
    if ccb.stage == UiConnectionStage::ConnectedToNeighbor {
        let message_body =
            ui_client.wait_for_specific_broadcast(vec!["connectionChange"], Duration::from_secs(5));
        let (ccb, _) = UiConnectionChangeBroadcast::fmb(message_body).unwrap();
        assert_eq!(ccb.stage, UiConnectionStage::RouteFound);
    } else {
        assert_eq!(ccb.stage, UiConnectionStage::RouteFound);
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
