// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use std::time::Duration;

use log::Level;
use regex::escape;
use serde_derive::Serialize;

use masq_lib::messages::{FromMessageBody, ScanType, ToMessageBody, UiScanRequest, UiScanResponse};
use masq_lib::utils::find_free_port;
use multinode_integration_tests_lib::masq_node::MASQNode;
use multinode_integration_tests_lib::masq_node::MASQNodeUtils;
use multinode_integration_tests_lib::masq_node_cluster::MASQNodeCluster;
use multinode_integration_tests_lib::masq_real_node::{
    ConsumingWalletInfo, NodeStartupConfigBuilder,
};
use multinode_integration_tests_lib::mock_blockchain_client_server::MBCSBuilder;
use multinode_integration_tests_lib::utils::{config_dao, database_conn, receivable_dao};

#[test]
fn debtors_are_credited_once_but_not_twice() {
    let mbcs_port = find_free_port();
    let ui_port = find_free_port();
    // Create and initialize mock blockchain client: prepare a receivable at block 2000
    let _blockchain_client_server = MBCSBuilder::new(mbcs_port)
        .response(
            vec![LogObject {
                removed: false,
                log_index: Some("0x20".to_string()),
                transaction_index: Some("0x30".to_string()),
                transaction_hash: Some(
                    "0x2222222222222222222222222222222222222222222222222222222222222222"
                        .to_string(),
                ),
                block_hash: Some(
                    "0x1111111111111111111111111111111111111111111111111111111111111111"
                        .to_string(),
                ),
                block_number: Some("0x7D0".to_string()), // 2000 decimal
                address: "0x3333333333333333333333333333333333333333".to_string(),
                data: "0x000000000000000000000000000000000000000000000000000000003b5dc100"
                    .to_string(),
                topics: vec![
                    "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef".to_string(),
                    "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef".to_string(),
                ],
            }],
            1,
        )
        .start();
    // Start a real Node pointing at the mock blockchain client with a start block of 1000
    let mut cluster = MASQNodeCluster::start().unwrap();
    let node = cluster.start_real_node(
        NodeStartupConfigBuilder::standard()
            .log_level(Level::Debug)
            .scans(false)
            .blockchain_service_url(format!(
                "http://{}:{}",
                MASQNodeCluster::host_ip_addr(),
                mbcs_port
            ))
            .ui_port(ui_port)
            .build(),
    );
    // Get direct access to the RECEIVABLE table
    {
        let conn = database_conn(&node);
        // Create a receivable record to match the client receivable
        let mut stmt = conn
            .prepare(
                "insert into receivable (\
                wallet_address, \
                balance, \
                last_received_timestamp\
            ) values (\
                '0x3333333333333333333333333333333333333333',
                1000000,
                15000000
            )",
            )
            .unwrap();
        match stmt.execute([]) {
            Ok(_) => (),
            Err(e) => {
                let msg = format!("{:?}", e);
                panic!("Couldn't execute insert statement: {:?}", msg);
            }
        }
        let mut stmt = conn
            .prepare("update config set value = '1000' where name = 'start_block'")
            .unwrap();
        match stmt.execute([]) {
            Ok(_) => (),
            Err(e) => {
                let msg = format!("{:?}", e);
                panic!("Couldn't execute update statement: {:?}", msg);
            }
        }
    }
    {
        // Use the config DAO to verify that the start block was correctly set
        let config_dao = config_dao(&node);
        assert_eq!(
            config_dao.get("start_block").unwrap().value_opt.unwrap(),
            "1000"
        );
    }
    let ui_client = node.make_ui(ui_port);
    // Command a scan log
    ui_client.send_request(
        UiScanRequest {
            scan_type: ScanType::Receivables,
        }
        .tmb(1235),
    );
    let response = ui_client.wait_for_response(1235, Duration::from_secs(10));
    let (_, context_id) = UiScanResponse::fmb(response).unwrap();
    assert_eq!(context_id, 1235);
    // Kill the real Node
    node.kill_node();
    // Use the receivable DAO to verify that the receivable's balance has been adjusted
    {
        let receivable_dao = receivable_dao(&node);
        let receivable_accounts = receivable_dao.receivables();
        assert_eq!(receivable_accounts.len(), 1);
        assert_eq!(receivable_accounts[0].balance, 1000000); // this will probably fail
    }
    {
        // Use the config DAO to verify that the start block has been advanced to 2001
        let config_dao = config_dao(&node);
        assert_eq!(
            config_dao.get("start_block").unwrap().value_opt.unwrap(),
            "2001"
        );
    }
}

#[test]
fn blockchain_bridge_logs_when_started() {
    let mut cluster = MASQNodeCluster::start().unwrap();
    let private_key = "0011223300112233001122330011223300112233001122330011223300112233";
    let subject = cluster.start_real_node(
        NodeStartupConfigBuilder::zero_hop()
            .consuming_wallet_info(ConsumingWalletInfo::PrivateKey(private_key.to_string()))
            .chain(cluster.chain)
            .build(),
    );

    let escaped_pattern = escape(&format!(
        "DEBUG: BlockchainBridge: Received BindMessage; consuming wallet address {}",
        subject.consuming_wallet().unwrap()
    ));
    MASQNodeUtils::wrote_log_containing(
        subject.name(),
        &escaped_pattern,
        Duration::from_millis(1000),
    )
}

#[derive(Serialize)]
struct LogObject {
    // Strings are all hexadecimal
    removed: bool,
    #[serde(rename = "logIndex")]
    log_index: Option<String>,
    #[serde(rename = "transactionIndex")]
    transaction_index: Option<String>,
    #[serde(rename = "transactionHash")]
    transaction_hash: Option<String>,
    #[serde(rename = "blockHash")]
    block_hash: Option<String>,
    #[serde(rename = "blockNumber")]
    block_number: Option<String>,
    address: String,
    data: String,
    topics: Vec<String>,
}
