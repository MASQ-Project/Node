// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
use multinode_integration_tests_lib::masq_node::{MASQNode, NodeReference};
use multinode_integration_tests_lib::masq_node_cluster::MASQNodeCluster;
use multinode_integration_tests_lib::masq_real_node::{
    make_consuming_wallet_info, make_earning_wallet_info, MASQRealNode, NodeStartupConfigBuilder,
    STANDARD_CLIENT_TIMEOUT_MILLIS,
};
use multinode_integration_tests_lib::utils::{payable_dao, receivable_dao};
use node_lib::accountant::db_access_objects::payable_dao::PayableAccount;
use node_lib::accountant::db_access_objects::receivable_dao::ReceivableAccount;
use node_lib::accountant::db_access_objects::utils::CustomQuery;
use node_lib::sub_lib::neighborhood::RatePack;
use node_lib::sub_lib::wallet::Wallet;
use std::collections::HashMap;
use std::thread;
use std::time::{Duration, SystemTime};
use itertools::Itertools;

#[test]
fn provided_and_consumed_services_are_recorded_in_databases() {
    let mut cluster = MASQNodeCluster::start().unwrap();

    let originating_node = start_lonely_real_node(&mut cluster);
    let non_originating_nodes = (0..6)
        .into_iter()
        .map(|_| start_real_node(&mut cluster, originating_node.node_reference()))
        .collect::<Vec<MASQRealNode>>();

    //TODO card #803 Create function wait_for_gossip
    thread::sleep(Duration::from_secs(10));

    let mut client = originating_node.make_client(8080, STANDARD_CLIENT_TIMEOUT_MILLIS);
    client.set_timeout(Duration::from_secs(10));
    let request = "GET /index.html HTTP/1.1\r\nHost: www.testingmcafeesites.com\r\n\r\n".as_bytes();

    client.send_chunk(request);
    let response = String::from_utf8(client.wait_for_chunk()).unwrap();
    assert!(
        response.contains("<title>URL for testing.</title>"),
        "Not from www.testingmcafeesites.com:\n{}",
        response
    );

    // Waiting until everybody has finished generating payables and receivables
    thread::sleep(Duration::from_secs(10));

    // get all payables from originating node
    let payables = non_pending_payables(&originating_node);

    // get all receivables from all other nodes
    let receivable_nodes = non_originating_nodes
        .iter()
        .flat_map(|node| {
            receivables(node)
                .into_iter()
                .map(move |receivable_account| {
                    (node.earning_wallet(), (node.name().to_string(), receivable_account.balance_wei))
                })
        })
        .collect::<HashMap<Wallet, (String, i128)>>();

    // check that each payable has a receivable
    assert_eq!(
        payables.len(),
        receivable_nodes.len(),
        "Lengths of payables and receivables should match.\nPayables: {:?}\nReceivables: {:?}",
        payables,
        receivable_nodes
    );
    assert!(
        receivable_nodes.len() >= 3, // minimum service list: route, route, exit.
        "not enough receivables found {:?}",
        receivable_nodes
    );

    let messages = payables.iter().flat_map(|payable| {
        let payable_balance = payable.balance_wei;
        let (non_originating_node_name, receivable_balance) = receivable_nodes.get(&payable.wallet).unwrap().clone();
        if payable_balance != receivable_balance as u128 {
            Some(format!(
                "Payable for {} ({}) does not match receivable for {} ({})",
                originating_node.name(), payable_balance, non_originating_node_name, receivable_balance
            ))
        } else {
            None
        }
    })
        .collect_vec();

    assert!(messages.is_empty(), "{:#?}", messages);
}

fn non_pending_payables(node: &MASQRealNode) -> Vec<PayableAccount> {
    let payable_dao = payable_dao(node.name());
    payable_dao.non_pending_payables()
}

fn receivables(node: &MASQRealNode) -> Vec<ReceivableAccount> {
    let receivable_dao = receivable_dao(node.name());
    receivable_dao
        .custom_query(CustomQuery::RangeQuery {
            min_age_s: 0,
            max_age_s: i64::MAX as u64,
            min_amount_gwei: i64::MIN,
            max_amount_gwei: i64::MAX,
            timestamp: SystemTime::now(),
        })
        .unwrap_or_default()
}

pub fn start_lonely_real_node(cluster: &mut MASQNodeCluster) -> MASQRealNode {
    let index = cluster.next_index();
    cluster.start_real_node(
        NodeStartupConfigBuilder::standard()
            .earning_wallet_info(make_earning_wallet_info(&index.to_string()))
            .consuming_wallet_info(make_consuming_wallet_info(&index.to_string()))
            .chain(cluster.chain)
            .build(),
    )
}

pub fn start_real_node(cluster: &mut MASQNodeCluster, neighbor: NodeReference) -> MASQRealNode {
    let index = cluster.next_index();
    cluster.start_real_node(
        NodeStartupConfigBuilder::standard()
            .db_password(None)
            .neighbor(neighbor)
            .earning_wallet_info(make_earning_wallet_info(&index.to_string()))
            .chain(cluster.chain)
            .rate_pack(RatePack {
                //TODO in case we are going to test more scenarios with need of higher RatePack:
                // create method in RatePack to return Default RatePack increased by some value or factor
                // make sure there is a test for this method
                routing_byte_rate: 2000000000,
                routing_service_rate: 2000000000,
                exit_byte_rate: 2000000000,
                exit_service_rate: 2000000000,
            })
            .build(),
    )
}
