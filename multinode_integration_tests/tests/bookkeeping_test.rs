// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use multinode_integration_tests_lib::substratum_node::{
    NodeReference, SubstratumNode, SubstratumNodeUtils,
};
use multinode_integration_tests_lib::substratum_node_cluster::SubstratumNodeCluster;
use multinode_integration_tests_lib::substratum_real_node::{
    make_consuming_wallet_info, make_earning_wallet_info, NodeStartupConfigBuilder,
    SubstratumRealNode,
};
use node_lib::accountant::payable_dao::{PayableAccount, PayableDao, PayableDaoReal};
use node_lib::accountant::receivable_dao::{ReceivableAccount, ReceivableDao, ReceivableDaoReal};
use node_lib::database::db_initializer::{DbInitializer, DbInitializerReal};
use node_lib::sub_lib::wallet::Wallet;
use std::collections::HashMap;
use std::thread;
use std::time::Duration;

#[test]
fn provided_and_consumed_services_are_recorded_in_databases() {
    let mut cluster = SubstratumNodeCluster::start().unwrap();

    let originating_node = start_lonely_real_node(&mut cluster);
    let non_originating_nodes = (0..6)
        .into_iter()
        .map(|_| start_real_node(&mut cluster, originating_node.node_reference()))
        .collect::<Vec<SubstratumRealNode>>();

    thread::sleep(Duration::from_millis(2000));

    let mut client = originating_node.make_client(8080);
    let request = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".as_bytes();

    client.send_chunk(request);
    let response = String::from_utf8(client.wait_for_chunk()).unwrap();
    assert!(
        response.contains(
            "This domain is established to be used for illustrative examples in documents."
        ),
        "Not from example.com:\n{}",
        response
    );

    // get all payables from originating node
    let payables = non_pending_payables(&originating_node, cluster.chain_id);

    // get all receivables from all other nodes
    let receivable_balances = non_originating_nodes
        .iter()
        .flat_map(|node| {
            receivables(node, cluster.chain_id)
                .into_iter()
                .map(move |receivable_account| (node.earning_wallet(), receivable_account.balance))
        })
        .collect::<HashMap<Wallet, i64>>();

    // check that each payable has a receivable
    assert_eq!(
        payables.len(),
        receivable_balances.len(),
        "Lengths of payables and receivables should match.\nPayables: {:?}\nReceivables: {:?}",
        payables,
        receivable_balances
    );
    assert!(
        receivable_balances.len() >= 3, // minimum service list: route, route, exit.
        "not enough receivables found {:?}",
        receivable_balances
    );

    payables.iter().for_each(|payable| {
        assert_eq!(
            &payable.balance,
            receivable_balances.get(&payable.wallet).unwrap(),
        );
    });
}

fn non_pending_payables(node: &SubstratumRealNode, chain_id: u8) -> Vec<PayableAccount> {
    let db_initializer = DbInitializerReal::new();
    let payable_dao = PayableDaoReal::new(
        db_initializer
            .initialize(
                &std::path::PathBuf::from(SubstratumRealNode::node_home_dir(
                    &SubstratumNodeUtils::find_project_root(),
                    &node.name().to_string(),
                )),
                chain_id,
            )
            .unwrap(),
    );
    payable_dao.non_pending_payables()
}

fn receivables(node: &SubstratumRealNode, chain_id: u8) -> Vec<ReceivableAccount> {
    let db_initializer = DbInitializerReal::new();
    let receivable_dao = ReceivableDaoReal::new(
        db_initializer
            .initialize(
                &std::path::PathBuf::from(SubstratumRealNode::node_home_dir(
                    &SubstratumNodeUtils::find_project_root(),
                    &node.name().to_string(),
                )),
                chain_id,
            )
            .unwrap(),
    );
    receivable_dao.receivables()
}

pub fn start_lonely_real_node(cluster: &mut SubstratumNodeCluster) -> SubstratumRealNode {
    let index = cluster.next_index();
    cluster.start_real_node(
        NodeStartupConfigBuilder::standard()
            .earning_wallet_info(make_earning_wallet_info(&index.to_string()))
            .consuming_wallet_info(make_consuming_wallet_info(&index.to_string()))
            .build(),
    )
}

pub fn start_real_node(
    cluster: &mut SubstratumNodeCluster,
    neighbor: NodeReference,
) -> SubstratumRealNode {
    let index = cluster.next_index();
    cluster.start_real_node(
        NodeStartupConfigBuilder::standard()
            .neighbor(neighbor)
            .earning_wallet_info(make_earning_wallet_info(&index.to_string()))
            .build(),
    )
}
