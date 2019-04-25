// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use multinode_integration_tests_lib::substratum_node::{
    NodeReference, SubstratumNode, SubstratumNodeUtils,
};
use multinode_integration_tests_lib::substratum_node_cluster::SubstratumNodeCluster;
use multinode_integration_tests_lib::substratum_real_node::NodeStartupConfigBuilder;
use multinode_integration_tests_lib::substratum_real_node::SubstratumRealNode;
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

    let bootstrap = cluster.start_real_node(NodeStartupConfigBuilder::bootstrap().build());

    let originating_node = start_real_node(&mut cluster, bootstrap.node_reference(), 2);
    let test_node_3 = start_real_node(&mut cluster, originating_node.node_reference(), 3);
    let test_node_4 = start_real_node(&mut cluster, originating_node.node_reference(), 4);
    let test_node_5 = start_real_node(&mut cluster, test_node_3.node_reference(), 5);
    let test_node_6 = start_real_node(&mut cluster, test_node_4.node_reference(), 6);
    let test_node_7 = start_real_node(&mut cluster, test_node_4.node_reference(), 7);
    let test_node_8 = start_real_node(&mut cluster, test_node_4.node_reference(), 8);

    thread::sleep(Duration::from_millis(2000));

    let mut client = originating_node.make_client(80);
    let request = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".as_bytes();

    client.send_chunk(Vec::from(request));
    let _response = client.wait_for_chunk();

    let nodes = vec![
        test_node_3,
        test_node_4,
        test_node_5,
        test_node_6,
        test_node_7,
        test_node_8,
    ];

    // get all payables from originating node
    let payables = non_pending_payables(&originating_node);

    // get all receivables from all other nodes
    let receivable_balances = nodes
        .iter()
        .flat_map(|node| {
            receivables(node)
                .into_iter()
                .map(move |receivable_account| (node.earning_wallet(), receivable_account.balance))
        })
        .collect::<HashMap<Wallet, i64>>();

    // check that each payable has a receivable
    assert!(
        receivable_balances.len() >= 3,
        "not enough receivables found {:?}",
        receivable_balances
    );
    assert_eq!(payables.len(), receivable_balances.len());

    payables.iter().for_each(|payable| {
        assert_eq!(
            receivable_balances.get(&payable.wallet_address).unwrap(),
            &payable.balance
        );
    });
}

fn non_pending_payables(node: &SubstratumRealNode) -> Vec<PayableAccount> {
    let db_initializer = DbInitializerReal::new();
    let payable_dao = PayableDaoReal::new(
        db_initializer
            .initialize(&std::path::PathBuf::from(
                SubstratumRealNode::node_home_dir(
                    &SubstratumNodeUtils::find_project_root(),
                    &node.name().to_string(),
                ),
            ))
            .unwrap(),
    );
    payable_dao.non_pending_payables()
}

fn receivables(node: &SubstratumRealNode) -> Vec<ReceivableAccount> {
    let db_initializer = DbInitializerReal::new();
    let receivable_dao = ReceivableDaoReal::new(
        db_initializer
            .initialize(&std::path::PathBuf::from(
                SubstratumRealNode::node_home_dir(
                    &SubstratumNodeUtils::find_project_root(),
                    &node.name().to_string(),
                ),
            ))
            .unwrap(),
    );
    receivable_dao.receivables()
}

pub fn start_real_node(
    cluster: &mut SubstratumNodeCluster,
    bootstrap_from: NodeReference,
    index: usize,
) -> SubstratumRealNode {
    cluster.start_real_node(
        NodeStartupConfigBuilder::standard()
            .neighbor(bootstrap_from)
            .earning_wallet(make_wallet_from(index))
            .build(),
    )
}

fn make_wallet_from(n: usize) -> Wallet {
    let mut address = String::from("0x");
    for _ in 0..40 {
        address.push(((n + '0' as usize) as u8) as char);
    }
    Wallet::new(address.as_str())
}
