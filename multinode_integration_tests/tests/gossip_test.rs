// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

use multinode_integration_tests_lib::substratum_cores_server::SubstratumCoresServer;
use multinode_integration_tests_lib::substratum_node::SubstratumNode;
use multinode_integration_tests_lib::substratum_node_cluster::SubstratumNodeCluster;
use multinode_integration_tests_lib::substratum_real_node::NodeStartupConfigBuilder;
use node_lib::neighborhood::gossip::GossipNodeRecord;
use node_lib::neighborhood::node_record::NodeRecordInner;
use node_lib::sub_lib::accountant;
use node_lib::sub_lib::cryptde::{CryptDE, CryptData, PlainData};
use node_lib::sub_lib::cryptde_null::CryptDENull;
use node_lib::sub_lib::hopper::MessageType;
use node_lib::sub_lib::neighborhood::DEFAULT_RATE_PACK;
use node_lib::test_utils::test_utils::assert_contains;
use std::collections::btree_set::BTreeSet;
use std::net::IpAddr;
use std::str::FromStr;
use std::time::Duration;

#[test]
fn node_sends_gossip_to_neighbors_upon_startup() {
    let mut cluster = SubstratumNodeCluster::start().unwrap();
    let server = SubstratumCoresServer::new();
    let neighbor_node_ref = server.node_reference();

    let subject = cluster.start_real_node(
        NodeStartupConfigBuilder::standard()
            .neighbor(neighbor_node_ref.clone())
            .build(),
    );

    let package = server.wait_for_package(Duration::from_millis(1000));
    let cores_package = package
        .to_expired(IpAddr::from_str("1.2.3.4").unwrap(), server.cryptde())
        .unwrap();
    let gossip: MessageType = cores_package.payload;
    match gossip {
        MessageType::Gossip(gossip) => {
            let node_ref = subject.node_reference();
            let inner = NodeRecordInner {
                public_key: node_ref.public_key.clone(),
                earning_wallet: accountant::DEFAULT_EARNING_WALLET.clone(),
                rate_pack: DEFAULT_RATE_PACK,
                neighbors: BTreeSet::default(),
                version: 0,
            };
            let cryptde = CryptDENull::from(&node_ref.public_key);
            let signed_data = PlainData::from(serde_cbor::ser::to_vec(&inner).unwrap());
            let signature = CryptData::from(cryptde.sign(&signed_data).unwrap());
            let gnr = GossipNodeRecord {
                signed_data,
                signature,
                node_addr_opt: Some(node_ref.node_addr.clone()),
            };
            assert_contains(&gossip.node_records, &gnr);
        }
        _ => panic!("Expected MessageType::Gossip, got something else"),
    }
}
