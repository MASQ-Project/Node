// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
extern crate multinode_integration_tests_lib;
extern crate node_lib;
extern crate regex;
extern crate serde_cbor;
extern crate sub_lib;
extern crate hopper_lib;
extern crate neighborhood_lib;
extern crate base64;
extern crate test_utils;

use node_lib::json_masquerader::JsonMasquerader;
use multinode_integration_tests_lib::substratum_cores_server::SubstratumCoresServer;
use multinode_integration_tests_lib::substratum_node_cluster::SubstratumNodeCluster;
use multinode_integration_tests_lib::substratum_cores_client::SubstratumCoresClient;
use sub_lib::route::RouteSegment;
use sub_lib::route::Route;
use sub_lib::dispatcher::Component;
use sub_lib::hopper::IncipientCoresPackage;
use std::time::Duration;
use multinode_integration_tests_lib::substratum_node::NodeStartupConfigBuilder;
use neighborhood_lib::gossip::Gossip;
use neighborhood_lib::gossip::GossipNodeRecord;
use multinode_integration_tests_lib::substratum_node::SubstratumNode;
use sub_lib::cryptde::Key;
use sub_lib::cryptde::CryptDE;
use multinode_integration_tests_lib::substratum_node::PortSelector;
use neighborhood_lib::gossip::NeighborRelationship;
use sub_lib::hopper::ExpiredCoresPackage;
use std::collections::HashMap;

#[test]
fn standard_node_sends_gossip_to_bootstrap_upon_startup () {
    let mut cluster = SubstratumNodeCluster::start ().unwrap ();
    let server = SubstratumCoresServer::new ();
    let node_ref = server.node_reference ();

    let subject: &SubstratumNode = cluster.start_node (NodeStartupConfigBuilder::standard ()
        .bootstrap_from (node_ref)
        .build ()
    ).expect ("Couldn't create standard Node");

    let cores_package = server.wait_for_package(Duration::from_millis (1000));
    let gossip: Gossip = cores_package.payload ().unwrap ();
    let node_ref = subject.node_reference();
    find (&gossip.node_records, GossipNodeRecord {
        public_key: node_ref.public_key.clone (),
        node_addr_opt: Some (node_ref.node_addr.clone ()),
        is_bootstrap_node: false,
    });
    find (&gossip.node_records, GossipNodeRecord {
        public_key: server.public_key (),
        node_addr_opt: None,
        is_bootstrap_node: true,
    });
}

#[test]
fn bootstrap_node_receives_gossip_and_broadcasts_result () {
    let mut cluster = SubstratumNodeCluster::start ().unwrap ();
    let one_standard_node = SubstratumCoresServer::new ();
    let another_standard_node = SubstratumCoresServer::new ();
    let masquerader = JsonMasquerader::new ();

    let subject = cluster.start_node (NodeStartupConfigBuilder::bootstrap ()
        .build ()
    ).expect ("Couldn't create bootstrap Node");

    let one_gossip = Gossip {
        node_records: vec! (GossipNodeRecord {
            public_key: one_standard_node.public_key (),
            node_addr_opt: Some (one_standard_node.node_addr ()),
            is_bootstrap_node: false
        }),
        neighbor_pairs: vec! (),
    };
    let one_cores_package = make_gossip_cores_package (one_standard_node.public_key (),
        subject.public_key(), one_gossip, one_standard_node.cryptde ());
    let mut one_client = SubstratumCoresClient::new (subject.socket_addr (PortSelector::First),
        one_standard_node.cryptde ());
    one_client.transmit_package (one_cores_package, &masquerader, subject.public_key ());

    let one_gossip_response = one_standard_node.wait_for_package(Duration::from_millis (1000));
    let one_gossip_response_payload: Gossip = one_gossip_response.payload ().unwrap ();
    let subject_index = find (&one_gossip_response_payload.node_records, GossipNodeRecord {
        public_key: subject.public_key (),
        node_addr_opt: Some (subject.node_addr ()),
        is_bootstrap_node: true
    });
    let one_node_index = find (&one_gossip_response_payload.node_records, GossipNodeRecord {
        public_key: one_standard_node.public_key (),
        node_addr_opt: None,
        is_bootstrap_node: false
    });
    assert_eq! (one_gossip_response_payload.neighbor_pairs, vec! (NeighborRelationship {from: subject_index as u32, to: one_node_index as u32}));

    let another_gossip = Gossip {
        node_records: vec! (GossipNodeRecord {
            public_key: another_standard_node.public_key (),
            node_addr_opt: Some (another_standard_node.node_addr ()),
            is_bootstrap_node: false
        }),
        neighbor_pairs: vec! (),
    };
    let another_cores_package = make_gossip_cores_package (another_standard_node.public_key (),
                                                       subject.public_key(), another_gossip, another_standard_node.cryptde ());
    let mut another_client = SubstratumCoresClient::new (subject.socket_addr (PortSelector::First),
                                                     another_standard_node.cryptde ());
println! ("Transmitting Gossip from second fake node");
    another_client.transmit_package (another_cores_package, &masquerader, subject.public_key ());

    let another_gossip_response = another_standard_node.wait_for_package(Duration::from_millis (1000));
    verify_three_node_gossip(another_gossip_response, &subject, &another_standard_node, &one_standard_node);
//    let one_gossip_response = one_standard_node.wait_for_package(Duration::from_millis (1000));
//    verify_three_node_gossip(one_gossip_response, &subject, &one_standard_node, &another_standard_node);
}

fn make_gossip_cores_package (from: Key, to: Key, gossip: Gossip, source_cryptde: &CryptDE) -> IncipientCoresPackage {
    IncipientCoresPackage::new (
        Route::new (vec! (RouteSegment::new (vec! (&from, &to), Component::Neighborhood)), source_cryptde).unwrap (),
        gossip,
        &to
    )
}

fn verify_three_node_gossip (package: ExpiredCoresPackage, subject: &SubstratumNode,
        recipient: &SubstratumCoresServer, foreigner: &SubstratumCoresServer) {
    let payload: Gossip = package.payload ().unwrap ();
    let subject_index = find (&payload.node_records, GossipNodeRecord {
        public_key: subject.public_key (),
        node_addr_opt: Some (subject.node_addr ()),
        is_bootstrap_node: true
    });
    let recipient_index = find (&payload.node_records, GossipNodeRecord {
        public_key: recipient.public_key (),
        node_addr_opt: None,
        is_bootstrap_node: false
    });
    let foreigner_index = find (&payload.node_records, GossipNodeRecord {
        public_key: foreigner.public_key (),
        node_addr_opt: Some (foreigner.node_addr ()),
        is_bootstrap_node: false
    });
    assert_relationship_present (&payload, subject_index, "subject", foreigner_index, "foreigner");
    assert_relationship_present (&payload, recipient_index, "recipient", foreigner_index, "foreigner");
    assert_relationship_present (&payload, foreigner_index, "foreigner", recipient_index, "recipient");
    assert_eq! (payload.neighbor_pairs.len (), 3);
}

fn find (haystack: &Vec<GossipNodeRecord>, needle: GossipNodeRecord) -> usize {
    for i in 0..haystack.len () {
        let candidate = &haystack[i];
        if candidate == &needle {
            return i
        }
    }
    panic! ("{:?} did not contain {:?}", haystack, needle)
}

fn assert_relationship_present (payload: &Gossip, from_idx: usize, from_name: &str, to_idx: usize, to_name: &str) {
    let relationship = NeighborRelationship {from: from_idx as u32, to: to_idx as u32};
    let mut name_hash: HashMap<usize, String> = HashMap::new ();
    name_hash.insert (from_idx, String::from (from_name));
    name_hash.insert (to_idx, String::from (to_name));
    let convert_idx = |idx: usize| {
        match name_hash.get (&idx) {
            Some (name) => name.clone (),
            None => format! ("{}", idx),
        }
    };
    let convert_nr = |nr: &NeighborRelationship| {
        format! ("{} -> {}", convert_idx (nr.from as usize), convert_idx (nr.to as usize))
    };
    assert_eq! (payload.neighbor_pairs.contains (&relationship), true, "{:?} did not contain {:?}",
                payload.neighbor_pairs.iter ().map (|x| convert_nr (x)).collect::<Vec<String>> (), convert_nr (&relationship));
}