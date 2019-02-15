// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
extern crate accountant_lib;
extern crate base64;
extern crate hopper_lib;
extern crate multinode_integration_tests_lib;
extern crate neighborhood_lib;
extern crate node_lib;
extern crate proxy_client_lib;
extern crate regex;
extern crate serde_cbor;
extern crate sub_lib;
extern crate test_utils;

use accountant_lib::dao_utils;
use accountant_lib::receivable_dao::Account;
use multinode_integration_tests_lib::substratum_node::SubstratumNode;
use multinode_integration_tests_lib::substratum_node_cluster::SubstratumNodeCluster;
use multinode_integration_tests_lib::substratum_real_node::NodeStartupConfigBuilder;
use multinode_integration_tests_lib::substratum_real_node::SubstratumRealNode;
use std::net::SocketAddr;
use std::str::FromStr;
use std::thread;
use std::time::Duration;
use std::time::SystemTime;
use sub_lib::cryptde::CryptDE;
use sub_lib::cryptde::PlainData;
use sub_lib::hopper::TEMPORARY_PER_ROUTING_BYTE_RATE;
use sub_lib::hopper::TEMPORARY_PER_ROUTING_RATE;
use sub_lib::proxy_client::ClientResponsePayload;
use sub_lib::proxy_client::TEMPORARY_PER_EXIT_BYTE_RATE;
use sub_lib::proxy_client::TEMPORARY_PER_EXIT_RATE;
use sub_lib::proxy_server::ClientRequestPayload;
use sub_lib::proxy_server::ProxyProtocol;
use sub_lib::sequence_buffer::SequencedPacket;
use sub_lib::stream_key::StreamKey;
use sub_lib::wallet::Wallet;

#[test]
fn provided_services_are_recorded_in_accounts_receivable() {
    let mut cluster = SubstratumNodeCluster::start().unwrap();

    let bootstrap = cluster.start_mock_bootstrap_node(vec![5550]);

    let _nodes = (0..3)
        .map(|_| {
            cluster.start_real_node(
                NodeStartupConfigBuilder::standard()
                    .neighbor(bootstrap.node_reference())
                    .build(),
            )
        })
        .collect::<Vec<SubstratumRealNode>>();
    thread::sleep(Duration::from_millis(2000));

    let originating_node = cluster
        .get_real_node_by_key(&bootstrap.originating_node_key())
        .unwrap();
    let mut client = originating_node.make_client(80);
    let request = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".as_bytes();
    let before = SystemTime::now();

    client.send_chunk(Vec::from(request));
    let response = client.wait_for_chunk();

    let param_block = ParamBlock {
        before,
        after: SystemTime::now(),
        request_len: request.len(),
        response_len: response.len(),
        consuming_wallet: originating_node
            .consuming_wallet()
            .as_ref()
            .unwrap()
            .clone(),
    };
    let originating_node = cluster
        .get_real_node_by_key(&bootstrap.originating_node_key())
        .unwrap();
    let routing_node = cluster
        .get_real_node_by_key(&bootstrap.routing_node_keys()[0])
        .unwrap();
    let exit_node = cluster
        .get_real_node_by_key(&bootstrap.exit_node_key())
        .unwrap();
    check_originating_charges(&originating_node, &param_block);
    check_routing_charges(
        routing_node,
        &param_block,
        &originating_node.cryptde(),
        &exit_node.cryptde(),
    );
    check_exit_charges(exit_node, &param_block);
}

#[derive(Debug)]
struct ParamBlock {
    before: SystemTime,
    after: SystemTime,
    request_len: usize,
    response_len: usize,
    consuming_wallet: Wallet,
}

fn check_originating_charges(originating_node: &SubstratumRealNode, param_block: &ParamBlock) {
    let account_status = account_status(&originating_node, &param_block.consuming_wallet);

    assert_eq!(account_status, None);
}

fn check_routing_charges(
    routing_node: SubstratumRealNode,
    param_block: &ParamBlock,
    originating_cryptde: &CryptDE,
    exit_cryptde: &CryptDE,
) {
    let account_status = account_status(&routing_node, &param_block.consuming_wallet).unwrap();

    let (request_bytes, expected_request_charge) =
        calculate_request_routing_charge(param_block.request_len, exit_cryptde);
    let (response_bytes, expected_response_charge) =
        calculate_response_routing_charge(param_block.response_len, originating_cryptde);
    assert_eq!(
        account_status.balance as u64,
        expected_request_charge + expected_response_charge,
        "Balance should be calculated for 2 routing services and {} + {} bytes",
        request_bytes,
        response_bytes
    );
    timestamp_between(
        &param_block.before,
        &account_status.last_received_timestamp,
        &param_block.after,
    );
}

fn check_exit_charges(exit_node: SubstratumRealNode, param_block: &ParamBlock) {
    let account_status = account_status(&exit_node, &param_block.consuming_wallet).unwrap();

    let expected_request_charge = calculate_exit_charge(param_block.request_len);
    let expected_response_charge = calculate_exit_charge(param_block.response_len);
    assert_eq!(
        account_status.balance as u64,
        expected_request_charge + expected_response_charge,
        "Balance should be calculated for 2 exit services and {} + {} bytes",
        param_block.request_len,
        param_block.response_len
    );
    timestamp_between(
        &param_block.before,
        &account_status.last_received_timestamp,
        &param_block.after,
    );
}

fn account_status(node: &SubstratumRealNode, consuming_wallet: &Wallet) -> Option<Account> {
    let receivable_dao = node.daos().receivable;
    receivable_dao.account_status(consuming_wallet)
}

fn calculate_request_routing_charge(bytes: usize, exit_cryptde: &CryptDE) -> (usize, u64) {
    let payload: ClientRequestPayload = make_request_payload(bytes, exit_cryptde);
    let payload_ser = PlainData::from(serde_cbor::ser::to_vec(&payload).unwrap());
    let payload_enc = exit_cryptde
        .encode(&exit_cryptde.public_key(), &payload_ser)
        .unwrap();
    let payload_len = payload_enc.len();
    (
        payload_len,
        TEMPORARY_PER_ROUTING_RATE + (TEMPORARY_PER_ROUTING_BYTE_RATE * payload_len as u64),
    )
}

fn calculate_response_routing_charge(bytes: usize, originating_cryptde: &CryptDE) -> (usize, u64) {
    let payload: ClientResponsePayload = make_response_payload(bytes, originating_cryptde);
    let payload_ser = PlainData::from(serde_cbor::ser::to_vec(&payload).unwrap());
    let payload_enc = originating_cryptde
        .encode(&originating_cryptde.public_key(), &payload_ser)
        .unwrap();
    let payload_len = payload_enc.len();
    (
        payload_len,
        TEMPORARY_PER_ROUTING_RATE + (TEMPORARY_PER_ROUTING_BYTE_RATE * payload_len as u64),
    )
}

fn calculate_exit_charge(bytes: usize) -> u64 {
    TEMPORARY_PER_EXIT_RATE + (TEMPORARY_PER_EXIT_BYTE_RATE * bytes as u64)
}

fn timestamp_between(before: &SystemTime, timestamp: &SystemTime, after: &SystemTime) {
    let before_t = dao_utils::to_time_t(before);
    let timestamp_t = dao_utils::to_time_t(timestamp);
    let after_t = dao_utils::to_time_t(after);
    assert!(
        timestamp_t >= before_t,
        "{} should have been after {}, but wasn't",
        timestamp_t,
        before_t
    );
    assert!(
        timestamp_t <= after_t,
        "{} should have been before {}, but wasn't",
        timestamp_t,
        after_t
    );
}

fn make_request_payload(bytes: usize, cryptde: &CryptDE) -> ClientRequestPayload {
    ClientRequestPayload {
        stream_key: StreamKey::new(
            cryptde.public_key(),
            SocketAddr::from_str("1.2.3.4:5678").unwrap(),
        ),
        sequenced_packet: SequencedPacket::new(make_garbage_data(bytes), 0, true),
        target_hostname: Some("example.com".to_string()),
        target_port: 80,
        protocol: ProxyProtocol::HTTP,
        originator_public_key: cryptde.public_key(),
    }
}

fn make_response_payload(bytes: usize, cryptde: &CryptDE) -> ClientResponsePayload {
    ClientResponsePayload {
        stream_key: StreamKey::new(
            cryptde.public_key(),
            SocketAddr::from_str("1.2.3.4:5678").unwrap(),
        ),
        sequenced_packet: SequencedPacket::new(make_garbage_data(bytes), 0, true),
    }
}

fn make_garbage_data(bytes: usize) -> Vec<u8> {
    let mut data = Vec::with_capacity(bytes);
    for _ in 0..bytes {
        data.push(0);
    }
    data
}
