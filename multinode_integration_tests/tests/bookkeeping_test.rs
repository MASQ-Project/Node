// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use multinode_integration_tests_lib::substratum_node::{NodeReference, SubstratumNode};
use multinode_integration_tests_lib::substratum_node_cluster::SubstratumNodeCluster;
use multinode_integration_tests_lib::substratum_real_node::NodeStartupConfigBuilder;
use multinode_integration_tests_lib::substratum_real_node::SubstratumRealNode;
use node_lib::accountant::dao_utils;
use node_lib::accountant::payable_dao::PayableAccount;
use node_lib::accountant::receivable_dao::ReceivableAccount;
use node_lib::sub_lib::cryptde::CryptDE;
use node_lib::sub_lib::cryptde::PlainData;
use node_lib::sub_lib::hopper::MessageType;
use node_lib::sub_lib::neighborhood::DEFAULT_RATE_PACK;
use node_lib::sub_lib::proxy_client::ClientResponsePayload;
use node_lib::sub_lib::proxy_server::ClientRequestPayload;
use node_lib::sub_lib::sequence_buffer::SequencedPacket;
use node_lib::sub_lib::stream_key::StreamKey;
use node_lib::sub_lib::wallet::Wallet;
use node_lib::test_utils::test_utils::{make_garbage_data, make_request_payload};
use std::net::SocketAddr;
use std::str::FromStr;
use std::thread;
use std::time::Duration;
use std::time::SystemTime;

fn start_real_node(
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

#[test]
fn provided_and_consumed_services_are_recorded_in_databases() {
    let mut cluster = SubstratumNodeCluster::start().unwrap();

    let bootstrap = cluster.start_real_node(NodeStartupConfigBuilder::bootstrap().build());

    let originating_node = start_real_node(&mut cluster, bootstrap.node_reference(), 2);
    let test_node_3 = start_real_node(&mut cluster, originating_node.node_reference(), 3);
    let test_node_4 = start_real_node(&mut cluster, test_node_3.node_reference(), 4);

    thread::sleep(Duration::from_millis(2000));

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
        originating_node: originating_node.clone(),
    };

    let (_, expected_request_charge) =
        calculate_request_routing_charge(request.len(), &test_node_4.cryptde());
    let (_, expected_response_charge) =
        calculate_response_routing_charge(response.len(), &originating_node.cryptde());
    // Was test_node_3 used as the routing Node?
    let receivable_account_3 =
        receivable_account_status(&test_node_3, &originating_node.consuming_wallet().unwrap())
            .unwrap();
    if expected_request_charge + expected_response_charge == receivable_account_3.balance as u64 {
        // Yes. Assert that test_node_3 was the routing Node and test_node_4 was the exit Node.
        check_originating_charges(&param_block, &test_node_3, &test_node_4);
        check_routing_charges(&param_block, &test_node_3, &test_node_4);
        check_exit_charges(&param_block, &test_node_3, &test_node_4);
    } else {
        // No. Assert that test_node_4 was the routing Node and test_node_3 was the exit Node.
        check_originating_charges(&param_block, &test_node_4, &test_node_3);
        check_routing_charges(&param_block, &test_node_4, &test_node_3);
        check_exit_charges(&param_block, &test_node_4, &test_node_3);
    }
}

#[derive(Debug)]
struct ParamBlock {
    before: SystemTime,
    after: SystemTime,
    request_len: usize,
    response_len: usize,
    originating_node: SubstratumRealNode,
}

fn check_originating_charges(
    param_block: &ParamBlock,
    routing_node: &SubstratumRealNode,
    exit_node: &SubstratumRealNode,
) {
    let receivable_account = receivable_account_status(
        &param_block.originating_node,
        &param_block.originating_node.consuming_wallet().unwrap(),
    );
    let payable_routing_account = payable_account_status(
        &param_block.originating_node,
        &routing_node.earning_wallet(),
    )
    .unwrap();
    let payable_exit_account =
        payable_account_status(&param_block.originating_node, &exit_node.earning_wallet()).unwrap();

    assert_eq!(receivable_account, None);
    let (cores_request_bytes, expected_request_routing_charge) =
        cores_payload_request_routing_charges(&param_block, exit_node);
    let expected_request_exit_charge = calculate_exit_charge(param_block.request_len);
    let (cores_response_bytes, expected_response_routing_charge) =
        cores_payload_response_routing_charges(&param_block, exit_node);
    let expected_response_exit_charge = calculate_exit_charge(param_block.response_len);
    println!(
        "request_routing_charge: {}, response_routing_charge: {}",
        expected_request_routing_charge, expected_response_routing_charge
    );
    assert_eq!(
        payable_routing_account.balance as u64,
        expected_request_routing_charge + expected_response_routing_charge,
        "Balance should be calculated for 2 routing services and {} + {} bytes",
        cores_request_bytes,
        cores_response_bytes
    );
    assert_eq!(payable_routing_account.pending_payment_transaction, None);
    assert_timestamp_between(
        &param_block.before,
        &payable_routing_account.last_paid_timestamp,
        &param_block.after,
    );
    assert_eq!(
        payable_exit_account.balance as u64,
        expected_request_exit_charge + expected_response_exit_charge,
        "Balance should be calculated for 2 exit services and {} + {} bytes",
        cores_request_bytes,
        cores_response_bytes
    );
    assert_eq!(payable_exit_account.pending_payment_transaction, None);
    assert_timestamp_between(
        &param_block.before,
        &payable_exit_account.last_paid_timestamp,
        &param_block.after,
    );
}

fn cores_payload_request_routing_charges(
    param_block: &ParamBlock,
    exit_node: &SubstratumRealNode,
) -> (usize, u64) {
    calculate_request_routing_charge(param_block.request_len, &exit_node.cryptde())
}

fn cores_payload_response_routing_charges(
    param_block: &ParamBlock,
    exit_node: &SubstratumRealNode,
) -> (usize, u64) {
    calculate_response_routing_charge(param_block.response_len, &exit_node.cryptde())
}

fn check_routing_charges(
    param_block: &ParamBlock,
    routing_node: &SubstratumRealNode,
    exit_node: &SubstratumRealNode,
) {
    let receivable_account = receivable_account_status(
        routing_node,
        &param_block.originating_node.consuming_wallet().unwrap(),
    )
    .unwrap();
    let payable_originating_account =
        payable_account_status(routing_node, &param_block.originating_node.earning_wallet());
    let payable_exit_account = payable_account_status(routing_node, &exit_node.earning_wallet());

    let (request_bytes, expected_request_charge) =
        calculate_request_routing_charge(param_block.request_len, &exit_node.cryptde());
    let (response_bytes, expected_response_charge) = calculate_response_routing_charge(
        param_block.response_len,
        &param_block.originating_node.cryptde(),
    );
    assert_eq!(
        receivable_account.balance as u64,
        expected_request_charge + expected_response_charge,
        "Balance should be calculated for 2 routing services and {} + {} bytes",
        request_bytes,
        response_bytes
    );
    assert_timestamp_between(
        &param_block.before,
        &receivable_account.last_received_timestamp,
        &param_block.after,
    );
    assert_eq!(payable_originating_account, None);
    assert_eq!(payable_exit_account, None);
}

fn check_exit_charges(
    param_block: &ParamBlock,
    routing_node: &SubstratumRealNode,
    exit_node: &SubstratumRealNode,
) {
    let receivable_account = receivable_account_status(
        exit_node,
        &param_block.originating_node.consuming_wallet().unwrap(),
    )
    .unwrap();
    let payable_originating_account =
        payable_account_status(exit_node, &param_block.originating_node.earning_wallet());
    let payable_routing_account = payable_account_status(exit_node, &routing_node.earning_wallet());

    let expected_request_charge = calculate_exit_charge(param_block.request_len);
    let expected_response_charge = calculate_exit_charge(param_block.response_len);
    assert_eq!(
        receivable_account.balance as u64,
        expected_request_charge + expected_response_charge,
        "Balance should be calculated for 2 exit services and {} + {} bytes",
        param_block.request_len,
        param_block.response_len
    );
    assert_timestamp_between(
        &param_block.before,
        &receivable_account.last_received_timestamp,
        &param_block.after,
    );
    assert_eq!(payable_originating_account, None);
    assert_eq!(payable_routing_account, None);
}

fn payable_account_status(
    node: &SubstratumRealNode,
    earning_wallet: &Wallet,
) -> Option<PayableAccount> {
    let payable_dao = node.daos().payable;
    payable_dao.account_status(earning_wallet)
}

fn receivable_account_status(
    node: &SubstratumRealNode,
    consuming_wallet: &Wallet,
) -> Option<ReceivableAccount> {
    let receivable_dao = node.daos().receivable;
    receivable_dao.account_status(consuming_wallet)
}

fn calculate_request_routing_charge(bytes: usize, exit_cryptde: &CryptDE) -> (usize, u64) {
    let payload: ClientRequestPayload = make_request_payload(bytes, exit_cryptde);
    let payload_ser =
        PlainData::from(serde_cbor::ser::to_vec(&MessageType::ClientRequest(payload)).unwrap());
    let payload_enc = exit_cryptde
        .encode(&exit_cryptde.public_key(), &payload_ser)
        .unwrap();
    let payload_len = payload_enc.len();
    (
        payload_len,
        DEFAULT_RATE_PACK.routing_service_rate
            + (DEFAULT_RATE_PACK.routing_byte_rate * payload_len as u64),
    )
}

fn calculate_response_routing_charge(bytes: usize, originating_cryptde: &CryptDE) -> (usize, u64) {
    let payload: ClientResponsePayload = make_response_payload(bytes, originating_cryptde);
    let payload_ser =
        PlainData::from(serde_cbor::ser::to_vec(&MessageType::ClientResponse(payload)).unwrap());
    let payload_enc = originating_cryptde
        .encode(&originating_cryptde.public_key(), &payload_ser)
        .unwrap();
    let payload_len = payload_enc.len();
    (
        payload_len,
        DEFAULT_RATE_PACK.routing_service_rate
            + (DEFAULT_RATE_PACK.routing_byte_rate * payload_len as u64),
    )
}

fn calculate_exit_charge(bytes: usize) -> u64 {
    DEFAULT_RATE_PACK.exit_service_rate + (DEFAULT_RATE_PACK.exit_byte_rate * bytes as u64)
}

fn assert_timestamp_between(before: &SystemTime, timestamp: &SystemTime, after: &SystemTime) {
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

fn make_response_payload(bytes: usize, cryptde: &CryptDE) -> ClientResponsePayload {
    ClientResponsePayload {
        stream_key: StreamKey::new(
            cryptde.public_key(),
            SocketAddr::from_str("1.2.3.4:5678").unwrap(),
        ),
        sequenced_packet: SequencedPacket::new(make_garbage_data(bytes), 0, true),
    }
}

fn make_wallet_from(n: usize) -> Wallet {
    let mut address = String::from("0x");
    for _ in 0..40 {
        address.push(((n + '0' as usize) as u8) as char);
    }
    Wallet::new(address.as_str())
}
