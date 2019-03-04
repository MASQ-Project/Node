// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use multinode_integration_tests_lib::substratum_node::SubstratumNode;
use multinode_integration_tests_lib::substratum_node_cluster::SubstratumNodeCluster;
use multinode_integration_tests_lib::substratum_real_node::NodeStartupConfigBuilder;
use multinode_integration_tests_lib::substratum_real_node::SubstratumRealNode;
use node_lib::accountant::dao_utils;
use node_lib::accountant::payable_dao::PayableAccount;
use node_lib::accountant::receivable_dao::ReceivableAccount;
use node_lib::sub_lib::cryptde::CryptDE;
use node_lib::sub_lib::cryptde::PlainData;
use node_lib::sub_lib::hopper::TEMPORARY_PER_ROUTING_BYTE_RATE;
use node_lib::sub_lib::hopper::TEMPORARY_PER_ROUTING_RATE;
use node_lib::sub_lib::proxy_client::ClientResponsePayload;
use node_lib::sub_lib::proxy_client::TEMPORARY_PER_EXIT_BYTE_RATE;
use node_lib::sub_lib::proxy_client::TEMPORARY_PER_EXIT_RATE;
use node_lib::sub_lib::proxy_server::ClientRequestPayload;
use node_lib::sub_lib::proxy_server::ProxyProtocol;
use node_lib::sub_lib::sequence_buffer::SequencedPacket;
use node_lib::sub_lib::stream_key::StreamKey;
use node_lib::sub_lib::wallet::Wallet;
use std::net::SocketAddr;
use std::str::FromStr;
use std::thread;
use std::time::Duration;
use std::time::SystemTime;

#[test]
fn provided_and_consumed_services_are_recorded_in_databases() {
    let mut cluster = SubstratumNodeCluster::start().unwrap();

    let bootstrap = cluster.start_mock_bootstrap_node(vec![5550]);

    let _nodes = (0..3)
        .map(|idx| {
            cluster.start_real_node(
                NodeStartupConfigBuilder::standard()
                    .neighbor(bootstrap.node_reference())
                    .earning_wallet(make_wallet_from(idx))
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
    let originating_node = cluster
        .get_real_node_by_key(&bootstrap.originating_node_key())
        .unwrap();
    let routing_node = cluster
        .get_real_node_by_key(&bootstrap.routing_node_keys()[0])
        .unwrap();
    let exit_node = cluster
        .get_real_node_by_key(&bootstrap.exit_node_key())
        .unwrap();

    let param_block = ParamBlock {
        before,
        after: SystemTime::now(),
        request_len: request.len(),
        response_len: response.len(),
        originating_node: originating_node.clone(),
        routing_node: routing_node.clone(),
        exit_node: exit_node.clone(),
    };

    check_originating_charges(&param_block);
    check_routing_charges(&param_block);
    check_exit_charges(&param_block);
}

#[derive(Debug)]
struct ParamBlock {
    before: SystemTime,
    after: SystemTime,
    request_len: usize,
    response_len: usize,
    originating_node: SubstratumRealNode,
    routing_node: SubstratumRealNode,
    exit_node: SubstratumRealNode,
}

fn check_originating_charges(param_block: &ParamBlock) {
    let receivable_account = receivable_account_status(
        &param_block.originating_node,
        &param_block.originating_node.consuming_wallet().unwrap(),
    );
    let payable_routing_account = payable_account_status(
        &param_block.originating_node,
        &param_block.routing_node.earning_wallet(),
    )
    .unwrap();
    let payable_exit_account = payable_account_status(
        &param_block.originating_node,
        &param_block.exit_node.earning_wallet(),
    )
    .unwrap();

    assert_eq!(receivable_account, None);
    let (cores_request_bytes, expected_request_routing_charge) =
        cores_payload_request_routing_charges(&param_block);
    let expected_request_exit_charge = calculate_exit_charge(param_block.request_len);
    let (cores_response_bytes, expected_response_routing_charge) =
        cores_payload_response_routing_charges(&param_block);
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

fn cores_payload_request_routing_charges(param_block: &ParamBlock) -> (usize, u64) {
    calculate_request_routing_charge(param_block.request_len, &param_block.exit_node.cryptde())
}

fn cores_payload_response_routing_charges(param_block: &ParamBlock) -> (usize, u64) {
    calculate_response_routing_charge(param_block.response_len, &param_block.exit_node.cryptde())
}

fn check_routing_charges(param_block: &ParamBlock) {
    let receivable_account = receivable_account_status(
        &param_block.routing_node,
        &param_block.originating_node.consuming_wallet().unwrap(),
    )
    .unwrap();
    let payable_originating_account = payable_account_status(
        &param_block.routing_node,
        &param_block.originating_node.earning_wallet(),
    );
    let payable_exit_account = payable_account_status(
        &param_block.routing_node,
        &param_block.exit_node.earning_wallet(),
    );

    let (request_bytes, expected_request_charge) =
        calculate_request_routing_charge(param_block.request_len, &param_block.exit_node.cryptde());
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

fn check_exit_charges(param_block: &ParamBlock) {
    let receivable_account = receivable_account_status(
        &param_block.exit_node,
        &param_block.originating_node.consuming_wallet().unwrap(),
    )
    .unwrap();
    let payable_originating_account = payable_account_status(
        &param_block.exit_node,
        &param_block.originating_node.earning_wallet(),
    );
    let payable_routing_account = payable_account_status(
        &param_block.exit_node,
        &param_block.routing_node.earning_wallet(),
    );

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

fn make_wallet_from(n: usize) -> Wallet {
    let mut address = String::from("0x");
    for _ in 0..40 {
        address.push(((n + '0' as usize) as u8) as char);
    }
    Wallet::new(address.as_str())
}

fn make_garbage_data(bytes: usize) -> Vec<u8> {
    let mut data = Vec::with_capacity(bytes);
    for _ in 0..bytes {
        data.push(0);
    }
    data
}
