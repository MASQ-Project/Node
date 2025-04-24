// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use masq_lib::blockchains::chains::Chain;
use masq_lib::test_utils::utils::TEST_DEFAULT_MULTINODE_CHAIN;
use masq_lib::utils::find_free_port;
use multinode_integration_tests_lib::masq_mock_node::MASQMockNode;
use multinode_integration_tests_lib::masq_node::{MASQNode, MASQNodeUtils, PortSelector};
use multinode_integration_tests_lib::masq_node_cluster::MASQNodeCluster;
use multinode_integration_tests_lib::masq_node_server::MASQNodeServer;
use multinode_integration_tests_lib::masq_real_node::{EarningWalletInfo, MASQRealNode, STANDARD_CLIENT_TIMEOUT_MILLIS};
use multinode_integration_tests_lib::multinode_gossip::{parse_gossip, GossipType};
use multinode_integration_tests_lib::neighborhood_constructor::{
    construct_neighborhood, do_not_modify_config,
};
use node_lib::hopper::live_cores_package::LiveCoresPackage;
use node_lib::json_masquerader::JsonMasquerader;
use node_lib::masquerader::Masquerader;
use node_lib::neighborhood::neighborhood_database::NeighborhoodDatabase;
use node_lib::neighborhood::node_record::NodeRecord;
use node_lib::sub_lib::cryptde::{decodex, CryptDE, PublicKey};
use node_lib::sub_lib::cryptde_null::CryptDENull;
use node_lib::sub_lib::dispatcher::Component;
use node_lib::sub_lib::hopper::{IncipientCoresPackage, MessageType};
use node_lib::sub_lib::proxy_client::ClientResponsePayload_0v1;
use node_lib::sub_lib::proxy_server::{ClientRequestPayload_0v1, ProxyProtocol};
use node_lib::sub_lib::route::{Route, RouteSegment};
use node_lib::sub_lib::sequence_buffer::SequencedPacket;
use node_lib::sub_lib::stream_key::StreamKey;
use masq_lib::data_version::DataVersion;
use node_lib::test_utils::neighborhood_test_utils::{db_from_node, make_node_record};
use std::io;
use std::net::SocketAddr;
use std::str::FromStr;
use std::time::Duration;
use websocket::ws::util::bytes_to_string;
use multinode_integration_tests_lib::utils::{database_conn, payable_dao};
use node_lib::sub_lib::versioned_data::VersionedData;
use node_lib::sub_lib::wallet::Wallet;
use node_lib::test_utils::wait_for;

const HTTP_REQUEST: &[u8] = b"GET / HTTP/1.1\r\nHost: booga.com\r\n\r\n";
const HTTP_RESPONSE: &[u8] =
    b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Type: text/plain\r\n\r\nbooga";

#[test]
// Given: Originating Node is real_node; exit Node is fictional Node with exit_key.
// Given: A stream is established from the client through the originating Node.
// When: Client (browser?) drops connection to originating Node.
// Then: Originating Node sends ClientRequestPayload to exit Node with empty SequencedPacket having last_data = true.
// -------------------------------------------------
// When: Originating Node receives a straggling SequencedPacket that was sent before the exit Node received the client drop.
// Then: Originating Node creates payable records for relays and exit for the straggler.
fn actual_client_drop() {
    let mut cluster = MASQNodeCluster::start().unwrap();
    let (originating_node, first_relay, second_relay, exit_node) = create_neighborhood(&mut cluster);
    let payable_dao = payable_dao(originating_node.name());
    let exit_cryptde = CryptDENull::from(exit_node.public_key(), cluster.chain);
    let mut client = originating_node.make_client(8080, STANDARD_CLIENT_TIMEOUT_MILLIS);
    let masquerader = JsonMasquerader::new();
    client.send_chunk(HTTP_REQUEST);
    first_relay
        .wait_for_package(&masquerader, Duration::from_secs(2))
        .unwrap();

    client.shutdown();

    let (_, _, lcp) = first_relay
        .wait_for_package(&masquerader, Duration::from_secs(2))
        .unwrap();
    let mut route = lcp.route.clone();
    let payload = match decodex::<MessageType>(&exit_cryptde, &lcp.payload).unwrap() {
        MessageType::ClientRequest(vd) => vd
            .extract(&node_lib::sub_lib::migrations::client_request_payload::MIGRATIONS)
            .unwrap(),
        mt => panic!("Unexpected: {:?}", mt),
    };
    let stream_key = payload.stream_key;
    assert!(payload.sequenced_packet.data.is_empty());
    assert!(payload.sequenced_packet.last_data);
    
    route.shift(first_relay.main_cryptde_null().unwrap()).unwrap();
    route.shift(&CryptDENull::from(second_relay.public_key(), cluster.chain)).unwrap();
    route.shift(&CryptDENull::from(exit_node.public_key(), cluster.chain)).unwrap();
    route.shift(&CryptDENull::from(second_relay.public_key(), cluster.chain)).unwrap();
    // Needs one more shift, but that will be done inside transmit_package()
    let package = IncipientCoresPackage::new(
        originating_node.main_cryptde_null().unwrap(), // must be the CryptDE of the Node to which the top hop is encrypted
        route,
        MessageType::ClientResponse(VersionedData::new(
            &node_lib::sub_lib::migrations::client_response_payload::MIGRATIONS,
            &ClientResponsePayload_0v1 {
                stream_key,
                sequenced_packet: SequencedPacket::new(vec![42, 48, 193, 3], 2, false),
            }
        )),
        originating_node.main_public_key(),
    ).unwrap();
    let first_relay_payable_before = payable_dao.account_status(&first_relay.earning_wallet()).unwrap().balance_wei;
    let second_relay_payable_before = payable_dao.account_status(&second_relay.earning_wallet()).unwrap().balance_wei;
    let exit_node_payable_before = payable_dao.account_status(&exit_node.earning_wallet()).unwrap().balance_wei;
    first_relay.transmit_package(
        // There should be some data in this package, and last_data should be false
        first_relay.port_list()[0],
        package,
        &masquerader,
        originating_node.main_public_key(),
        SocketAddr::new(originating_node.ip_address(), originating_node.port_list()[0]),
    ).unwrap();
    wait_for(Some(500), Some(5000), || {
        let first_relay_payable_after = payable_dao.account_status(&first_relay.earning_wallet()).unwrap().balance_wei;
        let second_relay_payable_after = payable_dao.account_status(&second_relay.earning_wallet()).unwrap().balance_wei;
        let exit_node_payable_after = payable_dao.account_status(&exit_node.earning_wallet()).unwrap().balance_wei;

        let mut messages: Vec<String> = vec![];
        let mut compare = |before: u128, after: u128, name: &str| {
            if after == before {
                messages.push(format!("Payable to {} not yet updated; still {}", name, before));
            }
        };
        compare(first_relay_payable_before, first_relay_payable_after, "first_relay");
        compare(second_relay_payable_before, second_relay_payable_after, "second_relay");
        compare(exit_node_payable_before, exit_node_payable_after, "exit_node");
        if messages.is_empty() {
            true
        } else {
            eprintln!("{}", "");
            eprintln!("{}", messages.join("\n"));
            false
        }
    });
}

#[test]
// Given: Originating Node is real_node; exit Node is fictional Node with exit_key.
// Given: A stream is established from the client through the originating Node.
// When: Originating Node receives empty SequencedPacket having last_data = true.
// Then: Originating Node drops connection to client (browser?).
// Then: Originating Node does _not_ send CORES package back to exit Node.
fn reported_server_drop() {
    let mut cluster = MASQNodeCluster::start().unwrap();
    let (originating_node, first_relay, _, exit) = create_neighborhood(&mut cluster);
    let exit_cryptde = CryptDENull::from(exit.public_key(), cluster.chain);
    let mut client = originating_node.make_client(8080, STANDARD_CLIENT_TIMEOUT_MILLIS);
    let masquerader = JsonMasquerader::new();
    client.send_chunk(HTTP_REQUEST);
    let (_, _, lcp) = first_relay
        .wait_for_package(&masquerader, Duration::from_secs(2))
        .unwrap();
    let (stream_key, return_route_id) =
        context_from_request_lcp(lcp, originating_node.main_cryptde_null().unwrap(), &exit_cryptde);

    first_relay
        .transmit_package(
            first_relay.port_list()[0],
            create_server_drop_report(&first_relay, &originating_node, stream_key, return_route_id),
            &masquerader,
            originating_node.main_public_key(),
            originating_node.socket_addr(PortSelector::First),
        )
        .unwrap();

    wait_for_client_shutdown(&originating_node);
    ensure_no_further_traffic(&first_relay, &masquerader);
}

#[ignore]
#[test]
// Given: Exit Node is real_node; originating Node is mock_node.
// Given: A stream is established through the exit Node to a server.
// When: Server drops connection to exit Node.
// Then: Exit Node sends ClientRequestPayload to originating Node with empty SequencedPacket having last_data = true.
fn actual_server_drop() {
    let mut cluster = MASQNodeCluster::start().unwrap();
    let (exit_node, second_relay, _, _) = create_neighborhood(&mut cluster);
    let server_port = find_free_port();
    let mut server = exit_node.make_server(server_port);
    let masquerader = JsonMasquerader::new();
    let (stream_key, return_route_id) = arbitrary_context();
    let index: u64 = 0;
    request_server_payload(
        index,
        &cluster,
        &exit_node,
        &second_relay,
        &mut server,
        &masquerader,
        stream_key,
        return_route_id,
    );
    let index: u64 = 1;
    request_server_payload(
        index,
        &cluster,
        &exit_node,
        &second_relay,
        &mut server,
        &masquerader,
        stream_key,
        return_route_id,
    );

    server.shutdown();

    // Send another package to trigger do_housekeeping() in the StreamHandlerPool: agh.
    second_relay
        .transmit_package(
            second_relay.port_list()[0],
            create_meaningless_icp(&second_relay, &exit_node),
            &masquerader,
            exit_node.main_public_key(),
            exit_node.socket_addr(PortSelector::First),
        )
        .unwrap();
    let (_, _, lcp) = second_relay
        .wait_for_package(&masquerader, Duration::from_secs(1))
        .unwrap();
    let payload = match decodex::<MessageType>(second_relay.main_cryptde_null().unwrap(), &lcp.payload)
        .unwrap()
    {
        MessageType::ClientResponse(vd) => vd
            .extract(&node_lib::sub_lib::migrations::client_response_payload::MIGRATIONS)
            .unwrap(),
        mt => panic!("Unexpected: {:?}", mt),
    };
    assert!(payload.sequenced_packet.data.is_empty());
    assert!(payload.sequenced_packet.last_data);
}

fn request_server_payload(
    index: u64,
    cluster: &MASQNodeCluster,
    real_node: &MASQRealNode,
    mock_node: &MASQMockNode,
    server: &mut MASQNodeServer,
    masquerader: &JsonMasquerader,
    stream_key: StreamKey,
    return_route_id: u32,
) {
    mock_node
        .transmit_package(
            mock_node.port_list()[0],
            create_request_icp(
                index,
                &mock_node,
                &real_node,
                stream_key,
                return_route_id,
                &server,
                cluster.chain,
            ),
            masquerader,
            real_node.main_public_key(),
            real_node.socket_addr(PortSelector::First),
        )
        .unwrap();
    server.wait_for_chunk(Duration::from_secs(2)).unwrap();
    server.send_chunk(HTTP_RESPONSE);
    mock_node
        .wait_for_package(masquerader, Duration::from_secs(2))
        .unwrap();
}

#[test]
// Given: Exit Node is real_node; originating Node is mock_node.
// Given: A stream is established through the exit Node to a server.
// When: Exit Node receives empty SequencedPacket having last_data = true.
// Then: Exit Node drops connection to server.
// Then: Exit Node does _not_ send CORES package back to originating Node.
fn reported_client_drop() {
    let mut cluster = MASQNodeCluster::start().unwrap();
    let (exit_node, second_relay, _, _) = create_neighborhood(&mut cluster);
    let server_port = find_free_port();
    let mut server = exit_node.make_server(server_port);
    let masquerader = JsonMasquerader::new();
    let (stream_key, return_route_id) = arbitrary_context();
    let index: u64 = 0;
    second_relay
        .transmit_package(
            second_relay.port_list()[0],
            create_request_icp(
                index,
                &second_relay,
                &exit_node,
                stream_key,
                return_route_id,
                &server,
                cluster.chain,
            ),
            &masquerader,
            exit_node.main_public_key(),
            exit_node.socket_addr(PortSelector::First),
        )
        .unwrap();
    server.wait_for_chunk(Duration::from_secs(1)).unwrap();
    server.send_chunk(HTTP_RESPONSE);
    second_relay
        .wait_for_package(&masquerader, Duration::from_secs(1))
        .unwrap();

    second_relay
        .transmit_package(
            second_relay.port_list()[0],
            create_client_drop_report(&second_relay, &exit_node, stream_key, return_route_id),
            &masquerader,
            exit_node.main_public_key(),
            exit_node.socket_addr(PortSelector::First),
        )
        .unwrap();

    wait_for_server_shutdown(&exit_node, server.local_addr());
    ensure_no_further_traffic(&second_relay, &masquerader);
}

#[test]
fn downed_nodes_not_offered_in_passes_or_introductions() {
    let real_node: NodeRecord = make_node_record(1234, true);
    let mut db: NeighborhoodDatabase = db_from_node(&real_node);
    let desirable_but_down = db.add_node(make_node_record(2345, true)).unwrap();
    let undesirable_but_up = db.add_node(make_node_record(3456, true)).unwrap();
    let fictional = db.add_node(make_node_record(4567, true)).unwrap();
    db.add_arbitrary_full_neighbor(real_node.public_key(), &desirable_but_down);
    db.add_arbitrary_full_neighbor(real_node.public_key(), &undesirable_but_up);
    db.add_arbitrary_full_neighbor(&desirable_but_down, &undesirable_but_up);
    db.add_arbitrary_full_neighbor(&desirable_but_down, &fictional);

    let mut cluster = MASQNodeCluster::start().unwrap();
    let (_, masq_real_node, mut node_map) =
        construct_neighborhood(&mut cluster, db, vec![], do_not_modify_config());
    let desirable_but_down_node = node_map.remove(&desirable_but_down).unwrap();
    let undesirable_but_up_node = node_map.remove(&undesirable_but_up).unwrap();
    let debuter: NodeRecord = make_node_record(5678, true);
    let debuter_node = cluster.start_mock_node_with_public_key(vec![5550], debuter.public_key());

    // Kill desirable neighbor
    desirable_but_down_node.kill();
    // Debut a new Node
    debuter_node.transmit_debut(&masq_real_node).unwrap();
    // What's the return Gossip?
    let (gossip, ip_addr) = debuter_node
        .wait_for_gossip(Duration::from_secs(2))
        .unwrap();
    match parse_gossip(&gossip, ip_addr) {
        GossipType::IntroductionGossip(introduction) => {
            // It's an Introduction of the one that didn't go down!
            assert_eq!(
                introduction.introducee_key(),
                undesirable_but_up_node.main_public_key()
            );
        }
        unexpected => panic!("Unexpected gossip: {:?}", unexpected),
    }
}

#[test]
// Given: Originating Node is real_node; relay Node is mock_node.
// Given: A stream is established from a client into the originating Node through the relay Node.
// Given: The client shuts down the stream, resulting in a last_data=true SequencedPacket.
// When: The last few packets from the server straggle into the Originating Node
// Then: The Nodes that participated in their transfer are properly credited.
fn pipeline_is_properly_drained() {
    let mut cluster = MASQNodeCluster::start().unwrap();
    let (originating_node, first_relay, second_relay, exit) =
        create_neighborhood(&mut cluster);
    let exit_cryptde = CryptDENull::from(exit.public_key(), cluster.chain);
    let mut client = originating_node.make_client(8080, STANDARD_CLIENT_TIMEOUT_MILLIS);
    let masquerader = JsonMasquerader::new();
    client.send_chunk(HTTP_REQUEST);
    let (_, _, lcp) = first_relay
        .wait_for_package(&masquerader, Duration::from_secs(2))
        .unwrap();
    let (stream_key, return_route_id) =
        context_from_request_lcp(lcp, originating_node.main_cryptde_null().unwrap(), &exit_cryptde);

    first_relay
        .transmit_package(
            first_relay.port_list()[0],
            create_server_drop_report(&first_relay, &originating_node, stream_key, return_route_id),
            &masquerader,
            originating_node.main_public_key(),
            originating_node.socket_addr(PortSelector::First),
        )
        .unwrap();

    wait_for_client_shutdown(&originating_node);
    ensure_no_further_traffic(&first_relay, &masquerader);
}

fn create_neighborhood(cluster: &mut MASQNodeCluster) -> (MASQRealNode, MASQMockNode, NodeRecord, NodeRecord) {
    let mut near_end: NodeRecord = make_node_record(1234, true);
    let mut near_relay: NodeRecord = make_node_record(2345, true);
    let mut far_relay: NodeRecord = make_node_record(3456, true);
    let mut far_end: NodeRecord = make_node_record(4567, true);
    full_neighbor(&mut near_end, &mut near_relay);
    full_neighbor(&mut near_relay, &mut far_relay);
    full_neighbor(&mut far_relay, &mut far_end);
    let mut db: NeighborhoodDatabase = db_from_node(&near_end);
    full_neighbor(db.root_mut(), &mut near_relay);
    db.add_node(near_relay.clone()).unwrap();
    db.add_node(far_relay.clone()).unwrap();
    db.add_node(far_end.clone()).unwrap();
    let (_, masq_real_node, mut node_map) =
        construct_neighborhood(cluster, db, vec![], do_not_modify_config());
    let masq_mock_node = node_map.remove(near_relay.public_key()).unwrap();
    (
        masq_real_node,
        masq_mock_node,
        far_relay,
        far_end,
    )
}

fn full_neighbor(one: &mut NodeRecord, another: &mut NodeRecord) {
    one.add_half_neighbor_key(another.public_key().clone())
        .unwrap();
    another
        .add_half_neighbor_key(one.public_key().clone())
        .unwrap();
}

fn context_from_request_lcp(
    lcp: LiveCoresPackage,
    originating_cryptde: &dyn CryptDE,
    exit_cryptde: &dyn CryptDE,
) -> (StreamKey, u32) {
    let payload = match decodex::<MessageType>(exit_cryptde, &lcp.payload).unwrap() {
        MessageType::ClientRequest(vd) => vd
            .extract(&node_lib::sub_lib::migrations::client_request_payload::MIGRATIONS)
            .unwrap(),
        mt => panic!("Unexpected: {:?}", mt),
    };
    let stream_key = payload.stream_key;
    let return_route_id = decodex::<u32>(originating_cryptde, &lcp.route.hops[6]).unwrap();
    (stream_key, return_route_id)
}

fn arbitrary_context() -> (StreamKey, u32) {
    (
        StreamKey::make_meaningful_stream_key("arbitrary_context"),
        12345678,
    )
}

fn create_request_icp(
    index: u64,
    originating_node: &MASQMockNode,
    exit_node: &MASQRealNode,
    stream_key: StreamKey,
    return_route_id: u32,
    server: &MASQNodeServer,
    chain: Chain,
) -> IncipientCoresPackage {
    IncipientCoresPackage::new(
        originating_node.main_cryptde_null().unwrap(),
        Route::round_trip(
            RouteSegment::new(
                vec![
                    originating_node.main_public_key(),
                    exit_node.main_public_key(),
                ],
                Component::ProxyClient,
            ),
            RouteSegment::new(
                vec![
                    exit_node.main_public_key(),
                    originating_node.main_public_key(),
                ],
                Component::ProxyServer,
            ),
            originating_node.main_cryptde_null().unwrap(),
            originating_node.consuming_wallet(),
            return_route_id,
            Some(chain.rec().contract),
        )
        .unwrap(),
        MessageType::ClientRequest(VersionedData::new(
            &node_lib::sub_lib::migrations::client_request_payload::MIGRATIONS,
            &ClientRequestPayload_0v1 {
                stream_key,
                sequenced_packet: SequencedPacket::new(Vec::from(HTTP_REQUEST), index, false),
                target_hostname: Some(format!("{}", server.local_addr().ip())),
                target_port: server.local_addr().port(),
                protocol: ProxyProtocol::HTTP,
                originator_public_key: originating_node.main_public_key().clone(),
            },
        )),
        exit_node.main_public_key(),
    )
    .unwrap()
}

fn create_meaningless_icp(
    originating_node: &MASQMockNode,
    exit_node: &MASQRealNode,
) -> IncipientCoresPackage {
    let socket_addr = SocketAddr::from_str("3.2.1.0:7654").unwrap();
    let stream_key =
        StreamKey::make_meaningful_stream_key("Chancellor on brink of second bailout for banks");
    IncipientCoresPackage::new(
        originating_node.main_cryptde_null().unwrap(),
        Route::round_trip(
            RouteSegment::new(
                vec![
                    originating_node.main_public_key(),
                    exit_node.main_public_key(),
                ],
                Component::ProxyClient,
            ),
            RouteSegment::new(
                vec![
                    exit_node.main_public_key(),
                    originating_node.main_public_key(),
                ],
                Component::ProxyServer,
            ),
            originating_node.main_cryptde_null().unwrap(),
            originating_node.consuming_wallet(),
            1357,
            Some(TEST_DEFAULT_MULTINODE_CHAIN.rec().contract),
        )
        .unwrap(),
        MessageType::ClientRequest(VersionedData::new(
            &node_lib::sub_lib::migrations::client_request_payload::MIGRATIONS,
            &ClientRequestPayload_0v1 {
                stream_key,
                sequenced_packet: SequencedPacket::new(Vec::from(HTTP_REQUEST), 0, false),
                target_hostname: Some(format!("nowhere.com")),
                target_port: socket_addr.port(),
                protocol: ProxyProtocol::HTTP,
                originator_public_key: originating_node.main_public_key().clone(),
            },
        )),
        exit_node.main_public_key(),
    )
    .unwrap()
}

fn create_final_icp(
    originating_node: &MASQRealNode,
    exit_key: &PublicKey,
) -> IncipientCoresPackage {
    let socket_addr = SocketAddr::from_str("3.2.1.0:7654").unwrap();
    let stream_key =
        StreamKey::make_meaningful_stream_key("Chancellor on brink of second bailout for banks");
    IncipientCoresPackage::new(
        originating_node.main_cryptde_null().unwrap(),
        Route::round_trip(
            RouteSegment::new(
                vec![
                    originating_node.main_public_key(),
                    exit_key,
                ],
                Component::ProxyClient,
            ),
            RouteSegment::new(
                vec![
                    exit_key,
                    originating_node.main_public_key(),
                ],
                Component::ProxyServer,
            ),
            originating_node.main_cryptde_null().unwrap(),
            originating_node.consuming_wallet(),
            1357,
            Some(TEST_DEFAULT_MULTINODE_CHAIN.rec().contract),
        )
        .unwrap(),
        MessageType::ClientRequest(VersionedData::new(
            &node_lib::sub_lib::migrations::client_request_payload::MIGRATIONS,
            &ClientRequestPayload_0v1 {
                stream_key,
                sequenced_packet: SequencedPacket::new(Vec::from(HTTP_REQUEST), 1, true),
                target_hostname: Some(format!("nowhere.com")),
                target_port: socket_addr.port(),
                protocol: ProxyProtocol::HTTP,
                originator_public_key: originating_node.main_public_key().clone(),
            },
        )),
        exit_key,
    )
    .unwrap()
}

fn create_server_drop_report(
    exit_node: &MASQMockNode,
    originating_node: &MASQRealNode,
    stream_key: StreamKey,
    return_route_id: u32,
) -> IncipientCoresPackage {
    let mut route = Route::round_trip(
        RouteSegment::new(
            vec![
                originating_node.main_public_key(),
                exit_node.main_public_key(),
            ],
            Component::ProxyClient,
        ),
        RouteSegment::new(
            vec![
                exit_node.main_public_key(),
                originating_node.main_public_key(),
            ],
            Component::ProxyServer,
        ),
        originating_node.main_cryptde_null().unwrap(),
        originating_node.consuming_wallet(),
        return_route_id,
        Some(TEST_DEFAULT_MULTINODE_CHAIN.rec().contract),
    )
    .unwrap();
    route
        .shift(originating_node.main_cryptde_null().unwrap())
        .unwrap();
    let payload = MessageType::ClientResponse(VersionedData::new(
        &node_lib::sub_lib::migrations::client_response_payload::MIGRATIONS,
        &ClientResponsePayload_0v1 {
            stream_key,
            sequenced_packet: SequencedPacket::new(vec![], 0, true),
        },
    ));

    IncipientCoresPackage::new(
        exit_node.main_cryptde_null().unwrap(),
        route,
        payload,
        originating_node.alias_public_key(),
    )
    .unwrap()
}

fn create_client_drop_report(
    originating_node: &MASQMockNode,
    exit_node: &MASQRealNode,
    stream_key: StreamKey,
    return_route_id: u32,
) -> IncipientCoresPackage {
    let route = Route::round_trip(
        RouteSegment::new(
            vec![
                originating_node.main_public_key(),
                exit_node.main_public_key(),
            ],
            Component::ProxyClient,
        ),
        RouteSegment::new(
            vec![
                exit_node.main_public_key(),
                originating_node.main_public_key(),
            ],
            Component::ProxyServer,
        ),
        originating_node.main_cryptde_null().unwrap(),
        originating_node.consuming_wallet(),
        return_route_id,
        Some(TEST_DEFAULT_MULTINODE_CHAIN.rec().contract),
    )
    .unwrap();
    let payload = MessageType::ClientRequest(VersionedData::new(
        &node_lib::sub_lib::migrations::client_request_payload::MIGRATIONS,
        &ClientRequestPayload_0v1 {
            stream_key,
            sequenced_packet: SequencedPacket::new(vec![], 1, true),
            target_hostname: Some(String::from("doesnt.matter.com")),
            target_port: 80,
            protocol: ProxyProtocol::HTTP,
            originator_public_key: originating_node.main_public_key().clone(),
        },
    ));

    IncipientCoresPackage::new(
        originating_node.main_cryptde_null().unwrap(),
        route,
        payload,
        exit_node.main_public_key(),
    )
    .unwrap()
}

fn ensure_no_further_traffic(mock_node: &MASQMockNode, masquerader: &dyn Masquerader) {
    match mock_node.wait_for_package(masquerader, Duration::from_secs(1)) {
        Ok((addr1, addr2, lcp)) => panic!(
            "Should not have received package, but: {:?} -> {:?}:\n{:?}",
            addr1, addr2, lcp
        ),
        Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => (), // expected: pass
        Err(ref e) => panic!("Unexpected error: {:?}", e),
    }
}

fn wait_for_client_shutdown(real_node: &MASQRealNode) {
    // This is a jury-rigged way to wait for a shutdown, since client.wait_for_shutdown() doesn't
    // work, but it serves the purpose.
    MASQNodeUtils::assert_node_wrote_log_containing(
        real_node.name(),
        "Shutting down stream to client at 127.0.0.1",
        Duration::from_secs(1),
    );
}

fn wait_for_server_shutdown(real_node: &MASQRealNode, local_addr: SocketAddr) {
    // This is a jury-rigged way to wait for a shutdown, since server.wait_for_shutdown() doesn't
    // work, but it serves the purpose.
    MASQNodeUtils::assert_node_wrote_log_containing(
        real_node.name(),
        &format!(
            "Shutting down stream to server at {} in response to client-drop report",
            local_addr
        ),
        Duration::from_secs(1),
    );
}
