// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use multinode_integration_tests_lib::command::Command;
use multinode_integration_tests_lib::main::CONTROL_STREAM_PORT;
use multinode_integration_tests_lib::masq_cores_client::MASQCoresClient;
use multinode_integration_tests_lib::masq_cores_server::MASQCoresServer;
use multinode_integration_tests_lib::masq_node::MASQNode;
use multinode_integration_tests_lib::masq_node::PortSelector;
use multinode_integration_tests_lib::masq_node_cluster::MASQNodeCluster;
use multinode_integration_tests_lib::masq_real_node::NodeStartupConfigBuilder;
use node_lib::json_masquerader::JsonMasquerader;
use node_lib::sub_lib::cryptde::PublicKey;
use node_lib::sub_lib::dispatcher::Component;
use node_lib::sub_lib::hopper::IncipientCoresPackage;
use node_lib::sub_lib::route::Route;
use node_lib::sub_lib::route::RouteSegment;
use node_lib::test_utils::{make_meaningless_message_type, make_paying_wallet};
use std::collections::HashSet;
use std::io::ErrorKind;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::net::TcpStream;
use std::str::FromStr;
use std::time::Duration;
use masq_lib::test_utils::utils::TEST_DEFAULT_CHAIN;
use node_lib::sub_lib::cryptde_null::CryptDENull;

#[test]
fn establishes_masq_node_cluster_from_nothing() {
    let mut cluster = MASQNodeCluster::start().unwrap();
    assert_eq!(network_is_running(), true);
    let real_node_name = "test_node_1";
    let mock_node_name = "mock_node_2";
    let first_ip_addr = IpAddr::V4(Ipv4Addr::new(172, 18, 1, 1));
    let second_ip_addr = IpAddr::V4(Ipv4Addr::new(172, 18, 1, 2));
    cluster.start_real_node(
        NodeStartupConfigBuilder::standard()
            .fake_public_key(&PublicKey::new(&[1, 2, 3, 4]))
            .chain(cluster.chain)
            .build(),
    );
    cluster.start_mock_node_with_public_key(vec![2345], &PublicKey::new(&[2, 3, 4, 5]));

    let expected_nodes: HashSet<String> =
        vec![real_node_name.to_string(), mock_node_name.to_string()]
            .into_iter()
            .collect();
    assert_eq!(cluster.running_node_names(), expected_nodes);
    check_node(&cluster, real_node_name, "172.18.1.1", 8080);
    check_node(&cluster, mock_node_name, "172.18.1.2", CONTROL_STREAM_PORT);

    cluster.stop_node(real_node_name);
    ensure_node_is_not_running(real_node_name, first_ip_addr, 8080);
    ensure_node_is_running(mock_node_name, second_ip_addr, CONTROL_STREAM_PORT);

    cluster.stop_node(mock_node_name);
    ensure_node_is_not_running(real_node_name, first_ip_addr, 8080);
    ensure_node_is_not_running(mock_node_name, second_ip_addr, CONTROL_STREAM_PORT);

    cluster.stop();
    assert_eq!(network_is_running(), false);
}

#[test]
fn server_relays_cores_package() {
    let cluster = MASQNodeCluster::start().unwrap();
    let masquerader = JsonMasquerader::new();
    let server = MASQCoresServer::new(cluster.chain);
    let cryptde = server.main_cryptde();
    let mut client = MASQCoresClient::new(server.local_addr(), cryptde);
    let mut route = Route::one_way(
        RouteSegment::new(
            vec![&cryptde.public_key(), &cryptde.public_key()],
            Component::Neighborhood,
        ),
        cryptde,
        Some(make_paying_wallet(b"consuming")),
        Some(cluster.chain.rec().contract),
    )
    .unwrap();
    let incipient = IncipientCoresPackage::new(
        cryptde,
        route.clone(),
        make_meaningless_message_type(),
        &cryptde.public_key(),
    )
    .unwrap();

    client.transmit_package(incipient, &masquerader, cryptde.public_key().clone());
    let package = server.wait_for_package(Duration::from_millis(1000));
    let expired = package
        .to_expired(
            SocketAddr::from_str("1.2.3.4:1234").unwrap(),
            cryptde,
            cryptde,
        )
        .unwrap();

    route.shift(cryptde).unwrap();
    assert_eq!(expired.remaining_route, route);
    assert_eq!(expired.payload, make_meaningless_message_type());
}

#[test]
fn one_mock_node_talks_to_another() {
    let masquerader = JsonMasquerader::new();
    let mut cluster = MASQNodeCluster::start().unwrap();
    cluster.start_mock_node_with_public_key(vec![5550], &PublicKey::new(&[1, 2, 3, 4]));
    cluster.start_mock_node_with_public_key(vec![5551], &PublicKey::new(&[2, 3, 4, 5]));
    let mock_node_1 = cluster.get_mock_node_by_name("mock_node_1").unwrap();
    let mock_node_2 = cluster.get_mock_node_by_name("mock_node_2").unwrap();
    let cryptde = CryptDENull::new(TEST_DEFAULT_CHAIN);
    let route = Route::one_way(
        RouteSegment::new(
            vec![
                &mock_node_1.main_public_key(),
                &mock_node_2.main_public_key(),
            ],
            Component::Hopper,
        ),
        &cryptde,
        Some(make_paying_wallet(b"consuming")),
        Some(cluster.chain.rec().contract),
    )
    .unwrap();
    let incipient_cores_package = IncipientCoresPackage::new(
        &cryptde,
        route,
        make_meaningless_message_type(),
        &mock_node_2.main_public_key(),
    )
    .unwrap();

    mock_node_1
        .transmit_package(
            5550,
            incipient_cores_package,
            &masquerader,
            &mock_node_2.main_public_key(),
            mock_node_2.socket_addr(PortSelector::First),
        )
        .unwrap();
    let (package_from, package_to, package) = mock_node_2
        .wait_for_package(&masquerader, Duration::from_millis(1000))
        .unwrap();
    let expired_cores_package = package
        .to_expired(
            SocketAddr::from_str("1.2.3.4:1234").unwrap(),
            mock_node_2.main_cryptde_null().unwrap(),
            mock_node_2.main_cryptde_null().unwrap(),
        )
        .unwrap();

    assert_eq!(package_from.ip(), mock_node_1.ip_address());
    assert_eq!(package_to, mock_node_2.socket_addr(PortSelector::First));
    assert_eq!(
        expired_cores_package.payload,
        make_meaningless_message_type()
    );
}

fn check_node(cluster: &MASQNodeCluster, name: &str, ip_address: &str, port: u16) {
    let node = cluster
        .get_node_by_name(name)
        .expect(format!("Couldn't find node {} to check", name).as_str());
    assert_eq!(node.name(), name);
    assert_eq!(
        format!("{}", node.node_reference()).contains(ip_address),
        true,
        "{}",
        node.node_reference()
    );
    assert_eq!(format!("{}", node.ip_address()), String::from(ip_address));
    assert_eq!(node.port_list().len(), 1);
    ensure_node_is_running(name, node.ip_address(), port);
}

fn node_is_running(ip_address: IpAddr, port: u16) -> bool {
    let socket_addr = SocketAddr::new(ip_address, port);
    match TcpStream::connect_timeout(&socket_addr, Duration::from_millis(100)) {
        Ok(_) => true,
        Err(ref e) if e.kind() == ErrorKind::TimedOut => false,
        Err(ref e) if e.kind() == ErrorKind::AddrNotAvailable => false,
        Err(e) => panic!("Could not connect to {}: {}", socket_addr, e),
    }
}

fn network_is_running() -> bool {
    let mut command = Command::new("docker", Command::strings(vec!["network", "ls"]));
    assert_eq!(command.wait_for_exit(), 0);
    let output = command.stdout_as_string();
    output.contains("integration_net")
}

fn ensure_node_is_running(container_name: &str, ip_address: IpAddr, port: u16) {
    assert_eq!(
        node_is_running(ip_address, port),
        true,
        "{} should be running on {}, but isn't",
        container_name,
        ip_address
    )
}

fn ensure_node_is_not_running(container_name: &str, ip_address: IpAddr, port: u16) {
    assert_eq!(
        node_is_running(ip_address, port),
        false,
        "{} should not be running on {}, but is",
        container_name,
        ip_address
    )
}
