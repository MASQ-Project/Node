// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
extern crate multinode_integration_tests_lib;
extern crate node_lib;
extern crate regex;
extern crate serde_cbor;
extern crate sub_lib;
extern crate test_utils;

use multinode_integration_tests_lib::command::Command;
use multinode_integration_tests_lib::main::CONTROL_STREAM_PORT;
use multinode_integration_tests_lib::substratum_cores_client::SubstratumCoresClient;
use multinode_integration_tests_lib::substratum_cores_server::SubstratumCoresServer;
use multinode_integration_tests_lib::substratum_node::NodeReference;
use multinode_integration_tests_lib::substratum_node::PortSelector;
use multinode_integration_tests_lib::substratum_node::SubstratumNode;
use multinode_integration_tests_lib::substratum_node_cluster::SubstratumNodeCluster;
use multinode_integration_tests_lib::substratum_real_node::NodeStartupConfigBuilder;
use node_lib::json_masquerader::JsonMasquerader;
use std::collections::HashSet;
use std::io::ErrorKind;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::net::TcpStream;
use std::time::Duration;
use sub_lib::cryptde::Key;
use sub_lib::cryptde_null::CryptDENull;
use sub_lib::dispatcher::Component;
use sub_lib::hopper::IncipientCoresPackage;
use sub_lib::neighborhood::sentinel_ip_addr;
use sub_lib::route::Route;
use sub_lib::route::RouteSegment;
use test_utils::test_utils::wait_for;

#[test]
fn establishes_substratum_node_cluster_from_nothing() {
    let mut cluster = SubstratumNodeCluster::start().unwrap();
    assert_eq!(network_is_running(), true);
    let real_node_name = "test_node_1";
    let mock_node_name = "mock_node_2";
    let first_ip_addr = IpAddr::V4(Ipv4Addr::new(172, 18, 1, 1));
    let second_ip_addr = IpAddr::V4(Ipv4Addr::new(172, 18, 1, 2));
    cluster.start_real_node(
        NodeStartupConfigBuilder::standard()
            .neighbor(NodeReference::new(
                Key::new(&[1]),
                sentinel_ip_addr(),
                vec![1234],
            ))
            .build(),
    );
    cluster.start_mock_node(vec![2345]);

    let expected_nodes: HashSet<String> =
        vec![real_node_name.to_string(), mock_node_name.to_string()]
            .into_iter()
            .collect();
    assert_eq!(cluster.running_node_names(), expected_nodes);
    check_node(&cluster, real_node_name, "172.18.1.1", 80);
    check_node(&cluster, mock_node_name, "172.18.1.2", CONTROL_STREAM_PORT);

    cluster.stop_node(real_node_name);
    ensure_node_is_not_running(real_node_name, first_ip_addr, 80);
    ensure_node_is_running(mock_node_name, second_ip_addr, CONTROL_STREAM_PORT);

    cluster.stop_node(mock_node_name);
    ensure_node_is_not_running(real_node_name, first_ip_addr, 80);
    ensure_node_is_not_running(mock_node_name, second_ip_addr, CONTROL_STREAM_PORT);

    cluster.stop();
    assert_eq!(network_is_running(), false);
}

#[test]
fn dropping_node_and_cluster_cleans_up() {
    let real_ip_addr = IpAddr::V4(Ipv4Addr::new(172, 18, 1, 1));
    let mock_ip_addr = IpAddr::V4(Ipv4Addr::new(172, 18, 1, 2));
    {
        let mut cluster = SubstratumNodeCluster::start().unwrap();
        cluster.start_real_node(NodeStartupConfigBuilder::bootstrap().build());
        cluster.start_mock_node(vec![1234]);
    }

    wait_for(None, None, || !node_is_running(real_ip_addr, 80));
    wait_for(None, None, || {
        !node_is_running(mock_ip_addr, CONTROL_STREAM_PORT)
    });
    wait_for(None, None, || !network_is_running());
}

#[test]
fn server_relays_cores_package() {
    let _cluster = SubstratumNodeCluster::start().unwrap();
    let masquerader = JsonMasquerader::new();
    let server = SubstratumCoresServer::new();
    let cryptde = server.cryptde();
    let mut client = SubstratumCoresClient::new(server.local_addr(), cryptde);
    let mut route = Route::new(
        vec![RouteSegment::new(
            vec![&cryptde.public_key(), &cryptde.public_key()],
            Component::Neighborhood,
        )],
        cryptde,
    )
    .unwrap();
    let payload = String::from("Booga booga!");
    let incipient = IncipientCoresPackage::new(route.clone(), payload, &cryptde.public_key());

    client.transmit_package(incipient, &masquerader, cryptde.public_key());
    let package = server.wait_for_package(Duration::from_millis(1000));
    let expired = package.to_expired(server.cryptde());

    route.shift(cryptde);
    assert_eq!(expired.remaining_route, route);
    assert_eq!(
        serde_cbor::de::from_slice::<String>(&expired.payload.data[..]).unwrap(),
        String::from("Booga booga!")
    );
}

#[test]
fn one_mock_node_talks_to_another() {
    let masquerader = JsonMasquerader::new();
    let mut cluster = SubstratumNodeCluster::start().unwrap();
    cluster.start_mock_node(vec![5550]);
    cluster.start_mock_node(vec![5551]);
    let mock_node_1 = cluster.get_mock_node("mock_node_1").unwrap();
    let mock_node_2 = cluster.get_mock_node("mock_node_2").unwrap();
    let cryptde = CryptDENull::new();
    let route = Route::new(
        vec![RouteSegment::new(
            vec![&mock_node_1.public_key(), &mock_node_2.public_key()],
            Component::Hopper,
        )],
        &cryptde,
    )
    .unwrap();
    let incipient_cores_package =
        IncipientCoresPackage::new(route, String::from("payload"), &mock_node_2.public_key());

    mock_node_1
        .transmit_package(
            5550,
            incipient_cores_package,
            &masquerader,
            &mock_node_2.public_key(),
            mock_node_2.socket_addr(PortSelector::First),
        )
        .unwrap();
    let (package_from, package_to, package) = mock_node_2
        .wait_for_package(&masquerader, Duration::from_millis(1000))
        .unwrap();
    let expired_cores_package = package.to_expired(mock_node_2.cryptde());

    assert_eq!(package_from.ip(), mock_node_1.ip_address());
    assert_eq!(package_to, mock_node_2.socket_addr(PortSelector::First));
    let actual_payload: String = expired_cores_package.payload().unwrap();
    assert_eq!(actual_payload, String::from("payload"));
}

fn check_node(cluster: &SubstratumNodeCluster, name: &str, ip_address: &str, port: u16) {
    let node = cluster
        .get_node(name)
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
