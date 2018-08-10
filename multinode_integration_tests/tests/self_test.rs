// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
extern crate regex;
extern crate sub_lib;
extern crate multinode_integration_tests_lib;
extern crate node_lib;
extern crate serde_cbor;

use std::collections::HashSet;
use std::net::IpAddr;
use std::net::TcpStream;
use std::net::SocketAddr;
use std::io::ErrorKind;
use std::time::Duration;
use multinode_integration_tests_lib::substratum_node_cluster::SubstratumNodeCluster;
use multinode_integration_tests_lib::command::Command;
use multinode_integration_tests_lib::substratum_node::NodeStartupConfigBuilder;
use std::net::Ipv4Addr;
use node_lib::json_masquerader::JsonMasquerader;
use multinode_integration_tests_lib::substratum_cores_server::SubstratumCoresServer;
use multinode_integration_tests_lib::substratum_cores_client::SubstratumCoresClient;
use sub_lib::route::Route;
use sub_lib::route::RouteSegment;
use sub_lib::dispatcher::Component;
use sub_lib::hopper::IncipientCoresPackage;
use sub_lib::hopper::ExpiredCoresPackage;

#[test]
fn establishes_substratum_node_cluster_from_nothing () {
    let mut cluster = SubstratumNodeCluster::start ().unwrap ();
    assert_eq!(network_is_running(), true);
    {
        let node_1_name = "test_node_1";
        let node_2_name = "test_node_2";
        let first_ip_addr = IpAddr::V4 (Ipv4Addr::new (172, 18, 1, 1));
        let second_ip_addr = IpAddr::V4 (Ipv4Addr::new (172, 18, 1, 2));
        cluster.start_node(NodeStartupConfigBuilder::bootstrap().build()).unwrap();
        cluster.start_node(NodeStartupConfigBuilder::bootstrap().build()).unwrap();

        let expected_nodes: HashSet<String> = vec![node_1_name.to_string(), node_2_name.to_string()].into_iter().collect();
        assert_eq!(cluster.running_node_names(), expected_nodes);
        check_node(&cluster, node_1_name, "172.18.1.1");
        check_node(&cluster, node_2_name, "172.18.1.2");

        cluster.stop_node(node_1_name).unwrap();
        ensure_node_is_not_running(node_1_name, first_ip_addr);
        ensure_node_is_running(node_2_name, second_ip_addr);

        cluster.stop_node(node_2_name).unwrap();
        ensure_node_is_not_running(node_1_name, first_ip_addr);
        ensure_node_is_not_running(node_2_name, second_ip_addr);
    }
    cluster.stop ().unwrap ();
    assert_eq! (network_is_running (), false);
}

#[test]
fn dropping_node_and_cluster_cleans_up () {
    let first_ip_addr = IpAddr::V4(Ipv4Addr::new(172, 18, 1, 1));
    {
        let mut cluster = SubstratumNodeCluster::start().unwrap();
        cluster.start_node(NodeStartupConfigBuilder::bootstrap().build()).unwrap();
    }

    assert_eq! (node_is_running (first_ip_addr), false);
    assert_eq! (network_is_running (), false);
}

#[test]
fn relays_cores_package () {
    let _cluster = SubstratumNodeCluster::start ().unwrap ();
    let masquerader = JsonMasquerader::new ();
    let server = SubstratumCoresServer::new ();
    let cryptde = server.cryptde ();
    let mut client = SubstratumCoresClient::new (server.local_addr (), cryptde);
    let mut route = Route::new (
        vec! (
            RouteSegment::new (vec! (&cryptde.public_key(), &cryptde.public_key()), Component::Neighborhood)
        ),
        cryptde
    ).unwrap ();
    let payload = String::from ("Booga booga!");
    let incipient = IncipientCoresPackage::new (route.clone (), payload, &cryptde.public_key());

    client.transmit_package(incipient, &masquerader, cryptde.public_key());
    let expired: ExpiredCoresPackage = server.wait_for_package (Duration::from_millis(1000));

    route.shift (&cryptde.private_key (), cryptde);
    assert_eq! (expired.remaining_route, route);
    assert_eq! (serde_cbor::de::from_slice::<String> (&expired.payload.data[..]).unwrap (), String::from ("Booga booga!"));
}

fn check_node (cluster: &SubstratumNodeCluster, name: &str, ip_address: &str) {
    let node = cluster.get_node (name).unwrap ();
    assert_eq! (node.name(), name);
    assert_eq! (format! ("{}", node.node_reference()).contains (ip_address), true, "{}", node.node_reference());
    assert_eq! (format! ("{}", node.ip_address()), String::from (ip_address));
    assert_eq! (node.port_list().len (), 1);
    ensure_node_is_running(name, node.ip_address());
}

fn node_is_running(ip_address: IpAddr) -> bool {
    let socket_addr = SocketAddr::new(ip_address, 80);
    match TcpStream::connect_timeout(&socket_addr, Duration::from_millis(100)) {
        Ok(_) => true,
        Err(ref e) if e.kind() == ErrorKind::TimedOut => false,
        Err(e) => panic!("{}", e),
    }
}

fn network_is_running () -> bool {
    let mut command = Command::new ("docker", Command::strings (vec! ("network", "ls")));
    assert_eq! (command.wait_for_exit (), 0);
    let output = command.stdout_as_string();
    output.contains ("integration_net")
}

fn ensure_node_is_running(container_name: &str, ip_address: IpAddr) {
    assert_eq!(node_is_running(ip_address), true, "{} should be running on {}, but isn't", container_name, ip_address)
}

fn ensure_node_is_not_running(container_name: &str, ip_address: IpAddr) {
    assert_eq!(node_is_running(ip_address), false, "{} should not be running on {}, but is", container_name, ip_address)
}
