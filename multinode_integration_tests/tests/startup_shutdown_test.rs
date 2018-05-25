// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
extern crate regex;
extern crate multinode_integration_tests_lib;

use std::collections::HashSet;
use std::net::IpAddr;
use std::str::FromStr;
use std::net::TcpStream;
use std::net::SocketAddr;
use std::io::ErrorKind;
use std::time::Duration;
use regex::Regex;
use multinode_integration_tests_lib::substratum_node_cluster::NodeStartupConfig;
use multinode_integration_tests_lib::substratum_node_cluster::SubstratumNodeCluster;
use multinode_integration_tests_lib::command::Command;

#[test]
fn starts_and_stops_substratum_nodes () {
    clear_leaked_containers ();

    let mut subject = SubstratumNodeCluster::new (vec! (
        NodeStartupConfig::new (vec! (1234)),
        NodeStartupConfig::new (vec! (2345)),
        NodeStartupConfig::new (vec! (3456)),
    ));

    let expected_nodes: HashSet<String> = vec!["test_node_1".to_string (), "test_node_2".to_string (), "test_node_3".to_string ()].into_iter().collect();
    assert_eq!(subject.running_node_names(), expected_nodes);
    check_node(&subject, "test_node_1", 1234, "172.18.1.1");
    check_node(&subject, "test_node_2", 2345, "172.18.1.2");
    check_node(&subject, "test_node_3", 3456, "172.18.1.3");

    let result = subject.stop ("test_node_1");

    assert_eq! (result, true);
    let expected_nodes: HashSet<String> = vec!["test_node_2".to_string (), "test_node_3".to_string ()].into_iter().collect();
    assert_eq!(subject.running_node_names(), expected_nodes);
    assert_eq!(subject.get_node ("test_node_1").is_none (), true);
    assert_eq!(node_is_running ("172.18.1.1"), false);
    check_node(&subject, "test_node_2", 2345, "172.18.1.2");
    check_node(&subject, "test_node_3", 3456, "172.18.1.3");

    subject.stop_all ();

    let expected_nodes: HashSet<String> = HashSet::new ();
    assert_eq!(subject.running_node_names(), expected_nodes);
    assert_eq!(node_is_running ("172.18.1.1"), false);
    assert_eq!(node_is_running ("172.18.1.2"), false);
    assert_eq!(node_is_running ("172.18.1.3"), false);
}

fn check_node(cluster: &SubstratumNodeCluster, name: &str, port: u16, ip_address: &str) {
    let node = cluster.get_node (name).unwrap ();
    assert_eq! (node.get_name (), name);
    assert_eq! (node.get_startup_config ().get_port_numbers (), &vec! (port));
    assert_eq! (node.get_ip_address (), IpAddr::from_str (ip_address).unwrap ());
    ensure_node_is_running(name, ip_address);
}

fn node_is_running(ip_address: &str) -> bool {
    let socket_addr = SocketAddr::new(IpAddr::from_str(ip_address).unwrap(), 80);
    match TcpStream::connect_timeout(&socket_addr, Duration::from_millis(100)) {
        Ok(_) => true,
        Err(ref e) if e.kind() == ErrorKind::TimedOut => false,
        Err(e) => panic!("{}", e),
    }
}

fn ensure_node_is_running(container_name: &str, ip_address: &str) {
    assert_eq!(node_is_running(ip_address), true, "{} should be running on {}, but isn't", container_name, ip_address)
}

fn clear_leaked_containers () {
    let names_to_stop = find_running_container_names ();
    if names_to_stop.is_empty () {return}
    println! ("Stopping running containers before test: {:?}", names_to_stop);
    let mut parameters = vec! ("stop", "-t", "0");
    let str_names_to_stop: Vec<&str> = names_to_stop.iter ().map (|p| {p.as_str ()}).collect ();
    parameters.extend (str_names_to_stop);
    let mut stop_command = Command::new ("docker", parameters);
    if stop_command.wait_for_exit () != 0 {panic! ("Couldn't stop remaining containers")}
}

fn find_running_container_names () -> Vec<String> {
    let mut ps_command = Command::new ("docker", vec! ("ps"));
    if ps_command.wait_for_exit() != 0 {panic! ("Couldn't get container list")}
    let ps_output = ps_command.stdout_as_string();
    let regex = Regex::new ("(test_node_\\d+)").unwrap ();
    let capture_matches = regex.captures_iter (&ps_output);
    capture_matches.map (|captures| {
        String::from (captures.get (1).unwrap ().as_str ())
    }).collect ()
}
