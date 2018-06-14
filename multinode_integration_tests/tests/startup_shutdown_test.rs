// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
extern crate regex;
extern crate sub_lib;
extern crate multinode_integration_tests_lib;

use std::collections::HashSet;
use std::net::IpAddr;
use std::str::FromStr;
use std::net::TcpStream;
use std::net::SocketAddr;
use std::io::ErrorKind;
use std::time::Duration;
use regex::Regex;
use sub_lib::utils::index_of;
use multinode_integration_tests_lib::substratum_node_cluster::SubstratumNodeCluster;
use multinode_integration_tests_lib::command::Command;
use multinode_integration_tests_lib::substratum_node::NodeStartupConfig;
use multinode_integration_tests_lib::substratum_client::SubstratumNodeClient;

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

    let client = subject.get_node ("test_node_3").unwrap ().make_client (80);
    perform_client_interaction (client);

    subject.stop_all ();

    let expected_nodes: HashSet<String> = HashSet::new ();
    assert_eq!(subject.running_node_names(), expected_nodes);
    assert_eq!(node_is_running ("172.18.1.1"), false);
    assert_eq!(node_is_running ("172.18.1.2"), false);
    assert_eq!(node_is_running ("172.18.1.3"), false);
}

fn perform_client_interaction (mut client: SubstratumNodeClient) {
    let request = make_http_request();
    client.send_chunk(request);
    let response = client.wait_for_chunk();
    assert_eq!(index_of(&response[..], b"It was the Bottle Conjuror!").is_some(), true,
               "Did not contain 'It was the Bottle Conjuror!': '{}'", String::from_utf8(response).unwrap())
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

fn make_http_request () -> Vec<u8> {
    Vec::from (&b"GET /html HTTP/1.1\r\nHost: httpbin.org\r\n\r\n"[..])
}
