// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use std::net::IpAddr;
use std::net::SocketAddr;
use std::str::FromStr;
use base64;
use substratum_client::SubstratumNodeClient;
use sub_lib::node_addr::NodeAddr;
use sub_lib::cryptde::Key;
use sub_lib::neighborhood::sentinel_ip_addr;
use std::net::Ipv4Addr;
use std::path::Path;
use std::env;
use std::fs;
use std::ffi::OsStr;
use std::fs::DirEntry;
use std::io;
use std::path::PathBuf;
use command::Command;
use std::net::TcpStream;
use std::time::Duration;
use std::thread;
use regex::Regex;
use std::fmt;
use base64::STANDARD_NO_PAD;

#[derive (PartialEq, Clone, Debug)]
pub struct NodeReference {
    pub public_key: Key,
    pub node_addr: NodeAddr,
}

impl FromStr for NodeReference {
    type Err = String;

    fn from_str(string_rep: &str) -> Result<Self, <Self as FromStr>::Err> {
        let pieces: Vec<&str> = string_rep.split (":").collect ();
        if pieces.len () != 3 {
            return Err(format!("A NodeReference must have the form <public_key>:<IP address>:<port list>, not '{}'", string_rep))
        }
        let public_key = Self::extract_public_key (pieces[0])?;
        let ip_addr = Self::extract_ip_addr (pieces[1])?;
        let port_list = Self::extract_port_list (pieces[2])?;
        Ok (NodeReference::new (public_key, ip_addr, port_list))
    }
}

impl fmt::Display for NodeReference {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        let public_key_string = base64::encode_config (&self.public_key.data, STANDARD_NO_PAD);
        let ip_addr_string = format! ("{}", self.node_addr.ip_addr());
        let port_list_string = self.node_addr.ports ().iter ()
            .map (|port| port.to_string ())
            .collect::<Vec<String>> ()
            .join (",");
        write! (f, "{}:{}:{}", public_key_string, ip_addr_string, port_list_string)
    }
}

impl NodeReference {
    pub fn new (public_key: Key, ip_addr: IpAddr, ports: Vec<u16>) -> NodeReference {
        NodeReference {
            public_key,
            node_addr: NodeAddr::new (&ip_addr, &ports),
        }
    }

    fn extract_public_key (slice: &str) -> Result<Key, String> {
        match base64::decode(slice) {
            Ok (data) => Ok (Key::new (&data[..])),
            Err (_) => return Err (format!("The public key of a NodeReference must be represented as a valid Base64 string, not '{}'", slice))
        }
    }

    fn extract_ip_addr (slice: &str) -> Result<IpAddr, String> {
        match IpAddr::from_str (slice) {
            Ok (ip_addr) => Ok (ip_addr),
            Err (_) => return Err (format! ("The IP address of a NodeReference must be valid, not '{}'", slice))
        }
    }

    fn extract_port_list (slice: &str) -> Result<Vec<u16>, String> {
        let port_list_numbers: Vec<i64> = if slice.is_empty () {
            vec! ()
        }
            else {
                String::from(slice).split(",")
                    .map(|x| {
                        match x.parse::<i64>() {
                            Ok(n) => n,
                            Err(_) => -1
                        }
                    })
                    .collect()
            };
        if port_list_numbers.contains (&-1) {
            return Err(format!("The port list must be a comma-separated sequence of valid numbers, not '{}'", slice))
        }
        match port_list_numbers.iter ().find (|x| x > &&65535) {
            Some (x) => return Err (format! ("Each port number must be 65535 or less, not '{}'", x)),
            None => ()
        }
        Ok (port_list_numbers.into_iter ().map (|x| x as u16).collect ())
    }
}

#[derive (PartialEq, Clone, Debug, Copy)]
pub enum NodeType {
    Standard,
    Bootstrap,
}

#[derive (PartialEq)]
pub struct NodeStartupConfig {
    pub ip: IpAddr,
    pub dns_servers: Vec<IpAddr>,
    pub neighbors: Vec<NodeReference>,
    pub bootstrap_froms: Vec<NodeReference>,
    pub node_type: NodeType,
    pub port_count: usize,
    pub dns_target: IpAddr,
    pub dns_port: u16,
}

impl NodeStartupConfig {
    pub fn new () -> NodeStartupConfig {
        NodeStartupConfig {
            ip: sentinel_ip_addr(),
            dns_servers: Vec::new(),
            neighbors: Vec::new(),
            bootstrap_froms: Vec::new(),
            node_type: NodeType::Bootstrap,
            port_count: 0,
            dns_target: sentinel_ip_addr(),
            dns_port: 0,
        }
    }
}

pub struct NodeStartupConfigBuilder {
    ip: IpAddr,
    dns_servers: Vec<IpAddr>,
    neighbors: Vec<NodeReference>,
    bootstrap_froms: Vec<NodeReference>,
    node_type: NodeType,
    port_count: usize,
    dns_target: IpAddr,
    dns_port: u16,
}

impl NodeStartupConfigBuilder {
    pub fn standard() -> NodeStartupConfigBuilder {
        NodeStartupConfigBuilder {
            ip: sentinel_ip_addr(), // this is replaced at startup
            dns_servers: vec! (IpAddr::from_str ("8.8.8.8").unwrap ()),
            neighbors: vec! (),
            bootstrap_froms: vec! (),
            node_type: NodeType::Standard,
            port_count: 1,
            dns_target: IpAddr::from_str ("127.0.0.1").unwrap (),
            dns_port: 53,
        }
    }

    pub fn bootstrap() -> NodeStartupConfigBuilder {
        NodeStartupConfigBuilder {
            ip: sentinel_ip_addr(), // this is replaced at startup
            dns_servers: vec! (IpAddr::from_str ("8.8.8.8").unwrap ()),
            neighbors: vec! (),
            bootstrap_froms: vec! (),
            node_type: NodeType::Bootstrap,
            port_count: 1,
            dns_target: IpAddr::from_str ("127.0.0.1").unwrap (),
            dns_port: 53,
        }
    }

    pub fn copy (config: &NodeStartupConfig) -> NodeStartupConfigBuilder {
        NodeStartupConfigBuilder {
            ip: config.ip.clone (),
            dns_servers: config.dns_servers.clone (),
            neighbors: config.neighbors.clone (),
            bootstrap_froms: config.bootstrap_froms.clone (),
            node_type: config.node_type,
            port_count: config.port_count,
            dns_target: config.dns_target.clone (),
            dns_port: config.dns_port,
        }
    }

    pub fn ip (mut self, value: IpAddr) -> NodeStartupConfigBuilder {
        self.ip = value;
        self
    }

    pub fn dns_servers (mut self, value: Vec<IpAddr>) -> NodeStartupConfigBuilder {
        self.dns_servers = value;
        self
    }

    pub fn neighbor (mut self, value: NodeReference) -> NodeStartupConfigBuilder {
        self.neighbors.push (value);
        self
    }

    pub fn neighbors (mut self, value: Vec<NodeReference>) -> NodeStartupConfigBuilder {
        self.neighbors = value;
        self
    }

    pub fn bootstrap_from (mut self, value: NodeReference) -> NodeStartupConfigBuilder {
        self.bootstrap_froms.push (value);
        self
    }

    pub fn bootstrap_froms (mut self, value: Vec<NodeReference>) -> NodeStartupConfigBuilder {
        self.bootstrap_froms = value;
        self
    }

    pub fn node_type (mut self, value: NodeType) -> NodeStartupConfigBuilder {
        self.node_type = value;
        self
    }

    pub fn port_count (mut self, value: usize) -> NodeStartupConfigBuilder {
        self.port_count = value;
        self
    }

    pub fn dns_target (mut self, value: IpAddr) -> NodeStartupConfigBuilder {
        self.dns_target = value;
        self
    }

    pub fn dns_port (mut self, value: u16) -> NodeStartupConfigBuilder {
        self.dns_port = value;
        self
    }

    pub fn build (self) -> NodeStartupConfig {
        NodeStartupConfig {
            ip: self.ip,
            dns_servers: self.dns_servers,
            neighbors: self.neighbors,
            bootstrap_froms: self.bootstrap_froms,
            node_type: self.node_type,
            port_count: self.port_count,
            dns_target: self.dns_target,
            dns_port: self.dns_port,
        }
    }
}

pub enum PortSelector {
    First,
    Last,
    Index(usize),
}

pub struct SubstratumNode {
    startup_config: NodeStartupConfig,
    name: String,
    node_reference: NodeReference,
}

impl Drop for SubstratumNode {
    fn drop(&mut self) {
        match self.stop () {
            Ok (_) => (),
            Err (e) => eprintln! ("Stopping node {} failed; continuing: {}", self.name, e),
        }
    }
}

impl SubstratumNode {

    pub fn start (startup_config: NodeStartupConfig, index: usize, host_node_parent_dir: Option<String>) -> Result<SubstratumNode, String> {
        let ip_addr = IpAddr::V4 (Ipv4Addr::new (172, 18, 1, index as u8));
        let name = format! ("test_node_{}", index);
        Self::clean_up_existing_container (&name[..]);
        let real_startup_config = NodeStartupConfigBuilder::copy (&startup_config)
            .ip (ip_addr)
            .build ();
        Self::do_docker_run(&real_startup_config, host_node_parent_dir, ip_addr, &name)?;
        Self::wait_for_startup(ip_addr, &name)?;
        let node_reference = SubstratumNode::extract_node_reference(index, &name)?;
        Ok (SubstratumNode {
            startup_config,
            name,
            node_reference,
        })
    }

    fn clean_up_existing_container (name: &str) {
        let mut command = Command::new ("docker", Command::strings (vec! ("rm", name)));
        command.wait_for_exit(); // success, failure, don't care
    }

    fn do_docker_run(startup_config: &NodeStartupConfig, host_node_parent_dir: Option<String>, ip_addr: IpAddr, name: &String) -> Result<(), String> {
        let root = match host_node_parent_dir {
            Some(dir) => dir,
            None => Self::find_project_root(),
        };
        let node_command_dir = format!("{}/node/target/release", root);
        let node_args = Self::make_node_args(&startup_config);
        let docker_command = "docker";
        let ip_addr_string = format!("{}", ip_addr);
        let name_string = name.clone();
        let v_param = format!("{}:/node_root/node", node_command_dir);
        let mut docker_args = Command::strings(vec!("run", "--detach", "--ip",
                                                    ip_addr_string.as_str(), "--dns", "127.0.0.1", "--name", name_string.as_str(),
                                                    "--net", "integration_net", "-v", v_param.as_str(), "test_node_image",
                                                    "/node_root/node/SubstratumNode"));
        docker_args.extend(node_args);
        let mut command = Command::new(docker_command, docker_args);
        command.stdout_or_stderr()?;
        Ok(())
    }

    fn wait_for_startup(ip_addr: IpAddr, name: &String) -> Result<(), String> {
        let wait_addr = SocketAddr::new(ip_addr, 80);
        let mut retries = 10;
        loop {
            match TcpStream::connect(wait_addr) {
                Ok(_) => {eprintln! ("{} startup detected on {}", name, wait_addr); break},
                Err(e) => {println! ("{} startup on {} failed: {}", name, wait_addr, e); ()},
            }
            retries -= 1;
            if retries <= 0 { break }
            thread::sleep(Duration::from_millis(100))
        }
        if retries <= 0 { return Err(format!("Timed out trying to contact node {}", name)) }
        Ok (())
    }

    fn extract_node_reference(index: usize, name: &String) -> Result<NodeReference, String> {
        let mut command = Command::new("docker", Command::strings(vec!("logs", name.as_str())));
        let output = command.stdout_or_stderr()?;
        let regex = Regex::new(r"SubstratumNode local descriptor: ([^:]+:[\d.]+:[\d,]*)").unwrap();
        match regex.captures(output.as_str()) {
            Some(captures) => Ok (NodeReference::from_str(captures.get(1).unwrap().as_str()).unwrap ()),
            None => return Err(format!("test_node_{} did not produce recognizable identifier: {}", index, output)),
        }
    }

    pub fn stop (&self) -> Result<(), String> {
        let mut command = Command::new ("docker", Command::strings (vec! ("stop", "-t", "0", self.name.as_str ())));
        match command.stdout_or_stderr () {
            Ok (_) => Ok (()),
            Err (e) => Err (e),
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn node_reference(&self) -> NodeReference {
        self.node_reference.clone ()
    }

    pub fn public_key(&self) -> Key {
        self.node_reference.public_key.clone ()
    }

    pub fn ip_address(&self) -> IpAddr {
        self.node_reference.node_addr.ip_addr()
    }

    pub fn port_list(&self) -> Vec<u16> {
        self.node_reference.node_addr.ports().clone ()
    }

    pub fn node_addr(&self) -> NodeAddr {
        NodeAddr::new (&self.ip_address (), &self.port_list ())
    }

    pub fn socket_addr(&self, port_selector: PortSelector) -> SocketAddr {
        let port_list = self.port_list ();
        if port_list.is_empty () {panic! ("{} has no clandestine ports; can't make SocketAddr", self.name ())}
        let idx = match port_selector {
            PortSelector::First => 0,
            PortSelector::Last => port_list.len () - 1,
            PortSelector::Index (i) => i,
        };
        SocketAddr::new (self.ip_address (), port_list[idx])
    }

    pub fn startup_config(&self) -> &NodeStartupConfig {
        &self.startup_config
    }

    pub fn make_client (&self, port: u16) -> SubstratumNodeClient {
        let socket_addr = SocketAddr::new(self.ip_address(), port);
        SubstratumNodeClient::new(socket_addr)
    }

    fn find_project_root () -> String {
        let path_buf = Self::start_from (Path::new (&env::var ("PWD").unwrap ()));
        path_buf.as_path ().to_str ().unwrap ().to_string ()
    }

    fn start_from (start: &Path) -> PathBuf {
        let recognized: Vec<Result<DirEntry, io::Error>> = fs::read_dir (start).unwrap ()
            .filter (|entry| {
                let file_name = match entry {
                    Ok (dir_entry) => dir_entry.file_name (),
                    Err (e) => panic! ("Should never happen: {}", e),
                };
                file_name == OsStr::new ("multinode_integration_tests") ||
                file_name == OsStr::new ("node")
            })
            .collect ();
        if recognized.len () == 2 {
            PathBuf::from (start)
        }
        else {
            Self::start_from (start.parent ().unwrap ())
        }
    }

    fn make_node_args (config: &NodeStartupConfig) -> Vec<String> {
        let mut args = vec! ();
        args.push ("--ip".to_string ());
        args.push (format! ("{}", config.ip));
        args.push ("--dns_servers".to_string ());
        args.push (Self::join_ip_addrs (&config.dns_servers));
        config.neighbors.iter ().for_each (|neighbor| {
            args.push ("--neighbor".to_string ());
            args.push (format! ("{}", neighbor));
        });
        config.bootstrap_froms.iter ().for_each (|bootstrap_from| {
            args.push ("--bootstrap_from".to_string ());
            args.push (format! ("{}", bootstrap_from));
        });
        args.push ("--node_type".to_string ());
        args.push (match config.node_type {NodeType::Standard => "standard", NodeType::Bootstrap => "bootstrap"}.to_string ());
        args.push ("--port_count".to_string ());
        args.push (format! ("{}", config.port_count));
        args.push ("--dns_target".to_string ());
        args.push (format! ("{}", config.dns_target));
        args.push ("--dns_port".to_string ());
        args.push (format! ("{}", config.dns_port));
        args.push ("--log_level".to_string ());
        args.push ("trace".to_string ());
        args
    }

    fn join_ip_addrs (ip_addrs: &Vec<IpAddr>) -> String {
        ip_addrs.iter ()
            .map (|ip_addr| format! ("{}", ip_addr))
            .collect::<Vec<String>> ()
            .join (",")
    }
}

#[cfg (test)]
mod tests {
    use super::*;

    #[test]
    fn node_reference_from_string_fails_if_there_are_not_three_fields () {
        let string = String::from ("Only two:fields");

        let result = NodeReference::from_str (string.as_str ());

        assert_eq! (result, Err (String::from ("A NodeReference must have the form <public_key>:<IP address>:<port list>, not 'Only two:fields'")));
    }

    #[test]
    fn node_reference_from_string_fails_if_key_is_not_valid_base64 () {
        let string = String::from (";;;:12.34.56.78:1234,2345");

        let result = NodeReference::from_str (string.as_str ());

        assert_eq! (result, Err (String::from ("The public key of a NodeReference must be represented as a valid Base64 string, not ';;;'")));
    }

    #[test]
    fn node_reference_from_string_fails_if_ip_address_is_not_valid () {
        let key = Key::new (&b"Booga"[..]);
        let string = format! ("{}:blippy:1234,2345", key);

        let result = NodeReference::from_str (string.as_str ());

        assert_eq! (result, Err (String::from ("The IP address of a NodeReference must be valid, not 'blippy'")));
    }

    #[test]
    fn node_reference_from_string_fails_if_a_port_number_is_not_valid () {
        let key = Key::new (&b"Booga"[..]);
        let string = format! ("{}:12.34.56.78:weeble,frud", key);

        let result = NodeReference::from_str (string.as_str ());

        assert_eq! (result, Err (String::from ("The port list must be a comma-separated sequence of valid numbers, not 'weeble,frud'")));
    }

    #[test]
    fn node_reference_from_string_fails_if_a_port_number_is_too_big () {
        let key = Key::new (&b"Booga"[..]);
        let string = format! ("{}:12.34.56.78:1234,65536", key);

        let result = NodeReference::from_str (string.as_str ());

        assert_eq! (result, Err (String::from ("Each port number must be 65535 or less, not '65536'")));
    }

    #[test]
    fn node_reference_from_string_happy () {
        let key = Key::new (&b"Booga"[..]);
        let string = format! ("{}:12.34.56.78:1234,2345", key);

        let result = NodeReference::from_str (string.as_str ()).unwrap ();

        assert_eq! (result.public_key, key);
        assert_eq! (result.node_addr, NodeAddr::new (&IpAddr::from_str ("12.34.56.78").unwrap (), &vec! (1234, 2345)));
    }

    #[test]
    fn node_reference_from_string_works_if_there_are_no_ports () {
        let key = Key::new (&b"Booga"[..]);
        let string = format! ("{}:12.34.56.78:", key);

        let result = NodeReference::from_str (string.as_str ()).unwrap ();

        assert_eq! (result.public_key, key);
        assert_eq! (result.node_addr, NodeAddr::new (&IpAddr::from_str ("12.34.56.78").unwrap (), &vec! ()));
    }

    #[test]
    fn node_startup_config_builder_standard () {

        let result = NodeStartupConfigBuilder::standard().build ();

        assert_eq! (result.ip, sentinel_ip_addr());
        assert_eq! (result.dns_servers, vec! (IpAddr::from_str ("8.8.8.8").unwrap ()));
        assert_eq! (result.neighbors, vec! ());
        assert_eq! (result.bootstrap_froms, vec! ());
        assert_eq! (result.node_type, NodeType::Standard);
        assert_eq! (result.port_count, 1);
        assert_eq! (result.dns_target, IpAddr::from_str ("127.0.0.1").unwrap ());
        assert_eq! (result.dns_port, 53);
    }

    #[test]
    fn node_startup_config_builder_bootstrap () {

        let result = NodeStartupConfigBuilder::bootstrap().build ();

        assert_eq! (result.ip, sentinel_ip_addr());
        assert_eq! (result.dns_servers, vec! (IpAddr::from_str ("8.8.8.8").unwrap ()));
        assert_eq! (result.neighbors, vec! ());
        assert_eq! (result.bootstrap_froms, vec! ());
        assert_eq! (result.node_type, NodeType::Bootstrap);
        assert_eq! (result.port_count, 1);
        assert_eq! (result.dns_target, IpAddr::from_str ("127.0.0.1").unwrap ());
        assert_eq! (result.dns_port, 53);
    }
    
    #[test]
    fn node_startup_config_builder_settings () {
        let ip_addr = IpAddr::from_str ("1.2.3.4").unwrap ();
        let one_neighbor_key = Key::new (&[1, 2, 3, 4]);
        let one_neighbor_ip_addr = IpAddr::from_str ("4.5.6.7").unwrap ();
        let one_neighbor_ports = vec! (1234, 2345);
        let another_neighbor_key = Key::new (&[2, 3, 4, 5]);
        let another_neighbor_ip_addr = IpAddr::from_str ("5.6.7.8").unwrap ();
        let another_neighbor_ports = vec! (3456, 4567);
        let one_bootstrap_key = Key::new (&[3, 4, 5, 6]);
        let one_bootstrap_ip_addr = IpAddr::from_str ("6.7.8.9").unwrap ();
        let one_bootstrap_ports = vec! (5678, 6789);
        let another_bootstrap_key = Key::new (&[4, 5, 6, 7]);
        let another_bootstrap_ip_addr = IpAddr::from_str ("7.8.9.10").unwrap ();
        let another_bootstrap_ports = vec! (7890, 8901);
        let dns_servers = vec! (
            IpAddr::from_str ("2.3.4.5").unwrap (), 
            IpAddr::from_str ("3.4.5.6").unwrap ()
        );
        let neighbors = vec! (
            NodeReference::new (one_neighbor_key.clone (), one_neighbor_ip_addr.clone (), one_neighbor_ports.clone ()),
            NodeReference::new (another_neighbor_key.clone (), another_neighbor_ip_addr.clone (), another_neighbor_ports.clone ())
        );
        let bootstrap_froms = vec! (
            NodeReference::new (one_bootstrap_key.clone (), one_bootstrap_ip_addr.clone (), one_bootstrap_ports.clone ()),
            NodeReference::new (another_bootstrap_key.clone (), another_bootstrap_ip_addr.clone (), another_bootstrap_ports.clone ())
        );
        let dns_target = IpAddr::from_str ("8.9.10.11").unwrap ();

        let result = NodeStartupConfigBuilder::bootstrap ()
            .ip (ip_addr)
            .dns_servers (dns_servers.clone ())
            .neighbor (neighbors[0].clone ())
            .neighbor (neighbors[1].clone ())
            .bootstrap_from (bootstrap_froms[0].clone ())
            .bootstrap_from (bootstrap_froms[1].clone ())
            .node_type (NodeType::Standard)
            .port_count (2)
            .dns_target (dns_target)
            .dns_port (35)
            .build ();

        assert_eq! (result.ip, ip_addr);
        assert_eq! (result.dns_servers, dns_servers);
        assert_eq! (result.neighbors, neighbors);
        assert_eq! (result.bootstrap_froms, bootstrap_froms);
        assert_eq! (result.node_type, NodeType::Standard);
        assert_eq! (result.port_count, 2);
        assert_eq! (result.dns_target, dns_target);
        assert_eq! (result.dns_port, 35);
    }

    #[test]
    fn node_startup_config_builder_copy () {
        let original = NodeStartupConfig {
            ip: IpAddr::from_str ("255.255.255.255").unwrap (),
            dns_servers: vec! (IpAddr::from_str ("255.255.255.255").unwrap ()),
            neighbors: vec! (NodeReference::new (Key::new (&[255]), IpAddr::from_str ("255.255.255.255").unwrap (), vec! (255))),
            bootstrap_froms: vec! (NodeReference::new (Key::new (&[255]), IpAddr::from_str ("255.255.255.255").unwrap (), vec! (255))),
            node_type: NodeType::Standard,
            port_count: 200,
            dns_target: IpAddr::from_str ("255.255.255.255").unwrap (),
            dns_port: 54,
        };
        let ip_addr = IpAddr::from_str ("1.2.3.4").unwrap ();
        let one_neighbor_key = Key::new (&[1, 2, 3, 4]);
        let one_neighbor_ip_addr = IpAddr::from_str ("4.5.6.7").unwrap ();
        let one_neighbor_ports = vec! (1234, 2345);
        let another_neighbor_key = Key::new (&[2, 3, 4, 5]);
        let another_neighbor_ip_addr = IpAddr::from_str ("5.6.7.8").unwrap ();
        let another_neighbor_ports = vec! (3456, 4567);
        let one_bootstrap_key = Key::new (&[3, 4, 5, 6]);
        let one_bootstrap_ip_addr = IpAddr::from_str ("6.7.8.9").unwrap ();
        let one_bootstrap_ports = vec! (5678, 6789);
        let another_bootstrap_key = Key::new (&[4, 5, 6, 7]);
        let another_bootstrap_ip_addr = IpAddr::from_str ("7.8.9.10").unwrap ();
        let another_bootstrap_ports = vec! (7890, 8901);
        let dns_servers = vec! (
            IpAddr::from_str ("2.3.4.5").unwrap (),
            IpAddr::from_str ("3.4.5.6").unwrap ()
        );
        let neighbors = vec! (
            NodeReference::new (one_neighbor_key.clone (), one_neighbor_ip_addr.clone (), one_neighbor_ports.clone ()),
            NodeReference::new (another_neighbor_key.clone (), another_neighbor_ip_addr.clone (), another_neighbor_ports.clone ())
        );
        let bootstrap_froms = vec! (
            NodeReference::new (one_bootstrap_key.clone (), one_bootstrap_ip_addr.clone (), one_bootstrap_ports.clone ()),
            NodeReference::new (another_bootstrap_key.clone (), another_bootstrap_ip_addr.clone (), another_bootstrap_ports.clone ())
        );
        let dns_target = IpAddr::from_str ("8.9.10.11").unwrap ();

        let result = NodeStartupConfigBuilder::copy (&original)
            .ip (ip_addr)
            .dns_servers (dns_servers.clone ())
            .neighbors (neighbors.clone ())
            .bootstrap_froms (bootstrap_froms.clone ())
            .node_type (NodeType::Bootstrap)
            .port_count (2)
            .dns_target (dns_target)
            .dns_port (35)
            .build ();

        assert_eq! (result.ip, ip_addr);
        assert_eq! (result.dns_servers, dns_servers);
        assert_eq! (result.neighbors, neighbors);
        assert_eq! (result.bootstrap_froms, bootstrap_froms);
        assert_eq! (result.node_type, NodeType::Bootstrap);
        assert_eq! (result.port_count, 2);
        assert_eq! (result.dns_target, dns_target);
        assert_eq! (result.dns_port, 35);
    }
}