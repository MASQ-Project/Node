// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use std::collections::HashSet;
use std::collections::HashMap;
use std::env;
use std::net::IpAddr;
use std::path::PathBuf;
use std::str::FromStr;
use regex::Regex;
use command::Command;

pub struct NodeStartupConfig {
    port_numbers: Vec<u16>
}

impl NodeStartupConfig {
    pub fn new (port_numbers: Vec<u16>) -> NodeStartupConfig {
        NodeStartupConfig {
            port_numbers
        }
    }

    pub fn get_port_numbers (&self) -> &Vec<u16> {
        &self.port_numbers
    }

    pub fn as_command_line_parameter<'a> (&'a self) -> &'a str {
        // We don't know what these parameter clusters will look like eventually;
        // right now they are not looked at except to ensure that they contain no spaces.
        "booga"
    }
}

pub struct SubstratumNode {
    startup_config: NodeStartupConfig,
    name: String,
    ip_address: IpAddr
}

impl SubstratumNode {
    pub fn new (startup_config: NodeStartupConfig, index: usize) -> SubstratumNode {
        SubstratumNode {
            startup_config,
            name: format! ("test_node_{}", index),
            ip_address: IpAddr::from_str (&format! ("172.18.1.{}", index)).unwrap ()
        }
    }

    pub fn get_name (&self) -> &str {
        &self.name
    }

    pub fn get_ip_address (&self) -> IpAddr {
        self.ip_address
    }

    pub fn get_startup_config (&self) -> &NodeStartupConfig {
        &self.startup_config
    }
}

pub struct SubstratumNodeCluster {
    nodes: HashMap<String, SubstratumNode>,
}

impl SubstratumNodeCluster {
    pub fn new (mut configs: Vec<NodeStartupConfig>) -> SubstratumNodeCluster {
        start_nodes(&configs);
        let mut nodes: HashMap<String, SubstratumNode> = HashMap::new();
        for idx in 0..configs.len() {
            let config = configs.remove (0);
            let node = SubstratumNode::new(config, idx + 1);
            nodes.insert(node.get_name().to_string(), node);
        }
        SubstratumNodeCluster {nodes}
    }

    pub fn running_node_names(&self) -> HashSet<String> {
        self.nodes.keys ().map (|key_ref| {key_ref.clone ()}).collect()
    }

    pub fn get_node (&self, name: &str) -> Option<&SubstratumNode> {
        self.nodes.get (name)
    }

    pub fn stop (&mut self, node_name: &str) -> bool {
        run_docker_script("stop_node.sh", vec!(node_name));

        match self.nodes.remove(node_name) {
            Some(_) => true,
            None => false
        }
    }

    pub fn stop_all (&mut self) {
        self.nodes.clear ();
        let names_to_stop = find_running_container_names ();
        if names_to_stop.is_empty () {return}
        println! ("stop_all: {:?}", names_to_stop);
        let mut parameters = vec! ("stop", "-t", "0");
        let str_names_to_stop: Vec<&str> = names_to_stop.iter ().map (|p| {p.as_str ()}).collect ();
        parameters.extend (str_names_to_stop);
        let mut stop_command = Command::new ("docker", parameters);
        if stop_command.wait_for_exit () != 0 {panic! ("Couldn't stop remaining containers")}
    }
}

fn start_nodes (configs: &Vec<NodeStartupConfig>) {
    let parameters = configs.iter().map(|config| { config.as_command_line_parameter() }).collect();
    run_docker_script("start_nodes.sh", parameters);
}

fn run_docker_script(script_name: &str, parameters: Vec<&str>) {
    let mut script = docker_dir();
    script.push(script_name);
    let mut command = Command::new(script.to_str().unwrap(), parameters.clone());
    let exit_code = command.wait_for_exit();
    if exit_code != 0 {
        panic!("{}: Script failed:\n{} {:?}\n{}", exit_code, script_name, parameters, command.stderr_as_string())
    }
}

fn docker_dir () -> PathBuf {
    let mut result = env::current_dir().unwrap();
    let mut possible_module_dir = env::current_dir().unwrap();
    possible_module_dir.push("multinode_integration_tests");
    if possible_module_dir.exists() {
        result = possible_module_dir;
    }
    result.push("docker");
    result
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
