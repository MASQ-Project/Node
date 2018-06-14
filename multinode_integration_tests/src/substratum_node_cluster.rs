// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use command::Command;
use regex::Regex;
use std::collections::HashMap;
use std::collections::HashSet;
use std::env;
use std::path::PathBuf;
use substratum_node::NodeStartupConfig;
use substratum_node::SubstratumNode;

pub struct SubstratumNodeCluster {
    nodes: HashMap<String, SubstratumNode>,
}

impl SubstratumNodeCluster {
    pub fn new (mut configs: Vec<NodeStartupConfig>) -> SubstratumNodeCluster {
        start_nodes(&configs);
        let mut cluster = SubstratumNodeCluster {
            nodes: HashMap::new (),
        };
        for idx in 0..configs.len() {
            let config = configs.remove (0);
            let node = SubstratumNode::new(config, idx + 1);
            cluster.nodes.insert(node.get_name().to_string(), node);
        }
        cluster
    }

    pub fn running_node_names(&self) -> HashSet<String> {
        self.nodes.keys ().map (|key_ref| {key_ref.clone ()}).collect()
    }

    pub fn get_node (&self, name: &str) -> Option<&SubstratumNode> {
        self.nodes.get (name)
    }

    pub fn stop (&mut self, node_name: &str) -> bool {
        run_docker_script("stop_node.sh", vec!(String::from (node_name)));

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

fn run_docker_script(script_name: &str, parameters: Vec<String>) {
    let mut script = docker_dir();
    script.push(script_name);
    let mut command = Command::new(script.to_str().unwrap(), parameters.iter ().map (|x| x.as_str ()).collect ());
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
