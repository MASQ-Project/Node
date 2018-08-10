// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use command::Command;
use std::collections::HashMap;
use std::collections::HashSet;
use std::env;
use substratum_node::NodeStartupConfig;
use substratum_node::SubstratumNode;

pub struct SubstratumNodeCluster {
    nodes: HashMap<String, SubstratumNode>,
    host_node_parent_dir: Option<String>,
    next_index: usize,
}

impl Drop for SubstratumNodeCluster {
    fn drop(&mut self) {
        self.nodes.clear ();
        Self::cleanup ().unwrap ();
    }
}

impl SubstratumNodeCluster {
    pub fn start () -> Result<SubstratumNodeCluster, String> {
        SubstratumNodeCluster::cleanup()?;
        SubstratumNodeCluster::create_network ()?;
        let host_node_parent_dir = match env::var("HOST_NODE_PARENT_DIR") {
            Ok(ref hnpd) if !hnpd.is_empty() => Some(hnpd.clone()),
            _ => None,
        };
        if Self::is_in_jenkins () {
            SubstratumNodeCluster::interconnect_network ()?;
        }
        Ok (SubstratumNodeCluster {
            nodes: HashMap::new (),
            host_node_parent_dir,
            next_index: 1,
        })
    }

    pub fn start_node (&mut self, config: NodeStartupConfig) -> Result<&mut SubstratumNode, String> {
        let index = self.next_index;
        self.next_index += 1;
        let node = SubstratumNode::start (config, index, self.host_node_parent_dir.clone ())?;
        let name = node.name().to_string ();
        self.nodes.insert (node.name().to_string (), node);
        Ok (self.nodes.get_mut (&name).unwrap ())
    }

    pub fn stop (self) -> Result<(), String> {
        SubstratumNodeCluster::cleanup()
    }

    pub fn stop_node (&mut self, name: &str) -> Result<(), String> {
        match self.nodes.remove(name) {
            Some(node) => { node.stop() },
            None => { Err(format!("Node {} was not found in cluster", name)) },
        }
    }

    pub fn running_node_names(&self) -> HashSet<String> {
        self.nodes.keys ().map (|key_ref| {key_ref.clone ()}).collect()
    }

    pub fn get_node<'a> (&'a self, name: &str) -> Option<&'a SubstratumNode> {
        self.nodes.get (name)
    }

    pub fn is_in_jenkins () -> bool {
        match env::var ("HOST_NODE_PARENT_DIR") {
            Ok (ref value) if value.is_empty () => false,
            Ok (_) => true,
            Err (_) => false,
        }
    }

    fn cleanup() -> Result<(), String> {
        SubstratumNodeCluster::stop_running_nodes ()?;
        if Self::is_in_jenkins () {
            Self::disconnect_network()
        }
        SubstratumNodeCluster::remove_network_if_running()
    }

    fn stop_running_nodes () -> Result <(), String> {
        let mut command = Command::new ("docker", Command::strings (vec! ("ps", "-a", "-q", "--filter", "ancestor=\"test_node_image\"")));
        if command.wait_for_exit () != 0 {return Err (format! ("Could not stop running nodes: {}", command.stderr_as_string()))}
        let results: Vec<String> = command.stdout_as_string().split ("\n")
            .filter (|result| !result.is_empty ())
            .map (|node_name| {
                let mut command = Command::new ("docker", Command::strings (vec! ("stop", "-t", "0", node_name)));
                match command.wait_for_exit () {
                    0 => Ok (()),
                    _ => Err (format! ("Could not stop node '{}': {}", node_name, command.stderr_as_string ()))
                }
            })
            .filter (|result| result.is_err ())
            .map (|result| result.err ().unwrap ())
            .collect ();
        if results.is_empty () {
            Ok (())
        }
        else {
            Err (results.join ("; "))
        }
    }

    fn disconnect_network () {
        let mut command = Command::new ("docker", Command::strings (vec! ("network", "disconnect", "integration_net", "subjenkins")));
        command.wait_for_exit ();
    }

    fn remove_network_if_running() -> Result <(), String> {
        let mut command = Command::new ("docker", Command::strings (vec! ("network", "ls")));
        if command.wait_for_exit () != 0 {return Err (format! ("Could not list networks: {}", command.stderr_as_string()))}
        let output = command.stdout_as_string();
        if !output.contains ("integration_net") {return Ok (())}
        let mut command = Command::new ("docker", Command::strings (vec! ("network", "rm", "integration_net")));
        match command.wait_for_exit () {
            0 => Ok(()),
            _ => Err(format!("Could not remove network integration_net: {}", command.stderr_as_string()))
        }
    }

    fn create_network () -> Result <(), String> {
        let mut command = Command::new ("docker", Command::strings (vec! ("network", "create", "--subnet=172.18.0.0/16", "integration_net")));
        match command.wait_for_exit () {
            0 => Ok(()),
            _ => Err(format!("Could not create network integration_net: {}", command.stderr_as_string()))
        }
    }

    fn interconnect_network () -> Result <(), String> {
        let mut command = Command::new ("docker", Command::strings (vec! ("network", "connect", "integration_net", "subjenkins")));
        match command.wait_for_exit () {
            0 => Ok(()),
            _ => Err(format!("Could not connect subjenkins to integration_net: {}", command.stderr_as_string()))
        }
    }
}
