// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

use crate::command::Command;
use crate::masq_node::MASQNodeUtils;
use node_lib::test_utils;
use std::net::{IpAddr, Ipv4Addr};

pub struct BlockchainServer<'a> {
    pub name: &'a str,
}

impl<'a> BlockchainServer<'a> {
    pub fn start(&self) {
        MASQNodeUtils::clean_up_existing_container(self.name);
        let ip_addr = IpAddr::V4(Ipv4Addr::new(172, 18, 1, 250));
        let ip_addr_string = ip_addr.to_string();
        let args = vec![
            "run",
            "--detach",
            "--name",
            self.name,
            "--ip",
            ip_addr_string.as_str(),
            "-p",
            "18545:18545",
            "--net",
            "integration_net",
            "ganache-cli",
        ];
        let mut command = Command::new("docker", Command::strings(args));
        command.stdout_or_stderr().unwrap();
    }

    pub fn ip(&self) -> Result<String, String> {
        let args = vec![
            "inspect",
            "-f",
            "{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
            self.name,
        ];
        let mut command = Command::new("docker", Command::strings(args));
        command.stdout_or_stderr()
    }

    pub fn service_url(&self) -> String {
        format!("http://{}:18545", self.ip().unwrap().trim())
    }

    pub fn wait_until_ready(&self) {
        test_utils::wait_for(Some(500), Some(10000), || {
            let mut cmd = Command::new("docker", Command::strings(vec!["logs", "ganache-cli"]));
            let output = cmd.stdout_and_stderr();
            output.contains("Listening on 0.0.0.0:18545")
        })
    }
}

impl<'a> Drop for BlockchainServer<'a> {
    fn drop(&mut self) {
        MASQNodeUtils::stop(self.name);
    }
}
