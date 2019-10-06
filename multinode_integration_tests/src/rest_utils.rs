// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

use crate::command::Command;
use crate::masq_node::MASQNodeUtils;

pub struct RestServer<'a> {
    pub name: &'a str,
}

impl<'a> RestServer<'a> {
    pub fn start(&self) {
        MASQNodeUtils::clean_up_existing_container(self.name);
        let args = vec![
            "run",
            "--detach",
            "--name",
            self.name,
            "--net",
            "integration_net",
            "mock_rest_server",
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
        command.stdout_or_stderr().map(|x| x.trim().to_string())
    }
}

impl<'a> Drop for RestServer<'a> {
    fn drop(&mut self) {
        MASQNodeUtils::stop(self.name);
    }
}
