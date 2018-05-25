// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

use std::process;
use std::process::Output;

pub struct Command {
    command: process::Command,
    output: Option<Output>
}

impl Command {

    pub fn new (program: &str, args: Vec<&str>) -> Command {
        let mut command = process::Command::new (program);
        command.args (args);

        Command {command, output: None}
    }

    pub fn wait_for_exit (&mut self) -> i32 {
        self.output = Some (self.command.output ().unwrap ());
        match self.output.as_ref ().unwrap ().status.code () {
            None => panic! ("Command terminated by signal"),
            Some (exit_code) => exit_code
        }
    }

    pub fn stdout_as_string (&self) -> String {
        String::from_utf8 (self.output.as_ref ().unwrap ().stdout.clone ()).unwrap ()
    }

    pub fn stderr_as_string (&self) -> String {
        String::from_utf8 (self.output.as_ref ().unwrap ().stderr.clone ()).unwrap ()
    }
}
