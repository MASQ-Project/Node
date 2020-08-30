// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

use std::process;
use std::process::Output;

pub struct Command {
    text: String,
    command: process::Command,
    output: Option<Output>,
}

// Jenkins will fail if you try to println! too many (hundreds of thousands) of characters at once
const MAX_PRINTED_STRING_SIZE: usize = 10000;

impl Command {
    pub fn new(program: &str, args: Vec<String>) -> Command {
        let mut command = process::Command::new(program);
        command.args(args.iter().map(|x| x.as_str()));

        Command {
            text: format!("{} {}", program, args.join(" ")),
            command,
            output: None,
        }
    }

    pub fn strings(slices: Vec<&str>) -> Vec<String> {
        slices.into_iter().map(String::from).collect()
    }

    pub fn wait_for_exit(&mut self) -> i32 {
        println!("{}", self.text);
        self.output = Some(self.command.output().unwrap());
        match self.output.as_ref().unwrap().status.code() {
            None => panic!("Command terminated by signal"),
            Some(exit_code) => exit_code,
        }
    }

    pub fn stdout_or_stderr(&mut self) -> Result<String, String> {
        match self.wait_for_exit() {
            0 => Ok(self.stdout_as_string()),
            _ => Err(self.stderr_as_string()),
        }
    }

    pub fn stdout_and_stderr(&mut self) -> String {
        self.wait_for_exit();
        self.stdout_as_string() + self.stderr_as_string().as_str()
    }

    pub fn stdout_as_string(&self) -> String {
        let text = String::from_utf8(self.output.as_ref().unwrap().stdout.clone()).unwrap();
        println!("{}", Self::truncate_long_string(text.clone()));
        text
    }

    pub fn stderr_as_string(&self) -> String {
        let text = String::from_utf8(self.output.as_ref().unwrap().stderr.clone()).unwrap();
        println!("{}", Self::truncate_long_string(text.clone()));
        text
    }

    fn truncate_long_string(mut string: String) -> String {
        if string.len() <= MAX_PRINTED_STRING_SIZE {
            string
        } else {
            string.truncate(MAX_PRINTED_STRING_SIZE);
            string.push_str(" [...truncated...]");
            string
        }
    }
}
