// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

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
            _ => Err(self.diagnosis()),
        }
    }

    pub fn stdout_and_stderr(&mut self) -> String {
        let exit_code = self.wait_for_exit();
        self.combine_exit_code_stdout_and_stderr(exit_code)
    }

    fn combine_exit_code_stdout_and_stderr(&self, exit_code: i32) -> String {
        format!(
            "EXIT CODE: {}\nSTDOUT:\n{}\n\nSTDERR:\n{}\n\n",
            exit_code,
            self.stdout_as_string(),
            self.stderr_as_string()
        )
    }

    fn diagnosis(&self) -> String {
        let stdout = self.stdout_as_string();
        let stderr = self.stderr_as_string();
        if stdout.len() > stderr.len() {
            format!("{} (stdout: '{}')", stderr, stdout)
        } else {
            stderr
        }
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
        if string.len() > MAX_PRINTED_STRING_SIZE {
            string.truncate(MAX_PRINTED_STRING_SIZE);
            string.push_str(" [...truncated...]");
        }
        string
    }
}
