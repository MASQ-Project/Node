// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

use std::env;
use std::io::Read;
use std::ops::Drop;
use std::process::Child;
use std::process::Command;
use std::process::Stdio;

pub struct TestCommand {
    command: String,
    child: Child,
}

impl Drop for TestCommand {
    fn drop(&mut self) {
        self.kill();
    }
}

impl TestCommand {
    pub fn start(command: &str, parameters: Vec<&str>) -> TestCommand {
        let mut command_object = TestCommand::make_command(command, parameters.clone());
        command_object.stdout(Stdio::piped());
        command_object.stderr(Stdio::piped());
        let child = command_object.spawn().unwrap();
        TestCommand {
            command: format!(
                "{}{}",
                command,
                parameters.iter().fold(String::new(), |so_far, parameter| {
                    format!("{} {}", so_far, parameter)
                })
            ),
            child,
        }
    }

    pub fn wait(&mut self) -> Option<i32> {
        match self.child.wait() {
            Err(e) => panic!("{:?}", e),
            Ok(exit_status) => exit_status.code(),
        }
    }

    pub fn kill(&mut self) {
        let _ = self.child.kill(); // can't do anything special for failure
    }

    pub fn output(&mut self) -> String {
        let mut stdout = String::new();
        let child_stdout = match self.child.stdout.as_mut() {
            Some(cso) => cso,
            None => panic!(
                "Could not get standard output from command: {}",
                self.command
            ),
        };
        child_stdout.read_to_string(&mut stdout).unwrap();
        let mut stderr = String::new();
        let child_stderr = match self.child.stderr.as_mut() {
            Some(cse) => cse,
            None => panic!(
                "Could not get standard error from command: {}",
                self.command
            ),
        };
        child_stderr.read_to_string(&mut stderr).unwrap();
        format!(
            "STANDARD OUTPUT:\n{}\nSTANDARD ERROR:\n{}\n",
            stdout, stderr
        )
    }

    #[cfg(target_os = "windows")]
    fn make_command(command: &str, parameters: Vec<&str>) -> Command {
        let test_command = env::args().next().unwrap();
        let debug_or_release = test_command
            .split("\\")
            .skip_while(|s| s != &"target")
            .skip(1)
            .next()
            .unwrap();
        let command_to_start = &format!("target\\{}\\{}", debug_or_release, command);
        let mut command = Command::new(command_to_start);
        command.args(parameters);
        command
    }

    #[cfg(not(target_os = "windows"))]
    fn make_command(command: &str, parameters: Vec<&str>) -> Command {
        let test_command = env::args().next().unwrap();
        let debug_or_release = test_command
            .split("/")
            .skip_while(|s| s != &"target")
            .skip(1)
            .next()
            .unwrap();
        let command_to_start = format!("target/{}/{}", debug_or_release, command);
        let mut command = Command::new(command_to_start);
        command.args(parameters);
        command
    }
}
