// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
extern crate regex;

use std::process::Command;
use std::process::Child;
use std::io::Read;
use std::env;
use std::ops::Drop;

pub struct TestCommand {
    child: Child
}

impl Drop for TestCommand {
    fn drop(&mut self) {
        self.kill ();
    }
}

impl TestCommand {
    pub fn start (command: &str, parameters: Vec<&str>) -> TestCommand {
        let mut command = TestCommand::make_command(command, parameters);
        let child = command.spawn ().unwrap ();
        TestCommand {
            child
        }
    }

    pub fn wait (&mut self) -> Option<i32> {
        match self.child.wait () {
            Err (e) => panic! ("{:?}", e),
            Ok (exit_status) => exit_status.code ()
        }
    }

    pub fn kill (&mut self) {
        self.child.kill ().is_ok (); // can't do anything special for failure
    }

    pub fn output (&mut self) -> String {
        let mut stdout = String::new ();
        self.child.stdout.as_mut ().unwrap ().read_to_string (&mut stdout).unwrap ();
        let mut stderr = String::new ();
        self.child.stderr.as_mut ().unwrap ().read_to_string (&mut stderr).unwrap ();
        format! ("STANDARD OUTPUT:\n{}\nSTANDARD ERROR:\n{}\n", stdout, stderr)
    }

    #[cfg(windows)]
    fn make_command (command: &str, parameters: Vec<&str>) -> Command {
        let test_command = env::args ().next ().unwrap ();
        let debug_or_release = test_command.split ("\\").skip_while (|s| s != &"target").skip(1).next().unwrap();
        let command_to_start = &format! ("target\\{}\\{}", debug_or_release, command);
        let mut command = Command::new (command_to_start);
        command.args (parameters);
        command
    }

    #[cfg(unix)]
    fn make_command (command: &str, parameters: Vec<&str>) -> Command {
        let test_command = env::args ().next ().unwrap ();
        let debug_or_release = test_command.split ("/").skip_while (|s| s != &"target").skip(1).next().unwrap();
        let command_to_start = format! ("target/{}/{}", debug_or_release, command);
        let mut command = Command::new (command_to_start);
        command.args (parameters);
        command
    }
}
