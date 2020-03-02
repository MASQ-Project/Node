// Copyright (c) 2019-2020, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use std::path::PathBuf;
use std::process::{Child, Command, Stdio};

#[allow(dead_code)]
pub struct DaemonProcess {}

#[allow(dead_code)]
impl DaemonProcess {
    pub fn new() -> Self {
        Self {}
    }

    pub fn start(self, port: u16) -> StopHandle {
        let mut command = Command::new(executable_path(executable_name("MASQNode")));
        let command = command.args(vec![
            "--ui-port".to_string(),
            format!("{}", port),
            "--initialization".to_string(),
        ]);
        let child = child_from_command(command);
        StopHandle {
            name: "Daemon".to_string(),
            child,
        }
    }
}

pub struct MasqProcess {}

#[allow(dead_code)]
impl MasqProcess {
    pub fn new() -> Self {
        Self {}
    }

    pub fn start_noninteractive(self, params: Vec<&str>) -> StopHandle {
        let mut command = Command::new(executable_path(executable_name("masq")));
        let command = command.args(params);
        let child = child_from_command(command);
        StopHandle {
            name: "masq".to_string(),
            child,
        }
    }
}

pub struct StopHandle {
    name: String,
    child: Child,
}

#[allow(dead_code)]
impl StopHandle {
    pub fn stop(self) -> (String, String, i32) {
        let output = self.child.wait_with_output();
        match output {
            Ok(output) => {
                let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                let exit_code = output.status.code().unwrap();
                (stdout, stderr, exit_code)
            }
            Err(e) => {
                eprintln!("Couldn't get output from {}: {:?}", self.name, e);
                (String::new(), String::new(), -1)
            }
        }
    }

    pub fn kill(mut self) {
        self.child.kill().unwrap();
    }
}

fn executable_name(root: &str) -> String {
    #[cfg(not(target_os = "windows"))]
    let result = root.to_string();
    #[cfg(target_os = "windows")]
    let result = format!("{}.exe", root);
    return result;
}

fn executable_path(executable_name: String) -> PathBuf {
    std::env::current_dir()
        .unwrap()
        .join("..")
        .join("node")
        .join("target")
        .join("release")
        .join(executable_name)
}

fn child_from_command(command: &mut Command) -> Child {
    command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
}
