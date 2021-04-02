// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use masq_lib::short_writeln;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;

#[allow(dead_code)]
pub struct DaemonProcess {}

#[allow(dead_code)]
impl DaemonProcess {
    pub fn new() -> Self {
        Self {}
    }

    pub fn start(self, port: u16) -> StopHandle {
        let executable = executable_path(executable_name("MASQNode"));
        let args = vec![
            "--ui-port".to_string(),
            format!("{}", port),
            "--initialization".to_string(),
        ];
        eprintln!(
            "About to start Daemon at '{:?}' with args {:?}",
            executable, args
        );
        let mut command = Command::new(executable);
        let command = command.args(args);
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

    pub fn start_interactive(self) -> ControlHandle {
        let mut command = Command::new(executable_path(executable_name("masq")));
        let child = child_from_command(&mut command);
        ControlHandle::new(
            child.stdin.unwrap(),
            child.stdout.unwrap(),
            child.stderr.unwrap(),
        )
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
        Self::taskkill();
    }

    pub fn taskkill() {
        #[cfg(target_os = "windows")]
        {
            let mut command = Command::new("taskkill");
            command.args(&["/IM", "MASQNode.exe", "/F", "/T"]);
            let _ = command.output().expect("Couldn't kill MASQNode.exe");
        }
    }
}

#[allow(dead_code)]
pub struct ControlHandle {
    stdin: ChildStdin,
    stdout: Arc<Mutex<String>>,
    stderr: Arc<Mutex<String>>,
}

#[allow(dead_code)]
impl ControlHandle {
    fn new(stdin: ChildStdin, stdout: ChildStdout, stderr: ChildStderr) -> Self {
        let stdout_arc = Self::start_listener(Box::new(stdout));
        let stderr_arc = Self::start_listener(Box::new(stderr));
        ControlHandle {
            stdin,
            stdout: stdout_arc,
            stderr: stderr_arc,
        }
    }

    pub fn type_command(&mut self, command: &str) {
        short_writeln!(self.stdin, "{}", command);
    }

    pub fn get_stdout(&mut self) -> String {
        Self::read_chunk(&self.stdout)
    }

    pub fn get_stderr(&mut self) -> String {
        Self::read_chunk(&self.stderr)
    }

    fn read_chunk(string_arc: &Arc<Mutex<String>>) -> String {
        let mut string = string_arc.lock().unwrap();
        let chunk = (*string).clone();
        string.clear();
        chunk
    }

    fn start_listener(mut stream: Box<dyn Read + Send>) -> Arc<Mutex<String>> {
        let internal_arc = Arc::new(Mutex::new(String::new()));
        let external_arc = internal_arc.clone();
        thread::spawn(move || loop {
            let mut buf = String::new();
            match stream.read_to_string(&mut buf) {
                Err(e) => {
                    let mut internal = internal_arc.lock().unwrap();
                    internal.push_str(format!("[Error: {:?}]", e).as_str());
                    break;
                }
                Ok(_) => {
                    let mut internal = internal_arc.lock().unwrap();
                    internal.push_str(buf.as_str());
                }
            }
        });
        external_arc
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
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
}
