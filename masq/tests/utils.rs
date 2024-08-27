// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

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
        let interval = Duration::from_secs(5);
        let start = Instant::now();
        loop {
            if Instant::now().duration_since(start) >= interval {
                panic!("Daemon didn't start up successfully. Maybe try to run the tests again with privilege.");
            }

            let masq_handle = MasqProcess::new().start_noninteractive(vec![
                "--ui-port",
                format!("{}", port).as_str(),
                "descriptor",
            ]);

            let (_stdout, stderr, _exit_code) = masq_handle.stop();
            if stderr.contains("Cannot handle descriptor request: Node is not running") {
                break;
            }
            thread::sleep(Duration::from_millis(40));
        }

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
        let command = command.args(&params);
        eprintln!("About to start masq with args {:?}", &params);
        let child = child_from_command(command);
        StopHandle {
            name: "masq".to_string(),
            child,
        }
    }

    pub fn start_interactive(self, port: u16, fake_terminal: bool) -> StopHandle {
        todo!()
        // if fake_terminal {
        //     std::env::set_var(MASQ_TEST_INTEGRATION_KEY, MASQ_TEST_INTEGRATION_VALUE)
        // };
        // let mut command = Command::new(executable_path(executable_name("masq")));
        // let command = command.arg("--ui-port").arg(port.to_string());
        // eprintln!("About to start masq using {:?}", command);
        // let child = child_from_command(command);
        // StopHandle {
        //     name: "masq".to_string(),
        //     child,
        // }
    }
}

#[allow(dead_code)]
pub struct StdinHandle {
    stdin: ChildStdin,
}

#[allow(dead_code)]
impl StdinHandle {
    fn new(native_stdin: ChildStdin) -> Self {
        Self {
            stdin: native_stdin,
        }
    }
    pub fn type_command(&mut self, command: &str) {
        match self.stdin.write_fmt(format_args!("{}\n", command)) {
            Ok(_) => match self.stdin.flush() {
                Ok(_) => (),
                Err(e) => panic!("flush failed in type_command: {}", e),
            },
            Err(e) => {
                panic!("type_command write failed: {}", e)
            }
        }
    }
}

pub struct StopHandle {
    name: String,
    pub child: Child,
}

#[allow(dead_code)]
impl StopHandle {
    pub fn stop(self) -> (String, String, Option<i32>) {
        let output = self.child.wait_with_output();
        match output {
            Ok(output) => {
                let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                let exit_code = output.status.code();
                (stdout, stderr, exit_code)
            }
            Err(e) => {
                eprintln!("Couldn't get output from {}: {:?}", self.name, e);
                (String::new(), String::new(), Some(-1))
            }
        }
    }

    pub fn create_stdin_handle(&mut self) -> StdinHandle {
        StdinHandle::new(self.child.stdin.take().unwrap())
    }

    pub fn child_id(&self) -> u32 {
        self.child.id()
    }

    pub fn kill(mut self) {
        self.child.kill().unwrap();

        #[cfg(target_os = "windows")]
        Self::taskkill();
    }

    #[cfg(target_os = "windows")]
    pub fn taskkill() {
        let mut command = Command::new("taskkill");
        command.args(&["/IM", "MASQNode.exe", "/F", "/T"]);
        let _ = command.output().expect("Couldn't kill MASQNode.exe");
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
