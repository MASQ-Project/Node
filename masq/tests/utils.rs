// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use masq_cli_lib::terminal::terminal_interface::{
    MASQ_TEST_INTEGRATION_KEY, MASQ_TEST_INTEGRATION_VALUE,
};
use masq_lib::short_writeln;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, Stdio};

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
        let command = command.args(&params);
        eprintln!("About to start masq with args {:?}", &params);
        let child = child_from_command(command);
        StopHandle {
            name: "masq".to_string(),
            child,
        }
    }

    pub fn start_interactive(self, port: u16, mocked_terminal: bool) -> StopHandle {
        if mocked_terminal {
            std::env::set_var(MASQ_TEST_INTEGRATION_KEY, MASQ_TEST_INTEGRATION_VALUE)
        };
        let mut command = Command::new(executable_path(executable_name("masq")));
        let command = command.arg("--ui-port").arg(port.to_string());
        eprintln!("About to start masq using {:?}", command);
        let child = child_from_command(command);
        StopHandle {
            name: "masq".to_string(),
            child,
        }
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
        short_writeln!(&self.stdin, "{}", command);
    }
}

pub struct StopHandle {
    name: String,
    child: Child,
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

#[derive(Default)]
#[allow(dead_code)]
pub struct MasqProcessMediated {}

#[allow(dead_code)]
impl MasqProcessMediated {
    #[cfg(not(target_os = "windows"))]
    pub fn start_masq_interactive_in_bash(
        self,
        port: u16,
        mocked_terminal: bool
    ) -> (StopHandle,StdinHandle, i32) {
        if mocked_terminal {std::env::set_var(MASQ_TEST_INTEGRATION_KEY, MASQ_TEST_INTEGRATION_VALUE)};
        let mut shell_child = Self::prepare_shell();
        let mut bash_stdin_handle = StdinHandle::new(shell_child.stdin.take().unwrap());
        let masq_executable = executable_path(executable_name("masq"));
        // let file_directory = PATH_TO_MASQ_GENERATED_FOR_INT_TESTS.join(test_module);
        // let _ = create_dir_all(&file_directory);
        // let masq_output_full_path = file_directory.join("redirected_output.txt");
        // let cash_file_full_path = file_directory.join("cash_file.txt");
        // File::create(&masq_output_full_path).unwrap();
        // File::create(&cash_file_full_path).unwrap();
        let bash_command = format!(
            "{} --ui-port {}",
            masq_executable.as_os_str().to_str().unwrap(),
            port
        );
        eprintln!(
            "About to start masq in the background using {:?}",
            bash_command
        );
        bash_stdin_handle.type_command(&bash_command);

        (
            StopHandle {
                name: "shell".to_string(),
                child: shell_child,
            },
            bash_stdin_handle,
            0 //TODO make meaningful or remove, should have been the masq process's PID
        )
    }

    fn prepare_shell() -> Child {
        let mut command = Command::new("bash");
        child_from_command(&mut command)
    }
}
//
// lazy_static! {
//     pub static ref PATH_TO_MASQ_GENERATED_FOR_INT_TESTS: PathBuf =
//         current_dir().unwrap().join(BASE_TEST_DIR);
// }
