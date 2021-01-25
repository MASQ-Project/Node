// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

use masq_lib::constants::{CURRENT_LOGFILE_NAME, DEFAULT_UI_PORT};
use masq_lib::test_utils::utils::{ensure_node_home_directory_exists, TEST_DEFAULT_CHAIN_NAME};
use masq_lib::utils::localhost;
use node_lib::test_utils::await_value;
use std::env;
use std::io;
use std::net::SocketAddr;
use std::ops::Drop;
use std::path::{Path, PathBuf};
use std::process;
use std::process::Output;
use std::thread;
use std::time::Duration;
use std::time::Instant;

pub struct MASQNode {
    pub logfile_contents: String,
    pub data_dir: PathBuf,
    child: Option<process::Child>,
    output: Option<Output>,
}

#[derive(Clone)]
pub struct CommandConfig {
    pub args: Vec<String>,
}

impl CommandConfig {
    pub fn new() -> CommandConfig {
        CommandConfig { args: vec![] }
    }

    #[allow(dead_code)]
    pub fn opt(mut self, option: &str) -> CommandConfig {
        self.args.push(option.to_string());
        self
    }

    pub fn pair(mut self, option: &str, value: &str) -> CommandConfig {
        self.args.push(option.to_string());
        self.args.push(value.to_string());
        self
    }

    pub fn value_of(&self, parameter: &str) -> Option<String> {
        for n in 0..self.args.len() {
            if self.args[n] == parameter {
                if (n + 1) >= self.args.len() {
                    return None;
                }
                return Some(self.args[n + 1].clone());
            }
        }
        None
    }
}

impl Drop for MASQNode {
    fn drop(&mut self) {
        let _ = self.kill();
    }
}

impl MASQNode {
    pub fn path_to_logfile(data_dir: &PathBuf) -> Box<Path> {
        data_dir.join(CURRENT_LOGFILE_NAME).into_boxed_path()
    }

    pub fn path_to_database(data_dir: &PathBuf) -> Box<Path> {
        data_dir.join("node-data.db").into_boxed_path()
    }

    #[allow(dead_code)]
    pub fn output(&mut self) -> Option<Output> {
        self.output.take()
    }

    pub fn start_daemon(
        test_name: &str,
        config_opt: Option<CommandConfig>,
        ensure_start: bool,
    ) -> MASQNode {
        Self::start_something(
            test_name,
            config_opt,
            ensure_start,
            Self::make_daemon_command,
        )
    }

    #[allow(dead_code)]
    pub fn start_standard(
        test_name: &str,
        config_opt: Option<CommandConfig>,
        ensure_start: bool,
    ) -> MASQNode {
        Self::start_something(test_name, config_opt, ensure_start, Self::make_node_command)
    }

    #[allow(dead_code)]
    pub fn run_dump_config(test_name: &str) -> String {
        let data_dir = ensure_node_home_directory_exists("integration", test_name);
        let mut command = MASQNode::make_dump_config_command(&data_dir);
        let output = command.output().unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        format!("stdout:\n{}\nstderr:\n{}", stdout, stderr)
    }

    #[allow(dead_code)]
    pub fn wait_for_log(&mut self, pattern: &str, limit_ms: Option<u64>) {
        let regex = regex::Regex::new(pattern).unwrap();
        let real_limit_ms = limit_ms.unwrap_or(0xFFFFFFFF);
        let started_at = Instant::now();
        let path_to_logfile = Self::path_to_logfile(&self.data_dir);
        loop {
            match std::fs::read_to_string(&path_to_logfile) {
                Ok(contents) => {
                    self.logfile_contents = contents;
                    if regex.is_match(&self.logfile_contents[..]) {
                        break;
                    }
                }
                Err(e) => {
                    eprintln!("Could not read logfile at {:?}: {:?}", path_to_logfile, e);
                }
            };
            assert_eq!(
                MASQNode::millis_since(started_at) < real_limit_ms,
                true,
                "Timeout: waited for more than {}ms without finding '{}' in these logs:\n{}\n",
                real_limit_ms,
                pattern,
                self.logfile_contents
            );
            thread::sleep(Duration::from_millis(200));
        }
    }

    #[allow(dead_code)]
    pub fn wait_for_exit(&mut self) -> Option<Output> {
        let child_opt = self.child.take();
        let output_opt = self.output.take();
        match (child_opt, output_opt) {
            (None, Some(output)) => {
                self.output = Some(output);
                self.output.clone()
            }
            (Some(child), None) => match child.wait_with_output() {
                Ok(output) => Some(output),
                Err(e) => panic!("{:?}", e),
            },
            (Some(_), Some(_)) => panic!("Internal error: Inconsistent MASQ Node state"),
            (None, None) => None,
        }
    }

    #[cfg(not(target_os = "windows"))]
    pub fn kill(&mut self) -> Result<process::ExitStatus, io::Error> {
        let child_opt = self.child.take();
        let output_opt = self.output.take();
        Ok(match (child_opt, output_opt) {
            (Some(mut child), None) => {
                child.kill()?;
                let result = child.wait()?;
                self.output = Some(Output {
                    status: result,
                    stdout: vec![],
                    stderr: vec![],
                });
                result
            }
            (None, Some(output)) => {
                let result = output.status.clone();
                self.output = Some(output);
                result
            }
            (Some(_), Some(_)) => panic!("Internal error: Inconsistent MASQ Node state"),
            (None, None) => return Err(io::Error::from(io::ErrorKind::InvalidData)),
        })
    }

    #[cfg(target_os = "windows")]
    pub fn kill(&mut self) -> Result<(), io::Error> {
        let mut command = process::Command::new("taskkill");
        command.args(&["/IM", "MASQNode.exe", "/F"]);
        let _ = command.output().expect("Couldn't kill MASQNode.exe");
        self.child.take();
        // Be nice if we could figure out how to populate self.output here
        Ok(()) //Could it be left like that?
    }

    pub fn remove_logfile(data_dir: &PathBuf) -> Box<Path> {
        let logfile_path = Self::path_to_logfile(data_dir);
        match std::fs::remove_file(&logfile_path) {
            Ok(_) => (),
            Err(ref e) if e.kind() == std::io::ErrorKind::NotFound => (),
            Err(ref e) => panic!("{:?}", e),
        }
        logfile_path
    }

    pub fn remove_database(data_dir: &PathBuf) {
        let database = Self::path_to_database(data_dir);
        match std::fs::remove_file(database.clone()) {
            Ok(_) => (),
            Err(ref e) if e.kind() == io::ErrorKind::NotFound => (),
            Err(e) => panic!(
                "Couldn't remove preexisting database at {:?}: {}",
                database, e
            ),
        }
    }

    fn start_something<F: FnOnce(&PathBuf, Option<CommandConfig>) -> process::Command>(
        test_name: &str,
        config_opt: Option<CommandConfig>,
        ensure_start: bool,
        command_getter: F,
    ) -> MASQNode {
        let data_dir = ensure_node_home_directory_exists("integration", test_name);
        Self::remove_logfile(&data_dir);
        let ui_port = Self::ui_port_from_config_opt(&config_opt);
        let mut command = command_getter(&data_dir, config_opt);
        eprintln!("{:?}", command);
        let child = command.spawn().unwrap();
        let mut result = MASQNode {
            logfile_contents: String::new(),
            data_dir,
            child: Some(child),
            output: None,
        };
        if ensure_start {
            result.wait_for_node(ui_port).unwrap();
        }
        result
    }

    fn millis_since(started_at: Instant) -> u64 {
        let interval = Instant::now().duration_since(started_at);
        let second_milliseconds = interval.as_secs() * 1000;
        let nanosecond_milliseconds = (interval.subsec_nanos() as u64) / 1000000;
        second_milliseconds + nanosecond_milliseconds
    }

    fn make_daemon_command(data_dir: &PathBuf, config: Option<CommandConfig>) -> process::Command {
        Self::remove_database(data_dir);
        let mut command = command_to_start();
        let mut args = Self::daemon_args();
        args.extend(match config {
            Some(c) => c.args,
            None => vec![],
        });
        command.args(&args);
        command
    }

    fn make_node_command(data_dir: &PathBuf, config: Option<CommandConfig>) -> process::Command {
        Self::remove_database(data_dir);
        let mut command = command_to_start();
        let mut args = Self::standard_args();
        args.extend(Self::get_extra_args(data_dir, config));
        command.args(&args);
        command
    }

    #[allow(dead_code)]
    fn make_dump_config_command(data_dir: &PathBuf) -> process::Command {
        Self::remove_database(&data_dir);
        let mut command = command_to_start();
        let args = Self::dump_config_args();
        command.args(&args);
        command
    }

    fn daemon_args() -> Vec<String> {
        apply_prefix_parameters(CommandConfig::new())
            .opt("--initialization")
            .args
    }

    fn standard_args() -> Vec<String> {
        apply_prefix_parameters(CommandConfig::new())
            .pair("--neighborhood-mode", "zero-hop")
            .pair(
                "--consuming-private-key",
                "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
            )
            .pair("--chain", TEST_DEFAULT_CHAIN_NAME)
            .pair("--log-level", "trace")
            .args
    }

    #[allow(dead_code)]
    fn dump_config_args() -> Vec<String> {
        apply_prefix_parameters(CommandConfig::new())
            .opt("--dump-config")
            .args
    }

    fn get_extra_args(data_dir: &PathBuf, config_opt: Option<CommandConfig>) -> Vec<String> {
        let mut args = config_opt.unwrap_or(CommandConfig::new()).args;
        if !args.contains(&"--data-directory".to_string()) {
            args.push("--data-directory".to_string());
            args.push(data_dir.to_string_lossy().to_string());
        }
        args
    }

    fn wait_for_node(&mut self, ui_port: u16) -> Result<(), String> {
        let result = await_value(Some((600, 6000)), || {
            let address = SocketAddr::new(localhost(), ui_port);
            match std::net::TcpStream::connect_timeout(&address, Duration::from_millis(100)) {
                Ok(stream) => {
                    stream.shutdown(std::net::Shutdown::Both).unwrap();
                    Ok(())
                }
                Err(e) => Err(format!("Can't connect yet on port {}: {:?}", ui_port, e)),
            }
        });
        if result.is_err() {
            self.kill().map_err(|e| format!("{:?}", e))?;
        };
        result
    }

    fn ui_port_from_config_opt(config_opt: &Option<CommandConfig>) -> u16 {
        match config_opt {
            None => DEFAULT_UI_PORT,
            Some(config) => match config.value_of("--ui-port") {
                None => DEFAULT_UI_PORT,
                Some(ui_port_string) => ui_port_string.parse::<u16>().unwrap(),
            },
        }
    }
}

#[cfg(target_os = "windows")]
fn command_to_start() -> process::Command {
    process::Command::new("cmd")
}

#[cfg(not(target_os = "windows"))]
fn command_to_start() -> process::Command {
    let test_command = env::args().next().unwrap();
    let debug_or_release = test_command
        .split("/")
        .skip_while(|s| s != &"target")
        .skip(1)
        .next()
        .unwrap();
    let bin_dir = &format!("target/{}", debug_or_release);
    let command_to_start = &format!("{}/MASQNode", bin_dir);
    process::Command::new(command_to_start)
}

#[cfg(target_os = "windows")]
fn apply_prefix_parameters(command_config: CommandConfig) -> CommandConfig {
    command_config.pair("/c", &node_command())
}

#[cfg(not(target_os = "windows"))]
fn apply_prefix_parameters(command_config: CommandConfig) -> CommandConfig {
    command_config
}

#[cfg(target_os = "windows")]
#[allow(dead_code)]
fn node_command() -> String {
    let test_command = env::args().next().unwrap();
    let debug_or_release = test_command
        .split("\\")
        .skip_while(|s| s != &"target")
        .skip(1)
        .next()
        .unwrap();
    let bin_dir = &format!("target\\{}", debug_or_release);
    format!("{}\\MASQNode.exe", bin_dir)
}
