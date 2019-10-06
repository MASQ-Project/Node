// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

use std::env;
use std::io;
use std::ops::Drop;
use std::path::Path;
use std::process;
use std::process::Output;
use std::thread;
use std::time::Duration;
use std::time::Instant;

pub struct MASQNode {
    pub logfile_contents: String,
    child: Option<process::Child>,
    output: Option<Output>,
}

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
}

impl Drop for MASQNode {
    fn drop(&mut self) {
        let _ = self.kill();
    }
}

impl MASQNode {
    pub fn data_dir() -> Box<Path> {
        let cur_dir = env::current_dir().unwrap();
        let generated_dir = cur_dir.join(Path::new("generated"));
        generated_dir.into_boxed_path()
    }

    pub fn path_to_logfile() -> Box<Path> {
        Self::data_dir()
            .join("MASQNode_rCURRENT.log")
            .into_boxed_path()
    }

    pub fn path_to_database() -> Box<Path> {
        Self::data_dir().join("node-data.db").into_boxed_path()
    }

    #[allow(dead_code)]
    pub fn output(&mut self) -> Option<Output> {
        self.output.take()
    }

    #[allow(dead_code)]
    pub fn start_standard(config: Option<CommandConfig>) -> MASQNode {
        let mut command = MASQNode::make_node_command(config);
        eprintln!("{:?}", command);
        let child = command.spawn().unwrap();
        thread::sleep(Duration::from_millis(500)); // needs time to open logfile and sockets
        MASQNode {
            logfile_contents: String::new(),
            child: Some(child),
            output: None,
        }
    }

    #[allow(dead_code)]
    pub fn run_dump_config() -> String {
        let mut command = MASQNode::make_dump_config_command();
        let output = command.output().unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        format!("stdout:\n{}\nstderr:\n{}", stdout, stderr)
    }

    #[allow(dead_code)]
    pub fn run_generate(config: CommandConfig) -> String {
        let mut command = MASQNode::make_generate_command(config);
        let output = command.output().unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        format!("stdout:\n{}\nstderr:\n{}", stdout, stderr)
    }

    #[allow(dead_code)]
    pub fn run_recover(config: CommandConfig) -> String {
        let mut command = MASQNode::make_recover_command(config);
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
        loop {
            self.logfile_contents = std::fs::read_to_string(Self::path_to_logfile()).unwrap();
            if regex.is_match(&self.logfile_contents[..]) {
                break;
            }
            assert_eq!(
                MASQNode::millis_since(started_at) < real_limit_ms,
                true,
                "Timeout: waited for more than {}ms",
                real_limit_ms
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
            (None, None) => panic!("Internal error: MASQ Node is already empty"),
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
    pub fn kill(&mut self) {
        let mut command = process::Command::new("taskkill");
        command.args(&vec!["/IM", "MASQNode.exe", "/F"]);
        let _ = command.output().expect("Couldn't kill MASQNode.exe");
        self.child.take();
        // Be nice if we could figure out how to populate self.output here
    }

    pub fn remove_database() {
        let database = Self::path_to_database();
        match std::fs::remove_file(database.clone()) {
            Ok(_) => (),
            Err(ref e) if e.kind() == io::ErrorKind::NotFound => (),
            Err(e) => panic!(
                "Couldn't remove preexisting database at {:?}: {}",
                database, e
            ),
        }
    }

    fn millis_since(started_at: Instant) -> u64 {
        let interval = Instant::now().duration_since(started_at);
        let second_milliseconds = interval.as_secs() * 1000;
        let nanosecond_milliseconds = (interval.subsec_nanos() as u64) / 1000000;
        second_milliseconds + nanosecond_milliseconds
    }

    fn make_node_command(config: Option<CommandConfig>) -> process::Command {
        Self::remove_database();
        let mut command = command_to_start();
        let mut args = Self::standard_args();
        args.extend(Self::get_extra_args(config));
        command.args(&args);
        command
    }

    #[allow(dead_code)]
    fn make_dump_config_command() -> process::Command {
        Self::remove_database();
        let mut command = command_to_start();
        let args = Self::dump_config_args();
        command.args(&args);
        command
    }

    fn make_generate_command(config: CommandConfig) -> process::Command {
        Self::remove_database();
        let mut command = command_to_start();
        let mut args = Self::generate_args();
        args.extend(Self::get_extra_args(Some(config)));
        command.args(&args);
        command
    }

    fn make_recover_command(config: CommandConfig) -> process::Command {
        Self::remove_database();
        let mut command = command_to_start();
        let mut args = Self::recover_args();
        args.extend(Self::get_extra_args(Some(config)));
        command.args(&args);
        command
    }

    fn standard_args() -> Vec<String> {
        apply_prefix_parameters(CommandConfig::new())
            .pair("--dns-servers", "8.8.8.8")
            .pair("--neighborhood-mode", "zero-hop")
            .pair(
                "--consuming-private-key",
                "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
            )
            .pair("--log-level", "trace")
            .args
    }

    #[allow(dead_code)]
    fn dump_config_args() -> Vec<String> {
        apply_prefix_parameters(CommandConfig::new())
            .opt("--dump-config")
            .args
    }

    fn generate_args() -> Vec<String> {
        apply_prefix_parameters(CommandConfig::new())
            .opt("--generate-wallet")
            .args
    }

    fn recover_args() -> Vec<String> {
        apply_prefix_parameters(CommandConfig::new())
            .opt("--recover-wallet")
            .args
    }

    fn get_extra_args(config_opt: Option<CommandConfig>) -> Vec<String> {
        let mut args = config_opt.unwrap_or(CommandConfig::new()).args;
        if !args.contains(&"--data-directory".to_string()) {
            args.push("--data-directory".to_string());
            args.push(MASQNode::data_dir().to_string_lossy().to_string());
        }
        args
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
