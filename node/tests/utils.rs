// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

use std::env;
use std::fs::OpenOptions;
use std::io;
use std::io::Read;
use std::ops::Drop;
use std::path::Path;
use std::process;
use std::thread;
use std::time::Duration;
use std::time::Instant;

pub struct SubstratumNode {
    logfile_stream: Box<dyn Read>,
    logfile_contents: String,
    child: process::Child,
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

impl Drop for SubstratumNode {
    fn drop(&mut self) {
        let _ = self.kill();
    }
}

impl SubstratumNode {
    pub fn data_dir() -> Box<Path> {
        env::temp_dir().into_boxed_path()
    }

    pub fn path_to_logfile() -> Box<Path> {
        Self::data_dir()
            .join("SubstratumNode.log")
            .into_boxed_path()
    }

    pub fn path_to_database() -> Box<Path> {
        Self::data_dir().join("node-data.db").into_boxed_path()
    }

    #[allow(dead_code)]
    pub fn start_standard(config: Option<CommandConfig>) -> SubstratumNode {
        let mut command = SubstratumNode::make_node_command(config);
        let child = command.spawn().unwrap();
        thread::sleep(Duration::from_millis(500)); // needs time to open logfile and sockets
        let stream = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(Self::path_to_logfile().to_str().unwrap())
            .unwrap();
        SubstratumNode {
            logfile_stream: Box::new(stream),
            logfile_contents: String::new(),
            child,
        }
    }

    #[allow(dead_code)]
    pub fn run_generate(config: CommandConfig) -> String {
        let mut command = SubstratumNode::make_generate_command(config);
        let output = command.output().unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        format!("stdout:\n{}\nstderr:\n{}", stdout, stderr)
    }

    #[allow(dead_code)]
    pub fn run_recover(config: CommandConfig) -> String {
        let mut command = SubstratumNode::make_recover_command(config);
        let output = command.output().unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        format!("stdout:\n{}\nstderr:\n{}", stdout, stderr)
    }

    #[allow(dead_code)]
    pub fn wait_for_log(&mut self, pattern: &str, limit_ms: Option<u64>) {
        let regex = regex::Regex::new(pattern).unwrap();
        let mut buf: [u8; 0x1000] = [0; 0x1000];
        let real_limit_ms = limit_ms.unwrap_or(0xFFFFFFFF);
        let started_at = Instant::now();
        loop {
            SubstratumNode::update_string(
                &mut self.logfile_stream,
                &mut buf,
                &mut self.logfile_contents,
            );
            if regex.is_match(&self.logfile_contents[..]) {
                break;
            }
            assert_eq!(
                SubstratumNode::millis_since(started_at) < real_limit_ms,
                true,
                "Timeout: waited for more than {}ms",
                real_limit_ms
            );
            thread::sleep(Duration::from_millis(50));
        }
    }

    #[allow(dead_code)]
    pub fn wait_for_exit(&mut self, milliseconds: u64) -> Option<i32> {
        let time_limit = Instant::now() + Duration::from_millis(milliseconds);
        while Instant::now() < time_limit {
            match self.child.try_wait() {
                Err(e) => panic!("{:?}", e),
                Ok(Some(exit_status)) => return exit_status.code(),
                Ok(None) => (),
            }
            thread::sleep(Duration::from_millis(100));
        }
        panic!(
            "Waited fruitlessly for Node termination for {}ms",
            milliseconds
        );
    }

    #[cfg(not(windows))]
    pub fn kill(&mut self) -> Result<process::ExitStatus, io::Error> {
        self.child.kill()?;
        self.child.wait()
    }

    #[cfg(windows)]
    pub fn kill(&mut self) {
        let mut command = process::Command::new("taskkill");
        command.args(&vec!["/IM", "SubstratumNode.exe", "/F"]);
        let _ = command.output().expect("Couldn't kill SubstratumNode.exe");
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

    #[allow(dead_code)]
    fn update_string(stream: &mut dyn Read, mut buf: &mut [u8], stream_string: &mut String) {
        let len = stream.read(&mut buf).unwrap();
        let increment = String::from_utf8(Vec::from(&buf[0..len])).unwrap();
        print!("{}", increment);
        stream_string.push_str(&increment[..])
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
        let mut args = standard_args();
        args.extend(get_extra_args(config));
        command.args(&args);
        command
    }

    fn make_generate_command(config: CommandConfig) -> process::Command {
        Self::remove_database();
        let mut command = command_to_start();
        let mut args = generate_args();
        args.extend(get_extra_args(Some(config)));
        eprintln!("{:?}", args);
        command.args(&args);
        command
    }

    fn make_recover_command(config: CommandConfig) -> process::Command {
        Self::remove_database();
        let mut command = command_to_start();
        let mut args = recover_args();
        args.extend(get_extra_args(Some(config)));
        eprintln!("{:?}", args);
        command.args(&args);
        command
    }
}

#[cfg(windows)]
fn command_to_start() -> process::Command {
    process::Command::new("cmd")
}

#[cfg(windows)]
#[allow(dead_code)]
fn standard_args() -> Vec<String> {
    let args = CommandConfig::new()
        .pair("/c", &node_command())
        .pair("--dns-servers", "8.8.8.8")
        .pair(
            "--data-directory",
            &SubstratumNode::data_dir().to_string_lossy().to_string(),
        )
        .pair("--log-level", "trace");
    args.args
}

#[cfg(windows)]
#[allow(dead_code)]
fn generate_args() -> Vec<String> {
    let args = CommandConfig::new()
        .pair("/c", &node_command())
        .pair(
            "--data-directory",
            &SubstratumNode::data_dir().to_string_lossy().to_string(),
        )
        .opt("--generate-wallet");
    args.args
}

#[cfg(windows)]
#[allow(dead_code)]
fn recover_args() -> Vec<String> {
    let args = CommandConfig::new()
        .pair("/c", &node_command())
        .pair(
            "--data-directory",
            &SubstratumNode::data_dir().to_string_lossy().to_string(),
        )
        .opt("--recover-wallet");
    args.args
}

#[cfg(windows)]
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
    format!("{}\\SubstratumNode.exe", bin_dir)
}

#[cfg(not(windows))]
fn command_to_start() -> process::Command {
    let test_command = env::args().next().unwrap();
    let debug_or_release = test_command
        .split("/")
        .skip_while(|s| s != &"target")
        .skip(1)
        .next()
        .unwrap();
    let bin_dir = &format!("target/{}", debug_or_release);
    let command_to_start = &format!("{}/SubstratumNode", bin_dir);
    process::Command::new(command_to_start)
}

#[cfg(not(windows))]
#[allow(dead_code)]
fn standard_args() -> Vec<String> {
    let args = CommandConfig::new()
        .pair("--dns-servers", "8.8.8.8")
        .pair(
            "--data-directory",
            &SubstratumNode::data_dir().to_string_lossy().to_string(),
        )
        .pair("--log-level", "trace");
    args.args
}

#[cfg(not(windows))]
#[allow(dead_code)]
fn generate_args() -> Vec<String> {
    let args = CommandConfig::new()
        .pair(
            "--data-directory",
            &SubstratumNode::data_dir().to_string_lossy().to_string(),
        )
        .opt("--generate-wallet");
    args.args
}

#[cfg(not(windows))]
#[allow(dead_code)]
fn recover_args() -> Vec<String> {
    let args = CommandConfig::new()
        .pair(
            "--data-directory",
            &SubstratumNode::data_dir().to_string_lossy().to_string(),
        )
        .opt("--recover-wallet");
    args.args
}

fn get_extra_args(config_opt: Option<CommandConfig>) -> Vec<String> {
    config_opt.unwrap_or(CommandConfig::new()).args
}
