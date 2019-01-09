// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
extern crate regex;
extern crate sub_lib;

use std::env;
use std::fs::File;
use std::io::ErrorKind;
use std::io::Read;
use std::ops::Drop;
use std::process::Child;
use std::process::Command;
use std::thread;
use std::time::Duration;
use std::time::Instant;
use sub_lib::crash_point::CrashPoint;

pub struct SubstratumNode {
    logfile_stream: Box<Read>,
    logfile_contents: String,
    child: Child,
}

pub struct CommandConfig {
    pub crash_point: CrashPoint,
}

impl CommandConfig {
    pub fn new() -> CommandConfig {
        CommandConfig {
            crash_point: CrashPoint::None,
        }
    }
}

impl Drop for SubstratumNode {
    fn drop(&mut self) {
        self.kill();
    }
}

impl SubstratumNode {
    pub fn start(config: Option<CommandConfig>) -> SubstratumNode {
        let mut logfile_path_buf = env::temp_dir();
        logfile_path_buf.push("SubstratumNode.log");
        let logfile_path = logfile_path_buf.into_boxed_path();
        let mut command = SubstratumNode::make_node_command(config);
        let child = command.spawn().unwrap();
        thread::sleep(Duration::from_millis(500)); // needs time to open logfile and sockets
        let stream = File::open(logfile_path.to_str().unwrap()).unwrap();
        SubstratumNode {
            logfile_stream: Box::new(stream),
            logfile_contents: String::new(),
            child,
        }
    }

    #[allow(dead_code)]
    pub fn wait_for(&mut self, pattern: &str, limit_ms: Option<u64>) {
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
    pub fn wait(&mut self) -> Option<i32> {
        match self.child.wait() {
            Err(e) => panic!("{:?}", e),
            Ok(exit_status) => exit_status.code(),
        }
    }

    pub fn kill(&mut self) {
        self.child.kill().is_ok();
    }

    #[allow(dead_code)]
    fn update_string(stream: &mut Read, mut buf: &mut [u8], stream_string: &mut String) {
        let len = stream.read(&mut buf).unwrap();
        let increment = String::from_utf8(Vec::from(&buf[0..len])).unwrap();
        print!("{}", increment);
        stream_string.push_str(&increment[..])
    }

    #[allow(dead_code)]
    fn millis_since(started_at: Instant) -> u64 {
        let interval = Instant::now().duration_since(started_at);
        let second_milliseconds = interval.as_secs() * 1000;
        let nanosecond_milliseconds = (interval.subsec_nanos() as u64) / 1000000;
        second_milliseconds + nanosecond_milliseconds
    }

    #[cfg(windows)]
    fn make_node_command(config: Option<CommandConfig>) -> Command {
        let config = get_command_config(config);
        let crash_point = format!("{}", config.crash_point);
        let test_command = env::args().next().unwrap();
        let debug_or_release = test_command
            .split("\\")
            .skip_while(|s| s != &"target")
            .skip(1)
            .next()
            .unwrap();
        let command_to_start = &format!("target\\{}\\SubstratumNode", debug_or_release);
        let mut command = Command::new("cmd");
        command.args(&[
            "/c",
            command_to_start,
            "--dns_servers",
            "8.8.8.8",
            "--crash_point",
            &crash_point,
            "--log_level",
            "trace",
        ]);
        command
    }

    #[cfg(unix)]
    fn make_node_command(config: Option<CommandConfig>) -> Command {
        let config = get_command_config(config);
        let crash_point = format!("{}", config.crash_point);
        let test_command = env::args().next().unwrap();
        let debug_or_release = test_command
            .split("/")
            .skip_while(|s| s != &"target")
            .skip(1)
            .next()
            .unwrap();
        let command_to_start = format!("target/{}/SubstratumNode", debug_or_release);
        let mut command = Command::new(command_to_start);
        command.args(&[
            "--dns_servers",
            "8.8.8.8",
            "--crash_point",
            &crash_point,
            "--log_level",
            "trace",
        ]);
        command
    }
}

#[allow(dead_code)]
pub fn read_until_timeout(stream: &mut Read) -> Vec<u8> {
    let mut buf = [0u8; 16384];
    let mut begin_opt: Option<Instant> = None;
    let mut offset: usize = 0;
    loop {
        match stream.read(&mut buf[offset..]) {
            Err(e) => {
                if (e.kind() == ErrorKind::WouldBlock) || (e.kind() == ErrorKind::TimedOut) {
                    ()
                } else {
                    panic!("Read error: {}", e);
                }
            }
            Ok(len) => {
                offset += len;
                begin_opt = Some(Instant::now())
            }
        }
        match begin_opt {
            None => (),
            Some(begin) => {
                if Instant::now().duration_since(begin).as_secs() > 1 {
                    break;
                }
            }
        }
    }
    buf[..offset].to_vec()
}

fn get_command_config(config_opt: Option<CommandConfig>) -> CommandConfig {
    if config_opt.is_some() {
        config_opt.unwrap()
    } else {
        CommandConfig::new()
    }
}
