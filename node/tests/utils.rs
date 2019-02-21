// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use regex;
use sub_lib;

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
    logfile_stream: Box<dyn Read>,
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

    pub fn kill(&mut self) {
        self.child.kill().is_ok();
    }

    #[allow(dead_code)]
    fn update_string(stream: &mut dyn Read, mut buf: &mut [u8], stream_string: &mut String) {
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
pub fn read_until_timeout(stream: &mut dyn Read) -> Vec<u8> {
    let mut response: Vec<u8> = vec![];
    let mut buf = [0u8; 16384];
    let mut last_data_at = Instant::now();
    loop {
        match stream.read(&mut buf) {
            Err(ref e)
                if (e.kind() == ErrorKind::WouldBlock) || (e.kind() == ErrorKind::TimedOut) =>
            {
                thread::sleep(Duration::from_millis(100));
            }
            Err(ref e) if (e.kind() == ErrorKind::ConnectionReset) && (response.len() > 0) => break,
            Err(e) => panic!("Read error: {}", e),
            Ok(len) => {
                response.extend(&buf[..len]);
                last_data_at = Instant::now()
            }
        }
        let now = Instant::now();
        if now.duration_since(last_data_at).subsec_millis() > 500 {
            break;
        }
    }
    response
}

fn get_command_config(config_opt: Option<CommandConfig>) -> CommandConfig {
    config_opt.unwrap_or(CommandConfig::new())
}
