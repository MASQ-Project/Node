// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
extern crate regex;

use std::process::Command;
use std::process::Child;
use std::io::Read;
use std::env;
use std::time::Instant;
use std::fs::File;
use std::ops::Drop;
use std::time::Duration;
use std::thread;

pub struct SubstratumNode {
    logfile_stream: Box<Read>,
    logfile_contents: String,
    child: Child
}

impl Drop for SubstratumNode {
    fn drop(&mut self) {
        self.kill ();
    }
}

impl SubstratumNode {
    pub fn start () -> SubstratumNode {
        let mut logfile_path_buf = env::temp_dir();
        logfile_path_buf.push ("SubstratumNode.log");
        let logfile_path = logfile_path_buf.into_boxed_path ();
        let mut command = SubstratumNode::make_node_command();
        let child = command.spawn ().unwrap ();
        thread::sleep(Duration::from_millis(500)); // needs time to open logfile and sockets
        let stream = File::open (logfile_path.to_str ().unwrap ()).unwrap ();
        SubstratumNode {
            logfile_stream: Box::new (stream),
            logfile_contents: String::new (),
            child
        }
    }

    #[allow (dead_code)]
    pub fn wait_for (&mut self, pattern: &str, limit_ms: Option<u64>) {
        let regex = regex::Regex::new (pattern).unwrap ();
        let mut buf: [u8; 0x1000] = [0; 0x1000];
        let real_limit_ms = limit_ms.unwrap_or (0xFFFFFFFF);
        let started_at = Instant::now ();
        loop {
            SubstratumNode::update_string (&mut self.logfile_stream, &mut buf, &mut self.logfile_contents);
            if regex.is_match (&self.logfile_contents[..]) {break}
            assert_eq! (SubstratumNode::millis_since (started_at) < real_limit_ms, true,
                        "Timeout: waited for more than {}ms", real_limit_ms);
            thread::sleep (Duration::from_millis (50));
        }
    }

    pub fn kill (&mut self) {
        self.child.kill ().is_ok ();
    }

    #[allow (dead_code)]
    fn update_string (stream: &mut Read, mut buf: &mut [u8], stream_string: &mut String) {
        let len = stream.read (&mut buf).unwrap ();
        let increment = String::from_utf8 (Vec::from (&buf[0..len])).unwrap ();
        print! ("{}", increment);
        stream_string.push_str (&increment[..])
    }

    #[allow (dead_code)]
    fn millis_since (started_at: Instant) -> u64 {
        let interval = Instant::now ().duration_since (started_at);
        let second_milliseconds = interval.as_secs () * 1000;
        let nanosecond_milliseconds = (interval.subsec_nanos() as u64) / 1000000;
        second_milliseconds + nanosecond_milliseconds
    }

    #[cfg(windows)]
    fn make_node_command () -> Command {
        let test_command = env::args ().next ().unwrap ();
        let debug_or_release = test_command.split ("\\").skip_while (|s| s != &"target").skip(1).next().unwrap();
        let command_to_start = &format! ("target\\{}\\SubstratumNode", debug_or_release);
        let mut command = Command::new ("cmd");
        command.args (&["/c", "start", command_to_start, "--dns_port", "5454", "--dns_servers", "8.8.8.8"]);
        command
    }

    #[cfg(unix)]
    fn make_node_command () -> Command {
        let test_command = env::args ().next ().unwrap ();
        let debug_or_release = test_command.split ("/").skip_while (|s| s != &"target").skip(1).next().unwrap();
        let command_to_start = format! ("target/{}/SubstratumNode", debug_or_release);
        let mut command = Command::new (command_to_start);
        command.args (&["--dns_port", "5454", "--dns_servers", "8.8.8.8"]);
        command
    }
}
