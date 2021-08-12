// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

use crate::sub_lib::logger::Logger;
use clap::App;
use masq_lib::messages::UiCrashRequest;
use masq_lib::multi_config::{MultiConfig, VirtualCommandLine};
use masq_lib::shared_schema::ConfiguratorError;
use std::io::ErrorKind;
use std::time::{SystemTime, UNIX_EPOCH};

static DEAD_STREAM_ERRORS: [ErrorKind; 5] = [
    ErrorKind::BrokenPipe,
    ErrorKind::ConnectionAborted,
    ErrorKind::ConnectionReset,
    ErrorKind::ConnectionRefused,
    ErrorKind::TimedOut,
];

pub static NODE_MAILBOX_CAPACITY: usize = 0; // 0 for unbound

macro_rules! recipient {
    ($addr:expr, $_type:ty) => {
        $addr.clone().recipient::<$_type>()
    };
}

macro_rules! send_bind_message {
    ($subs:expr, $peer_actors:expr) => {
        $subs
            .bind
            .try_send(BindMessage {
                peer_actors: $peer_actors.clone(),
            })
            .expect(&format!("Actor for {:?} is dead", $subs));
    };
}

macro_rules! send_start_message {
    ($subs:expr) => {
        $subs
            .start
            .try_send(StartMessage {})
            .expect(&format!("Actor for {:?} is dead", $subs));
    };
}

pub fn indicates_dead_stream(kind: ErrorKind) -> bool {
    DEAD_STREAM_ERRORS.contains(&kind)
}

pub fn time_t_timestamp() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("bad interval")
        .as_secs() as u32
}

pub fn make_printable_string(bytes: &[u8]) -> String {
    let strs: Vec<String> = bytes
        .iter()
        .map(|b| match b {
            nonprintable if b"\n\r\t".contains(nonprintable) => {
                format!("{}", *nonprintable as char)
            }
            nonprintable if *nonprintable < b' ' => format!("{:02X}", nonprintable),
            _ => format!("{}", *b as char),
        })
        .collect();
    strs.join("")
}

pub fn to_string(data: &[u8]) -> String {
    match String::from_utf8(data.to_owned()) {
        Ok(string) => make_printable_string(string.as_bytes()),
        Err(_) => format!("{:?}", data),
    }
}

pub fn to_string_s(data: &[u8]) -> String {
    match String::from_utf8(Vec::from(data)) {
        Ok(string) => make_printable_string(string.as_bytes()),
        Err(_) => format!("{:?}", data),
    }
}

pub fn plus<T>(mut source: Vec<T>, item: T) -> Vec<T> {
    let mut result = vec![];
    result.append(&mut source);
    result.push(item);
    result
}

pub static NODE_DESCRIPTOR_DELIMITERS: [char; 4] = ['_', '@', ':', ':'];

pub fn node_descriptor_delimiter(chain_id: u8) -> char {
    NODE_DESCRIPTOR_DELIMITERS[chain_id as usize]
}

pub fn make_new_multi_config<'a>(
    schema: &App<'a, 'a>,
    vcls: Vec<Box<dyn VirtualCommandLine>>,
) -> Result<MultiConfig<'a>, ConfiguratorError> {
    MultiConfig::try_new(schema, vcls)
}

pub fn handle_ui_crash_request(
    msg: UiCrashRequest,
    logger: &Logger,
    crashable: bool,
    crash_key: &str,
) {
    if msg.actor != crash_key {
        return;
    }
    if crashable {
        panic!("{}", msg.panic_message);
    } else {
        info!(logger, "Rejected crash attempt: '{}'", msg.panic_message);
    }
}

#[cfg(test)]
pub fn make_new_test_multi_config<'a>(
    schema: &App<'a, 'a>,
    vcls: Vec<Box<dyn VirtualCommandLine>>,
) -> Result<MultiConfig<'a>, ConfiguratorError> {
    make_new_multi_config(schema, vcls)
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::apps::app_node;
    use crate::test_utils::logging::{init_test_logging, TestLogHandler};
    use masq_lib::multi_config::CommandLineVcl;

    #[test]
    fn indicates_dead_stream_identifies_dead_stream_errors() {
        vec![
            ErrorKind::BrokenPipe,
            ErrorKind::ConnectionRefused,
            ErrorKind::ConnectionReset,
            ErrorKind::ConnectionAborted,
            ErrorKind::TimedOut,
        ]
        .iter()
        .for_each(|kind| {
            let result = indicates_dead_stream(*kind);

            assert_eq!(
                result, true,
                "indicates_dead_stream ({:?}) should have been true but was false",
                kind
            )
        });
    }

    #[test]
    fn indicates_dead_stream_identifies_non_dead_stream_errors() {
        vec![
            ErrorKind::NotFound,
            ErrorKind::PermissionDenied,
            ErrorKind::NotConnected,
            ErrorKind::AddrInUse,
            ErrorKind::AddrNotAvailable,
            ErrorKind::AlreadyExists,
            ErrorKind::WouldBlock,
            ErrorKind::InvalidInput,
            ErrorKind::InvalidData,
            ErrorKind::WriteZero,
            ErrorKind::Interrupted,
            ErrorKind::Other,
            ErrorKind::UnexpectedEof,
        ]
        .iter()
        .for_each(|kind| {
            let result = indicates_dead_stream(*kind);

            assert_eq!(
                result, false,
                "indicates_dead_stream ({:?}) should have been false but was true",
                kind
            )
        });
    }

    #[test]
    fn node_mailbox_capacity_is_unbound() {
        assert_eq!(NODE_MAILBOX_CAPACITY, 0)
    }

    #[test]
    fn handle_ui_crash_message_doesnt_crash_if_not_crashable() {
        init_test_logging();
        let logger = Logger::new("Example");
        let msg = UiCrashRequest {
            actor: "CRASHKEY".to_string(),
            panic_message: "Foiled again!".to_string(),
        };

        handle_ui_crash_request(msg, &logger, false, "CRASHKEY");

        TestLogHandler::new()
            .exists_log_containing("INFO: Example: Rejected crash attempt: 'Foiled again!'");
    }

    #[test]
    fn handle_ui_crash_message_doesnt_crash_if_no_actor_match() {
        let logger = Logger::new("Example");
        let msg = UiCrashRequest {
            actor: "CRASHKEY".to_string(),
            panic_message: "Foiled again!".to_string(),
        };

        handle_ui_crash_request(msg, &logger, true, "mismatch");

        // no panic; test passes
    }

    #[test]
    #[should_panic(expected = "Foiled again!")]
    fn handle_ui_crash_message_crashes_if_everythings_just_right() {
        let logger = Logger::new("Example");
        let msg = UiCrashRequest {
            actor: "CRASHKEY".to_string(),
            panic_message: "Foiled again!".to_string(),
        };

        handle_ui_crash_request(msg, &logger, true, "CRASHKEY");
    }

    #[test]
    #[should_panic(expected = "The program's entry check failed to catch this.")]
    fn make_new_multi_config_should_panic_after_trying_to_process_help_request() {
        let app = app_node();
        let vcls: Vec<Box<dyn VirtualCommandLine>> = vec![Box::new(CommandLineVcl::new(vec![
            String::from("program"),
            "--help".to_string(),
        ]))];

        let _ = make_new_multi_config(&app, vcls);
    }

    #[test]
    #[should_panic(expected = "The program's entry check failed to catch this.")]
    fn make_new_multi_config_should_panic_after_trying_to_process_version_request() {
        let app = app_node();
        let vcls: Vec<Box<dyn VirtualCommandLine>> = vec![Box::new(CommandLineVcl::new(vec![
            String::from("program"),
            "--version".to_string(),
        ]))];

        let _ = make_new_multi_config(&app, vcls);
    }
}
