// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

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

#[cfg(test)]
pub mod tests {
    use super::*;

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
}
