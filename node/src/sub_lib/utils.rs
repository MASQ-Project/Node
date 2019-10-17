// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr};
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

pub fn localhost() -> IpAddr {
    IpAddr::V4(Ipv4Addr::LOCALHOST)
}

pub fn indicates_dead_stream(kind: ErrorKind) -> bool {
    DEAD_STREAM_ERRORS.contains(&kind)
}

pub fn index_of<T>(haystack: &[T], needles: &[T]) -> Option<usize>
where
    T: PartialEq,
{
    if needles.is_empty() {
        return None;
    }
    for h in 0..haystack.len() {
        let mut mismatch = false;
        for n in 0..needles.len() {
            let i = h + n;
            if i >= haystack.len() {
                mismatch = true;
                break;
            }
            if haystack[i] != needles[n] {
                mismatch = true;
                break;
            }
        }
        if !mismatch {
            return Some(h);
        }
    }
    None
}

pub fn index_of_from<T>(haystack: &Vec<T>, needle: &T, start_at: usize) -> Option<usize>
where
    T: PartialEq,
{
    let mut index = start_at;
    while index < haystack.len() && (haystack[index] != *needle) {
        index += 1;
    }
    if index >= haystack.len() {
        None
    } else {
        Some(index)
    }
}

pub fn time_t_timestamp() -> u32 {
    SystemTime::now().duration_since (UNIX_EPOCH).expect("bad interval").as_secs() as u32
}

pub fn make_printable_string(bytes: &[u8]) -> String {
    let strs: Vec<String> = bytes
        .iter()
        .map(|b| match b {
            nonprintable if b"\n\r\t".contains(nonprintable) => {
                format!("{}", *nonprintable as char)
            }
            nonprintable if *nonprintable < ' ' as u8 => format!("{:02X}", nonprintable),
            _ => format!("{}", *b as char),
        })
        .collect();
    strs.join("")
}

pub fn to_string(data: &Vec<u8>) -> String {
    match String::from_utf8(data.clone()) {
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
    fn index_of_fails_to_find_nonexistent_needle_in_haystack() {
        let result = index_of("haystack".as_bytes(), "needle".as_bytes());

        assert_eq!(result, None);
    }

    #[test]
    fn index_of_finds_needle_at_beginning_of_haystack() {
        let result = index_of("haystack haystack".as_bytes(), "haystack".as_bytes());

        assert_eq!(result, Some(0));
    }

    #[test]
    fn index_of_finds_needle_at_end_of_haystack() {
        let result = index_of("needle haystack".as_bytes(), "haystack".as_bytes());

        assert_eq!(result, Some(7));
    }

    #[test]
    fn index_of_fails_to_find_nonempty_needle_in_empty_haystack() {
        let result = index_of("".as_bytes(), "needle".as_bytes());

        assert_eq!(result, None);
    }

    #[test]
    fn index_of_returns_none_for_empty_needle() {
        let result = index_of("haystack".as_bytes(), "".as_bytes());

        assert_eq!(result, None);
    }

    #[test]
    fn index_of_fails_to_find_needle_that_ends_past_end_of_haystack() {
        let result = index_of("haystack needl".as_bytes(), "needle".as_bytes());

        assert_eq!(result, None);
    }

    #[test]
    fn index_of_from_fails_to_find_nonexistent_needle_in_haystack() {
        let haystack = vec![true, true, true, true];

        let result = index_of_from(&haystack, &false, 0);

        assert_eq!(result, None);
    }

    #[test]
    fn index_of_from_fails_to_find_needle_in_empty_haystack() {
        let haystack: Vec<i32> = vec![];

        let result = index_of_from(&haystack, &-42, 0);

        assert_eq!(result, None);
    }

    #[test]
    fn index_of_from_finds_needle_at_beginning_of_search() {
        let haystack = vec![8, 7, 8, 3];

        let result = index_of_from(&haystack, &8, 2);

        assert_eq!(result, Some(2));
    }

    #[test]
    fn index_of_from_finds_needle_at_end_of_haystack() {
        let haystack = vec![8, 7, 8, 3];

        let result = index_of_from(&haystack, &3, 0);

        assert_eq!(result, Some(3));
    }

    #[test]
    fn node_mailbox_capacity_is_unbound() {
        assert_eq!(NODE_MAILBOX_CAPACITY, 0)
    }
}
