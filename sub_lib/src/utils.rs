// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use std::io::ErrorKind;

macro_rules! try_opt {
    ($e:expr) => {
        match $e {
            Some(x) => x,
            None => return None
        }
    }
}

macro_rules! try_flg {
    ($e:expr) => {
        match $e {
            Some(x) => x,
            None => return false
        }
    }
}

static DEAD_STREAM_ERRORS: [ErrorKind; 5] = [
    ErrorKind::BrokenPipe, ErrorKind::ConnectionAborted, ErrorKind::ConnectionReset,
    ErrorKind::ConnectionRefused, ErrorKind::TimedOut
];

pub fn indicates_dead_stream (kind: ErrorKind) -> bool {
    DEAD_STREAM_ERRORS.contains (&kind)
}

// TODO: Take this out when SC-152 is played
pub fn indicates_timeout (kind: ErrorKind) -> bool {
    (kind == ErrorKind::WouldBlock) || (kind == ErrorKind::TimedOut)
}

pub fn index_of<T> (haystack: &[T], needle: &[T]) -> Option<usize> where T: PartialEq {
    if needle.len () == 0 {return None}
    for h in 0..haystack.len () {
        let mut mismatch = false;
        for n in 0..needle.len () {
            let i = h + n;
            if i >= haystack.len () {mismatch = true; break}
            if haystack[h + n] != needle[n] {mismatch = true; break}
        }
        if !mismatch {return Some (h)}
    }
    None
}

pub fn index_of_from<T> (haystack: &Vec<T>, needle: &T, start_at: usize) -> Option<usize> where T: PartialEq {
    let mut index = start_at;
    while index < haystack.len () && (haystack[index] != *needle) {
        index += 1;
    }
    if index >= haystack.len () {None}
        else {Some (index)}
}

pub fn accumulate<F, R> (mut f: F) -> Vec<R> where F: FnMut () -> Option<R> {
    let mut result: Vec<R> = Vec::new ();
    loop {
        match f () {
            Some (r) => result.push (r),
            None => break
        }
    }
    result
}

pub fn make_hex_string(bytes: &[u8]) -> String {
    let strs: Vec<String> = bytes.iter()
        .map(|b| format!("{:02X}", b))
        .collect();
    strs.join("")
}

pub fn make_printable_string(bytes: &[u8]) -> String {
    let strs: Vec<String> = bytes.iter()
        .map(|b| match b {
            nonprintable if b"\n\r\t".contains (nonprintable) => format!("{}", *nonprintable as char),
            nonprintable if *nonprintable < ' ' as u8 => format!("{:02X}", nonprintable),
            _ => format!("{}", *b as char)
        })
        .collect();
    strs.join("")
}

pub fn to_string (data: &Vec<u8>) -> String {
    match String::from_utf8 (data.clone ()) {
        Ok (string) => make_printable_string(string.as_bytes()),
        Err (_) => format! ("{:?}", data)
    }
}

pub fn to_string_s(data: &[u8]) -> String {
    match String::from_utf8 (Vec::from (data)) {
        Ok (string) => make_printable_string(string.as_bytes()),
        Err (_) => format! ("{:?}", data)
    }
}


#[cfg (test)]
mod tests {
    use super::*;

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
    fn index_of_from_fails_to_find_nonexistent_needle_in_haystack () {
        let haystack = vec! (true, true, true, true);

        let result = index_of_from (&haystack, &false, 0);

        assert_eq! (result, None);
    }

    #[test]
    fn index_of_from_fails_to_find_needle_in_empty_haystack () {
        let haystack: Vec<i32> = vec! ();

        let result = index_of_from (&haystack, &-42, 0);

        assert_eq! (result, None);
    }

    #[test]
    fn index_of_from_finds_needle_at_beginning_of_search () {
        let haystack = vec! (8, 7, 8, 3);

        let result = index_of_from (&haystack, &8, 2);

        assert_eq! (result, Some (2));
    }

    #[test]
    fn index_of_from_finds_needle_at_end_of_haystack () {
        let haystack = vec! (8, 7, 8, 3);

        let result = index_of_from (&haystack, &3, 0);

        assert_eq! (result, Some (3));
    }

    #[test]
    fn accumulate_returns_empty_vec_for_immediate_none () {
        let result: Vec<i32> = accumulate (|| {None});

        assert_eq! (result.len (), 0);
    }

    #[test]
    fn accumulate_can_mutate_environment () {
        let mut values = vec! (3, 2, 1);

        let result = accumulate (|| {values.pop ()});

        assert_eq! (values, vec! ());
        assert_eq! (result, vec! (1, 2, 3));
    }
}