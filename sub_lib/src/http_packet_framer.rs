// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use std::usize;
use std::fmt;
use std::fmt::Debug;
use std::fmt::Formatter;
use regex::Regex;
use logger::Logger;
use utils::index_of;
use utils::index_of_from;
use utils::to_string;
use framer::Framer;

#[derive (Debug, PartialEq)]
pub enum State {
    SeekingRequestStart,
    SeekingBodyStart,
    SeekingBodyEnd
}

#[derive (PartialEq)]
pub struct HttpFramerState {
    pub data_so_far: Vec<u8>,
    pub state: State,
    pub content_length: usize,
    pub lines: Vec<Vec<u8>>,
}

impl Debug for HttpFramerState {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        writeln! (f, "HttpFramerState {{").expect ("Internal error");
        writeln! (f, "  data_so_far: {}", to_string (&self.data_so_far)).expect ("Internal error");
        writeln! (f, "  state: {:?}", self.state).expect ("Internal error");
        writeln! (f, "  content_length: {}", self.content_length).expect ("Internal error");
        writeln! (f, "  lines: [").expect ("Internal error");
        for line in &self.lines {
            writeln! (f, "    {}", to_string (line)).expect ("Internal error");
        }
        writeln! (f, "  ]").expect ("Internal error");
        writeln! (f, "}}").expect ("Internal error");
        Ok (())
    }
}

pub trait HttpPacketStartFinder: Send {
    fn handle_seeking_request_start(&self, framer_state: &mut HttpFramerState);
}

pub struct HttpPacketFramer {
    framer_state: HttpFramerState,
    start_finder: Box<HttpPacketStartFinder>,
    requests: Vec<Vec<u8>>,
    logger: Logger
}

impl Framer for HttpPacketFramer {

    fn add_data(&mut self, data: &[u8]) {
        self.framer_state.data_so_far.extend (data);

        let mut prev_len = usize::MAX;
        while self.framer_state.data_so_far.len () < prev_len {
            prev_len = self.framer_state.data_so_far.len ();
            self.start_finder.handle_seeking_request_start (&mut self.framer_state);
            self.handle_seeking_body_start ();
            self.handle_seeking_body_end ();
        }
    }

    fn take_frame (&mut self) -> Option<Vec<u8>> {
        if self.requests.len () == 0 {return None}
        Some (self.requests.remove (0))
    }
}

impl HttpPacketFramer {
    pub fn new (start_finder: Box<HttpPacketStartFinder>) -> HttpPacketFramer {
        HttpPacketFramer {
            framer_state: HttpFramerState {
                data_so_far: Vec::new(),
                state: State::SeekingRequestStart,
                content_length: 0,
                lines: Vec::new()
            },
            start_finder,
            requests: vec!(),
            logger: Logger::new("HttpRequestFramer")
        }
    }

    fn handle_seeking_body_start (&mut self) {
        while self.framer_state.state == State::SeekingBodyStart {
            match index_of(&self.framer_state.data_so_far[..], "\r\n".as_bytes()) {
                Some(line_end) => {
                    let remainder = self.framer_state.data_so_far.split_off(line_end + 2);
                    let line = self.framer_state.data_so_far.clone();
                    self.framer_state.data_so_far = remainder;
                    self.check_for_content_length(&line);
                    self.check_for_zero_length(&line);
                    self.framer_state.lines.push(line);
                }
                None => break
            }
        }
    }

    fn handle_seeking_body_end (&mut self) {
        if self.framer_state.state == State::SeekingBodyEnd {
            if self.framer_state.data_so_far.len() >= self.framer_state.content_length {
                let remainder = self.framer_state.data_so_far.split_off(self.framer_state.content_length);
                let line = self.framer_state.data_so_far.clone();
                self.framer_state.data_so_far = remainder;
                self.framer_state.lines.push(line);
                self.framer_state.state = State::SeekingRequestStart;
                self.framer_state.content_length = 0;
                let mut request = vec!();
                while self.framer_state.lines.len() > 0 {
                    request.extend(self.framer_state.lines.remove(0))
                }
                self.logger.info (HttpPacketFramer::summarize_request (&request));
                self.requests.push(request);
            }
        }
    }

    fn check_for_content_length (&mut self, line: &Vec<u8>) {
        if !line.starts_with ("Content-Length:".as_bytes ()) {return}
        let string = match String::from_utf8 (line.clone ()) {
            Err (_) => {self.discard_current_request (); return},
            Ok (string) => string
        };
        let regex = Regex::new(r"^Content-Length: *(\d+)").unwrap();
        let captures = match regex.captures (&string[..]) {
            None => {self.discard_current_request (); return},
            Some (captures) => captures
        };
        let length_str = captures.get (1).expect ("Internal error").as_str ();
        self.framer_state.content_length = match length_str.parse::<usize> () {
            Ok (length) => length,
            Err (_) => {self.discard_current_request(); 0}
        }
    }

    fn check_for_zero_length (&mut self, line: &Vec<u8>) {
        if line.len () != 2 {return}
        self.framer_state.state = State::SeekingBodyEnd;
    }

    fn discard_current_request (&mut self) {
        self.framer_state.state = State::SeekingRequestStart;
        self.framer_state.content_length = 0;
        self.framer_state.lines.clear ();
    }

    fn summarize_request (request: &Vec<u8>) -> String {
        let first_space_index = match index_of_from (request, &(' ' as u8), 0) {
            None => return String::from("<bad HTTP syntax: no spaces>"),
            Some(index) => index
        };
        let second_space_index = match index_of_from (request, &(' ' as u8), first_space_index + 1) {
            None => return String::from("<bad HTTP syntax: one space>"),
            Some(index) => index
        };
        match String::from_utf8 (Vec::from (&request[0..second_space_index])) {
            Err (_) => String::from ("<bad HTTP syntax: UTF-8 encoding error>"),
            Ok (summary) => summary
        }
    }
}

#[cfg (test)]
mod framer_tests {
    use super::*;
    use utils::to_string;
    use utils::to_string_s;

    const GOOD_FIRST_LINE: [u8; 15] = *b"GOOD_FIRST_LINE";

    struct TameStartFinder {}

    impl HttpPacketStartFinder for TameStartFinder {
        fn handle_seeking_request_start(&self, framer_state: &mut HttpFramerState) {
            if framer_state.state == State::SeekingRequestStart {
                match index_of (&framer_state.data_so_far[..], &GOOD_FIRST_LINE[..]) {
                    Some (offset) => {
                        framer_state.data_so_far = framer_state.data_so_far.split_off (offset);
                        framer_state.state = State::SeekingBodyStart;
                        framer_state.content_length = 0;
                        framer_state.lines.clear();
                    },
                    None => ()
                }
            }
        }
    }

    #[test]
    fn tame_start_finder_yes_clean () {
        let mut framer_state = HttpFramerState {
            data_so_far: Vec::from (&b"GOOD_FIRST_LINE\r\n"[..]),
            state: State::SeekingRequestStart,
            content_length: 100,
            lines: vec! (vec! (), vec! ()),
        };
        let subject = TameStartFinder {};

        subject.handle_seeking_request_start (&mut framer_state);

        assert_eq! (framer_state, HttpFramerState {
            data_so_far: Vec::from (&b"GOOD_FIRST_LINE\r\n"[..]),
            state: State::SeekingBodyStart,
            content_length: 0,
            lines: vec! (),
        });
    }

    #[test]
    fn tame_start_finder_yes_garbage () {
        let mut framer_state = HttpFramerState {
            data_so_far: Vec::from (&b"garbageGOOD_FIRST_LINE\r\n"[..]),
            state: State::SeekingRequestStart,
            content_length: 100,
            lines: vec! (vec! (), vec! ()),
        };
        let subject = TameStartFinder {};

        subject.handle_seeking_request_start (&mut framer_state);

        assert_eq! (framer_state, HttpFramerState {
            data_so_far: Vec::from (&b"GOOD_FIRST_LINE\r\n"[..]),
            state: State::SeekingBodyStart,
            content_length: 0,
            lines: vec! (),
        });
    }

    #[test]
    fn tame_start_finder_no_state () {
        let mut framer_state = HttpFramerState {
            data_so_far: Vec::from (&b"GOOD_FIRST_LINE\r\n"[..]),
            state: State::SeekingBodyEnd,
            content_length: 100,
            lines: vec! (vec! (), vec! ()),
        };
        let subject = TameStartFinder {};

        subject.handle_seeking_request_start (&mut framer_state);

        assert_eq! (framer_state, HttpFramerState {
            data_so_far: Vec::from (&b"GOOD_FIRST_LINE\r\n"[..]),
            state: State::SeekingBodyEnd,
            content_length: 100,
            lines: vec! (vec! (), vec! ()),
        });
    }

    #[test]
    fn tame_start_finder_no_match () {
        let mut framer_state = HttpFramerState {
            data_so_far: Vec::from (&b"BAD_FIRST_LINE\r\n"[..]),
            state: State::SeekingRequestStart,
            content_length: 100,
            lines: vec! (vec! (), vec! ()),
        };
        let subject = TameStartFinder {};

        subject.handle_seeking_request_start (&mut framer_state);

        assert_eq! (framer_state, HttpFramerState {
            data_so_far: Vec::from (&b"BAD_FIRST_LINE\r\n"[..]),
            state: State::SeekingRequestStart,
            content_length: 100,
            lines: vec! (vec! (), vec! ()),
        });
    }

    #[test]
    fn returns_none_if_no_data_has_been_added() {
        let mut subject = HttpPacketFramer::new(Box::new (TameStartFinder {}));

        let result = subject.take_frame();

        assert_eq!(result, None);
    }

    #[test]
    fn recognizes_packet_with_body() {
        let request =
            "GOOD_FIRST_LINE\r\n\
One-Header: value\r\n\
Content-Length: 26\r\n\
Another-Header: value\r\n\
\r\n\
name=Billy&value=obnoxious".as_bytes();
        let mut data = Vec::from(request);
        data.append(&mut Vec::from("egabrag egabrag".as_bytes()));
        let mut subject = HttpPacketFramer::new(Box::new (TameStartFinder {}));

        subject.add_data(&data[..]);
        let result = subject.take_frame().unwrap();

        assert_eq!(to_string(&result), to_string_s(request))
    }

    #[test]
    fn handles_packet_in_two_pieces_divided_in_middle_of_body_with_garbage() {
        let first_piece = "GOOD_FIRST_LINE\r\nContent-Length: 10\r\n\r\nooga-".as_bytes();
        let second_piece = "booga garbage".as_bytes();
        let mut subject = HttpPacketFramer::new(Box::new (TameStartFinder {}));
        subject.add_data(first_piece);
        subject.add_data(second_piece);

        let result = subject.take_frame().unwrap();

        assert_eq!(to_string(&result), String::from("GOOD_FIRST_LINE\r\nContent-Length: 10\r\n\r\nooga-booga"));
    }

    #[test]
    fn handles_packet_in_two_pieces_divided_in_middle_of_content_length() {
        let first_piece = "GOOD_FIRST_LINE\r\nCont".as_bytes();
        let second_piece = "ent-Length: 10\r\n\r\nooga-booga".as_bytes();
        let mut subject = HttpPacketFramer::new(Box::new (TameStartFinder {}));
        subject.add_data(first_piece);
        subject.add_data(second_piece);

        let result = subject.take_frame().unwrap();
        let should_be_none = subject.take_frame();

        assert_eq!(to_string(&result), String::from("GOOD_FIRST_LINE\r\nContent-Length: 10\r\n\r\nooga-booga"));
        assert_eq!(should_be_none, None);
    }

    #[test]
    fn handles_multiple_packets_with_bodies_in_one_piece() {
        let data =
            "GOOD_FIRST_LINE\r\nContent-Length: 5\r\n\r\nbooga\
GOOD_FIRST_LINE\r\nContent-Length: 5\r\n\r\ngooba".as_bytes();
        let mut subject = HttpPacketFramer::new(Box::new (TameStartFinder {}));
        subject.add_data(data);

        let first_result = subject.take_frame().unwrap();
        let second_result = subject.take_frame().unwrap();

        assert_eq!(to_string(&first_result), String::from("GOOD_FIRST_LINE\r\nContent-Length: 5\r\n\r\nbooga"));
        assert_eq!(to_string(&second_result), String::from("GOOD_FIRST_LINE\r\nContent-Length: 5\r\n\r\ngooba"));
    }

    #[test]
    fn discards_packet_with_non_utf8_content_length_line() {
        let mut data = Vec::from("GOOD_FIRST_LINE\r\nContent-Length: ".as_bytes());
        data.push(0xFE);
        data.push(0xFF);
        data.append(&mut Vec::from("\r\n\r\nbooga\
GOOD_FIRST_LINE\r\nContent-Length: 5\r\n\r\ngooba".as_bytes()));
        let mut subject = HttpPacketFramer::new(Box::new (TameStartFinder {}));
        subject.add_data(&data[..]);

        let result = subject.take_frame().unwrap();

        assert_eq!(to_string(&result), String::from("GOOD_FIRST_LINE\r\nContent-Length: 5\r\n\r\ngooba"));
    }

    #[test]
    fn discards_packet_with_nonnumeric_content_length() {
        let data =
            "GOOD_FIRST_LINE\r\nContent-Length: booga\r\n\r\nbooga\
GOOD_FIRST_LINE\r\nContent-Length: 5\r\n\r\ngooba".as_bytes();
        let mut subject = HttpPacketFramer::new(Box::new (TameStartFinder {}));
        subject.add_data(data);

        let result = subject.take_frame().unwrap();

        assert_eq!(to_string(&result), String::from("GOOD_FIRST_LINE\r\nContent-Length: 5\r\n\r\ngooba"));
    }

    #[test]
    fn discards_packet_with_unparseable_content_length() {
        // Content-Length one more than 2^64
        let data =
            "GOOD_FIRST_LINE\r\nContent-Length: 18446744073709551616\r\n\r\nbooga\
GOOD_FIRST_LINE\r\nContent-Length: 5\r\n\r\ngooba".as_bytes();
        let mut subject = HttpPacketFramer::new(Box::new (TameStartFinder {}));
        subject.add_data(data);

        let result = subject.take_frame().unwrap();

        assert_eq!(to_string(&result), String::from("GOOD_FIRST_LINE\r\nContent-Length: 5\r\n\r\ngooba"));
    }

    #[test]
    fn summarize_request_handles_no_spaces () {
        let request = Vec::from ("therearenospacesinthisbuffer\r\n".as_bytes ());

        let result = HttpPacketFramer::summarize_request (&request);

        assert_eq! (result, String::from ("<bad HTTP syntax: no spaces>"))
    }

    #[test]
    fn summarize_request_handles_single_space () {
        let request = Vec::from("thereisone spaceinthisbuffer\r\n".as_bytes());

        let result = HttpPacketFramer::summarize_request(&request);

        assert_eq!(result, String::from("<bad HTTP syntax: one space>"))
    }

    #[test]
    fn summarize_request_handles_non_utf8 () {
        let request = vec! (1, 2, 3, 32, 192, 193, 32, 4, 5);

        let result = HttpPacketFramer::summarize_request(&request);

        assert_eq!(result, String::from("<bad HTTP syntax: UTF-8 encoding error>"))
    }

    #[test]
    fn summarize_request_handles_good_data () {
        let request = Vec::from ("OPTION http://somewhere.com HTTP/1.1\r\n".as_bytes ());

        let result = HttpPacketFramer::summarize_request(&request);

        assert_eq!(result, String::from("OPTION http://somewhere.com"))
    }
}
