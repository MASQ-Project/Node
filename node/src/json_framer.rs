// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use crate::sub_lib::framer::FramedChunk;
use crate::sub_lib::framer::Framer;

#[derive(Default)]
pub struct JsonFramer {
    possible_start: Option<usize>,
    possible_end: Option<usize>,
    data_so_far: Vec<u8>,
    brace_nest_count: i32,
    in_single_quote_string: bool,
    in_double_quote_string: bool,
    after_backslash: bool,
}

impl Framer for JsonFramer {
    fn add_data(&mut self, data: &[u8]) {
        self.data_so_far.extend(data.iter());
    }

    fn take_frame(&mut self) -> Option<FramedChunk> {
        self.reset();
        for i in 0..self.data_so_far.len() {
            let byte = self.data_so_far[i];
            self.update_state(byte, i);
            if let Some(chunk) = self.check_data_chunk() {
                self.data_so_far = Vec::from(&self.data_so_far[(i + 1)..]);
                return Some(FramedChunk {
                    chunk,
                    last_chunk: true,
                });
            }
        }
        match (self.possible_start, self.possible_end) {
            (None, None) => {
                self.data_so_far.clear();
                None
            }
            (Some(start), None) => {
                self.data_so_far = Vec::from(&self.data_so_far[start..]);
                self.possible_start = Some(0);
                None
            }
            // crashpoint - return none?
            _ => panic!("Internal error framing JSON"),
        }
    }
}

impl JsonFramer {
    pub fn new() -> JsonFramer {
        JsonFramer {
            possible_start: None,
            possible_end: None,
            data_so_far: vec![],
            brace_nest_count: 0,
            in_single_quote_string: false,
            in_double_quote_string: false,
            after_backslash: false,
        }
    }

    fn reset(&mut self) {
        self.possible_start = None;
        self.possible_end = None;
        self.brace_nest_count = 0;
        self.in_single_quote_string = false;
        self.in_double_quote_string = false;
        self.after_backslash = false;
    }

    fn check_data_chunk(&mut self) -> Option<Vec<u8>> {
        match (self.possible_start, self.possible_end) {
            (Some(start), Some(end)) => {
                self.reset();
                Some(Vec::from(&self.data_so_far[start..end]))
            }
            _ => None,
        }
    }

    fn update_state(&mut self, byte: u8, offset: usize) {
        static BS: u8 = b'\\';

        if self.after_backslash {
            self.after_backslash = false;
        } else {
            self.handle_quotes(byte);
            if !self.in_single_quote_string && !self.in_double_quote_string {
                self.handle_braces(byte, offset);
            } else if self.possible_start.is_some() && (byte == BS) {
                self.after_backslash = true
            }
        }
    }

    fn handle_quotes(&mut self, byte: u8) {
        static SQ: u8 = b'\'';
        static DQ: u8 = b'"';

        if self.possible_start.is_none() {
            return;
        }
        match (
            self.in_single_quote_string,
            byte == SQ,
            self.in_double_quote_string,
            byte == DQ,
        ) {
            (false, false, false, true) => self.in_double_quote_string = true,
            (false, false, true, true) => self.in_double_quote_string = false,
            (false, true, false, false) => self.in_single_quote_string = true,
            (true, true, false, false) => self.in_single_quote_string = false,
            (_, _, _, _) => (),
        }
    }

    fn handle_braces(&mut self, byte: u8, offset: usize) {
        static OB: u8 = b'{';
        static CB: u8 = b'}';

        if byte == OB {
            self.brace_nest_count += 1;
            if self.brace_nest_count == 1 {
                self.reset();
                self.brace_nest_count = 1;
                self.possible_start = Some(offset)
            }
        } else if byte == CB {
            self.brace_nest_count -= 1;
            if self.brace_nest_count < 0 {
                self.brace_nest_count = 0;
                self.possible_start = None;
            } else if self.brace_nest_count == 0 && self.possible_start.is_some() {
                self.possible_end = Some(offset + 1);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_framer_handles_backslashed_characters() {
        let mut subject = JsonFramer::new();

        subject.add_data(
            "}garbage}{\"component\": \"NBHD\", \"bodyText\": \"\\\\}\\\"{'\"} more garbage"
                .as_ref(),
        );
        let chunk = subject.take_frame().unwrap();

        assert_eq!(
            String::from_utf8(chunk.chunk).unwrap(),
            "{\"component\": \"NBHD\", \"bodyText\": \"\\\\}\\\"{'\"}"
        );
    }

    #[test]
    fn json_framer_handles_badly_fragmented_input() {
        let mut subject = JsonFramer::new();

        subject.add_data("}garbage}".as_bytes());
        assert_eq!(subject.take_frame(), None);
        subject.add_data("{\"compone".as_bytes());
        assert_eq!(subject.take_frame(), None);
        subject.add_data("nt\": \"PXSV".as_bytes());
        assert_eq!(subject.take_frame(), None);
        subject.add_data("\", \"bodyText\": \"stuff and nonsense".as_bytes());
        assert_eq!(subject.take_frame(), None);
        subject.add_data(
            "\"}{\"component\": \"NBHD\", \"bodyText\": \"glabber\"}{\"component\": \"HOPR\""
                .as_bytes(),
        );
        assert_eq!(
            subject.take_frame().unwrap().chunk,
            Vec::from("{\"component\": \"PXSV\", \"bodyText\": \"stuff and nonsense\"}".as_bytes())
        );
        assert_eq!(
            subject.take_frame().unwrap().chunk,
            Vec::from("{\"component\": \"NBHD\", \"bodyText\": \"glabber\"}".as_bytes())
        );
        assert_eq!(subject.take_frame(), None);
        subject.add_data(", \"bodyText\": \"boing\"}".as_bytes());
        assert_eq!(
            subject.take_frame().unwrap().chunk,
            Vec::from("{\"component\": \"HOPR\", \"bodyText\": \"boing\"}".as_bytes())
        );
        assert_eq!(subject.take_frame(), None);
    }

    #[test]
    fn json_framer_handles_one_and_a_half_packets() {
        let mut subject = JsonFramer::new();

        subject.add_data("{\"component\": \"NBHD\", \"bodyText\": \"blah\"}{\"compo".as_ref());
        let chunk = subject.take_frame().unwrap().chunk;

        assert_eq!(
            String::from_utf8(chunk).unwrap(),
            "{\"component\": \"NBHD\", \"bodyText\": \"blah\"}"
        );
        assert_eq!(subject.data_so_far.len(), "{\"compo".len());
    }

    #[test]
    fn json_framer_picks_two_packets_out_of_trash() {
        let mut subject = JsonFramer::new();

        subject.add_data ("}}#$%^&*({\"component\": \"NBHD\", \"bodyText\": \"blah\"}upi3r\"'jhbgva;oue\\{\"component\": \"HOPR\", \"bodyText\": \"halb\"};owhe".as_ref ());

        let chunk = subject.take_frame().unwrap().chunk;
        assert_eq!(
            String::from_utf8(chunk).unwrap(),
            "{\"component\": \"NBHD\", \"bodyText\": \"blah\"}"
        );
        let chunk = subject.take_frame().unwrap().chunk;
        assert_eq!(
            String::from_utf8(chunk).unwrap(),
            "{\"component\": \"HOPR\", \"bodyText\": \"halb\"}"
        );
        assert_eq!(subject.take_frame(), None);
    }

    #[test]
    fn json_framer_ignores_obvious_non_json() {
        let mut subject = JsonFramer::new();

        subject.add_data("} blikko whomper ][".as_ref());
        let result = subject.take_frame();

        assert_eq!(result, None);
    }
}
