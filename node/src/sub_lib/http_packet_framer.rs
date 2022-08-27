// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
use crate::sub_lib::framer::FramedChunk;
use crate::sub_lib::framer::Framer;
use crate::sub_lib::framer_utils;
use crate::sub_lib::utils::to_string;
use masq_lib::logger::Logger;
use masq_lib::utils::index_of;
use masq_lib::utils::index_of_from;
use regex::Regex;
use std::fmt;
use std::fmt::Debug;
use std::fmt::Formatter;
use std::usize;

#[derive(Debug, PartialEq, Eq)]
pub enum PacketProgressState {
    SeekingPacketStart,
    SeekingBodyStart,
    SeekingBodyEnd,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ChunkExistenceState {
    Standard,
    ChunkedResponse,
    Chunk,
}

#[derive(PartialEq, Eq, Debug)]
pub enum ChunkProgressState {
    None,
    SeekingLengthHeader,
    SeekingEndOfChunk,
    SeekingEndOfFinalChunk,
}

#[derive(PartialEq, Eq)]
pub struct HttpFramerState {
    pub data_so_far: Vec<u8>,
    pub packet_progress_state: PacketProgressState,
    pub content_length: usize,
    pub transfer_encoding_chunked: ChunkExistenceState,
    pub chunk_progress_state: ChunkProgressState,
    pub chunk_size: Option<usize>,
    pub lines: Vec<Vec<u8>>,
}

impl Debug for HttpFramerState {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        writeln!(f, "HttpFramerState {{")?;
        writeln!(f, "  data_so_far: {}", to_string(&self.data_so_far))?;
        writeln!(f, "  state: {:?}", self.packet_progress_state)?;
        writeln!(f, "  content_length: {}", self.content_length)?;
        writeln!(
            f,
            "  transfer_encoding_chunked: {:?}",
            self.transfer_encoding_chunked
        )?;
        writeln!(f, "  chunk_progress_state: {:?}", self.chunk_progress_state)?;
        writeln!(f, "  chunk_size: {:?}", self.chunk_size)?;
        writeln!(f, "  lines: [")?;
        for line in &self.lines {
            writeln!(f, "    {}", to_string(line))?;
        }
        writeln!(f, "  ]")?;
        writeln!(f, "}}")
    }
}

pub trait HttpPacketStartFinder: Send {
    fn seek_packet_start(&self, framer_state: &mut HttpFramerState) -> bool;
}

pub struct HttpPacketFramer {
    framer_state: HttpFramerState,
    start_finder: Box<dyn HttpPacketStartFinder>,
    logger: Logger,
}

impl Framer for HttpPacketFramer {
    fn add_data(&mut self, data: &[u8]) {
        self.framer_state.data_so_far.extend(data);
    }

    fn take_frame(&mut self) -> Option<FramedChunk> {
        if self.framer_state.transfer_encoding_chunked == ChunkExistenceState::Chunk {
            self.take_chunk_frame()
        } else {
            self.take_packet_frame()
        }
    }
}

impl HttpPacketFramer {
    pub fn new(start_finder: Box<dyn HttpPacketStartFinder>) -> HttpPacketFramer {
        HttpPacketFramer {
            framer_state: HttpFramerState {
                data_so_far: Vec::new(),
                packet_progress_state: PacketProgressState::SeekingPacketStart,
                content_length: 0,
                transfer_encoding_chunked: ChunkExistenceState::Standard,
                chunk_progress_state: ChunkProgressState::None,
                chunk_size: None,
                lines: Vec::new(),
            },
            start_finder,
            logger: Logger::new("HttpRequestFramer"),
        }
    }

    fn take_packet_frame(&mut self) -> Option<FramedChunk> {
        if self.framer_state.packet_progress_state == PacketProgressState::SeekingPacketStart
            && !self.start_finder.seek_packet_start(&mut self.framer_state)
            || self.framer_state.packet_progress_state == PacketProgressState::SeekingBodyStart
                && !self.seek_body_start()
        {
            return None;
        }
        if self.framer_state.packet_progress_state == PacketProgressState::SeekingBodyEnd {
            self.seek_body_end().map(|request| FramedChunk {
                chunk: request,
                last_chunk: false,
            })
        } else {
            None
        }
    }

    fn seek_body_start(&mut self) -> bool {
        while self.framer_state.packet_progress_state == PacketProgressState::SeekingBodyStart {
            match index_of(&self.framer_state.data_so_far[..], b"\r\n") {
                Some(line_end) => {
                    let remainder = self.framer_state.data_so_far.split_off(line_end + 2);
                    let line = self.framer_state.data_so_far.clone();
                    self.framer_state.data_so_far = remainder;
                    if self.framer_state.content_length == 0 {
                        self.check_for_content_length(&line)
                    }
                    if self.framer_state.transfer_encoding_chunked == ChunkExistenceState::Standard
                    {
                        self.check_for_transfer_encoding(&line)
                    }
                    let result = self.check_for_zero_length(&line);
                    self.framer_state.lines.push(line);
                    if result {
                        return true;
                    }
                }
                None => return false,
            }
        }
        false
    }

    fn seek_body_end(&mut self) -> Option<Vec<u8>> {
        if (self.framer_state.packet_progress_state == PacketProgressState::SeekingBodyEnd)
            && (self.framer_state.data_so_far.len() >= self.framer_state.content_length)
        {
            let remainder = self
                .framer_state
                .data_so_far
                .split_off(self.framer_state.content_length);
            let line = self.framer_state.data_so_far.clone();
            self.framer_state.data_so_far = remainder;
            self.framer_state.lines.push(line);
            self.framer_state.packet_progress_state = PacketProgressState::SeekingPacketStart;
            if self.framer_state.transfer_encoding_chunked == ChunkExistenceState::ChunkedResponse {
                self.framer_state.transfer_encoding_chunked = ChunkExistenceState::Chunk;
                self.framer_state.chunk_progress_state = ChunkProgressState::SeekingLengthHeader;
                self.framer_state.chunk_size = None;
            } else {
                self.framer_state.transfer_encoding_chunked = ChunkExistenceState::Standard;
            }
            self.framer_state.content_length = 0;
            let mut request = vec![];
            while !self.framer_state.lines.is_empty() {
                request.extend(self.framer_state.lines.remove(0))
            }
            info!(self.logger, "{}", summarize_http_packet(&request));
            Some(request)
        } else {
            None
        }
    }

    fn check_for_content_length(&mut self, line: &[u8]) {
        if !line.starts_with(b"Content-Length:") {
            return;
        }
        let string = match String::from_utf8(line.to_owned()) {
            Err(_) => {
                self.discard_current_request();
                return;
            }
            Ok(string) => string,
        };
        let regex = Regex::new(r"^Content-Length: *(\d+)").expect("Could not create regex");
        let captures = match regex.captures(&string[..]) {
            None => {
                self.discard_current_request();
                return;
            }
            Some(captures) => captures,
        };
        let length_str = match captures.get(1) {
            Some(thing) => thing.as_str(),
            None => return,
        };
        self.framer_state.content_length = match length_str.parse::<usize>() {
            Ok(length) => length,
            Err(_) => {
                self.discard_current_request();
                0
            }
        }
    }

    fn check_for_transfer_encoding(&mut self, line: &[u8]) {
        if !line.starts_with(b"Transfer-Encoding:") {
            return;
        }
        let string = match String::from_utf8(line.to_owned()) {
            Err(_) => {
                self.discard_current_request();
                return;
            }
            Ok(string) => string,
        };
        let regex = Regex::new(r"^Transfer-Encoding: *(.+)").expect("Could not create regex");
        let captures = match regex.captures(&string[..]) {
            None => {
                self.discard_current_request();
                return;
            }
            Some(captures) => captures,
        };
        let encodings = match captures.get(1) {
            Some(thing) => thing.as_str(),
            None => return,
        };
        if encodings.contains("chunked") {
            self.framer_state.transfer_encoding_chunked = ChunkExistenceState::ChunkedResponse;
            self.framer_state.chunk_progress_state = ChunkProgressState::SeekingLengthHeader;
            self.framer_state.chunk_size = None;
        }
    }

    fn check_for_zero_length(&mut self, line: &[u8]) -> bool {
        if line.len() != 2 {
            return false;
        }
        self.framer_state.packet_progress_state = PacketProgressState::SeekingBodyEnd;
        true
    }

    fn discard_current_request(&mut self) {
        self.framer_state.packet_progress_state = PacketProgressState::SeekingPacketStart;
        self.framer_state.content_length = 0;
        self.framer_state.lines.clear();
    }

    fn take_chunk_frame(&mut self) -> Option<FramedChunk> {
        match self.framer_state.chunk_progress_state {
            ChunkProgressState::None => {
                panic!("This should have been set only if we were done reading chunks")
            }
            ChunkProgressState::SeekingLengthHeader => {
                self.take_frame_while_seeking_length_header()
            }
            ChunkProgressState::SeekingEndOfChunk => self.take_frame_while_seeking_end_of_chunk(),
            ChunkProgressState::SeekingEndOfFinalChunk => {
                self.take_frame_while_seeking_end_of_final_chunk()
            }
        }
    }

    fn take_frame_while_seeking_length_header(&mut self) -> Option<FramedChunk> {
        match framer_utils::find_chunk_offset_length(&self.framer_state.data_so_far[..]) {
            None => {
                if self.framer_state.data_so_far.len() > BYTES_TO_PRESERVE {
                    let split = self.framer_state.data_so_far.len() - BYTES_TO_PRESERVE;
                    self.framer_state.data_so_far = self.framer_state.data_so_far.split_off(split);
                }
                None
            }
            Some(chunk_offset_length) => {
                self.framer_state.data_so_far = self
                    .framer_state
                    .data_so_far
                    .split_off(chunk_offset_length.offset);
                if (chunk_offset_length.length == 3)
                    && (self.framer_state.data_so_far[chunk_offset_length.offset] == (b'0'))
                {
                    self.framer_state.chunk_progress_state =
                        ChunkProgressState::SeekingEndOfFinalChunk;
                    self.framer_state.chunk_size = None;
                } else {
                    self.framer_state.chunk_progress_state = ChunkProgressState::SeekingEndOfChunk;
                    self.framer_state.chunk_size = Some(chunk_offset_length.length);
                }
                self.take_chunk_frame()
            }
        }
    }

    fn take_frame_while_seeking_end_of_chunk(&mut self) -> Option<FramedChunk> {
        let chunk_size = self
            .framer_state
            .chunk_size
            .expect("If we are seeking the end of the chunk then we should have the chunk size");
        if self.framer_state.data_so_far.len() < (chunk_size + CRLF.len()) {
            return None;
        }
        let remaining_data = self
            .framer_state
            .data_so_far
            .split_off(chunk_size + CRLF.len());
        let mut chunk = self.framer_state.data_so_far.clone();
        self.framer_state.data_so_far = remaining_data;
        if !chunk.ends_with(CRLF) {
            // If the chunk has no CRLF terminator, rescue the last two characters back into data_so_far
            // Should we consider aborting malformed data-stream?
            self.framer_state
                .data_so_far
                .insert(0, chunk[chunk.len() - 1]);
            self.framer_state
                .data_so_far
                .insert(0, chunk[chunk.len() - 2]);
            let result_data_len = chunk.len();
            chunk.truncate(result_data_len - 2);
        }
        self.framer_state.chunk_progress_state = ChunkProgressState::SeekingLengthHeader;
        self.framer_state.chunk_size = None;
        Some(FramedChunk {
            chunk,
            last_chunk: false,
        })
    }

    fn take_frame_while_seeking_end_of_final_chunk(&mut self) -> Option<FramedChunk> {
        match index_of(&self.framer_state.data_so_far[..], DOUBLE_CRLF) {
            Some(offset) => {
                let temp = self
                    .framer_state
                    .data_so_far
                    .split_off(offset + DOUBLE_CRLF.len());
                let result_data = self.framer_state.data_so_far.clone();
                self.framer_state.data_so_far = temp;
                self.framer_state.transfer_encoding_chunked = ChunkExistenceState::Standard;
                self.framer_state.chunk_progress_state = ChunkProgressState::None;
                self.framer_state.chunk_size = None;
                Some(FramedChunk {
                    chunk: result_data,
                    last_chunk: false,
                })
            }
            None => None,
        }
    }
}

const BYTES_TO_PRESERVE: usize = 9;
const CRLF: &[u8; 2] = b"\r\n";
const DOUBLE_CRLF: &[u8; 4] = b"\r\n\r\n";

pub fn summarize_http_packet(request: &[u8]) -> String {
    let first_space_index = match index_of_from(request, &(b' '), 0) {
        None => return String::from("<bad HTTP syntax: no spaces>"),
        Some(index) => index,
    };
    let second_space_index = match index_of_from(request, &(b' '), first_space_index + 1) {
        None => return String::from("<bad HTTP syntax: one space>"),
        Some(index) => index,
    };
    match String::from_utf8(Vec::from(&request[0..second_space_index])) {
        Err(_) => String::from("<bad HTTP syntax: UTF-8 encoding error>"),
        Ok(summary) => summary,
    }
}

#[cfg(test)]
mod framer_tests {
    use super::*;
    use crate::sub_lib::http_response_start_finder::HttpResponseStartFinder;
    use crate::sub_lib::utils::to_string;
    use crate::sub_lib::utils::to_string_s;

    #[test]
    fn constants_have_correct_values() {
        assert_eq!(BYTES_TO_PRESERVE, 9);
        assert_eq!(CRLF, b"\r\n");
        assert_eq!(DOUBLE_CRLF, b"\r\n\r\n");
    }

    const GOOD_FIRST_LINE: [u8; 15] = *b"GOOD_FIRST_LINE";

    struct TameStartFinder {}

    impl HttpPacketStartFinder for TameStartFinder {
        fn seek_packet_start(&self, framer_state: &mut HttpFramerState) -> bool {
            if framer_state.packet_progress_state == PacketProgressState::SeekingPacketStart {
                match index_of(&framer_state.data_so_far[..], &GOOD_FIRST_LINE[..]) {
                    Some(offset) => {
                        framer_state.data_so_far = framer_state.data_so_far.split_off(offset);
                        framer_state.packet_progress_state = PacketProgressState::SeekingBodyStart;
                        framer_state.content_length = 0;
                        framer_state.transfer_encoding_chunked = ChunkExistenceState::Standard;
                        framer_state.chunk_progress_state = ChunkProgressState::None;
                        framer_state.chunk_size = None;
                        framer_state.lines.clear();
                        true
                    }
                    None => false,
                }
            } else {
                false
            }
        }
    }

    #[test]
    fn tame_start_finder_yes_clean() {
        let mut framer_state = HttpFramerState {
            data_so_far: Vec::from(&b"GOOD_FIRST_LINE\r\n"[..]),
            packet_progress_state: PacketProgressState::SeekingPacketStart,
            content_length: 100,
            transfer_encoding_chunked: ChunkExistenceState::ChunkedResponse,
            chunk_progress_state: ChunkProgressState::SeekingEndOfFinalChunk,
            chunk_size: Some(200),
            lines: vec![vec![], vec![]],
        };
        let subject = TameStartFinder {};

        let result = subject.seek_packet_start(&mut framer_state);

        assert_eq!(result, true);
        assert_eq!(
            framer_state,
            HttpFramerState {
                data_so_far: Vec::from(&b"GOOD_FIRST_LINE\r\n"[..]),
                packet_progress_state: PacketProgressState::SeekingBodyStart,
                content_length: 0,
                transfer_encoding_chunked: ChunkExistenceState::Standard,
                chunk_progress_state: ChunkProgressState::None,
                chunk_size: None,
                lines: vec![],
            }
        );
    }

    #[test]
    fn tame_start_finder_yes_garbage() {
        let mut framer_state = HttpFramerState {
            data_so_far: Vec::from(&b"garbageGOOD_FIRST_LINE\r\n"[..]),
            packet_progress_state: PacketProgressState::SeekingPacketStart,
            content_length: 100,
            transfer_encoding_chunked: ChunkExistenceState::ChunkedResponse,
            chunk_progress_state: ChunkProgressState::SeekingEndOfFinalChunk,
            chunk_size: Some(200),
            lines: vec![vec![], vec![]],
        };
        let subject = TameStartFinder {};

        let result = subject.seek_packet_start(&mut framer_state);

        assert_eq!(result, true);
        assert_eq!(
            framer_state,
            HttpFramerState {
                data_so_far: Vec::from(&b"GOOD_FIRST_LINE\r\n"[..]),
                packet_progress_state: PacketProgressState::SeekingBodyStart,
                content_length: 0,
                transfer_encoding_chunked: ChunkExistenceState::Standard,
                chunk_progress_state: ChunkProgressState::None,
                chunk_size: None,
                lines: vec![],
            }
        );
    }

    #[test]
    fn tame_start_finder_no_state() {
        let mut framer_state = HttpFramerState {
            data_so_far: Vec::from(&b"GOOD_FIRST_LINE\r\n"[..]),
            packet_progress_state: PacketProgressState::SeekingBodyEnd,
            content_length: 100,
            transfer_encoding_chunked: ChunkExistenceState::ChunkedResponse,
            chunk_progress_state: ChunkProgressState::SeekingEndOfFinalChunk,
            chunk_size: Some(200),
            lines: vec![vec![], vec![]],
        };
        let subject = TameStartFinder {};

        let result = subject.seek_packet_start(&mut framer_state);

        assert_eq!(result, false);
        assert_eq!(
            framer_state,
            HttpFramerState {
                data_so_far: Vec::from(&b"GOOD_FIRST_LINE\r\n"[..]),
                packet_progress_state: PacketProgressState::SeekingBodyEnd,
                content_length: 100,
                transfer_encoding_chunked: ChunkExistenceState::ChunkedResponse,
                chunk_progress_state: ChunkProgressState::SeekingEndOfFinalChunk,
                chunk_size: Some(200),
                lines: vec![vec![], vec![]],
            }
        );
    }

    #[test]
    fn tame_start_finder_no_match() {
        let mut framer_state = HttpFramerState {
            data_so_far: Vec::from(&b"BAD_FIRST_LINE\r\n"[..]),
            packet_progress_state: PacketProgressState::SeekingPacketStart,
            content_length: 100,
            transfer_encoding_chunked: ChunkExistenceState::ChunkedResponse,
            chunk_progress_state: ChunkProgressState::SeekingEndOfFinalChunk,
            chunk_size: Some(200),
            lines: vec![vec![], vec![]],
        };
        let subject = TameStartFinder {};

        let result = subject.seek_packet_start(&mut framer_state);

        assert_eq!(result, false);
        assert_eq!(
            framer_state,
            HttpFramerState {
                data_so_far: Vec::from(&b"BAD_FIRST_LINE\r\n"[..]),
                packet_progress_state: PacketProgressState::SeekingPacketStart,
                content_length: 100,
                transfer_encoding_chunked: ChunkExistenceState::ChunkedResponse,
                chunk_progress_state: ChunkProgressState::SeekingEndOfFinalChunk,
                chunk_size: Some(200),
                lines: vec![vec![], vec![]],
            }
        );
    }

    #[test]
    fn returns_none_if_no_data_has_been_added() {
        let mut subject = HttpPacketFramer::new(Box::new(TameStartFinder {}));

        let result = subject.take_frame();

        assert_eq!(result, None);
    }

    #[test]
    fn recognizes_packet_with_body() {
        let request = "GOOD_FIRST_LINE\r\n\
                       One-Header: value\r\n\
                       Content-Length: 26\r\n\
                       Another-Header: value\r\n\
                       \r\n\
                       name=Billy&value=obnoxious"
            .as_bytes();
        let mut data = Vec::from(request);
        data.append(&mut Vec::from("egabrag egabrag".as_bytes()));
        let mut subject = HttpPacketFramer::new(Box::new(TameStartFinder {}));

        subject.add_data(&data[..]);
        let result = subject.take_frame().unwrap();

        assert_eq!(to_string(&result.chunk), to_string_s(request));
        assert_eq!(result.last_chunk, false)
    }

    #[test]
    fn handles_packet_in_two_pieces_divided_in_middle_of_body_with_garbage() {
        let first_piece = "GOOD_FIRST_LINE\r\nContent-Length: 10\r\n\r\nooga-".as_bytes();
        let second_piece = "booga garbage".as_bytes();
        let mut subject = HttpPacketFramer::new(Box::new(TameStartFinder {}));
        subject.add_data(first_piece);
        subject.add_data(second_piece);

        let result = subject.take_frame().unwrap();

        assert_eq!(
            to_string(&result.chunk),
            String::from("GOOD_FIRST_LINE\r\nContent-Length: 10\r\n\r\nooga-booga")
        );
        assert_eq!(result.last_chunk, false)
    }

    #[test]
    fn handles_packet_in_two_pieces_divided_in_middle_of_content_length() {
        let first_piece = "GOOD_FIRST_LINE\r\nCont".as_bytes();
        let second_piece = "ent-Length: 10\r\n\r\nooga-booga".as_bytes();
        let mut subject = HttpPacketFramer::new(Box::new(TameStartFinder {}));
        subject.add_data(first_piece);
        subject.add_data(second_piece);

        let result = subject.take_frame().unwrap();
        let should_be_none = subject.take_frame();

        assert_eq!(
            to_string(&result.chunk),
            String::from("GOOD_FIRST_LINE\r\nContent-Length: 10\r\n\r\nooga-booga")
        );
        assert_eq!(result.last_chunk, false);
        assert_eq!(should_be_none, None);
    }

    #[test]
    fn handles_multiple_packets_with_bodies_in_one_piece() {
        let data = "GOOD_FIRST_LINE\r\nContent-Length: 5\r\n\r\nbooga\
                    GOOD_FIRST_LINE\r\nContent-Length: 5\r\n\r\ngooba"
            .as_bytes();
        let mut subject = HttpPacketFramer::new(Box::new(TameStartFinder {}));
        subject.add_data(data);

        let first_result = subject.take_frame().unwrap();
        let second_result = subject.take_frame().unwrap();

        assert_eq!(
            to_string(&first_result.chunk),
            String::from("GOOD_FIRST_LINE\r\nContent-Length: 5\r\n\r\nbooga")
        );
        assert_eq!(first_result.last_chunk, false);
        assert_eq!(
            to_string(&second_result.chunk),
            String::from("GOOD_FIRST_LINE\r\nContent-Length: 5\r\n\r\ngooba")
        );
        assert_eq!(second_result.last_chunk, false)
    }

    #[test]
    fn discards_packet_with_non_utf8_content_length_line() {
        let mut data = Vec::from("GOOD_FIRST_LINE\r\nContent-Length: ".as_bytes());
        data.push(0xFE);
        data.push(0xFF);
        data.append(&mut Vec::from(
            "\r\n\r\nbooga\
             GOOD_FIRST_LINE\r\nContent-Length: 5\r\n\r\ngooba"
                .as_bytes(),
        ));
        let mut subject = HttpPacketFramer::new(Box::new(TameStartFinder {}));
        subject.add_data(&data[..]);

        let result = subject.take_frame();

        assert_eq!(result, None);
        assert_eq!(
            to_string(&subject.framer_state.data_so_far),
            "\r\nboogaGOOD_FIRST_LINE\r\nContent-Length: 5\r\n\r\ngooba"
        );
    }

    #[test]
    fn discards_packet_with_non_utf8_transfer_encoding_line() {
        let mut data = Vec::from("GOOD_FIRST_LINE\r\nTransfer-Encoding: ".as_bytes());
        data.push(0xFE);
        data.push(0xFF);
        data.append(&mut Vec::from(
            "\r\n\r\nbooga\
             GOOD_FIRST_LINE\r\nContent-Length: 5\r\n\r\ngooba"
                .as_bytes(),
        ));
        let mut subject = HttpPacketFramer::new(Box::new(TameStartFinder {}));
        subject.add_data(&data[..]);

        let result = subject.take_frame();

        assert_eq!(result, None);
        assert_eq!(
            to_string(&subject.framer_state.data_so_far),
            "\r\nboogaGOOD_FIRST_LINE\r\nContent-Length: 5\r\n\r\ngooba"
        );
    }

    #[test]
    fn discards_packet_with_nonnumeric_content_length() {
        let data = "GOOD_FIRST_LINE\r\nContent-Length: booga\r\n\r\nbooga\
                    GOOD_FIRST_LINE\r\nContent-Length: 5\r\n\r\ngooba"
            .as_bytes();
        let mut subject = HttpPacketFramer::new(Box::new(TameStartFinder {}));
        subject.add_data(data);

        let result = subject.take_frame();

        assert_eq!(result, None);
        assert_eq!(
            to_string(&subject.framer_state.data_so_far),
            "\r\nboogaGOOD_FIRST_LINE\r\nContent-Length: 5\r\n\r\ngooba"
        );
    }

    #[test]
    fn discards_packet_with_unparseable_content_length() {
        // Content-Length one more than 2^64
        let data = "GOOD_FIRST_LINE\r\nContent-Length: 18446744073709551616\r\n\r\nbooga\
                    GOOD_FIRST_LINE\r\nContent-Length: 5\r\n\r\ngooba"
            .as_bytes();
        let mut subject = HttpPacketFramer::new(Box::new(TameStartFinder {}));
        subject.add_data(data);

        let result = subject.take_frame();

        assert_eq!(result, None);
        assert_eq!(
            to_string(&subject.framer_state.data_so_far),
            "\r\nboogaGOOD_FIRST_LINE\r\nContent-Length: 5\r\n\r\ngooba"
        );
    }

    #[test]
    fn transfer_encoding_is_standard_if_not_mentioned() {
        let data = "GOOD_FIRST_LINE\r\nOoga: Booga\r\n\r\n".as_bytes();
        let mut subject = HttpPacketFramer::new(Box::new(TameStartFinder {}));
        subject.add_data(data);

        subject.take_frame().unwrap();

        assert_eq!(
            subject.framer_state.transfer_encoding_chunked,
            ChunkExistenceState::Standard
        );
    }

    #[test]
    fn transfer_encoding_is_standard_if_header_is_present_but_does_not_mention_chunked() {
        let data = "GOOD_FIRST_LINE\r\nTransfer-Encoding: goober, whomp, miffle\r\n\r\n".as_bytes();
        let mut subject = HttpPacketFramer::new(Box::new(TameStartFinder {}));
        subject.add_data(data);

        subject.take_frame().unwrap();

        assert_eq!(
            subject.framer_state.transfer_encoding_chunked,
            ChunkExistenceState::Standard
        );
    }

    #[test]
    fn transfer_encoding_is_chunked_if_header_is_present_and_mentions_chunked_alone() {
        let data = "GOOD_FIRST_LINE\r\nTransfer-Encoding: goober, chunked, whomp\r\n".as_bytes();
        let mut subject = HttpPacketFramer::new(Box::new(TameStartFinder {}));
        subject.add_data(data);

        let result = subject.take_frame();

        assert_eq!(result, None);
        assert_eq!(
            subject.framer_state.transfer_encoding_chunked,
            ChunkExistenceState::ChunkedResponse
        );
    }

    #[test]
    fn transfer_encoding_is_chunked_if_header_is_present_and_mentions_chunked_among_others() {
        let data =
            "GOOD_FIRST_LINE\r\nTransfer-Encoding: goober, chunked, whomp\r\n\r\n".as_bytes();
        let mut subject = HttpPacketFramer::new(Box::new(TameStartFinder {}));
        subject.add_data(data);

        subject.take_frame().unwrap();

        assert_eq!(
            subject.framer_state.transfer_encoding_chunked,
            ChunkExistenceState::Chunk
        );
    }

    #[test]
    fn transfer_encoding_does_not_need_spaces_after_commas() {
        let data = "GOOD_FIRST_LINE\r\nTransfer-Encoding: goober,chunked,whomp\r\n\r\n".as_bytes();
        let mut subject = HttpPacketFramer::new(Box::new(TameStartFinder {}));
        subject.add_data(data);

        subject.take_frame().unwrap();

        assert_eq!(
            subject.framer_state.transfer_encoding_chunked,
            ChunkExistenceState::Chunk
        );
    }

    #[test]
    fn transfer_encoding_is_detected_even_if_split_by_buffers() {
        let data1 = "GOOD_FIRST_LINE\r\nTransfer-Encoding: goober,chun".as_bytes();
        let data2 = "ked,whomp\r\n\r\n".as_bytes();
        let mut subject = HttpPacketFramer::new(Box::new(TameStartFinder {}));
        subject.add_data(data1);
        subject.add_data(data2);

        subject.take_frame().unwrap();

        assert_eq!(
            subject.framer_state.transfer_encoding_chunked,
            ChunkExistenceState::Chunk
        );
    }

    #[test]
    fn transfer_encoding_response_followed_by_non_chunked_response() {
        let data = "GOOD_FIRST_LINE\r\nTransfer-Encoding: chunked\r\n\r\nB\r\nFirst chunk\r\nC\r\nSecond chunk\r\n0\r\n\r\nGOOD_FIRST_LINE\r\n\r\n".as_bytes();
        let mut subject = HttpPacketFramer::new(Box::new(TameStartFinder {}));
        subject.add_data(data);

        let first_response = subject.take_frame().unwrap();
        let first_chunk = subject.take_frame().unwrap();
        let second_chunk = subject.take_frame().unwrap();
        let final_chunk = subject.take_frame().unwrap();
        let second_response = subject.take_frame().unwrap();
        let none = subject.take_frame();

        assert_eq!(
            first_response,
            FramedChunk {
                chunk: Vec::from(
                    "GOOD_FIRST_LINE\r\nTransfer-Encoding: chunked\r\n\r\n".as_bytes()
                ),
                last_chunk: false,
            }
        );
        assert_eq!(
            first_chunk,
            FramedChunk {
                chunk: Vec::from("B\r\nFirst chunk\r\n".as_bytes()),
                last_chunk: false,
            }
        );
        assert_eq!(
            second_chunk,
            FramedChunk {
                chunk: Vec::from("C\r\nSecond chunk\r\n".as_bytes()),
                last_chunk: false,
            }
        );
        assert_eq!(
            final_chunk,
            FramedChunk {
                chunk: Vec::from("0\r\n\r\n".as_bytes()),
                last_chunk: false,
            }
        );
        assert_eq!(
            second_response,
            FramedChunk {
                chunk: Vec::from("GOOD_FIRST_LINE\r\n\r\n".as_bytes()),
                last_chunk: false,
            }
        );
        assert_eq!(none, None);
    }

    #[test]
    fn summarize_http_packethandles_no_spaces() {
        let request = Vec::from("therearenospacesinthisbuffer\r\n".as_bytes());

        let result = summarize_http_packet(&request);

        assert_eq!(result, String::from("<bad HTTP syntax: no spaces>"))
    }

    #[test]
    fn summarize_http_packethandles_single_space() {
        let request = Vec::from("thereisone spaceinthisbuffer\r\n".as_bytes());

        let result = summarize_http_packet(&request);

        assert_eq!(result, String::from("<bad HTTP syntax: one space>"))
    }

    #[test]
    fn summarize_http_packethandles_non_utf8() {
        let request = vec![1, 2, 3, 32, 192, 193, 32, 4, 5];

        let result = summarize_http_packet(&request);

        assert_eq!(
            result,
            String::from("<bad HTTP syntax: UTF-8 encoding error>")
        )
    }

    #[test]
    fn summarize_http_packethandles_good_request() {
        let request = Vec::from("OPTION http://somewhere.com HTTP/1.1\r\n".as_bytes());

        let result = summarize_http_packet(&request);

        assert_eq!(result, String::from("OPTION http://somewhere.com"))
    }

    #[test]
    fn summarize_http_packethandles_good_response() {
        let request = Vec::from("HTTP/1.1 200 OK\r\n".as_bytes());

        let result = summarize_http_packet(&request);

        assert_eq!(result, String::from("HTTP/1.1 200"))
    }

    #[test]
    fn ignores_garbage_except_for_last_nine_chars() {
        let data = &b"these are the times that try men's souls"[..];
        let mut subject = HttpPacketFramer::new(Box::new(TameStartFinder {}));
        subject.framer_state.transfer_encoding_chunked = ChunkExistenceState::Chunk;
        subject.framer_state.chunk_progress_state = ChunkProgressState::SeekingLengthHeader;
        subject.add_data(data);

        let result = subject.take_frame();

        assert_eq!(result, None);
        assert_eq!(
            subject.framer_state.data_so_far,
            Vec::from(&b"n's souls"[..])
        );
        assert_eq!(
            subject.framer_state.chunk_progress_state,
            ChunkProgressState::SeekingLengthHeader
        );
        assert_eq!(subject.framer_state.chunk_size, None);
    }

    #[test]
    fn ignores_hexadecimal_data_except_for_last_nine_chars() {
        let data = &b"0123456789ABCDEFEDCBA98765432\r"[..];
        let mut subject = HttpPacketFramer::new(Box::new(TameStartFinder {}));
        subject.framer_state.transfer_encoding_chunked = ChunkExistenceState::Chunk;
        subject.framer_state.chunk_progress_state = ChunkProgressState::SeekingLengthHeader;
        subject.add_data(data);

        let result = subject.take_frame();

        assert_eq!(result, None);
        assert_eq!(
            subject.framer_state.data_so_far,
            Vec::from(&b"98765432\r"[..])
        );
        assert_eq!(
            subject.framer_state.chunk_progress_state,
            ChunkProgressState::SeekingLengthHeader
        );
        assert_eq!(subject.framer_state.chunk_size, None);
    }

    #[test]
    fn senses_beginning_properly() {
        let data = &b"garbageFEDCBA98765432\r\nbeginning of content"[..];
        let mut subject = HttpPacketFramer::new(Box::new(TameStartFinder {}));
        subject.framer_state.transfer_encoding_chunked = ChunkExistenceState::Chunk;
        subject.framer_state.chunk_progress_state = ChunkProgressState::SeekingLengthHeader;
        subject.add_data(data);

        let result = subject.take_frame();

        assert_eq!(result, None);
        assert_eq!(
            subject.framer_state.data_so_far,
            Vec::from(&b"98765432\r\nbeginning of content"[..])
        );
        assert_eq!(
            subject.framer_state.chunk_progress_state,
            ChunkProgressState::SeekingEndOfChunk
        );
        assert_eq!(subject.framer_state.chunk_size, Some(0x98765432 + 10));
    }

    #[test]
    fn frames_single_chunk() {
        let data = &b"13\r\nnineteen characters\r\n11\r\nanother"[..];
        let mut subject = HttpPacketFramer::new(Box::new(TameStartFinder {}));
        subject.framer_state.transfer_encoding_chunked = ChunkExistenceState::Chunk;
        subject.framer_state.chunk_progress_state = ChunkProgressState::SeekingLengthHeader;
        subject.add_data(data);

        let result = subject.take_frame();

        assert_eq!(
            result,
            Some(FramedChunk {
                chunk: Vec::from(&b"13\r\nnineteen characters\r\n"[..]),
                last_chunk: false,
            })
        );
        assert_eq!(
            subject.framer_state.data_so_far,
            Vec::from(&b"11\r\nanother"[..])
        );
        assert_eq!(
            subject.framer_state.chunk_progress_state,
            ChunkProgressState::SeekingLengthHeader
        );
        assert_eq!(subject.framer_state.chunk_size, None);
    }

    #[test]
    fn frames_multiple_chunks_even_unterminated_ones() {
        let data1 = &b"13\r\nnineteen characters\r\ntrash trash16\r"[..];
        let data2 = &b"\nanother few characterstrash1"[..];
        let data3 = &b"2\r\nand one"[..];
        let mut subject = HttpPacketFramer::new(Box::new(TameStartFinder {}));
        subject.framer_state.transfer_encoding_chunked = ChunkExistenceState::Chunk;
        subject.framer_state.chunk_progress_state = ChunkProgressState::SeekingLengthHeader;
        subject.add_data(data1);
        subject.add_data(data2);
        subject.add_data(data3);

        let result1 = subject.take_frame();
        let result2 = subject.take_frame();
        let result3 = subject.take_frame();

        assert_eq!(
            result1,
            Some(FramedChunk {
                chunk: Vec::from(&b"13\r\nnineteen characters\r\n"[..]),
                last_chunk: false,
            })
        );
        // unterminated; will cause error in browser, but that's appropriate
        assert_eq!(
            result2,
            Some(FramedChunk {
                chunk: Vec::from(&b"16\r\nanother few characters"[..]),
                last_chunk: false,
            })
        );
        assert_eq!(result3, None);
        assert_eq!(
            subject.framer_state.data_so_far,
            Vec::from(&b"12\r\nand one"[..])
        );
        assert_eq!(
            subject.framer_state.chunk_progress_state,
            ChunkProgressState::SeekingEndOfChunk
        );
        assert_eq!(subject.framer_state.chunk_size, Some(0x12 + 4));
    }

    #[test]
    fn frames_final_chunk_without_header() {
        let data = &b"0\r\n\r\ngarbage"[..];
        let mut subject = HttpPacketFramer::new(Box::new(TameStartFinder {}));
        subject.framer_state.transfer_encoding_chunked = ChunkExistenceState::Chunk;
        subject.framer_state.chunk_progress_state = ChunkProgressState::SeekingLengthHeader;
        subject.add_data(data);

        let result = subject.take_frame();

        assert_eq!(
            result,
            Some(FramedChunk {
                chunk: Vec::from(&b"0\r\n\r\n"[..]),
                last_chunk: false,
            })
        );
        assert_eq!(subject.framer_state.data_so_far, Vec::from(&b"garbage"[..]));
        assert_eq!(
            subject.framer_state.chunk_progress_state,
            ChunkProgressState::None
        );
        assert_eq!(subject.framer_state.chunk_size, None);
    }

    #[test]
    fn frames_final_chunk_with_header() {
        let data1 = &b"13\r\nnineteen characters0\r\nHeader: "[..];
        let data2 = &b"value\r\n\r\n"[..];
        let mut subject = HttpPacketFramer::new(Box::new(TameStartFinder {}));
        subject.framer_state.transfer_encoding_chunked = ChunkExistenceState::Chunk;
        subject.framer_state.chunk_progress_state = ChunkProgressState::SeekingLengthHeader;
        subject.add_data(data1);
        assert_eq!(subject.take_frame().is_some(), true);
        assert_eq!(subject.take_frame().is_none(), true);
        subject.add_data(data2);

        let result = subject.take_frame();

        assert_eq!(
            result,
            Some(FramedChunk {
                chunk: Vec::from(&b"0\r\nHeader: value\r\n\r\n"[..]),
                last_chunk: false,
            })
        );
        assert_eq!(subject.framer_state.data_so_far, Vec::from(&b""[..]));
        assert_eq!(
            subject.framer_state.chunk_progress_state,
            ChunkProgressState::None
        );
        assert_eq!(subject.framer_state.chunk_size, None);
    }

    #[test]
    fn version_of_troublesome_proxy_client_test() {
        let data = &b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 29\r\n\r\nUser-agent: *\nDisallow: /deny";
        let mut subject = HttpPacketFramer::new(Box::new(HttpResponseStartFinder {}));
        subject.add_data(&data[0..40]);
        assert_eq!(subject.take_frame().is_none(), true);
        subject.add_data(&data[40..]);

        let result = subject.take_frame();

        let actual_chunk = result.unwrap();
        assert_eq!(to_string(&actual_chunk.chunk), to_string_s(&data[..]));
        assert_eq!(actual_chunk.last_chunk, false);
    }
}
