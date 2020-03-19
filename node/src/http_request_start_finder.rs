// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use crate::discriminator::Discriminator;
use crate::discriminator::DiscriminatorFactory;
use crate::null_masquerader::NullMasquerader;
use crate::sub_lib::http_packet_framer::HttpFramerState;
use crate::sub_lib::http_packet_framer::HttpPacketFramer;
use crate::sub_lib::http_packet_framer::HttpPacketStartFinder;
use crate::sub_lib::http_packet_framer::PacketProgressState;
use masq_lib::utils::index_of;

const METHODS: &[&[u8]] = &[
    b"GET", b"HEAD", b"POST", b"PUT", b"DELETE", b"CONNECT", b"OPTIONS", b"TRACE", b"PATCH",
];
const LONGEST_METHOD_LEN: usize = 7;

pub struct HttpRequestStartFinder {}

impl HttpPacketStartFinder for HttpRequestStartFinder {
    fn seek_packet_start(&self, framer_state: &mut HttpFramerState) -> bool {
        if framer_state.packet_progress_state == PacketProgressState::SeekingPacketStart {
            match METHODS
                .iter()
                .flat_map(|method| index_of(&framer_state.data_so_far[..], *method))
                .min()
            {
                Some(first_method_offset) => {
                    let clean_start_data = framer_state.data_so_far.split_off(first_method_offset);
                    framer_state.data_so_far = clean_start_data;
                    framer_state.packet_progress_state = PacketProgressState::SeekingBodyStart;
                    framer_state.content_length = 0;
                    framer_state.lines.clear();
                    true
                }
                None => {
                    let index = if framer_state.data_so_far.len() > LONGEST_METHOD_LEN {
                        framer_state.data_so_far.len() - LONGEST_METHOD_LEN
                    } else {
                        0
                    };
                    let remainder = framer_state.data_so_far.split_off(index);
                    framer_state.data_so_far = remainder;
                    false
                }
            }
        } else {
            false
        }
    }
}

#[derive(Debug, Default)]
pub struct HttpRequestDiscriminatorFactory {}

impl DiscriminatorFactory for HttpRequestDiscriminatorFactory {
    fn make(&self) -> Discriminator {
        Discriminator::new(
            Box::new(HttpPacketFramer::new(Box::new(HttpRequestStartFinder {}))),
            vec![Box::new(NullMasquerader::new())],
        )
    }

    fn duplicate(&self) -> Box<dyn DiscriminatorFactory> {
        Box::new(HttpRequestDiscriminatorFactory {})
    }
}

impl HttpRequestDiscriminatorFactory {
    pub fn new() -> HttpRequestDiscriminatorFactory {
        HttpRequestDiscriminatorFactory {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discriminator::UnmaskedChunk;
    use crate::sub_lib::http_packet_framer::ChunkExistenceState;
    use crate::sub_lib::http_packet_framer::ChunkProgressState;
    use crate::sub_lib::http_packet_framer::PacketProgressState;

    #[test]
    fn discriminator_factory_duplicate_works() {
        let subject = HttpRequestDiscriminatorFactory::new();

        subject.duplicate();

        // no panic; test passes
    }

    #[test]
    fn refuses_to_operate_in_state_other_than_seeking_request_start() {
        let mut framer_state = HttpFramerState {
            data_so_far: Vec::from("GET http://nowhere.com/index.html HTTP/1.1\r\n".as_bytes()),
            packet_progress_state: PacketProgressState::SeekingBodyStart,
            content_length: 100,
            transfer_encoding_chunked: ChunkExistenceState::Chunk,
            chunk_progress_state: ChunkProgressState::SeekingEndOfFinalChunk,
            chunk_size: Some(200),
            lines: vec![vec![], vec![]],
        };
        let subject = HttpRequestStartFinder {};

        let result = subject.seek_packet_start(&mut framer_state);

        assert_eq!(result, false);
        assert_eq!(
            framer_state,
            HttpFramerState {
                data_so_far: Vec::from("GET http://nowhere.com/index.html HTTP/1.1\r\n".as_bytes()),
                packet_progress_state: PacketProgressState::SeekingBodyStart,
                content_length: 100,
                transfer_encoding_chunked: ChunkExistenceState::Chunk,
                chunk_progress_state: ChunkProgressState::SeekingEndOfFinalChunk,
                chunk_size: Some(200),
                lines: vec!(vec!(), vec!()),
            }
        );
    }

    #[test]
    fn throws_away_leading_garbage_except_for_last_seven_characters() {
        let mut framer_state = HttpFramerState {
            data_so_far: Vec::from("this is garbage".as_bytes()),
            packet_progress_state: PacketProgressState::SeekingPacketStart,
            content_length: 100,
            transfer_encoding_chunked: ChunkExistenceState::Chunk,
            chunk_progress_state: ChunkProgressState::SeekingEndOfFinalChunk,
            chunk_size: Some(200),
            lines: vec![vec![], vec![]],
        };
        let subject = HttpRequestStartFinder {};

        let result = subject.seek_packet_start(&mut framer_state);

        assert_eq!(result, false);
        assert_eq!(
            framer_state,
            HttpFramerState {
                data_so_far: Vec::from("garbage".as_bytes()),
                packet_progress_state: PacketProgressState::SeekingPacketStart,
                content_length: 100,
                transfer_encoding_chunked: ChunkExistenceState::Chunk,
                chunk_progress_state: ChunkProgressState::SeekingEndOfFinalChunk,
                chunk_size: Some(200),
                lines: vec!(vec!(), vec!()),
            }
        );
    }

    #[test]
    fn frames_properly_in_the_presence_of_garbage() {
        let mut framer_state = HttpFramerState {
            data_so_far: Vec::from(
                "this is garbageGET http://nowhere.com/index.html HTTP/1.1\r\n\
                 One-Header: value\r\n\
                 Another-Header: val"
                    .as_bytes(),
            ),
            packet_progress_state: PacketProgressState::SeekingPacketStart,
            content_length: 100,
            transfer_encoding_chunked: ChunkExistenceState::Chunk,
            chunk_progress_state: ChunkProgressState::SeekingEndOfFinalChunk,
            chunk_size: Some(200),
            lines: vec![vec![], vec![]],
        };
        let subject = HttpRequestStartFinder {};

        let result = subject.seek_packet_start(&mut framer_state);

        assert_eq!(result, true);
        assert_eq!(
            framer_state,
            HttpFramerState {
                data_so_far: Vec::from(
                    "GET http://nowhere.com/index.html HTTP/1.1\r\n\
                     One-Header: value\r\n\
                     Another-Header: val"
                        .as_bytes()
                ),
                packet_progress_state: PacketProgressState::SeekingBodyStart,
                content_length: 0,
                transfer_encoding_chunked: ChunkExistenceState::Chunk,
                chunk_progress_state: ChunkProgressState::SeekingEndOfFinalChunk,
                chunk_size: Some(200),
                lines: vec!(),
            }
        );
    }

    #[test]
    fn recognizes_all_methods() {
        METHODS.iter().for_each(|method| check_method(method))
    }

    fn check_method(method: &[u8]) {
        let mut request = Vec::from(method);
        request.extend(" http://nowhere.com/index.html HTTP/1.1\r\n\r\n".as_bytes());
        let saved_request = request.clone();
        let mut data = Vec::from("garbage".as_bytes());
        data.extend(request);
        let mut framer_state = HttpFramerState {
            data_so_far: data,
            packet_progress_state: PacketProgressState::SeekingPacketStart,
            content_length: 0,
            transfer_encoding_chunked: ChunkExistenceState::Chunk,
            chunk_progress_state: ChunkProgressState::SeekingEndOfFinalChunk,
            chunk_size: Some(200),
            lines: vec![],
        };
        let subject = HttpRequestStartFinder {};

        let result = subject.seek_packet_start(&mut framer_state);

        assert_eq!(result, true);
        assert_eq!(
            framer_state,
            HttpFramerState {
                data_so_far: saved_request,
                packet_progress_state: PacketProgressState::SeekingBodyStart,
                content_length: 0,
                transfer_encoding_chunked: ChunkExistenceState::Chunk,
                chunk_progress_state: ChunkProgressState::SeekingEndOfFinalChunk,
                chunk_size: Some(200),
                lines: vec!(),
            }
        );
    }

    #[test]
    fn factory_makes_discriminator() {
        let subject = HttpRequestDiscriminatorFactory::new();

        let mut http_discriminator = subject.make();

        http_discriminator.add_data("GET http://url.com HTTP/1.1\r\n\r\n".as_bytes());
        let http_chunk = http_discriminator.take_chunk().unwrap();
        assert_eq!(
            http_chunk,
            UnmaskedChunk::new(
                Vec::from("GET http://url.com HTTP/1.1\r\n\r\n".as_bytes()),
                true,
                true
            )
        );
    }
}
