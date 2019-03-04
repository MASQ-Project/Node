// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use crate::sub_lib::framer::Framer;
use crate::sub_lib::logger::Logger;
use crate::sub_lib::proxy_client::InboundServerData;
use crate::sub_lib::sequencer::Sequencer;
use crate::sub_lib::stream_key::StreamKey;
use crate::sub_lib::tokio_wrappers::ReadHalfWrapper;
use crate::sub_lib::utils::indicates_dead_stream;
use crate::sub_lib::utils::to_string;
use actix::Recipient;
use actix::Syn;
use std::net::SocketAddr;
use std::sync::mpsc::Sender;
use tokio::prelude::Async;
use tokio::prelude::Future;

pub struct StreamReader {
    stream_key: StreamKey,
    proxy_client_sub: Recipient<Syn, InboundServerData>,
    stream: Box<dyn ReadHalfWrapper>,
    stream_killer: Sender<StreamKey>,
    peer_addr: SocketAddr,
    framer: Box<dyn Framer>,
    logger: Logger,
    sequencer: Sequencer,
}

impl Future for StreamReader {
    type Item = ();
    type Error = ();

    fn poll(&mut self) -> Result<Async<<Self as Future>::Item>, <Self as Future>::Error> {
        let mut buf: [u8; 16384] = [0; 16384];
        loop {
            match self.stream.poll_read(&mut buf) {
                Ok(Async::NotReady) => return Ok(Async::NotReady),
                Ok(Async::Ready(0)) => {
                    // see RETURN VALUE section of recv man page (Unix)
                    self.logger.debug(format!(
                        "Stream from {} was closed: (0-byte read)",
                        self.peer_addr
                    ));
                    self.shutdown();
                    return Ok(Async::Ready(()));
                }
                Ok(Async::Ready(len)) => {
                    self.logger.trace(format!(
                        "Read {}-byte chunk from {}: {}",
                        len,
                        self.peer_addr,
                        to_string(&Vec::from(&buf[0..len]))
                    ));
                    self.framer.add_data(&buf[0..len]);
                    self.send_frames_loop();
                }
                Err(e) => {
                    if indicates_dead_stream(e.kind()) {
                        self.logger
                            .debug(format!("Stream from {} was closed: {}", self.peer_addr, e));
                        self.shutdown();
                        return Err(());
                    } else {
                        // TODO this could be exploitable and inefficient: if we keep getting non-dead-stream errors, we go into a tight loop and do not return
                        self.logger.warning(format!(
                            "Continuing after read error on stream from {}: {}",
                            self.peer_addr, e
                        ));
                    }
                }
            }
        }
    }
}

impl StreamReader {
    pub fn new(
        stream_key: StreamKey,
        proxy_client_sub: Recipient<Syn, InboundServerData>,
        stream: Box<dyn ReadHalfWrapper>,
        stream_killer: Sender<StreamKey>,
        peer_addr: SocketAddr,
        framer: Box<dyn Framer>,
    ) -> StreamReader {
        StreamReader {
            stream_key,
            proxy_client_sub,
            stream,
            stream_killer,
            peer_addr,
            framer,
            logger: Logger::new(&format!("StreamReader for {:?}/{}", stream_key, peer_addr)[..]),
            sequencer: Sequencer::new(),
        }
    }

    fn shutdown(&mut self) {
        let stream_key = self.stream_key.clone();
        self.send_inbound_server_data(stream_key, vec![], true);
        self.stream_killer.send(self.stream_key).is_ok();
    }

    fn send_frames_loop(&mut self) {
        loop {
            match self.framer.take_frame() {
                Some(response_chunk) => {
                    self.logger.trace(format!(
                        "Framed {}-byte {} response chunk, '{}'",
                        response_chunk.chunk.len(),
                        if response_chunk.last_chunk {
                            "final"
                        } else {
                            "non-final"
                        },
                        to_string(&response_chunk.chunk)
                    ));
                    let stream_key = self.stream_key.clone();
                    self.send_inbound_server_data(
                        stream_key.clone(),
                        response_chunk.chunk,
                        response_chunk.last_chunk,
                    );
                    if response_chunk.last_chunk {
                        // FIXME no production framer sets this to true...
                        self.stream_killer.send(self.stream_key).is_ok();
                        break;
                    }
                }
                None => break,
            }
        }
    }

    fn send_inbound_server_data(&mut self, stream_key: StreamKey, data: Vec<u8>, last_data: bool) {
        self.proxy_client_sub
            .try_send(InboundServerData {
                stream_key,
                last_data,
                sequence_number: self.sequencer.next_sequence_number(),
                source: self.peer_addr,
                data,
            })
            .expect("Proxy Client is dead");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sub_lib::framer::FramedChunk;
    use crate::sub_lib::http_packet_framer::HttpPacketFramer;
    use crate::sub_lib::http_response_start_finder::HttpResponseStartFinder;
    use crate::test_utils::logging::init_test_logging;
    use crate::test_utils::logging::TestLogHandler;
    use crate::test_utils::recorder::make_recorder;
    use crate::test_utils::recorder::peer_actors_builder;
    use crate::test_utils::test_utils::make_meaningless_stream_key;
    use crate::test_utils::tokio_wrapper_mocks::ReadHalfWrapperMock;
    use actix::System;
    use std::io::Error;
    use std::io::ErrorKind;
    use std::net::SocketAddr;
    use std::str::FromStr;
    use std::sync::mpsc;
    use std::thread;

    struct StreamEndingFramer {}

    impl Framer for StreamEndingFramer {
        fn add_data(&mut self, _data: &[u8]) {}
        fn take_frame(&mut self) -> Option<FramedChunk> {
            Some(FramedChunk {
                chunk: vec![],
                last_chunk: true,
            })
        }
    }

    #[test]
    fn stream_reader_assigns_a_sequence_to_client_response_payloads() {
        let (proxy_client, proxy_client_awaiter, proxy_client_recording_arc) = make_recorder();

        let read_results = vec![
            b"HTTP/1.1 200".to_vec(),
            b" OK\r\n\r\nHTTP/1.1 40".to_vec(),
            b"4 File not found\r\n\r\nHTTP/1.1 503 Server error\r\n\r\n".to_vec(),
        ];

        let mut stream = Box::new(ReadHalfWrapperMock::new());

        stream.poll_read_results = vec![
            (
                read_results[0].clone(),
                Ok(Async::Ready(read_results[0].len())),
            ),
            (
                read_results[1].clone(),
                Ok(Async::Ready(read_results[1].len())),
            ),
            (
                read_results[2].clone(),
                Ok(Async::Ready(read_results[2].len())),
            ),
            (vec![], Ok(Async::Ready(0))),
        ];

        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let system = System::new("test");
            let peer_actors = peer_actors_builder().proxy_client(proxy_client).build();

            tx.send(peer_actors.proxy_client.inbound_server_data)
                .is_ok();
            system.run();
        });

        let proxy_client_sub = rx.recv().unwrap();
        let (stream_killer, stream_killer_params) = mpsc::channel();
        let mut subject = StreamReader {
            stream_key: make_meaningless_stream_key(),
            proxy_client_sub,
            stream,
            stream_killer,
            peer_addr: SocketAddr::from_str("8.7.4.3:50").unwrap(),
            framer: Box::new(HttpPacketFramer::new(Box::new(HttpResponseStartFinder {}))),
            logger: Logger::new("test"),
            sequencer: Sequencer::new(),
        };

        let _res = subject.poll();

        proxy_client_awaiter.await_message_count(4);
        let proxy_client_recording = proxy_client_recording_arc.lock().unwrap();
        assert_eq!(
            proxy_client_recording.get_record::<InboundServerData>(0),
            &InboundServerData {
                stream_key: make_meaningless_stream_key(),
                last_data: false,
                sequence_number: 0,
                source: SocketAddr::from_str("8.7.4.3:50").unwrap(),
                data: b"HTTP/1.1 200 OK\r\n\r\n".to_vec()
            },
        );
        assert_eq!(
            proxy_client_recording.get_record::<InboundServerData>(1),
            &InboundServerData {
                stream_key: make_meaningless_stream_key(),
                last_data: false,
                sequence_number: 1,
                source: SocketAddr::from_str("8.7.4.3:50").unwrap(),
                data: b"HTTP/1.1 404 File not found\r\n\r\n".to_vec()
            },
        );
        assert_eq!(
            proxy_client_recording.get_record::<InboundServerData>(2),
            &InboundServerData {
                stream_key: make_meaningless_stream_key(),
                last_data: false,
                sequence_number: 2,
                source: SocketAddr::from_str("8.7.4.3:50").unwrap(),
                data: b"HTTP/1.1 503 Server error\r\n\r\n".to_vec()
            },
        );
        assert_eq!(
            proxy_client_recording.get_record::<InboundServerData>(3),
            &InboundServerData {
                stream_key: make_meaningless_stream_key(),
                last_data: true,
                sequence_number: 3,
                source: SocketAddr::from_str("8.7.4.3:50").unwrap(),
                data: vec![]
            },
        );
        let stream_killer_parameters = stream_killer_params.try_recv().unwrap();
        assert_eq!(stream_killer_parameters, make_meaningless_stream_key());
    }

    #[test]
    fn when_framer_identifies_last_chunk_stream_reader_takes_down_connection_properly() {
        let (proxy_client, proxy_client_awaiter, proxy_client_recording_arc) = make_recorder();
        let stream_key = make_meaningless_stream_key();
        let mut stream = Box::new(ReadHalfWrapperMock::new());
        stream.poll_read_results = vec![
            (vec![4], Ok(Async::Ready(1))),
            (vec![], Ok(Async::NotReady)),
        ];
        let (stream_killer, stream_killer_params) = mpsc::channel();
        let framer = Box::new(StreamEndingFramer {});
        let logger = Logger::new("test");

        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let system = System::new("test");
            let peer_actors = peer_actors_builder().proxy_client(proxy_client).build();

            tx.send(peer_actors.proxy_client.inbound_server_data)
                .is_ok();
            system.run();
        });

        let proxy_client_sub = rx.recv().unwrap();
        let mut subject = StreamReader {
            stream_key,
            proxy_client_sub,
            stream,
            stream_killer,
            peer_addr: SocketAddr::from_str("4.3.6.5:574").unwrap(),
            framer,
            logger,
            sequencer: Sequencer::new(),
        };

        let result = subject.poll();

        assert_eq!(result, Ok(Async::NotReady));
        proxy_client_awaiter.await_message_count(1);
        let kill_stream_key = stream_killer_params.try_recv().unwrap();
        assert_eq!(kill_stream_key, stream_key.clone());
        let recording = proxy_client_recording_arc.lock().unwrap();
        assert_eq!(
            recording.get_record::<InboundServerData>(0),
            &InboundServerData {
                stream_key,
                last_data: true,
                sequence_number: 0,
                source: SocketAddr::from_str("4.3.6.5:574").unwrap(),
                data: vec![]
            }
        );
    }

    #[test]
    fn stream_reader_can_handle_multiple_packets_followed_by_dropped_stream() {
        let (proxy_client, proxy_client_awaiter, proxy_client_recording_arc) = make_recorder();
        let mut stream = ReadHalfWrapperMock::new();
        stream.poll_read_results = vec![
            (
                Vec::from(&b"HTTP/1.1 200"[..]),
                Ok(Async::Ready(b"HTTP/1.1 200".len())),
            ),
            (
                Vec::from(&b" OK\r\n\r\nHTTP/1.1 40"[..]),
                Ok(Async::Ready(b" OK\r\n\r\nHTTP/1.1 40".len())),
            ),
            (
                Vec::from(&b"4 File not found\r\n\r\nHTTP/1.1 503 Server error\r\n\r\n"[..]),
                Ok(Async::Ready(
                    b"4 File not found\r\n\r\nHTTP/1.1 503 Server error\r\n\r\n".len(),
                )),
            ),
            (vec![], Err(Error::from(ErrorKind::BrokenPipe))),
        ];
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let system = System::new("test");
            let peer_actors = peer_actors_builder().proxy_client(proxy_client).build();
            tx.send(peer_actors.proxy_client.inbound_server_data)
                .is_ok();

            system.run();
        });
        let proxy_client_sub = rx.recv().unwrap();
        let (stream_killer, stream_killer_params) = mpsc::channel();
        let mut subject = StreamReader {
            stream_key: make_meaningless_stream_key(),
            proxy_client_sub,
            stream: Box::new(stream),
            stream_killer,
            peer_addr: SocketAddr::from_str("5.7.9.0:95").unwrap(),
            framer: Box::new(HttpPacketFramer::new(Box::new(HttpResponseStartFinder {}))),
            logger: Logger::new("test"),
            sequencer: Sequencer::new(),
        };

        let result = subject.poll();

        assert_eq!(result, Err(()));
        proxy_client_awaiter.await_message_count(4);
        let proxy_client_recording = proxy_client_recording_arc.lock().unwrap();
        assert_eq!(
            proxy_client_recording.get_record::<InboundServerData>(0),
            &InboundServerData {
                stream_key: make_meaningless_stream_key(),
                last_data: false,
                sequence_number: 0,
                source: SocketAddr::from_str("5.7.9.0:95").unwrap(),
                data: b"HTTP/1.1 200 OK\r\n\r\n".to_vec()
            }
        );
        assert_eq!(
            proxy_client_recording.get_record::<InboundServerData>(1),
            &InboundServerData {
                stream_key: make_meaningless_stream_key(),
                last_data: false,
                sequence_number: 1,
                source: SocketAddr::from_str("5.7.9.0:95").unwrap(),
                data: b"HTTP/1.1 404 File not found\r\n\r\n".to_vec()
            }
        );
        assert_eq!(
            proxy_client_recording.get_record::<InboundServerData>(2),
            &InboundServerData {
                stream_key: make_meaningless_stream_key(),
                last_data: false,
                sequence_number: 2,
                source: SocketAddr::from_str("5.7.9.0:95").unwrap(),
                data: b"HTTP/1.1 503 Server error\r\n\r\n".to_vec()
            }
        );
        assert_eq!(
            proxy_client_recording.get_record::<InboundServerData>(3),
            &InboundServerData {
                stream_key: make_meaningless_stream_key(),
                last_data: true,
                sequence_number: 3,
                source: SocketAddr::from_str("5.7.9.0:95").unwrap(),
                data: vec!()
            }
        );

        let kill_stream_msg = stream_killer_params
            .try_recv()
            .expect("stream was not killed");
        assert_eq!(kill_stream_msg, make_meaningless_stream_key());
        assert!(stream_killer_params.try_recv().is_err());
    }

    #[test]
    fn receiving_0_bytes_sends_empty_cores_response_and_kills_stream() {
        init_test_logging();
        let (proxy_client, proxy_client_awaiter, proxy_client_recording_arc) = make_recorder();
        let stream_key = make_meaningless_stream_key();
        let (stream_killer, kill_stream_params) = mpsc::channel();
        let mut stream = ReadHalfWrapperMock::new();
        stream.poll_read_results = vec![(vec![], Ok(Async::Ready(0)))];

        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let system =
                System::new("receiving_0_bytes_sends_empty_cores_response_and_kills_stream");
            let peer_actors = peer_actors_builder().proxy_client(proxy_client).build();

            tx.send(peer_actors.proxy_client.inbound_server_data)
                .is_ok();
            system.run();
        });

        let proxy_client_sub = rx.recv().unwrap();
        let mut subject = StreamReader {
            stream_key,
            proxy_client_sub,
            stream: Box::new(stream),
            stream_killer,
            peer_addr: SocketAddr::from_str("5.3.4.3:654").unwrap(),
            framer: Box::new(HttpPacketFramer::new(Box::new(HttpResponseStartFinder {}))),
            logger: Logger::new("test"),
            sequencer: Sequencer::new(),
        };

        let result = subject.poll();

        assert_eq!(result, Ok(Async::Ready(())));
        proxy_client_awaiter.await_message_count(1);
        assert_eq!(kill_stream_params.try_recv().unwrap(), stream_key);
        let proxy_client_recording = proxy_client_recording_arc.lock().unwrap();
        assert_eq!(
            proxy_client_recording.get_record::<InboundServerData>(0),
            &InboundServerData {
                stream_key: make_meaningless_stream_key(),
                last_data: true,
                sequence_number: 0,
                source: SocketAddr::from_str("5.3.4.3:654").unwrap(),
                data: vec![]
            }
        );
        TestLogHandler::new()
            .exists_log_containing("Stream from 5.3.4.3:654 was closed: (0-byte read)");
    }

    #[test]
    fn non_dead_stream_read_errors_log_but_do_not_shut_down() {
        init_test_logging();
        let (proxy_client, proxy_client_awaiter, proxy_client_recording_arc) = make_recorder();
        let stream_key = make_meaningless_stream_key();
        let (stream_killer, _) = mpsc::channel();
        let mut stream = ReadHalfWrapperMock::new();
        stream.poll_read_results = vec![
            (vec![], Err(Error::from(ErrorKind::Other))),
            (
                Vec::from(&b"HTTP/1.1 200 OK\r\n\r\n"[..]),
                Ok(Async::Ready(b"HTTP/1.1 200 OK\r\n\r\n".len())),
            ),
            (vec![], Err(Error::from(ErrorKind::BrokenPipe))),
        ];

        let (tx, rx) = mpsc::channel();

        thread::spawn(move || {
            let system = System::new("non_dead_stream_read_errors_log_but_do_not_shut_down");
            let peer_actors = peer_actors_builder().proxy_client(proxy_client).build();

            tx.send(peer_actors.proxy_client.inbound_server_data)
                .is_ok();
            system.run();
        });

        let proxy_client_sub = rx.recv().unwrap();
        let mut subject = StreamReader {
            stream_key,
            proxy_client_sub,
            stream: Box::new(stream),
            stream_killer,
            peer_addr: SocketAddr::from_str("6.5.4.1:8325").unwrap(),
            framer: Box::new(HttpPacketFramer::new(Box::new(HttpResponseStartFinder {}))),
            logger: Logger::new("test"),
            sequencer: Sequencer::new(),
        };

        let result = subject.poll();

        assert_eq!(result, Err(()));
        proxy_client_awaiter.await_message_count(1);
        TestLogHandler::new().exists_log_containing(
            "WARN: test: Continuing after read error on stream from 6.5.4.1:8325: other os error",
        );
        let proxy_client_recording = proxy_client_recording_arc.lock().unwrap();
        assert_eq!(
            proxy_client_recording.get_record::<InboundServerData>(0),
            &InboundServerData {
                stream_key: make_meaningless_stream_key(),
                last_data: false,
                sequence_number: 0,
                source: SocketAddr::from_str("6.5.4.1:8325").unwrap(),
                data: b"HTTP/1.1 200 OK\r\n\r\n".to_vec()
            }
        );
    }
}
