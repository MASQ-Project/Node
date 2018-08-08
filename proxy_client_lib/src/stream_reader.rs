// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use actix::Recipient;
use actix::Syn;
use sub_lib::cryptde::Key;
use sub_lib::cryptde::PlainData;
use sub_lib::cryptde::StreamKey;
use sub_lib::framer::Framer;
use sub_lib::hopper::IncipientCoresPackage;
use sub_lib::logger::Logger;
use sub_lib::proxy_client::ClientResponsePayload;
use sub_lib::route::Route;
use sub_lib::utils::indicates_dead_stream;
use sub_lib::utils::to_string;
use sub_lib::sequencer::Sequencer;
use sub_lib::tokio_wrappers::ReadHalfWrapper;
use tokio::prelude::Async;
use tokio::prelude::Future;
use std::sync::mpsc::Sender;

pub struct StreamReader {
    stream_key: StreamKey,
    hopper_sub: Recipient<Syn, IncipientCoresPackage>,
    stream: Box<ReadHalfWrapper>,
    stream_killer: Sender<StreamKey>,
    peer_addr: String,
    remaining_route: Route,
    framer: Box<Framer>,
    originator_public_key: Key,
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
                Ok(Async::Ready(0)) => { // see RETURN VALUE section of recv man page (Unix)
                    self.logger.debug(format!("Stream from {} was closed: (0-byte read)", self.peer_addr));
                    self.shutdown();
                    return Ok(Async::Ready(()));
                },
                Ok(Async::Ready(len)) => {
                    self.logger.debug(format!("Read {}-byte chunk from {}: {}", len, self.peer_addr,
                                              to_string(&Vec::from(&buf[0..len]))));
                    self.framer.add_data(&buf[0..len]);
                    self.send_frames_loop();
                },
                Err(e) => {
                    if indicates_dead_stream(e.kind()) {
                        self.logger.debug(format!("Stream from {} was closed: {}", self.peer_addr, e));
                        self.shutdown();
                        return Err(());
                    } else {
                        // TODO this could be exploitable and inefficient: if we keep getting non-dead-stream errors, we go into a tight loop and do not return
                        self.logger.warning(format!("Continuing after read error on stream from {}: {}", self.peer_addr, e));
                    }
                }
            }
        }
    }
}

impl StreamReader {
    pub fn new(stream_key: StreamKey, hopper_sub: Recipient<Syn, IncipientCoresPackage>,
               stream: Box<ReadHalfWrapper>, stream_killer: Sender<StreamKey>, peer_addr: String,
               remaining_route: Route, framer: Box<Framer>, originator_public_key: Key) -> StreamReader {
        StreamReader {
            stream_key,
            hopper_sub,
            stream,
            stream_killer,
            peer_addr,
            remaining_route,
            framer,
            originator_public_key,
            logger: Logger::new ("Proxy Client"),
            sequencer: Sequencer::new(),
        }
    }

    fn shutdown(&mut self) {
        let stream_key = self.stream_key.clone();
        self.send_cores_response(stream_key, PlainData::new(&[]), true);
        self.stream_killer.send(self.stream_key).is_ok();
    }

    fn send_frames_loop(&mut self) {
        loop {
            match self.framer.take_frame () {
                Some (response_chunk) => {
                    self.logger.debug (format! ("Framed {}-byte {} response chunk, '{}'", response_chunk.chunk.len (),
                                                if response_chunk.last_chunk {"final"} else {"non-final"},
                                                to_string (&response_chunk.chunk)));
                    let stream_key = self.stream_key.clone();
                    self.send_cores_response(
                        stream_key,
                        PlainData::new(&response_chunk.chunk[..]),
                        response_chunk.last_chunk,
                    );
                    if response_chunk.last_chunk { // FIXME no production framer sets this to true...
                        self.stream_killer.send(self.stream_key).is_ok();
                        break
                    }
                },
                None => break,
            }
        }
    }

    fn send_cores_response(&mut self, stream_key: StreamKey, response_data: PlainData, last_response: bool) {
        let response_payload = ClientResponsePayload {
            stream_key,
            last_response,
            sequence_number: self.sequencer.next_sequence_number(),
            data: response_data,
        };
        let incipient_cores_package =
            IncipientCoresPackage::new (self.remaining_route.clone (),
                                        response_payload, &self.originator_public_key);
        self.hopper_sub.try_send(incipient_cores_package).expect ("Hopper is dead");
    }
}

#[cfg (test)]
mod tests {
    use super::*;
    use std::io::Error;
    use std::net::SocketAddr;
    use std::str::FromStr;
    use std::sync::mpsc;
    use std::thread;
    use actix::System;
    use serde_cbor;
    use sub_lib::framer::FramedChunk;
    use sub_lib::http_packet_framer::HttpPacketFramer;
    use sub_lib::http_response_start_finder::HttpResponseStartFinder;
    use test_utils::test_utils;
    use test_utils::recorder;
    use test_utils::recorder::Recorder;
    use test_utils::logging::init_test_logging;
    use test_utils::logging::TestLogHandler;
    use std::io::ErrorKind;
    use test_utils::tokio_wrapper_mocks::ReadHalfWrapperMock;

    struct StreamEndingFramer {}

    impl Framer for StreamEndingFramer {
        fn add_data(&mut self, _data: &[u8]) {}
        fn take_frame(&mut self) -> Option<FramedChunk> {
            Some(FramedChunk { chunk: vec!(), last_chunk: true })
        }
    }

    #[test]
    fn stream_reader_assigns_a_sequence_to_client_response_payloads() {
        let hopper = Recorder::new();
        let awaiter = hopper.get_awaiter();
        let hopper_recording_arc = hopper.get_recording();

        let read_results = vec!(
            b"HTTP/1.1 200".to_vec(),
            b" OK\r\n\r\nHTTP/1.1 40".to_vec(),
            b"4 File not found\r\n\r\nHTTP/1.1 503 Server error\r\n\r\n".to_vec()
        );

        let mut stream = Box::new(ReadHalfWrapperMock::new());

        stream.poll_read_results = vec!(
            (read_results[0].clone(), Ok(Async::Ready(read_results[0].len()))),
            (read_results[1].clone(), Ok(Async::Ready(read_results[1].len()))),
            (read_results[2].clone(), Ok(Async::Ready(read_results[2].len()))),
            (vec!(), Ok(Async::Ready(0))),
        );

        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let system = System::new("test");
            let hopper_sub =
                recorder::make_peer_actors_from(None, None, Some(hopper), None, None)
                    .hopper.from_hopper_client;
            tx.send(hopper_sub).is_ok();
            system.run();
        });

        let hopper_sub = rx.recv().unwrap();
        let (stream_killer, stream_killer_params) = mpsc::channel();
        let mut subject = StreamReader {
            stream_key: SocketAddr::from_str("1.2.3.4:80").unwrap(),
            hopper_sub,
            stream,
            stream_killer: stream_killer,
            peer_addr: String::from("Peer Address"),
            remaining_route: test_utils::make_meaningless_route(),
            framer: Box::new(HttpPacketFramer::new(Box::new(HttpResponseStartFinder {}))),
            originator_public_key: Key::new(&b"abcd"[..]),
            logger: Logger::new("test"),
            sequencer: Sequencer::new(),
        };

        let _res = subject.poll();

        awaiter.await_message_count(4);
        let hopper_recording = hopper_recording_arc.lock().unwrap();
        assert_eq!(hopper_recording.get_record::<IncipientCoresPackage>(0), &IncipientCoresPackage::new(
            test_utils::make_meaningless_route(),
            ClientResponsePayload {
                stream_key: SocketAddr::from_str("1.2.3.4:80").unwrap(),
                last_response: false,
                sequence_number: 0,
                data: PlainData::new(&b"HTTP/1.1 200 OK\r\n\r\n"[..]),
            },
            &Key::new(&b"abcd"[..]),
        ));
        assert_eq!(hopper_recording.get_record::<IncipientCoresPackage>(1), &IncipientCoresPackage::new(
            test_utils::make_meaningless_route(),
            ClientResponsePayload {
                stream_key: SocketAddr::from_str("1.2.3.4:80").unwrap(),
                last_response: false,
                sequence_number: 1,
                data: PlainData::new(&b"HTTP/1.1 404 File not found\r\n\r\n"[..]),
            },
            &Key::new(&b"abcd"[..]),
        ));
        assert_eq!(hopper_recording.get_record::<IncipientCoresPackage>(2), &IncipientCoresPackage::new(
            test_utils::make_meaningless_route(),
            ClientResponsePayload {
                stream_key: SocketAddr::from_str("1.2.3.4:80").unwrap(),
                last_response: false,
                sequence_number: 2,
                data: PlainData::new(&b"HTTP/1.1 503 Server error\r\n\r\n"[..]),
            },
            &Key::new(&b"abcd"[..]),
        ));
        assert_eq!(hopper_recording.get_record::<IncipientCoresPackage>(3), &IncipientCoresPackage::new(
            test_utils::make_meaningless_route(),
            ClientResponsePayload {
                stream_key: SocketAddr::from_str("1.2.3.4:80").unwrap(),
                last_response: true,
                sequence_number: 3,
                data: PlainData::new(&Vec::new()),
            },
            &Key::new(&b"abcd"[..]),
        ));
        let stream_killer_parameters = stream_killer_params.try_recv().unwrap();
        assert_eq!(stream_killer_parameters, SocketAddr::from_str("1.2.3.4:80").unwrap());
    }

    #[test]
    fn when_framer_identifies_last_chunk_stream_reader_takes_down_connection_properly() {
        let stream_key = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let hopper = Recorder::new();
        let recording = hopper.get_recording();
        let awaiter = hopper.get_awaiter();
        let mut stream = Box::new(ReadHalfWrapperMock::new());
        stream.poll_read_results = vec!(
            (vec!(4), Ok(Async::Ready(1))),
            (vec!(), Ok(Async::NotReady))
        );
        let (stream_killer, stream_killer_params) = mpsc::channel();
        let remaining_route = test_utils::make_meaningless_route();
        let framer = Box::new(StreamEndingFramer {});
        let originator_public_key = Key::new(&b"men's souls"[..]);
        let logger = Logger::new("test");

        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let system = System::new("test");
            let hopper_sub = recorder::make_peer_actors_from(None, None, Some(hopper), None, None).hopper.from_hopper_client;
            tx.send(hopper_sub).is_ok();
            system.run();
        });

        let hopper_sub = rx.recv().unwrap();
        let mut subject = StreamReader {
            stream_key,
            hopper_sub,
            stream,
            stream_killer,
            peer_addr: String::new(),
            remaining_route,
            framer,
            originator_public_key,
            logger,
            sequencer: Sequencer::new(),
        };

        let result = subject.poll();

        assert_eq!(result, Ok(Async::NotReady));
        awaiter.await_message_count(1);
        let kill_stream_key = stream_killer_params.try_recv().unwrap();
        assert_eq!(kill_stream_key, stream_key.clone());
        let recording = recording.lock().unwrap();
        let record = recording.get_record::<IncipientCoresPackage>(0);
        assert_eq!(*record, IncipientCoresPackage {
            route: test_utils::make_meaningless_route(),
            payload: PlainData::new(&serde_cbor::ser::to_vec(&ClientResponsePayload {
                stream_key,
                last_response: true,
                sequence_number: 0,
                data: PlainData::new(&[]),
            }).unwrap()[..]),
            payload_destination_key: Key::new(&b"men's souls"[..]),
        });
    }

    #[test]
    fn stream_reader_can_handle_multiple_packets_followed_by_dropped_stream() {
        let hopper = Recorder::new();
        let awaiter = hopper.get_awaiter();
        let hopper_recording_arc = hopper.get_recording();
        let mut stream = ReadHalfWrapperMock::new();
        stream.poll_read_results = vec!(
            (Vec::from(&b"HTTP/1.1 200"[..]), Ok(Async::Ready(b"HTTP/1.1 200".len()))),
            (Vec::from(&b" OK\r\n\r\nHTTP/1.1 40"[..]), Ok(Async::Ready(b" OK\r\n\r\nHTTP/1.1 40".len()))),
            (Vec::from(&b"4 File not found\r\n\r\nHTTP/1.1 503 Server error\r\n\r\n"[..]), Ok(Async::Ready(b"4 File not found\r\n\r\nHTTP/1.1 503 Server error\r\n\r\n".len()))),
            (vec!(), Err(Error::from(ErrorKind::BrokenPipe)))
        );
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let system = System::new("test");
            let hopper_sub =
                recorder::make_peer_actors_from(None, None, Some(hopper), None, None)
                    .hopper.from_hopper_client;
            tx.send(hopper_sub).is_ok();

            system.run();
        });
        let hopper_sub = rx.recv().unwrap();
        let (stream_killer, stream_killer_params) = mpsc::channel();
        let mut subject = StreamReader {
            stream_key: SocketAddr::from_str("1.2.3.4:80").unwrap(),
            hopper_sub,
            stream: Box::new(stream),
            stream_killer,
            peer_addr: String::from("Peer Address"),
            remaining_route: test_utils::make_meaningless_route(),
            framer: Box::new(HttpPacketFramer::new(Box::new(HttpResponseStartFinder {}))),
            originator_public_key: Key::new(&b"abcd"[..]),
            logger: Logger::new("test"),
            sequencer: Sequencer::new(),
        };

        let result = subject.poll();

        assert_eq!(result, Err(()));
        awaiter.await_message_count(4);
        let hopper_recording = hopper_recording_arc.lock().unwrap();
        assert_eq!(hopper_recording.get_record::<IncipientCoresPackage>(0), &IncipientCoresPackage::new(
            test_utils::make_meaningless_route(),
            ClientResponsePayload {
                stream_key: SocketAddr::from_str("1.2.3.4:80").unwrap(),
                last_response: false,
                sequence_number: 0,
                data: PlainData::new(&b"HTTP/1.1 200 OK\r\n\r\n"[..]),
            },
            &Key::new(&b"abcd"[..]),
        ));
        assert_eq!(hopper_recording.get_record::<IncipientCoresPackage>(1), &IncipientCoresPackage::new(
            test_utils::make_meaningless_route(),
            ClientResponsePayload {
                stream_key: SocketAddr::from_str("1.2.3.4:80").unwrap(),
                last_response: false,
                sequence_number: 1,
                data: PlainData::new(&b"HTTP/1.1 404 File not found\r\n\r\n"[..]),
            },
            &Key::new(&b"abcd"[..]),
        ));
        assert_eq!(hopper_recording.get_record::<IncipientCoresPackage>(2), &IncipientCoresPackage::new(
            test_utils::make_meaningless_route(),
            ClientResponsePayload {
                stream_key: SocketAddr::from_str("1.2.3.4:80").unwrap(),
                last_response: false,
                sequence_number: 2,
                data: PlainData::new(&b"HTTP/1.1 503 Server error\r\n\r\n"[..]),
            },
            &Key::new(&b"abcd"[..]),
        ));
        assert_eq!(hopper_recording.get_record::<IncipientCoresPackage>(3), &IncipientCoresPackage::new(
            test_utils::make_meaningless_route(),
            ClientResponsePayload {
                stream_key: SocketAddr::from_str("1.2.3.4:80").unwrap(),
                last_response: true,
                sequence_number: 3,
                data: PlainData::new(&b""[..]),
            },
            &Key::new(&b"abcd"[..]),
        ));
        let kill_stream_msg = stream_killer_params.try_recv().expect("stream was not killed");
        assert_eq!(kill_stream_msg, SocketAddr::from_str("1.2.3.4:80").unwrap());
        assert!(stream_killer_params.try_recv().is_err());
    }

    #[test]
    fn receiving_0_bytes_sends_empty_cores_response_and_kills_stream() {
        init_test_logging();
        let hopper = Recorder::new();
        let awaiter = hopper.get_awaiter();
        let hopper_recording_arc = hopper.get_recording();
        let stream_key = SocketAddr::from_str("1.2.3.4:80").unwrap();
        let (stream_killer, kill_stream_params) = mpsc::channel();
        let mut stream = ReadHalfWrapperMock::new();
        stream.poll_read_results = vec!((vec!(), Ok(Async::Ready(0))));

        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let system = System::new("receiving_0_bytes_sends_empty_cores_response_and_kills_stream");
            let hopper_sub =
                recorder::make_peer_actors_from(None, None, Some(hopper), None, None)
                    .hopper.from_hopper_client;

            tx.send(hopper_sub).is_ok();
            system.run();
        });

        let hopper_sub = rx.recv().unwrap();
        let mut subject = StreamReader {
            stream_key,
            hopper_sub,
            stream: Box::new(stream),
            stream_killer,
            peer_addr: String::from("Peer Address"),
            remaining_route: test_utils::make_meaningless_route(),
            framer: Box::new(HttpPacketFramer::new(Box::new(HttpResponseStartFinder {}))),
            originator_public_key: Key::new(&b"abcd"[..]),
            logger: Logger::new("test"),
            sequencer: Sequencer::new(),
        };

        let result = subject.poll();

        assert_eq!(result, Ok(Async::Ready(())));
        awaiter.await_message_count(1);
        assert_eq!(kill_stream_params.try_recv().unwrap(), stream_key);
        let hopper_recording = hopper_recording_arc.lock().unwrap();
        assert_eq!(hopper_recording.get_record::<IncipientCoresPackage>(0), &IncipientCoresPackage::new(
            test_utils::make_meaningless_route(),
            ClientResponsePayload {
                stream_key: SocketAddr::from_str("1.2.3.4:80").unwrap(),
                last_response: true,
                sequence_number: 0,
                data: PlainData::new(&[]),
            },
            &Key::new(&b"abcd"[..]),
        ));
        TestLogHandler::new().exists_log_containing("Stream from Peer Address was closed: (0-byte read)");
    }

    #[test]
    fn non_dead_stream_read_errors_log_but_do_not_shut_down() {
        init_test_logging();
        let hopper = Recorder::new();
        let awaiter = hopper.get_awaiter();
        let hopper_recording_arc = hopper.get_recording();
        let stream_key = SocketAddr::from_str("1.2.3.4:80").unwrap();
        let (stream_killer, _) = mpsc::channel();
        let mut stream = ReadHalfWrapperMock::new();
        stream.poll_read_results = vec!(
            (vec!(), Err(Error::from(ErrorKind::Other))),
            (Vec::from(&b"HTTP/1.1 200 OK\r\n\r\n"[..]), Ok(Async::Ready(b"HTTP/1.1 200 OK\r\n\r\n".len()))),
            (vec!(), Err(Error::from(ErrorKind::BrokenPipe))),
        );

        let (tx, rx) = mpsc::channel();

        thread::spawn(move || {
            let system = System::new("non_dead_stream_read_errors_log_but_do_not_shut_down");
            let hopper_sub =
                recorder::make_peer_actors_from(None, None, Some(hopper), None, None)
                    .hopper.from_hopper_client;

            tx.send(hopper_sub).is_ok();
            system.run();
        });

        let hopper_sub = rx.recv().unwrap();
        let mut subject = StreamReader {
            stream_key,
            hopper_sub,
            stream: Box::new(stream),
            stream_killer,
            peer_addr: String::from("Peer Address"),
            remaining_route: test_utils::make_meaningless_route(),
            framer: Box::new(HttpPacketFramer::new(Box::new(HttpResponseStartFinder {}))),
            originator_public_key: Key::new(&b"abcd"[..]),
            logger: Logger::new("test"),
            sequencer: Sequencer::new(),
        };

        let result = subject.poll();

        assert_eq!(result, Err(()));
        awaiter.await_message_count(1);
        TestLogHandler::new().exists_log_containing("WARN: test: Continuing after read error on stream from Peer Address: other os error");
        let hopper_recording = hopper_recording_arc.lock().unwrap();
        assert_eq!(hopper_recording.get_record::<IncipientCoresPackage>(0), &IncipientCoresPackage::new(
            test_utils::make_meaningless_route(),
            ClientResponsePayload {
                stream_key: SocketAddr::from_str("1.2.3.4:80").unwrap(),
                last_response: false,
                sequence_number: 0,
                data: PlainData::new(&b"HTTP/1.1 200 OK\r\n\r\n"[..]),
            },
            &Key::new(&b"abcd"[..]),
        ));
    }
}