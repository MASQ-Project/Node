// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use std::net::Shutdown;
use std::sync::mpsc::Sender;
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
use sub_lib::tcp_wrappers::TcpStreamWrapper;
use sub_lib::utils::indicates_dead_stream;
use sub_lib::utils::to_string;

pub struct StreamReader {
    stream_key: StreamKey,
    hopper_sub: Recipient<Syn, IncipientCoresPackage>,
    stream: Box<TcpStreamWrapper>,
    stream_killer: Sender<StreamKey>,
    peer_addr: String,
    remaining_route: Route,
    framer: Box<Framer>,
    originator_public_key: Key,
    logger: Logger,
}

impl StreamReader {

    pub fn new (stream_key: StreamKey, hopper_sub: Recipient<Syn, IncipientCoresPackage>,
        stream: Box<TcpStreamWrapper>, stream_killer: Sender<StreamKey>, peer_addr: String,
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
        }
    }

    pub fn run(&mut self) {
        let mut buf: [u8; 16384] = [0; 16384];
        while self.read_buffer (&mut buf) && self.write_loop() {
            // keep calling read and write until one of them returns false
        }
    }

    fn read_buffer (&mut self, buf: &mut [u8]) -> bool {
        match self.stream.read (buf) {
            Ok (0) => { // see RETURN VALUE section of recv man page (Unix)
                self.logger.debug (format! ("Stream from {} was closed: (0-byte read)", self.peer_addr));
                self.shutdown();
                false
            },
            Ok (len) => {
                self.logger.debug (format! ("Read {}-byte chunk from {}: {}", len, self.peer_addr,
                                            to_string (&Vec::from (&buf[0..len]))));
                self.framer.add_data (&buf[0..len]);
                true
            },
            Err (e) => {
                if indicates_dead_stream(e.kind ()) {
                    self.logger.debug (format! ("Stream from {} was closed: {}", self.peer_addr, e));
                    self.shutdown();
                    false
                }
                else {
                    self.logger.warning(format! ("Continuing after read error on stream from {}: {}", self.peer_addr, e));
                    true
                }
            }
        }
    }

    fn shutdown(&self) {
        self.send_cores_response (self.stream_key, PlainData::new (&[]), true);
        self.stream.shutdown (Shutdown::Both).is_ok ();
        self.stream_killer.send (self.stream_key).is_ok ();
    }

    fn write_loop (&mut self) -> bool {
        loop {
            match self.framer.take_frame () {
                Some (response_chunk) => {
                    self.logger.debug (format! ("Framed {}-byte {} response chunk, '{}'", response_chunk.chunk.len (),
                                                if response_chunk.last_chunk {"final"} else {"non-final"},
                                                to_string (&response_chunk.chunk)));
                    self.send_cores_response(
                        self.stream_key,
                        PlainData::new (&response_chunk.chunk[..]),
                        response_chunk.last_chunk
                    );
                    if response_chunk.last_chunk {
                        self.stream.shutdown (Shutdown::Both).is_ok ();
                        self.stream_killer.send (self.stream_key).is_ok ();
                        return false;
                    }
                },
                None => {
                    return true;
                }
            }
        }
    }

    fn send_cores_response(&self, stream_key: StreamKey, response_data: PlainData, last_response: bool) {
        let response_payload = ClientResponsePayload {
            stream_key,
            last_response,
            data: response_data
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
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::sync::mpsc;
    use std::thread;
    use actix::System;
    use serde_cbor;
    use sub_lib::framer::FramedChunk;
    use sub_lib::http_packet_framer::HttpPacketFramer;
    use sub_lib::http_response_start_finder::HttpResponseStartFinder;
    use test_utils::test_utils;
    use test_utils::test_utils::Recorder;
    use test_utils::test_utils::init_test_logging;
    use test_utils::test_utils::TestLogHandler;
    use local_test_utils::TcpStreamWrapperMock;
    use std::io::ErrorKind;

    struct StreamEndingFramer {}

    impl Framer for StreamEndingFramer {
        fn add_data(&mut self, _data: &[u8]) {}
        fn take_frame(&mut self) -> Option<FramedChunk> {
            Some(FramedChunk { chunk: vec!(), last_chunk: true })
        }
    }

    #[test]
    fn when_framer_identifies_last_chunk_stream_reader_takes_down_connection_properly() {
        let stream_key = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let hopper = Recorder::new();
        let recording = hopper.get_recording();
        let awaiter = hopper.get_awaiter();
        let mut shutdown_parameters = Arc::new(Mutex::new(vec!()));
        let stream = Box::new(TcpStreamWrapperMock::new()
            .read_buffer(vec!(4))
            .read_result(Ok(1))
            .shutdown_parameters(&mut shutdown_parameters)
            .shutdown_result(Ok(())));
        let (stream_killer, rx) = mpsc::channel();
        let remaining_route = test_utils::make_meaningless_route();
        let framer = Box::new(StreamEndingFramer {});
        let originator_public_key = Key::new(&b"men's souls"[..]);
        let logger = Logger::new("test");

        thread::spawn(move || {
            let system = System::new("test");
            let hopper_sub = test_utils::make_peer_actors_from(None, None, Some(hopper), None, None).hopper.from_hopper_client;
            let mut subject = StreamReader {
                stream_key,
                hopper_sub,
                stream,
                stream_killer,
                peer_addr: String::new(),
                remaining_route,
                framer,
                originator_public_key,
                logger
            };

            subject.run();

            system.run();
        });

        awaiter.await_message_count(1);
        let kill_stream_key = rx.recv().unwrap();
        assert_eq!(kill_stream_key, stream_key);
        let shutdown_parameter = shutdown_parameters.lock().unwrap()[0];
        assert_eq!(shutdown_parameter, Shutdown::Both);
        let recording = recording.lock().unwrap();
        let record = recording.get_record::<IncipientCoresPackage>(0);
        assert_eq!(*record, IncipientCoresPackage {
            route: test_utils::make_meaningless_route(),
            payload: PlainData::new(&serde_cbor::ser::to_vec(&ClientResponsePayload {
                stream_key,
                last_response: true,
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
        let mut shutdown_parameters = Arc::new(Mutex::new(vec!()));
        let stream = TcpStreamWrapperMock::new()
            .peer_addr_result(Ok(SocketAddr::from_str("2.3.4.5:80").unwrap()))
            .read_buffer(Vec::from(&b"HTTP/1.1 200"[..]))
            .read_result(Ok(b"HTTP/1.1 200".len()))
            .read_buffer(Vec::from(&b" OK\r\n\r\nHTTP/1.1 40"[..]))
            .read_result(Ok(b" OK\r\n\r\nHTTP/1.1 40".len()))
            .read_buffer(Vec::from(&b"4 File not found\r\n\r\nHTTP/1.1 503 Server error\r\n\r\n"[..]))
            .read_result(Ok(b"4 File not found\r\n\r\nHTTP/1.1 503 Server error\r\n\r\n".len()))
            .read_result(Err(Error::from(ErrorKind::BrokenPipe)))
            .shutdown_parameters(&mut shutdown_parameters)
            .shutdown_result(Ok(()));
        thread::spawn(move || {
            let system = System::new("test");
            let hopper_sub =
                test_utils::make_peer_actors_from(None, None, Some(hopper), None, None)
                    .hopper.from_hopper_client;
            let (stream_killer, _) = mpsc::channel::<StreamKey>();
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
            };

            subject.run();

            system.run();
        });

        awaiter.await_message_count(4);
        let hopper_recording = hopper_recording_arc.lock().unwrap();
        assert_eq!(hopper_recording.get_record::<IncipientCoresPackage>(0), &IncipientCoresPackage::new(
            test_utils::make_meaningless_route(),
            ClientResponsePayload {
                stream_key: SocketAddr::from_str("1.2.3.4:80").unwrap(),
                last_response: false,
                data: PlainData::new(&b"HTTP/1.1 200 OK\r\n\r\n"[..]),
            },
            &Key::new(&b"abcd"[..])
        ));
        assert_eq!(hopper_recording.get_record::<IncipientCoresPackage>(1), &IncipientCoresPackage::new(
            test_utils::make_meaningless_route(),
            ClientResponsePayload {
                stream_key: SocketAddr::from_str("1.2.3.4:80").unwrap(),
                last_response: false,
                data: PlainData::new(&b"HTTP/1.1 404 File not found\r\n\r\n"[..]),
            },
            &Key::new(&b"abcd"[..])
        ));
        assert_eq!(hopper_recording.get_record::<IncipientCoresPackage>(2), &IncipientCoresPackage::new(
            test_utils::make_meaningless_route(),
            ClientResponsePayload {
                stream_key: SocketAddr::from_str("1.2.3.4:80").unwrap(),
                last_response: false,
                data: PlainData::new(&b"HTTP/1.1 503 Server error\r\n\r\n"[..]),
            },
            &Key::new(&b"abcd"[..])
        ));
        assert_eq!(hopper_recording.get_record::<IncipientCoresPackage>(3), &IncipientCoresPackage::new(
            test_utils::make_meaningless_route(),
            ClientResponsePayload {
                stream_key: SocketAddr::from_str("1.2.3.4:80").unwrap(),
                last_response: true,
                data: PlainData::new(&b""[..]),
            },
            &Key::new(&b"abcd"[..])
        ));
        let shutdown_parameter = shutdown_parameters.lock().unwrap()[0];
        assert_eq!(shutdown_parameter, Shutdown::Both);
    }

    #[test]
    fn receiving_0_bytes_sends_empty_cores_response_and_kills_stream() {
        init_test_logging();
        let hopper = Recorder::new();
        let awaiter = hopper.get_awaiter();
        let hopper_recording_arc = hopper.get_recording();
        let stream_key = SocketAddr::from_str("1.2.3.4:80").unwrap();
        let mut shutdown_parameters = Arc::new(Mutex::new(vec!()));
        let (stream_killer, rx) = mpsc::channel::<StreamKey>();
            let stream = TcpStreamWrapperMock::new()
                .peer_addr_result(Ok(SocketAddr::from_str("2.3.4.5:80").unwrap()))
                .read_buffer(vec!())
                .read_result(Ok(0))
                .shutdown_parameters(&mut shutdown_parameters)
                .shutdown_result(Ok(()));

        thread::spawn(move || {
            let system = System::new("receiving_0_bytes_sends_empty_cores_response_and_kills_stream");
            let hopper_sub =
                test_utils::make_peer_actors_from(None, None, Some(hopper), None, None)
                    .hopper.from_hopper_client;
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
            };

            subject.run();

            system.run();
        });

        awaiter.await_message_count(1);
        let kill_stream_key = rx.recv().unwrap();
        assert_eq!(kill_stream_key, stream_key);
        let shutdown_parameter = shutdown_parameters.lock().unwrap()[0];
        assert_eq!(shutdown_parameter, Shutdown::Both);
        let hopper_recording = hopper_recording_arc.lock().unwrap();
        assert_eq!(hopper_recording.get_record::<IncipientCoresPackage>(0), &IncipientCoresPackage::new(
            test_utils::make_meaningless_route(),
            ClientResponsePayload {
                stream_key: SocketAddr::from_str("1.2.3.4:80").unwrap(),
                last_response: true,
                data: PlainData::new(&[]),
            },
            &Key::new(&b"abcd"[..])
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
        let (stream_killer, _) = mpsc::channel::<StreamKey>();
        let mut shutdown_parameters = Arc::new(Mutex::new(vec!()));
        let stream = TcpStreamWrapperMock::new()
            .read_result(Err(Error::from(ErrorKind::Other)))
            .read_buffer(Vec::from(&b"HTTP/1.1 200 OK\r\n\r\n"[..]))
            .read_result(Ok(b"HTTP/1.1 200 OK\r\n\r\n".len()))
            .read_result(Err(Error::from(ErrorKind::BrokenPipe)))
            .shutdown_parameters(&mut shutdown_parameters)
            .shutdown_result(Ok(()));

        thread::spawn(move || {
            let system = System::new("receiving_0_bytes_sends_empty_cores_response_and_kills_stream");
            let hopper_sub =
                test_utils::make_peer_actors_from(None, None, Some(hopper), None, None)
                    .hopper.from_hopper_client;
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
            };

            subject.run();

            system.run();
        });

        awaiter.await_message_count(1);
        TestLogHandler::new().exists_log_containing("WARN: test: Continuing after read error on stream from Peer Address: other os error");
        let hopper_recording = hopper_recording_arc.lock().unwrap();
        assert_eq!(hopper_recording.get_record::<IncipientCoresPackage>(0), &IncipientCoresPackage::new(
            test_utils::make_meaningless_route(),
            ClientResponsePayload {
                stream_key: SocketAddr::from_str("1.2.3.4:80").unwrap(),
                last_response: false,
                data: PlainData::new(&b"HTTP/1.1 200 OK\r\n\r\n"[..]),
            },
            &Key::new(&b"abcd"[..])
        ));
        let shutdown_parameter = shutdown_parameters.lock().unwrap()[0];
        assert_eq!(shutdown_parameter, Shutdown::Both);
    }
}