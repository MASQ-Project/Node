// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
use crate::sub_lib::proxy_client::InboundServerData;
use crate::sub_lib::sequencer::Sequencer;
use crate::sub_lib::stream_key::StreamKey;
use crate::sub_lib::tokio_wrappers::ReadHalfWrapper;
use crate::sub_lib::utils;
use crate::sub_lib::utils::indicates_dead_stream;
use actix::Recipient;
use crossbeam_channel::Sender;
use masq_lib::logger::Logger;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{ReadBuf};

pub struct StreamReader {
    stream_key: StreamKey,
    proxy_client_sub: Recipient<InboundServerData>,
    stream: Box<dyn ReadHalfWrapper>,
    stream_killer: Sender<(StreamKey, u64)>,
    peer_addr: SocketAddr,
    logger: Logger,
    sequencer: Sequencer,
}

impl StreamReader {
    pub fn new(
        stream_key: StreamKey,
        proxy_client_sub: Recipient<InboundServerData>,
        stream: Box<dyn ReadHalfWrapper>,
        stream_killer: Sender<(StreamKey, u64)>,
        peer_addr: SocketAddr,
    ) -> StreamReader {
        StreamReader {
            stream_key,
            proxy_client_sub,
            stream,
            stream_killer,
            peer_addr,
            logger: Logger::new(&format!("StreamReader for {:?}/{}", stream_key, peer_addr)[..]),
            sequencer: Sequencer::new(),
        }
    }

    const BUF_LEN: usize = 16384;
    async fn go(&mut self) -> io::Result<()> {
        let mut buf: [u8; Self::BUF_LEN] = [0; Self::BUF_LEN];
        loop {
            let prev_buf_len = Self::BUF_LEN;
            match self.stream.as_mut().read(&mut buf).await {
                Ok(_) => {
                    let len = Self::BUF_LEN - prev_buf_len;
                    if len == 0 {
                        // see RETURN VALUE section of recv man page (Unix)
                        debug!(
                        self.logger,
                        "Stream from {} was closed: (0-byte read)", self.peer_addr
                    );
                        self.shutdown();
                        return Ok(());
                    }
                    else {
                        if self.logger.trace_enabled() {
                            trace!(
                            self.logger,
                            "Read {}-byte chunk from {}: {}",
                            len,
                            self.peer_addr,
                            utils::to_string(&Vec::from(&buf[0..len]))
                        );
                        }
                        let stream_key = self.stream_key;
                        self.send_inbound_server_data(stream_key, Vec::from(&buf[0..len]), false);
                    }
                }
                Err(e) => {
                    if indicates_dead_stream(e.kind()) {
                        debug!(
                            self.logger,
                            "Stream from {} was closed: {}", self.peer_addr, e
                        );
                        self.shutdown();
                        return Err(e);
                    } else {
                        // TODO this could be exploitable and inefficient: if we keep getting non-dead-stream errors,
                        // we go into a tight loop and do not return
                        warning!(
                            self.logger,
                            "Continuing after read error on stream from {}: {}",
                            self.peer_addr,
                            e
                        );
                    }
                }
            }
        }
    }

    fn shutdown(&mut self) {
        let _ = self
            .stream_killer
            .send((self.stream_key, self.sequencer.next_sequence_number()));
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
            .expect("ProxyClient is dead");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::make_meaningless_stream_key;
    use crate::test_utils::recorder::make_recorder;
    use crate::test_utils::recorder::peer_actors_builder;
    use crate::test_utils::tokio_wrapper_mocks::ReadHalfWrapperMock;
    use actix::System;
    use crossbeam_channel::unbounded;
    use masq_lib::test_utils::logging::init_test_logging;
    use masq_lib::test_utils::logging::TestLogHandler;
    use std::io::Error;
    use std::io::ErrorKind;
    use std::net::SocketAddr;
    use std::str::FromStr;
    use std::thread;

    #[tokio::test]
    async fn stream_reader_assigns_a_sequence_to_client_response_payloads() {
        let (proxy_client, proxy_client_awaiter, proxy_client_recording_arc) = make_recorder();

        let read_results = vec![
            b"HTTP/1.1 200".to_vec(),
            b" OK\r\n\r\nHTTP/1.1 40".to_vec(),
            b"4 File not found\r\n\r\nHTTP/1.1 503 Server error\r\n\r\n".to_vec(),
        ];

        let mut stream = ReadHalfWrapperMock::new()
            .read_result(Ok(b"HTTP/1.1 200".to_vec()))
            .read_result(Ok(b" OK\r\n\r\nHTTP/1.1 40".to_vec()))
            .read_result(Ok(b"4 File not found\r\n\r\nHTTP/1.1 503 Server error\r\n\r\n".to_vec()))
            .read_result(Ok(vec![]));

        let (tx, rx) = unbounded();
        thread::spawn(move || {
            let system = System::new();
            let peer_actors = peer_actors_builder().proxy_client(proxy_client).build();

            tx.send(peer_actors.proxy_client_opt.unwrap().inbound_server_data)
                .expect("Internal Error");
            system.run().unwrap();
        });

        let proxy_client_sub = rx.recv().unwrap();
        let (stream_killer, stream_killer_params) = unbounded();
        let mut subject = StreamReader {
            stream_key: make_meaningless_stream_key(),
            proxy_client_sub,
            stream: Box::new(stream),
            stream_killer,
            peer_addr: SocketAddr::from_str("8.7.4.3:50").unwrap(),
            logger: Logger::new("test"),
            sequencer: Sequencer::new(),
        };

        let _res = subject.go().await;

        proxy_client_awaiter.await_message_count(3);
        let proxy_client_recording = proxy_client_recording_arc.lock().unwrap();
        assert_eq!(
            proxy_client_recording.get_record::<InboundServerData>(0),
            &InboundServerData {
                stream_key: make_meaningless_stream_key(),
                last_data: false,
                sequence_number: 0,
                source: SocketAddr::from_str("8.7.4.3:50").unwrap(),
                data: b"HTTP/1.1 200".to_vec()
            },
        );
        assert_eq!(
            proxy_client_recording.get_record::<InboundServerData>(1),
            &InboundServerData {
                stream_key: make_meaningless_stream_key(),
                last_data: false,
                sequence_number: 1,
                source: SocketAddr::from_str("8.7.4.3:50").unwrap(),
                data: b" OK\r\n\r\nHTTP/1.1 40".to_vec()
            },
        );
        assert_eq!(
            proxy_client_recording.get_record::<InboundServerData>(2),
            &InboundServerData {
                stream_key: make_meaningless_stream_key(),
                last_data: false,
                sequence_number: 2,
                source: SocketAddr::from_str("8.7.4.3:50").unwrap(),
                data: b"4 File not found\r\n\r\nHTTP/1.1 503 Server error\r\n\r\n".to_vec()
            },
        );
        let stream_killer_parameters = stream_killer_params.try_recv().unwrap();
        assert_eq!(stream_killer_parameters, (make_meaningless_stream_key(), 3));
    }

    #[tokio::test]
    async fn stream_reader_can_handle_multiple_packets_followed_by_dropped_stream() {
        let (proxy_client, proxy_client_awaiter, proxy_client_recording_arc) = make_recorder();
        let mut stream = ReadHalfWrapperMock::new()
            .read_result(Ok(Vec::from(&b"HTTP/1.1 200"[..])))
            .read_result(Ok(Vec::from(&b" OK\r\n\r\nHTTP/1.1 40"[..])))
            .read_result(Ok(Vec::from(&b"4 File not found\r\n\r\nHTTP/1.1 503 Server error\r\n\r\n"[..])))
            .read_result(Err(Error::from(ErrorKind::BrokenPipe)));
        let (tx, rx) = unbounded();
        thread::spawn(move || {
            let system = System::new();
            let peer_actors = peer_actors_builder().proxy_client(proxy_client).build();
            tx.send(peer_actors.proxy_client_opt.unwrap().inbound_server_data)
                .expect("Internal Error");

            system.run().unwrap();
        });
        let proxy_client_sub = rx.recv().unwrap();
        let (stream_killer, stream_killer_params) = unbounded();
        let mut subject = StreamReader {
            stream_key: make_meaningless_stream_key(),
            proxy_client_sub,
            stream: Box::new(stream),
            stream_killer,
            peer_addr: SocketAddr::from_str("5.7.9.0:95").unwrap(),
            logger: Logger::new("test"),
            sequencer: Sequencer::new(),
        };

        let result = subject.go().await;

        assert_eq!(result.err().unwrap().kind(), ErrorKind::BrokenPipe);
        proxy_client_awaiter.await_message_count(3);
        let proxy_client_recording = proxy_client_recording_arc.lock().unwrap();
        assert_eq!(
            proxy_client_recording.get_record::<InboundServerData>(0),
            &InboundServerData {
                stream_key: make_meaningless_stream_key(),
                last_data: false,
                sequence_number: 0,
                source: SocketAddr::from_str("5.7.9.0:95").unwrap(),
                data: b"HTTP/1.1 200".to_vec()
            }
        );
        assert_eq!(
            proxy_client_recording.get_record::<InboundServerData>(1),
            &InboundServerData {
                stream_key: make_meaningless_stream_key(),
                last_data: false,
                sequence_number: 1,
                source: SocketAddr::from_str("5.7.9.0:95").unwrap(),
                data: b" OK\r\n\r\nHTTP/1.1 40".to_vec()
            }
        );
        assert_eq!(
            proxy_client_recording.get_record::<InboundServerData>(2),
            &InboundServerData {
                stream_key: make_meaningless_stream_key(),
                last_data: false,
                sequence_number: 2,
                source: SocketAddr::from_str("5.7.9.0:95").unwrap(),
                data: b"4 File not found\r\n\r\nHTTP/1.1 503 Server error\r\n\r\n".to_vec()
            }
        );

        let kill_stream_msg = stream_killer_params
            .try_recv()
            .expect("stream was not killed");
        assert_eq!(kill_stream_msg, (make_meaningless_stream_key(), 3));
        assert!(stream_killer_params.try_recv().is_err());
    }

    #[tokio::test]
    async fn receiving_0_bytes_kills_stream() {
        init_test_logging();
        let stream_key = make_meaningless_stream_key();
        let (stream_killer, kill_stream_params) = unbounded();
        let mut stream = ReadHalfWrapperMock::new()
            .read_result(Ok(vec![]));

        let system = System::new();
        let peer_actors = peer_actors_builder().build();
        let mut sequencer = Sequencer::new();
        sequencer.next_sequence_number();
        sequencer.next_sequence_number();

        let mut subject = StreamReader {
            stream_key,
            proxy_client_sub: peer_actors.proxy_client_opt.unwrap().inbound_server_data,
            stream: Box::new(stream),
            stream_killer,
            peer_addr: SocketAddr::from_str("5.3.4.3:654").unwrap(),
            logger: Logger::new("test"),
            sequencer,
        };
        System::current().stop_with_code(0);
        system.run().unwrap();

        let result = subject.go().await;

        let _ = result.unwrap(); // no panic; result is Ok(())
        assert_eq!(kill_stream_params.try_recv().unwrap(), (stream_key, 2));
        TestLogHandler::new()
            .exists_log_containing("Stream from 5.3.4.3:654 was closed: (0-byte read)");
    }

    #[tokio::test]
    async fn non_dead_stream_read_errors_log_but_do_not_shut_down() {
        init_test_logging();
        let (proxy_client, proxy_client_awaiter, proxy_client_recording_arc) = make_recorder();
        let stream_key = make_meaningless_stream_key();
        let (stream_killer, _) = unbounded();
        let mut stream = ReadHalfWrapperMock::new()
            .read_result(Err(Error::from(ErrorKind::Other)))
            .read_result(Ok(b"HTTP/1.1 200 OK\r\n\r\n".to_vec()))
            .read_result(Err(Error::from(ErrorKind::BrokenPipe)));

        let (tx, rx) = unbounded();

        thread::spawn(move || {
            let system = System::new();
            let peer_actors = peer_actors_builder().proxy_client(proxy_client).build();

            tx.send(peer_actors.proxy_client_opt.unwrap().inbound_server_data)
                .expect("Internal Error");
            system.run().unwrap();
        });

        let proxy_client_sub = rx.recv().unwrap();
        let mut subject = StreamReader {
            stream_key,
            proxy_client_sub,
            stream: Box::new(stream),
            stream_killer,
            peer_addr: SocketAddr::from_str("6.5.4.1:8325").unwrap(),
            logger: Logger::new("test"),
            sequencer: Sequencer::new(),
        };

        let result = subject.go().await;

        assert_eq!(result.err().unwrap().kind(), ErrorKind::BrokenPipe);
        proxy_client_awaiter.await_message_count(1);
        TestLogHandler::new().exists_log_containing(
            "WARN: test: Continuing after read error on stream from 6.5.4.1:8325: other error",
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
