// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
use crate::sub_lib::channel_wrappers::ReceiverWrapper;
use crate::sub_lib::sequence_buffer::SequenceBuffer;
use crate::sub_lib::sequence_buffer::SequencedPacket;
use crate::sub_lib::stream_key::StreamKey;
use crate::sub_lib::tokio_wrappers::WriteHalfWrapper;
use crate::sub_lib::utils::indicates_dead_stream;
use masq_lib::logger::Logger;
use std::net::SocketAddr;
use tokio::prelude::Async;
use tokio::prelude::Future;

pub struct StreamWriter {
    stream: Box<dyn WriteHalfWrapper>,
    peer_addr: SocketAddr,
    logger: Logger,
    sequence_buffer: SequenceBuffer,
    rx_to_write: Box<dyn ReceiverWrapper<SequencedPacket>>,
    shutting_down: bool,
}

impl Future for StreamWriter {
    type Item = ();
    type Error = ();

    fn poll(&mut self) -> Result<Async<<Self as Future>::Item>, <Self as Future>::Error> {
        if self.shutting_down {
            return self.shutdown();
        }

        let read_result = self.read_data_from_channel();
        let write_result = self.write_from_buffer_to_stream();

        match (read_result, write_result) {
            (_, Err(_)) => Err(()),
            (Ok(Async::NotReady), _) => Ok(Async::NotReady),
            _ => write_result,
        }
    }
}

impl StreamWriter {
    pub fn new(
        stream: Box<dyn WriteHalfWrapper>,
        peer_addr: SocketAddr,
        rx_to_write: Box<dyn ReceiverWrapper<SequencedPacket>>,
        stream_key: StreamKey,
    ) -> StreamWriter {
        let name = format!("StreamWriter for {:?}/{}", stream_key, peer_addr);
        let logger = Logger::new(&name[..]);
        StreamWriter {
            stream,
            peer_addr,
            logger,
            sequence_buffer: SequenceBuffer::new(),
            rx_to_write,
            shutting_down: false,
        }
    }

    fn shutdown(&mut self) -> Result<Async<()>, ()> {
        match self.stream.shutdown() {
            Ok(Async::NotReady) => Ok(Async::NotReady),
            Ok(Async::Ready(())) => Ok(Async::Ready(())),
            Err(_) => Err(()),
        }
    }

    fn read_data_from_channel(&mut self) -> Result<Async<()>, ()> {
        loop {
            match self.rx_to_write.poll() {
                Ok(Async::Ready(Some(sequenced_packet))) => {
                    self.sequence_buffer.push(sequenced_packet);
                }
                Ok(Async::Ready(None)) => return Ok(Async::Ready(())),
                Ok(Async::NotReady) => return Ok(Async::NotReady),
                Err(e) => panic!(
                    "got an error from an unbounded channel which cannot return error: {:?}",
                    e
                ),
            };
        }
    }

    fn write_from_buffer_to_stream(&mut self) -> Result<Async<()>, ()> {
        loop {
            let packet_opt = self.sequence_buffer.poll();

            match packet_opt {
                Some(packet) => {
                    debug!(
                        self.logger,
                        "Writing {} bytes from packet {}{} over existing stream",
                        packet.data.len(),
                        packet.sequence_number,
                        if packet.last_data {" (last data)"} else {""}
                    );
                    match self.stream.poll_write(&packet.data) {
                        Err(e) => {
                            if indicates_dead_stream(e.kind()) {
                                error!(
                                    self.logger,
                                    "Error writing {} bytes from packet {}{}: {}",
                                    packet.data.len(),
                                    packet.sequence_number,
                                    if packet.last_data {" (last data)"} else {""},
                                    e
                                );
                                return Err(());
                            } else {
                                // TODO this could be exploitable and inefficient: if we keep getting non-dead-stream errors, we go into a tight loop and do not return
                                warning!(self.logger, "Continuing after write error: {}", e);
                                self.sequence_buffer.repush(packet);
                            }
                        }
                        Ok(Async::NotReady) => {
                            self.sequence_buffer.repush(packet);
                            return Ok(Async::NotReady);
                        }
                        Ok(Async::Ready(bytes_written_count)) => {
                            debug!(
                                self.logger,
                                "Wrote {}/{} bytes of clear data (#{})",
                                bytes_written_count,
                                &packet.data.len(),
                                &packet.sequence_number
                            );
                            if bytes_written_count != packet.data.len() {
                                debug!(
                                    self.logger,
                                    "rescheduling {} bytes",
                                    packet.data.len() - bytes_written_count
                                );
                                self.sequence_buffer.repush(SequencedPacket::new(
                                    packet
                                        .data
                                        .iter()
                                        .skip(bytes_written_count)
                                        .cloned()
                                        .collect(),
                                    packet.sequence_number,
                                    packet.last_data,
                                ));
                            } else if packet.last_data {
                                debug!(self.logger, "Shutting down stream to server at {} in response to client-drop report", self.peer_addr);
                                self.shutting_down = true;
                                return self.shutdown();
                            }
                        }
                    }
                }
                None => return Ok(Async::Ready(())),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::channel_wrapper_mocks::ReceiverWrapperMock;
    use crate::test_utils::tokio_wrapper_mocks::WriteHalfWrapperMock;
    use masq_lib::test_utils::logging::init_test_logging;
    use masq_lib::test_utils::logging::TestLogHandler;
    use std::io::Error;
    use std::io::ErrorKind;
    use std::str::FromStr;
    use std::sync::{Arc, Mutex};
    use std::thread;

    fn thread_id_string() -> String {
        let thread_id_str = format!("{:?}", thread::current().id());
        let thread_id = &thread_id_str[9..(thread_id_str.len() - 1)];
        format!("Thd{}", thread_id)
    }

    #[test]
    fn stream_writer_writes_packets_in_sequenced_order() {
        init_test_logging();
        let packet_a: Vec<u8> = vec![1, 3, 5, 9, 7];
        let packet_b: Vec<u8> = vec![2, 4, 10, 8, 6, 3];
        let packet_c: Vec<u8> = vec![1, 0, 1, 2];

        let stream_key = StreamKey::make_meaningless_stream_key();

        let mut rx_to_write = Box::new(ReceiverWrapperMock::new());
        rx_to_write.poll_results = vec![
            Ok(Async::Ready(Some(SequencedPacket {
                data: packet_c.to_vec(),
                sequence_number: 2,
                last_data: false,
            }))),
            Ok(Async::Ready(Some(SequencedPacket {
                data: packet_b.to_vec(),
                sequence_number: 1,
                last_data: false,
            }))),
            Ok(Async::Ready(Some(SequencedPacket {
                data: vec![],
                sequence_number: 3,
                last_data: false,
            }))),
            Ok(Async::Ready(Some(SequencedPacket {
                data: packet_a.to_vec(),
                sequence_number: 0,
                last_data: false,
            }))),
            Ok(Async::Ready(None)),
        ];

        let writer = WriteHalfWrapperMock::new()
            .poll_write_result(Ok(Async::Ready(packet_a.len())))
            .poll_write_result(Ok(Async::Ready(packet_b.len())))
            .poll_write_result(Ok(Async::Ready(packet_c.len())))
            .poll_write_result(Ok(Async::Ready(0)));

        let write_params_mutex = writer.poll_write_params.clone();
        let peer_addr = SocketAddr::from_str("2.2.3.4:5678").unwrap();

        let mut subject = StreamWriter::new(Box::new(writer), peer_addr, rx_to_write, stream_key);

        let _res = subject.poll();

        let write_params = write_params_mutex.lock().unwrap();

        assert_eq!(write_params[0], packet_a);
        assert_eq!(write_params[1], packet_b);
        assert_eq!(write_params[2], packet_c);
        let empty_packet: Vec<u8> = vec![];
        assert_eq!(write_params[3], empty_packet);

        let tlh = TestLogHandler::new();
        let thread_id = thread_id_string();
        tlh.assert_logs_contain_in_order(vec![
            format!(
                "{}: DEBUG: StreamWriter for {:?}/2.2.3.4:5678: Writing 5 bytes from packet 0 over existing stream",
                thread_id,
                stream_key
            )
            .as_str(),
            format!(
                "{}: DEBUG: StreamWriter for {:?}/2.2.3.4:5678: Wrote 5/5 bytes of clear data",
                thread_id,
                stream_key
            )
            .as_str(),
            format!(
                "{}: DEBUG: StreamWriter for {:?}/2.2.3.4:5678: Writing 6 bytes from packet 1 over existing stream",
                thread_id,
                stream_key
            )
            .as_str(),
            format!(
                "{}: DEBUG: StreamWriter for {:?}/2.2.3.4:5678: Wrote 6/6 bytes of clear data",
                thread_id,
                stream_key
            )
            .as_str(),
            format!(
                "{}: DEBUG: StreamWriter for {:?}/2.2.3.4:5678: Writing 4 bytes from packet 2 over existing stream",
                thread_id,
                stream_key
            )
            .as_str(),
            format!(
                "{}: DEBUG: StreamWriter for {:?}/2.2.3.4:5678: Wrote 4/4 bytes of clear data",
                thread_id,
                stream_key
            )
            .as_str(),
            format!(
                "{}: DEBUG: StreamWriter for {:?}/2.2.3.4:5678: Writing 0 bytes from packet 3 over existing stream",
                thread_id,
                stream_key
            )
            .as_str(),
            format!(
                "{}: DEBUG: StreamWriter for {:?}/2.2.3.4:5678: Wrote 0/0 bytes of clear data",
                thread_id,
                stream_key
            )
            .as_str(),
        ]);
    }

    #[test]
    fn stream_writer_returns_not_ready_when_the_stream_is_not_ready() {
        let stream_key = StreamKey::make_meaningless_stream_key();
        let mut rx_to_write = Box::new(ReceiverWrapperMock::new());
        rx_to_write.poll_results = vec![
            Ok(Async::Ready(Some(SequencedPacket {
                data: b"These are the times".to_vec(),
                sequence_number: 0,
                last_data: false,
            }))),
            Ok(Async::Ready(None)),
        ];
        let writer = WriteHalfWrapperMock::new().poll_write_result(Ok(Async::NotReady));

        let write_params = writer.poll_write_params.clone();

        let mut subject = StreamWriter::new(
            Box::new(writer),
            SocketAddr::from_str("1.3.3.4:5678").unwrap(),
            rx_to_write,
            stream_key,
        );

        let result = subject.poll();

        assert_eq!(result, Ok(Async::NotReady));
        assert_eq!(write_params.lock().unwrap().len(), 1);
    }

    #[test]
    fn stream_writer_returns_not_ready_when_the_channel_is_not_ready() {
        let mut rx_to_write = Box::new(ReceiverWrapperMock::new());
        rx_to_write.poll_results = vec![Ok(Async::NotReady)];
        let stream_key = StreamKey::make_meaningless_stream_key();
        let writer = WriteHalfWrapperMock::new().poll_write_result(Ok(Async::Ready(5)));

        let mut subject = StreamWriter::new(
            Box::new(writer),
            SocketAddr::from_str("1.2.4.4:5678").unwrap(),
            rx_to_write,
            stream_key,
        );

        let result = subject.poll();

        assert_eq!(result, Ok(Async::NotReady));
    }

    #[test]
    fn stream_writer_logs_error_and_continues_when_it_gets_a_non_dead_stream_error() {
        init_test_logging();
        let text_data = b"These are the times";
        let stream_key = StreamKey::make_meaningless_stream_key();

        let mut rx_to_write = Box::new(ReceiverWrapperMock::new());
        rx_to_write.poll_results = vec![
            Ok(Async::Ready(Some(SequencedPacket {
                data: text_data.to_vec(),
                sequence_number: 0,
                last_data: false,
            }))),
            Ok(Async::NotReady),
        ];
        let writer = WriteHalfWrapperMock::new()
            .poll_write_result(Err(Error::from(ErrorKind::Other)))
            .poll_write_result(Ok(Async::Ready(text_data.len())))
            .poll_write_result(Ok(Async::NotReady));

        let write_params = writer.poll_write_params.clone();
        let peer_addr = SocketAddr::from_str("1.3.3.4:5678").unwrap();

        let mut subject = StreamWriter::new(Box::new(writer), peer_addr, rx_to_write, stream_key);

        subject.poll().unwrap();

        assert_eq!(write_params.lock().unwrap().len(), 2);
        let tlh = TestLogHandler::new();
        tlh.assert_logs_contain_in_order(vec!(
            format!("DEBUG: StreamWriter for {:?}/1.3.3.4:5678: Writing 19 bytes from packet 0 over existing stream", stream_key).as_str (),
            format!("WARN: StreamWriter for {:?}/1.3.3.4:5678: Continuing after write error: other error", stream_key).as_str (),
            format!("DEBUG: StreamWriter for {:?}/1.3.3.4:5678: Wrote 19/19 bytes of clear data", stream_key).as_str ()));
    }

    #[test]
    fn stream_writer_attempts_to_write_until_successful_before_reading_new_messages_from_channel() {
        let stream_key = StreamKey::make_meaningless_stream_key();
        let first_data = &b"These are the times"[..];
        let second_data = &b"These are the other times"[..];

        let mut rx_to_write = Box::new(ReceiverWrapperMock::new());
        rx_to_write.poll_results = vec![
            Ok(Async::Ready(Some(SequencedPacket {
                data: first_data.to_vec(),
                sequence_number: 0,
                last_data: false,
            }))),
            Ok(Async::Ready(Some(SequencedPacket {
                data: second_data.to_vec(),
                sequence_number: 1,
                last_data: false,
            }))),
            Ok(Async::NotReady),
        ];
        let writer = WriteHalfWrapperMock::new()
            .poll_write_result(Err(Error::from(ErrorKind::Other)))
            .poll_write_result(Ok(Async::Ready(first_data.len())))
            .poll_write_result(Ok(Async::Ready(second_data.len())))
            .poll_write_result(Ok(Async::NotReady));

        let write_params = writer.poll_write_params.clone();
        let peer_addr = SocketAddr::from_str("1.2.3.9:5678").unwrap();

        let mut subject = StreamWriter::new(Box::new(writer), peer_addr, rx_to_write, stream_key);

        let result = subject.poll();

        assert_eq!(result.is_ok(), true);

        let mut params = write_params.lock().unwrap();
        assert_eq!(params.len(), 3);
        assert_eq!(params.remove(0), first_data.to_vec());
        assert_eq!(params.remove(0), first_data.to_vec());
        assert_eq!(params.remove(0), second_data.to_vec());
    }

    #[test]
    fn stream_writer_exits_if_channel_is_closed() {
        let stream_key = StreamKey::make_meaningless_stream_key();
        let mut rx_to_write = Box::new(ReceiverWrapperMock::new());
        rx_to_write.poll_results = vec![
            Ok(Async::Ready(Some(SequencedPacket {
                data: b"These are the times".to_vec(),
                sequence_number: 0,
                last_data: false,
            }))),
            Ok(Async::Ready(None)),
        ];
        let writer = WriteHalfWrapperMock::new().poll_write_result(Ok(Async::Ready(19)));

        let peer_addr = SocketAddr::from_str("1.2.3.4:999").unwrap();

        let mut subject = StreamWriter::new(Box::new(writer), peer_addr, rx_to_write, stream_key);

        let result = subject.poll();

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Async::Ready(()));
    }

    #[test]
    #[should_panic(expected = "got an error from an unbounded channel which cannot return error")]
    fn stream_writer_panics_if_channel_returns_err() {
        let mut rx_to_write = Box::new(ReceiverWrapperMock::new());
        rx_to_write.poll_results = vec![Err(())];
        let writer = WriteHalfWrapperMock::new();

        let stream_key = StreamKey::make_meaningless_stream_key();
        let peer_addr = SocketAddr::from_str("4.2.3.4:5678").unwrap();

        let mut subject = StreamWriter::new(Box::new(writer), peer_addr, rx_to_write, stream_key);

        subject.poll().unwrap();
    }

    #[test]
    fn dead_stream_error_generates_log_and_returns_err() {
        init_test_logging();

        let stream_key = StreamKey::make_meaningless_stream_key();
        let mut rx_to_write = Box::new(ReceiverWrapperMock::new());
        rx_to_write.poll_results = vec![
            Ok(Async::Ready(Some(SequencedPacket {
                data: b"These are the times".to_vec(),
                sequence_number: 0,
                last_data: false,
            }))),
            Ok(Async::Ready(None)),
        ];
        let writer =
            WriteHalfWrapperMock::new().poll_write_result(Err(Error::from(ErrorKind::BrokenPipe)));

        let mut subject = StreamWriter::new(
            Box::new(writer),
            SocketAddr::from_str("2.3.4.5:80").unwrap(),
            rx_to_write,
            stream_key,
        );

        assert!(subject.poll().is_err());

        TestLogHandler::new().exists_log_containing(
            format!(
                "ERROR: StreamWriter for {:?}/2.3.4.5:80: Error writing 19 bytes from packet 0: broken pipe",
                stream_key
            )
            .as_str(),
        );
    }

    #[test]
    fn stream_writer_reattempts_writing_packets_that_were_prevented_by_not_ready() {
        let stream_key = StreamKey::make_meaningless_stream_key();
        let mut rx = Box::new(ReceiverWrapperMock::new());
        rx.poll_results = vec![
            Ok(Async::Ready(Some(SequencedPacket {
                data: b"These are the times".to_vec(),
                sequence_number: 0,
                last_data: false,
            }))),
            Ok(Async::NotReady),
            Ok(Async::NotReady),
        ];

        let writer = WriteHalfWrapperMock::new()
            .poll_write_result(Ok(Async::NotReady))
            .poll_write_result(Ok(Async::Ready(19)))
            .poll_write_result(Ok(Async::NotReady));

        let write_params = writer.poll_write_params.clone();
        let peer_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();

        let mut subject = StreamWriter::new(Box::new(writer), peer_addr, rx, stream_key);

        let result = subject.poll();
        assert_eq!(result, Ok(Async::NotReady));

        let result = subject.poll();
        assert_eq!(result, Ok(Async::NotReady));

        assert_eq!(write_params.lock().unwrap().len(), 2);
    }

    #[test]
    fn stream_writer_resubmits_partial_packet_when_written_len_is_less_than_packet_len() {
        let stream_key = StreamKey::make_meaningless_stream_key();
        let mut rx = Box::new(ReceiverWrapperMock::new());
        rx.poll_results = vec![
            Ok(Async::Ready(Some(SequencedPacket::new(
                b"worlds".to_vec(),
                0,
                false,
            )))),
            Ok(Async::NotReady),
            Ok(Async::NotReady),
            Ok(Async::NotReady),
        ];

        let writer = WriteHalfWrapperMock::new()
            .poll_write_result(Ok(Async::Ready(3)))
            .poll_write_result(Ok(Async::Ready(2)))
            .poll_write_result(Ok(Async::Ready(1)))
            .poll_write_result(Ok(Async::NotReady));

        let write_params = writer.poll_write_params.clone();
        let peer_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();

        let mut subject = StreamWriter::new(Box::new(writer), peer_addr, rx, stream_key);

        let result = subject.poll();
        assert_eq!(result, Ok(Async::NotReady));

        assert_eq!(write_params.lock().unwrap().len(), 3);
        assert_eq!(
            write_params.lock().unwrap().get(0).unwrap(),
            &b"worlds".to_vec()
        );
        assert_eq!(
            write_params.lock().unwrap().get(1).unwrap(),
            &b"lds".to_vec()
        );
        assert_eq!(write_params.lock().unwrap().get(2).unwrap(), &b"s".to_vec());
    }

    #[test]
    fn stream_writer_shuts_down_stream_after_writing_last_data() {
        init_test_logging();
        let packet_a: Vec<u8> = vec![1, 3, 5, 9, 7];

        let stream_key = StreamKey::make_meaningless_stream_key();

        let mut rx_to_write = Box::new(ReceiverWrapperMock::new());
        rx_to_write.poll_results = vec![
            Ok(Async::Ready(Some(SequencedPacket {
                data: packet_a.to_vec(),
                sequence_number: 0,
                last_data: true,
            }))),
            Ok(Async::Ready(None)),
        ];

        let writer = WriteHalfWrapperMock {
            poll_write_params: Arc::new(Mutex::new(vec![])),
            poll_write_results: vec![Ok(Async::Ready(packet_a.len()))],
            shutdown_results: Arc::new(Mutex::new(vec![Ok(Async::Ready(()))])),
        };
        let shutdown_remainder = writer.shutdown_results.clone();
        let write_params_mutex = writer.poll_write_params.clone();
        let peer_addr = SocketAddr::from_str("2.2.3.4:5678").unwrap();

        let mut subject = StreamWriter::new(Box::new(writer), peer_addr, rx_to_write, stream_key);

        let res = subject.poll();

        let write_params = write_params_mutex.lock().unwrap();

        assert_eq!(write_params[0], packet_a);

        let tlh = TestLogHandler::new();
        tlh.assert_logs_contain_in_order(vec![
            format!(
                "DEBUG: StreamWriter for {:?}/2.2.3.4:5678: Writing 5 bytes from packet 0 (last data) over existing stream",
                stream_key
            )
            .as_str(),
            format!(
                "DEBUG: StreamWriter for {:?}/2.2.3.4:5678: Wrote 5/5 bytes of clear data",
                stream_key
            )
            .as_str(),
        ]);

        assert_eq!(res, Ok(Async::Ready(())));
        assert_eq!(shutdown_remainder.lock().unwrap().len(), 0);
    }

    #[test]
    fn stream_writer_returns_not_ready_when_shutdown_is_not_ready_and_retries_on_next_poll() {
        init_test_logging();
        let packet_a: Vec<u8> = vec![1, 3, 5, 9, 7];

        let stream_key = StreamKey::make_meaningless_stream_key();

        let mut rx_to_write = Box::new(ReceiverWrapperMock::new());
        rx_to_write.poll_results = vec![
            Ok(Async::Ready(Some(SequencedPacket {
                data: packet_a.to_vec(),
                sequence_number: 0,
                last_data: true,
            }))),
            Ok(Async::Ready(None)),
        ];

        let writer = WriteHalfWrapperMock {
            poll_write_params: Arc::new(Mutex::new(vec![])),
            poll_write_results: vec![Ok(Async::Ready(packet_a.len()))],
            shutdown_results: Arc::new(Mutex::new(vec![Ok(Async::NotReady), Ok(Async::Ready(()))])),
        };

        let shutdown_remainder = writer.shutdown_results.clone();
        let write_params_mutex = writer.poll_write_params.clone();
        let peer_addr = SocketAddr::from_str("2.2.3.4:5678").unwrap();

        let mut subject = StreamWriter::new(Box::new(writer), peer_addr, rx_to_write, stream_key);

        let res = subject.poll();

        let write_params = write_params_mutex.lock().unwrap();

        assert_eq!(write_params[0], packet_a);

        let tlh = TestLogHandler::new();
        tlh.assert_logs_contain_in_order(vec![
            format!(
                "DEBUG: StreamWriter for {:?}/2.2.3.4:5678: Writing 5 bytes from packet 0 (last data) over existing stream",
                stream_key
            )
            .as_str(),
            format!(
                "DEBUG: StreamWriter for {:?}/2.2.3.4:5678: Wrote 5/5 bytes of clear data",
                stream_key
            )
            .as_str(),
        ]);

        assert_eq!(res, Ok(Async::NotReady));
        assert_eq!(shutdown_remainder.lock().unwrap().len(), 1);

        let res = subject.poll();
        assert_eq!(res, Ok(Async::Ready(())));
        assert_eq!(shutdown_remainder.lock().unwrap().len(), 0);
    }

    #[test]
    fn stream_writer_returns_error_when_shutdown_returns_error() {
        init_test_logging();
        let packet_a: Vec<u8> = vec![1, 3, 5, 9, 7];

        let stream_key = StreamKey::make_meaningless_stream_key();

        let mut rx_to_write = Box::new(ReceiverWrapperMock::new());
        rx_to_write.poll_results = vec![
            Ok(Async::Ready(Some(SequencedPacket {
                data: packet_a.to_vec(),
                sequence_number: 0,
                last_data: true,
            }))),
            Ok(Async::Ready(None)),
        ];

        let writer = WriteHalfWrapperMock::new()
            .poll_write_result(Ok(Async::Ready(packet_a.len())))
            .shutdown_result(Err(Error::from(ErrorKind::Other)));

        let write_params_mutex = writer.poll_write_params.clone();
        let peer_addr = SocketAddr::from_str("2.2.3.4:5678").unwrap();

        let mut subject = StreamWriter::new(Box::new(writer), peer_addr, rx_to_write, stream_key);

        let res = subject.poll();

        let write_params = write_params_mutex.lock().unwrap();

        assert_eq!(write_params[0], packet_a);

        let tlh = TestLogHandler::new();
        tlh.assert_logs_contain_in_order(vec![
            format!(
                "DEBUG: StreamWriter for {:?}/2.2.3.4:5678: Writing 5 bytes from packet 0 (last data) over existing stream",
                stream_key
            )
            .as_str(),
            format!(
                "DEBUG: StreamWriter for {:?}/2.2.3.4:5678: Wrote 5/5 bytes of clear data",
                stream_key
            )
            .as_str(),
        ]);

        assert_eq!(res, Err(()));
    }
}
