// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
use crate::sub_lib::channel_wrappers::ReceiverWrapper;
use crate::sub_lib::sequence_buffer::SequenceBuffer;
use crate::sub_lib::sequence_buffer::SequencedPacket;
use crate::sub_lib::tokio_wrappers::WriteHalfWrapper;
use crate::sub_lib::utils::indicates_dead_stream;
use masq_lib::logger::Logger;
use std::net::SocketAddr;
use tokio::prelude::Async;
use tokio::prelude::Future;

pub struct StreamWriterSorted {
    stream: Box<dyn WriteHalfWrapper>,
    peer_addr: SocketAddr,
    rx_to_write: Box<dyn ReceiverWrapper<SequencedPacket>>,
    logger: Logger,
    sequence_buffer: SequenceBuffer,
    shutting_down: bool,
}

impl Future for StreamWriterSorted {
    type Item = ();
    type Error = ();

    fn poll(&mut self) -> Result<Async<<Self as Future>::Item>, <Self as Future>::Error> {
        if self.shutting_down {
            return self.shutdown();
        }

        let read_result = self.read_data_from_channel();
        let write_result = self.write_from_buffer_to_stream();

        match (read_result, write_result) {
            // read_result can only be NotReady or Ready; write_result can only be Err, NotReady, or Ready
            (_, WriteBufferStatus::StreamInError) => Err(()), // dead stream error, shut down (this must be first in the match)
            (ReadChannelStatus::StillOpen, _) => Ok(Async::NotReady), // may receive more data, don't shut down
            (ReadChannelStatus::Closed, WriteBufferStatus::BufferNotEmpty) => Ok(Async::NotReady), // still have packets to write, don't shut down yet
            (ReadChannelStatus::Closed, WriteBufferStatus::BufferEmpty) => Ok(Async::Ready(())), // all done, shut down
        }
    }
}

impl StreamWriterSorted {
    pub fn new(
        stream: Box<dyn WriteHalfWrapper>,
        peer_addr: SocketAddr,
        rx_to_write: Box<dyn ReceiverWrapper<SequencedPacket>>,
    ) -> StreamWriterSorted {
        let name = format!("StreamWriter for {}", peer_addr);
        let logger = Logger::new(&name[..]);
        StreamWriterSorted {
            stream,
            peer_addr,
            rx_to_write,
            logger,
            sequence_buffer: SequenceBuffer::new(),
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

    fn read_data_from_channel(&mut self) -> ReadChannelStatus {
        loop {
            match self.rx_to_write.poll() {
                Ok(Async::Ready(Some(sequenced_packet))) => {
                    self.sequence_buffer.push(sequenced_packet)
                }
                Ok(Async::Ready(None)) => return ReadChannelStatus::Closed,
                Ok(Async::NotReady) => return ReadChannelStatus::StillOpen,
                Err(e) => panic!(
                    "got an error from an unbounded channel which cannot return error: {:?}",
                    e
                ),
            }
        }
    }

    fn write_from_buffer_to_stream(&mut self) -> WriteBufferStatus {
        loop {
            let packet_opt = self.sequence_buffer.poll();

            match packet_opt {
                Some(packet) => {
                    match self.stream.poll_write(&packet.data) {
                        Err(e) => {
                            if indicates_dead_stream(e.kind()) {
                                error!(
                                    self.logger,
                                    "Error writing {} bytes to {}: {}",
                                    packet.data.len(),
                                    self.peer_addr,
                                    e
                                );
                                return WriteBufferStatus::StreamInError;
                            } else {
                                // TODO this could be exploitable and inefficient: if we keep getting non-dead-stream errors, we go into a tight loop and do not return
                                warning!(self.logger, "Continuing after write error: {}", e);
                                self.sequence_buffer.repush(packet);
                            }
                        }
                        Ok(Async::NotReady) => {
                            self.sequence_buffer.repush(packet);
                            return WriteBufferStatus::BufferNotEmpty;
                        }
                        Ok(Async::Ready(len)) => {
                            debug!(
                                self.logger,
                                "Wrote {}/{} bytes of clear data (#{})",
                                len,
                                &packet.data.len(),
                                &packet.sequence_number
                            );
                            if len != packet.data.len() {
                                debug!(
                                    self.logger,
                                    "rescheduling {} bytes",
                                    packet.data.len() - len
                                );
                                self.sequence_buffer.repush(SequencedPacket::new(
                                    packet.data.iter().skip(len).cloned().collect(),
                                    packet.sequence_number,
                                    packet.last_data,
                                ));
                            } else if packet.last_data {
                                debug!(self.logger, "Shutting down stream to client at {} in response to server-drop report", self.peer_addr);
                                self.shutting_down = true;
                                return match self.stream.shutdown() {
                                    Ok(Async::NotReady) => WriteBufferStatus::BufferNotEmpty,
                                    Ok(Async::Ready(())) => WriteBufferStatus::BufferEmpty,
                                    Err(_) => WriteBufferStatus::StreamInError,
                                };
                            }
                        }
                    }
                }
                None => return WriteBufferStatus::BufferEmpty,
            }
        }
    }
}

enum ReadChannelStatus {
    StillOpen,
    Closed,
}

enum WriteBufferStatus {
    StreamInError,
    BufferNotEmpty,
    BufferEmpty,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sub_lib::sequence_buffer::SequencedPacket;
    use crate::test_utils::channel_wrapper_mocks::ReceiverWrapperMock;
    use crate::test_utils::tokio_wrapper_mocks::WriteHalfWrapperMock;
    use masq_lib::test_utils::logging::init_test_logging;
    use masq_lib::test_utils::logging::TestLogHandler;
    use std::io;
    use std::io::ErrorKind;
    use std::net::SocketAddr;
    use std::str::FromStr;
    use std::sync::{Arc, Mutex};

    #[test]
    fn stream_writer_returns_not_ready_when_the_stream_is_not_ready() {
        let mut rx = Box::new(ReceiverWrapperMock::new());
        rx.poll_results = vec![
            Ok(Async::Ready(Some(SequencedPacket::new(
                b"hello".to_vec(),
                0,
                false,
            )))),
            Ok(Async::Ready(Some(SequencedPacket::new(
                b"world".to_vec(),
                1,
                false,
            )))),
            Ok(Async::Ready(None)),
        ];

        let writer = WriteHalfWrapperMock::new().poll_write_result(Ok(Async::NotReady));
        let write_params = writer.poll_write_params.clone();
        let peer_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();

        let mut subject = StreamWriterSorted::new(Box::new(writer), peer_addr, rx);

        let result = subject.poll();

        assert_eq!(result, Ok(Async::NotReady));
        assert_eq!(write_params.lock().unwrap().len(), 1);
    }

    #[test]
    fn stream_writer_returns_not_ready_when_the_channel_is_not_ready() {
        let mut rx = Box::new(ReceiverWrapperMock::new());
        rx.poll_results = vec![Ok(Async::NotReady)];

        let writer = WriteHalfWrapperMock::new().poll_write_result(Ok(Async::Ready(5)));
        let peer_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();

        let mut subject = StreamWriterSorted::new(Box::new(writer), peer_addr, rx);

        let result = subject.poll();

        assert_eq!(result, Ok(Async::NotReady));
    }

    #[test]
    fn stream_writer_logs_and_returns_err_when_it_gets_a_dead_stream_error() {
        init_test_logging();
        let mut rx = Box::new(ReceiverWrapperMock::new());
        rx.poll_results = vec![
            Ok(Async::Ready(Some(SequencedPacket::new(
                b"hello".to_vec(),
                0,
                false,
            )))),
            Ok(Async::Ready(Some(SequencedPacket::new(
                b"world".to_vec(),
                0,
                false,
            )))),
            Ok(Async::NotReady),
        ];
        let writer = WriteHalfWrapperMock::new()
            .poll_write_result(Err(io::Error::from(ErrorKind::BrokenPipe)));
        let write_params = writer.poll_write_params.clone();
        let peer_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();

        let mut subject = StreamWriterSorted::new(Box::new(writer), peer_addr.clone(), rx);

        let result = subject.poll();

        assert_eq!(result.is_ok(), false);
        assert_eq!(write_params.lock().unwrap().len(), 1);
        TestLogHandler::new()
            .await_log_containing("Error writing 5 bytes to 1.2.3.4:5678: broken pipe", 1000);
    }

    #[test]
    fn stream_writer_logs_error_and_continues_when_it_gets_a_non_dead_stream_error() {
        init_test_logging();
        let mut rx = Box::new(ReceiverWrapperMock::new());
        rx.poll_results = vec![
            Ok(Async::Ready(Some(SequencedPacket::new(
                b"hello".to_vec(),
                0,
                false,
            )))),
            Ok(Async::Ready(Some(SequencedPacket::new(
                b"world".to_vec(),
                1,
                false,
            )))),
            Ok(Async::NotReady),
        ];
        let writer = WriteHalfWrapperMock::new()
            .poll_write_result(Err(io::Error::from(ErrorKind::Other)))
            .poll_write_result(Ok(Async::Ready(5)))
            .poll_write_result(Ok(Async::NotReady));
        let write_params = writer.poll_write_params.clone();
        let peer_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();

        let mut subject = StreamWriterSorted::new(Box::new(writer), peer_addr.clone(), rx);

        subject.poll().unwrap();

        TestLogHandler::new().exists_log_containing(
            "WARN: StreamWriter for 1.2.3.4:5678: Continuing after write error: other error",
        );
        assert_eq!(write_params.lock().unwrap().len(), 3);
    }

    #[test]
    fn stream_writer_writes_to_stream_and_does_not_shut_down() {
        let first_data = b"hello";
        let second_data = b"world";
        let mut rx = Box::new(ReceiverWrapperMock::new());
        rx.poll_results = vec![
            Ok(Async::Ready(Some(SequencedPacket::new(
                first_data.to_vec(),
                0,
                false,
            )))),
            Ok(Async::Ready(Some(SequencedPacket::new(
                second_data.to_vec(),
                1,
                false,
            )))),
            Ok(Async::NotReady),
        ];
        let writer = WriteHalfWrapperMock::new()
            .poll_write_result(Ok(Async::Ready(first_data.len())))
            .poll_write_result(Ok(Async::Ready(second_data.len())));
        let write_params = writer.poll_write_params.clone();
        let peer_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();

        let mut subject = StreamWriterSorted::new(Box::new(writer), peer_addr.clone(), rx);

        let result = subject.poll();

        assert_eq!(result.is_ok(), true);

        let mut params = write_params.lock().unwrap();
        assert_eq!(params.len(), 2);
        assert_eq!(params.remove(0), first_data.to_vec());
        assert_eq!(params.remove(0), second_data.to_vec());
    }

    #[test]
    fn stream_writer_writes_packets_to_stream_in_order_and_does_not_shut_down() {
        let first_data = b"hello";
        let second_data = b"world";
        let third_data = b"!";
        let mut rx = Box::new(ReceiverWrapperMock::new());
        rx.poll_results = vec![
            Ok(Async::Ready(Some(SequencedPacket::new(
                third_data.to_vec(),
                2,
                false,
            )))),
            Ok(Async::Ready(Some(SequencedPacket::new(
                second_data.to_vec(),
                1,
                false,
            )))),
            Ok(Async::Ready(Some(SequencedPacket::new(
                first_data.to_vec(),
                0,
                false,
            )))),
            Ok(Async::NotReady),
        ];
        let writer = WriteHalfWrapperMock::new()
            .poll_write_result(Ok(Async::Ready(first_data.len())))
            .poll_write_result(Ok(Async::Ready(second_data.len())))
            .poll_write_result(Ok(Async::Ready(third_data.len())));
        let write_params = writer.poll_write_params.clone();
        let peer_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();

        let mut subject = StreamWriterSorted::new(Box::new(writer), peer_addr.clone(), rx);

        let result = subject.poll();

        assert_eq!(result.is_ok(), true);

        let mut params = write_params.lock().unwrap();
        assert_eq!(params.len(), 3);
        assert_eq!(params.remove(0), first_data.to_vec());
        assert_eq!(params.remove(0), second_data.to_vec());
        assert_eq!(params.remove(0), third_data.to_vec());
    }

    #[test]
    fn stream_writer_attempts_to_write_until_successful_before_reading_new_messages_from_channel() {
        let first_data = b"hello";
        let second_data = b"worlds";
        let mut rx = Box::new(ReceiverWrapperMock::new());
        rx.poll_results = vec![
            Ok(Async::Ready(Some(SequencedPacket::new(
                first_data.to_vec(),
                0,
                false,
            )))),
            Ok(Async::Ready(Some(SequencedPacket::new(
                second_data.to_vec(),
                1,
                false,
            )))),
            Ok(Async::NotReady),
        ];
        let writer = WriteHalfWrapperMock::new()
            .poll_write_result(Err(io::Error::from(ErrorKind::Other)))
            .poll_write_result(Ok(Async::Ready(first_data.len())))
            .poll_write_result(Ok(Async::Ready(second_data.len())))
            .poll_write_result(Ok(Async::NotReady));
        let write_params = writer.poll_write_params.clone();
        let peer_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();

        let mut subject = StreamWriterSorted::new(Box::new(writer), peer_addr.clone(), rx);

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
        let mut rx = Box::new(ReceiverWrapperMock::new());
        rx.poll_results = vec![
            Ok(Async::Ready(Some(SequencedPacket::new(
                b"hello".to_vec(),
                0,
                false,
            )))),
            Ok(Async::Ready(None)),
        ];
        let writer = WriteHalfWrapperMock::new()
            .poll_write_result(Ok(Async::Ready(5)))
            .poll_write_result(Err(io::Error::from(ErrorKind::BrokenPipe)));
        let peer_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();

        let mut subject = StreamWriterSorted::new(Box::new(writer), peer_addr.clone(), rx);

        let result = subject.poll();

        assert_eq!(result.is_ok(), true);
    }

    #[test]
    #[should_panic(expected = "got an error from an unbounded channel which cannot return error")]
    fn stream_writer_panics_if_channel_returns_err() {
        let mut rx = Box::new(ReceiverWrapperMock::new());
        rx.poll_results = vec![Err(())];
        let writer = WriteHalfWrapperMock::new();
        let peer_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();

        let mut subject = StreamWriterSorted::new(Box::new(writer), peer_addr.clone(), rx);

        subject.poll().unwrap();
    }

    #[test]
    fn stream_writer_reattempts_writing_packets_that_were_prevented_by_not_ready() {
        let mut rx = Box::new(ReceiverWrapperMock::new());
        rx.poll_results = vec![
            Ok(Async::Ready(Some(SequencedPacket::new(
                b"hello".to_vec(),
                0,
                false,
            )))),
            Ok(Async::NotReady),
            Ok(Async::NotReady),
        ];

        let writer = WriteHalfWrapperMock::new()
            .poll_write_result(Ok(Async::NotReady))
            .poll_write_result(Ok(Async::Ready(5)));
        let write_params = writer.poll_write_params.clone();
        let peer_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();

        let mut subject = StreamWriterSorted::new(Box::new(writer), peer_addr, rx);

        let result = subject.poll();
        assert_eq!(result, Ok(Async::NotReady));

        let result = subject.poll();
        assert_eq!(result, Ok(Async::NotReady));

        assert_eq!(write_params.lock().unwrap().len(), 2);
    }

    #[test]
    fn stream_writer_resubmits_partial_packet_when_written_len_is_less_than_packet_len() {
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

        let mut subject = StreamWriterSorted::new(Box::new(writer), peer_addr, rx);

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
        let packet_a: Vec<u8> = vec![1, 3, 5, 9, 7];

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

        let mut subject = StreamWriterSorted::new(Box::new(writer), peer_addr, rx_to_write);

        let res = subject.poll();

        let write_params = write_params_mutex.lock().unwrap();

        assert_eq!(write_params[0], packet_a);

        assert_eq!(res, Ok(Async::Ready(())));
        assert_eq!(shutdown_remainder.lock().unwrap().len(), 0);
    }

    #[test]
    fn stream_writer_returns_not_ready_when_shutdown_is_not_ready_and_retries_on_next_poll() {
        let packet_a: Vec<u8> = vec![1, 3, 5, 9, 7];

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

        let mut subject = StreamWriterSorted::new(Box::new(writer), peer_addr, rx_to_write);

        let res = subject.poll();

        let write_params = write_params_mutex.lock().unwrap();

        assert_eq!(write_params[0], packet_a);

        assert_eq!(res, Ok(Async::NotReady));
        assert_eq!(shutdown_remainder.lock().unwrap().len(), 1);

        let res = subject.poll();
        assert_eq!(res, Ok(Async::Ready(())));
        assert_eq!(shutdown_remainder.lock().unwrap().len(), 0);
    }

    #[test]
    fn stream_writer_returns_error_when_shutdown_returns_error() {
        let packet_a: Vec<u8> = vec![1, 3, 5, 9, 7];

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
            .shutdown_result(Err(io::Error::from(ErrorKind::Other)));

        let write_params_mutex = writer.poll_write_params.clone();
        let peer_addr = SocketAddr::from_str("2.2.3.4:5678").unwrap();

        let mut subject = StreamWriterSorted::new(Box::new(writer), peer_addr, rx_to_write);

        let res = subject.poll();

        let write_params = write_params_mutex.lock().unwrap();

        assert_eq!(write_params[0], packet_a);

        assert_eq!(res, Err(()));
    }
}
