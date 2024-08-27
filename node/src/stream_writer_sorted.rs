use std::future::Future;
// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
use crate::sub_lib::channel_wrappers::ReceiverWrapper;
use crate::sub_lib::sequence_buffer::SequenceBuffer;
use crate::sub_lib::sequence_buffer::SequencedPacket;
use crate::sub_lib::tokio_wrappers::WriteHalfWrapper;
use crate::sub_lib::utils::indicates_dead_stream;
use masq_lib::logger::Logger;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::AsyncWriteExt;

pub struct StreamWriterSorted {
    stream: Option<Box<dyn WriteHalfWrapper>>,
    peer_addr: SocketAddr,
    rx_to_write: Box<dyn ReceiverWrapper<SequencedPacket>>,
    logger: Logger,
    sequence_buffer: SequenceBuffer,
    shutting_down: bool,
}

impl Future for StreamWriterSorted {
    type Output = Result<(), ()>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if self.shutting_down {
            return self.shutdown(cx);
        }

        let read_result = self.as_mut().read_data_from_channel();
        let write_result = self.as_mut().write_from_buffer_to_stream(cx);

        match (read_result, write_result) {
            // read_result can only be NotReady or Ready; write_result can only be Err, NotReady, or Ready
            (_, WriteBufferStatus::StreamInError) => Poll::Ready(Err(())), // dead stream error, shut down (this must be first in the match)
            (ReadChannelStatus::StillOpen, _) => Poll::Pending, // may receive more data, don't shut down
            (ReadChannelStatus::Closed, WriteBufferStatus::BufferNotEmpty) => Poll::Pending, // still have packets to write, don't shut down yet
            (ReadChannelStatus::Closed, WriteBufferStatus::BufferEmpty) => Poll::Ready(Ok(())), // all done, shut down
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
            stream: Some(stream),
            peer_addr,
            rx_to_write,
            logger,
            sequence_buffer: SequenceBuffer::new(),
            shutting_down: false,
        }
    }

    fn shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let to_shut_down = self.stream.take().expect("Stream was shut down before shutdown");
        match to_shut_down.poll_shutdown(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(_)) => Poll::Ready(Err(())),
        }
    }

    fn read_data_from_channel(self: Pin<&mut Self>) -> ReadChannelStatus {
        loop {
            match self.rx_to_write.poll() {
                Poll::Ready(Ok(Some(sequenced_packet))) => {
                    self.sequence_buffer.push(sequenced_packet)
                }
                Poll::Ready(Ok(None)) => return ReadChannelStatus::Closed,
                Poll::Pending => return ReadChannelStatus::StillOpen,
                Err(e) => panic!(
                    "got an error from an unbounded channel which cannot return error: {:?}",
                    e
                ),
            }
        }
    }

    fn write_from_buffer_to_stream(self: Pin<&mut Self>, cx: &mut Context<'_>) -> WriteBufferStatus {
        loop {
            let packet_opt = self.sequence_buffer.poll();

            match packet_opt {
                Some(packet) => {
                    match self.stream().poll_write(cx, &packet.data) {
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
                        Poll::Pending => {
                            self.sequence_buffer.repush(packet);
                            return WriteBufferStatus::BufferNotEmpty;
                        }
                        Poll::Ready(Ok(len)) => {
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
                                    Poll::Pending => WriteBufferStatus::BufferNotEmpty,
                                    Poll::Ready(Ok(())) => WriteBufferStatus::BufferEmpty,
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

    fn stream(&self) -> &Box<dyn WriteHalfWrapper> {
        &self.stream.as_ref().expect("Stream was accessed after shutdown")
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
            Poll::Ready(Ok(Some(SequencedPacket::new(
                b"hello".to_vec(),
                0,
                false,
            )))),
            Poll::Ready(Ok(Some(SequencedPacket::new(
                b"world".to_vec(),
                1,
                false,
            )))),
            Poll::Ready(Ok(None)),
        ];

        let writer = WriteHalfWrapperMock::new().poll_write_result(Poll::Pending);
        let write_params = writer.poll_write_params.clone();
        let peer_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();

        let mut subject = StreamWriterSorted::new(Box::new(writer), peer_addr, rx);

        let result = subject.poll();

        assert_eq!(result, Poll::Pending);
        assert_eq!(write_params.lock().unwrap().len(), 1);
    }

    #[test]
    fn stream_writer_returns_not_ready_when_the_channel_is_not_ready() {
        let mut rx = Box::new(ReceiverWrapperMock::new());
        rx.poll_results = vec![Poll::Pending];

        let writer = WriteHalfWrapperMock::new().poll_write_result(Poll::Ready(Ok(5)));
        let peer_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();

        let mut subject = StreamWriterSorted::new(Box::new(writer), peer_addr, rx);

        let result = subject.poll();

        assert_eq!(result, Poll::Pending);
    }

    #[test]
    fn stream_writer_logs_and_returns_err_when_it_gets_a_dead_stream_error() {
        init_test_logging();
        let mut rx = Box::new(ReceiverWrapperMock::new());
        rx.poll_results = vec![
            Poll::Ready(Ok(Some(SequencedPacket::new(
                b"hello".to_vec(),
                0,
                false,
            )))),
            Poll::Ready(Ok(Some(SequencedPacket::new(
                b"world".to_vec(),
                0,
                false,
            )))),
            Poll::Pending,
        ];
        let writer = WriteHalfWrapperMock::new()
            .poll_write_result(Poll::Ready(Err(io::Error::from(ErrorKind::BrokenPipe))));
        let write_params = writer.poll_write_params.clone();
        let peer_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();

        let mut subject = StreamWriterSorted::new(Box::new(writer), peer_addr.clone(), rx);

        let result = subject.poll();

        assert_eq!(result, Poll::Ready(Err(io::Error::from(ErrorKind::BrokenPipe))));
        assert_eq!(write_params.lock().unwrap().len(), 1);
        TestLogHandler::new()
            .await_log_containing("Error writing 5 bytes to 1.2.3.4:5678: broken pipe", 1000);
    }

    #[test]
    fn stream_writer_logs_error_and_continues_when_it_gets_a_non_dead_stream_error() {
        init_test_logging();
        let mut rx = Box::new(ReceiverWrapperMock::new());
        rx.poll_results = vec![
            Poll::Ready(Ok(Some(SequencedPacket::new(
                b"hello".to_vec(),
                0,
                false,
            )))),
            Poll::Ready(Ok(Some(SequencedPacket::new(
                b"world".to_vec(),
                1,
                false,
            )))),
            Poll::Pending,
        ];
        let writer = WriteHalfWrapperMock::new()
            .poll_write_result(Poll::Ready(Err(io::Error::from(ErrorKind::Other))))
            .poll_write_result(Poll::Ready(Ok(5)))
            .poll_write_result(Poll::Pending);
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
            Poll::Ready(Ok(Some(SequencedPacket::new(
                first_data.to_vec(),
                0,
                false,
            )))),
            Poll::Ready(Ok(Some(SequencedPacket::new(
                second_data.to_vec(),
                1,
                false,
            )))),
            Poll::Pending,
        ];
        let writer = WriteHalfWrapperMock::new()
            .poll_write_result(Poll::Ready(Ok(first_data.len())))
            .poll_write_result(Poll::Ready(Ok(second_data.len())));
        let write_params = writer.poll_write_params.clone();
        let peer_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();

        let mut subject = StreamWriterSorted::new(Box::new(writer), peer_addr.clone(), rx);

        let result = subject.poll();

        assert_eq!(result, Poll::Ready(()));
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
            Poll::Ready(Ok(Some(SequencedPacket::new(
                third_data.to_vec(),
                2,
                false,
            )))),
            Poll::Ready(Ok(Some(SequencedPacket::new(
                second_data.to_vec(),
                1,
                false,
            )))),
            Poll::Ready(Ok(Some(SequencedPacket::new(
                first_data.to_vec(),
                0,
                false,
            )))),
            Poll::Pending,
        ];
        let writer = WriteHalfWrapperMock::new()
            .poll_write_result(Poll::Ready(Ok(first_data.len())))
            .poll_write_result(Poll::Ready(Ok(second_data.len())))
            .poll_write_result(Poll::Ready(Ok(third_data.len())));
        let write_params = writer.poll_write_params.clone();
        let peer_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();

        let mut subject = StreamWriterSorted::new(Box::new(writer), peer_addr.clone(), rx);

        let result = subject.poll();

        assert_eq!(result, Poll::Ready(()));
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
            Poll::Ready(Ok(Some(SequencedPacket::new(
                first_data.to_vec(),
                0,
                false,
            )))),
            Poll::Ready(Ok(Some(SequencedPacket::new(
                second_data.to_vec(),
                1,
                false,
            )))),
            Poll::Pending,
        ];
        let writer = WriteHalfWrapperMock::new()
            .poll_write_result(Poll::Ready(Err(io::Error::from(ErrorKind::Other))))
            .poll_write_result(Poll::Ready(Ok(first_data.len())))
            .poll_write_result(Poll::Ready(Ok(second_data.len())))
            .poll_write_result(Poll::Pending);
        let write_params = writer.poll_write_params.clone();
        let peer_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();

        let mut subject = StreamWriterSorted::new(Box::new(writer), peer_addr.clone(), rx);

        let result = subject.poll();

        assert_eq!(result, Poll::Ready(()));
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
            Poll::Ready(Ok(Some(SequencedPacket::new(
                b"hello".to_vec(),
                0,
                false,
            )))),
            Poll::Ready(Ok(None)),
        ];
        let writer = WriteHalfWrapperMock::new()
            .poll_write_result(Poll::Ready(Ok(5)))
            .poll_write_result(Poll::Ready(Err(io::Error::from(ErrorKind::BrokenPipe))));
        let peer_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let mut subject = StreamWriterSorted::new(Box::new(writer), peer_addr.clone(), rx);

        let result = subject.poll();

        assert_eq!(result, Poll::Ready(()));
    }

    #[test]
    #[should_panic(expected = "got an error from an unbounded channel which cannot return error")]
    fn stream_writer_panics_if_channel_returns_err() {
        let mut rx = Box::new(ReceiverWrapperMock::new());
        rx.poll_results = vec![Poll::Ready(Err(()))];
        let writer = WriteHalfWrapperMock::new();
        let peer_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();

        let mut subject = StreamWriterSorted::new(Box::new(writer), peer_addr.clone(), rx);

        subject.poll().unwrap();
    }

    #[test]
    fn stream_writer_reattempts_writing_packets_that_were_prevented_by_not_ready() {
        let mut rx = Box::new(ReceiverWrapperMock::new());
        rx.poll_results = vec![
            Poll::Ready(Ok(Some(SequencedPacket::new(
                b"hello".to_vec(),
                0,
                false,
            )))),
            Poll::Pending,
            Poll::Pending,
        ];

        let writer = WriteHalfWrapperMock::new()
            .poll_write_result(Poll::Pending)
            .poll_write_result(Poll::Ready(Ok(5)));
        let write_params = writer.poll_write_params.clone();
        let peer_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();

        let mut subject = StreamWriterSorted::new(Box::new(writer), peer_addr, rx);

        let result = subject.poll();
        assert_eq!(result, Poll::Pending);

        let result = subject.poll();
        assert_eq!(result, Poll::Pending);

        assert_eq!(write_params.lock().unwrap().len(), 2);
    }

    #[test]
    fn stream_writer_resubmits_partial_packet_when_written_len_is_less_than_packet_len() {
        let mut rx = Box::new(ReceiverWrapperMock::new());
        rx.poll_results = vec![
            Poll::Ready(Ok(Some(SequencedPacket::new(
                b"worlds".to_vec(),
                0,
                false,
            )))),
            Poll::Pending,
            Poll::Pending,
            Poll::Pending,
        ];

        let writer = WriteHalfWrapperMock::new()
            .poll_write_result(Poll::Ready(Ok(3)))
            .poll_write_result(Poll::Ready(Ok(2)))
            .poll_write_result(Poll::Ready(Ok(1)))
            .poll_write_result(Poll::Pending);

        let write_params = writer.poll_write_params.clone();
        let peer_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();

        let mut subject = StreamWriterSorted::new(Box::new(writer), peer_addr, rx);

        let result = subject.poll();
        assert_eq!(result, Poll::Pending);

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
            Poll::Ready(Ok(Some(SequencedPacket {
                data: packet_a.to_vec(),
                sequence_number: 0,
                last_data: true,
            }))),
            Poll::Ready(Ok(None)),
        ];

        let writer = WriteHalfWrapperMock {
            poll_write_params: Arc::new(Mutex::new(vec![])),
            poll_write_results: vec![Poll::Ready(Ok(packet_a.len()))],
            poll_close_results: Arc::new(Mutex::new(vec![Poll::Ready(Ok(()))])),
        };
        let shutdown_remainder = writer.poll_close_results.clone();
        let write_params_mutex = writer.poll_write_params.clone();
        let peer_addr = SocketAddr::from_str("2.2.3.4:5678").unwrap();

        let mut subject = StreamWriterSorted::new(Box::new(writer), peer_addr, rx_to_write);

        let res = subject.poll();

        let write_params = write_params_mutex.lock().unwrap();

        assert_eq!(write_params[0], packet_a);

        assert_eq!(res, Poll::Ready(Ok(())));
        assert_eq!(shutdown_remainder.lock().unwrap().len(), 0);
    }

    #[test]
    fn stream_writer_returns_not_ready_when_shutdown_is_not_ready_and_retries_on_next_poll() {
        let packet_a: Vec<u8> = vec![1, 3, 5, 9, 7];

        let mut rx_to_write = Box::new(ReceiverWrapperMock::new());
        rx_to_write.poll_results = vec![
            Poll::Ready(Ok(Some(SequencedPacket {
                data: packet_a.to_vec(),
                sequence_number: 0,
                last_data: true,
            }))),
            Poll::Ready(Ok(None)),
        ];

        let writer = WriteHalfWrapperMock {
            poll_write_params: Arc::new(Mutex::new(vec![])),
            poll_write_results: vec![Poll::Ready(Ok(packet_a.len()))],
            poll_close_results: Arc::new(Mutex::new(vec![
                Poll::Pending,
                Poll::Ready(Ok(())),
            ])),
        };

        let shutdown_remainder = writer.poll_close_results.clone();
        let write_params_mutex = writer.poll_write_params.clone();
        let peer_addr = SocketAddr::from_str("2.2.3.4:5678").unwrap();

        let mut subject = StreamWriterSorted::new(Box::new(writer), peer_addr, rx_to_write);

        let res = subject.poll();

        let write_params = write_params_mutex.lock().unwrap();

        assert_eq!(write_params[0], packet_a);

        assert_eq!(res, Poll::Pending);
        assert_eq!(shutdown_remainder.lock().unwrap().len(), 1);

        let res = subject.poll();
        assert_eq!(res, Poll::Ready(Ok(())));
        assert_eq!(shutdown_remainder.lock().unwrap().len(), 0);
    }

    #[test]
    fn stream_writer_returns_error_when_shutdown_returns_error() {
        let packet_a: Vec<u8> = vec![1, 3, 5, 9, 7];

        let mut rx_to_write = Box::new(ReceiverWrapperMock::new());
        rx_to_write.poll_results = vec![
            Poll::Ready(Ok(Some(SequencedPacket {
                data: packet_a.to_vec(),
                sequence_number: 0,
                last_data: true,
            }))),
            Poll::Ready(Ok(None)),
        ];

        let writer = WriteHalfWrapperMock::new()
            .poll_write_result(Poll::Ready(Ok(packet_a.len())))
            .poll_close_result(Poll::Ready(Err(io::Error::from(ErrorKind::Other))));

        let write_params_mutex = writer.poll_write_params.clone();
        let peer_addr = SocketAddr::from_str("2.2.3.4:5678").unwrap();

        let mut subject = StreamWriterSorted::new(Box::new(writer), peer_addr, rx_to_write);

        let res = subject.poll();

        let write_params = write_params_mutex.lock().unwrap();

        assert_eq!(write_params[0], packet_a);

        assert_eq!(res, Err(()));
    }
}
