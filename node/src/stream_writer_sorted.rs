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
    stream_opt: Option<Box<dyn WriteHalfWrapper>>,
    peer_addr: SocketAddr,
    rx_to_write: Box<dyn ReceiverWrapper<SequencedPacket>>,
    logger: Logger,
    sequence_buffer: SequenceBuffer,
    shutdown_reason_opt: Option<Result<(), std::io::Error>>
}

impl StreamWriterSorted {
    pub fn spawn(
        stream: Box<dyn WriteHalfWrapper>,
        peer_addr: SocketAddr,
        rx_to_write: Box<dyn ReceiverWrapper<SequencedPacket>>,
    ) {
        let writer = Self::new(
            stream,
            peer_addr,
            rx_to_write,
        );
        let future = writer.go();
        tokio::spawn(future);
    }

    fn new(
        stream: Box<dyn WriteHalfWrapper>,
        peer_addr: SocketAddr,
        rx_to_write: Box<dyn ReceiverWrapper<SequencedPacket>>,
    ) -> Self {
        let name = format!("StreamWriter for {}", peer_addr);
        let logger = Logger::new(&name[..]);
        Self {
            stream_opt: Some(stream),
            peer_addr,
            rx_to_write,
            logger,
            sequence_buffer: SequenceBuffer::new(),
            shutdown_reason_opt: None,
        }
    }

    async fn go(mut self) -> Result<(), std::io::Error> {
        loop {
            match self.shutdown_reason_opt {
                Some(reason) => return reason,
                None => {}
            }

            let read_result = self.read_data_from_channel().await;
            let write_result = self.write_from_buffer_to_stream().await;

            match (read_result, write_result) {
                (_, WriteBufferStatus::StreamInError(e)) => {
                    self.shutdown_reason_opt = Some(Err(e));
                }
                (ReadChannelStatus::StillOpen, _) => {}
                (ReadChannelStatus::Closed, WriteBufferStatus::BufferNotEmpty) => {}
                (ReadChannelStatus::Closed, WriteBufferStatus::BufferEmpty) => {
                    self.shutdown_reason_opt = Some(Ok(()));
                }
            }
        }
    }

    async fn read_data_from_channel(&mut self) -> ReadChannelStatus {
        match self.rx_to_write.recv().await {
            Some(sequenced_packet) => {
                self.sequence_buffer.push(sequenced_packet);
                ReadChannelStatus::StillOpen
            }
            None => ReadChannelStatus::Closed,
        }
    }

    async fn write_from_buffer_to_stream(&mut self) -> WriteBufferStatus {
        loop {
            let packet_opt = self.sequence_buffer.poll();
            match packet_opt {
                Some(packet) => {
                    match self.stream_mut().write(&packet.data).await {
                        Err(e) => {
                            if indicates_dead_stream(e.kind()) {
                                error!(
                                    self.logger,
                                    "Error writing {} bytes to {}: {}",
                                    packet.data.len(),
                                    self.peer_addr,
                                    e
                                );
                                return WriteBufferStatus::StreamInError(e);
                            } else {
                                // TODO this could be exploitable and inefficient: if we keep getting non-dead-stream errors, we go into a tight loop and do not return
                                warning!(self.logger, "Continuing after write error: {}", e);
                                self.sequence_buffer.repush(packet);
                            }
                        }
                        Ok(len) => {
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
                                debug!(self.logger, "Received server-drop report for client at {}", self.peer_addr);
                                return WriteBufferStatus::BufferEmpty
                            }
                        }
                    }
                }
                None => return WriteBufferStatus::BufferEmpty,
            }
        }
    }

    async fn shutdown(mut self) {
        match self.stream_opt.take() {
            None => {
                todo!("Drive in a panic here: this is the only place stream_opt can be set to None, and it can't be called twice")
            },
            Some(mut stream) => {
                match stream.shutdown().await {
                    Ok(()) => {
                        // TODO: Debug-log stream shutdown
                    },
                    Err(e) => {
                        todo!("Not tested");
                        error!(self.logger, "Error shutting down stream: {}", e);
                    }
                }
            }
        }
    }

    fn stream(&self) -> &dyn WriteHalfWrapper {
        self.stream_opt.as_ref().expect("Stream was accessed after shutdown").as_ref()
    }

    fn stream_mut(&mut self) -> &mut dyn WriteHalfWrapper {
        self.stream_opt.as_mut().expect("Stream was accessed after shutdown").as_mut()
    }
}
//
// pub struct StreamWriterSortedOld {
//     stream: Option<Box<dyn WriteHalfWrapper>>,
//     peer_addr: SocketAddr,
//     rx_to_write: Box<dyn ReceiverWrapper<SequencedPacket>>,
//     logger: Logger,
//     sequence_buffer: SequenceBuffer,
//     shutting_down: bool,
// }
//
// impl Future for StreamWriterSortedOld {
//     type Output = Result<(), std::io::Error>;
//
//     fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
//         if self.shutting_down {
//             return self.shutdown(cx);
//         }
//
//         let read_result = self.as_mut().read_data_from_channel();
//         let write_result = self.as_mut().write_from_buffer_to_stream(cx);
//
//         match (read_result, write_result) {
//             // read_result can only be NotReady or Ready; write_result can only be Err, NotReady, or Ready
//             (_, WriteBufferStatus::StreamInError(e)) => Poll::Ready(Err(e)), // dead stream error, shut down (this must be first in the match)
//             (ReadChannelStatus::StillOpen, _) => Poll::Pending, // may receive more data, don't shut down
//             (ReadChannelStatus::Closed, WriteBufferStatus::BufferNotEmpty) => Poll::Pending, // still have packets to write, don't shut down yet
//             (ReadChannelStatus::Closed, WriteBufferStatus::BufferEmpty) => Poll::Ready(Ok(())), // all done, shut down
//         }
//     }
// }

enum ReadChannelStatus {
    StillOpen,
    Closed,
}

enum WriteBufferStatus {
    StreamInError(std::io::Error),
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
    use core::future::Future;

    #[tokio::test]
    async fn stream_writer_returns_not_ready_when_the_stream_is_not_ready() {
        let rx = ReceiverWrapperMock::new()
            .recv_result(Some(SequencedPacket {
                data: b"hello".to_vec(),
                sequence_number: 0,
                last_data: false,
            }))
            .recv_result(Some(SequencedPacket {
                data: b"world".to_vec(),
                sequence_number: 1,
                last_data: false,
            }))
            .recv_result(None);

        let write_params_arc = Arc::new(Mutex::new(vec![]));
        let writer = WriteHalfWrapperMock::new()
            .write_params(&write_params_arc);
        let peer_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();

        let mut subject = StreamWriterSorted::new(Box::new(writer), peer_addr, Box::new(rx));

        subject.go().await.unwrap();

        assert_eq!(write_params_arc.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn stream_writer_returns_not_ready_when_the_channel_is_not_ready() {
        let rx = ReceiverWrapperMock::new()
            .recv_result(None);
        let writer = WriteHalfWrapperMock::new()
            .write_result(Ok(5));
        let peer_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();

        let mut subject = StreamWriterSorted::new(Box::new(writer), peer_addr, Box::new(rx));

        subject.go().await.unwrap();

        // no panic; test passes
    }

    #[tokio::test]
    async fn stream_writer_logs_and_returns_err_when_it_gets_a_dead_stream_error() {
        init_test_logging();
        let rx = ReceiverWrapperMock::new()
            .recv_result(Some(SequencedPacket {
                data: b"hello".to_vec(),
                sequence_number: 0,
                last_data: false,
            }))
            .recv_result(Some(SequencedPacket {
                data: b"world".to_vec(),
                sequence_number: 0,
                last_data: false,
            }))
            .recv_result(None);
        let write_params_arc = Arc::new(Mutex::new(vec![]));
        let writer = WriteHalfWrapperMock::new()
            .write_params(&write_params_arc)
            .write_result(Err(io::Error::from(ErrorKind::BrokenPipe)));
        let peer_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();

        let mut subject = StreamWriterSorted::new(Box::new(writer), peer_addr.clone(), Box::new(rx));

        let result = subject.go().await;

        assert_eq!(result.err().unwrap().kind(), ErrorKind::BrokenPipe);
        assert_eq!(write_params_arc.lock().unwrap().len(), 1);
        TestLogHandler::new()
            .await_log_containing("Error writing 5 bytes to 1.2.3.4:5678: broken pipe", 1000);
    }

    #[tokio::test]
    async fn stream_writer_logs_error_and_continues_when_it_gets_a_non_dead_stream_error() {
        init_test_logging();
        let rx = ReceiverWrapperMock::new()
            .recv_result(Some(SequencedPacket {
                data: b"hello".to_vec(),
                sequence_number: 0,
                last_data: false,
            }))
            .recv_result(Some(SequencedPacket {
                data: b"world".to_vec(),
                sequence_number: 1,
                last_data: false,
            }))
            .recv_result(None);
        let write_params_arc = Arc::new(Mutex::new(vec![]));
        let writer = WriteHalfWrapperMock::new()
            .write_params(&write_params_arc)
            .write_result(Err(io::Error::from(ErrorKind::Other)))
            .write_result(Ok(5));
        let peer_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();

        let mut subject = StreamWriterSorted::new(Box::new(writer), peer_addr.clone(), Box::new(rx));

        let result = subject.go().await;

        assert_eq!(result.err().unwrap().kind(), ErrorKind::BrokenPipe);
        TestLogHandler::new().exists_log_containing(
            "WARN: StreamWriter for 1.2.3.4:5678: Continuing after write error: other error",
        );
        assert_eq!(write_params_arc.lock().unwrap().len(), 3);
    }

    #[tokio::test]
    async fn stream_writer_writes_to_stream_and_does_not_shut_down() {
        let first_data = b"hello";
        let second_data = b"world";
        let rx = ReceiverWrapperMock::new()
            .recv_result(Some(SequencedPacket {
                data: first_data.to_vec(),
                sequence_number: 0,
                last_data: false,
            }))
            .recv_result(Some(SequencedPacket {
                data: second_data.to_vec(),
                sequence_number: 1,
                last_data: false,
            }))
            .recv_result(None);
        let write_params_arc = Arc::new(Mutex::new(vec![]));
        let writer = WriteHalfWrapperMock::new()
            .write_params(&write_params_arc)
            .write_result(Ok(first_data.len()))
            .write_result(Ok(second_data.len()));
        let peer_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let mut subject = StreamWriterSorted::new(Box::new(writer), peer_addr.clone(), Box::new(rx));

        subject.go().await.unwrap();

        assert_eq!(*(write_params_arc.lock().unwrap()), vec![
            first_data.to_vec(),
            second_data.to_vec()
        ]);
    }

    #[tokio::test]
    async fn stream_writer_writes_packets_to_stream_in_order_and_does_not_shut_down() {
        let first_data = b"hello";
        let second_data = b"world";
        let third_data = b"!";
        let rx = ReceiverWrapperMock::new()
            .recv_result(Some(SequencedPacket {
                data: third_data.to_vec(),
                sequence_number: 2,
                last_data: false,
            }))
            .recv_result(Some(SequencedPacket {
                data: second_data.to_vec(),
                sequence_number: 1,
                last_data: false,
            }))
            .recv_result(Some(SequencedPacket {
                data: first_data.to_vec(),
                sequence_number: 0,
                last_data: false,
            }))
            .recv_result(None);
        let write_params_arc = Arc::new(Mutex::new(vec![]));
        let writer = WriteHalfWrapperMock::new()
            .write_params(&write_params_arc)
            .write_result(Ok(first_data.len()))
            .write_result(Ok(second_data.len()))
            .write_result(Ok(third_data.len()));
        let peer_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();

        let mut subject = StreamWriterSorted::new(Box::new(writer), peer_addr.clone(), Box::new(rx));

        subject.go().await.unwrap();

        assert_eq!(*(write_params_arc.lock().unwrap()), vec![
            first_data.to_vec(),
            second_data.to_vec(),
            third_data.to_vec()
        ]);
    }

    #[tokio::test]
    async fn stream_writer_attempts_to_write_until_successful_before_reading_new_messages_from_channel() {
        let first_data = b"hello";
        let second_data = b"worlds";
        let rx = ReceiverWrapperMock::new()
            .recv_result(Some(SequencedPacket {
                data: first_data.to_vec(),
                sequence_number: 0,
                last_data: false,
            }))
            .recv_result(Some(SequencedPacket {
                data: second_data.to_vec(),
                sequence_number: 1,
                last_data: false,
            }))
            .recv_result(None);
        let write_params_arc = Arc::new(Mutex::new(vec![]));
        let writer = WriteHalfWrapperMock::new()
            .write_params(&write_params_arc)
            .write_result(Err(io::Error::from(ErrorKind::Other)))
            .write_result(Ok(first_data.len()))
            .write_result(Ok(second_data.len()));
        let peer_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();

        let mut subject = StreamWriterSorted::new(Box::new(writer), peer_addr.clone(), Box::new(rx));

        subject.go().await.unwrap();

        assert_eq!(*(write_params_arc.lock().unwrap()), vec![
            first_data.to_vec(),
            first_data.to_vec(),
            second_data.to_vec()
        ]);
    }

    #[tokio::test]
    async fn stream_writer_exits_if_channel_is_closed() {
        let rx = ReceiverWrapperMock::new()
            .recv_result(Some(SequencedPacket {
                data: b"hello".to_vec(),
                sequence_number: 0,
                last_data: false,
            }))
            .recv_result(None);
        let writer = WriteHalfWrapperMock::new()
            .write_result(Ok(5))
            .write_result(Err(io::Error::from(ErrorKind::BrokenPipe)));
        let peer_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let mut subject = StreamWriterSorted::new(Box::new(writer), peer_addr.clone(), Box::new(rx));

        subject.go().await.unwrap();

        // no panic; test passes
    }

    #[tokio::test]
    async fn stream_writer_reattempts_writing_packets_that_were_prevented_by_not_ready() {
        let rx = ReceiverWrapperMock::new()
            .recv_result(Some(SequencedPacket {
                data: b"hello".to_vec(),
                sequence_number: 0,
                last_data: false,
            }))
            .recv_result(None)
            .recv_result(None);

        let write_params_arc = Arc::new(Mutex::new(vec![]));
        let writer = WriteHalfWrapperMock::new()
            .write_params(&write_params_arc)
            .write_result(Ok(5));
        let peer_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();

        let mut subject = StreamWriterSorted::new(Box::new(writer), peer_addr, Box::new(rx));

        subject.go().await.unwrap();

        assert_eq!(write_params_arc.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn stream_writer_resubmits_partial_packet_when_written_len_is_less_than_packet_len() {
        let rx = ReceiverWrapperMock::new()
            .recv_result(Some(SequencedPacket {
                data: b"worlds".to_vec(),
                sequence_number: 0,
                last_data: false,
            }))
            .recv_result(None)
            .recv_result(None)
            .recv_result(None);

        let write_params_arc = Arc::new(Mutex::new(vec![]));
        let writer = WriteHalfWrapperMock::new()
            .write_params(&write_params_arc)
            .write_result(Ok(3))
            .write_result(Ok(2))
            .write_result(Ok(1));
        let peer_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let mut subject = StreamWriterSorted::new(Box::new(writer), peer_addr, Box::new(rx));

        subject.go().await.unwrap();

        assert_eq!(*(write_params_arc.lock().unwrap()), vec![b"worlds".to_vec(), b"lds".to_vec(), b"s".to_vec()]);
    }

    #[tokio::test]
    async fn stream_writer_shuts_down_stream_after_writing_last_data() {
        let packet_a: Vec<u8> = vec![1, 3, 5, 9, 7];

        let rx_to_write = ReceiverWrapperMock::new()
            .recv_result(Some(SequencedPacket {
                data: packet_a.to_vec(),
                sequence_number: 0,
                last_data: true,
            }))
            .recv_result(None);

        let write_params_arc = Arc::new(Mutex::new(vec![]));
        let shutdown_params_arc = Arc::new(Mutex::new(vec![]));
        let writer = WriteHalfWrapperMock::new()
            .write_params(&write_params_arc)
            .write_result(Ok(packet_a.len()))
            .shutdown_params(&shutdown_params_arc)
            .shutdown_result(Ok(()));

        let peer_addr = SocketAddr::from_str("2.2.3.4:5678").unwrap();

        let mut subject = StreamWriterSorted::new(Box::new(writer), peer_addr, Box::new(rx_to_write));

        subject.go().await.unwrap();

        let write_params = write_params_arc.lock().unwrap();

        assert_eq!(write_params[0], packet_a);

        assert_eq!(*(shutdown_params_arc.lock().unwrap()), vec![()]);
    }

    #[tokio::test]
    async fn stream_writer_returns_not_ready_when_shutdown_is_not_ready_and_retries_on_next_poll() {
        let packet_a: Vec<u8> = vec![1, 3, 5, 9, 7];
        let rx_to_write = ReceiverWrapperMock::new()
            .recv_result(Some(SequencedPacket {
                data: packet_a.to_vec(),
                sequence_number: 0,
                last_data: true,
            }))
            .recv_result(None);
        let write_params_arc = Arc::new(Mutex::new(vec![]));
        let shutdown_params_arc = Arc::new(Mutex::new(vec![]));
        let writer = WriteHalfWrapperMock::new()
            .write_params(&write_params_arc)
            .write_result(Ok(packet_a.len()))
            .shutdown_params(&shutdown_params_arc)
            .shutdown_result(Ok(()));
        let peer_addr = SocketAddr::from_str("2.2.3.4:5678").unwrap();
        let mut subject = StreamWriterSorted::new(Box::new(writer), peer_addr, Box::new(rx_to_write));

        subject.go().await.unwrap();

        let write_params = write_params_arc.lock().unwrap();
        assert_eq!(write_params[0], packet_a);
        assert_eq!(*(shutdown_params_arc.lock().unwrap()), vec![(), ()]);
    }

    #[tokio::test]
    async fn stream_writer_returns_error_when_shutdown_returns_error() {
        let packet_a: Vec<u8> = vec![1, 3, 5, 9, 7];
        let mut rx_to_write = ReceiverWrapperMock::new()
            .recv_result(Some(SequencedPacket {
                data: packet_a.to_vec(),
                sequence_number: 0,
                last_data: true,
            }))
            .recv_result(None);
        let write_params_arc = Arc::new(Mutex::new(vec![]));
        let writer = WriteHalfWrapperMock::new()
            .write_params(&write_params_arc)
            .write_result(Ok(packet_a.len()))
            .shutdown_result(Err(io::Error::from(ErrorKind::Other)));
        let peer_addr = SocketAddr::from_str("2.2.3.4:5678").unwrap();
        let mut subject = StreamWriterSorted::new(Box::new(writer), peer_addr, Box::new(rx_to_write));

        let res = subject.go().await;

        let write_params = write_params_arc.lock().unwrap();
        assert_eq!(write_params[0], packet_a);
        assert_eq!(res.err().unwrap().kind(), ErrorKind::Other);
    }
}
