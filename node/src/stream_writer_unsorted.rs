use std::future::Future;
use crate::sub_lib::channel_wrappers::ReceiverWrapper;
use crate::sub_lib::sequence_buffer::SequencedPacket;
use crate::sub_lib::tokio_wrappers::WriteHalfWrapper;
use crate::sub_lib::utils::indicates_dead_stream;
use masq_lib::logger::Logger;
use std::net::SocketAddr;
use std::task::{Poll};
use tokio::io::AsyncWriteExt;

pub struct StreamWriterUnsorted {
    stream: Box<dyn WriteHalfWrapper>,
    rx_to_write: Box<dyn ReceiverWrapper<SequencedPacket>>,
    logger: Logger,
    buf: Option<SequencedPacket>,
}

impl StreamWriterUnsorted {
    pub fn new(
        stream: Box<dyn WriteHalfWrapper>,
        peer_addr: SocketAddr,
        rx_to_write: Box<dyn ReceiverWrapper<SequencedPacket>>,
    ) -> StreamWriterUnsorted {
        let name = format!("StreamWriter for {}", peer_addr);
        let logger = Logger::new(&name[..]);
        StreamWriterUnsorted {
            stream,
            rx_to_write,
            logger,
            buf: None,
        }
    }

    pub async fn run(mut self) {
        loop {
            match self.buf.take() {
                None => {
                    self.buf = match self.rx_to_write.recv().await {
                        Some(data) => Some(data),
                        None => return, // the channel has been closed on the tx side
                    }
                }
                Some(packet) => {
                    // TODO in SC-646 "Graceful Shutdown from GUI" (marked obsolete): handle packet.last_data = true here
                    debug!(
                        self.logger,
                        "Transmitting {} bytes of clandestine data",
                        packet.data.len()
                    );
                    match self.stream.as_mut().write(&packet.data).await {  //poll_write(cx, &packet.data) {
                        Err(e) => {
                            if indicates_dead_stream(e.kind()) {
                                error!(
                                    self.logger,
                                    "Cannot transmit {} bytes: {}",
                                    packet.data.len(),
                                    e
                                );
                                return;
                            } else {
                                self.buf = Some(packet);
                                // TODO this could be... inefficient, if we keep getting non-dead-stream errors. (we do not return)
                                warning!(self.logger, "Continuing after write error: {}", e);
                            }
                        }
                        Ok(len) => {
                            debug!(
                                self.logger,
                                "Wrote {}/{} bytes of clandestine data",
                                len,
                                &packet.data.len()
                            );
                            if len != packet.data.len() {
                                debug!(
                                    self.logger,
                                    "rescheduling {} bytes",
                                    packet.data.len() - len
                                );
                                self.buf = Some(SequencedPacket::new(
                                    packet.data.iter().skip(len).cloned().collect(),
                                    packet.sequence_number,
                                    false,
                                ));
                            }
                        }
                    }
                }
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
    use std::io;
    use std::io::ErrorKind;
    use std::net::SocketAddr;
    use std::str::FromStr;
    use std::task::Poll;

    #[tokio::test]
    async fn stream_writer_terminates_when_it_gets_a_dead_stream_error() {
        let mut rx = Box::new(ReceiverWrapperMock::new()
            .recv_result(Some(SequencedPacket::new(
                b"hello".to_vec(),
                0,
                false,
            )))
            .recv_result(Some(SequencedPacket::new(
              b"world".to_vec(),
              1,
              false,
            )))
        );
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
        ];
        let writer = WriteHalfWrapperMock::new()
            .poll_write_result(Err(io::Error::from(ErrorKind::BrokenPipe)));
        let write_params = writer.poll_write_params.clone();
        let peer_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let mut subject = StreamWriterUnsorted::new(Box::new(writer), peer_addr, rx);

        subject.run().await;

        TestLogHandler::new().exists_log_containing(
            // This is a guess.
            "ERROR: StreamWriter for 1.2.3.4:5678: Cannot transmit 5 bytes: Broken Pipe",
        );
        assert_eq!(write_params.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn stream_writer_logs_error_and_continues_when_it_gets_a_non_dead_stream_error() {
        init_test_logging();
        let rx = Box::new(ReceiverWrapperMock::new()
            .recv_result(Some(SequencedPacket::new(
                b"hello".to_vec(),
                0,
                false,
            )))
            .recv_result(Some(SequencedPacket::new(
                b"world".to_vec(),
                1,
                false,
            )))
        );
        let writer = WriteHalfWrapperMock::new()
            .poll_write_result(Err(io::Error::from(ErrorKind::Other)))
            .poll_write_result(Poll::Ready(Ok(5)))
            .poll_write_result(Poll::Pending);
        let write_params = writer.poll_write_params.clone();
        let peer_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let mut subject = StreamWriterUnsorted::new(Box::new(writer), peer_addr, rx);

        subject.run().await;

        TestLogHandler::new().exists_log_containing(
            "WARN: StreamWriter for 1.2.3.4:5678: Continuing after write error: other error",
        );
        assert_eq!(write_params.lock().unwrap().len(), 3);
    }

    #[tokio::test]
    async fn stream_writer_writes_to_stream_and_does_not_shut_down() {
        let first_data = b"hello";
        let second_data = b"world";
        let rx = Box::new(ReceiverWrapperMock::new()
            .poll_result(Poll::Ready(Ok(Some(SequencedPacket::new(
                first_data.to_vec(),
                0,
                false,
            )))))
            .poll_result(Poll::Ready(Ok(Some(SequencedPacket::new(
                second_data.to_vec(),
                1,
                false,
            )))))
            .poll_result(Poll::Pending)
        );
        let writer = WriteHalfWrapperMock::new()
            .poll_write_result(Poll::Ready(Ok(first_data.len())))
            .poll_write_result(Poll::Ready(Ok(second_data.len())));

        let write_params = writer.poll_write_params.clone();
        let peer_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();

        let mut subject = StreamWriterUnsorted::new(Box::new(writer), peer_addr, rx);

        let result = subject.run().await;

        let mut params = write_params.lock().unwrap();
        assert_eq!(params.len(), 2);
        assert_eq!(params.remove(0), first_data.to_vec());
        assert_eq!(params.remove(0), second_data.to_vec());
    }

    #[tokio::test]
    async fn stream_writer_attempts_to_write_until_successful_before_reading_new_messages_from_channel() {
        let first_data = b"hello";
        let second_data = b"world";
        let rx = Box::new(ReceiverWrapperMock::new()
            .poll_result(Poll::Ready(Ok(Some(SequencedPacket::new(
                first_data.to_vec(),
                0,
                false,
            )))))
            .poll_result(Poll::Ready(Ok(Some(SequencedPacket::new(
                second_data.to_vec(),
                1,
                false,
            )))))
            .poll_result(Poll::Pending)
        );
        let writer = WriteHalfWrapperMock::new()
            .poll_write_result(Poll::Ready(Err(io::Error::from(ErrorKind::Other))))
            .poll_write_result(Poll::Ready(Ok(first_data.len())))
            .poll_write_result(Poll::Pending);

        let write_params = writer.poll_write_params.clone();
        let peer_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();

        let mut subject = StreamWriterUnsorted::new(Box::new(writer), peer_addr, rx);

        let result = subject.run().await;

        let mut params = write_params.lock().unwrap();
        assert_eq!(params.len(), 3);
        assert_eq!(params.remove(0), first_data.to_vec());
        assert_eq!(params.remove(0), first_data.to_vec());
        assert_eq!(params.remove(0), second_data.to_vec());
    }

    #[tokio::test]
    async fn stream_writer_exits_if_channel_is_closed() {
        let rx = Box::new(ReceiverWrapperMock::new()
            .poll_result(Poll::Ready(Ok(Some(SequencedPacket::new(
                b"hello".to_vec(),
                0,
                false,
            )))))
            .poll_result(Poll::Ready(Ok(None)))
        );
        let writer = WriteHalfWrapperMock::new()
            .poll_write_result(Poll::Ready(Ok(5)))
            .poll_write_result(Err(io::Error::from(ErrorKind::BrokenPipe)));

        let peer_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();

        let mut subject = StreamWriterUnsorted::new(Box::new(writer), peer_addr, rx);

        let result = subject.run().await;

        // Future completed; test passes
    }

    #[tokio::test]
    #[should_panic(expected = "got an error from an unbounded channel which cannot return error")]
    async fn stream_writer_panics_if_channel_returns_err() {
        let rx = Box::new(ReceiverWrapperMock::new()
            .poll_result(Poll::Ready(Err(())))
        );
        let writer = WriteHalfWrapperMock::new();
        let peer_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();

        let mut subject = StreamWriterUnsorted::new(Box::new(writer), peer_addr, rx);

        subject.run().await;
    }

    #[tokio::test]
    async fn stream_writer_reattempts_writing_packets_that_were_prevented_by_not_ready() {
        let rx = Box::new(ReceiverWrapperMock::new()
            .poll_result(Poll::Ready(Ok(Some(SequencedPacket::new(
                b"hello".to_vec(),
                0,
                false,
            )))))
            .poll_result(Poll::Pending)
            .poll_result(Poll::Pending)
        );

        let writer = WriteHalfWrapperMock::new()
            .poll_write_result(Poll::Pending)
            .poll_write_result(Poll::Ready(Ok(5)));

        let write_params = writer.poll_write_params.clone();
        let peer_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();

        let mut subject = StreamWriterUnsorted::new(Box::new(writer), peer_addr, rx);

        subject.run().await;

        assert_eq!(write_params.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn stream_writer_resubmits_partial_packet_when_written_len_is_less_than_packet_len() {
        let rx = Box::new(ReceiverWrapperMock::new()
            .poll_result(Poll::Ready(Ok(Some(SequencedPacket::new(
              b"worlds".to_vec(),
              0,
              false,
            )))))
            .poll_result(Poll::Pending)
            .poll_result(Poll::Pending)
            .poll_result(Poll::Pending)
        );

        let writer = WriteHalfWrapperMock::new()
            .poll_write_result(Poll::Ready(Ok(3)))
            .poll_write_result(Poll::Ready(Ok(2)))
            .poll_write_result(Poll::Ready(Ok(1)));

        let write_params = writer.poll_write_params.clone();
        let peer_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();

        let mut subject = StreamWriterUnsorted::new(Box::new(writer), peer_addr, rx);

        subject.run().await;

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
}
