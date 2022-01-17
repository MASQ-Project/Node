use crate::sub_lib::channel_wrappers::ReceiverWrapper;
use crate::sub_lib::sequence_buffer::SequencedPacket;
use crate::sub_lib::tokio_wrappers::WriteHalfWrapper;
use crate::sub_lib::utils::indicates_dead_stream;
use masq_lib::logger::Logger;
use std::net::SocketAddr;
use tokio::prelude::Async;
use tokio::prelude::Future;

pub struct StreamWriterUnsorted {
    stream: Box<dyn WriteHalfWrapper>,
    rx_to_write: Box<dyn ReceiverWrapper<SequencedPacket>>,
    logger: Logger,
    buf: Option<SequencedPacket>,
}

impl Future for StreamWriterUnsorted {
    type Item = ();
    type Error = ();

    fn poll(&mut self) -> Result<Async<<Self as Future>::Item>, <Self as Future>::Error> {
        loop {
            match self.buf.take() {
                None => {
                    self.buf = match self.rx_to_write.poll() {
                        Ok(Async::Ready(Some(data))) => Some(data),
                        Ok(Async::Ready(None)) => return Ok(Async::Ready(())), // the channel has been closed on the tx side
                        Ok(Async::NotReady) => return Ok(Async::NotReady),
                        Err(e) => panic!(
                            "got an error from an unbounded channel which cannot return error: {:?}", e
                        ),
                    }
                }
                Some(packet) => {
                    // TODO in SC-646 "Graceful Shutdown from GUI" (marked obsolete): handle packet.last_data = true here
                    debug!(
                        self.logger,
                        "Transmitting {} bytes of clandestine data",
                        packet.data.len()
                    );
                    match self.stream.poll_write(&packet.data) {
                        Err(e) => {
                            if indicates_dead_stream(e.kind()) {
                                error!(
                                    self.logger,
                                    "Cannot transmit {} bytes: {}",
                                    packet.data.len(),
                                    e
                                );
                                return Err(());
                            } else {
                                self.buf = Some(packet);
                                // TODO this could be... inefficient, if we keep getting non-dead-stream errors. (we do not return)
                                warning!(self.logger, "Continuing after write error: {}", e);
                            }
                        }
                        Ok(Async::Ready(len)) => {
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
                        Ok(Async::NotReady) => {
                            self.buf = Some(packet);
                            return Ok(Async::NotReady);
                        }
                    }
                }
            }
        }
    }
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
                0,
                false,
            )))),
        ];

        let writer = WriteHalfWrapperMock::new().poll_write_result(Ok(Async::NotReady));
        let write_params = writer.poll_write_params.clone();
        let peer_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();

        let mut subject = StreamWriterUnsorted::new(Box::new(writer), peer_addr, rx);

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

        let mut subject = StreamWriterUnsorted::new(Box::new(writer), peer_addr, rx);

        let result = subject.poll();

        assert_eq!(result, Ok(Async::NotReady));
    }

    #[test]
    fn stream_writer_returns_err_when_it_gets_a_dead_stream_error() {
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
        ];
        let writer = WriteHalfWrapperMock::new()
            .poll_write_result(Err(io::Error::from(ErrorKind::BrokenPipe)));
        let write_params = writer.poll_write_params.clone();
        let peer_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();

        let mut subject = StreamWriterUnsorted::new(Box::new(writer), peer_addr, rx);

        let result = subject.poll();

        assert_eq!(result.is_ok(), false);
        assert_eq!(write_params.lock().unwrap().len(), 1);
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
                0,
                false,
            )))),
        ];
        let writer = WriteHalfWrapperMock::new()
            .poll_write_result(Err(io::Error::from(ErrorKind::Other)))
            .poll_write_result(Ok(Async::Ready(5)))
            .poll_write_result(Ok(Async::NotReady));

        let write_params = writer.poll_write_params.clone();
        let peer_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();

        let mut subject = StreamWriterUnsorted::new(Box::new(writer), peer_addr, rx);

        subject.poll().unwrap();

        TestLogHandler::new().await_log_containing(
            "WARN: StreamWriter for 1.2.3.4:5678: Continuing after write error: other error",
            1000,
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
                0,
                false,
            )))),
            Ok(Async::NotReady),
        ];
        let writer = WriteHalfWrapperMock::new()
            .poll_write_result(Ok(Async::Ready(first_data.len())))
            .poll_write_result(Ok(Async::Ready(second_data.len())));

        let write_params = writer.poll_write_params.clone();
        let peer_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();

        let mut subject = StreamWriterUnsorted::new(Box::new(writer), peer_addr, rx);

        let result = subject.poll();

        assert_eq!(result.is_ok(), true);

        let mut params = write_params.lock().unwrap();
        assert_eq!(params.len(), 2);
        assert_eq!(params.remove(0), first_data.to_vec());
        assert_eq!(params.remove(0), second_data.to_vec());
    }

    #[test]
    fn stream_writer_attempts_to_write_until_successful_before_reading_new_messages_from_channel() {
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
                0,
                false,
            )))),
            Ok(Async::NotReady),
        ];
        let writer = WriteHalfWrapperMock::new()
            .poll_write_result(Err(io::Error::from(ErrorKind::Other)))
            .poll_write_result(Ok(Async::Ready(first_data.len())))
            .poll_write_result(Ok(Async::NotReady));

        let write_params = writer.poll_write_params.clone();
        let peer_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();

        let mut subject = StreamWriterUnsorted::new(Box::new(writer), peer_addr, rx);

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

        let mut subject = StreamWriterUnsorted::new(Box::new(writer), peer_addr, rx);

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

        let mut subject = StreamWriterUnsorted::new(Box::new(writer), peer_addr, rx);

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

        let mut subject = StreamWriterUnsorted::new(Box::new(writer), peer_addr, rx);

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
            .poll_write_result(Ok(Async::Ready(1)));

        let write_params = writer.poll_write_params.clone();
        let peer_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();

        let mut subject = StreamWriterUnsorted::new(Box::new(writer), peer_addr, rx);

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
}
