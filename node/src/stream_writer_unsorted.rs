use tokio::prelude::Async;
use tokio::prelude::Future;
use sub_lib::channel_wrappers::ReceiverWrapper;
use sub_lib::cryptde::StreamKey;
use sub_lib::logger::Logger;
use sub_lib::tokio_wrappers::WriteHalfWrapper;
use sub_lib::utils::indicates_dead_stream;
use masquerader::Masquerader;
use sub_lib::sequence_buffer::SequencedPacket;

pub struct StreamWriterUnsorted {
    stream: Box<WriteHalfWrapper>,
    _stream_key: StreamKey,
    rx_to_write: Box<ReceiverWrapper<SequencedPacket>>,
    logger: Logger,
    buf: Option<SequencedPacket>,
    masquerader: Box<Masquerader>,
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
                        Err(_) => panic!("got an error from an unbounded channel which cannot return error")
                    }
                },
                Some(packet) => {
                    let mask_result = self.masquerader.mask(packet.data.as_slice());
                    let write_result = match mask_result {
                        Err(_) => unimplemented!("Masking failed"), // TODO should the stream be shut down, or should we allow the recipient to request a retry? // TODO FIXME this will allow silently dropped sequenced packets: the writer will continue to write the remaining packets, which is a problem
                        Ok(masked_data) => self.stream.poll_write(&masked_data)
                    };
                    match write_result {
                        Err(e) => {
                            if indicates_dead_stream(e.kind()) {
                                self.logger.error(format!("Cannot transmit {} bytes: {}", packet.data.len(), e));
                                return Err(())
                            } else {
                                self.buf = Some(packet);
                                // TODO this could be... inefficient, if we keep getting non-dead-stream errors. (we do not return)
                                self.logger.warning(format!("Continuing after write error: {}", e));
                            }
                        },
                        Ok(Async::Ready(_)) => {},
                        Ok(Async::NotReady) => {
                            self.buf = Some(packet);
                            return Ok(Async::NotReady)
                        },
                    }
                }
            }
        }
    }
}

impl StreamWriterUnsorted {
    pub fn new (stream: Box<WriteHalfWrapper>, socket_addr: StreamKey, rx_to_write: Box<ReceiverWrapper<SequencedPacket>>, writer_config: Box<Masquerader>) -> StreamWriterUnsorted {
        let name = format! ("StreamWriter for {}", socket_addr);
        let logger = Logger::new (&name[..]);
        StreamWriterUnsorted {
            stream,
            _stream_key: socket_addr,
            rx_to_write,
            logger,
            buf: None,
            masquerader: writer_config,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
    use std::net::SocketAddr;
    use std::str::FromStr;
    use std::sync::Arc;
    use std::sync::Mutex;
    use test_utils::tokio_wrapper_mocks::WriteHalfWrapperMock;
    use test_utils::channel_wrapper_mocks::ReceiverWrapperMock;
    use std::io::ErrorKind;
    use test_utils::logging::init_test_logging;
    use test_utils::logging::TestLogHandler;
    use null_masquerader::NullMasquerader;
    use json_masquerader::JsonMasquerader;
    use node_test_utils::FailingMasquerader;

    #[test]
    fn stream_writer_returns_not_ready_when_the_stream_is_not_ready() {
        let mut rx = Box::new(ReceiverWrapperMock::new());
        rx.poll_results = vec!(
            Ok(Async::Ready(Some(SequencedPacket::new(b"hello".to_vec(), 0, false)))),
            Ok(Async::Ready(Some(SequencedPacket::new(b"world".to_vec(), 0, false)))),
        );

        let writer = WriteHalfWrapperMock {
            poll_write_params: Arc::new(Mutex::new(vec!())),
            poll_write_results: vec!(
                Ok(Async::NotReady)
            ) };
        let write_params = writer.poll_write_params.clone();
        let peer_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();

        let mut subject = StreamWriterUnsorted::new(Box::new(writer), peer_addr, rx, Box::new(NullMasquerader::new()));

        let result = subject.poll();

        assert_eq!(result, Ok(Async::NotReady));
        assert_eq!(write_params.lock().unwrap().len(), 1);
    }

    #[test]
    fn stream_writer_returns_not_ready_when_the_channel_is_not_ready() {
        let mut rx = Box::new(ReceiverWrapperMock::new());
        rx.poll_results = vec!(
            Ok(Async::NotReady),
        );

        let writer = WriteHalfWrapperMock {
            poll_write_params: Arc::new(Mutex::new(vec!())),
            poll_write_results: vec!(
                Ok(Async::Ready(5))
            ) };
        let peer_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();

        let mut subject = StreamWriterUnsorted::new(Box::new(writer), peer_addr, rx, Box::new(NullMasquerader::new()));

        let result = subject.poll();

        assert_eq!(result, Ok(Async::NotReady));
    }

    #[test]
    fn stream_writer_returns_err_when_it_gets_a_dead_stream_error() {
        let mut rx = Box::new(ReceiverWrapperMock::new());
        rx.poll_results = vec!(
            Ok(Async::Ready(Some(SequencedPacket::new(b"hello".to_vec(), 0, false)))),
            Ok(Async::Ready(Some(SequencedPacket::new(b"world".to_vec(), 0, false)))),
        );
        let writer = WriteHalfWrapperMock {
            poll_write_params: Arc::new(Mutex::new(vec!())),
            poll_write_results: vec!(
                Err(io::Error::from(ErrorKind::BrokenPipe))
            )
        };
        let write_params = writer.poll_write_params.clone();
        let peer_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();

        let mut subject = StreamWriterUnsorted::new(Box::new(writer), peer_addr, rx, Box::new(NullMasquerader::new()));

        let result = subject.poll();

        assert_eq!(result.is_ok(), false);
        assert_eq!(write_params.lock().unwrap().len(), 1);
    }

    #[test]
    fn stream_writer_logs_error_and_continues_when_it_gets_a_non_dead_stream_error() {
        init_test_logging();
        let mut rx = Box::new(ReceiverWrapperMock::new());
        rx.poll_results = vec!(
            Ok(Async::Ready(Some(SequencedPacket::new(b"hello".to_vec(), 0, false)))),
            Ok(Async::Ready(Some(SequencedPacket::new(b"world".to_vec(), 0, false)))),
        );
        let writer = WriteHalfWrapperMock {
            poll_write_params: Arc::new(Mutex::new(vec!())),
            poll_write_results: vec!(
                Err(io::Error::from(ErrorKind::Other)),
                Ok(Async::Ready(5)),
                Ok(Async::NotReady)
            )
        };
        let write_params = writer.poll_write_params.clone();
        let peer_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();

        let mut subject = StreamWriterUnsorted::new(Box::new(writer), peer_addr, rx, Box::new(NullMasquerader::new()));

        subject.poll().unwrap();

        TestLogHandler::new ().await_log_matching("ThreadId\\(\\d+\\): WARN: StreamWriter for 1\\.2\\.3\\.4:5678: Continuing after write error: other os error", 1000);
        assert_eq!(write_params.lock().unwrap().len(), 3);
    }

    #[test]
    fn stream_writer_writes_to_stream_and_does_not_shut_down() {
        let first_data = b"hello";
        let second_data = b"world";
        let mut rx = Box::new(ReceiverWrapperMock::new());
        rx.poll_results = vec!(
            Ok(Async::Ready(Some(SequencedPacket::new(first_data.to_vec(), 0, false)))),
            Ok(Async::Ready(Some(SequencedPacket::new(second_data.to_vec(), 0, false)))),
            Ok(Async::NotReady)
        );
        let writer = WriteHalfWrapperMock {
            poll_write_params: Arc::new(Mutex::new(vec!())),
            poll_write_results: vec!(
                Ok(Async::Ready(first_data.len())),
                Ok(Async::Ready(second_data.len())),
            )
        };
        let write_params = writer.poll_write_params.clone();
        let peer_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();

        let mut subject = StreamWriterUnsorted::new(Box::new(writer), peer_addr, rx, Box::new(NullMasquerader::new()));

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
        rx.poll_results = vec!(
            Ok(Async::Ready(Some(SequencedPacket::new(first_data.to_vec(), 0, false)))),
            Ok(Async::Ready(Some(SequencedPacket::new(second_data.to_vec(), 0, false)))),
            Ok(Async::NotReady)
        );
        let writer = WriteHalfWrapperMock {
            poll_write_params: Arc::new(Mutex::new(vec!())),
            poll_write_results: vec!(
                Err(io::Error::from(ErrorKind::Other)),
                Ok(Async::Ready(first_data.len())),
                Ok(Async::NotReady)
            )
        };
        let write_params = writer.poll_write_params.clone();
        let peer_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();

        let mut subject = StreamWriterUnsorted::new(Box::new(writer), peer_addr, rx, Box::new(NullMasquerader::new()));

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
        rx.poll_results = vec!(
            Ok(Async::Ready(Some(SequencedPacket::new(b"hello".to_vec(), 0, false)))),
            Ok(Async::Ready(None))
        );
        let writer = WriteHalfWrapperMock {
            poll_write_params: Arc::new(Mutex::new(vec!())),
            poll_write_results: vec!(
                Ok(Async::Ready(5)),
                Err(io::Error::from(ErrorKind::BrokenPipe))
            )
        };
        let peer_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();

        let mut subject = StreamWriterUnsorted::new(Box::new(writer), peer_addr, rx, Box::new(NullMasquerader::new()));

        let result = subject.poll();

        assert_eq!(result.is_ok(), true);
    }

    #[test]
    #[should_panic (expected = "got an error from an unbounded channel which cannot return error")]
    fn stream_writer_panics_if_channel_returns_err() {
        let mut rx = Box::new(ReceiverWrapperMock::new());
        rx.poll_results = vec!(
            Err(()),
        );
        let writer = WriteHalfWrapperMock {
            poll_write_params: Arc::new(Mutex::new(vec!())),
            poll_write_results: vec!()
        };
        let peer_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();

        let mut subject = StreamWriterUnsorted::new(Box::new(writer), peer_addr, rx, Box::new(NullMasquerader::new()));

        subject.poll().unwrap();
    }

    #[test]
    fn stream_writer_reattempts_writing_packets_that_were_prevented_by_not_ready() {
        let mut rx = Box::new(ReceiverWrapperMock::new());
        rx.poll_results = vec!(
            Ok(Async::Ready(Some(SequencedPacket::new(b"hello".to_vec(), 0, false)))),
            Ok(Async::NotReady),
            Ok(Async::NotReady),
        );

        let writer = WriteHalfWrapperMock {
            poll_write_params: Arc::new(Mutex::new(vec!())),
            poll_write_results: vec!(
                Ok(Async::NotReady),
                Ok(Async::Ready(5)),
            ),
        };
        let write_params = writer.poll_write_params.clone();
        let peer_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();

        let mut subject = StreamWriterUnsorted::new(Box::new(writer), peer_addr, rx, Box::new(NullMasquerader::new()));

        let result = subject.poll();
        assert_eq!(result, Ok(Async::NotReady));

        let result = subject.poll();
        assert_eq!(result, Ok(Async::NotReady));

        assert_eq!(write_params.lock().unwrap().len(), 2);
    }

    #[test]
    fn stream_writer_uses_masquerader_to_mask_outgoing_data() {
        let first_data = b"hello";
        let second_data = b"world";
        let mut rx_to_write = Box::new(ReceiverWrapperMock::new());
        rx_to_write.poll_results = vec!(
            Ok(Async::Ready(Some(SequencedPacket::new(first_data.to_vec(), 0, false)))),
            Ok(Async::Ready(Some(SequencedPacket::new(second_data.to_vec(), 0, false)))),
            Ok(Async::NotReady)
        );
        let writer = WriteHalfWrapperMock {
            poll_write_params: Arc::new(Mutex::new(vec!())),
            poll_write_results: vec!(
                Ok(Async::Ready(first_data.len())),
                Ok(Async::Ready(second_data.len())),
            )
        };
        let write_params = writer.poll_write_params.clone();
        let peer_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();

        let mut subject = StreamWriterUnsorted::new(Box::new(writer), peer_addr.clone(), rx_to_write, Box::new(JsonMasquerader::new()));

        let result = subject.poll();

        assert_eq!(result.is_ok(), true);

        let mut params = write_params.lock().unwrap();
        assert_eq!(params.len(), 2);
        let masquerader = JsonMasquerader::new();
        assert_eq!(params.remove(0), masquerader.mask(first_data).unwrap());
        assert_eq!(params.remove(0), masquerader.mask(second_data).unwrap());
    }

    #[test]
    #[should_panic(expected="Masking failed")]
    fn stream_writer_panics_when_masking_fails() {
        let first_data = b"hello";
        let mut rx_to_write = Box::new(ReceiverWrapperMock::new());
        rx_to_write.poll_results = vec!(
            Ok(Async::Ready(Some(SequencedPacket::new(first_data.to_vec(), 0, false)))),
            Ok(Async::NotReady)
        );
        let writer = WriteHalfWrapperMock {
            poll_write_params: Arc::new(Mutex::new(vec!())),
            poll_write_results: vec!()
        };
        let peer_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();

        let mut subject = StreamWriterUnsorted::new(Box::new(writer), peer_addr.clone(), rx_to_write, Box::new(FailingMasquerader {}));

        let _result = subject.poll();
    }
}