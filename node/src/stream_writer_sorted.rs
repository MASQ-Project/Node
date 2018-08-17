// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use tokio::prelude::Async;
use tokio::prelude::Future;
use sub_lib::channel_wrappers::ReceiverWrapper;
use sub_lib::cryptde::StreamKey;
use sub_lib::logger::Logger;
use sub_lib::sequence_buffer::SequenceBuffer;
use sub_lib::tokio_wrappers::WriteHalfWrapper;
use sub_lib::utils::indicates_dead_stream;
use sub_lib::sequence_buffer::SequencedPacket;

pub struct StreamWriterSorted {
    stream: Box<WriteHalfWrapper>,
    stream_key: StreamKey,
    rx_to_write: Box<ReceiverWrapper<SequencedPacket>>,
    logger: Logger,
    sequence_buffer: SequenceBuffer,
}

impl Future for StreamWriterSorted {
    type Item = ();
    type Error = ();


    fn poll(&mut self) -> Result<Async<<Self as Future>::Item>, <Self as Future>::Error> {
        loop {
            let read_result = self.read_data_from_channel();
            let write_result = self.write_from_buffer_to_stream();

            match (read_result, write_result) { // read_result can only be NotReady or Ready; write_result can only be Err, NotReady, or Ready
                (_, WriteBufferStatus::StreamInError) => return Err(()), // dead stream error, shut down (this must be first in the match)
                (ReadChannelStatus::StillOpen, _) => return Ok(Async::NotReady), // may receive more data, don't shut down
                (ReadChannelStatus::Closed, WriteBufferStatus::BufferNotEmpty) => return Ok(Async::NotReady), // still have packets to write, don't shut down yet
                (ReadChannelStatus::Closed, WriteBufferStatus::BufferEmpty) => return Ok(Async::Ready(())), // all done, shut down
            }
        }
    }
}

impl StreamWriterSorted {
    pub fn new (stream: Box<WriteHalfWrapper>, socket_addr: StreamKey, rx_to_write: Box<ReceiverWrapper<SequencedPacket>>) -> StreamWriterSorted {
        let name = format! ("StreamWriter for {}", socket_addr);
        let logger = Logger::new (&name[..]);
        StreamWriterSorted {
            stream,
            stream_key: socket_addr,
            rx_to_write,
            logger,
            sequence_buffer: SequenceBuffer::new(),
        }
    }

    fn read_data_from_channel(&mut self) -> ReadChannelStatus {
        loop {
            match self.rx_to_write.poll() {
                Ok(Async::Ready(Some(sequenced_packet))) => self.sequence_buffer.push(sequenced_packet),
                Ok(Async::Ready(None)) => return ReadChannelStatus::Closed,
                Ok(Async::NotReady) => return ReadChannelStatus::StillOpen,
                Err(_) => panic!("got an error from an unbounded channel which cannot return error")
            }
        }
    }

    fn write_from_buffer_to_stream(&mut self) -> WriteBufferStatus {
        let mut repushee = None;
        while let Some(packet) = match repushee { // this will break the outer loop if the stream is not ready
            None => self.sequence_buffer.poll(),
            Some(_) => None,
        } {
            loop { // this inner loop allows retries for non-dead-stream errors
                match self.stream.poll_write(&packet.data) {
                    Err(e) => {
                        if indicates_dead_stream(e.kind()) {
                            self.logger.error(format!("Error writing {} bytes to {}: {}", packet.data.len(), self.stream_key, e));
                            return WriteBufferStatus::StreamInError;
                        } else {
                            // TODO this could be exploitable and inefficient: if we keep getting non-dead-stream errors, we go into a tight loop and do not return
                            self.logger.warning(format!("Continuing after write error: {}", e));
                        }
                    },
                    Ok(Async::Ready(_)) => break,
                    Ok(Async::NotReady) => {
                        repushee = Some(packet);
                        break;
                    }
                }
            }
        }

        if let Some(packet) = repushee {
            self.sequence_buffer.repush(packet);
            return WriteBufferStatus::BufferNotEmpty;
        };

        WriteBufferStatus::BufferEmpty
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
    use std::io;
    use std::net::SocketAddr;
    use std::str::FromStr;
    use std::sync::Arc;
    use std::sync::Mutex;
    use test_utils::channel_wrapper_mocks::ReceiverWrapperMock;
    use test_utils::tokio_wrapper_mocks::WriteHalfWrapperMock;
    use std::io::ErrorKind;
    use test_utils::logging::init_test_logging;
    use sub_lib::sequence_buffer::SequencedPacket;
    use test_utils::logging::TestLogHandler;

    #[test]
    fn stream_writer_returns_not_ready_when_the_stream_is_not_ready() {
        let mut rx = Box::new(ReceiverWrapperMock::new());
        rx.poll_results = vec!(
            Ok(Async::Ready(Some(SequencedPacket::new(b"hello".to_vec(), 0)))),
            Ok(Async::Ready(Some(SequencedPacket::new(b"world".to_vec(), 1)))),
            Ok(Async::Ready(None)),
        );

        let writer = WriteHalfWrapperMock {
            poll_write_params: Arc::new(Mutex::new(vec!())),
            poll_write_results: vec!(
                Ok(Async::NotReady),
            ),
        };
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
        rx.poll_results = vec!(
            Ok(Async::NotReady),
        );

        let writer = WriteHalfWrapperMock {
            poll_write_params: Arc::new(Mutex::new(vec!())),
            poll_write_results: vec!(
                Ok(Async::Ready(5))
            ),
        };
        let peer_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();

        let mut subject = StreamWriterSorted::new(Box::new(writer), peer_addr, rx);

        let result = subject.poll();

        assert_eq!(result, Ok(Async::NotReady));
    }

    #[test]
    fn stream_writer_logs_and_returns_err_when_it_gets_a_dead_stream_error() {
        init_test_logging();
        let mut rx = Box::new(ReceiverWrapperMock::new());
        rx.poll_results = vec!(
            Ok(Async::Ready(Some(SequencedPacket::new(b"hello".to_vec(), 0)))),
            Ok(Async::Ready(Some(SequencedPacket::new(b"world".to_vec(), 0)))),
            Ok(Async::NotReady),
        );
        let writer = WriteHalfWrapperMock {
            poll_write_params: Arc::new(Mutex::new(vec!())),
            poll_write_results: vec!(
                Err(io::Error::from(ErrorKind::BrokenPipe))
            ),
        };
        let write_params = writer.poll_write_params.clone();
        let peer_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();

        let mut subject = StreamWriterSorted::new(Box::new(writer), peer_addr.clone(), rx);

        let result = subject.poll();

        assert_eq!(result.is_ok(), false);
        assert_eq!(write_params.lock().unwrap().len(), 1);
        TestLogHandler::new().await_log_containing("Error writing 5 bytes to 1.2.3.4:5678: broken pipe", 1000);
    }

    #[test]
    fn stream_writer_logs_error_and_continues_when_it_gets_a_non_dead_stream_error() {
        init_test_logging();
        let mut rx = Box::new(ReceiverWrapperMock::new());
        rx.poll_results = vec!(
            Ok(Async::Ready(Some(SequencedPacket::new(b"hello".to_vec(), 0)))),
            Ok(Async::Ready(Some(SequencedPacket::new(b"world".to_vec(), 1)))),
            Ok(Async::NotReady),
        );
        let writer = WriteHalfWrapperMock {
            poll_write_params: Arc::new(Mutex::new(vec!())),
            poll_write_results: vec!(
                Err(io::Error::from(ErrorKind::Other)),
                Ok(Async::Ready(5)),
                Ok(Async::NotReady)
            ),
        };
        let write_params = writer.poll_write_params.clone();
        let peer_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();

        let mut subject = StreamWriterSorted::new(Box::new(writer), peer_addr.clone(), rx);

        subject.poll().unwrap();

        TestLogHandler::new().exists_log_containing("WARN: StreamWriter for 1.2.3.4:5678: Continuing after write error: other os error");
        assert_eq!(write_params.lock().unwrap().len(), 3);
    }

    #[test]
    fn stream_writer_writes_to_stream_and_does_not_shut_down() {
        let first_data = b"hello";
        let second_data = b"world";
        let mut rx = Box::new(ReceiverWrapperMock::new());
        rx.poll_results = vec!(
            Ok(Async::Ready(Some(SequencedPacket::new(first_data.to_vec(), 0)))),
            Ok(Async::Ready(Some(SequencedPacket::new(second_data.to_vec(), 1)))),
            Ok(Async::NotReady)
        );
        let writer = WriteHalfWrapperMock {
            poll_write_params: Arc::new(Mutex::new(vec!())),
            poll_write_results: vec!(
                Ok(Async::Ready(first_data.len())),
                Ok(Async::Ready(second_data.len())),
            ),
        };
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
        rx.poll_results = vec!(
            Ok(Async::Ready(Some(SequencedPacket::new(third_data.to_vec(), 2)))),
            Ok(Async::Ready(Some(SequencedPacket::new(second_data.to_vec(), 1)))),
            Ok(Async::Ready(Some(SequencedPacket::new(first_data.to_vec(), 0)))),
            Ok(Async::NotReady)
        );
        let writer = WriteHalfWrapperMock {
            poll_write_params: Arc::new(Mutex::new(vec!())),
            poll_write_results: vec!(
                Ok(Async::Ready(first_data.len())),
                Ok(Async::Ready(second_data.len())),
                Ok(Async::Ready(third_data.len())),
            ),
        };
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
        rx.poll_results = vec!(
            Ok(Async::Ready(Some(SequencedPacket::new(first_data.to_vec(), 0)))),
            Ok(Async::Ready(Some(SequencedPacket::new(second_data.to_vec(), 1)))),
            Ok(Async::NotReady)
        );
        let writer = WriteHalfWrapperMock {
            poll_write_params: Arc::new(Mutex::new(vec!())),
            poll_write_results: vec!(
                Err(io::Error::from(ErrorKind::Other)),
                Ok(Async::Ready(first_data.len())),
                Ok(Async::Ready(second_data.len())),
                Ok(Async::NotReady)
            ),
        };
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
        rx.poll_results = vec!(
            Ok(Async::Ready(Some(SequencedPacket::new(b"hello".to_vec(), 0)))),
            Ok(Async::Ready(None))
        );
        let writer = WriteHalfWrapperMock {
            poll_write_params: Arc::new(Mutex::new(vec!())),
            poll_write_results: vec!(
                Ok(Async::Ready(5)),
                Err(io::Error::from(ErrorKind::BrokenPipe))
            ),
        };
        let peer_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();

        let mut subject = StreamWriterSorted::new(Box::new(writer), peer_addr.clone(), rx);

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
            poll_write_results: vec!(),
        };
        let peer_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();

        let mut subject = StreamWriterSorted::new(Box::new(writer), peer_addr.clone(), rx);

        subject.poll().unwrap();
    }

    #[test]
    fn stream_writer_reattempts_writing_packets_that_were_prevented_by_not_ready() {
        let mut rx = Box::new(ReceiverWrapperMock::new());
        rx.poll_results = vec!(
            Ok(Async::Ready(Some(SequencedPacket::new(b"hello".to_vec(), 0)))),
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

        let mut subject = StreamWriterSorted::new(Box::new(writer), peer_addr, rx);

        let result = subject.poll();
        assert_eq!(result, Ok(Async::NotReady));

        let result = subject.poll();
        assert_eq!(result, Ok(Async::NotReady));

        assert_eq!(write_params.lock().unwrap().len(), 2);
    }
}
