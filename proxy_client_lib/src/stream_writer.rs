// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use std::net::SocketAddr;
use tokio::prelude::Async;
use tokio::prelude::Future;
use sub_lib::channel_wrappers::ReceiverWrapper;
use sub_lib::logger::Logger;
use sub_lib::sequence_buffer::SequenceBuffer;
use sub_lib::sequence_buffer::SequencedPacket;
use sub_lib::stream_key::StreamKey;
use sub_lib::tokio_wrappers::WriteHalfWrapper;
use sub_lib::utils::indicates_dead_stream;

pub struct StreamWriter {
    stream: Box<WriteHalfWrapper>,
    logger: Logger,
    sequence_buffer: SequenceBuffer,
    rx_to_write: Box<ReceiverWrapper<SequencedPacket>>,
}

impl Future for StreamWriter {
    type Item = ();
    type Error = ();

    fn poll(&mut self) -> Result<Async<<Self as Future>::Item>, <Self as Future>::Error> {
        let read_result = self.read_data_from_channel();
        let write_result = self.write_from_buffer_to_stream();

        match (read_result, write_result) {
            (_, Err(e)) => Err(e),
            (Ok(Async::NotReady), _) => Ok(Async::NotReady),
            _ => write_result
        }
    }
}

impl StreamWriter {
    pub fn new(stream: Box<WriteHalfWrapper>,
               peer_addr: SocketAddr,
               rx_to_write: Box<ReceiverWrapper<SequencedPacket>>,
               stream_key: StreamKey) -> StreamWriter {
        let name = format!("ProxyClient for {:?}/{}", stream_key, peer_addr);
        let logger = Logger::new(&name[..]);
        StreamWriter {
            stream,
            logger,
            sequence_buffer: SequenceBuffer::new(),
            rx_to_write,
        }
    }

    fn read_data_from_channel(&mut self) -> Result<Async<()>, ()> {
        loop {
            match self.rx_to_write.poll() {
                Ok(Async::Ready(Some(sequenced_packet))) => {
                    self.sequence_buffer.push(sequenced_packet);
                },
                Ok(Async::Ready(None)) => return Ok(Async::Ready(())),
                Ok(Async::NotReady) => return Ok(Async::NotReady),
                Err(_) => panic!("got an error from an unbounded channel which cannot return error"),
            };
        }
    }

    fn write_from_buffer_to_stream(&mut self) -> Result<Async<()>, ()> {
        let mut repushee = None;

        while let Some(packet) = match repushee { // break out of outer loop if there was a NotReady
            None => self.sequence_buffer.poll(),
            Some(_) => None,
        } {
            loop { // this allows retries for non-dead-stream errors
                self.logger.debug(format!("Writing {} bytes over existing stream", packet.data.len()));
                match self.stream.poll_write(&packet.data) {
                    Err(e) => {
                        if indicates_dead_stream(e.kind()) {
                            self.logger.error(format!("Error writing {} bytes: {}", packet.data.len(), e));
                            return Err(())
                        } else {
                            // TODO this could be exploitable and inefficient: if we keep getting non-dead-stream errors, we go into a tight loop and do not return
                            self.logger.warning(format!("Continuing after write error: {}", e));
                        }
                    },
                    Ok(Async::Ready(_)) => {
                        self.logger.debug(format!("Wrote {} bytes", packet.data.len()));
                        break // break out of inner loop to get the next packet from buffer
                    },
                    Ok(Async::NotReady) => {
                        repushee = Some(packet);
                        break
                    }
                }
            }
        }

        if let Some(packet) = repushee {
            self.sequence_buffer.repush(packet);
            return Ok(Async::NotReady)
        }
        Ok(Async::Ready(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Error;
    use std::io::ErrorKind;
    use std::str::FromStr;
    use test_utils::logging::init_test_logging;
    use test_utils::logging::TestLogHandler;
    use std::sync::Arc;
    use std::sync::Mutex;
    use test_utils::channel_wrapper_mocks::ReceiverWrapperMock;
    use test_utils::tokio_wrapper_mocks::WriteHalfWrapperMock;
    use test_utils::test_utils::make_meaningless_stream_key;

    #[test]
    fn stream_writer_writes_packets_in_sequenced_order() {
        init_test_logging();
        let packet_a : Vec<u8> = vec!(1, 3, 5, 9, 7);
        let packet_b : Vec<u8> = vec!(2, 4, 10, 8, 6, 3);
        let packet_c : Vec<u8> = vec!(1, 0, 1, 2);

        let stream_key = make_meaningless_stream_key ();

        let mut rx_to_write = Box::new(ReceiverWrapperMock::new());
        rx_to_write.poll_results = vec!(
            Ok(Async::Ready(Some(SequencedPacket {data: packet_c.to_vec (), sequence_number: 2}))),
            Ok(Async::Ready(Some(SequencedPacket {data: packet_b.to_vec (), sequence_number: 1}))),
            Ok(Async::Ready(Some(SequencedPacket {data: vec! (), sequence_number: 3}))),
            Ok(Async::Ready(Some(SequencedPacket {data: packet_a.to_vec (), sequence_number: 0}))),
            Ok(Async::Ready(None))
        );

        let writer = WriteHalfWrapperMock {
            poll_write_params: Arc::new(Mutex::new(vec!())),
            poll_write_results: vec!(
                Ok(Async::Ready(packet_a.len())),
                Ok(Async::Ready(packet_b.len())),
                Ok(Async::Ready(packet_c.len())),
                Ok(Async::Ready(0))
            ),
        };
        let write_params_mutex = writer.poll_write_params.clone();
        let peer_addr = SocketAddr::from_str("2.2.3.4:5678").unwrap();

        let mut subject = StreamWriter::new(
            Box::new(writer),
            peer_addr,
            rx_to_write,
            stream_key,
        );

        let _res = subject.poll();

        let write_params = write_params_mutex.lock().unwrap();

        assert_eq!(write_params[0], packet_a);
        assert_eq!(write_params[1], packet_b);
        assert_eq!(write_params[2], packet_c);
        assert_eq!(write_params[3], vec!());

        let tlh = TestLogHandler::new();
        tlh.assert_logs_contain_in_order(vec!(
            format! ("DEBUG: ProxyClient for {:?}/2.2.3.4:5678: Writing 5 bytes over existing stream", stream_key).as_str (),
            format! ("DEBUG: ProxyClient for {:?}/2.2.3.4:5678: Wrote 5 bytes", stream_key).as_str (),
            format! ("DEBUG: ProxyClient for {:?}/2.2.3.4:5678: Writing 6 bytes over existing stream", stream_key).as_str (),
            format! ("DEBUG: ProxyClient for {:?}/2.2.3.4:5678: Wrote 6 bytes", stream_key).as_str (),
            format! ("DEBUG: ProxyClient for {:?}/2.2.3.4:5678: Writing 4 bytes over existing stream", stream_key).as_str (),
            format! ("DEBUG: ProxyClient for {:?}/2.2.3.4:5678: Wrote 4 bytes", stream_key).as_str (),
            format! ("DEBUG: ProxyClient for {:?}/2.2.3.4:5678: Writing 0 bytes over existing stream", stream_key).as_str (),
            format! ("DEBUG: ProxyClient for {:?}/2.2.3.4:5678: Wrote 0 bytes", stream_key).as_str (),
        ));
    }

    #[test]
    fn stream_writer_returns_not_ready_when_the_stream_is_not_ready() {
        let stream_key = make_meaningless_stream_key ();
        let mut rx_to_write = Box::new(ReceiverWrapperMock::new());
        rx_to_write.poll_results = vec!(
            Ok(Async::Ready(Some(SequencedPacket {data: b"These are the times".to_vec (), sequence_number: 0}))),
            Ok(Async::Ready(None)),
        );
        let writer = WriteHalfWrapperMock {
            poll_write_params: Arc::new(Mutex::new(vec!())),
            poll_write_results: vec!(
                Ok(Async::NotReady)
            ),
        };
        let write_params = writer.poll_write_params.clone();

        let mut subject = StreamWriter::new(Box::new(writer), SocketAddr::from_str("1.3.3.4:5678").unwrap(),
                                            rx_to_write, stream_key);

        let result = subject.poll();

        assert_eq!(result, Ok(Async::NotReady));
        assert_eq!(write_params.lock().unwrap().len(), 1);
    }

    #[test]
    fn stream_writer_returns_not_ready_when_the_channel_is_not_ready() {
        let mut rx_to_write    = Box::new(ReceiverWrapperMock::new());
        rx_to_write.poll_results = vec!(
            Ok(Async::NotReady),
        );
        let stream_key = make_meaningless_stream_key ();
        let writer = WriteHalfWrapperMock {
            poll_write_params: Arc::new(Mutex::new(vec!())),
            poll_write_results: vec!(
                Ok(Async::Ready(5))
            ),
        };

        let mut subject = StreamWriter::new(Box::new(writer), SocketAddr::from_str("1.2.4.4:5678").unwrap(),
                                            rx_to_write, stream_key);

        let result = subject.poll();

        assert_eq!(result, Ok(Async::NotReady));
    }

    #[test]
    fn stream_writer_logs_error_and_continues_when_it_gets_a_non_dead_stream_error() {
        init_test_logging();
        let text_data = b"These are the times";
        let stream_key = make_meaningless_stream_key ();

        let mut rx_to_write = Box::new(ReceiverWrapperMock::new());
        rx_to_write.poll_results = vec!(
            Ok(Async::Ready(Some(SequencedPacket {data: text_data.to_vec (), sequence_number: 0}))),
            Ok(Async::NotReady)
        );
        let writer = WriteHalfWrapperMock {
            poll_write_params: Arc::new(Mutex::new(vec!())),
            poll_write_results: vec!(
                Err(Error::from(ErrorKind::Other)),
                Ok(Async::Ready(text_data.len())),
                Ok(Async::NotReady)
            ),
        };
        let write_params = writer.poll_write_params.clone();
        let peer_addr = SocketAddr::from_str("1.3.3.4:5678").unwrap();

        let mut subject = StreamWriter::new(Box::new(writer), peer_addr,
                                            rx_to_write, stream_key);

        subject.poll().unwrap();

        assert_eq!(write_params.lock().unwrap().len(), 2);
        let tlh = TestLogHandler::new();
        tlh.assert_logs_contain_in_order(vec!(
            format! ("DEBUG: ProxyClient for {:?}/1.3.3.4:5678: Writing 19 bytes over existing stream", stream_key).as_str (),
            format! ("WARN: ProxyClient for {:?}/1.3.3.4:5678: Continuing after write error: other os error", stream_key).as_str (),
            format! ("DEBUG: ProxyClient for {:?}/1.3.3.4:5678: Wrote 19 bytes", stream_key).as_str ()));
    }

    #[test]
    fn stream_writer_attempts_to_write_until_successful_before_reading_new_messages_from_channel() {
        let stream_key = make_meaningless_stream_key ();
        let first_data = &b"These are the times"[..];
        let second_data = &b"These are the other times"[..];

        let mut rx_to_write = Box::new(ReceiverWrapperMock::new());
        rx_to_write.poll_results = vec!(
            Ok(Async::Ready(Some(SequencedPacket {data: first_data.to_vec (), sequence_number: 0}))),
            Ok(Async::Ready(Some(SequencedPacket {data: second_data.to_vec (), sequence_number: 1}))),
            Ok(Async::NotReady),
        );
        let writer = WriteHalfWrapperMock {
            poll_write_params: Arc::new(Mutex::new(vec!())),
            poll_write_results: vec!(
                Err(Error::from(ErrorKind::Other)),
                Ok(Async::Ready(first_data.len())),
                Ok(Async::Ready(second_data.len())),
                Ok(Async::NotReady)
            ),
        };
        let write_params = writer.poll_write_params.clone();
        let peer_addr = SocketAddr::from_str("1.2.3.9:5678").unwrap();

        let mut subject = StreamWriter::new(Box::new(writer), peer_addr,
                                            rx_to_write, stream_key);

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
        let stream_key = make_meaningless_stream_key ();
        let mut rx_to_write = Box::new(ReceiverWrapperMock::new());
        rx_to_write.poll_results = vec!(
            Ok(Async::Ready(Some(SequencedPacket {data: b"These are the times".to_vec (), sequence_number: 0}))),
            Ok(Async::Ready(None))
        );
        let writer = WriteHalfWrapperMock {
            poll_write_params: Arc::new(Mutex::new(vec!())),
            poll_write_results: vec!(
                Ok(Async::Ready(5)),
                Err(Error::from(ErrorKind::BrokenPipe))
            ),
        };
        let peer_addr = SocketAddr::from_str("1.2.3.4:999").unwrap();

        let mut subject = StreamWriter::new(Box::new(writer), peer_addr,
                                            rx_to_write, stream_key);

        let result = subject.poll();

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Async::Ready(()));
    }

    #[test]
    #[should_panic(expected = "got an error from an unbounded channel which cannot return error")]
    fn stream_writer_panics_if_channel_returns_err() {
        let mut rx_to_write = Box::new(ReceiverWrapperMock::new());
        rx_to_write.poll_results = vec!(
            Err(()),
        );
        let writer = WriteHalfWrapperMock {
            poll_write_params: Arc::new(Mutex::new(vec!())),
            poll_write_results: vec!(),
        };
        let stream_key = make_meaningless_stream_key ();
        let peer_addr = SocketAddr::from_str("4.2.3.4:5678").unwrap();

        let mut subject = StreamWriter::new(Box::new(writer), peer_addr,
                                            rx_to_write, stream_key);

        subject.poll().unwrap();
    }

    #[test]
    fn dead_stream_error_generates_log_and_returns_err() {
        init_test_logging();

        let stream_key = make_meaningless_stream_key ();
        let mut rx_to_write = Box::new(ReceiverWrapperMock::new());
        rx_to_write.poll_results = vec!(
            Ok(Async::Ready(Some(SequencedPacket {data: b"These are the times".to_vec (), sequence_number: 0}))),
            Ok(Async::Ready(None))
        );
        let writer = WriteHalfWrapperMock {
            poll_write_params: Arc::new(Mutex::new(vec!())),
            poll_write_results: vec!(Err(Error::from(ErrorKind::BrokenPipe))),
        };
        let mut subject = StreamWriter::new(Box::new(writer), SocketAddr::from_str("2.3.4.5:80").unwrap(),
                                            rx_to_write, stream_key);

        assert!(subject.poll().is_err());

        TestLogHandler::new().exists_log_containing(format! ("ERROR: ProxyClient for {:?}/2.3.4.5:80: Error writing 19 bytes: broken pipe", stream_key).as_str ());
    }

    #[test]
    fn stream_writer_reattempts_writing_packets_that_were_prevented_by_not_ready() {
        let stream_key = make_meaningless_stream_key ();
        let mut rx = Box::new(ReceiverWrapperMock::new());
        rx.poll_results = vec!(
            Ok(Async::Ready(Some(SequencedPacket {data: b"These are the times".to_vec (), sequence_number: 0}))),
            Ok(Async::NotReady),
            Ok(Async::NotReady),
        );

        let writer = WriteHalfWrapperMock {
            poll_write_params: Arc::new(Mutex::new(vec!())),
            poll_write_results: vec!(
                Ok(Async::NotReady),
                Ok(Async::Ready(5)),
                Ok(Async::NotReady),
            ) };
        let write_params = writer.poll_write_params.clone();
        let peer_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();

        let mut subject = StreamWriter::new(
            Box::new(writer),
                   peer_addr,
                   rx,
                   stream_key,
        );

        let result = subject.poll();
        assert_eq!(result, Ok(Async::NotReady));

        let result = subject.poll();
        assert_eq!(result, Ok(Async::NotReady));

        assert_eq!(write_params.lock().unwrap().len(), 2);
    }
}