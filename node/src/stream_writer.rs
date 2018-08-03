// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use actix::Recipient;
use actix::Syn;
use tokio::prelude::Async;
use tokio::prelude::Future;
use sub_lib::channel_wrappers::ReceiverWrapper;
use sub_lib::cryptde::StreamKey;
use sub_lib::logger::Logger;
use sub_lib::sequence_buffer::SequenceBuffer;
use sub_lib::tokio_wrappers::WriteHalfWrapper;
use sub_lib::utils::indicates_dead_stream;
use stream_messages::*;
use masquerader::Masquerader;
use sub_lib::sequence_buffer::SequencedPacket;

pub struct StreamWriterReal {
    stream: Box<WriteHalfWrapper>,
    stream_key: StreamKey,
    remove_sub: Recipient<Syn, RemoveStreamMsg>,
    rx_to_write: Box<ReceiverWrapper<SequencedPacket>>,
    logger: Logger,
    masquerader: Box<Masquerader>,
    sequence_buffer: SequenceBuffer,
}

impl Future for StreamWriterReal {
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

impl StreamWriterReal {
    pub fn new(stream: Box<WriteHalfWrapper>,
               remove_sub: Recipient<Syn, RemoveStreamMsg>,
               socket_addr: StreamKey,
               rx_to_write: Box<ReceiverWrapper<SequencedPacket>>,
               writer_config: Box<Masquerader>) -> StreamWriterReal {
        let name = format! ("StreamWriter for {}", socket_addr);
        let logger = Logger::new (&name[..]);
        StreamWriterReal {
            stream,
            stream_key: socket_addr,
            remove_sub,
            rx_to_write,
            logger,
            masquerader: writer_config,
            sequence_buffer: SequenceBuffer::new(),
        }
    }

    fn read_data_from_channel(&mut self) -> Result<Async<()>, ()> {
        loop {
            match self.rx_to_write.poll() {
                Ok(Async::Ready(Some(sequenced_packet))) => self.sequence_buffer.push(sequenced_packet),
                Ok(Async::Ready(None)) => return Ok(Async::Ready(())),
                Ok(Async::NotReady) => return Ok(Async::NotReady),
                Err(_) => panic!("got an error from an unbounded channel which cannot return error")
            }
        }
    }

    fn write_from_buffer_to_stream(&mut self) -> Result<Async<()>, ()> {
        while let Some(packet) = self.sequence_buffer.poll() {
            loop {
                let mask_result = self.masquerader.mask(packet.data.as_slice());
                let write_result = match mask_result {
                    Err(_) => unimplemented!("Masking failed"), // TODO should the stream be shut down, or should we allow the recipient to request a retry? // TODO FIXME this will allow silently dropped sequenced packets: the writer will continue to write the remaining packets, which is a problem
                    Ok(masked_data) => self.stream.poll_write(&masked_data)
                };
                match write_result {
                    Err(e) => {
                        if indicates_dead_stream(e.kind()) {
                            self.logger.error(format!("Cannot transmit {} bytes: {}", packet.data.len(), e));
                            self.remove_sub.try_send(RemoveStreamMsg { socket_addr: self.stream_key }).expect("StreamHandlerPool is dead");
                            return Err(())
                        } else {
                            // TODO this could be... inefficient, if we keep getting non-dead-stream errors. (we do not return)
                            self.logger.warning(format!("Continuing after write error: {}", e));
                        }
                    },
                    Ok(Async::Ready(_)) => break,
                    Ok(Async::NotReady) => return Ok(Async::NotReady)
                }
            }
        }
        Ok(Async::Ready(()))
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
    use actix::Arbiter;
    use actix::msgs;
    use actix::System;
    use stream_handler_pool::StreamHandlerPoolSubs;
    use node_test_utils::make_stream_handler_pool_subs_from;
    use test_utils::channel_wrapper_mocks::ReceiverWrapperMock;
    use test_utils::tokio_wrapper_mocks::WriteHalfWrapperMock;
    use test_utils::test_utils::init_test_logging;
    use test_utils::test_utils::TestLogHandler;
    use null_masquerader::NullMasquerader;
    use json_masquerader::JsonMasquerader;
    use discriminator::UnmaskedChunk;
    use masquerader::MasqueradeError;
    use test_utils::recorder::make_recorder;
    use test_utils::recorder::RecordAwaiter;
    use test_utils::recorder::Recording;
    use std::io::ErrorKind;

    fn make_stream_handler_pool_mock() -> (RecordAwaiter, Arc<Mutex<Recording>>, StreamHandlerPoolSubs) {
        let (shp, awaiter, recording) = make_recorder();
        (awaiter, recording, make_stream_handler_pool_subs_from(Some(shp)))
    }

    struct FailingMasquerader {}

    impl Masquerader for FailingMasquerader {
        fn try_unmask(&self, _item: &[u8]) -> Option<UnmaskedChunk> {
            unimplemented!()
        }

        fn mask(&self, _data: &[u8]) -> Result<Vec<u8>, MasqueradeError> {
            Err(MasqueradeError::LowLevelDataError(String::from_str("don't care").unwrap()))
        }
    }

    #[test]
    fn stream_writer_returns_not_ready_when_the_stream_is_not_ready() {
        let system = System::new("test");
        let mut rx = Box::new(ReceiverWrapperMock::new());
        rx.poll_results = vec!(
            Ok(Async::Ready(Some(SequencedPacket::new(b"hello".to_vec(), 0, false)))),
            Ok(Async::Ready(Some(SequencedPacket::new(b"world".to_vec(), 1, false)))),
            Ok(Async::NotReady),
        );

        let writer = WriteHalfWrapperMock {
            poll_write_params: Arc::new(Mutex::new(vec!())),
            poll_write_results: vec!(
                Ok(Async::NotReady)
            ) };
        let write_params = writer.poll_write_params.clone();
        let (_awaiter, _recording, stream_handler_pool_subs) = make_stream_handler_pool_mock();
        let peer_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();

        let mut subject = StreamWriterReal::new(Box::new(writer), stream_handler_pool_subs.remove_sub, peer_addr, rx, Box::new(NullMasquerader::new()));

        let result = subject.poll();

        Arbiter::system().try_send(msgs::SystemExit(0)).unwrap ();
        system.run ();

        assert_eq!(result, Ok(Async::NotReady));
        assert_eq!(write_params.lock().unwrap().len(), 1);
    }

    #[test]
    fn stream_writer_returns_not_ready_when_the_channel_is_not_ready() {
        let system = System::new("test");
        let mut rx = Box::new(ReceiverWrapperMock::new());
        rx.poll_results = vec!(
            Ok(Async::NotReady),
        );

        let writer = WriteHalfWrapperMock {
            poll_write_params: Arc::new(Mutex::new(vec!())),
            poll_write_results: vec!(
                Ok(Async::Ready(5))
            ) };
        let (_awaiter, _recording, stream_handler_pool_subs) = make_stream_handler_pool_mock();
        let peer_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();

        let mut subject = StreamWriterReal::new(Box::new(writer), stream_handler_pool_subs.remove_sub, peer_addr, rx, Box::new(NullMasquerader::new()));

        let result = subject.poll();

        Arbiter::system().try_send(msgs::SystemExit(0)).unwrap ();
        system.run ();

        assert_eq!(result, Ok(Async::NotReady));
    }

    #[test]
    fn stream_writer_shuts_down_and_returns_err_when_it_gets_a_dead_stream_error() {
        let system = System::new("test");
        let mut rx = Box::new(ReceiverWrapperMock::new());
        rx.poll_results = vec!(
            Ok(Async::Ready(Some(SequencedPacket::new(b"hello".to_vec(), 0, false)))),
            Ok(Async::Ready(Some(SequencedPacket::new(b"world".to_vec(), 0, false)))),
            Ok(Async::NotReady),
        );
        let writer = WriteHalfWrapperMock {
            poll_write_params: Arc::new(Mutex::new(vec!())),
            poll_write_results: vec!(
                Err(io::Error::from(ErrorKind::BrokenPipe))
            )
        };
        let write_params = writer.poll_write_params.clone();
        let (awaiter, recording_arc, stream_handler_pool_subs) = make_stream_handler_pool_mock();
        let peer_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();

        let mut subject = StreamWriterReal::new(Box::new(writer), stream_handler_pool_subs.remove_sub, peer_addr.clone(), rx, Box::new(NullMasquerader::new()));

        let result = subject.poll();

        Arbiter::system().try_send(msgs::SystemExit(0)).unwrap ();
        system.run ();

        awaiter.await_message_count(1);
        let recording = recording_arc.lock().unwrap();
        assert_eq!(recording.get_record::<RemoveStreamMsg>(0), &RemoveStreamMsg {
            socket_addr: peer_addr,
        });

        assert_eq!(result.is_ok(), false);
        assert_eq!(write_params.lock().unwrap().len(), 1);
    }

    #[test]
    fn stream_writer_logs_error_and_continues_when_it_gets_a_non_dead_stream_error() {
        init_test_logging();
        let system = System::new("test");
        let mut rx = Box::new(ReceiverWrapperMock::new());
        rx.poll_results = vec!(
            Ok(Async::Ready(Some(SequencedPacket::new(b"hello".to_vec(), 0, false)))),
            Ok(Async::Ready(Some(SequencedPacket::new(b"world".to_vec(), 1, false)))),
            Ok(Async::NotReady),
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
        let (_, _, stream_handler_pool_subs) = make_stream_handler_pool_mock();
        let peer_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();

        let mut subject = StreamWriterReal::new(Box::new(writer), stream_handler_pool_subs.remove_sub, peer_addr.clone(), rx, Box::new(NullMasquerader::new()));

        subject.poll().unwrap();

        Arbiter::system().try_send(msgs::SystemExit(0)).unwrap ();
        system.run ();

        TestLogHandler::new ().await_log_matching("ThreadId\\(\\d+\\): WARN: StreamWriter for 1\\.2\\.3\\.4:5678: Continuing after write error: other os error", 1000);
        assert_eq!(write_params.lock().unwrap().len(), 3);
    }

    #[test]
    fn stream_writer_writes_to_stream_and_does_not_shut_down() {
        let system = System::new("test");
        let first_data = b"hello";
        let second_data = b"world";
        let mut rx = Box::new(ReceiverWrapperMock::new());
        rx.poll_results = vec!(
            Ok(Async::Ready(Some(SequencedPacket::new(first_data.to_vec(), 0, false)))),
            Ok(Async::Ready(Some(SequencedPacket::new(second_data.to_vec(), 1, false)))),
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
        let (_awaiter, _recording_arc, stream_handler_pool_subs) = make_stream_handler_pool_mock();
        let peer_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();

        let mut subject = StreamWriterReal::new(Box::new(writer), stream_handler_pool_subs.remove_sub, peer_addr.clone(), rx, Box::new(NullMasquerader::new()));

        let result = subject.poll();

        Arbiter::system().try_send(msgs::SystemExit(0)).unwrap ();
        system.run ();

        assert_eq!(result.is_ok(), true);

        let mut params = write_params.lock().unwrap();
        assert_eq!(params.len(), 2);
        assert_eq!(params.remove(0), first_data.to_vec());
        assert_eq!(params.remove(0), second_data.to_vec());
    }

    #[test]
    fn stream_writer_writes_packets_to_stream_in_order_and_does_not_shut_down() {
        let system = System::new("test");
        let first_data = b"hello";
        let second_data = b"world";
        let third_data = b"!";
        let mut rx = Box::new(ReceiverWrapperMock::new());
        rx.poll_results = vec!(
            Ok(Async::Ready(Some(SequencedPacket::new(third_data.to_vec(), 2, false)))),
            Ok(Async::Ready(Some(SequencedPacket::new(second_data.to_vec(), 1, false)))),
            Ok(Async::Ready(Some(SequencedPacket::new(first_data.to_vec(), 0, false)))),
            Ok(Async::NotReady)
        );
        let writer = WriteHalfWrapperMock {
            poll_write_params: Arc::new(Mutex::new(vec!())),
            poll_write_results: vec!(
                Ok(Async::Ready(first_data.len())),
                Ok(Async::Ready(second_data.len())),
                Ok(Async::Ready(third_data.len())),
            )
        };
        let write_params = writer.poll_write_params.clone();
        let (_awaiter, _recording_arc, stream_handler_pool_subs) = make_stream_handler_pool_mock();
        let peer_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();

        let mut subject = StreamWriterReal::new(Box::new(writer), stream_handler_pool_subs.remove_sub, peer_addr.clone(), rx, Box::new(NullMasquerader::new()));

        let result = subject.poll();

        Arbiter::system().try_send(msgs::SystemExit(0)).unwrap ();
        system.run ();

        assert_eq!(result.is_ok(), true);

        let mut params = write_params.lock().unwrap();
        assert_eq!(params.len(), 3);
        assert_eq!(params.remove(0), first_data.to_vec());
        assert_eq!(params.remove(0), second_data.to_vec());
        assert_eq!(params.remove(0), third_data.to_vec());
    }

    #[test]
    fn stream_writer_attempts_to_write_until_successful_before_reading_new_messages_from_channel() {
        let system = System::new("test");
        let first_data = b"hello";
        let second_data = b"world";
        let mut rx = Box::new(ReceiverWrapperMock::new());
        rx.poll_results = vec!(
            Ok(Async::Ready(Some(SequencedPacket::new(first_data.to_vec(), 0, false)))),
            Ok(Async::Ready(Some(SequencedPacket::new(second_data.to_vec(), 1, false)))),
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
        let (_awaiter, _recording_arc, stream_handler_pool_subs) = make_stream_handler_pool_mock();
        let peer_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();

        let mut subject = StreamWriterReal::new(Box::new(writer), stream_handler_pool_subs.remove_sub, peer_addr.clone(), rx, Box::new(NullMasquerader::new()));

        let result = subject.poll();

        Arbiter::system().try_send(msgs::SystemExit(0)).unwrap ();
        system.run ();

        assert_eq!(result.is_ok(), true);

        let mut params = write_params.lock().unwrap();
        assert_eq!(params.len(), 3);
        assert_eq!(params.remove(0), first_data.to_vec());
        assert_eq!(params.remove(0), first_data.to_vec());
        assert_eq!(params.remove(0), second_data.to_vec());
    }

    #[test]
    fn stream_writer_exits_if_channel_is_closed() {
        let system = System::new("test");
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
        let (_awaiter, _recording_arc, stream_handler_pool_subs) = make_stream_handler_pool_mock();
        let peer_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();

        let mut subject = StreamWriterReal::new(Box::new(writer), stream_handler_pool_subs.remove_sub, peer_addr.clone(), rx, Box::new(NullMasquerader::new()));

        let result = subject.poll();

        Arbiter::system().try_send(msgs::SystemExit(0)).unwrap ();
        system.run ();

        assert_eq!(result.is_ok(), true);
    }

    #[test]
    #[should_panic (expected = "got an error from an unbounded channel which cannot return error")]
    fn stream_writer_panics_if_channel_returns_err() {
        let system = System::new("test");
        let mut rx = Box::new(ReceiverWrapperMock::new());
        rx.poll_results = vec!(
            Err(()),
        );
        let writer = WriteHalfWrapperMock {
            poll_write_params: Arc::new(Mutex::new(vec!())),
            poll_write_results: vec!()
        };
        let (_awaiter, _recording_arc, stream_handler_pool_subs) = make_stream_handler_pool_mock();
        let peer_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();

        let mut subject = StreamWriterReal::new(Box::new(writer), stream_handler_pool_subs.remove_sub, peer_addr.clone(), rx, Box::new(NullMasquerader::new()));

        subject.poll().unwrap();

        Arbiter::system().try_send(msgs::SystemExit(0)).unwrap ();
        system.run ();
    }

    #[test]
    fn stream_writer_uses_masquerader_to_mask_outgoing_data() {
        let system = System::new("test");
        let first_data = b"hello";
        let second_data = b"world";
        let mut rx_to_write = Box::new(ReceiverWrapperMock::new());
        rx_to_write.poll_results = vec!(
            Ok(Async::Ready(Some(SequencedPacket::new(first_data.to_vec(), 0, false)))),
            Ok(Async::Ready(Some(SequencedPacket::new(second_data.to_vec(), 1, false)))),
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
        let (_awaiter, _recording_arc, stream_handler_pool_subs) = make_stream_handler_pool_mock();
        let peer_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();

        let mut subject = StreamWriterReal::new(Box::new(writer), stream_handler_pool_subs.remove_sub, peer_addr.clone(), rx_to_write, Box::new(JsonMasquerader::new()));

        let result = subject.poll();

        Arbiter::system().try_send(msgs::SystemExit(0)).unwrap ();
        system.run ();

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
        let system = System::new("test");
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
        let (_awaiter, _recording_arc, stream_handler_pool_subs) = make_stream_handler_pool_mock();
        let peer_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();

        let mut subject = StreamWriterReal::new(Box::new(writer), stream_handler_pool_subs.remove_sub, peer_addr.clone(), rx_to_write, Box::new(FailingMasquerader {}));

        let _result = subject.poll();

        Arbiter::system().try_send(msgs::SystemExit(0)).unwrap ();
        system.run ();
    }
}
