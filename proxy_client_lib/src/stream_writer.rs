// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use std::net::SocketAddr;
use tokio::prelude::Async;
use tokio::prelude::Future;
use sub_lib::channel_wrappers::ReceiverWrapper;
use sub_lib::hopper::ExpiredCoresPackage;
use sub_lib::logger::Logger;
use sub_lib::proxy_server::ClientRequestPayload;
use sub_lib::sequence_buffer::SequenceBuffer;
use sub_lib::sequence_buffer::SequencedPacket;
use sub_lib::stream_key::StreamKey;
use sub_lib::tokio_wrappers::WriteHalfWrapper;
use sub_lib::utils::indicates_dead_stream;

pub struct StreamWriter {
    stream: Box<WriteHalfWrapper>,
    peer_addr: SocketAddr,
    logger: Logger,
    sequence_buffer: SequenceBuffer,
    rx_to_write: Box<ReceiverWrapper<ExpiredCoresPackage>>,
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
               rx_to_write: Box<ReceiverWrapper<ExpiredCoresPackage>>,
               stream_key: StreamKey) -> StreamWriter {
        let name = format!("ProxyClient for {}", stream_key);
        let logger = Logger::new(&name[..]);
        StreamWriter {
            peer_addr,
            stream,
            logger,
            sequence_buffer: SequenceBuffer::new(),
            rx_to_write,
        }
    }

    fn extract_payload(&self, package: &ExpiredCoresPackage) -> Result<ClientRequestPayload, ()> {
        package.payload::<ClientRequestPayload>().map_err(|err| {
            self.logger.error(format!("Error ('{}') interpreting payload for transmission: {:?}", err, package.payload.data));
            ()
        })
    }

    fn read_data_from_channel(&mut self) -> Result<Async<()>, ()> {
        loop {
            match self.rx_to_write.poll() {
                Ok(Async::Ready(Some(package))) => {
                    let payload = self.extract_payload(&package)?;
                    let packet = SequencedPacket::from(&payload);
                    self.sequence_buffer.push(packet);
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
                self.logger.debug(format!("Writing {} bytes to {} over existing stream", packet.data.len(), self.peer_addr));
                match self.stream.poll_write(&packet.data) {
                    Err(e) => {
                        if indicates_dead_stream(e.kind()) {
                            self.logger.error(format!("Error writing {} bytes to {}: {}", packet.data.len(), self.peer_addr, e));
                            return Err(())
                        } else {
                            // TODO this could be exploitable and inefficient: if we keep getting non-dead-stream errors, we go into a tight loop and do not return
                            self.logger.warning(format!("Continuing after write error: {}", e));
                        }
                    },
                    Ok(Async::Ready(_)) => {
                        self.logger.debug(format!("Wrote {} bytes to {}", packet.data.len(), self.peer_addr));
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
    use serde_cbor;
    use sub_lib::hopper::ExpiredCoresPackage;
    use sub_lib::proxy_server::ProxyProtocol;
    use test_utils::channel_wrapper_mocks::ReceiverWrapperMock;
    use test_utils::tokio_wrapper_mocks::WriteHalfWrapperMock;
    use test_utils::test_utils;
    use test_utils::test_utils::zero_hop_route_response;
    use sub_lib::cryptde::CryptDE;
    use sub_lib::cryptde_null::CryptDENull;
    use sub_lib::cryptde::Key;
    use sub_lib::cryptde::PlainData;

    #[test]
    fn stream_writer_writes_packets_in_sequenced_order() {
        init_test_logging();
        let packet_a : Vec<u8> = vec!(1, 3, 5, 9, 7);
        let packet_b : Vec<u8> = vec!(2, 4, 10, 8, 6, 3);
        let packet_c : Vec<u8> = vec!(1, 0, 1, 2);

        let stream_key = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let cryptde = CryptDENull::new();
        let originator_public_key = cryptde.public_key();

        let crp_a = ClientRequestPayload {
            stream_key,
            last_data: false,
            sequence_number: 0,
            data: PlainData::new(&packet_a),
            target_hostname: None,
            target_port: 0,
            protocol: ProxyProtocol::HTTP,
            originator_public_key: originator_public_key.clone(),
        };

        let crp_b = ClientRequestPayload {
            sequence_number: 1,
            data: PlainData::new(&packet_b),
            ..crp_a.clone()
        };

        let crp_c = ClientRequestPayload {
            sequence_number: 2,
            data: PlainData::new(&packet_c),
            ..crp_a.clone()
        };

        let crp_d = ClientRequestPayload {
            sequence_number: 3,
            data: PlainData::new(&vec!()),
            ..crp_a.clone()
        };

        let route_dont_care = zero_hop_route_response(&originator_public_key, &cryptde).route;

        let ecp_c = ExpiredCoresPackage::new(route_dont_care.clone(), PlainData::new(&serde_cbor::ser::to_vec(&crp_b).unwrap()));
        let ecp_b = ExpiredCoresPackage::new(route_dont_care.clone(), PlainData::new(&serde_cbor::ser::to_vec(&crp_c).unwrap()));
        let ecp_d = ExpiredCoresPackage::new(route_dont_care.clone(), PlainData::new(&serde_cbor::ser::to_vec(&crp_d).unwrap()));
        let ecp_a = ExpiredCoresPackage::new(route_dont_care, PlainData::new(&serde_cbor::ser::to_vec(&crp_a).unwrap()));

        let mut rx_to_write = Box::new(ReceiverWrapperMock::new());
        rx_to_write.poll_results = vec!(
            Ok(Async::Ready(Some(ecp_c))),
            Ok(Async::Ready(Some(ecp_b))),
            Ok(Async::Ready(Some(ecp_d))),
            Ok(Async::Ready(Some(ecp_a))),
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
        tlh.assert_logs_match_in_order(vec!(
            "DEBUG: ProxyClient for 1.2.3.4:5678: Writing 5 bytes to 2.2.3.4:5678 over existing stream",
            "DEBUG: ProxyClient for 1.2.3.4:5678: Wrote 5 bytes to 2.2.3.4:5678",
            "DEBUG: ProxyClient for 1.2.3.4:5678: Writing 6 bytes to 2.2.3.4:5678 over existing stream",
            "DEBUG: ProxyClient for 1.2.3.4:5678: Wrote 6 bytes to 2.2.3.4:5678",
            "DEBUG: ProxyClient for 1.2.3.4:5678: Writing 4 bytes to 2.2.3.4:5678 over existing stream",
            "DEBUG: ProxyClient for 1.2.3.4:5678: Wrote 4 bytes to 2.2.3.4:5678",
            "DEBUG: ProxyClient for 1.2.3.4:5678: Writing 0 bytes to 2.2.3.4:5678 over existing stream",
            "DEBUG: ProxyClient for 1.2.3.4:5678: Wrote 0 bytes to 2.2.3.4:5678",
        ));
    }

    #[test]
    fn stream_writer_returns_not_ready_when_the_stream_is_not_ready() {
        let stream_key = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let client_request_payload = ClientRequestPayload {
            stream_key,
            last_data: false,
            data: PlainData::new(&b"These are the times"[..]),
            target_hostname: Some(String::from("that.try")),
            target_port: 80,
            protocol: ProxyProtocol::HTTP,
            originator_public_key: Key::new(&b"men's souls"[..]),
            sequence_number: 0,
        };
        let package = ExpiredCoresPackage::new(test_utils::make_meaningless_route(),
                                               PlainData::new(&(serde_cbor::ser::to_vec(&client_request_payload).unwrap())[..]));
        let mut rx_to_write = Box::new(ReceiverWrapperMock::new());
        rx_to_write.poll_results = vec!(
            Ok(Async::Ready(Some(package))),
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
        let stream_key = SocketAddr::from_str("1.2.3.4:5678").unwrap();
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
        let stream_key = SocketAddr::from_str("4.4.4.4:7264").unwrap();

        let client_request_payload = ClientRequestPayload {
            stream_key: stream_key.clone(),
            last_data: false,
            data: PlainData::new(&text_data[..]),
            target_hostname: Some(String::from("that.try")),
            target_port: 80,
            protocol: ProxyProtocol::HTTP,
            originator_public_key: Key::new(&b"men's souls"[..]),
            sequence_number: 0,
        };
        let package = ExpiredCoresPackage::new(test_utils::make_meaningless_route(),
                                               PlainData::new(&(serde_cbor::ser::to_vec(&client_request_payload).unwrap())[..]));
        let mut rx_to_write = Box::new(ReceiverWrapperMock::new());
        rx_to_write.poll_results = vec!(
            Ok(Async::Ready(Some(package))),
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
        let peer_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();

        let mut subject = StreamWriter::new(Box::new(writer), peer_addr,
                                            rx_to_write, stream_key);

        subject.poll().unwrap();

        assert_eq!(write_params.lock().unwrap().len(), 2);
        let tlh = TestLogHandler::new();
        tlh.assert_logs_contain_in_order(vec!(
            "DEBUG: ProxyClient for 4.4.4.4:7264: Writing 19 bytes to 1.2.3.4:5678 over existing stream",
            "WARN: ProxyClient for 4.4.4.4:7264: Continuing after write error: other os error",
            "DEBUG: ProxyClient for 4.4.4.4:7264: Wrote 19 bytes to 1.2.3.4:5678"));
    }

    #[test]
    fn stream_writer_attempts_to_write_until_successful_before_reading_new_messages_from_channel() {
        let first_data = &b"These are the times"[..];
        let stream_key = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let client_request_payload = ClientRequestPayload {
            stream_key,
            last_data: false,
            data: PlainData::new(first_data),
            target_hostname: Some(String::from("that.try")),
            target_port: 80,
            protocol: ProxyProtocol::HTTP,
            originator_public_key: Key::new(&b"men's souls"[..]),
            sequence_number: 0,
        };
        let first_package = ExpiredCoresPackage::new(test_utils::make_meaningless_route(),
                                                     PlainData::new(&(serde_cbor::ser::to_vec(&client_request_payload).unwrap())[..]));
        let second_data = &b"These are the other times"[..];
        let client_request_payload = ClientRequestPayload {
            stream_key,
            last_data: false,
            data: PlainData::new(second_data),
            target_hostname: Some(String::from("that.try")),
            target_port: 80,
            protocol: ProxyProtocol::HTTP,
            originator_public_key: Key::new(&b"ladies' souls instead"[..]),
            sequence_number: 1,
        };
        let second_package = ExpiredCoresPackage::new(test_utils::make_meaningless_route(),
                                                      PlainData::new(&(serde_cbor::ser::to_vec(&client_request_payload).unwrap())[..]));

        let mut rx_to_write = Box::new(ReceiverWrapperMock::new());
        rx_to_write.poll_results = vec!(
            Ok(Async::Ready(Some(first_package))),
            Ok(Async::Ready(Some(second_package))),
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
        let stream_key = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let client_request_payload = ClientRequestPayload {
            stream_key,
            last_data: false,
            data: PlainData::new(&b"These are the times"[..]),
            target_hostname: Some(String::from("that.try")),
            target_port: 80,
            protocol: ProxyProtocol::HTTP,
            originator_public_key: Key::new(&b"men's souls"[..]),
            sequence_number: 0,
        };
        let package = ExpiredCoresPackage::new(test_utils::make_meaningless_route(),
                                               PlainData::new(&(serde_cbor::ser::to_vec(&client_request_payload).unwrap())[..]));
        let mut rx_to_write = Box::new(ReceiverWrapperMock::new());
        rx_to_write.poll_results = vec!(
            Ok(Async::Ready(Some(package))),
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
        let stream_key = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let peer_addr = SocketAddr::from_str("4.2.3.4:5678").unwrap();

        let mut subject = StreamWriter::new(Box::new(writer), peer_addr,
                                            rx_to_write, stream_key);

        subject.poll().unwrap();
    }

    #[test]
    fn dead_stream_error_generates_log_and_returns_err() {
        init_test_logging();

        let stream_key = SocketAddr::from_str("1.2.3.4:8765").unwrap();
        let client_request_payload = ClientRequestPayload {
            stream_key,
            last_data: false,
            data: PlainData::new(&b"These are the times"[..]),
            target_hostname: Some(String::from("that.try")),
            target_port: 80,
            protocol: ProxyProtocol::HTTP,
            originator_public_key: Key::new(&b"men's souls"[..]),
            sequence_number: 0
        };
        let package = ExpiredCoresPackage::new(test_utils::make_meaningless_route(),
                                               PlainData::new(&(serde_cbor::ser::to_vec(&client_request_payload).unwrap())[..]));
        let mut rx_to_write = Box::new(ReceiverWrapperMock::new());
        rx_to_write.poll_results = vec!(
            Ok(Async::Ready(Some(package))),
            Ok(Async::Ready(None))
        );
        let writer = WriteHalfWrapperMock {
            poll_write_params: Arc::new(Mutex::new(vec!())),
            poll_write_results: vec!(Err(Error::from(ErrorKind::BrokenPipe))),
        };
        let mut subject = StreamWriter::new(Box::new(writer), SocketAddr::from_str("2.3.4.5:80").unwrap(),
                                            rx_to_write, stream_key);

        assert!(subject.poll().is_err());

        TestLogHandler::new().exists_log_containing("ERROR: ProxyClient for 1.2.3.4:8765: Error writing 19 bytes to 2.3.4.5:80: broken pipe");
    }

    #[test]
    fn stream_writer_reattempts_writing_packets_that_were_prevented_by_not_ready() {
        let stream_key = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let client_request_payload = ClientRequestPayload {
            stream_key,
            last_data: false,
            data: PlainData::new(&b"These are the times"[..]),
            target_hostname: Some(String::from("that.try")),
            target_port: 80,
            protocol: ProxyProtocol::HTTP,
            originator_public_key: Key::new(&b"men's souls"[..]),
            sequence_number: 0
        };
        let package = ExpiredCoresPackage::new(test_utils::make_meaningless_route(),
                                               PlainData::new(&(serde_cbor::ser::to_vec(&client_request_payload).unwrap())[..]));
        let mut rx = Box::new(ReceiverWrapperMock::new());
        rx.poll_results = vec!(
            Ok(Async::Ready(Some(package))),
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