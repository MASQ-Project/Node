// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

use std::io;
use std::io::Error;
use std::net::IpAddr;
use std::sync::mpsc::Sender;
use actix::Recipient;
use actix::Syn;
use sub_lib::channel_wrappers::SenderWrapper;
use sub_lib::cryptde::StreamKey;
use sub_lib::hopper::ExpiredCoresPackage;
use sub_lib::hopper::IncipientCoresPackage;
use sub_lib::logger::Logger;
use sub_lib::proxy_server::ClientRequestPayload;
use sub_lib::tokio_wrappers::ReadHalfWrapper;
use stream_handler_pool::StreamHandlerPoolReal;
use stream_reader::StreamReader;
use stream_writer::StreamWriter;
use trust_dns_resolver::lookup_ip::LookupIp;
use tokio;
use trust_dns_resolver::error::ResolveError;
use sub_lib::channel_wrappers::FuturesChannelFactory;
use sub_lib::channel_wrappers::FuturesChannelFactoryReal;
use stream_handler_pool::StreamConnector;
use stream_handler_pool::StreamSplitter;

pub struct StreamHandlerEstablisher {
    pub stream_adder_tx: Sender<(StreamKey, Box<SenderWrapper<ExpiredCoresPackage>>)>,
    pub stream_killer_tx: Sender<StreamKey>,
    pub stream_connector: Box<StreamConnector>,
    pub stream_splitter: Box<StreamSplitter>,
    pub hopper_sub: Recipient<Syn, IncipientCoresPackage>,
    pub logger: Logger,
    pub channel_factory: Box<FuturesChannelFactory<ExpiredCoresPackage>>,
}

impl StreamHandlerEstablisher {
    pub fn establish_stream(&mut self, payload: &ClientRequestPayload, package: &ExpiredCoresPackage, lookup_result: Result<LookupIp, ResolveError>) -> io::Result<Box<SenderWrapper<ExpiredCoresPackage>>> {
        let target_hostname = payload.target_hostname.clone ().expect ("Internal error: DNS resolution succeeded on missing hostname");
        let ip_addrs: Vec<IpAddr> = match lookup_result {
            Err (e) => {
                self.logger.error (format! ("Could not find IP address for host {}: {}", target_hostname, e));
                return Err (Error::from (e))
            },
            Ok (lookup_ip) => lookup_ip.iter ().map (|x| x).collect ()
        };
        self.logger.debug (format! ("Found IP addresses for {}: {:?}", target_hostname, &ip_addrs));

        let stream = self.stream_connector.connect(ip_addrs, &target_hostname, payload.target_port, &self.logger);
        let (reader, writer, stream_peer_addr) = self.stream_splitter.split_stream(stream)?;

        let peer_addr = match stream_peer_addr {Ok (a) => format! ("{}", a), Err (_) => format! ("<unknown>")};

        self.spawn_stream_reader (package, &payload.clone(), reader, peer_addr.clone())?;

        let (tx_to_write, rx_to_write) = self.channel_factory.make();
        let stream_writer = StreamWriter::new (writer, peer_addr, rx_to_write, payload.stream_key);
        tokio::spawn(stream_writer);

        self.stream_adder_tx.send ((payload.stream_key, tx_to_write.clone())).expect("StreamHandlerPool died");
        Ok (tx_to_write)
    }

    fn spawn_stream_reader (&self, package: &ExpiredCoresPackage, payload: &ClientRequestPayload, read_stream: Box<ReadHalfWrapper>, peer_addr: String) -> io::Result<()> {
        let framer = StreamHandlerPoolReal::framer_from_protocol (payload.protocol);

        let stream_reader = StreamReader::new (
            payload.stream_key,
            self.hopper_sub.clone (),
            read_stream,
            self.stream_killer_tx.clone (),
            peer_addr.clone (),
            package.remaining_route.clone (),
            framer,
            payload.originator_public_key.clone (),
        );
        self.logger.debug (format! ("Spawning StreamReader for {}", peer_addr));
        tokio::spawn(stream_reader);
        Ok (())
    }
}

pub trait StreamEstablisherFactory {
    fn make(&self) -> StreamHandlerEstablisher;
}

pub struct StreamEstablisherFactoryReal {
    pub stream_adder_tx: Sender<(StreamKey, Box<SenderWrapper<ExpiredCoresPackage>>)>,
    pub stream_killer_tx: Sender<StreamKey>,
    pub stream_connector: Box<StreamConnector>,
    pub stream_splitter: Box<StreamSplitter>,
    pub hopper_sub: Recipient<Syn, IncipientCoresPackage>,
    pub logger: Logger,
}

impl StreamEstablisherFactory for StreamEstablisherFactoryReal {
    fn make(&self) -> StreamHandlerEstablisher {
        StreamHandlerEstablisher {
            stream_adder_tx: self.stream_adder_tx.clone(),
            stream_killer_tx: self.stream_killer_tx.clone(),
            stream_connector: self.stream_connector.dup(),
            stream_splitter: self.stream_splitter.dup(),
            hopper_sub: self.hopper_sub.clone(),
            logger: self.logger.clone(),
            channel_factory: Box::new(FuturesChannelFactoryReal {})
        }
    }
}

#[cfg (test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::io::ErrorKind;
    use std::net::SocketAddr;
    use std::str::FromStr;
    use std::sync::Arc;
    use std::sync::mpsc;
    use std::sync::Mutex;
    use std::thread;
    use actix::System;
    use serde_cbor;
    use local_test_utils::StreamConnectorMock;
    use local_test_utils::StreamSplitterMock;
    use sub_lib::cryptde::PlainData;
    use sub_lib::cryptde::Key;
    use sub_lib::proxy_server::ProxyProtocol;
    use sub_lib::proxy_client::ClientResponsePayload;
    use test_utils::tokio_wrapper_mocks::ReadHalfWrapperMock;
    use test_utils::test_utils;
    use test_utils::recorder::make_recorder;
    use test_utils::recorder::make_peer_actors_from;
    use futures::future::lazy;
    use tokio::prelude::Async;

    #[test]
    fn spawn_stream_reader_handles_http () {
        let (hopper, awaiter, hopper_recording_arc) = make_recorder();
        let (hopper_tx, hopper_rx) = mpsc::channel();
        thread::spawn(move || {
            let system = System::new ("test");
            let hopper_sub = make_peer_actors_from (None, None, Some (hopper), None, None).hopper.from_hopper_client;
            hopper_tx.send(hopper_sub).is_ok();
            system.run ();
        });

        let (response_tx, response_rx) = mpsc::channel();
        let test_future = lazy(move || {
            let hopper_sub = hopper_rx.recv().unwrap();

            let (stream_adder_tx, _stream_adder_rx) = mpsc::channel();
            let (stream_killer_tx, _) = mpsc::channel();
            let mut read_stream = Box::new (ReadHalfWrapperMock::new ());
            read_stream.poll_read_results = vec!(
                (vec! (0x16, 0x03, 0x03, 0x00, 0x00), Ok (Async::Ready(5))),
                (b"HTTP/1.1 200 OK\r\n\r\n".to_vec (), Ok (Async::Ready(19))),
                (vec!(), Err (Error::from (ErrorKind::BrokenPipe)))
            );

            let subject = StreamHandlerEstablisher {
                stream_adder_tx,
                stream_killer_tx,
                stream_connector: Box::new(StreamConnectorMock { connect_params: Arc::new(Mutex::new(vec!())) }), // only used in "after_resolution"
                stream_splitter: Box::new(StreamSplitterMock { split_stream_results: RefCell::new(vec!()) }), // only used in "after_resolution"
                hopper_sub,
                logger: Logger::new("Proxy Client"),
                channel_factory: Box::new(FuturesChannelFactoryReal {}),
            };
            subject.spawn_stream_reader(
                &ExpiredCoresPackage::new(test_utils::make_meaningless_route(), PlainData::new(&[])),
                &ClientRequestPayload {
                    stream_key: SocketAddr::from_str("255.255.255.255:65535").unwrap(),
                    last_data: false,
                    sequence_number: 0,
                    data: PlainData::new(&[]),
                    target_hostname: Some("blah".to_string()),
                    target_port: 0,
                    protocol: ProxyProtocol::HTTP,
                    originator_public_key: Key::new(&[]),
                },
                read_stream,
                String::from_str("1.2.3.4:5678").unwrap(),
            ).expect ("spawn_stream_reader () failed");

            awaiter.await_message_count (1);
            let hopper_recording = hopper_recording_arc.lock ().unwrap ();
            let record = hopper_recording.get_record::<IncipientCoresPackage> (0);
            let response = serde_cbor::de::from_slice::<ClientResponsePayload> (&record.payload.data[..]).unwrap ();
            response_tx.send(response).unwrap();
            return Ok(())
        });

        thread::spawn(move || {
            tokio::run(test_future);
        });

        let response = response_rx.recv().unwrap();

        assert_eq! (response.last_response, false);
        assert_eq! (response.data.data, b"HTTP/1.1 200 OK\r\n\r\n".to_vec ());
    }

    #[test]
    fn spawn_stream_reader_handles_tls () {
        let (hopper, awaiter, hopper_recording_arc) = make_recorder();
        let (hopper_tx, hopper_rx) = mpsc::channel();
        thread::spawn(move || {
            let system = System::new ("test");
            let hopper_sub = make_peer_actors_from (None, None, Some (hopper), None, None).hopper.from_hopper_client;
            hopper_tx.send (hopper_sub).is_ok ();
            system.run ();
        });

        let (response_tx, response_rx) = mpsc::channel();
        let test_future = lazy(move || {
            let hopper_sub = hopper_rx.recv().unwrap();
            let mut read_stream = Box::new (ReadHalfWrapperMock::new ());
            read_stream.poll_read_results = vec!(
                (b"HTTP/1.1 200 OK\r\n\r\n".to_vec (),Ok (Async::Ready(19))),
                (vec! (0x16, 0x03, 0x03, 0x00, 0x00),Ok (Async::Ready(5))),
                (vec!(), Err (Error::from (ErrorKind::BrokenPipe)))
            );
            let (stream_adder_tx, _stream_adder_rx) = mpsc::channel();
            let (stream_killer_tx, _) = mpsc::channel();

            let subject = StreamHandlerEstablisher {
                stream_adder_tx,
                stream_killer_tx,
                stream_connector: Box::new(StreamConnectorMock { connect_params: Arc::new(Mutex::new(vec!())) }), // only used in "after_resolution"
                stream_splitter: Box::new(StreamSplitterMock { split_stream_results: RefCell::new(vec!()) }), // only used in "after_resolution"
                hopper_sub,
                logger: Logger::new("Proxy Client"),
                channel_factory: Box::new(FuturesChannelFactoryReal {})
            };

            subject.spawn_stream_reader(
                &ExpiredCoresPackage::new(test_utils::make_meaningless_route(), PlainData::new(&[])),
                &ClientRequestPayload {
                    stream_key: SocketAddr::from_str("255.255.255.255:65535").unwrap(),
                    last_data: false,
                    sequence_number: 0,
                    data: PlainData::new(&[]),
                    target_hostname: None,
                    target_port: 0,
                    protocol: ProxyProtocol::TLS,
                    originator_public_key: Key::new(&[]),
                },
                read_stream,
                String::from_str ("1.2.3.4:5678").unwrap(),
            ).expect ("spawn_stream_reader () failed");
            awaiter.await_message_count (1);
            let hopper_recording = hopper_recording_arc.lock ().unwrap ();
            let record = hopper_recording.get_record::<IncipientCoresPackage> (0);
            let response = serde_cbor::de::from_slice::<ClientResponsePayload> (&record.payload.data[..]).unwrap ();

            response_tx.send(response).unwrap();
            return Ok(())
        });

        thread::spawn(move || {
            tokio::run(test_future);
        });

        let response = response_rx.recv().unwrap();

        assert_eq! (response.last_response, false);
        assert_eq! (response.data.data, vec! (0x16, 0x03, 0x03, 0x00, 0x00));
    }
}