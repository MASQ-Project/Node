// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

use actix::Recipient;
use actix::Syn;
use std::io;
use std::io::Error;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::sync::mpsc::Sender;
use stream_handler_pool::StreamHandlerPoolReal;
use stream_reader::StreamReader;
use stream_writer::StreamWriter;
use sub_lib::channel_wrappers::FuturesChannelFactory;
use sub_lib::channel_wrappers::FuturesChannelFactoryReal;
use sub_lib::channel_wrappers::SenderWrapper;
use sub_lib::hopper::IncipientCoresPackage;
use sub_lib::logger::Logger;
use sub_lib::proxy_server::ClientRequestPayload;
use sub_lib::route::Route;
use sub_lib::sequence_buffer::SequencedPacket;
use sub_lib::stream_connector::StreamConnector;
use sub_lib::stream_connector::StreamConnectorReal;
use sub_lib::stream_key::StreamKey;
use sub_lib::tokio_wrappers::ReadHalfWrapper;
use tokio;
use trust_dns_resolver::error::ResolveError;
use trust_dns_resolver::lookup_ip::LookupIp;

pub struct StreamEstablisher {
    pub stream_adder_tx: Sender<(StreamKey, Box<SenderWrapper<SequencedPacket>>)>,
    pub stream_killer_tx: Sender<StreamKey>,
    pub stream_connector: Box<StreamConnector>,
    pub hopper_sub: Recipient<Syn, IncipientCoresPackage>,
    pub logger: Logger,
    pub channel_factory: Box<FuturesChannelFactory<SequencedPacket>>,
}

impl StreamEstablisher {
    pub fn establish_stream(
        &mut self,
        payload: &ClientRequestPayload,
        return_route: &Route,
        lookup_result: Result<LookupIp, ResolveError>,
    ) -> io::Result<Box<SenderWrapper<SequencedPacket>>> {
        let target_hostname = payload
            .target_hostname
            .clone()
            .expect("Internal error: DNS resolution succeeded on missing hostname");
        let ip_addrs: Vec<IpAddr> = match lookup_result {
            Err(e) => {
                self.logger.error(format!(
                    "Could not find IP address for host {}: {}",
                    target_hostname, e
                ));
                return Err(Error::from(e));
            }
            Ok(lookup_ip) => lookup_ip.iter().map(|x| x).collect(),
        };
        self.logger.debug(format!(
            "Found IP addresses for {}: {:?}",
            target_hostname, &ip_addrs
        ));

        let connection_info = self.stream_connector.connect_one(
            ip_addrs,
            &target_hostname,
            payload.target_port,
            &self.logger,
        )?;

        self.spawn_stream_reader(
            return_route,
            &payload.clone(),
            connection_info.reader,
            connection_info.peer_addr,
        )?;

        let (tx_to_write, rx_to_write) = self.channel_factory.make(connection_info.peer_addr);
        let stream_writer = StreamWriter::new(
            connection_info.writer,
            connection_info.peer_addr,
            rx_to_write,
            payload.stream_key,
        );
        tokio::spawn(stream_writer);

        self.stream_adder_tx
            .send((payload.stream_key, tx_to_write.clone()))
            .expect("StreamHandlerPool died");
        Ok(tx_to_write)
    }

    fn spawn_stream_reader(
        &self,
        return_route: &Route,
        payload: &ClientRequestPayload,
        read_stream: Box<ReadHalfWrapper>,
        peer_addr: SocketAddr,
    ) -> io::Result<()> {
        let framer = StreamHandlerPoolReal::framer_from_protocol(payload.protocol);

        let stream_reader = StreamReader::new(
            payload.stream_key,
            self.hopper_sub.clone(),
            read_stream,
            self.stream_killer_tx.clone(),
            peer_addr,
            return_route.clone(),
            framer,
            payload.originator_public_key.clone(),
        );
        self.logger
            .debug(format!("Spawning StreamReader for {}", peer_addr));
        tokio::spawn(stream_reader);
        Ok(())
    }
}

pub trait StreamEstablisherFactory {
    fn make(&self) -> StreamEstablisher;
}

pub struct StreamEstablisherFactoryReal {
    pub stream_adder_tx: Sender<(StreamKey, Box<SenderWrapper<SequencedPacket>>)>,
    pub stream_killer_tx: Sender<StreamKey>,
    pub hopper_sub: Recipient<Syn, IncipientCoresPackage>,
    pub logger: Logger,
}

impl StreamEstablisherFactory for StreamEstablisherFactoryReal {
    fn make(&self) -> StreamEstablisher {
        StreamEstablisher {
            stream_adder_tx: self.stream_adder_tx.clone(),
            stream_killer_tx: self.stream_killer_tx.clone(),
            stream_connector: Box::new(StreamConnectorReal {}),
            hopper_sub: self.hopper_sub.clone(),
            logger: self.logger.clone(),
            channel_factory: Box::new(FuturesChannelFactoryReal {}),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix::System;
    use futures::future::lazy;
    use serde_cbor;
    use std::io::ErrorKind;
    use std::net::SocketAddr;
    use std::str::FromStr;
    use std::sync::mpsc;
    use std::thread;
    use sub_lib::cryptde::Key;
    use sub_lib::proxy_client::ClientResponsePayload;
    use sub_lib::proxy_server::ProxyProtocol;
    use test_utils::recorder::make_peer_actors_from;
    use test_utils::recorder::make_recorder;
    use test_utils::stream_connector_mock::StreamConnectorMock;
    use test_utils::test_utils;
    use test_utils::test_utils::make_meaningless_stream_key;
    use test_utils::tokio_wrapper_mocks::ReadHalfWrapperMock;
    use tokio::prelude::Async;

    #[test]
    fn spawn_stream_reader_handles_http() {
        let (hopper, awaiter, hopper_recording_arc) = make_recorder();
        let (hopper_tx, hopper_rx) = mpsc::channel();
        thread::spawn(move || {
            let system = System::new("test");
            let hopper_sub = make_peer_actors_from(None, None, Some(hopper), None, None)
                .hopper
                .from_hopper_client;
            hopper_tx.send(hopper_sub).is_ok();
            system.run();
        });

        let (response_tx, response_rx) = mpsc::channel();
        let test_future = lazy(move || {
            let hopper_sub = hopper_rx.recv().unwrap();

            let (stream_adder_tx, _stream_adder_rx) = mpsc::channel();
            let (stream_killer_tx, _) = mpsc::channel();
            let mut read_stream = Box::new(ReadHalfWrapperMock::new());
            read_stream.poll_read_results = vec![
                (vec![0x16, 0x03, 0x03, 0x00, 0x00], Ok(Async::Ready(5))),
                (b"HTTP/1.1 200 OK\r\n\r\n".to_vec(), Ok(Async::Ready(19))),
                (vec![], Err(Error::from(ErrorKind::BrokenPipe))),
            ];

            let subject = StreamEstablisher {
                stream_adder_tx,
                stream_killer_tx,
                stream_connector: Box::new(StreamConnectorMock::new()), // only used in "establish_stream"
                hopper_sub,
                logger: Logger::new("Proxy Client"),
                channel_factory: Box::new(FuturesChannelFactoryReal {}),
            };
            subject
                .spawn_stream_reader(
                    &test_utils::make_meaningless_route(),
                    &ClientRequestPayload {
                        stream_key: make_meaningless_stream_key(),
                        sequenced_packet: SequencedPacket {
                            data: vec![],
                            sequence_number: 0,
                            last_data: false,
                        },
                        target_hostname: Some("blah".to_string()),
                        target_port: 0,
                        protocol: ProxyProtocol::HTTP,
                        originator_public_key: Key::new(&[]),
                    },
                    read_stream,
                    SocketAddr::from_str("1.2.3.4:5678").unwrap(),
                )
                .expect("spawn_stream_reader () failed");

            awaiter.await_message_count(1);
            let hopper_recording = hopper_recording_arc.lock().unwrap();
            let record = hopper_recording.get_record::<IncipientCoresPackage>(0);
            let response =
                serde_cbor::de::from_slice::<ClientResponsePayload>(&record.payload.data[..])
                    .unwrap();
            response_tx.send(response).unwrap();
            return Ok(());
        });

        thread::spawn(move || {
            tokio::run(test_future);
        });

        let response = response_rx.recv().unwrap();

        assert_eq!(response.sequenced_packet.last_data, false);
        assert_eq!(
            response.sequenced_packet.data,
            b"HTTP/1.1 200 OK\r\n\r\n".to_vec()
        );
    }

    #[test]
    fn spawn_stream_reader_handles_tls() {
        let (hopper, awaiter, hopper_recording_arc) = make_recorder();
        let (hopper_tx, hopper_rx) = mpsc::channel();
        thread::spawn(move || {
            let system = System::new("test");
            let hopper_sub = make_peer_actors_from(None, None, Some(hopper), None, None)
                .hopper
                .from_hopper_client;
            hopper_tx.send(hopper_sub).is_ok();
            system.run();
        });

        let (response_tx, response_rx) = mpsc::channel();
        let test_future = lazy(move || {
            let hopper_sub = hopper_rx.recv().unwrap();
            let mut read_stream = Box::new(ReadHalfWrapperMock::new());
            read_stream.poll_read_results = vec![
                (b"HTTP/1.1 200 OK\r\n\r\n".to_vec(), Ok(Async::Ready(19))),
                (vec![0x16, 0x03, 0x03, 0x00, 0x00], Ok(Async::Ready(5))),
                (vec![], Err(Error::from(ErrorKind::BrokenPipe))),
            ];
            let (stream_adder_tx, _stream_adder_rx) = mpsc::channel();
            let (stream_killer_tx, _) = mpsc::channel();

            let subject = StreamEstablisher {
                stream_adder_tx,
                stream_killer_tx,
                stream_connector: Box::new(StreamConnectorMock::new()), // only used in "establish_stream"
                hopper_sub,
                logger: Logger::new("Proxy Client"),
                channel_factory: Box::new(FuturesChannelFactoryReal {}),
            };

            subject
                .spawn_stream_reader(
                    &test_utils::make_meaningless_route(),
                    &ClientRequestPayload {
                        stream_key: make_meaningless_stream_key(),
                        sequenced_packet: SequencedPacket {
                            data: vec![],
                            sequence_number: 0,
                            last_data: false,
                        },
                        target_hostname: None,
                        target_port: 0,
                        protocol: ProxyProtocol::TLS,
                        originator_public_key: Key::new(&[]),
                    },
                    read_stream,
                    SocketAddr::from_str("1.2.3.4:5678").unwrap(),
                )
                .expect("spawn_stream_reader () failed");
            awaiter.await_message_count(1);
            let hopper_recording = hopper_recording_arc.lock().unwrap();
            let record = hopper_recording.get_record::<IncipientCoresPackage>(0);
            let response =
                serde_cbor::de::from_slice::<ClientResponsePayload>(&record.payload.data[..])
                    .unwrap();

            response_tx.send(response).unwrap();
            return Ok(());
        });

        thread::spawn(move || {
            tokio::run(test_future);
        });

        let response = response_rx.recv().unwrap();

        assert_eq!(response.sequenced_packet.last_data, false);
        assert_eq!(
            response.sequenced_packet.data,
            vec!(0x16, 0x03, 0x03, 0x00, 0x00)
        );
    }
}
