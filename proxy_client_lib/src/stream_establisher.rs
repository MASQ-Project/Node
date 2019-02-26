// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

use crate::stream_reader::StreamReader;
use crate::stream_writer::StreamWriter;
use actix::Recipient;
use actix::Syn;
use std::io;
use std::io::Error;
use std::io::ErrorKind;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::sync::mpsc::Sender;
use sub_lib::accountant::ReportExitServiceProvidedMessage;
use sub_lib::channel_wrappers::FuturesChannelFactory;
use sub_lib::channel_wrappers::FuturesChannelFactoryReal;
use sub_lib::channel_wrappers::SenderWrapper;
use sub_lib::cryptde::CryptDE;
use sub_lib::framer::Framer;
use sub_lib::hopper::IncipientCoresPackage;
use sub_lib::http_packet_framer::HttpPacketFramer;
use sub_lib::http_response_start_finder::HttpResponseStartFinder;
use sub_lib::logger::Logger;
use sub_lib::proxy_server::ClientRequestPayload;
use sub_lib::proxy_server::ProxyProtocol;
use sub_lib::route::Route;
use sub_lib::sequence_buffer::SequencedPacket;
use sub_lib::stream_connector::StreamConnector;
use sub_lib::stream_connector::StreamConnectorReal;
use sub_lib::stream_key::StreamKey;
use sub_lib::tls_framer::TlsFramer;
use sub_lib::tokio_wrappers::ReadHalfWrapper;
use sub_lib::wallet::Wallet;
use tokio;
use trust_dns_resolver::error::ResolveError;
use trust_dns_resolver::lookup_ip::LookupIp;

pub struct StreamEstablisher {
    pub cryptde: &'static dyn CryptDE,
    pub stream_adder_tx: Sender<(StreamKey, Box<dyn SenderWrapper<SequencedPacket>>)>,
    pub stream_killer_tx: Sender<StreamKey>,
    pub stream_connector: Box<dyn StreamConnector>,
    pub hopper_sub: Recipient<Syn, IncipientCoresPackage>,
    pub accountant_sub: Recipient<Syn, ReportExitServiceProvidedMessage>,
    pub logger: Logger,
    pub channel_factory: Box<dyn FuturesChannelFactory<SequencedPacket>>,
}

impl Clone for StreamEstablisher {
    fn clone(&self) -> Self {
        StreamEstablisher {
            cryptde: self.cryptde.clone(),
            stream_adder_tx: self.stream_adder_tx.clone(),
            stream_killer_tx: self.stream_killer_tx.clone(),
            stream_connector: Box::new(StreamConnectorReal {}),
            hopper_sub: self.hopper_sub.clone(),
            accountant_sub: self.accountant_sub.clone(),
            logger: self.logger.clone(),
            channel_factory: Box::new(FuturesChannelFactoryReal {}),
        }
    }
}

impl StreamEstablisher {
    pub fn establish_stream(
        &mut self,
        payload: &ClientRequestPayload,
        consuming_wallet: Option<Wallet>,
        return_route: &Route,
        lookup_result: Result<LookupIp, ResolveError>,
    ) -> io::Result<Box<dyn SenderWrapper<SequencedPacket>>> {
        let target_hostname = match &payload.target_hostname {
            Some(target_hostname) => target_hostname.clone(),
            None => {
                self.logger.error(format!(
                    "Cannot open new stream with key {:?}: no hostname supplied",
                    payload.stream_key
                ));
                return Err(Error::from(ErrorKind::Other));
            }
        };
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
            self.cryptde,
            return_route,
            &payload.clone(),
            consuming_wallet,
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
        cryptde: &'static dyn CryptDE,
        return_route: &Route,
        payload: &ClientRequestPayload,
        consuming_wallet: Option<Wallet>,
        read_stream: Box<dyn ReadHalfWrapper>,
        peer_addr: SocketAddr,
    ) -> io::Result<()> {
        let framer = Self::framer_from_protocol(payload.protocol);

        let stream_reader = StreamReader::new(
            cryptde,
            payload.stream_key,
            consuming_wallet,
            self.hopper_sub.clone(),
            self.accountant_sub.clone(),
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

    pub fn framer_from_protocol(protocol: ProxyProtocol) -> Box<dyn Framer> {
        match protocol {
            ProxyProtocol::HTTP => {
                Box::new(HttpPacketFramer::new(Box::new(HttpResponseStartFinder {})))
            }
            ProxyProtocol::TLS => Box::new(TlsFramer::new()),
        }
    }
}

pub trait StreamEstablisherFactory: Send {
    fn make(&self) -> StreamEstablisher;
}

pub struct StreamEstablisherFactoryReal {
    pub cryptde: &'static dyn CryptDE,
    pub stream_adder_tx: Sender<(StreamKey, Box<dyn SenderWrapper<SequencedPacket>>)>,
    pub stream_killer_tx: Sender<StreamKey>,
    pub hopper_sub: Recipient<Syn, IncipientCoresPackage>,
    pub accountant_sub: Recipient<Syn, ReportExitServiceProvidedMessage>,
    pub logger: Logger,
}

impl StreamEstablisherFactory for StreamEstablisherFactoryReal {
    fn make(&self) -> StreamEstablisher {
        StreamEstablisher {
            cryptde: self.cryptde.clone(),
            stream_adder_tx: self.stream_adder_tx.clone(),
            stream_killer_tx: self.stream_killer_tx.clone(),
            stream_connector: Box::new(StreamConnectorReal {}),
            hopper_sub: self.hopper_sub.clone(),
            accountant_sub: self.accountant_sub.clone(),
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
    use sub_lib::proxy_client::ClientResponsePayload;
    use sub_lib::proxy_server::ProxyProtocol;
    use test_utils::recorder::make_recorder;
    use test_utils::stream_connector_mock::StreamConnectorMock;
    use test_utils::test_utils::cryptde;
    use test_utils::test_utils::make_meaningless_route;
    use test_utils::test_utils::make_meaningless_stream_key;
    use test_utils::tokio_wrapper_mocks::ReadHalfWrapperMock;
    use tokio::prelude::Async;
    use test_utils::recorder::peer_actors_builder;

    #[test]
    fn spawn_stream_reader_handles_http() {
        let (hopper, hopper_awaiter, hopper_recording_arc) = make_recorder();
        let (accountant, _, _) = make_recorder();
        let (sub_tx, sub_rx) = mpsc::channel();
        thread::spawn(move || {
            let system = System::new("test");
            let peer_actors = peer_actors_builder().hopper (hopper).accountant(accountant).build ();
            sub_tx
                .send((
                    peer_actors.hopper.from_hopper_client,
                    peer_actors.accountant.report_exit_service_provided,
                ))
                .is_ok();
            system.run();
        });

        let (response_tx, response_rx) = mpsc::channel();
        let test_future = lazy(move || {
            let (hopper_sub, accountant_sub) = sub_rx.recv().unwrap();

            let (stream_adder_tx, _stream_adder_rx) = mpsc::channel();
            let (stream_killer_tx, _) = mpsc::channel();
            let mut read_stream = Box::new(ReadHalfWrapperMock::new());
            read_stream.poll_read_results = vec![
                (vec![0x16, 0x03, 0x03, 0x00, 0x00], Ok(Async::Ready(5))),
                (b"HTTP/1.1 200 OK\r\n\r\n".to_vec(), Ok(Async::Ready(19))),
                (vec![], Err(Error::from(ErrorKind::BrokenPipe))),
            ];

            let subject = StreamEstablisher {
                cryptde: cryptde(),
                stream_adder_tx,
                stream_killer_tx,
                stream_connector: Box::new(StreamConnectorMock::new()), // only used in "establish_stream"
                hopper_sub,
                accountant_sub,
                logger: Logger::new("Proxy Client"),
                channel_factory: Box::new(FuturesChannelFactoryReal {}),
            };
            subject
                .spawn_stream_reader(
                    cryptde(),
                    &make_meaningless_route(),
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
                        originator_public_key: subject.cryptde.public_key(),
                    },
                    Some(Wallet::new("consuming")),
                    read_stream,
                    SocketAddr::from_str("1.2.3.4:5678").unwrap(),
                )
                .expect("spawn_stream_reader () failed");

            hopper_awaiter.await_message_count(1);
            let hopper_recording = hopper_recording_arc.lock().unwrap();
            let record = hopper_recording.get_record::<IncipientCoresPackage>(0);
            let decrypted_payload = subject.cryptde.decode(&record.payload).unwrap();
            let response =
                serde_cbor::de::from_slice::<ClientResponsePayload>(decrypted_payload.as_slice())
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
        let (hopper, hopper_awaiter, hopper_recording_arc) = make_recorder();
        let (accountant, _, _) = make_recorder();
        let (sub_tx, sub_rx) = mpsc::channel();
        thread::spawn(move || {
            let system = System::new("test");
            let peer_actors = peer_actors_builder().hopper (hopper).accountant(accountant).build ();
            sub_tx
                .send((
                    peer_actors.hopper.from_hopper_client.clone(),
                    peer_actors.accountant.report_exit_service_provided.clone(),
                ))
                .is_ok();
            system.run();
        });

        let (response_tx, response_rx) = mpsc::channel();
        let test_future = lazy(move || {
            let (hopper_sub, accountant_sub) = sub_rx.recv().unwrap();
            let mut read_stream = Box::new(ReadHalfWrapperMock::new());
            read_stream.poll_read_results = vec![
                (b"HTTP/1.1 200 OK\r\n\r\n".to_vec(), Ok(Async::Ready(19))),
                (vec![0x16, 0x03, 0x03, 0x00, 0x00], Ok(Async::Ready(5))),
                (vec![], Err(Error::from(ErrorKind::BrokenPipe))),
            ];
            let (stream_adder_tx, _stream_adder_rx) = mpsc::channel();
            let (stream_killer_tx, _) = mpsc::channel();

            let subject = StreamEstablisher {
                cryptde: cryptde(),
                stream_adder_tx,
                stream_killer_tx,
                stream_connector: Box::new(StreamConnectorMock::new()), // only used in "establish_stream"
                hopper_sub,
                accountant_sub,
                logger: Logger::new("Proxy Client"),
                channel_factory: Box::new(FuturesChannelFactoryReal {}),
            };

            subject
                .spawn_stream_reader(
                    cryptde(),
                    &make_meaningless_route(),
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
                        originator_public_key: subject.cryptde.public_key(),
                    },
                    Some(Wallet::new("consuming")),
                    read_stream,
                    SocketAddr::from_str("1.2.3.4:5678").unwrap(),
                )
                .expect("spawn_stream_reader () failed");
            hopper_awaiter.await_message_count(1);
            let hopper_recording = hopper_recording_arc.lock().unwrap();
            let record = hopper_recording.get_record::<IncipientCoresPackage>(0);
            let decrypted_payload = subject.cryptde.decode(&record.payload).unwrap();
            let response =
                serde_cbor::de::from_slice::<ClientResponsePayload>(decrypted_payload.as_slice())
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
