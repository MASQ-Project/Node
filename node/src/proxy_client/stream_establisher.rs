// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

use crate::proxy_client::stream_reader::StreamReader;
use crate::proxy_client::stream_writer::StreamWriter;
use crate::sub_lib::channel_wrappers::FuturesChannelFactory;
use crate::sub_lib::channel_wrappers::FuturesChannelFactoryReal;
use crate::sub_lib::channel_wrappers::SenderWrapper;
use crate::sub_lib::cryptde::CryptDE;
use crate::sub_lib::framer::Framer;
use crate::sub_lib::http_packet_framer::HttpPacketFramer;
use crate::sub_lib::http_response_start_finder::HttpResponseStartFinder;
use crate::sub_lib::logger::Logger;
use crate::sub_lib::proxy_client::{InboundServerData, ProxyClientSubs};
use crate::sub_lib::proxy_server::ClientRequestPayload;
use crate::sub_lib::proxy_server::ProxyProtocol;
use crate::sub_lib::sequence_buffer::SequencedPacket;
use crate::sub_lib::stream_connector::StreamConnector;
use crate::sub_lib::stream_connector::StreamConnectorReal;
use crate::sub_lib::stream_key::StreamKey;
use crate::sub_lib::tls_framer::TlsFramer;
use crate::sub_lib::tokio_wrappers::ReadHalfWrapper;
use actix::Recipient;
use std::io;
use std::io::Error;
use std::io::ErrorKind;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::sync::mpsc::Sender;
use tokio;
use trust_dns_resolver::error::ResolveError;
use trust_dns_resolver::lookup_ip::LookupIp;

pub struct StreamEstablisher {
    pub cryptde: &'static dyn CryptDE,
    pub stream_adder_tx: Sender<(StreamKey, Box<dyn SenderWrapper<SequencedPacket>>)>,
    pub stream_killer_tx: Sender<StreamKey>,
    pub stream_connector: Box<dyn StreamConnector>,
    pub proxy_client_sub: Recipient<InboundServerData>,
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
            proxy_client_sub: self.proxy_client_sub.clone(),
            logger: self.logger.clone(),
            channel_factory: Box::new(FuturesChannelFactoryReal {}),
        }
    }
}

impl StreamEstablisher {
    pub fn establish_stream(
        &mut self,
        payload: &ClientRequestPayload,
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
        payload: &ClientRequestPayload,
        read_stream: Box<dyn ReadHalfWrapper>,
        peer_addr: SocketAddr,
    ) -> io::Result<()> {
        let framer = Self::framer_from_protocol(payload.protocol);

        let stream_reader = StreamReader::new(
            payload.stream_key,
            self.proxy_client_sub.clone(),
            read_stream,
            self.stream_killer_tx.clone(),
            peer_addr,
            framer,
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
    pub proxy_client_subs: ProxyClientSubs,
    pub logger: Logger,
}

impl StreamEstablisherFactory for StreamEstablisherFactoryReal {
    fn make(&self) -> StreamEstablisher {
        StreamEstablisher {
            cryptde: self.cryptde.clone(),
            stream_adder_tx: self.stream_adder_tx.clone(),
            stream_killer_tx: self.stream_killer_tx.clone(),
            stream_connector: Box::new(StreamConnectorReal {}),
            proxy_client_sub: self.proxy_client_subs.inbound_server_data.clone(),
            logger: self.logger.clone(),
            channel_factory: Box::new(FuturesChannelFactoryReal {}),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sub_lib::proxy_server::ProxyProtocol;
    use crate::test_utils::recorder::make_recorder;
    use crate::test_utils::recorder::peer_actors_builder;
    use crate::test_utils::stream_connector_mock::StreamConnectorMock;
    use crate::test_utils::test_utils::cryptde;
    use crate::test_utils::test_utils::make_meaningless_stream_key;
    use crate::test_utils::tokio_wrapper_mocks::ReadHalfWrapperMock;
    use actix::System;
    use futures::future::lazy;
    use std::io::ErrorKind;
    use std::net::SocketAddr;
    use std::str::FromStr;
    use std::sync::mpsc;
    use std::thread;
    use tokio::prelude::Async;

    #[test]
    fn spawn_stream_reader_handles_http() {
        let (proxy_client, proxy_client_awaiter, proxy_client_recording_arc) = make_recorder();
        let (sub_tx, sub_rx) = mpsc::channel();
        thread::spawn(move || {
            let system = System::new("test");
            let peer_actors = peer_actors_builder().proxy_client(proxy_client).build();
            sub_tx
                .send(peer_actors.proxy_client.inbound_server_data)
                .expect("Unable to send inbound_server_data sub from proxy_client to test");
            system.run();
        });

        let (ibsd_tx, ibsd_rx) = mpsc::channel();
        let test_future = lazy(move || {
            let proxy_client_sub = sub_rx.recv().unwrap();

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
                proxy_client_sub,
                logger: Logger::new("Proxy Client"),
                channel_factory: Box::new(FuturesChannelFactoryReal {}),
            };
            subject
                .spawn_stream_reader(
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
                        originator_public_key: subject.cryptde.public_key().clone(),
                    },
                    read_stream,
                    SocketAddr::from_str("1.2.3.4:5678").unwrap(),
                )
                .expect("spawn_stream_reader () failed");

            proxy_client_awaiter.await_message_count(1);
            let proxy_client_recording = proxy_client_recording_arc.lock().unwrap();
            let record = proxy_client_recording
                .get_record::<InboundServerData>(0)
                .clone();
            ibsd_tx.send(record).unwrap();
            return Ok(());
        });

        thread::spawn(move || {
            tokio::run(test_future);
        });

        let ibsd = ibsd_rx.recv().unwrap();

        assert_eq!(
            ibsd,
            InboundServerData {
                stream_key: make_meaningless_stream_key(),
                last_data: false,
                sequence_number: 0,
                source: SocketAddr::from_str("1.2.3.4:5678").unwrap(),
                data: b"HTTP/1.1 200 OK\r\n\r\n".to_vec()
            }
        );
    }

    #[test]
    fn spawn_stream_reader_handles_tls() {
        let (proxy_client, proxy_client_awaiter, proxy_client_recording_arc) = make_recorder();
        let (sub_tx, sub_rx) = mpsc::channel();
        thread::spawn(move || {
            let system = System::new("test");
            let peer_actors = peer_actors_builder().proxy_client(proxy_client).build();
            sub_tx
                .send(peer_actors.proxy_client.inbound_server_data)
                .expect("Internal Error");
            system.run();
        });

        let (ibsd_tx, ibsd_rx) = mpsc::channel();
        let test_future = lazy(move || {
            let proxy_client_sub = sub_rx.recv().unwrap();
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
                proxy_client_sub,
                logger: Logger::new("Proxy Client"),
                channel_factory: Box::new(FuturesChannelFactoryReal {}),
            };

            subject
                .spawn_stream_reader(
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
                        originator_public_key: subject.cryptde.public_key().clone(),
                    },
                    read_stream,
                    SocketAddr::from_str("1.2.3.4:5678").unwrap(),
                )
                .expect("spawn_stream_reader () failed");
            proxy_client_awaiter.await_message_count(1);
            let proxy_client_recording = proxy_client_recording_arc.lock().unwrap();
            let record = proxy_client_recording
                .get_record::<InboundServerData>(0)
                .clone();
            ibsd_tx.send(record).unwrap();
            return Ok(());
        });

        thread::spawn(move || {
            tokio::run(test_future);
        });

        let ibsd = ibsd_rx.recv().unwrap();

        assert_eq!(
            ibsd,
            InboundServerData {
                stream_key: make_meaningless_stream_key(),
                last_data: false,
                sequence_number: 0,
                source: SocketAddr::from_str("1.2.3.4:5678").unwrap(),
                data: vec!(0x16, 0x03, 0x03, 0x00, 0x00)
            }
        );
    }
}
