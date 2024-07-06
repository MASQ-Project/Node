// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::proxy_client::stream_handler_pool::StreamSenders;
use crate::proxy_client::stream_reader::StreamReader;
use crate::proxy_client::stream_writer::StreamWriter;
use crate::sub_lib::channel_wrappers::FuturesChannelFactoryReal;
use crate::sub_lib::channel_wrappers::SenderWrapper;
use crate::sub_lib::channel_wrappers::{FuturesChannelFactory, SenderWrapperReal};
use crate::sub_lib::cryptde::CryptDE;
use crate::sub_lib::proxy_client::{InboundServerData, ProxyClientSubs};
use crate::sub_lib::proxy_server::ClientRequestPayload_0v1;
use crate::sub_lib::sequence_buffer::SequencedPacket;
use crate::sub_lib::stream_connector::StreamConnector;
use crate::sub_lib::stream_connector::StreamConnectorReal;
use crate::sub_lib::stream_key::StreamKey;
use crate::sub_lib::tokio_wrappers::ReadHalfWrapper;
use actix::Recipient;
use crossbeam_channel::{unbounded, Receiver, Sender};
use masq_lib::logger::Logger;
use std::io;
use std::net::IpAddr;
use std::net::SocketAddr;

pub struct StreamEstablisher {
    pub cryptde: &'static dyn CryptDE,
    pub stream_adder_tx: Sender<(StreamKey, StreamSenders)>,
    pub stream_killer_tx: Sender<(StreamKey, u64)>,
    pub shutdown_signal_rx: Receiver<()>,
    pub stream_connector: Box<dyn StreamConnector>,
    pub proxy_client_sub: Recipient<InboundServerData>,
    pub logger: Logger,
    pub channel_factory: Box<dyn FuturesChannelFactory<SequencedPacket>>,
}

impl Clone for StreamEstablisher {
    fn clone(&self) -> Self {
        StreamEstablisher {
            cryptde: self.cryptde,
            stream_adder_tx: self.stream_adder_tx.clone(),
            stream_killer_tx: self.stream_killer_tx.clone(),
            shutdown_signal_rx: unbounded().1,
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
        payload: &ClientRequestPayload_0v1,
        ip_addrs: Vec<IpAddr>,
        target_hostname: String,
    ) -> io::Result<Box<dyn SenderWrapper<SequencedPacket>>> {
        let connection_info = self.stream_connector.connect_one(
            ip_addrs,
            &target_hostname,
            payload.target_port,
            &self.logger,
        )?;

        // TODO: GH-800: Test Drive Me
        // let (shutdown_signal_tx, shutdown_signal_rx) = unbounded();

        let shutdown_signal_tx = unbounded().0;
        let shutdown_signal_rx = unbounded().1;

        self.spawn_stream_reader(
            &payload.clone(),
            connection_info.reader,
            connection_info.peer_addr,
            shutdown_signal_rx,
        );

        let (tx_to_write, rx_to_write) = self.channel_factory.make(connection_info.peer_addr);
        let stream_writer = StreamWriter::new(
            connection_info.writer,
            connection_info.peer_addr,
            rx_to_write,
            payload.stream_key,
        );
        tokio::spawn(stream_writer);

        let stream_senders = StreamSenders {
            writer_data: tx_to_write.clone(),
            reader_shutdown: shutdown_signal_tx,
        };

        self.stream_adder_tx
            .send((payload.stream_key, stream_senders))
            .expect("StreamHandlerPool died");
        Ok(tx_to_write)
    }

    fn spawn_stream_reader(
        &self,
        payload: &ClientRequestPayload_0v1,
        read_stream: Box<dyn ReadHalfWrapper>,
        peer_addr: SocketAddr,
        shutdown_signal: Receiver<()>,
    ) {
        let stream_reader = StreamReader::new(
            payload.stream_key,
            self.proxy_client_sub.clone(),
            read_stream,
            self.stream_killer_tx.clone(),
            shutdown_signal,
            peer_addr,
        );
        debug!(self.logger, "Spawning StreamReader for {}", peer_addr);
        tokio::spawn(stream_reader);
    }
}

pub trait StreamEstablisherFactory: Send {
    fn make(&self) -> StreamEstablisher;
}

pub struct StreamEstablisherFactoryReal {
    pub cryptde: &'static dyn CryptDE,
    pub stream_adder_tx: Sender<(StreamKey, StreamSenders)>,
    pub stream_killer_tx: Sender<(StreamKey, u64)>,
    pub proxy_client_subs: ProxyClientSubs,
    pub logger: Logger,
}

impl StreamEstablisherFactory for StreamEstablisherFactoryReal {
    fn make(&self) -> StreamEstablisher {
        StreamEstablisher {
            cryptde: self.cryptde,
            stream_adder_tx: self.stream_adder_tx.clone(),
            stream_killer_tx: self.stream_killer_tx.clone(),
            shutdown_signal_rx: unbounded().1,
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
    use crate::test_utils::main_cryptde;
    use crate::test_utils::recorder::make_recorder;
    use crate::test_utils::recorder::peer_actors_builder;
    use crate::test_utils::stream_connector_mock::StreamConnectorMock;
    use crate::test_utils::tokio_wrapper_mocks::ReadHalfWrapperMock;
    use actix::System;
    use crossbeam_channel::unbounded;
    use futures::future::lazy;
    use std::io::ErrorKind;
    use std::net::SocketAddr;
    use std::str::FromStr;
    use std::thread;
    use tokio::prelude::Async;

    #[test]
    fn spawn_stream_reader_handles_data() {
        let (proxy_client, proxy_client_awaiter, proxy_client_recording_arc) = make_recorder();
        let (sub_tx, sub_rx) = unbounded();
        thread::spawn(move || {
            let system = System::new("spawn_stream_reader_handles_data");
            let peer_actors = peer_actors_builder().proxy_client(proxy_client).build();
            sub_tx
                .send(peer_actors.proxy_client_opt.unwrap().inbound_server_data)
                .expect("Unable to send inbound_server_data sub from proxy_client to test");
            system.run();
        });

        let (ibsd_tx, ibsd_rx) = unbounded();
        let test_future = lazy(move || {
            let proxy_client_sub = sub_rx.recv().unwrap();

            let (stream_adder_tx, _stream_adder_rx) = unbounded();
            let (stream_killer_tx, _) = unbounded();
            let mut read_stream = Box::new(ReadHalfWrapperMock::new());
            let bytes = b"I'm a stream establisher test not a framer test";
            read_stream.poll_read_results = vec![
                (bytes.to_vec(), Ok(Async::Ready(bytes.len()))),
                (vec![], Err(io::Error::from(ErrorKind::BrokenPipe))),
            ];

            let subject = StreamEstablisher {
                cryptde: main_cryptde(),
                stream_adder_tx,
                stream_killer_tx,
                shutdown_signal_rx: unbounded().1,
                stream_connector: Box::new(StreamConnectorMock::new()), // only used in "establish_stream"
                proxy_client_sub,
                logger: Logger::new("ProxyClient"),
                channel_factory: Box::new(FuturesChannelFactoryReal {}),
            };
            subject.spawn_stream_reader(
                &ClientRequestPayload_0v1 {
                    stream_key: StreamKey::make_meaningless_stream_key(),
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
                unbounded().1,
            );

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
                stream_key: StreamKey::make_meaningless_stream_key(),
                last_data: false,
                sequence_number: 0,
                source: SocketAddr::from_str("1.2.3.4:5678").unwrap(),
                data: b"I'm a stream establisher test not a framer test".to_vec()
            }
        );
    }
}
