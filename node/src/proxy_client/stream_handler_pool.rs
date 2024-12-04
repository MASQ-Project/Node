// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
#![allow(proc_macro_derive_resolution_fallback)]

use crate::proxy_client::resolver_wrapper::ResolverWrapper;
use crate::proxy_client::stream_establisher::StreamEstablisherFactoryReal;
use crate::proxy_client::stream_establisher::{StreamEstablisher, StreamEstablisherFactory};
use crate::sub_lib::accountant::ReportExitServiceProvidedMessage;
use crate::sub_lib::cryptde::CryptDE;
use crate::sub_lib::proxy_client::{error_socket_addr, ProxyClientSubs};
use crate::sub_lib::proxy_client::{DnsResolveFailure_0v1, InboundServerData};
use crate::sub_lib::proxy_server::ClientRequestPayload_0v1;
use crate::sub_lib::sequence_buffer::SequencedPacket;
use crate::sub_lib::stream_key::StreamKey;
use crate::sub_lib::wallet::Wallet;
use actix::Recipient;
use crossbeam_channel::{unbounded, Receiver};
use hickory_resolver::error::ResolveError;
use hickory_resolver::lookup_ip::LookupIp;
use masq_lib::logger::Logger;
use std::collections::HashMap;
use std::future::{ready, Future};
use std::io;
use std::net::{AddrParseError, IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;
use tokio::task;
use crate::sub_lib::channel_wrappers::SenderWrapper;

pub trait StreamHandlerPool {
    fn process_package(&self, payload: ClientRequestPayload_0v1, paying_wallet_opt: Option<Wallet>);
}

pub struct StreamHandlerPoolReal {
    inner: Arc<Mutex<StreamHandlerPoolRealInner>>,
    stream_adder_rx: Receiver<(StreamKey, Box<dyn SenderWrapper<SequencedPacket>>)>,
    stream_killer_rx: Receiver<(StreamKey, u64)>,
}

struct StreamHandlerPoolRealInner {
    accountant_sub: Recipient<ReportExitServiceProvidedMessage>,
    proxy_client_subs: ProxyClientSubs,
    stream_writer_channels: HashMap<StreamKey, Box<dyn SenderWrapper<SequencedPacket>>>,
    resolver: Box<dyn ResolverWrapper>,
    logger: Logger,
    establisher_factory: Box<dyn StreamEstablisherFactory>,
    exit_service_rate: u64,
    exit_byte_rate: u64,
}

impl StreamHandlerPool for StreamHandlerPoolReal {
    fn process_package(
        &self,
        payload: ClientRequestPayload_0v1,
        paying_wallet_opt: Option<Wallet>,
    ) {
        self.do_housekeeping();
        Self::process_package(payload, paying_wallet_opt, self.inner.clone())
    }
}

type StreamEstablisherResultInner =
    Result<Box<dyn SenderWrapper<SequencedPacket> + 'static>, String>;
type StreamEstablisherResult = Box<dyn Future<Output = StreamEstablisherResultInner>>;

impl StreamHandlerPoolReal {
    pub fn new(
        resolver: Box<dyn ResolverWrapper>,
        cryptde: &'static dyn CryptDE,
        accountant_sub: Recipient<ReportExitServiceProvidedMessage>,
        proxy_client_subs: ProxyClientSubs,
        exit_service_rate: u64,
        exit_byte_rate: u64,
    ) -> StreamHandlerPoolReal {
        let (stream_killer_tx, stream_killer_rx) = unbounded();
        let (stream_adder_tx, stream_adder_rx) = unbounded();
        StreamHandlerPoolReal {
            inner: Arc::new(Mutex::new(StreamHandlerPoolRealInner {
                establisher_factory: Box::new(StreamEstablisherFactoryReal {
                    cryptde,
                    stream_adder_tx,
                    stream_killer_tx,
                    proxy_client_subs: proxy_client_subs.clone(),
                    logger: Logger::new("ProxyClient"),
                }),
                accountant_sub,
                proxy_client_subs,
                stream_writer_channels: HashMap::new(),
                resolver,
                logger: Logger::new("ProxyClient"),
                exit_service_rate,
                exit_byte_rate,
            })),
            stream_adder_rx,
            stream_killer_rx,
        }
    }

    fn process_package(
        payload: ClientRequestPayload_0v1,
        paying_wallet_opt: Option<Wallet>,
        inner_arc: Arc<Mutex<StreamHandlerPoolRealInner>>,
    ) {
        let stream_key = payload.stream_key;
        let inner_arc_1 = inner_arc.clone();
        match Self::find_stream_with_key(&stream_key, &inner_arc) {
            Some(sender_wrapper) => {
                let source = sender_wrapper.peer_addr();
                let future = async {
                    if let Err(msg) =
                        Self::write_and_tend(sender_wrapper, payload, paying_wallet_opt, inner_arc)
                            .await
                    {
                        Self::clean_up_bad_stream(inner_arc_1, &stream_key, source, msg)
                    }
                };
                task::spawn(future);
            }
            None => {
                if payload.sequenced_packet.data.is_empty() {
                    debug!(
                        Self::make_logger_copy(&inner_arc_1),
                        "Empty request payload received for nonexistent stream {:?} - ignoring",
                        payload.stream_key
                    )
                } else {
                    let future = async {
                        let sender_wrapper =
                            Self::make_stream_with_key(&payload, inner_arc_1.clone()).await?;
                        if let Err(msg) = Self::write_and_tend(
                            sender_wrapper,
                            payload,
                            paying_wallet_opt,
                            inner_arc,
                        )
                        .await
                        {
                            // TODO: This ends up sending an empty response back to the browser and terminating
                            // the stream. User deserves better than that. Send back a response from the
                            // proper ServerImpersonator describing the error.
                            Self::clean_up_bad_stream(
                                inner_arc_1,
                                &stream_key,
                                error_socket_addr(),
                                msg,
                            );
                        };
                        Ok(())
                    };
                    task::spawn(future);
                }
            }
        };
    }

    fn clean_up_bad_stream(
        inner_arc: Arc<Mutex<StreamHandlerPoolRealInner>>,
        stream_key: &StreamKey,
        source: SocketAddr,
        error: String,
    ) {
        let mut inner = inner_arc.lock().expect("Stream handler pool was poisoned");
        error!(
            inner.logger,
            "Couldn't process request from CORES package: {}", error
        );
        if let Some(sender_wrapper) = inner.stream_writer_channels.remove(stream_key) {
            debug!(
                inner.logger,
                "Removing stream writer for {}",
                sender_wrapper.peer_addr()
            );
        }
        Self::send_terminating_package(
            stream_key,
            source,
            &inner.proxy_client_subs.inbound_server_data,
        );
    }

    async fn write_and_tend(
        sender_wrapper: Box<dyn SenderWrapper<SequencedPacket>>,
        payload: ClientRequestPayload_0v1,
        paying_wallet_opt: Option<Wallet>,
        inner_arc: Arc<Mutex<StreamHandlerPoolRealInner>>,
    ) -> Result<(), String> {
        let stream_key = payload.stream_key;
        let last_data = payload.sequenced_packet.last_data;
        let payload_size = payload.sequenced_packet.data.len();

        Self::perform_write(payload.sequenced_packet, sender_wrapper.dup()).await?;
        let mut inner = inner_arc.lock().expect("Stream handler pool is poisoned");
        if last_data {
            match inner.stream_writer_channels.remove(&stream_key) {
                Some(channel) => debug!(
                    inner.logger,
                    "Removing StreamWriter {:?} to {}",
                    stream_key,
                    channel.peer_addr()
                ),
                None => debug!(
                    inner.logger,
                    "Trying to remove StreamWriter {:?}, but it's already gone", stream_key
                ),
            }
        }
        if payload_size > 0 {
            match paying_wallet_opt {
                Some(wallet) => inner
                    .accountant_sub
                    .try_send(ReportExitServiceProvidedMessage {
                        timestamp: SystemTime::now(),
                        paying_wallet: wallet,
                        payload_size,
                        service_rate: inner.exit_service_rate,
                        byte_rate: inner.exit_byte_rate,
                    })
                    .expect("Accountant is dead"),
                // This log is here mostly for testing, to prove that no Accountant message is sent in the no-wallet case
                None => debug!(
                    inner.logger,
                    "Sent {}-byte request without consuming wallet for free", payload_size
                ),
            }
        }
        Ok(())
    }

    fn make_stream_with_key(
        payload: &ClientRequestPayload_0v1,
        inner_arc: Arc<Mutex<StreamHandlerPoolRealInner>>,
    ) -> StreamEstablisherResult {
        // TODO: Figure out what to do if a flurry of requests for a particular stream key
        // come flooding in so densely that several of them arrive in the time it takes to
        // resolve the first one and add it to the stream_writers map.
        let logger = Self::make_logger_copy(&inner_arc);
        debug!(
            logger,
            "No stream to {:?} exists; resolving host", &payload.target_hostname
        );

        match payload.target_hostname {
            Some(ref target_hostname) => match Self::parse_ip(target_hostname) {
                Ok(socket_addr) => Self::handle_ip(
                    payload.clone(),
                    socket_addr,
                    inner_arc,
                    target_hostname.to_string(),
                ),
                Err(_) => Self::lookup_dns(inner_arc, target_hostname.to_string(), payload.clone()),
            },
            None => {
                error!(
                    logger,
                    "Cannot open new stream with key {:?}: no hostname supplied",
                    payload.stream_key
                );
                Box::new(ready(Err("No hostname provided".to_string())))
            }
        }
    }

    fn parse_ip(hostname: &str) -> Result<IpAddr, AddrParseError> {
        let socket_ip = SocketAddr::from_str(hostname).map(|sa| sa.ip());
        if socket_ip.is_ok() {
            socket_ip
        } else {
            IpAddr::from_str(hostname)
        }
    }

    fn make_establisher(inner_arc: Arc<Mutex<StreamHandlerPoolRealInner>>) -> StreamEstablisher {
        let inner = inner_arc
            .lock()
            .unwrap_or_else(|_| panic!("Stream handler pool is poisoned"));
        inner.establisher_factory.make()
    }

    async fn handle_ip(
        payload: ClientRequestPayload_0v1,
        ip_addr: IpAddr,
        inner_arc: Arc<Mutex<StreamHandlerPoolRealInner>>,
        target_hostname: String,
    ) -> StreamEstablisherResultInner {
        let mut stream_establisher = StreamHandlerPoolReal::make_establisher(inner_arc);
        match stream_establisher
            .establish_stream(&payload, vec![ip_addr], target_hostname)
            .await
        {
            Ok(sender_wrapper) => Ok(Box::new(sender_wrapper)),
            Err(io_error) => Err(format!("Could not establish stream: {:?}", io_error)),
        }
    }

    async fn lookup_dns(
        inner_arc: Arc<Mutex<StreamHandlerPoolRealInner>>,
        target_hostname: String,
        payload: ClientRequestPayload_0v1,
    ) -> StreamEstablisherResultInner {
        let fqdn = Self::make_fqdn(&target_hostname);
        let dns_resolve_failed_sub = inner_arc
            .lock()
            .expect("Stream handler pool is poisoned")
            .proxy_client_subs
            .dns_resolve_failed
            .clone();
        let mut establisher = StreamHandlerPoolReal::make_establisher(inner_arc.clone());
        let stream_key = payload.stream_key;
        let logger = StreamHandlerPoolReal::make_logger_copy(&inner_arc);
        match inner_arc
            .lock()
            .expect("Stream handler pool is poisoned")
            .resolver
            .lookup_ip(&fqdn)
            .await
        {
            Ok(lookup_result) => match Self::handle_lookup_ip(
                target_hostname.to_string(),
                &payload,
                lookup_result, // TODO  We should probably be taking care of the error side of this here, rather than in handle_lookup_ip().
                logger,
                &mut establisher,
            )
            .await
            {
                Ok(sender_wrapper) => Ok(sender_wrapper),
                Err(io_error) => Err(format!("Could not establish stream: {:?}", io_error)),
            },
            Err(err) => {
                error!(
                    logger,
                    "Could not find IP address for host {}: {}", target_hostname, err
                );
                dns_resolve_failed_sub
                    .try_send(DnsResolveFailure_0v1::new(stream_key))
                    .expect("ProxyClient is poisoned");

                // TODO SPIKE This code was returning a naked "err" before. How can that be right?
                Err(format!("DNS resolution failure: {:?}", err))
                // TODO SPIKE
            }
        }
    }

    fn handle_lookup_ip(
        target_hostname: String,
        payload: &ClientRequestPayload_0v1,
        lookup_ip: LookupIp,
        logger: Logger,
        establisher: &mut StreamEstablisher,
    ) -> io::Result<Box<dyn SenderWrapper<SequencedPacket>>> {
        let ip_addrs: Vec<IpAddr> = lookup_ip.iter().collect();
        debug!(
            logger,
            "Found IP addresses for {}: {:?}", target_hostname, &ip_addrs
        );
        establisher.establish_stream(payload, ip_addrs, target_hostname)
    }

    fn make_fqdn(target_hostname: &str) -> String {
        format!("{}.", target_hostname)
    }

    fn find_stream_with_key(
        stream_key: &StreamKey,
        inner_arc: &Arc<Mutex<StreamHandlerPoolRealInner>>,
    ) -> Option<Box<dyn SenderWrapper<SequencedPacket>>> {
        let inner = inner_arc.lock().expect("Stream handler pool is poisoned");
        let sender_wrapper_opt = inner.stream_writer_channels.get(stream_key);
        sender_wrapper_opt.map(|sender_wrapper_box_ref| Box::new(sender_wrapper_box_ref).clone())
    }

    fn make_logger_copy(inner_arc: &Arc<Mutex<StreamHandlerPoolRealInner>>) -> Logger {
        let inner = inner_arc.lock().expect("Stream handler pool is poisoned");
        inner.logger.clone()
    }

    async fn perform_write(
        sequenced_packet: SequencedPacket,
        sender_wrapper: Box<dyn SenderWrapper<SequencedPacket>>,
    ) -> Result<(), String> {
        match sender_wrapper.send(sequenced_packet).await {
            Ok(_) => Ok(()),
            Err(_) => Err("Could not queue write to stream; channel full".to_string()),
        }
    }

    fn send_terminating_package(
        stream_key: &StreamKey,
        source: SocketAddr,
        proxy_client_sub: &Recipient<InboundServerData>,
    ) {
        proxy_client_sub
            .try_send(InboundServerData {
                stream_key: *stream_key,
                last_data: true,
                sequence_number: 0,
                source,
                data: vec![],
            })
            .expect("ProxyClient is dead");
    }

    fn do_housekeeping(&self) {
        self.clean_up_dead_streams();
        self.add_new_streams();
    }

    fn clean_up_dead_streams(&self) {
        let mut inner = self.inner.lock().expect("Stream handler pool is poisoned");
        while let Ok((stream_key, sequence_number)) = self.stream_killer_rx.try_recv() {
            match inner.stream_writer_channels.remove(&stream_key) {
                Some(writer_channel) => {
                    inner
                        .proxy_client_subs
                        .inbound_server_data
                        .try_send(InboundServerData {
                            stream_key,
                            last_data: true,
                            sequence_number,
                            source: writer_channel.peer_addr(),
                            data: vec![],
                        })
                        .expect("ProxyClient is dead");
                    debug!(
                        inner.logger,
                        "Killed StreamWriter to {} and sent server-drop report",
                        writer_channel.peer_addr()
                    )
                }
                None => debug!(
                    inner.logger,
                    "Tried to kill StreamWriter for key {:?}, but it was already gone", stream_key
                ),
            }
        }
    }

    fn add_new_streams(&self) {
        let mut inner = self.inner.lock().expect("Stream handler pool is poisoned");
        loop {
            match self.stream_adder_rx.try_recv() {
                Err(_) => break,
                Ok((stream_key, stream_writer_channel)) => {
                    debug!(
                        inner.logger,
                        "Persisting StreamWriter to {} under key {:?}",
                        stream_writer_channel.peer_addr(),
                        stream_key
                    );
                    inner
                        .stream_writer_channels
                        .insert(stream_key, stream_writer_channel)
                }
            };
        }
    }
}

pub trait StreamHandlerPoolFactory {
    fn make(
        &self,
        resolver: Box<dyn ResolverWrapper>,
        cryptde: &'static dyn CryptDE,
        accountant_sub: Recipient<ReportExitServiceProvidedMessage>,
        proxy_client_subs: ProxyClientSubs,
        exit_service_rate: u64,
        exit_byte_rate: u64,
    ) -> Box<dyn StreamHandlerPool>;
}

pub struct StreamHandlerPoolFactoryReal {}

impl StreamHandlerPoolFactory for StreamHandlerPoolFactoryReal {
    fn make(
        &self,
        resolver: Box<dyn ResolverWrapper>,
        cryptde: &'static dyn CryptDE,
        accountant_sub: Recipient<ReportExitServiceProvidedMessage>,
        proxy_client_subs: ProxyClientSubs,
        exit_service_rate: u64,
        exit_byte_rate: u64,
    ) -> Box<dyn StreamHandlerPool> {
        Box::new(StreamHandlerPoolReal::new(
            resolver,
            cryptde,
            accountant_sub,
            proxy_client_subs,
            exit_service_rate,
            exit_byte_rate,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node_test_utils::check_timestamp;
    use crate::proxy_client::local_test_utils::make_send_error;
    use crate::proxy_client::local_test_utils::ResolverWrapperMock;
    use crate::proxy_client::stream_establisher::StreamEstablisher;
    use crate::sub_lib::cryptde::PublicKey;
    use crate::sub_lib::hopper::ExpiredCoresPackage;
    use crate::sub_lib::hopper::MessageType;
    use crate::sub_lib::proxy_server::ProxyProtocol;
    use crate::test_utils::await_messages;
    use crate::test_utils::channel_wrapper_mocks::FuturesChannelFactoryMock;
    use crate::test_utils::channel_wrapper_mocks::ReceiverWrapperMock;
    use crate::test_utils::channel_wrapper_mocks::SenderWrapperMock;
    use crate::test_utils::main_cryptde;
    use crate::test_utils::make_meaningless_route;
    use crate::test_utils::make_meaningless_stream_key;
    use crate::test_utils::make_wallet;
    use crate::test_utils::recorder::make_recorder;
    use crate::test_utils::recorder::peer_actors_builder;
    use crate::test_utils::stream_connector_mock::StreamConnectorMock;
    use crate::test_utils::tokio_wrapper_mocks::ReadHalfWrapperMock;
    use crate::test_utils::tokio_wrapper_mocks::WriteHalfWrapperMock;
    use actix::System;
    use masq_lib::constants::HTTP_PORT;
    use masq_lib::test_utils::logging::init_test_logging;
    use masq_lib::test_utils::logging::TestLogHandler;
    use std::cell::RefCell;
    use std::io::Error;
    use std::io::ErrorKind;
    use std::net::IpAddr;
    use std::net::SocketAddr;
    use std::ops::Deref;
    use std::str::FromStr;
    use std::sync::{Arc, Mutex};
    use std::task::Poll;
    use std::thread;
    use hickory_resolver::error::ResolveErrorKind;
    use crate::sub_lib::channel_wrappers::FuturesChannelFactoryReal;

    struct StreamEstablisherFactoryMock {
        make_results: RefCell<Vec<StreamEstablisher>>,
    }

    impl StreamEstablisherFactory for StreamEstablisherFactoryMock {
        fn make(&self) -> StreamEstablisher {
            self.make_results.borrow_mut().remove(0)
        }
    }

    fn spawn_process_package(
        subject: StreamHandlerPoolReal,
        package: ExpiredCoresPackage<MessageType>,
    ) {
        let paying_wallet = package.paying_wallet.clone();
        let payload = match package.payload {
            MessageType::ClientRequest(vd) => vd
                .extract(&crate::sub_lib::migrations::client_request_payload::MIGRATIONS)
                .unwrap(),
            _ => panic!("Expected MessageType::ClientRequest, got something else"),
        };
        let future = async {
            subject.process_package(payload, paying_wallet);
        };
        task::spawn(future);
    }

    #[test]
    fn dns_resolution_failure_sends_a_message_to_proxy_client() {
        let (proxy_client, proxy_client_awaiter, proxy_client_recording) = make_recorder();
        let stream_key = make_meaningless_stream_key();
        thread::spawn(move || {
            let system = System::new();
            let peer_actors = peer_actors_builder().proxy_client(proxy_client).build();
            let cryptde = main_cryptde();
            let resolver_mock =
                ResolverWrapperMock::new().lookup_ip_failure(ResolveErrorKind::Io.into());
            let logger = Logger::new("dns_resolution_failure_sends_a_message_to_proxy_client");
            let establisher = StreamEstablisher {
                cryptde,
                stream_adder_tx: unbounded().0,
                stream_killer_tx: unbounded().0,
                stream_connector: Box::new(StreamConnectorMock::new()),
                proxy_client_sub: peer_actors
                    .proxy_client_opt
                    .clone()
                    .unwrap()
                    .inbound_server_data,
                logger: logger.clone(),
                channel_factory: Box::new(FuturesChannelFactoryMock::default()),
            };
            let inner = StreamHandlerPoolRealInner {
                accountant_sub: peer_actors.accountant.report_exit_service_provided.clone(),
                proxy_client_subs: peer_actors.proxy_client_opt.clone().unwrap(),
                stream_writer_channels: HashMap::new(),
                resolver: Box::new(resolver_mock),
                logger,
                establisher_factory: Box::new(StreamEstablisherFactoryMock {
                    make_results: RefCell::new(vec![establisher]),
                }),
                exit_service_rate: Default::default(),
                exit_byte_rate: Default::default(),
            };
            let payload = ClientRequestPayload_0v1 {
                stream_key,
                sequenced_packet: SequencedPacket::new(b"booga".to_vec(), 0, false),
                target_hostname: Some("www.example.com".to_string()),
                target_port: HTTP_PORT,
                protocol: ProxyProtocol::HTTP,
                originator_public_key: cryptde.public_key().clone(),
            };

            StreamHandlerPoolReal::process_package(payload, None, Arc::new(Mutex::new(inner)));

            system.run();
        });

        proxy_client_awaiter.await_message_count(1);

        assert_eq!(
            &DnsResolveFailure_0v1::new(stream_key),
            proxy_client_recording
                .lock()
                .unwrap()
                .get_record::<DnsResolveFailure_0v1>(0),
        );
    }

    #[test]
    fn non_terminal_payload_can_be_sent_over_existing_connection() {
        let cryptde = main_cryptde();
        let stream_key = make_meaningless_stream_key();
        let client_request_payload = ClientRequestPayload_0v1 {
            stream_key: stream_key.clone(),
            sequenced_packet: SequencedPacket {
                data: b"These are the times".to_vec(),
                sequence_number: 0,
                last_data: false,
            },
            target_hostname: None,
            target_port: HTTP_PORT,
            protocol: ProxyProtocol::HTTP,
            originator_public_key: PublicKey::new(&b"men's souls"[..]),
        };
        let write_parameters = Arc::new(Mutex::new(vec![]));
        let tx_to_write = Box::new(
            SenderWrapperMock::new(SocketAddr::from_str("1.2.3.4:5678").unwrap())
                .unbounded_send_result(Ok(()))
                .unbounded_send_params(&write_parameters),
        );

        let package = ExpiredCoresPackage::new(
            SocketAddr::from_str("1.2.3.4:1234").unwrap(),
            Some(make_wallet("consuming")),
            make_meaningless_route(),
            client_request_payload.clone().into(),
            0,
        );

        thread::spawn(move || {
            let peer_actors = peer_actors_builder().build();
            let subject = StreamHandlerPoolReal::new(
                Box::new(ResolverWrapperMock::new()),
                cryptde,
                peer_actors.accountant.report_exit_service_provided.clone(),
                peer_actors.proxy_client_opt.unwrap().clone(),
                100,
                200,
            );
            subject
                .inner
                .lock()
                .unwrap()
                .stream_writer_channels
                .insert(stream_key, tx_to_write);

            spawn_process_package(subject, package);
        });

        await_messages(1, &write_parameters);

        assert_eq!(
            write_parameters.lock().unwrap().remove(0),
            client_request_payload.sequenced_packet
        );
    }

    #[test]
    fn write_failure_for_nonexistent_stream_generates_termination_message() {
        init_test_logging();
        let cryptde = main_cryptde();
        let (proxy_client, proxy_client_awaiter, proxy_client_recording_arc) = make_recorder();
        let originator_key = PublicKey::new(&b"men's souls"[..]);
        thread::spawn(move || {
            let client_request_payload = ClientRequestPayload_0v1 {
                stream_key: make_meaningless_stream_key(),
                sequenced_packet: SequencedPacket {
                    data: b"These are the times".to_vec(),
                    sequence_number: 0,
                    last_data: false,
                },
                target_hostname: Some(String::from("that.try")),
                target_port: HTTP_PORT,
                protocol: ProxyProtocol::HTTP,
                originator_public_key: originator_key,
            };
            let package = ExpiredCoresPackage::new(
                SocketAddr::from_str("1.2.3.4:1234").unwrap(),
                Some(make_wallet("consuming")),
                make_meaningless_route(),
                client_request_payload.clone().into(),
                0,
            );
            let peer_actors = peer_actors_builder().proxy_client(proxy_client).build();
            let resolver = ResolverWrapperMock::new()
                .lookup_ip_success(vec![IpAddr::from_str("2.3.4.5").unwrap()]);

            let tx_to_write = SenderWrapperMock::new(SocketAddr::from_str("2.3.4.5:80").unwrap())
                .unbounded_send_result(make_send_error(
                    client_request_payload.sequenced_packet.clone(),
                ));

            let subject = StreamHandlerPoolReal::new(
                Box::new(resolver),
                cryptde,
                peer_actors.accountant.report_exit_service_provided.clone(),
                peer_actors.proxy_client_opt.unwrap().clone(),
                100,
                200,
            );
            subject
                .inner
                .lock()
                .unwrap()
                .stream_writer_channels
                .insert(client_request_payload.stream_key, Box::new(tx_to_write));

            spawn_process_package(subject, package);
        });
        proxy_client_awaiter.await_message_count(1);
        let proxy_client_recording = proxy_client_recording_arc.lock().unwrap();
        assert_eq!(
            proxy_client_recording.get_record::<InboundServerData>(0),
            &InboundServerData {
                stream_key: make_meaningless_stream_key(),
                last_data: true,
                sequence_number: 0,
                source: SocketAddr::from_str("2.3.4.5:80").unwrap(),
                data: vec![],
            }
        );
    }

    #[test]
    fn when_hostname_is_ip_establish_stream_without_dns_lookup() {
        let cryptde = main_cryptde();
        let lookup_ip_parameters = Arc::new(Mutex::new(vec![]));
        let expected_lookup_ip_parameters = lookup_ip_parameters.clone();
        let write_parameters = Arc::new(Mutex::new(vec![]));
        let expected_write_parameters = write_parameters.clone();
        let (proxy_client, proxy_client_awaiter, proxy_client_recording_arc) = make_recorder();
        thread::spawn(move || {
            let peer_actors = peer_actors_builder().proxy_client(proxy_client).build();
            let client_request_payload = ClientRequestPayload_0v1 {
                stream_key: make_meaningless_stream_key(),
                sequenced_packet: SequencedPacket {
                    data: b"These are the times".to_vec(),
                    sequence_number: 0,
                    last_data: false,
                },
                target_hostname: Some(String::from("3.4.5.6:80")),
                target_port: HTTP_PORT,
                protocol: ProxyProtocol::HTTP,
                originator_public_key: PublicKey::new(&b"men's souls"[..]),
            };
            let package = ExpiredCoresPackage::new(
                SocketAddr::from_str("1.2.3.4:1234").unwrap(),
                Some(make_wallet("consuming")),
                make_meaningless_route(),
                client_request_payload.into(),
                0,
            );
            let resolver = ResolverWrapperMock::new()
                .lookup_ip_params(&lookup_ip_parameters)
                .lookup_ip_success(vec![
                    IpAddr::from_str("2.3.4.5").unwrap(),
                    IpAddr::from_str("3.4.5.6").unwrap(),
                ]);
            let peer_addr = SocketAddr::from_str("3.4.5.6:80").unwrap();
            let first_read_result = b"HTTP/1.1 200 OK\r\n\r\n";
            let reader = ReadHalfWrapperMock {
                poll_read_results: vec![
                    (
                        first_read_result.to_vec(),
                        Poll::Ready(Ok(first_read_result.len())),
                    ),
                    (
                        vec![],
                        Poll::Ready(Err(Error::from(ErrorKind::ConnectionAborted))),
                    ),
                ],
            };
            let writer = WriteHalfWrapperMock {
                poll_write_params: write_parameters,
                poll_write_results: vec![Poll::Ready(Ok(first_read_result.len()))],
                poll_close_results: Arc::new(Mutex::new(vec![])),
            };
            let mut subject = StreamHandlerPoolReal::new(
                Box::new(resolver),
                cryptde,
                peer_actors.accountant.report_exit_service_provided.clone(),
                peer_actors.proxy_client_opt.unwrap().clone(),
                100,
                200,
            );
            let (stream_killer_tx, stream_killer_rx) = unbounded();
            subject.stream_killer_rx = stream_killer_rx;
            let (stream_adder_tx, _stream_adder_rx) = unbounded();
            {
                let mut inner = subject.inner.lock().unwrap();
                let establisher = StreamEstablisher {
                    cryptde,
                    stream_adder_tx,
                    stream_killer_tx,
                    stream_connector: Box::new(StreamConnectorMock::new().with_connection(
                        peer_addr.clone(),
                        peer_addr.clone(),
                        reader,
                        writer,
                    )),
                    proxy_client_sub: inner.proxy_client_subs.inbound_server_data.clone(),
                    logger: inner.logger.clone(),
                    channel_factory: Box::new(FuturesChannelFactoryReal {}),
                };

                inner.establisher_factory = Box::new(StreamEstablisherFactoryMock {
                    make_results: RefCell::new(vec![establisher]),
                });
            }

            spawn_process_package(subject, package);
        });

        proxy_client_awaiter.await_message_count(1);
        assert_eq!(
            expected_lookup_ip_parameters.lock().unwrap().deref(),
            &(vec![] as Vec<String>)
        );
        assert_eq!(
            expected_write_parameters.lock().unwrap().remove(0),
            b"These are the times".to_vec()
        );
        let proxy_client_recording = proxy_client_recording_arc.lock().unwrap();
        assert_eq!(
            proxy_client_recording.get_record::<InboundServerData>(0),
            &InboundServerData {
                stream_key: make_meaningless_stream_key(),
                last_data: false,
                sequence_number: 0,
                source: SocketAddr::from_str("3.4.5.6:80").unwrap(),
                data: b"HTTP/1.1 200 OK\r\n\r\n".to_vec(),
            }
        );
    }

    #[test]
    fn ip_is_parsed_even_without_port() {
        let cryptde = main_cryptde();
        let lookup_ip_parameters = Arc::new(Mutex::new(vec![]));
        let expected_lookup_ip_parameters = lookup_ip_parameters.clone();
        let write_parameters = Arc::new(Mutex::new(vec![]));
        let expected_write_parameters = write_parameters.clone();
        let (proxy_client, proxy_client_awaiter, proxy_client_recording_arc) = make_recorder();
        thread::spawn(move || {
            let peer_actors = peer_actors_builder().proxy_client(proxy_client).build();
            let client_request_payload = ClientRequestPayload_0v1 {
                stream_key: make_meaningless_stream_key(),
                sequenced_packet: SequencedPacket {
                    data: b"These are the times".to_vec(),
                    sequence_number: 0,
                    last_data: false,
                },
                target_hostname: Some(String::from("3.4.5.6")),
                target_port: HTTP_PORT,
                protocol: ProxyProtocol::HTTP,
                originator_public_key: PublicKey::new(&b"men's souls"[..]),
            };
            let package = ExpiredCoresPackage::new(
                SocketAddr::from_str("1.2.3.4:1234").unwrap(),
                Some(make_wallet("consuming")),
                make_meaningless_route(),
                client_request_payload.into(),
                0,
            );
            let resolver = ResolverWrapperMock::new()
                .lookup_ip_params(&lookup_ip_parameters)
                .lookup_ip_success(vec![
                    IpAddr::from_str("2.3.4.5").unwrap(),
                    IpAddr::from_str("3.4.5.6").unwrap(),
                ]);
            let peer_addr = SocketAddr::from_str("3.4.5.6:80").unwrap();
            let first_read_result = b"HTTP/1.1 200 OK\r\n\r\n";
            let reader = ReadHalfWrapperMock {
                poll_read_results: vec![
                    (
                        first_read_result.to_vec(),
                        Poll::Ready(Ok(first_read_result.len())),
                    ),
                    (
                        vec![],
                        Poll::Ready(Err(Error::from(ErrorKind::ConnectionAborted))),
                    ),
                ],
            };
            let writer = WriteHalfWrapperMock {
                poll_write_params: write_parameters,
                poll_write_results: vec![Poll::Ready(Ok(first_read_result.len()))],
                poll_close_results: Arc::new(Mutex::new(vec![])),
            };
            let mut subject = StreamHandlerPoolReal::new(
                Box::new(resolver),
                cryptde,
                peer_actors.accountant.report_exit_service_provided.clone(),
                peer_actors.proxy_client_opt.unwrap().clone(),
                100,
                200,
            );
            let (stream_killer_tx, stream_killer_rx) = unbounded();
            subject.stream_killer_rx = stream_killer_rx;
            let (stream_adder_tx, _stream_adder_rx) = unbounded();
            {
                let mut inner = subject.inner.lock().unwrap();
                let establisher = StreamEstablisher {
                    cryptde,
                    stream_adder_tx,
                    stream_killer_tx,
                    stream_connector: Box::new(StreamConnectorMock::new().with_connection(
                        peer_addr.clone(),
                        peer_addr.clone(),
                        reader,
                        writer,
                    )),
                    proxy_client_sub: inner.proxy_client_subs.inbound_server_data.clone(),
                    logger: inner.logger.clone(),
                    channel_factory: Box::new(FuturesChannelFactoryReal {}),
                };

                inner.establisher_factory = Box::new(StreamEstablisherFactoryMock {
                    make_results: RefCell::new(vec![establisher]),
                });
            }

            spawn_process_package(subject, package);
        });

        proxy_client_awaiter.await_message_count(1);
        assert_eq!(
            expected_lookup_ip_parameters.lock().unwrap().deref(),
            &(vec![] as Vec<String>)
        );
        assert_eq!(
            expected_write_parameters.lock().unwrap().remove(0),
            b"These are the times".to_vec()
        );
        let proxy_client_recording = proxy_client_recording_arc.lock().unwrap();
        assert_eq!(
            proxy_client_recording.get_record::<InboundServerData>(0),
            &InboundServerData {
                stream_key: make_meaningless_stream_key(),
                last_data: false,
                sequence_number: 0,
                source: SocketAddr::from_str("3.4.5.6:80").unwrap(),
                data: b"HTTP/1.1 200 OK\r\n\r\n".to_vec(),
            }
        );
    }

    #[test]
    fn missing_hostname_for_nonexistent_stream_generates_log_and_termination_message() {
        init_test_logging();
        let cryptde = main_cryptde();
        let (proxy_client, proxy_client_awaiter, proxy_client_recording_arc) = make_recorder();
        let originator_key = PublicKey::new(&b"men's souls"[..]);
        thread::spawn(move || {
            let peer_actors = peer_actors_builder().proxy_client(proxy_client).build();
            let client_request_payload = ClientRequestPayload_0v1 {
                stream_key: make_meaningless_stream_key(),
                sequenced_packet: SequencedPacket {
                    data: b"These are the times".to_vec(),
                    sequence_number: 0,
                    last_data: false,
                },
                target_hostname: None,
                target_port: HTTP_PORT,
                protocol: ProxyProtocol::HTTP,
                originator_public_key: originator_key,
            };
            let package = ExpiredCoresPackage::new(
                SocketAddr::from_str("1.2.3.4:1234").unwrap(),
                Some(make_wallet("consuming")),
                make_meaningless_route(),
                client_request_payload.into(),
                0,
            );
            let resolver =
                ResolverWrapperMock::new().lookup_ip_failure(ResolveErrorKind::Io.into());
            let subject = StreamHandlerPoolReal::new(
                Box::new(resolver),
                cryptde,
                peer_actors.accountant.report_exit_service_provided.clone(),
                peer_actors.proxy_client_opt.unwrap().clone(),
                100,
                200,
            );

            spawn_process_package(subject, package);
        });

        proxy_client_awaiter.await_message_count(1);
        let proxy_client_recording = proxy_client_recording_arc.lock().unwrap();
        assert_eq!(
            proxy_client_recording.get_record::<InboundServerData>(0),
            &InboundServerData {
                stream_key: make_meaningless_stream_key(),
                last_data: true,
                sequence_number: 0,
                source: error_socket_addr(),
                data: vec![],
            }
        );
        TestLogHandler::new().exists_log_containing(
            format!(
                "ERROR: ProxyClient: Cannot open new stream with key {:?}: no hostname supplied",
                make_meaningless_stream_key()
            )
            .as_str(),
        );
    }

    #[test]
    fn nonexistent_connection_springs_into_being_and_is_persisted_to_handle_transaction() {
        let cryptde = main_cryptde();
        let lookup_ip_parameters = Arc::new(Mutex::new(vec![]));
        let expected_lookup_ip_parameters = lookup_ip_parameters.clone();
        let write_parameters = Arc::new(Mutex::new(vec![]));
        let expected_write_parameters = write_parameters.clone();
        let (proxy_client, proxy_client_awaiter, proxy_client_recording_arc) = make_recorder();
        let (accountant, accountant_awaiter, accountant_recording_arc) = make_recorder();
        let before = SystemTime::now();
        thread::spawn(move || {
            let peer_actors = peer_actors_builder()
                .proxy_client(proxy_client)
                .accountant(accountant)
                .build();
            let client_request_payload = ClientRequestPayload_0v1 {
                stream_key: make_meaningless_stream_key(),
                sequenced_packet: SequencedPacket {
                    data: b"These are the times".to_vec(),
                    sequence_number: 0,
                    last_data: false,
                },
                target_hostname: Some(String::from("that.try")),
                target_port: HTTP_PORT,
                protocol: ProxyProtocol::HTTP,
                originator_public_key: PublicKey::new(&b"men's souls"[..]),
            };
            let package = ExpiredCoresPackage::new(
                SocketAddr::from_str("1.2.3.4:1234").unwrap(),
                Some(make_wallet("consuming")),
                make_meaningless_route(),
                client_request_payload.into(),
                0,
            );
            let resolver = ResolverWrapperMock::new()
                .lookup_ip_params(&lookup_ip_parameters)
                .lookup_ip_success(vec![
                    IpAddr::from_str("2.3.4.5").unwrap(),
                    IpAddr::from_str("3.4.5.6").unwrap(),
                ]);
            let peer_addr = SocketAddr::from_str("3.4.5.6:80").unwrap();
            let first_read_result = b"HTTP/1.1 200 OK\r\n\r\n";
            let reader = ReadHalfWrapperMock {
                poll_read_results: vec![
                    (
                        first_read_result.to_vec(),
                        Poll::Ready(Ok(first_read_result.len())),
                    ),
                    (
                        vec![],
                        Poll::Ready(Err(Error::from(ErrorKind::ConnectionAborted))),
                    ),
                ],
            };
            let writer = WriteHalfWrapperMock {
                poll_write_params: write_parameters,
                poll_write_results: vec![Poll::Ready(Ok(first_read_result.len()))],
                poll_close_results: Arc::new(Mutex::new(vec![])),
            };
            let mut subject = StreamHandlerPoolReal::new(
                Box::new(resolver),
                cryptde,
                peer_actors.accountant.report_exit_service_provided.clone(),
                peer_actors.proxy_client_opt.unwrap().clone(),
                100,
                200,
            );
            let (stream_killer_tx, stream_killer_rx) = unbounded();
            subject.stream_killer_rx = stream_killer_rx;
            let (stream_adder_tx, _stream_adder_rx) = unbounded();
            {
                let mut inner = subject.inner.lock().unwrap();
                let establisher = StreamEstablisher {
                    cryptde,
                    stream_adder_tx,
                    stream_killer_tx,
                    stream_connector: Box::new(StreamConnectorMock::new().with_connection(
                        peer_addr.clone(),
                        peer_addr.clone(),
                        reader,
                        writer,
                    )),
                    proxy_client_sub: inner.proxy_client_subs.inbound_server_data.clone(),
                    logger: inner.logger.clone(),
                    channel_factory: Box::new(FuturesChannelFactoryReal {}),
                };

                inner.establisher_factory = Box::new(StreamEstablisherFactoryMock {
                    make_results: RefCell::new(vec![establisher]),
                });
            }

            spawn_process_package(subject, package);
        });

        proxy_client_awaiter.await_message_count(1);
        accountant_awaiter.await_message_count(1);
        let after = SystemTime::now();
        assert_eq!(
            expected_lookup_ip_parameters.lock().unwrap().deref(),
            &["that.try.".to_string()]
        );
        assert_eq!(
            expected_write_parameters.lock().unwrap().remove(0),
            b"These are the times".to_vec()
        );
        let proxy_client_recording = proxy_client_recording_arc.lock().unwrap();
        assert_eq!(
            proxy_client_recording.get_record::<InboundServerData>(0),
            &InboundServerData {
                stream_key: make_meaningless_stream_key(),
                last_data: false,
                sequence_number: 0,
                source: SocketAddr::from_str("3.4.5.6:80").unwrap(),
                data: b"HTTP/1.1 200 OK\r\n\r\n".to_vec(),
            }
        );
        let accountant_recording = accountant_recording_arc.lock().unwrap();
        let resp_msg = accountant_recording.get_record::<ReportExitServiceProvidedMessage>(0);
        check_timestamp(before, resp_msg.timestamp, after);
    }

    #[test]
    fn failing_to_make_a_connection_sends_an_error_response() {
        let cryptde = main_cryptde();
        let stream_key = make_meaningless_stream_key();
        let lookup_ip_parameters = Arc::new(Mutex::new(vec![]));
        let (proxy_client, proxy_client_awaiter, proxy_client_recording_arc) = make_recorder();
        let originator_key = PublicKey::new(&b"men's souls"[..]);
        thread::spawn(move || {
            let peer_actors = peer_actors_builder().proxy_client(proxy_client).build();
            let client_request_payload = ClientRequestPayload_0v1 {
                stream_key,
                sequenced_packet: SequencedPacket {
                    data: b"These are the times".to_vec(),
                    sequence_number: 0,
                    last_data: false,
                },
                target_hostname: Some(String::from("that.try")),
                target_port: HTTP_PORT,
                protocol: ProxyProtocol::HTTP,
                originator_public_key: originator_key,
            };
            let package = ExpiredCoresPackage::new(
                SocketAddr::from_str("1.2.3.4:1234").unwrap(),
                Some(make_wallet("consuming")),
                make_meaningless_route(),
                client_request_payload.into(),
                0,
            );
            let resolver = ResolverWrapperMock::new()
                .lookup_ip_params(&lookup_ip_parameters)
                .lookup_ip_success(vec![
                    IpAddr::from_str("2.3.4.5").unwrap(),
                    IpAddr::from_str("3.4.5.6").unwrap(),
                ]);
            let proxy_client_sub = peer_actors
                .proxy_client_opt
                .clone()
                .unwrap()
                .inbound_server_data;
            let mut subject = StreamHandlerPoolReal::new(
                Box::new(resolver),
                cryptde,
                peer_actors.accountant.report_exit_service_provided.clone(),
                peer_actors.proxy_client_opt.clone().unwrap(),
                100,
                200,
            );
            let (stream_killer_tx, stream_killer_rx) = unbounded();
            subject.stream_killer_rx = stream_killer_rx;
            let (stream_adder_tx, _stream_adder_rx) = unbounded();
            let establisher = StreamEstablisher {
                cryptde,
                stream_adder_tx,
                stream_killer_tx,
                stream_connector: Box::new(
                    StreamConnectorMock::new()
                        .connect_pair_result(Err(Error::from(ErrorKind::Other))),
                ),
                proxy_client_sub,
                logger: subject.inner.lock().unwrap().logger.clone(),
                channel_factory: Box::new(FuturesChannelFactoryReal {}),
            };

            subject.inner.lock().unwrap().establisher_factory =
                Box::new(StreamEstablisherFactoryMock {
                    make_results: RefCell::new(vec![establisher]),
                });

            spawn_process_package(subject, package);
        });

        proxy_client_awaiter.await_message_count(1);
        let proxy_client_recording = proxy_client_recording_arc.lock().unwrap();
        assert_eq!(
            proxy_client_recording.get_record::<InboundServerData>(0),
            &InboundServerData {
                stream_key,
                last_data: true,
                sequence_number: 0,
                source: error_socket_addr(),
                data: vec![],
            }
        );
    }

    #[test]
    fn trying_to_write_to_disconnected_stream_writer_sends_an_error_response() {
        let cryptde = main_cryptde();
        let stream_key = make_meaningless_stream_key();
        let lookup_ip_parameters = Arc::new(Mutex::new(vec![]));
        let write_parameters = Arc::new(Mutex::new(vec![]));
        let (proxy_client, proxy_client_awaiter, proxy_client_recording_arc) = make_recorder();
        let (stream_adder_tx, _stream_adder_rx) = unbounded();

        thread::spawn(move || {
            let peer_actors = peer_actors_builder().proxy_client(proxy_client).build();

            let sequenced_packet = SequencedPacket {
                data: b"These are the times".to_vec(),
                sequence_number: 0,
                last_data: false,
            };

            let client_request_payload = ClientRequestPayload_0v1 {
                stream_key,
                sequenced_packet: sequenced_packet.clone(),
                target_hostname: Some(String::from("that.try")),
                target_port: HTTP_PORT,
                protocol: ProxyProtocol::HTTP,
                originator_public_key: PublicKey::new(&b"men's souls"[..]),
            };

            let package = ExpiredCoresPackage::new(
                SocketAddr::from_str("1.2.3.4:1234").unwrap(),
                Some(make_wallet("consuming")),
                make_meaningless_route(),
                client_request_payload.into(),
                0,
            );

            let resolver = ResolverWrapperMock::new()
                .lookup_ip_params(&lookup_ip_parameters)
                .lookup_ip_success(vec![
                    IpAddr::from_str("2.3.4.5").unwrap(),
                    IpAddr::from_str("3.4.5.6").unwrap(),
                ]);

            let reader = ReadHalfWrapperMock {
                poll_read_results: vec![
                    (vec![], Poll::Pending),
                    (
                        vec![],
                        Poll::Ready(Err(Error::from(ErrorKind::ConnectionAborted))),
                    ),
                ],
            };
            let writer = WriteHalfWrapperMock {
                poll_write_params: write_parameters,
                poll_write_results: vec![Poll::Pending],
                poll_close_results: Arc::new(Mutex::new(vec![])),
            };

            let mut subject = StreamHandlerPoolReal::new(
                Box::new(resolver),
                cryptde,
                peer_actors.accountant.report_exit_service_provided.clone(),
                peer_actors.proxy_client_opt.clone().unwrap(),
                100,
                200,
            );

            let peer_addr = SocketAddr::from_str("3.4.5.6:80").unwrap();
            let disconnected_sender = Box::new(
                SenderWrapperMock::new(peer_addr)
                    .unbounded_send_result(make_send_error(sequenced_packet)),
            );

            let (stream_killer_tx, stream_killer_rx) = unbounded();
            subject.stream_killer_rx = stream_killer_rx;

            {
                let mut inner = subject.inner.lock().unwrap();
                let establisher = StreamEstablisher {
                    cryptde,
                    stream_adder_tx,
                    stream_killer_tx,
                    stream_connector: Box::new(
                        StreamConnectorMock::new()
                            .with_connection(peer_addr, peer_addr, reader, writer),
                    ),
                    proxy_client_sub: peer_actors
                        .proxy_client_opt
                        .clone()
                        .unwrap()
                        .inbound_server_data,
                    logger: inner.logger.clone(),
                    channel_factory: Box::new(FuturesChannelFactoryMock {
                        results: vec![(
                            disconnected_sender,
                            Box::new(ReceiverWrapperMock {
                                poll_results: vec![Poll::Ready(Ok(None))],
                            }),
                        )],
                    }),
                };

                inner.establisher_factory = Box::new(StreamEstablisherFactoryMock {
                    make_results: RefCell::new(vec![establisher]),
                });
            }
            spawn_process_package(subject, package);
        });

        proxy_client_awaiter.await_message_count(1);
        let proxy_client_recording = proxy_client_recording_arc.lock().unwrap();
        assert_eq!(
            proxy_client_recording.get_record::<InboundServerData>(0),
            &InboundServerData {
                stream_key,
                last_data: true,
                sequence_number: 0,
                source: error_socket_addr(),
                data: vec![],
            }
        );
    }

    #[test]
    fn bad_dns_lookup_produces_log_and_sends_error_response() {
        init_test_logging();
        let cryptde = main_cryptde();
        let stream_key = make_meaningless_stream_key();
        let (proxy_client, proxy_client_awaiter, proxy_client_recording_arc) = make_recorder();
        let originator_key = PublicKey::new(&b"men's souls"[..]);
        thread::spawn(move || {
            let client_request_payload = ClientRequestPayload_0v1 {
                stream_key,
                sequenced_packet: SequencedPacket {
                    data: b"These are the times".to_vec(),
                    sequence_number: 0,
                    last_data: true,
                },
                target_hostname: Some(String::from("that.try")),
                target_port: HTTP_PORT,
                protocol: ProxyProtocol::HTTP,
                originator_public_key: originator_key,
            };
            let package = ExpiredCoresPackage::new(
                SocketAddr::from_str("1.2.3.4:1234").unwrap(),
                Some(make_wallet("consuming")),
                make_meaningless_route(),
                client_request_payload.into(),
                0,
            );
            let peer_actors = peer_actors_builder().proxy_client(proxy_client).build();
            let mut lookup_ip_parameters = Arc::new(Mutex::new(vec![]));
            let resolver = ResolverWrapperMock::new()
                .lookup_ip_params(&mut lookup_ip_parameters)
                .lookup_ip_failure(ResolveErrorKind::Io.into());
            let subject = StreamHandlerPoolReal::new(
                Box::new(resolver),
                cryptde,
                peer_actors.accountant.report_exit_service_provided.clone(),
                peer_actors.proxy_client_opt.unwrap().clone(),
                100,
                200,
            );
            subject.inner.lock().unwrap().logger =
                Logger::new("bad_dns_lookup_produces_log_and_sends_error_response");
            spawn_process_package(subject, package);
        });
        proxy_client_awaiter.await_message_count(2);
        let recording = proxy_client_recording_arc.lock().unwrap();
        assert_eq!(
            recording.get_record::<InboundServerData>(1),
            &InboundServerData {
                stream_key,
                last_data: true,
                sequence_number: 0,
                source: error_socket_addr(),
                data: vec![],
            }
        );
        TestLogHandler::new().exists_log_containing(
            "ERROR: bad_dns_lookup_produces_log_and_sends_error_response: Could not find IP address for host that.try: io error",
        );
    }

    #[test]
    fn error_from_tx_to_writer_removes_stream() {
        init_test_logging();
        let cryptde = main_cryptde();
        let stream_key = make_meaningless_stream_key();
        let (proxy_client, _, _) = make_recorder();
        let (hopper, _, _) = make_recorder();
        let (accountant, _, _) = make_recorder();
        let sequenced_packet = SequencedPacket {
            data: b"These are the times".to_vec(),
            sequence_number: 0,
            last_data: true,
        };
        let client_request_payload = ClientRequestPayload_0v1 {
            stream_key: stream_key.clone(),
            sequenced_packet: sequenced_packet.clone(),
            target_hostname: Some(String::from("that.try")),
            target_port: HTTP_PORT,
            protocol: ProxyProtocol::HTTP,
            originator_public_key: PublicKey::new(&b"men's souls"[..]),
        };
        let package = ExpiredCoresPackage::new(
            SocketAddr::from_str("1.2.3.4:1234").unwrap(),
            Some(make_wallet("consuming")),
            make_meaningless_route(),
            client_request_payload.into(),
            0,
        );
        let send_params = Arc::new(Mutex::new(vec![]));
        let sender_wrapper = SenderWrapperMock::new(SocketAddr::from_str("1.2.3.4:5678").unwrap())
            .unbounded_send_params(&send_params)
            .unbounded_send_result(make_send_error(sequenced_packet.clone()));
        thread::spawn(move || {
            let resolver = ResolverWrapperMock::new();
            let peer_actors = peer_actors_builder()
                .hopper(hopper)
                .accountant(accountant)
                .proxy_client(proxy_client)
                .build();

            let subject = StreamHandlerPoolReal::new(
                Box::new(resolver),
                cryptde,
                peer_actors.accountant.report_exit_service_provided.clone(),
                peer_actors.proxy_client_opt.unwrap().clone(),
                100,
                200,
            );
            subject
                .inner
                .lock()
                .unwrap()
                .stream_writer_channels
                .insert(stream_key, Box::new(sender_wrapper));

            spawn_process_package(subject, package);
        });

        await_messages(1, &send_params);
        assert_eq!(*send_params.lock().unwrap(), vec!(sequenced_packet));

        let tlh = TestLogHandler::new();
        tlh.await_log_containing("Removing stream writer for 1.2.3.4:5678", 1000);
    }

    #[test]
    fn process_package_does_not_create_new_connection_for_zero_length_data_with_unfamiliar_stream_key(
    ) {
        init_test_logging();
        let cryptde = main_cryptde();
        let (hopper, _, hopper_recording_arc) = make_recorder();
        let (accountant, _, accountant_recording_arc) = make_recorder();
        thread::spawn(move || {
            let peer_actors = peer_actors_builder()
                .hopper(hopper)
                .accountant(accountant)
                .build();
            let client_request_payload = ClientRequestPayload_0v1 {
                stream_key: make_meaningless_stream_key(),
                sequenced_packet: SequencedPacket {
                    data: vec![],
                    sequence_number: 0,
                    last_data: false,
                },
                target_hostname: None,
                target_port: HTTP_PORT,
                protocol: ProxyProtocol::HTTP,
                originator_public_key: PublicKey::new(&b"booga"[..]),
            };
            let package = ExpiredCoresPackage::new(
                SocketAddr::from_str("1.2.3.4:1234").unwrap(),
                Some(make_wallet("consuming")),
                make_meaningless_route(),
                client_request_payload.into(),
                0,
            );
            let resolver = ResolverWrapperMock::new();
            let subject = StreamHandlerPoolReal::new(
                Box::new(resolver),
                cryptde,
                peer_actors.accountant.report_exit_service_provided.clone(),
                peer_actors.proxy_client_opt.unwrap().clone(),
                100,
                200,
            );

            subject.inner.lock().unwrap().establisher_factory =
                Box::new(StreamEstablisherFactoryMock {
                    make_results: RefCell::new(vec![]),
                });

            spawn_process_package(subject, package);
        });

        let tlh = TestLogHandler::new();
        tlh.await_log_containing(
            &format!(
                "Empty request payload received for nonexistent stream {:?} - ignoring",
                make_meaningless_stream_key()
            )[..],
            2000,
        );
        let accountant_recording = accountant_recording_arc.lock().unwrap();
        assert_eq!(accountant_recording.len(), 0);
        let hopper_recording = hopper_recording_arc.lock().unwrap();
        assert_eq!(hopper_recording.len(), 0);
    }

    #[test]
    fn clean_up_dead_streams_sends_server_drop_report_if_dead_stream_is_in_map() {
        let system = System::new();
        let (proxy_client, _, proxy_client_recording_arc) = make_recorder();
        let peer_actors = peer_actors_builder().proxy_client(proxy_client).build();
        let mut subject = StreamHandlerPoolReal::new(
            Box::new(ResolverWrapperMock::new()),
            main_cryptde(),
            peer_actors.accountant.report_exit_service_provided,
            peer_actors.proxy_client_opt.unwrap(),
            0,
            0,
        );
        let (stream_killer_tx, stream_killer_rx) = unbounded();
        subject.stream_killer_rx = stream_killer_rx;
        let stream_key = make_meaningless_stream_key();
        let peer_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        {
            let mut inner = subject.inner.lock().unwrap();
            inner
                .stream_writer_channels
                .insert(stream_key, Box::new(SenderWrapperMock::new(peer_addr)));
        }
        stream_killer_tx.send((stream_key, 47)).unwrap();

        subject.clean_up_dead_streams();

        System::current().stop_with_code(0);
        system.run();
        let proxy_client_recording = proxy_client_recording_arc.lock().unwrap();
        let report = proxy_client_recording.get_record::<InboundServerData>(0);
        assert_eq!(
            report,
            &InboundServerData {
                stream_key,
                last_data: true,
                sequence_number: 47,
                source: peer_addr,
                data: vec![]
            }
        );
    }

    #[test]
    fn clean_up_dead_streams_does_not_send_server_drop_report_if_dead_stream_is_gone_already() {
        let system = System::new();
        let (proxy_client, _, proxy_client_recording_arc) = make_recorder();
        let peer_actors = peer_actors_builder().proxy_client(proxy_client).build();
        let mut subject = StreamHandlerPoolReal::new(
            Box::new(ResolverWrapperMock::new()),
            main_cryptde(),
            peer_actors.accountant.report_exit_service_provided,
            peer_actors.proxy_client_opt.unwrap(),
            0,
            0,
        );
        let (stream_killer_tx, stream_killer_rx) = unbounded();
        subject.stream_killer_rx = stream_killer_rx;
        let stream_key = make_meaningless_stream_key();
        stream_killer_tx.send((stream_key, 47)).unwrap();

        subject.clean_up_dead_streams();

        System::current().stop_with_code(0);
        system.run();
        let proxy_client_recording = proxy_client_recording_arc.lock().unwrap();
        assert_eq!(proxy_client_recording.len(), 0);
    }
}
