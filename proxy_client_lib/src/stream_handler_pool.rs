// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
#![allow(proc_macro_derive_resolution_fallback)]
use crate::resolver_wrapper::ResolverWrapper;
use crate::stream_establisher::StreamEstablisherFactory;
use crate::stream_establisher::StreamEstablisherFactoryReal;
use actix::Recipient;
use actix::Syn;
use futures::future::Future;
use std::collections::HashMap;
use std::sync::mpsc;
use std::sync::mpsc::Receiver;
use std::sync::Arc;
use std::sync::Mutex;
use sub_lib::accountant::ReportExitServiceProvidedMessage;
use sub_lib::channel_wrappers::SenderWrapper;
use sub_lib::cryptde::CryptDE;
use sub_lib::cryptde::PublicKey;
use sub_lib::hopper::IncipientCoresPackage;
use sub_lib::logger::Logger;
use sub_lib::proxy_client::ClientResponsePayload;
use sub_lib::proxy_client::TEMPORARY_PER_EXIT_BYTE_RATE;
use sub_lib::proxy_client::TEMPORARY_PER_EXIT_RATE;
use sub_lib::proxy_server::ClientRequestPayload;
use sub_lib::route::Route;
use sub_lib::sequence_buffer::SequencedPacket;
use sub_lib::stream_key::StreamKey;
use sub_lib::wallet::Wallet;
use tokio::prelude::future::FutureResult;
use tokio::prelude::future::{err, ok};

pub trait StreamHandlerPool {
    fn process_package(
        &self,
        payload: ClientRequestPayload,
        consuming_wallet: Option<Wallet>,
        route: Route,
    );
}

pub struct StreamHandlerPoolReal {
    inner: Arc<Mutex<StreamHandlerPoolRealInner>>,
    stream_adder_rx: Receiver<(StreamKey, Box<dyn SenderWrapper<SequencedPacket>>)>,
    stream_killer_rx: Receiver<StreamKey>,
    cryptde: &'static dyn CryptDE,
}

struct StreamHandlerPoolRealInner {
    hopper_sub: Recipient<Syn, IncipientCoresPackage>,
    accountant_sub: Recipient<Syn, ReportExitServiceProvidedMessage>,
    stream_writer_channels: HashMap<StreamKey, Box<dyn SenderWrapper<SequencedPacket>>>,
    resolver: Box<dyn ResolverWrapper>,
    logger: Logger,
    establisher_factory: Box<dyn StreamEstablisherFactory>,
}

impl StreamHandlerPool for StreamHandlerPoolReal {
    fn process_package(
        &self,
        payload: ClientRequestPayload,
        consuming_wallet: Option<Wallet>,
        return_route: Route,
    ) {
        self.do_housekeeping();

        if payload.sequenced_packet.last_data
            && (payload.sequenced_packet.data.len() == 0)
            && Self::find_stream_with_key(&payload.stream_key, &self.inner).is_none()
        {
            let inner = self.inner.lock().expect("Stream handler pool is poisoned");
            inner.logger.debug(format!(
                "Empty last_data message received for nonexistent stream {:?} - ignoring",
                payload.stream_key
            ));
        } else {
            Self::process_package(
                self.cryptde.clone(),
                payload,
                consuming_wallet,
                return_route,
                self.inner.clone(),
            )
        }
    }
}

impl StreamHandlerPoolReal {
    pub fn new(
        resolver: Box<dyn ResolverWrapper>,
        cryptde: &'static dyn CryptDE,
        hopper_sub: Recipient<Syn, IncipientCoresPackage>,
        accountant_sub: Recipient<Syn, ReportExitServiceProvidedMessage>,
    ) -> StreamHandlerPoolReal {
        let (stream_killer_tx, stream_killer_rx) = mpsc::channel();
        let (stream_adder_tx, stream_adder_rx) = mpsc::channel();
        StreamHandlerPoolReal {
            inner: Arc::new(Mutex::new(StreamHandlerPoolRealInner {
                establisher_factory: Box::new(StreamEstablisherFactoryReal {
                    cryptde,
                    stream_adder_tx,
                    stream_killer_tx,
                    hopper_sub: hopper_sub.clone(),
                    accountant_sub: accountant_sub.clone(),
                    logger: Logger::new("Proxy Client"),
                }),
                hopper_sub,
                accountant_sub,
                stream_writer_channels: HashMap::new(),
                resolver,
                logger: Logger::new("Proxy Client"),
            })),
            stream_adder_rx,
            stream_killer_rx,
            cryptde,
        }
    }

    fn process_package(
        cryptde: &'static dyn CryptDE,
        payload: ClientRequestPayload,
        consuming_wallet: Option<Wallet>,
        return_route: Route,
        inner_arc: Arc<Mutex<StreamHandlerPoolRealInner>>,
    ) {
        let stream_key = payload.stream_key;
        let originator_public_key = payload.originator_public_key.clone();
        let inner_arc_1 = inner_arc.clone();
        match Self::find_stream_with_key(&stream_key, &inner_arc) {
            Some(sender_wrapper) => {
                let future =
                    Self::write_and_tend(sender_wrapper, payload, consuming_wallet, inner_arc)
                        .map_err(move |error| {
                            Self::clean_up_bad_stream(
                                cryptde,
                                inner_arc_1,
                                &stream_key,
                                &return_route,
                                &originator_public_key,
                                error,
                            );
                            ()
                        });
                tokio::spawn(future);
            }
            None => {
                let future = Self::make_stream_with_key(
                    &payload,
                    consuming_wallet.clone(),
                    return_route.clone(),
                    inner_arc_1.clone(),
                )
                .and_then(move |sender_wrapper| {
                    Self::write_and_tend(sender_wrapper, payload, consuming_wallet, inner_arc)
                })
                .map_err(move |error| {
                    Self::clean_up_bad_stream(
                        cryptde,
                        inner_arc_1,
                        &stream_key,
                        &return_route,
                        &originator_public_key,
                        error,
                    );
                    ()
                });
                tokio::spawn(future);
            }
        };
    }

    fn clean_up_bad_stream(
        cryptde: &'static dyn CryptDE,
        inner_arc: Arc<Mutex<StreamHandlerPoolRealInner>>,
        stream_key: &StreamKey,
        return_route: &Route,
        originator_public_key: &PublicKey,
        error: String,
    ) {
        let mut inner = inner_arc.lock().expect("Stream handler pool was poisoned");
        inner.logger.error(format!(
            "Couldn't process request from CORES package: {}",
            error
        ));
        if let Some(sender_wrapper) = inner.stream_writer_channels.remove(stream_key) {
            inner.logger.debug(format!(
                "Removing stream writer for {}",
                sender_wrapper.peer_addr()
            ));
        }
        Self::send_terminating_package(
            cryptde,
            return_route,
            stream_key,
            originator_public_key,
            &inner.hopper_sub,
        );
    }

    fn write_and_tend(
        sender_wrapper: Box<dyn SenderWrapper<SequencedPacket>>,
        payload: ClientRequestPayload,
        consuming_wallet: Option<Wallet>,
        inner_arc: Arc<Mutex<StreamHandlerPoolRealInner>>,
    ) -> impl Future<Item = (), Error = String> {
        let stream_key = payload.stream_key.clone();
        let last_data = payload.sequenced_packet.last_data;
        let payload_size = payload.sequenced_packet.data.len() as u32;

        Self::perform_write(payload.sequenced_packet, sender_wrapper.clone()).and_then(move |_| {
            let mut inner = inner_arc.lock().expect("Stream handler pool is poisoned");
            if last_data {
                inner.stream_writer_channels.remove(&stream_key);
            }
            match consuming_wallet {
                Some(wallet) => inner
                    .accountant_sub
                    .try_send(ReportExitServiceProvidedMessage {
                        consuming_wallet: wallet,
                        payload_size,
                        service_rate: TEMPORARY_PER_EXIT_RATE,
                        byte_rate: TEMPORARY_PER_EXIT_BYTE_RATE,
                    })
                    .expect("Accountant is dead"),
                // This log is here mostly for testing, to prove that no Accountant message is sent in the no-wallet case
                None => inner.logger.debug(format!(
                    "Sent {}-byte request without consuming wallet for free",
                    payload_size
                )),
            }
            Ok(())
        })
    }

    fn make_stream_with_key(
        payload: &ClientRequestPayload,
        consuming_wallet: Option<Wallet>,
        return_route: Route,
        inner_arc: Arc<Mutex<StreamHandlerPoolRealInner>>,
    ) -> impl Future<Item = Box<dyn SenderWrapper<SequencedPacket> + 'static>, Error = String> {
        // TODO: Figure out what to do if a flurry of requests for a particular stream key
        // come flooding in so densely that several of them arrive in the time it takes to
        // resolve the first one and add it to the stream_writers map.
        let logger = Self::make_logger_copy(&inner_arc);
        let mut establisher = {
            let inner = inner_arc.lock().expect("Stream handler pool is poisoned");
            inner.establisher_factory.make()
        };
        logger.debug(format!(
            "No stream to {:?} exists; resolving host",
            &payload.target_hostname
        ));
        let fqdn_opt = Self::make_fqdn(&payload.target_hostname);

        let payload_clone = payload.clone();
        inner_arc
            .lock()
            .expect("Stream handler pool is poisoned")
            .resolver
            .lookup_ip(fqdn_opt)
            .then(move |lookup_result| {
                let result = establisher.establish_stream(
                    &payload_clone,
                    consuming_wallet,
                    &return_route,
                    lookup_result,
                );
                result
            })
            .map_err(|io_error| format!("Could not establish stream: {:?}", io_error))
    }

    fn make_fqdn(target_hostname_opt: &Option<String>) -> Option<String> {
        if let Some(target_hostname) = target_hostname_opt {
            Some(format!("{}.", target_hostname))
        } else {
            None
        }
    }

    fn find_stream_with_key(
        stream_key: &StreamKey,
        inner_arc: &Arc<Mutex<StreamHandlerPoolRealInner>>,
    ) -> Option<Box<dyn SenderWrapper<SequencedPacket>>> {
        let inner = inner_arc.lock().expect("Stream handler pool is poisoned");
        let sender_wrapper_opt = inner.stream_writer_channels.get(&stream_key);
        match sender_wrapper_opt {
            Some(sender_wrapper_box_ref) => Some(sender_wrapper_box_ref.as_ref().clone()),
            None => None,
        }
    }

    fn make_logger_copy(inner_arc: &Arc<Mutex<StreamHandlerPoolRealInner>>) -> Logger {
        let inner = inner_arc.lock().expect("Stream handler pool is poisoned");
        inner.logger.clone()
    }

    fn perform_write(
        sequenced_packet: SequencedPacket,
        sender_wrapper: Box<dyn SenderWrapper<SequencedPacket>>,
    ) -> FutureResult<(), String> {
        match sender_wrapper.unbounded_send(sequenced_packet) {
            Ok(_) => ok::<(), String>(()),
            Err(_) => err::<(), String>(format!("Could not queue write to stream; channel full")),
        }
    }

    fn send_terminating_package(
        cryptde: &'static dyn CryptDE,
        return_route: &Route,
        stream_key: &StreamKey,
        originator_public_key: &PublicKey,
        hopper_sub: &Recipient<Syn, IncipientCoresPackage>,
    ) {
        let response = ClientResponsePayload::make_terminating_payload(stream_key.clone());
        let package = IncipientCoresPackage::new(
            cryptde,
            return_route.clone(),
            response,
            &originator_public_key,
        )
        .expect("Key magically disappeared");
        hopper_sub.try_send(package).expect("Hopper died");
    }

    fn do_housekeeping(&self) {
        self.clean_up_dead_streams();
        self.add_new_streams();
    }

    fn clean_up_dead_streams(&self) {
        let mut inner = self.inner.lock().expect("Stream handler pool is poisoned");
        loop {
            match self.stream_killer_rx.try_recv() {
                Ok(stream_key) => match inner.stream_writer_channels.remove(&stream_key) {
                    Some(writer_channel) => inner.logger.debug(format!(
                        "Killed StreamWriter to {}",
                        writer_channel.peer_addr()
                    )),
                    None => inner.logger.debug(format!(
                        "Tried to kill StreamWriter for key {:?}, but it was not found",
                        stream_key
                    )),
                },
                Err(_) => break,
            };
        }
    }

    fn add_new_streams(&self) {
        let mut inner = self.inner.lock().expect("Stream handler pool is poisoned");
        loop {
            match self.stream_adder_rx.try_recv() {
                Err(_) => break,
                Ok((stream_key, stream_writer_channel)) => {
                    inner.logger.debug(format!(
                        "Persisting StreamWriter to {} under key {:?}",
                        stream_writer_channel.peer_addr(),
                        stream_key
                    ));
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
        hopper_sub: Recipient<Syn, IncipientCoresPackage>,
        accountant_sub: Recipient<Syn, ReportExitServiceProvidedMessage>,
    ) -> Box<dyn StreamHandlerPool>;
}

pub struct StreamHandlerPoolFactoryReal {}

impl StreamHandlerPoolFactory for StreamHandlerPoolFactoryReal {
    fn make(
        &self,
        resolver: Box<dyn ResolverWrapper>,
        cryptde: &'static dyn CryptDE,
        hopper_sub: Recipient<Syn, IncipientCoresPackage>,
        accountant_sub: Recipient<Syn, ReportExitServiceProvidedMessage>,
    ) -> Box<dyn StreamHandlerPool> {
        Box::new(StreamHandlerPoolReal::new(
            resolver,
            cryptde,
            hopper_sub,
            accountant_sub,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local_test_utils::make_send_error;
    use crate::local_test_utils::ResolverWrapperMock;
    use crate::stream_establisher::StreamEstablisher;
    use actix::Actor;
    use actix::Addr;
    use actix::Context;
    use actix::Handler;
    use actix::Message;
    use actix::System;
    use futures::lazy;
    use futures::sync::mpsc::unbounded;
    use futures::Stream;
    use serde_cbor;
    use std::cell::RefCell;
    use std::io::Error;
    use std::io::ErrorKind;
    use std::net::IpAddr;
    use std::net::SocketAddr;
    use std::ops::Deref;
    use std::str::FromStr;
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::thread;
    use std::time::Duration;
    use sub_lib::channel_wrappers::FuturesChannelFactoryReal;
    use sub_lib::channel_wrappers::SenderWrapperReal;
    use sub_lib::cryptde::PlainData;
    use sub_lib::cryptde_null::CryptDENull;
    use sub_lib::hopper::ExpiredCoresPackage;
    use sub_lib::proxy_server::ProxyProtocol;
    use sub_lib::wallet::Wallet;
    use test_utils::channel_wrapper_mocks::FuturesChannelFactoryMock;
    use test_utils::channel_wrapper_mocks::ReceiverWrapperMock;
    use test_utils::channel_wrapper_mocks::SenderWrapperMock;
    use test_utils::logging::init_test_logging;
    use test_utils::logging::TestLogHandler;
    use test_utils::recorder::make_peer_actors_from;
    use test_utils::recorder::make_recorder;
    use test_utils::stream_connector_mock::StreamConnectorMock;
    use test_utils::test_utils::await_messages;
    use test_utils::test_utils::cryptde;
    use test_utils::test_utils::make_meaningless_route;
    use test_utils::test_utils::make_meaningless_stream_key;
    use test_utils::tokio_wrapper_mocks::ReadHalfWrapperMock;
    use test_utils::tokio_wrapper_mocks::WriteHalfWrapperMock;
    use tokio;
    use tokio::prelude::Async;
    use trust_dns_resolver::error::ResolveError;
    use trust_dns_resolver::error::ResolveErrorKind;

    #[derive(Message)]
    struct TriggerSubject {
        package: ExpiredCoresPackage,
    }

    struct TestActor {
        subject: StreamHandlerPoolReal,
    }

    impl Actor for TestActor {
        type Context = Context<Self>;
    }

    impl Handler<TriggerSubject> for TestActor {
        type Result = ();

        fn handle(
            &mut self,
            msg: TriggerSubject,
            _ctx: &mut Self::Context,
        ) -> <Self as Handler<TriggerSubject>>::Result {
            let payload = msg.package.payload::<ClientRequestPayload>().unwrap();
            let consuming_wallet = msg.package.consuming_wallet;
            let route = msg.package.remaining_route;
            self.subject
                .process_package(payload, consuming_wallet, route);
            ()
        }
    }

    struct StreamEstablisherFactoryMock {
        make_results: RefCell<Vec<StreamEstablisher>>,
    }

    impl StreamEstablisherFactory for StreamEstablisherFactoryMock {
        fn make(&self) -> StreamEstablisher {
            self.make_results.borrow_mut().remove(0)
        }
    }

    #[test]
    fn non_terminal_payload_can_be_sent_over_existing_connection() {
        let stream_key = make_meaningless_stream_key();
        let client_request_payload = ClientRequestPayload {
            stream_key: stream_key.clone(),
            sequenced_packet: SequencedPacket {
                data: b"These are the times".to_vec(),
                sequence_number: 0,
                last_data: false,
            },
            target_hostname: None,
            target_port: 80,
            protocol: ProxyProtocol::HTTP,
            originator_public_key: PublicKey::new(&b"men's souls"[..]),
        };
        let mut tx_to_write = Box::new(SenderWrapperMock::new(
            SocketAddr::from_str("1.2.3.4:5678").unwrap(),
        ));
        tx_to_write.unbounded_send_results = RefCell::new(vec![Ok(())]);
        let write_parameters = tx_to_write.unbounded_send_params.clone();
        let package = ExpiredCoresPackage::new(
            IpAddr::from_str("1.2.3.4").unwrap(),
            Some(Wallet::new("consuming")),
            make_meaningless_route(),
            PlainData::new(&(serde_cbor::ser::to_vec(&client_request_payload).unwrap())[..]),
        );
        let package_a = package.clone();
        let (hopper, _, _) = make_recorder();
        let (accountant, accountant_awaiter, accountant_recording_arc) = make_recorder();

        thread::spawn(move || {
            let system = System::new("test");

            let peer_actors =
                make_peer_actors_from(None, None, Some(hopper), None, None, Some(accountant), None);
            let subject = StreamHandlerPoolReal::new(
                Box::new(ResolverWrapperMock::new()),
                cryptde(),
                peer_actors.hopper.from_hopper_client.clone(),
                peer_actors.accountant.report_exit_service_provided.clone(),
            );
            subject
                .inner
                .lock()
                .unwrap()
                .stream_writer_channels
                .insert(stream_key, tx_to_write);

            let test_actor = TestActor { subject };
            let addr: Addr<Syn, TestActor> = test_actor.start();
            let test_trigger: Recipient<Syn, TriggerSubject> =
                addr.clone().recipient::<TriggerSubject>();
            test_trigger.try_send(TriggerSubject { package }).is_ok();

            system.run();
        });

        await_messages(1, &write_parameters);

        assert_eq!(
            write_parameters.lock().unwrap().remove(0),
            client_request_payload.sequenced_packet
        );

        accountant_awaiter.await_message_count(1);
        let accountant_recording = accountant_recording_arc.lock().unwrap();
        let message = accountant_recording.get_record::<ReportExitServiceProvidedMessage>(0);
        assert_eq!(
            message,
            &ReportExitServiceProvidedMessage {
                consuming_wallet: package_a.consuming_wallet.clone().unwrap(),
                payload_size: client_request_payload.sequenced_packet.data.len() as u32,
                service_rate: TEMPORARY_PER_EXIT_RATE,
                byte_rate: TEMPORARY_PER_EXIT_BYTE_RATE,
            }
        );
    }

    #[test]
    fn when_no_consumer_wallet_is_specified_the_accountant_is_not_notified() {
        init_test_logging();
        let stream_key = make_meaningless_stream_key();
        let client_request_payload = ClientRequestPayload {
            stream_key: stream_key.clone(),
            sequenced_packet: SequencedPacket {
                data: b"These are the times".to_vec(),
                sequence_number: 0,
                last_data: false,
            },
            target_hostname: None,
            target_port: 80,
            protocol: ProxyProtocol::HTTP,
            originator_public_key: PublicKey::new(&b"men's souls"[..]),
        };
        let mut tx_to_write = Box::new(SenderWrapperMock::new(
            SocketAddr::from_str("1.2.3.4:5678").unwrap(),
        ));
        tx_to_write.unbounded_send_results = RefCell::new(vec![Ok(())]);
        let package = ExpiredCoresPackage::new(
            IpAddr::from_str("1.2.3.4").unwrap(),
            None,
            make_meaningless_route(),
            PlainData::new(&(serde_cbor::ser::to_vec(&client_request_payload).unwrap())[..]),
        );
        let (hopper, _, _) = make_recorder();
        let (accountant, _, accountant_recording_arc) = make_recorder();
        thread::spawn(move || {
            let system = System::new("test");

            let peer_actors =
                make_peer_actors_from(None, None, Some(hopper), None, None, Some(accountant), None);
            let subject = StreamHandlerPoolReal::new(
                Box::new(ResolverWrapperMock::new()),
                cryptde(),
                peer_actors.hopper.from_hopper_client.clone(),
                peer_actors.accountant.report_exit_service_provided.clone(),
            );
            subject
                .inner
                .lock()
                .unwrap()
                .stream_writer_channels
                .insert(stream_key, tx_to_write);

            let test_actor = TestActor { subject };
            let addr: Addr<Syn, TestActor> = test_actor.start();
            let test_trigger: Recipient<Syn, TriggerSubject> =
                addr.clone().recipient::<TriggerSubject>();
            test_trigger.try_send(TriggerSubject { package }).is_ok();
            system.run();
        });
        TestLogHandler::new().await_log_containing(
            format!(
                "DEBUG: Proxy Client: Sent {}-byte request without consuming wallet for free",
                client_request_payload.sequenced_packet.data.len()
            )
            .as_str(),
            1000,
        );

        let accountant_recording = accountant_recording_arc.lock().unwrap();
        assert_eq!(accountant_recording.len(), 0);
    }

    #[test]
    fn write_failure_for_nonexistent_stream_generates_termination_message() {
        init_test_logging();
        let (hopper, hopper_awaiter, hopper_recording_arc) = make_recorder();
        let (accountant, _, _) = make_recorder();
        let originator_key = PublicKey::new(&b"men's souls"[..]);
        let originator_cryptde = CryptDENull::from(&originator_key);
        thread::spawn(move || {
            let client_request_payload = ClientRequestPayload {
                stream_key: make_meaningless_stream_key(),
                sequenced_packet: SequencedPacket {
                    data: b"These are the times".to_vec(),
                    sequence_number: 0,
                    last_data: false,
                },
                target_hostname: Some(String::from("that.try")),
                target_port: 80,
                protocol: ProxyProtocol::HTTP,
                originator_public_key: originator_key,
            };
            let package = ExpiredCoresPackage::new(
                IpAddr::from_str("1.2.3.4").unwrap(),
                Some(Wallet::new("consuming")),
                make_meaningless_route(),
                PlainData::new(&(serde_cbor::ser::to_vec(&client_request_payload).unwrap())[..]),
            );
            let system = System::new("test");
            let peer_actors =
                make_peer_actors_from(None, None, Some(hopper), None, None, None, Some(accountant));
            let resolver = ResolverWrapperMock::new()
                .lookup_ip_success(vec![IpAddr::from_str("2.3.4.5").unwrap()]);
            let mut tx_to_write: SenderWrapperMock<SequencedPacket> =
                SenderWrapperMock::new(SocketAddr::from_str("2.3.4.5:80").unwrap());
            tx_to_write.unbounded_send_results = RefCell::new(vec![make_send_error(
                client_request_payload.sequenced_packet.clone(),
            )]);

            let subject = StreamHandlerPoolReal::new(
                Box::new(resolver),
                cryptde(),
                peer_actors.hopper.from_hopper_client.clone(),
                peer_actors.accountant.report_exit_service_provided.clone(),
            );
            subject
                .inner
                .lock()
                .unwrap()
                .stream_writer_channels
                .insert(client_request_payload.stream_key, Box::new(tx_to_write));

            let test_actor = TestActor { subject };
            let addr: Addr<Syn, TestActor> = test_actor.start();
            let test_trigger: Recipient<Syn, TriggerSubject> =
                addr.clone().recipient::<TriggerSubject>();
            test_trigger.try_send(TriggerSubject { package }).is_ok();

            system.run();
        });
        hopper_awaiter.await_message_count(1);
        let hopper_recording = hopper_recording_arc.lock().unwrap();
        let package = hopper_recording.get_record::<IncipientCoresPackage>(0);
        let decrypted_payload = originator_cryptde.decode(&package.payload).unwrap();
        let payload =
            serde_cbor::de::from_slice::<ClientResponsePayload>(decrypted_payload.as_slice())
                .unwrap();
        assert_eq!(payload.sequenced_packet.last_data, true);
    }

    #[test]
    fn missing_hostname_for_nonexistent_stream_generates_log_and_termination_message() {
        init_test_logging();
        let (hopper, hopper_awaiter, hopper_recording_arc) = make_recorder();
        let (accountant, _, _) = make_recorder();
        let originator_key = PublicKey::new(&b"men's souls"[..]);
        let originator_cryptde = CryptDENull::from(&originator_key);
        thread::spawn(move || {
            let system = System::new("test");
            let peer_actors =
                make_peer_actors_from(None, None, Some(hopper), None, None, Some(accountant), None);
            let client_request_payload = ClientRequestPayload {
                stream_key: make_meaningless_stream_key(),
                sequenced_packet: SequencedPacket {
                    data: b"These are the times".to_vec(),
                    sequence_number: 0,
                    last_data: false,
                },
                target_hostname: None,
                target_port: 80,
                protocol: ProxyProtocol::HTTP,
                originator_public_key: originator_key,
            };
            let package = ExpiredCoresPackage::new(
                IpAddr::from_str("1.2.3.4").unwrap(),
                Some(Wallet::new("consuming")),
                make_meaningless_route(),
                PlainData::new(&(serde_cbor::ser::to_vec(&client_request_payload).unwrap())[..]),
            );
            let resolver = ResolverWrapperMock::new()
                .lookup_ip_failure(ResolveError::from(ResolveErrorKind::Io));
            let subject = StreamHandlerPoolReal::new(
                Box::new(resolver),
                cryptde(),
                peer_actors.hopper.from_hopper_client.clone(),
                peer_actors.accountant.report_exit_service_provided.clone(),
            );

            let test_actor = TestActor { subject };
            let addr: Addr<Syn, TestActor> = test_actor.start();
            let test_trigger: Recipient<Syn, TriggerSubject> =
                addr.clone().recipient::<TriggerSubject>();
            test_trigger.try_send(TriggerSubject { package }).is_ok();

            system.run();
        });

        hopper_awaiter.await_message_count(1);
        let hopper_recording = hopper_recording_arc.lock().unwrap();
        let package = hopper_recording.get_record::<IncipientCoresPackage>(0);
        let decrypted_payload = originator_cryptde.decode(&package.payload).unwrap();
        let payload =
            serde_cbor::de::from_slice::<ClientResponsePayload>(decrypted_payload.as_slice())
                .unwrap();
        assert_eq!(payload.sequenced_packet.last_data, true);
        TestLogHandler::new().exists_log_containing(
            format!(
                "ERROR: Proxy Client: Cannot open new stream with key {:?}: no hostname supplied",
                make_meaningless_stream_key()
            )
            .as_str(),
        );
    }

    #[test]
    fn nonexistent_connection_springs_into_being_and_is_persisted_to_handle_transaction() {
        let lookup_ip_parameters = Arc::new(Mutex::new(vec![]));
        let expected_lookup_ip_parameters = lookup_ip_parameters.clone();
        let write_parameters = Arc::new(Mutex::new(vec![]));
        let expected_write_parameters = write_parameters.clone();
        let (hopper, hopper_awaiter, hopper_recording_arc) = make_recorder();
        let (accountant, _, _) = make_recorder();
        thread::spawn(move || {
            let system = System::new("test");
            let peer_actors =
                make_peer_actors_from(None, None, Some(hopper), None, None, Some(accountant), None);
            let client_request_payload = ClientRequestPayload {
                stream_key: make_meaningless_stream_key(),
                sequenced_packet: SequencedPacket {
                    data: b"These are the times".to_vec(),
                    sequence_number: 0,
                    last_data: false,
                },
                target_hostname: Some(String::from("that.try")),
                target_port: 80,
                protocol: ProxyProtocol::HTTP,
                originator_public_key: PublicKey::new(&b"men's souls"[..]),
            };
            let package = ExpiredCoresPackage::new(
                IpAddr::from_str("1.2.3.4").unwrap(),
                Some(Wallet::new("consuming")),
                make_meaningless_route(),
                PlainData::new(&(serde_cbor::ser::to_vec(&client_request_payload).unwrap())[..]),
            );
            let resolver = ResolverWrapperMock::new()
                .lookup_ip_parameters(&lookup_ip_parameters)
                .lookup_ip_success(vec![
                    IpAddr::from_str("2.3.4.5").unwrap(),
                    IpAddr::from_str("3.4.5.6").unwrap(),
                ]);
            let peer_addr = SocketAddr::from_str("3.4.5.6:80").unwrap();
            let reader = ReadHalfWrapperMock {
                poll_read_results: vec![
                    (b"HTTP/1.1 200 OK\r\n\r\n".to_vec(), Ok(Async::Ready(19))),
                    (vec![], Err(Error::from(ErrorKind::ConnectionAborted))),
                ],
            };
            let writer = WriteHalfWrapperMock {
                poll_write_params: write_parameters,
                poll_write_results: vec![Ok(Async::Ready(123))],
                shutdown_results: Arc::new(Mutex::new(vec![])),
            };
            let mut subject = StreamHandlerPoolReal::new(
                Box::new(resolver),
                cryptde(),
                peer_actors.hopper.from_hopper_client.clone(),
                peer_actors.accountant.report_exit_service_provided.clone(),
            );
            let (stream_killer_tx, stream_killer_rx) = mpsc::channel();
            subject.stream_killer_rx = stream_killer_rx;
            let (stream_adder_tx, _stream_adder_rx) = mpsc::channel();
            {
                let mut inner = subject.inner.lock().unwrap();
                let cryptde = cryptde();
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
                    hopper_sub: inner.hopper_sub.clone(),
                    accountant_sub: inner.accountant_sub.clone(),
                    logger: inner.logger.clone(),
                    channel_factory: Box::new(FuturesChannelFactoryReal {}),
                };

                inner.establisher_factory = Box::new(StreamEstablisherFactoryMock {
                    make_results: RefCell::new(vec![establisher]),
                });
            }

            let test_actor = TestActor { subject };
            let addr: Addr<Syn, TestActor> = test_actor.start();
            let test_trigger: Recipient<Syn, TriggerSubject> =
                addr.clone().recipient::<TriggerSubject>();
            test_trigger.try_send(TriggerSubject { package }).is_ok();

            system.run();
        });

        hopper_awaiter.await_message_count(1);
        assert_eq!(
            expected_lookup_ip_parameters.lock().unwrap().deref(),
            &vec!(Some(String::from("that.try.")))
        );
        assert_eq!(
            expected_write_parameters.lock().unwrap().remove(0),
            b"These are the times".to_vec()
        );
        let hopper_recording = hopper_recording_arc.lock().unwrap();
        let record = hopper_recording.get_record::<IncipientCoresPackage>(0);
        assert_eq!(
            *record,
            IncipientCoresPackage::new(
                cryptde(),
                make_meaningless_route(),
                ClientResponsePayload {
                    stream_key: make_meaningless_stream_key(),
                    sequenced_packet: SequencedPacket {
                        data: b"HTTP/1.1 200 OK\r\n\r\n".to_vec(),
                        sequence_number: 0,
                        last_data: false
                    },
                },
                &PublicKey::new(&b"men's souls"[..]),
            )
            .unwrap()
        );
    }

    #[test]
    fn failing_to_make_a_connection_sends_an_error_response() {
        let stream_key = make_meaningless_stream_key();
        let lookup_ip_parameters = Arc::new(Mutex::new(vec![]));
        let (hopper, hopper_awaiter, hopper_recording_arc) = make_recorder();
        let (accountant, _, _) = make_recorder();
        let originator_key = PublicKey::new(&b"men's souls"[..]);
        let originator_cryptde = CryptDENull::from(&originator_key);
        thread::spawn(move || {
            let system = System::new("test");
            let peer_actors =
                make_peer_actors_from(None, None, Some(hopper), None, None, Some(accountant), None);
            let client_request_payload = ClientRequestPayload {
                stream_key,
                sequenced_packet: SequencedPacket {
                    data: b"These are the times".to_vec(),
                    sequence_number: 0,
                    last_data: false,
                },
                target_hostname: Some(String::from("that.try")),
                target_port: 80,
                protocol: ProxyProtocol::HTTP,
                originator_public_key: originator_key,
            };
            let package = ExpiredCoresPackage::new(
                IpAddr::from_str("1.2.3.4").unwrap(),
                Some(Wallet::new("consuming")),
                make_meaningless_route(),
                PlainData::new(&(serde_cbor::ser::to_vec(&client_request_payload).unwrap())[..]),
            );
            let resolver = ResolverWrapperMock::new()
                .lookup_ip_parameters(&lookup_ip_parameters)
                .lookup_ip_success(vec![
                    IpAddr::from_str("2.3.4.5").unwrap(),
                    IpAddr::from_str("3.4.5.6").unwrap(),
                ]);
            let hopper_sub = peer_actors.hopper.from_hopper_client.clone();
            let accountant_sub = peer_actors.accountant.report_exit_service_provided.clone();
            let mut subject = StreamHandlerPoolReal::new(
                Box::new(resolver),
                cryptde(),
                hopper_sub.clone(),
                accountant_sub.clone(),
            );
            let (stream_killer_tx, stream_killer_rx) = mpsc::channel();
            subject.stream_killer_rx = stream_killer_rx;
            let (stream_adder_tx, _stream_adder_rx) = mpsc::channel();
            let cryptde = cryptde();
            let establisher = StreamEstablisher {
                cryptde,
                stream_adder_tx,
                stream_killer_tx,
                stream_connector: Box::new(
                    StreamConnectorMock::new()
                        .connect_pair_result(Err(Error::from(ErrorKind::Other))),
                ),
                hopper_sub,
                accountant_sub,
                logger: subject.inner.lock().unwrap().logger.clone(),
                channel_factory: Box::new(FuturesChannelFactoryReal {}),
            };

            subject.inner.lock().unwrap().establisher_factory =
                Box::new(StreamEstablisherFactoryMock {
                    make_results: RefCell::new(vec![establisher]),
                });

            let test_actor = TestActor { subject };
            let addr: Addr<Syn, TestActor> = test_actor.start();
            let test_trigger: Recipient<Syn, TriggerSubject> =
                addr.clone().recipient::<TriggerSubject>();
            test_trigger.try_send(TriggerSubject { package }).is_ok();

            system.run();
        });

        hopper_awaiter.await_message_count(1);
        let hopper_recording = hopper_recording_arc.lock().unwrap();
        let record = hopper_recording.get_record::<IncipientCoresPackage>(0);
        let decrypted_payload = originator_cryptde.decode(&record.payload).unwrap();
        let client_response_payload =
            serde_cbor::de::from_slice::<ClientResponsePayload>(decrypted_payload.as_slice())
                .unwrap();
        assert_eq!(
            client_response_payload,
            ClientResponsePayload::make_terminating_payload(stream_key)
        );
    }

    #[test]
    fn trying_to_write_to_disconnected_stream_writer_sends_an_error_response() {
        let stream_key = make_meaningless_stream_key();
        let lookup_ip_parameters = Arc::new(Mutex::new(vec![]));
        let write_parameters = Arc::new(Mutex::new(vec![]));
        let (hopper, hopper_awaiter, hopper_recording_arc) = make_recorder();
        let (accountant, _, _) = make_recorder();
        let originator_key = PublicKey::new(&b"men's souls"[..]);
        let originator_cryptde = CryptDENull::from(&originator_key);
        thread::spawn(move || {
            let system = System::new("test");
            let peer_actors =
                make_peer_actors_from(None, None, Some(hopper), None, None, Some(accountant), None);
            let sequenced_packet = SequencedPacket {
                data: b"These are the times".to_vec(),
                sequence_number: 0,
                last_data: false,
            };

            let client_request_payload = ClientRequestPayload {
                stream_key,
                sequenced_packet: sequenced_packet.clone(),
                target_hostname: Some(String::from("that.try")),
                target_port: 80,
                protocol: ProxyProtocol::HTTP,
                originator_public_key: originator_key,
            };
            let package = ExpiredCoresPackage::new(
                IpAddr::from_str("1.2.3.4").unwrap(),
                Some(Wallet::new("consuming")),
                make_meaningless_route(),
                PlainData::new(&(serde_cbor::ser::to_vec(&client_request_payload).unwrap())[..]),
            );
            let resolver = ResolverWrapperMock::new()
                .lookup_ip_parameters(&lookup_ip_parameters)
                .lookup_ip_success(vec![
                    IpAddr::from_str("2.3.4.5").unwrap(),
                    IpAddr::from_str("3.4.5.6").unwrap(),
                ]);
            let peer_addr = SocketAddr::from_str("3.4.5.6:80").unwrap();
            let reader = ReadHalfWrapperMock {
                poll_read_results: vec![
                    (vec![], Ok(Async::NotReady)),
                    (vec![], Err(Error::from(ErrorKind::ConnectionAborted))),
                ],
            };
            let writer = WriteHalfWrapperMock {
                poll_write_params: write_parameters,
                poll_write_results: vec![Ok(Async::NotReady)],
                shutdown_results: Arc::new(Mutex::new(vec![])),
            };
            let mut subject = StreamHandlerPoolReal::new(
                Box::new(resolver),
                cryptde(),
                peer_actors.hopper.from_hopper_client.clone(),
                peer_actors.accountant.report_exit_service_provided.clone(),
            );
            let disconnected_sender = Box::new(SenderWrapperMock {
                peer_addr,
                unbounded_send_params: Arc::new(Mutex::new(vec![])),
                unbounded_send_results: RefCell::new(vec![make_send_error(sequenced_packet)]),
            });
            let (stream_killer_tx, stream_killer_rx) = mpsc::channel();
            subject.stream_killer_rx = stream_killer_rx;
            let (stream_adder_tx, _stream_adder_rx) = mpsc::channel();
            {
                let mut inner = subject.inner.lock().unwrap();
                let cryptde = cryptde();
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
                    hopper_sub: inner.hopper_sub.clone(),
                    accountant_sub: inner.accountant_sub.clone(),
                    logger: inner.logger.clone(),
                    channel_factory: Box::new(FuturesChannelFactoryMock {
                        results: vec![(
                            disconnected_sender,
                            Box::new(ReceiverWrapperMock {
                                poll_results: vec![],
                            }),
                        )],
                    }),
                };

                inner.establisher_factory = Box::new(StreamEstablisherFactoryMock {
                    make_results: RefCell::new(vec![establisher]),
                });
            }

            let test_actor = TestActor { subject };
            let addr: Addr<Syn, TestActor> = test_actor.start();
            let test_trigger: Recipient<Syn, TriggerSubject> =
                addr.clone().recipient::<TriggerSubject>();
            test_trigger.try_send(TriggerSubject { package }).is_ok();
            system.run();
        });

        hopper_awaiter.await_message_count(1);
        let hopper_recording = hopper_recording_arc.lock().unwrap();
        let record = hopper_recording.get_record::<IncipientCoresPackage>(0);
        let decrypted_payload = originator_cryptde.decode(&record.payload).unwrap();
        let client_response_payload =
            serde_cbor::de::from_slice::<ClientResponsePayload>(decrypted_payload.as_slice())
                .unwrap();
        assert_eq!(
            client_response_payload,
            ClientResponsePayload::make_terminating_payload(stream_key)
        );
    }

    #[test]
    fn bad_dns_lookup_produces_log_and_sends_error_response() {
        init_test_logging();
        let stream_key = make_meaningless_stream_key();
        let (hopper, hopper_awaiter, hopper_recording_arc) = make_recorder();
        let (accountant, _, _) = make_recorder();
        let originator_key = PublicKey::new(&b"men's souls"[..]);
        let originator_cryptde = CryptDENull::from(&originator_key);
        thread::spawn(move || {
            let client_request_payload = ClientRequestPayload {
                stream_key,
                sequenced_packet: SequencedPacket {
                    data: b"These are the times".to_vec(),
                    sequence_number: 0,
                    last_data: true,
                },
                target_hostname: Some(String::from("that.try")),
                target_port: 80,
                protocol: ProxyProtocol::HTTP,
                originator_public_key: originator_key,
            };
            let package = ExpiredCoresPackage::new(
                IpAddr::from_str("1.2.3.4").unwrap(),
                Some(Wallet::new("consuming")),
                make_meaningless_route(),
                PlainData::new(&(serde_cbor::ser::to_vec(&client_request_payload).unwrap())[..]),
            );
            let system = System::new("test");
            let peer_actors =
                make_peer_actors_from(None, None, Some(hopper), None, None, Some(accountant), None);
            let mut lookup_ip_parameters = Arc::new(Mutex::new(vec![]));
            let resolver = ResolverWrapperMock::new()
                .lookup_ip_parameters(&mut lookup_ip_parameters)
                .lookup_ip_failure(ResolveError::from(ResolveErrorKind::Io));
            let subject = StreamHandlerPoolReal::new(
                Box::new(resolver),
                cryptde(),
                peer_actors.hopper.from_hopper_client.clone(),
                peer_actors.accountant.report_exit_service_provided.clone(),
            );
            let test_actor = TestActor { subject };
            let addr: Addr<Syn, TestActor> = test_actor.start();
            let test_trigger: Recipient<Syn, TriggerSubject> =
                addr.clone().recipient::<TriggerSubject>();
            test_trigger.try_send(TriggerSubject { package }).is_ok();

            system.run();
        });
        TestLogHandler::new().await_log_containing(
            "ERROR: Proxy Client: Could not find IP address for host that.try: io error",
            1000,
        );
        hopper_awaiter.await_message_count(1);
        let recording = hopper_recording_arc.lock().unwrap();
        let record = recording.get_record::<IncipientCoresPackage>(0);
        let decrypted_payload = originator_cryptde.decode(&record.payload).unwrap();
        let client_response_payload =
            serde_cbor::de::from_slice::<ClientResponsePayload>(decrypted_payload.as_slice())
                .unwrap();
        assert_eq!(
            client_response_payload,
            ClientResponsePayload::make_terminating_payload(stream_key)
        );
    }

    #[test]
    #[ignore] // TODO: Play SC-696 card to re-write this test -- it is flaky
    fn after_writing_last_data_the_stream_should_close() {
        init_test_logging();
        let stream_key = make_meaningless_stream_key();
        let (hopper, _, _) = make_recorder();
        let (accountant, _, _) = make_recorder();
        let (tx_to_write, mut rx_to_write) = unbounded();
        let sequenced_packet = SequencedPacket {
            data: b"These are the times".to_vec(),
            sequence_number: 0,
            last_data: true,
        };
        let client_request_payload = ClientRequestPayload {
            stream_key: stream_key.clone(),
            sequenced_packet: sequenced_packet.clone(),
            target_hostname: Some(String::from("that.try")),
            target_port: 80,
            protocol: ProxyProtocol::HTTP,
            originator_public_key: PublicKey::new(&b"men's souls"[..]),
        };
        let package = ExpiredCoresPackage::new(
            IpAddr::from_str("1.2.3.4").unwrap(),
            Some(Wallet::new("consuming")),
            make_meaningless_route(),
            PlainData::new(&(serde_cbor::ser::to_vec(&client_request_payload).unwrap())[..]),
        );
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let system = System::new("test");
            let peer_actors =
                make_peer_actors_from(None, None, Some(hopper), None, None, Some(accountant), None);
            let resolver = ResolverWrapperMock::new();
            let subject = StreamHandlerPoolReal::new(
                Box::new(resolver),
                cryptde(),
                peer_actors.hopper.from_hopper_client.clone(),
                peer_actors.accountant.report_exit_service_provided.clone(),
            );
            subject.inner.lock().unwrap().stream_writer_channels.insert(
                stream_key,
                Box::new(SenderWrapperReal::new(
                    SocketAddr::from_str("1.2.3.4:5678").unwrap(),
                    tx_to_write,
                )),
            );

            let test_actor = TestActor { subject };
            let addr: Addr<Syn, TestActor> = test_actor.start();
            let test_trigger: Recipient<Syn, TriggerSubject> =
                addr.clone().recipient::<TriggerSubject>();
            test_trigger.try_send(TriggerSubject { package }).is_ok();

            system.run();
        });

        let test_future = lazy(move || {
            let _ = tx.send(rx_to_write.poll());
            let _ = tx.send(rx_to_write.poll());
            Ok(())
        });

        thread::spawn(move || {
            thread::sleep(Duration::from_millis(100));
            tokio::run(test_future);
        });

        let rx_to_write_params = rx.recv().unwrap();
        assert_eq!(rx_to_write_params, Ok(Async::Ready(Some(sequenced_packet))));

        let tlh = TestLogHandler::new();
        tlh.exists_log_containing("Removing stream writer for 1.2.3.4:5678");

        let rx_to_write_result = rx.recv().unwrap();
        assert_eq!(rx_to_write_result, Ok(Async::Ready(None))); // Ok(Async::Ready(None)) indicates that all TXs to the channel are gone
    }

    #[test]
    fn error_from_tx_to_writer_removes_stream() {
        init_test_logging();
        let stream_key = make_meaningless_stream_key();
        let (hopper, _, _) = make_recorder();
        let (accountant, _, _) = make_recorder();
        let sequenced_packet = SequencedPacket {
            data: b"These are the times".to_vec(),
            sequence_number: 0,
            last_data: true,
        };
        let client_request_payload = ClientRequestPayload {
            stream_key: stream_key.clone(),
            sequenced_packet: sequenced_packet.clone(),
            target_hostname: Some(String::from("that.try")),
            target_port: 80,
            protocol: ProxyProtocol::HTTP,
            originator_public_key: PublicKey::new(&b"men's souls"[..]),
        };
        let package = ExpiredCoresPackage::new(
            IpAddr::from_str("1.2.3.4").unwrap(),
            Some(Wallet::new("consuming")),
            make_meaningless_route(),
            PlainData::new(&(serde_cbor::ser::to_vec(&client_request_payload).unwrap())[..]),
        );
        let mut sender_wrapper =
            SenderWrapperMock::new(SocketAddr::from_str("1.2.3.4:5678").unwrap());
        sender_wrapper.unbounded_send_results =
            RefCell::new(vec![make_send_error(sequenced_packet.clone())]);
        let send_params = sender_wrapper.unbounded_send_params.clone();
        thread::spawn(move || {
            let system = System::new("test");
            let peer_actors =
                make_peer_actors_from(None, None, Some(hopper), None, None, Some(accountant), None);
            let resolver = ResolverWrapperMock::new();

            let subject = StreamHandlerPoolReal::new(
                Box::new(resolver),
                cryptde(),
                peer_actors.hopper.from_hopper_client.clone(),
                peer_actors.accountant.report_exit_service_provided.clone(),
            );
            subject
                .inner
                .lock()
                .unwrap()
                .stream_writer_channels
                .insert(stream_key, Box::new(sender_wrapper));

            let test_actor = TestActor { subject };
            let addr: Addr<Syn, TestActor> = test_actor.start();
            let test_trigger: Recipient<Syn, TriggerSubject> =
                addr.clone().recipient::<TriggerSubject>();
            test_trigger.try_send(TriggerSubject { package }).is_ok();

            system.run();
        });

        await_messages(1, &send_params);
        assert_eq!(*send_params.lock().unwrap(), vec!(sequenced_packet));

        let tlh = TestLogHandler::new();
        tlh.exists_log_containing("Removing stream writer for 1.2.3.4:5678");
    }

    #[test]
    fn process_package_does_not_create_new_connection_for_last_data_message_with_no_data_and_sends_no_response(
    ) {
        init_test_logging();
        let (hopper, _, hopper_recording_arc) = make_recorder();
        let (accountant, _, _) = make_recorder();
        thread::spawn(move || {
            let system = System::new("test");
            let peer_actors =
                make_peer_actors_from(None, None, Some(hopper), None, None, Some(accountant), None);
            let client_request_payload = ClientRequestPayload {
                stream_key: make_meaningless_stream_key(),
                sequenced_packet: SequencedPacket {
                    data: vec![],
                    sequence_number: 0,
                    last_data: true,
                },
                target_hostname: None,
                target_port: 80,
                protocol: ProxyProtocol::HTTP,
                originator_public_key: PublicKey::new(&b"men's souls"[..]),
            };
            let package = ExpiredCoresPackage::new(
                IpAddr::from_str("1.2.3.4").unwrap(),
                Some(Wallet::new("consuming")),
                make_meaningless_route(),
                PlainData::new(&(serde_cbor::ser::to_vec(&client_request_payload).unwrap())[..]),
            );
            let resolver = ResolverWrapperMock::new();
            let subject = StreamHandlerPoolReal::new(
                Box::new(resolver),
                cryptde(),
                peer_actors.hopper.from_hopper_client.clone(),
                peer_actors.accountant.report_exit_service_provided.clone(),
            );

            subject.inner.lock().unwrap().establisher_factory =
                Box::new(StreamEstablisherFactoryMock {
                    make_results: RefCell::new(vec![]),
                });

            let test_actor = TestActor { subject };
            let addr: Addr<Syn, TestActor> = test_actor.start();
            let test_trigger: Recipient<Syn, TriggerSubject> =
                addr.clone().recipient::<TriggerSubject>();
            test_trigger.try_send(TriggerSubject { package }).is_ok();

            system.run();
        });

        let tlh = TestLogHandler::new();
        tlh.await_log_containing(
            &format!(
                "Empty last_data message received for nonexistent stream {:?} - ignoring",
                make_meaningless_stream_key()
            )[..],
            500,
        );

        let hopper_recording = hopper_recording_arc.lock().unwrap();
        assert_eq!(hopper_recording.len(), 0);
    }
}
