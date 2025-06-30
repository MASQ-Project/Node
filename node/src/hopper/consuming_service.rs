// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use super::live_cores_package::LiveCoresPackage;
use crate::sub_lib::cryptde::CryptData;
use crate::sub_lib::cryptde::{encodex, CryptDE};
use crate::sub_lib::dispatcher::{Endpoint, InboundClientData};
use crate::sub_lib::hopper::{IncipientCoresPackage, NoLookupIncipientCoresPackage};
use crate::sub_lib::stream_handler_pool::TransmitDataMsg;
use actix::Recipient;
use masq_lib::logger::Logger;
use std::borrow::Borrow;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::SystemTime;

pub struct ConsumingService {
    cryptde: Box<dyn CryptDE>,
    to_dispatcher: Recipient<TransmitDataMsg>,
    to_hopper: Recipient<InboundClientData>,
    logger: Logger,
}

impl ConsumingService {
    pub fn new(
        cryptde: Box<dyn CryptDE>,
        to_dispatcher: Recipient<TransmitDataMsg>,
        to_hopper: Recipient<InboundClientData>,
    ) -> Self {
        Self {
            cryptde,
            to_dispatcher,
            to_hopper,
            logger: Logger::new("ConsumingService"),
        }
    }

    pub fn consume_no_lookup(&self, incipient_cores_package: NoLookupIncipientCoresPackage) {
        debug!(
            self.logger,
            "Instructed to send NoLookupIncipientCoresPackage with {}-byte payload",
            incipient_cores_package.payload.len()
        );
        let target_key = incipient_cores_package.public_key.clone();
        let target_node_addr = incipient_cores_package.node_addr.clone();
        match LiveCoresPackage::from_no_lookup_incipient(incipient_cores_package, self.cryptde.as_ref()) {
            Ok((live_package, _)) => {
                let encrypted_package = match encodex(self.cryptde.as_ref(), &target_key, &live_package) {
                    Ok(p) => p,
                    Err(e) => {
                        error!(
                            self.logger,
                            "Could not accept CORES package for transmission: {:?}", e
                        );
                        return;
                    }
                };
                // This port should eventually be chosen by the Traffic Analyzer somehow.
                let socket_addrs: Vec<SocketAddr> = target_node_addr.into();
                self.launch_lcp(encrypted_package, Endpoint::Socket(socket_addrs[0]));
            }
            Err(e) => {
                error!(
                    self.logger,
                    "Could not accept CORES package for transmission: {}", e
                );
            }
        };
    }

    pub fn consume(&self, incipient_cores_package: IncipientCoresPackage) {
        debug!(
            self.logger,
            "Instructed to send IncipientCoresPackage with {}-byte payload",
            incipient_cores_package.payload.len()
        );
        match LiveCoresPackage::from_incipient(incipient_cores_package, self.cryptde.borrow()) {
            Ok((live_package, next_hop)) => {
                let encrypted_package =
                    match encodex(self.cryptde.as_ref(), &next_hop.public_key, &live_package) {
                        Ok(p) => p,
                        Err(e) => {
                            error!(self.logger, "Couldn't encode package: {:?}", e);
                            return;
                        }
                    };
                if &next_hop.public_key == self.cryptde.public_key() {
                    self.zero_hop(encrypted_package);
                } else {
                    self.launch_lcp(encrypted_package, Endpoint::Key(next_hop.public_key));
                }
            }
            Err(e) => error!(self.logger, "{}", e),
        };
    }

    fn zero_hop(&self, encrypted_package: CryptData) {
        let ibcd = InboundClientData {
            timestamp: SystemTime::now(),
            client_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0),
            reception_port: None,
            last_data: false,
            is_clandestine: true,
            sequence_number: None,
            data: encrypted_package.into(),
        };
        debug!(
            self.logger,
            "Sending zero-hop InboundClientData with {}-byte payload back to Hopper",
            ibcd.data.len()
        );
        self.to_hopper.try_send(ibcd).expect("Hopper is dead");
    }

    fn launch_lcp(&self, encrypted_package: CryptData, next_stop: Endpoint) {
        let transmit_msg = TransmitDataMsg {
            endpoint: next_stop,
            last_data: false, // Hopper-to-Hopper clandestine streams are never remotely killed
            data: encrypted_package.into(),
            sequence_number: None,
        };

        debug!(
            self.logger,
            "Sending TransmitDataMsg with {}-byte payload to Dispatcher",
            transmit_msg.data.len()
        );
        self.to_dispatcher
            .try_send(transmit_msg)
            .expect("Dispatcher is dead");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node_test_utils::check_timestamp;
    use crate::sub_lib::cryptde::PublicKey;
    use crate::sub_lib::dispatcher::{Component, InboundClientData};
    use crate::sub_lib::node_addr::NodeAddr;
    use crate::sub_lib::route::Route;
    use crate::sub_lib::route::RouteSegment;
    use crate::test_utils::recorder::make_recorder;
    use crate::test_utils::recorder::peer_actors_builder;
    use crate::test_utils::{make_meaningless_message_type, make_paying_wallet};
    use actix::System;
    use masq_lib::test_utils::logging::init_test_logging;
    use masq_lib::test_utils::logging::TestLogHandler;
    use masq_lib::test_utils::utils::TEST_DEFAULT_CHAIN;
    use std::net::{IpAddr, Ipv4Addr};
    use std::str::FromStr;
    use std::time::SystemTime;
    use lazy_static::lazy_static;
    use crate::bootstrapper::CryptDEPair;

    lazy_static! {
        static ref CRYPTDE_PAIR: CryptDEPair = CryptDEPair::null();
    }

    #[test]
    fn converts_no_lookup_incipient_message_to_live_and_sends_to_dispatcher() {
        let (dispatcher, _, dispatcher_recording_arc) = make_recorder();
        let target_key = PublicKey::new(&[1, 2]);
        let target_node_addr = NodeAddr::new(&IpAddr::from_str("1.2.1.2").unwrap(), &[1212, 2121]);
        let package = NoLookupIncipientCoresPackage::new(
            CRYPTDE_PAIR.main.as_ref(),
            &target_key,
            &target_node_addr,
            make_meaningless_message_type(),
        )
        .unwrap();
        let system = System::new("");
        let peer_actors = peer_actors_builder().dispatcher(dispatcher).build();
        let subject = ConsumingService::new(
            CRYPTDE_PAIR.main.dup(),
            peer_actors.dispatcher.from_dispatcher_client,
            peer_actors.hopper.from_dispatcher,
        );

        subject.consume_no_lookup(package.clone());

        System::current().stop();
        system.run();
        let dispatcher_recording = dispatcher_recording_arc.lock().unwrap();
        let transmit_data_msg = dispatcher_recording.get_record::<TransmitDataMsg>(0);
        let (lcp, _) = LiveCoresPackage::from_no_lookup_incipient(package, CRYPTDE_PAIR.main.as_ref()).unwrap();
        assert_eq!(
            &TransmitDataMsg {
                endpoint: Endpoint::Socket(SocketAddr::from_str("1.2.1.2:1212").unwrap()),
                last_data: false,
                sequence_number: None,
                data: encodex(CRYPTDE_PAIR.main.as_ref(), &target_key, &lcp).unwrap().into(),
            },
            transmit_data_msg
        );
    }

    #[test]
    fn complains_when_consume_no_lookup_is_given_bad_parameters() {
        init_test_logging();
        let blank_key = PublicKey::new(b"");
        let target_node_addr = NodeAddr::new(&IpAddr::from_str("1.2.1.2").unwrap(), &[1212, 2121]);
        let package = NoLookupIncipientCoresPackage {
            public_key: blank_key.clone(),
            node_addr: target_node_addr.clone(),
            payload: CryptData::new(b""),
        };
        let system = System::new("");
        let peer_actors = peer_actors_builder().build();
        let subject = ConsumingService::new(
            CRYPTDE_PAIR.main.dup(),
            peer_actors.dispatcher.from_dispatcher_client,
            peer_actors.hopper.from_dispatcher,
        );

        subject.consume_no_lookup(package);

        System::current().stop();
        system.run();
        TestLogHandler::new ().exists_log_containing ("ERROR: ConsumingService: Could not accept CORES package for transmission: EncryptionError(EmptyKey)");
    }

    #[test]
    fn consume_converts_incipient_message_to_live_and_sends_to_dispatcher() {
        let cryptde = CRYPTDE_PAIR.main.as_ref();
        let paying_wallet = make_paying_wallet(b"wallet");
        let (dispatcher, _, dispatcher_recording_arc) = make_recorder();
        let destination_key = PublicKey::new(&[65, 65, 65]);
        let route = Route::one_way(
            RouteSegment::new(
                vec![cryptde.public_key(), &destination_key.clone()],
                Component::Neighborhood,
            ),
            cryptde,
            Some(paying_wallet),
            Some(TEST_DEFAULT_CHAIN.rec().contract),
        )
        .unwrap();
        let payload = make_meaningless_message_type();
        let incipient_cores_package =
            IncipientCoresPackage::new(cryptde, route.clone(), payload, &destination_key).unwrap();
        let system = System::new("converts_incipient_message_to_live_and_sends_to_dispatcher");
        let peer_actors = peer_actors_builder().dispatcher(dispatcher).build();
        let subject = ConsumingService::new(
            cryptde.dup(),
            peer_actors.dispatcher.from_dispatcher_client,
            peer_actors.hopper.from_dispatcher,
        );

        subject.consume(incipient_cores_package.clone());

        System::current().stop();
        system.run();
        let dispatcher_recording = dispatcher_recording_arc.lock().unwrap();
        let record = dispatcher_recording.get_record::<TransmitDataMsg>(0);
        let (expected_lcp, _) =
            LiveCoresPackage::from_incipient(incipient_cores_package, cryptde).unwrap();
        let expected_lcp_enc = encodex(cryptde, &destination_key, &expected_lcp).unwrap();
        assert_eq!(
            TransmitDataMsg {
                endpoint: Endpoint::Key(destination_key.clone()),
                last_data: false,
                sequence_number: None,
                data: expected_lcp_enc.into(),
            },
            *record,
        );
    }

    #[test]
    fn consume_sends_zero_hop_incipient_directly_to_hopper() {
        let cryptde = CRYPTDE_PAIR.main.as_ref();
        let paying_wallet = make_paying_wallet(b"wallet");
        let (hopper, _, hopper_recording_arc) = make_recorder();
        let destination_key = cryptde.public_key();
        let route = Route::one_way(
            RouteSegment::new(
                vec![cryptde.public_key(), &destination_key.clone()],
                Component::Neighborhood,
            ),
            cryptde,
            Some(paying_wallet),
            Some(TEST_DEFAULT_CHAIN.rec().contract),
        )
        .unwrap();
        let payload = make_meaningless_message_type();
        let incipient_cores_package =
            IncipientCoresPackage::new(cryptde, route.clone(), payload, &destination_key).unwrap();
        let system = System::new("consume_sends_zero_hop_incipient_directly_to_hopper");
        let peer_actors = peer_actors_builder().hopper(hopper).build();
        let subject = ConsumingService::new(
            cryptde.dup(),
            peer_actors.dispatcher.from_dispatcher_client,
            peer_actors.hopper.from_dispatcher,
        );
        let before = SystemTime::now();

        subject.consume(incipient_cores_package.clone());

        System::current().stop();
        system.run();
        let after = SystemTime::now();
        let hopper_recording = hopper_recording_arc.lock().unwrap();
        let record = hopper_recording.get_record::<InboundClientData>(0);
        check_timestamp(before, record.timestamp, after);
        let (expected_lcp, _) =
            LiveCoresPackage::from_incipient(incipient_cores_package, cryptde).unwrap();
        let expected_lcp_enc = encodex(cryptde, &destination_key, &expected_lcp).unwrap();
        assert_eq!(
            *record,
            InboundClientData {
                timestamp: record.timestamp,
                client_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0),
                reception_port: None,
                last_data: false,
                is_clandestine: true,
                sequence_number: None,
                data: expected_lcp_enc.into(),
            },
        );
    }

    #[test]
    fn consume_logs_error_when_given_bad_input_data() {
        init_test_logging();
        let _system = System::new("consume_logs_error_when_given_bad_input_data");
        let peer_actors = peer_actors_builder().build();
        let to_dispatcher = peer_actors.dispatcher.from_dispatcher_client;
        let to_hopper = peer_actors.hopper.from_dispatcher;

        let subject = ConsumingService::new(CRYPTDE_PAIR.main.dup(), to_dispatcher, to_hopper);

        subject.consume(
            IncipientCoresPackage::new(
                CRYPTDE_PAIR.main.as_ref(),
                Route { hops: vec![] },
                make_meaningless_message_type(),
                &PublicKey::new(&[1, 2]),
            )
            .unwrap(),
        );

        TestLogHandler::new().exists_log_containing(
            "ERROR: ConsumingService: Could not decrypt next hop: RoutingError(EmptyRoute)",
        );
    }
}
