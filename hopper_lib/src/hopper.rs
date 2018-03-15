// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use std::sync::Arc;
use std::sync::Mutex;
use std::borrow::Borrow;
use serde_cbor;
use sub_lib::dispatcher::Endpoint;
use sub_lib::dispatcher::DispatcherClient;
use sub_lib::dispatcher::TransmitterHandle;
use sub_lib::dispatcher::PeerClients;
use sub_lib::dispatcher::Component;
use sub_lib::hopper::Hopper;
use sub_lib::hopper::IncipientCoresPackage;
use sub_lib::hopper::ExpiredCoresPackage;
use sub_lib::neighborhood::Neighborhood;
use sub_lib::hop::Hop;
use sub_lib::route::Route;
use sub_lib::cryptde::CryptDE;
use sub_lib::cryptde::Key;
use sub_lib::cryptde::CryptData;
use sub_lib::cryptde::PlainData;
use sub_lib::actor_messages::ExpiredCoresPackageMessage;
use actix::Subscriber;


pub struct HopperReal {
    neighborhood: Option<Arc<Mutex<Neighborhood>>>,
    cryptde: Box<CryptDE>,
    to_proxy_server: Option<Box<Subscriber<ExpiredCoresPackageMessage> + Send>>,
    to_proxy_client: Option<Box<Subscriber<ExpiredCoresPackageMessage> + Send>>,
}

impl Hopper for HopperReal {
    fn transmit_cores_package (&self, package: IncipientCoresPackage) {
        // Skinny Release-2-only implementation
        if package.route.next_hop ().public_key.is_some () {
            // from Proxy Server
            let expired_package = ExpiredCoresPackage::new (
                Route::rel2_to_proxy_client (&self.cryptde.public_key (), self.cryptde.borrow ()).unwrap (),
                package.payload
            );
            self.to_proxy_client.as_ref ().unwrap ().send (ExpiredCoresPackageMessage { pkg: expired_package });
            ()
        }
        else {
            // from Proxy Client
            let expired_package = ExpiredCoresPackage::new (
                Route::rel2_to_proxy_server (&self.cryptde.public_key (), self.cryptde.borrow ()).unwrap (),
                package.payload
            );
            self.to_proxy_server.as_ref().expect("ProxyServer unbound").send( ExpiredCoresPackageMessage { pkg: expired_package });
            ()
        };
    }

    fn temporary_bind(&mut self, to_proxy_server: Box<Subscriber<ExpiredCoresPackageMessage> + Send>, to_proxy_client: Box<Subscriber<ExpiredCoresPackageMessage> + Send>) {
        self.to_proxy_server = Some(to_proxy_server);
        self.to_proxy_client = Some(to_proxy_client);
    }
}

impl DispatcherClient for HopperReal {
    fn bind(&mut self, _transmitter_handle: Box<TransmitterHandle>, clients: &PeerClients) {
        self.neighborhood = Some (clients.neighborhood.clone ());
    }

    fn receive(&mut self, _source: Endpoint, data: PlainData) {
        let live_package = match serde_cbor::de::from_slice::<LiveCoresPackage> (&data.data[..]) {
            Ok (live_package) => live_package,
            Err (_) => unimplemented! ()
        };
        let next_hop = live_package.next_hop (self.cryptde.borrow ());
        // TODO Post-Release 2, look at next_hop to decide whether to route or dispatch
        let expired_package = live_package.to_expired (self.cryptde.borrow ());
        self.dispatch (next_hop.component.expect ("Internal error"), expired_package);
    }
}

impl HopperReal {
    pub fn new (cryptde: Box<CryptDE>) -> HopperReal {
        HopperReal {
            neighborhood: None,
            cryptde,
            to_proxy_server: None,
            to_proxy_client: None,
        }
    }

    fn dispatch (&mut self, recipient: Component, package: ExpiredCoresPackage) {
        match recipient {
            Component::Neighborhood => unimplemented! (),
            Component::ProxyServer => { self.to_proxy_server.as_ref ().expect ("Unbound").send(ExpiredCoresPackageMessage { pkg: package }); () },
            Component::ProxyClient => { self.to_proxy_client.as_ref ().expect ("Unbound").send( ExpiredCoresPackageMessage { pkg: package }); () },
            Component::Hopper => unimplemented! ()
        }
    }
}

#[derive (Clone, PartialEq, Serialize, Deserialize)]
pub struct LiveCoresPackage {
    pub hops: Vec<CryptData>,
    pub payload: CryptData
}

impl LiveCoresPackage {
    pub fn new (hops: Vec<CryptData>, payload: CryptData) -> LiveCoresPackage {
        LiveCoresPackage {hops, payload}
    }

    pub fn from_incipient (incipient: IncipientCoresPackage, cryptde: &CryptDE) -> (LiveCoresPackage, Key) {
        let encrypted_payload = cryptde.encode (&incipient.payload_destination_key, &incipient.payload).expect ("Encode error");
        let (next_hop, tail) = incipient.route.deconstruct ();
        if next_hop.component.is_some () {unimplemented! ()} // don't send over Substratum Network if it belongs on this node
        if next_hop.public_key.is_none () {unimplemented! ()} // can't send over Substratum Network if no destination
        (LiveCoresPackage::new (tail, encrypted_payload), next_hop.public_key.expect ("Internal error"))
    }

    pub fn to_expired (mut self, cryptde: &CryptDE) -> ExpiredCoresPackage {
        let next_hop = LiveCoresPackage::crypt_data_to_hop (&self.hops.remove (0), cryptde);
        let payload = match cryptde.decode (&cryptde.private_key (), &self.payload) {
            Ok (payload) => payload,
            Err (e) => panic! ("{:?}", e)
        };
        let remaining_route = Route::construct (next_hop, self.hops);
        ExpiredCoresPackage::new (remaining_route, payload)
    }

    pub fn next_hop (&self, cryptde: &CryptDE) -> Hop {
        let encrypted_hop = match &self.hops.first () {
            &Some (ref crypt_data) => *crypt_data,
            &None => unimplemented! ()
        };
        LiveCoresPackage::crypt_data_to_hop (encrypted_hop, cryptde)
    }

    fn crypt_data_to_hop (encrypted_hop: &CryptData, cryptde: &CryptDE) -> Hop {
        match Hop::decode (&cryptde.private_key (), cryptde, encrypted_hop) {
            Ok (hop) => hop,
            Err (e) => panic! ("{:?}", e)
        }
    }
}

#[cfg (test)]
mod tests {
    use super::*;
    use std::ops::Deref;
    use sub_lib::dispatcher::Component;
    use sub_lib::hopper::IncipientCoresPackage;
    use sub_lib::hopper::ExpiredCoresPackage;
    use sub_lib::hop::Hop;
    use sub_lib::route::Route;
    use sub_lib::route::RouteSegment;
    use sub_lib::cryptde_null::CryptDENull;
    use sub_lib::test_utils;
    use sub_lib::test_utils::TransmitterHandleMock;
    use sub_lib::test_utils::PayloadMock;
    use actix::Actor;
    use actix::Arbiter;
    use actix::SyncAddress;
    use actix::System;
    use actix::msgs;
    use sub_lib::test_utils::Recorder;

    #[test]
    fn temporary_white_box_bind_test () {
        // TODO: Replace this test with a black-box receive() test when possible
        let cryptde = CryptDENull::new ();
        let transmitter_handle = Box::new (TransmitterHandleMock::new());
        let peer_clients = test_utils::make_peer_clients_with_mocks();
        let mut subject = HopperReal::new (Box::new (cryptde));

        subject.bind(transmitter_handle, &peer_clients);

        let actual_neighborhood_ptr = arc_to_ptr (&subject.neighborhood.as_ref ().unwrap ());
        let expected_neighborhood_ptr = arc_to_ptr (&peer_clients.neighborhood);
        assert_eq! (actual_neighborhood_ptr, expected_neighborhood_ptr);
    }

    #[test]
    fn temporary_white_box_bind_facade_test() {
        let system = System::new("temporary_white_box_bind_test");
        let cryptde = CryptDENull::new ();

        let proxy_client = Recorder::new();
        let proxy_client_log_arc = proxy_client.get_recording();
        let proxy_client_awaiter = proxy_client.get_awaiter();
        let proxy_client_addr: SyncAddress<_> = proxy_client.start();
        let other_expected_sub = proxy_client_addr.subscriber::<ExpiredCoresPackageMessage>();

        let proxy_server = Recorder::new();
        let proxy_server_log_arc = proxy_server.get_recording();
        let proxy_server_awaiter = proxy_server.get_awaiter();
        let proxy_server_addr: SyncAddress<_> = proxy_server.start();
        let expected_sub = proxy_server_addr.subscriber::<ExpiredCoresPackageMessage>();

        let expected_package = ExpiredCoresPackage {
            remaining_route: Route::rel2_from_proxy_client(&cryptde.public_key(), &cryptde).unwrap(),
            payload: PlainData::new(b"some data")
        };
        let mut subject = HopperReal::new (Box::new (cryptde));

        subject.temporary_bind(expected_sub, other_expected_sub);
        subject.to_proxy_server.as_ref().unwrap().send(ExpiredCoresPackageMessage { pkg: expected_package.clone() });
        subject.to_proxy_client.as_ref().unwrap().send(ExpiredCoresPackageMessage { pkg: expected_package.clone() });

        Arbiter::system().send(msgs::SystemExit(0));
        system.run();

        assert_eq!(true, subject.to_proxy_server.is_some());
        proxy_server_awaiter.await_message_count(1);
        let recording = proxy_server_log_arc.lock().unwrap();
        let record = recording.get_record::<ExpiredCoresPackageMessage>(0);
        assert_eq!(record.pkg, expected_package);
        assert_eq!(true, subject.to_proxy_client.is_some());
        proxy_client_awaiter.await_message_count(1);
        let recording = proxy_client_log_arc.lock().unwrap();
        let record = recording.get_record::<ExpiredCoresPackageMessage>(0);
        assert_eq!(record.pkg, expected_package);
    }

    fn arc_to_ptr<T> (arc: &Arc<Mutex<T>>) -> *const T where T: ?Sized {
        arc.lock ().unwrap ().deref () as *const T
    }

    #[test]
    fn live_cores_package_can_be_constructed_from_scratch () {
        let hops = vec! (CryptData::new (&[1, 2]), CryptData::new (&[3, 4]));
        let payload = CryptData::new (&[5, 6]);

        let subject = LiveCoresPackage::new (hops.clone (), payload.clone ());

        assert_eq! (subject.hops, hops);
        assert_eq! (subject.payload, payload);
    }

    #[test]
    fn live_cores_package_can_be_constructed_from_incipient_cores_package () {
        let cryptde = CryptDENull::new ();
        let key12 = Key::new (&[1, 2]);
        let key34 = Key::new (&[3, 4]);
        let key56 = Key::new (&[5, 6]);
        let payload = PayloadMock::new ();
        let incipient = IncipientCoresPackage::new (
            Route::new(vec! (
                RouteSegment::new (vec! (&key12, &key34), Component::Neighborhood)
            ), &cryptde).unwrap (),
            payload.clone (),
            &key56
        );

        let (subject, next_stop) = LiveCoresPackage::from_incipient (incipient, &cryptde);

        assert_eq! (next_stop, key12);
        assert_eq! (subject.hops, vec! (
            Hop::with_key (&key34).encode (&key12, &cryptde).unwrap (),
            Hop::with_component (Component::Neighborhood).encode (&key34, &cryptde).unwrap (),
        ));
        assert_eq! (subject.payload, cryptde.encode (&key56, &PlainData::new (&serde_cbor::ser::to_vec (&payload).unwrap ())).unwrap ());
    }

    #[test]
    fn release_2_transmit_cores_package_from_proxy_server_calls_proxy_client_directly () {
        let system = System::new("release_2_transmit_cores_package_from_proxy_server_calls_proxy_client_directly");
        let cryptde = CryptDENull::new ();
        let incipient_package = IncipientCoresPackage::new (
            Route::rel2_from_proxy_server(&cryptde.public_key (), &cryptde).unwrap(),
            PayloadMock::new (), &cryptde.public_key ()
        );
        let proxy_client = Recorder::new ();
        let proxy_client_recording = proxy_client.get_recording();
        let proxy_client_awaiter = proxy_client.get_awaiter();
        let proxy_client_addr: SyncAddress<_> = proxy_client.start();
        let proxy_server = Recorder::new();
        let proxy_server_addr: SyncAddress<_> = proxy_server.start();

        let mut subject = HopperReal::new (Box::new (cryptde.clone ()));
        subject.bind (Box::new (TransmitterHandleMock::new ()), &test_utils::make_peer_clients_with_mocks());
        subject.temporary_bind(proxy_server_addr.subscriber::<ExpiredCoresPackageMessage>(), proxy_client_addr.subscriber::<ExpiredCoresPackageMessage>());

        subject.transmit_cores_package (incipient_package);

        Arbiter::system().send(msgs::SystemExit(0));
        system.run();

        let expected_expired_package = ExpiredCoresPackage::new (
            Route::rel2_to_proxy_client (&cryptde.public_key (), &cryptde).unwrap (),
            PlainData::new (&serde_cbor::ser::to_vec (&PayloadMock::new ()).unwrap ()[..])
        );

        proxy_client_awaiter.await_message_count(1);
        let recording = proxy_client_recording.lock().unwrap();
        let record = recording.get_record::<ExpiredCoresPackageMessage>(0);
        assert_eq!(record.pkg, expected_expired_package);
    }

    #[test]
    fn release_2_transmit_cores_package_from_proxy_client_calls_proxy_server_via_subscriber () {
        let cryptde = CryptDENull::new ();
        let system = System::new("release_2_transmit_cores_package_from_proxy_client_calls_proxy_server_directly");
        let proxy_client = Recorder::new();
        let proxy_client_addr: SyncAddress<_> = proxy_client.start();
        let proxy_server = Recorder::new();
        let proxy_server_log_arc = proxy_server.get_recording();
        let proxy_server_awaiter = proxy_server.get_awaiter();
        let proxy_server_addr: SyncAddress<_> = proxy_server.start();
        let incipient_package = IncipientCoresPackage::new (
            Route::rel2_from_proxy_client(&cryptde.public_key (), &cryptde).unwrap(),
            PayloadMock::new (), &cryptde.public_key ()
        );
        let mut subject = HopperReal::new (Box::new (cryptde.clone ()));
        subject.bind (Box::new (TransmitterHandleMock::new ()), &test_utils::make_peer_clients_with_mocks());
        subject.temporary_bind(proxy_server_addr.subscriber::<ExpiredCoresPackageMessage>(), proxy_client_addr.subscriber::<ExpiredCoresPackageMessage>());

        subject.transmit_cores_package (incipient_package.clone());

        Arbiter::system().send(msgs::SystemExit(0));
        system.run();

        let expected_package = ExpiredCoresPackage::new (
            Route::rel2_to_proxy_server (&cryptde.public_key (), &cryptde).unwrap (),
            incipient_package.payload
        );

        proxy_server_awaiter.await_message_count(1);
        let recording = proxy_server_log_arc.lock().unwrap();
        let record = recording.get_record::<ExpiredCoresPackageMessage>(0);
        assert_eq!(record.pkg, expected_package);
    }
}
