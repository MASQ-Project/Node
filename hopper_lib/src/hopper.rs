// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use std::borrow::Borrow;
use sub_lib::hopper::IncipientCoresPackage;
use sub_lib::hopper::ExpiredCoresPackage;
use sub_lib::hop::Hop;
use sub_lib::route::Route;
use sub_lib::cryptde::CryptDE;
use sub_lib::cryptde::Key;
use sub_lib::cryptde::CryptData;
use sub_lib::hopper::HopperSubs;
use sub_lib::actor_messages::ExpiredCoresPackageMessage;
use sub_lib::actor_messages::IncipientCoresPackageMessage;
use sub_lib::actor_messages::BindMessage;
use actix::Subscriber;
use actix::Actor;
use actix::Context;
use actix::Handler;
use actix::SyncAddress;

pub struct Hopper {
    cryptde: Box<CryptDE>,
    to_proxy_server: Option<Box<Subscriber<ExpiredCoresPackageMessage> + Send>>,
    to_proxy_client: Option<Box<Subscriber<ExpiredCoresPackageMessage> + Send>>,
}

impl Actor for Hopper {
    type Context = Context<Self>;
}

impl Handler<BindMessage> for Hopper {
    type Result = ();

    fn handle(&mut self, msg: BindMessage, _ctx: &mut Self::Context) -> Self::Result {
        self.to_proxy_server = Some(msg.peer_actors.proxy_server.from_hopper);
        self.to_proxy_client = Some(msg.peer_actors.proxy_client.from_hopper);
        ()
    }
}

impl Handler<IncipientCoresPackageMessage> for Hopper {
    type Result = ();

    fn handle(&mut self, msg: IncipientCoresPackageMessage, _ctx: &mut Self::Context) -> Self::Result {
        // Skinny Release-2-only implementation
        if msg.pkg.route.next_hop ().public_key.is_some () {
            // from Proxy Server
            let expired_package = ExpiredCoresPackage::new (
                Route::rel2_to_proxy_client (&self.cryptde.public_key (), self.cryptde.borrow ()).unwrap (),
                msg.pkg.payload
            );
            self.to_proxy_client.as_ref ().unwrap ().send (ExpiredCoresPackageMessage { pkg: expired_package }).expect ("Proxy Client is dead");
            ()
        }
        else {
            // from Proxy Client
            let expired_package = ExpiredCoresPackage::new (
                Route::rel2_to_proxy_server (&self.cryptde.public_key (), self.cryptde.borrow ()).unwrap (),
                msg.pkg.payload
            );
            self.to_proxy_server.as_ref().expect("ProxyServer unbound").send( ExpiredCoresPackageMessage { pkg: expired_package }).expect ("Proxy Server is dead");
            ()
        };
        ()
    }
}

impl Hopper {
    pub fn new (cryptde: Box<CryptDE>) -> Hopper {
        Hopper {
            cryptde,
            to_proxy_server: None,
            to_proxy_client: None,
        }
    }

    pub fn make_subs_from(addr: &SyncAddress<Hopper>) -> HopperSubs {
        HopperSubs {
            bind: addr.subscriber::<BindMessage>(),
            from_hopper_client: addr.subscriber::<IncipientCoresPackageMessage>(),
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
    use sub_lib::test_utils::RecordAwaiter;
    use sub_lib::test_utils::Recording;
    use sub_lib::test_utils::make_peer_actors_from;
    use std::thread;

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
        let cryptde = CryptDENull::new ();
        let thread_cryptde = cryptde.clone();
        let incipient_package = IncipientCoresPackage::new (
            Route::rel2_from_proxy_server(&cryptde.public_key (), &cryptde).unwrap(),
            PayloadMock::new (), &cryptde.public_key ()
        );
        let proxy_client = Recorder::new ();
        let proxy_client_recording = proxy_client.get_recording();
        let proxy_client_awaiter = proxy_client.get_awaiter();

        thread::spawn(move || {
            let system = System::new("release_2_transmit_cores_package_from_proxy_server_calls_proxy_client_directly");
            let peer_actors = make_peer_actors_from(None, None, None, None, Some(proxy_client));
            let subject = Hopper::new (Box::new (thread_cryptde));
            let subject_addr: SyncAddress<_> = subject.start();
            subject_addr.send(BindMessage { peer_actors });

            subject_addr.send(IncipientCoresPackageMessage { pkg: incipient_package });

            system.run();
        });

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
        let thread_cryptde = cryptde.clone();
        let proxy_server = Recorder::new();
        let proxy_server_log_arc = proxy_server.get_recording();
        let proxy_server_awaiter = proxy_server.get_awaiter();
        let incipient_package = IncipientCoresPackage::new (
            Route::rel2_from_proxy_client(&cryptde.public_key (), &cryptde).unwrap(),
            PayloadMock::new (), &cryptde.public_key ()
        );
        let thread_package = incipient_package.clone();
        thread::spawn(move || {
            let system = System::new("release_2_transmit_cores_package_from_proxy_client_calls_proxy_server_directly");
            let peer_actors = make_peer_actors_from(Some(proxy_server), None, None, None, None);
            let subject = Hopper::new (Box::new (thread_cryptde));
            let subject_addr: SyncAddress<_> = subject.start();
            subject_addr.send(BindMessage { peer_actors });

            subject_addr.send(IncipientCoresPackageMessage { pkg: thread_package });

            system.run();
        });

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
