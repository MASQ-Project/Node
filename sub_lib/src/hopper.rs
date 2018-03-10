// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use serde::ser::Serialize;
use serde::de::Deserialize;
use serde_cbor;
use dispatcher::DispatcherClient;
use route::Route;
use cryptde::Key;
use cryptde::PlainData;
use actor_messages::BindMessage;
use actor_messages::ExpiredCoresPackageMessage;
use actor_messages::IncipientCoresPackageMessage;
use actix::Subscriber;

pub trait Hopper: DispatcherClient {
    fn transmit_cores_package (&self, package: IncipientCoresPackage);
    // TODO remove once Hopper is actorized
    fn temporary_bind_proxy_server (&mut self, to_proxy_server: Box<Subscriber<ExpiredCoresPackageMessage> + Send>);
}

pub trait HopperClient {
    fn receive_cores_package (&mut self, package: ExpiredCoresPackage);
}

pub trait HopperDispatcherClient: Hopper + DispatcherClient + Send + Sync {}

impl<T: Hopper + DispatcherClient + Send + Sync> HopperDispatcherClient for T {}

/// New CORES package about to be sent to the Hopper and thence put on the Substratum Network
#[derive (Clone, Debug, PartialEq)]
pub struct IncipientCoresPackage {
    pub route: Route,
    pub payload: PlainData,
    pub payload_destination_key: Key
}

impl IncipientCoresPackage {
    pub fn new<T> (route: Route, payload: T, key: &Key) -> IncipientCoresPackage where T: Serialize {
        // TODO: Figure out how to log this serialization failure rather than letting data crash the Node.
        let serialized_payload = serde_cbor::ser::to_vec(&payload).expect ("Serialization failure");
        IncipientCoresPackage {
            route,
            payload: PlainData::new (&serialized_payload[..]),
            payload_destination_key: key.clone ()
        }
    }
}

/// CORES package that has traversed the Substratum Network and is arriving at its destination
#[derive (Clone, Debug, PartialEq)]
pub struct ExpiredCoresPackage {
    pub remaining_route: Route,
    pub payload: PlainData
}

impl ExpiredCoresPackage {
    pub fn new (remaining_route: Route, payload: PlainData) -> ExpiredCoresPackage {
        ExpiredCoresPackage {remaining_route, payload}
    }

    /// This method is exquisitely dangerous: hacked data might be deserialized to anything. In
    /// production code, the result of this method must be assiduously checked for malice before
    /// being used.  These checks should be driven by tests using raw CBOR.
    pub fn payload<'a, T> (&'a self) -> serde_cbor::error::Result<T> where T: Deserialize<'a> {
        serde_cbor::de::from_slice (&self.payload.data[..])
    }

    pub fn payload_data (self) -> PlainData {
        self.payload
    }
}

#[derive(Clone)]
pub struct HopperSubs {
    pub bind: Box<Subscriber<BindMessage> + Send>,
    pub from_hopper_client: Box<Subscriber<IncipientCoresPackageMessage> + Send>,
}

#[cfg (test)]
mod tests {
    use super::*;
    use cryptde::PlainData;
    use cryptde_null::CryptDENull;
    use test_utils::PayloadMock;

    #[test]
    fn incipient_cores_package_is_created_correctly () {
        let route_key = Key::new (&[1]);
        let route = Route::rel2_from_proxy_server (&route_key, &CryptDENull::new ()).unwrap ();
        let payload = PayloadMock::new ();
        let key = Key::new (&[5, 6]);

        let subject = IncipientCoresPackage::new (route.clone (),
                                                  payload.clone (), &key);

        assert_eq! (subject.route, route);
        assert_eq! (subject.payload_destination_key, key);
        let actual_payload: PayloadMock = serde_cbor::de::from_slice (&subject.payload.data[..]).unwrap ();
        assert_eq! (actual_payload, payload);
    }

    #[test]
    fn expired_cores_package_is_created_correctly () {
        let route_key = Key::new (&[1]);
        let route = Route::rel2_to_proxy_client (&route_key, &CryptDENull::new ()).unwrap ();
        let deserialized_payload = PayloadMock::new ();
        let payload = serde_cbor::ser::to_vec (&deserialized_payload).unwrap ();

        let subject = ExpiredCoresPackage::new (route.clone (),
                                                  PlainData::new (&payload[..]));

        assert_eq! (subject.remaining_route, route);
        assert_eq! (subject.payload::<PayloadMock> ().unwrap (), deserialized_payload);
    }
}
