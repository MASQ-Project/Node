// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use actix::Recipient;
use actix::Syn;
use cryptde::PlainData;
use cryptde::PublicKey;
use dispatcher::InboundClientData;
use peer_actors::BindMessage;
use route::Route;
use serde::de::Deserialize;
use serde::ser::Serialize;
use serde_cbor;
use std::net::IpAddr;
use wallet::Wallet;

/// New CORES package about to be sent to the Hopper and thence put on the Substratum Network
#[derive(Clone, Debug, PartialEq, Message)]
pub struct IncipientCoresPackage {
    pub route: Route,
    pub payload: PlainData,
    pub payload_destination_key: PublicKey,
}

impl IncipientCoresPackage {
    pub fn new<T>(
        route: Route,
        payload: T,
        payload_destination_key: &PublicKey,
    ) -> IncipientCoresPackage
    where
        T: Serialize,
    {
        // crashpoint - TODO: Figure out how to log this serialization failure rather than letting data crash the Node.
        let serialized_payload = serde_cbor::ser::to_vec(&payload).expect("Serialization failure");
        IncipientCoresPackage {
            route,
            payload: PlainData::new(&serialized_payload[..]),
            payload_destination_key: payload_destination_key.clone(),
        }
    }
}

/// CORES package that has traversed the Substratum Network and is arriving at its destination
#[derive(Clone, Debug, PartialEq, Message)]
pub struct ExpiredCoresPackage {
    pub immediate_neighbor_ip: IpAddr,
    pub consuming_wallet: Option<Wallet>,
    pub remaining_route: Route, // This is topped by the hop that brought the package here, not the next hop
    pub payload: PlainData,
}

impl ExpiredCoresPackage {
    pub fn new(
        immediate_neighbor_ip: IpAddr,
        consuming_wallet: Option<Wallet>,
        remaining_route: Route,
        payload: PlainData,
    ) -> ExpiredCoresPackage {
        ExpiredCoresPackage {
            immediate_neighbor_ip,
            consuming_wallet,
            remaining_route,
            payload,
        }
    }

    /// This method is exquisitely dangerous: hacked data might be deserialized to anything. In
    /// production code, the result of this method must be assiduously checked for malice before
    /// being used.  These checks should be driven by tests using raw CBOR.
    pub fn payload<'a, T>(&'a self) -> serde_cbor::error::Result<T>
    where
        T: Deserialize<'a>,
    {
        serde_cbor::de::from_slice(&self.payload.as_slice())
    }

    pub fn payload_data(self) -> PlainData {
        self.payload
    }
}

#[derive(Clone)]
pub struct HopperSubs {
    pub bind: Recipient<Syn, BindMessage>,
    pub from_hopper_client: Recipient<Syn, IncipientCoresPackage>,
    pub from_dispatcher: Recipient<Syn, InboundClientData>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use cryptde::PlainData;
    use cryptde_null::CryptDENull;
    use dispatcher::Component;
    use route::RouteSegment;
    use std::str::FromStr;
    use test_utils::test_utils::PayloadMock;

    #[test]
    fn incipient_cores_package_is_created_correctly() {
        let consuming_wallet = Wallet::new("wallet");
        let route_key = PublicKey::new(&[1]);
        let route = Route::new(
            vec![
                RouteSegment::new(vec![&route_key], Component::ProxyClient),
                RouteSegment::new(vec![&route_key, &route_key], Component::ProxyServer),
            ],
            &CryptDENull::new(),
            Some(consuming_wallet.clone()),
        )
        .unwrap();
        let payload = PayloadMock::new();
        let key = PublicKey::new(&[5, 6]);

        let subject = IncipientCoresPackage::new(route.clone(), payload.clone(), &key);

        assert_eq!(subject.route, route);
        assert_eq!(subject.payload_destination_key, key);
        let actual_payload: PayloadMock =
            serde_cbor::de::from_slice(subject.payload.as_slice()).unwrap();
        assert_eq!(actual_payload, payload);
    }

    #[test]
    fn expired_cores_package_is_created_correctly() {
        let immediate_neighbor_ip = IpAddr::from_str("1.2.3.4").unwrap();
        let a_key = PublicKey::new(&[65, 65, 65]);
        let b_key = PublicKey::new(&[66, 66, 66]);
        let cryptde = CryptDENull::new();
        let consuming_wallet = Wallet::new("wallet");
        let route = Route::new(
            vec![RouteSegment::new(
                vec![&a_key, &b_key],
                Component::Neighborhood,
            )],
            &cryptde,
            Some(consuming_wallet.clone()),
        )
        .unwrap();
        let deserialized_payload = PayloadMock::new();
        let payload = serde_cbor::ser::to_vec(&deserialized_payload).unwrap();

        let subject = ExpiredCoresPackage::new(
            immediate_neighbor_ip,
            Some(consuming_wallet),
            route.clone(),
            PlainData::new(&payload[..]),
        );

        assert_eq!(subject.immediate_neighbor_ip, immediate_neighbor_ip);
        assert_eq!(subject.consuming_wallet, Some(Wallet::new("wallet")));
        assert_eq!(subject.remaining_route, route);
        assert_eq!(
            subject.payload::<PayloadMock>().unwrap(),
            deserialized_payload
        );
    }
}
