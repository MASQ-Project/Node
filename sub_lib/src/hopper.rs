// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use crate::cryptde::decodex;
use crate::cryptde::CryptDE;
use crate::cryptde::CryptData;
use crate::cryptde::PlainData;
use crate::cryptde::PublicKey;
use crate::dispatcher::InboundClientData;
use crate::peer_actors::BindMessage;
use crate::route::Route;
use crate::wallet::Wallet;
use actix::Message;
use actix::Recipient;
use actix::Syn;
use serde::de::Deserialize;
use serde::ser::Serialize;
use serde_cbor;
use std::net::IpAddr;

pub const TEMPORARY_PER_ROUTING_BYTE_RATE: u64 = 4;
pub const TEMPORARY_PER_ROUTING_RATE: u64 = 3;

/// New CORES package about to be sent to the Hopper and thence put on the Substratum Network
#[derive(Clone, Debug, PartialEq, Message)]
pub struct IncipientCoresPackage {
    pub route: Route,
    pub payload: CryptData,
}

impl IncipientCoresPackage {
    pub fn new<T>(
        cryptde: &dyn CryptDE, // must be the CryptDE of the Node to which the top hop is encrypted
        route: Route,
        payload: T,
        payload_destination_key: &PublicKey,
    ) -> Result<IncipientCoresPackage, String>
    where
        T: Serialize,
    {
        // crashpoint - TODO: Figure out how to log this serialization failure rather than letting data crash the Node.
        let serialized_payload = serde_cbor::ser::to_vec(&payload).expect("Serialization failure");
        let encrypted_payload = match cryptde.encode(
            &payload_destination_key,
            &PlainData::new(&serialized_payload[..]),
        ) {
            Ok(p) => p,
            Err(e) => return Err(format!("Could not encrypt payload: {:?}", e)),
        };

        Ok(IncipientCoresPackage {
            route,
            payload: encrypted_payload,
        })
    }
}

/// CORES package that has traversed the Substratum Network and is arriving at its destination
#[derive(Clone, Debug, PartialEq, Message)]
pub struct ExpiredCoresPackage {
    pub immediate_neighbor_ip: IpAddr,
    pub consuming_wallet: Option<Wallet>,
    pub remaining_route: Route, // This is topped by the hop that brought the package here, not the next hop
    pub payload: CryptData,
}

impl ExpiredCoresPackage {
    pub fn new(
        immediate_neighbor_ip: IpAddr,
        consuming_wallet: Option<Wallet>,
        remaining_route: Route,
        payload: CryptData,
    ) -> ExpiredCoresPackage {
        ExpiredCoresPackage {
            immediate_neighbor_ip,
            consuming_wallet,
            remaining_route,
            payload,
        }
    }

    pub fn payload<T>(&self, cryptde: &CryptDE) -> Result<T, String>
    where
        for<'de> T: Deserialize<'de>,
    {
        decodex::<T>(cryptde, &self.payload)
    }

    pub fn payload_data(self) -> CryptData {
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
    use crate::cryptde::PlainData;
    use crate::cryptde_null::CryptDENull;
    use crate::dispatcher::Component;
    use crate::route::RouteSegment;
    use std::str::FromStr;
    use test_utils::test_utils::PayloadMock;

    #[test]
    fn incipient_cores_package_is_created_correctly() {
        let cryptde = CryptDENull::new();
        let consuming_wallet = Wallet::new("wallet");
        let key12 = cryptde.public_key();
        let key34 = PublicKey::new(&[3, 4]);
        let key56 = PublicKey::new(&[5, 6]);
        let route = Route::one_way(
            RouteSegment::new(vec![&key12, &key34, &key56], Component::ProxyClient),
            &cryptde,
            Some(consuming_wallet),
        )
        .unwrap();
        let payload = PayloadMock::new();

        let result = IncipientCoresPackage::new(&cryptde, route.clone(), payload.clone(), &key56);
        let subject = result.unwrap();

        assert_eq!(subject.route, route);
        assert_eq!(
            subject.payload,
            cryptde
                .encode(
                    &key56,
                    &PlainData::new(&serde_cbor::ser::to_vec(&payload).unwrap())
                )
                .unwrap()
        );
    }

    #[test]
    fn incipient_cores_package_new_complains_about_problems_encrypting_payload() {
        let cryptde = CryptDENull::new();
        let result = IncipientCoresPackage::new(
            &cryptde,
            Route { hops: vec![] },
            CryptData::new(&[]),
            &PublicKey::new(&[]),
        );

        assert_eq!(
            result,
            Err(String::from("Could not encrypt payload: EmptyKey"))
        );
    }

    #[test]
    fn expired_cores_package_is_created_correctly() {
        let immediate_neighbor_ip = IpAddr::from_str("1.2.3.4").unwrap();
        let a_key = PublicKey::new(&[65, 65, 65]);
        let b_key = PublicKey::new(&[66, 66, 66]);
        let cryptde = CryptDENull::new();
        let consuming_wallet = Wallet::new("wallet");
        let route = Route::one_way(
            RouteSegment::new(vec![&a_key, &b_key], Component::Neighborhood),
            &cryptde,
            Some(consuming_wallet.clone()),
        )
        .unwrap();
        let deserialized_payload = PayloadMock::new();
        let payload = PlainData::from(serde_cbor::ser::to_vec(&deserialized_payload).unwrap());
        let encrypted_payload = cryptde.encode(&cryptde.public_key(), &payload).unwrap();

        let subject = ExpiredCoresPackage::new(
            immediate_neighbor_ip,
            Some(consuming_wallet),
            route.clone(),
            encrypted_payload,
        );

        assert_eq!(subject.immediate_neighbor_ip, immediate_neighbor_ip);
        assert_eq!(subject.consuming_wallet, Some(Wallet::new("wallet")));
        assert_eq!(subject.remaining_route, route);
        assert_eq!(
            subject.payload::<PayloadMock>(&cryptde).unwrap(),
            deserialized_payload
        );
    }
}
