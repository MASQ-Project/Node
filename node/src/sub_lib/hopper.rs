// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use crate::neighborhood::gossip::Gossip;
use crate::sub_lib::cryptde::CryptDE;
use crate::sub_lib::cryptde::CryptData;
use crate::sub_lib::cryptde::PlainData;
use crate::sub_lib::cryptde::PublicKey;
use crate::sub_lib::dispatcher::InboundClientData;
use crate::sub_lib::peer_actors::BindMessage;
use crate::sub_lib::proxy_client::ClientResponsePayload;
use crate::sub_lib::proxy_server::ClientRequestPayload;
use crate::sub_lib::route::Route;
use crate::sub_lib::wallet::Wallet;
use actix::Message;
use actix::Recipient;
use serde_cbor;
use serde_derive::{Deserialize, Serialize};
use std::net::IpAddr;

/// New CORES package about to be sent to the Hopper and thence put on the Substratum Network
#[derive(Clone, Debug, PartialEq, Message)]
pub struct IncipientCoresPackage {
    pub route: Route,
    pub payload: CryptData,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum MessageType {
    ClientRequest(ClientRequestPayload),
    ClientResponse(ClientResponsePayload),
    Gossip(Gossip),
    DnsResolveFailed,
}

impl IncipientCoresPackage {
    pub fn new(
        cryptde: &dyn CryptDE, // must be the CryptDE of the Node to which the top hop is encrypted
        route: Route,
        payload: MessageType,
        payload_destination_key: &PublicKey,
    ) -> Result<IncipientCoresPackage, String> {
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
pub struct ExpiredCoresPackage<T> {
    pub immediate_neighbor_ip: IpAddr,
    pub consuming_wallet: Option<Wallet>,
    pub remaining_route: Route, // This is topped by the hop that brought the package here, not the next hop
    pub payload: T,
    pub payload_len: usize,
}

impl<T> ExpiredCoresPackage<T> {
    pub fn new(
        immediate_neighbor_ip: IpAddr,
        consuming_wallet: Option<Wallet>,
        remaining_route: Route,
        payload: T,
        payload_len: usize,
    ) -> Self {
        ExpiredCoresPackage {
            immediate_neighbor_ip,
            consuming_wallet,
            remaining_route,
            payload,
            payload_len,
        }
    }
}

#[derive(Clone)]
pub struct HopperConfig {
    pub cryptde: &'static dyn CryptDE,
    pub is_bootstrap_node: bool,
    pub per_routing_service: u64,
    pub per_routing_byte: u64,
}

#[derive(Clone)]
pub struct HopperSubs {
    pub bind: Recipient<BindMessage>,
    pub from_hopper_client: Recipient<IncipientCoresPackage>,
    pub from_dispatcher: Recipient<InboundClientData>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sub_lib::cryptde::PlainData;
    use crate::sub_lib::cryptde_null::CryptDENull;
    use crate::sub_lib::dispatcher::Component;
    use crate::sub_lib::route::RouteSegment;
    use std::str::FromStr;

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
        let payload = MessageType::DnsResolveFailed;

        let result = IncipientCoresPackage::new(&cryptde, route.clone(), payload.clone(), &key56);
        let subject = result.unwrap();

        assert_eq!(subject.route, route);
        assert_eq!(
            subject.payload,
            cryptde
                .encode(
                    &key56,
                    &PlainData::new(&serde_cbor::ser::to_vec(&payload).unwrap()),
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
            MessageType::DnsResolveFailed,
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
        let payload = MessageType::DnsResolveFailed;

        let subject: ExpiredCoresPackage<MessageType> = ExpiredCoresPackage::new(
            immediate_neighbor_ip,
            Some(consuming_wallet),
            route.clone(),
            payload.clone().into(),
            42,
        );

        assert_eq!(subject.immediate_neighbor_ip, immediate_neighbor_ip);
        assert_eq!(subject.consuming_wallet, Some(Wallet::new("wallet")));
        assert_eq!(subject.remaining_route, route);
        assert_eq!(subject.payload, payload);
        assert_eq!(subject.payload_len, 42);
    }
}
