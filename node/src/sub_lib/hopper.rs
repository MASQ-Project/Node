// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
use crate::bootstrapper::CryptDEPair;
use crate::neighborhood::gossip::Gossip_0v1;
use crate::sub_lib::cryptde::encodex;
use crate::sub_lib::cryptde::CryptDE;
use crate::sub_lib::cryptde::CryptData;
use crate::sub_lib::cryptde::PublicKey;
use crate::sub_lib::dispatcher::InboundClientData;
use crate::sub_lib::neighborhood::GossipFailure_0v1;
use crate::sub_lib::node_addr::NodeAddr;
use crate::sub_lib::peer_actors::BindMessage;
use crate::sub_lib::proxy_client::{ClientResponsePayload_0v1, DnsResolveFailure_0v1};
use crate::sub_lib::proxy_server::ClientRequestPayload_0v1;
use crate::sub_lib::route::Route;
use crate::sub_lib::versioned_data::VersionedData;
use crate::sub_lib::wallet::Wallet;
use actix::Message;
use actix::Recipient;
use masq_lib::ui_gateway::NodeFromUiMessage;
use serde_derive::{Deserialize, Serialize};
use std::fmt::Debug;
use std::net::SocketAddr;

/// Special-case hack to avoid extending a Card From Hell. I'm not sure what the right way to do
/// this is, but this doesn't feel like it. The intent here is to provide a way to send a CORES
/// package to a Node that isn't in the database yet, because while we have enough information
/// about it to send it CORES traffic, we don't have enough (or what we have isn't credible enough)
/// to put it in the database yet. This can happen when we start up and need to send Debut
/// Gossip to Nodes specified by --neighbors, about which we know only the local descriptor, when we send Pass
/// Gossip to a Debuting Node that hasn't made it into our database yet, or when we get
/// Introductions to possibly-nonexistent Nodes that we want to keep out of the database until they've been
/// verified. We can't use a regular IncipientCoresPackage for this, because it uses a Route full
/// of PublicKeys destined to be looked up in the database by the Dispatcher.
/// This struct can be used only for single-hop traffic.
#[derive(Clone, Debug, PartialEq, Eq, Message)]
pub struct NoLookupIncipientCoresPackage {
    pub public_key: PublicKey,
    pub node_addr: NodeAddr,
    pub payload: CryptData,
}

impl NoLookupIncipientCoresPackage {
    pub fn new(
        cryptde: &dyn CryptDE, // used only for encryption; can be any CryptDE
        public_key: &PublicKey,
        node_addr: &NodeAddr,
        payload: MessageType,
    ) -> Result<NoLookupIncipientCoresPackage, String> {
        let encrypted_payload = match encodex(cryptde, public_key, &payload) {
            Ok(p) => p,
            Err(e) => return Err(format!("Could not encrypt payload: {:?}", e)),
        };
        Ok(NoLookupIncipientCoresPackage {
            public_key: public_key.clone(),
            node_addr: node_addr.clone(),
            payload: encrypted_payload,
        })
    }
}

/// New CORES package about to be sent to the Hopper and thence put on the MASQ Network
#[derive(Clone, Debug, PartialEq, Eq, Message)]
pub struct IncipientCoresPackage {
    pub route: Route,
    pub payload: CryptData,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessageType {
    ClientRequest(VersionedData<ClientRequestPayload_0v1>),
    ClientResponse(VersionedData<ClientResponsePayload_0v1>),
    Gossip(VersionedData<Gossip_0v1>),
    GossipFailure(VersionedData<GossipFailure_0v1>),
    DnsResolveFailed(VersionedData<DnsResolveFailure_0v1>),
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MessageTypeLite {
    ClientRequest,
    ClientResponse,
    Gossip,
    GossipFailure,
    DnsResolveFailed,
}

#[allow(clippy::from_over_into)]
impl Into<MessageTypeLite> for MessageType {
    fn into(self) -> MessageTypeLite {
        match self {
            MessageType::ClientRequest(_) => MessageTypeLite::ClientRequest,
            MessageType::ClientResponse(_) => MessageTypeLite::ClientResponse,
            MessageType::Gossip(_) => MessageTypeLite::Gossip,
            MessageType::GossipFailure(_) => MessageTypeLite::GossipFailure,
            MessageType::DnsResolveFailed(_) => MessageTypeLite::DnsResolveFailed,
        }
    }
}

impl IncipientCoresPackage {
    pub fn new(
        cryptde: &dyn CryptDE, // must be the CryptDE of the Node to which the top hop is encrypted
        route: Route,
        payload: MessageType,
        payload_destination_key: &PublicKey,
    ) -> Result<IncipientCoresPackage, String> {
        let encrypted_payload = match encodex(cryptde, payload_destination_key, &payload) {
            Ok(p) => p,
            Err(e) => return Err(format!("Could not encrypt payload: {:?}", e)),
        };

        Ok(IncipientCoresPackage {
            route,
            payload: encrypted_payload,
        })
    }
}

/// CORES package that has traversed the MASQ Network and is arriving at its destination
#[derive(Clone, Debug, PartialEq, Eq, Message)]
pub struct ExpiredCoresPackage<T> {
    pub immediate_neighbor: SocketAddr,
    pub paying_wallet: Option<Wallet>,
    pub remaining_route: Route, // This is topped by the hop that brought the package here, not the next hop
    pub payload: T,
    pub payload_len: usize,
}

impl<T> ExpiredCoresPackage<T> {
    pub fn new(
        immediate_neighbor: SocketAddr,
        paying_wallet: Option<Wallet>,
        remaining_route: Route,
        payload: T,
        payload_len: usize,
    ) -> Self {
        ExpiredCoresPackage {
            immediate_neighbor,
            paying_wallet,
            remaining_route,
            payload,
            payload_len,
        }
    }
}

#[derive(Clone)]
pub struct HopperConfig {
    pub cryptdes: CryptDEPair,
    pub per_routing_service: u64,
    pub per_routing_byte: u64,
    pub is_decentralized: bool,
    pub crashable: bool,
}

#[derive(Clone, PartialEq, Eq)]
pub struct HopperSubs {
    pub bind: Recipient<BindMessage>,
    pub from_hopper_client: Recipient<IncipientCoresPackage>,
    pub from_hopper_client_no_lookup: Recipient<NoLookupIncipientCoresPackage>,
    pub from_dispatcher: Recipient<InboundClientData>,
    pub node_from_ui: Recipient<NodeFromUiMessage>,
}

impl Debug for HopperSubs {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        write!(f, "HopperSubs")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sub_lib::cryptde::PlainData;
    use crate::sub_lib::dispatcher::Component;
    use crate::sub_lib::route::RouteSegment;
    use crate::sub_lib::stream_key::StreamKey;
    use crate::test_utils::recorder::Recorder;
    use crate::test_utils::{main_cryptde, make_meaningless_message_type, make_paying_wallet};
    use actix::Actor;
    use masq_lib::test_utils::utils::TEST_DEFAULT_CHAIN;
    use std::net::IpAddr;
    use std::str::FromStr;

    #[test]
    fn hopper_subs_debug() {
        let recorder = Recorder::new().start();

        let subject = HopperSubs {
            bind: recipient!(recorder, BindMessage),
            from_hopper_client: recipient!(recorder, IncipientCoresPackage),
            from_hopper_client_no_lookup: recipient!(recorder, NoLookupIncipientCoresPackage),
            from_dispatcher: recipient!(recorder, InboundClientData),
            node_from_ui: recipient!(recorder, NodeFromUiMessage),
        };

        assert_eq!(format!("{:?}", subject), "HopperSubs");
    }

    #[test]
    fn no_lookup_incipient_cores_package_is_created_correctly() {
        let cryptde = main_cryptde();
        let public_key = PublicKey::new(&[1, 2]);
        let node_addr = NodeAddr::new(&IpAddr::from_str("1.2.3.4").unwrap(), &[1, 2, 3, 4]);
        let payload = make_meaningless_message_type(StreamKey::make_meaningless_stream_key());

        let result =
            NoLookupIncipientCoresPackage::new(cryptde, &public_key, &node_addr, payload.clone());
        let subject = result.unwrap();

        assert_eq!(public_key, subject.public_key);
        assert_eq!(node_addr, subject.node_addr);
        assert_eq!(
            cryptde
                .encode(
                    &public_key,
                    &PlainData::new(&serde_cbor::ser::to_vec(&payload).unwrap())
                )
                .unwrap(),
            subject.payload,
        );
    }

    #[test]
    fn no_lookup_incipient_cores_package_new_complains_about_problems_encrypting_payload() {
        let cryptde = main_cryptde();
        let result = NoLookupIncipientCoresPackage::new(
            cryptde,
            &PublicKey::new(&[]),
            &NodeAddr::new(&IpAddr::from_str("1.1.1.1").unwrap(), &[]),
            make_meaningless_message_type(StreamKey::make_meaningless_stream_key()),
        );
        assert_eq!(
            result,
            Err(String::from(
                "Could not encrypt payload: EncryptionError(EmptyKey)"
            ))
        );
    }

    #[test]
    fn incipient_cores_package_is_created_correctly() {
        let cryptde = main_cryptde();
        let paying_wallet = make_paying_wallet(b"wallet");
        let key12 = cryptde.public_key();
        let key34 = PublicKey::new(&[3, 4]);
        let key56 = PublicKey::new(&[5, 6]);
        let route = Route::one_way(
            RouteSegment::new(vec![&key12, &key34, &key56], Component::ProxyClient),
            cryptde,
            Some(paying_wallet),
            Some(TEST_DEFAULT_CHAIN.rec().contract),
        )
        .unwrap();
        let payload = make_meaningless_message_type(StreamKey::make_meaningless_stream_key());

        let result = IncipientCoresPackage::new(cryptde, route.clone(), payload.clone(), &key56);
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
        let cryptde = main_cryptde();
        let result = IncipientCoresPackage::new(
            cryptde,
            Route { hops: vec![] },
            make_meaningless_message_type(StreamKey::make_meaningless_stream_key()),
            &PublicKey::new(&[]),
        );

        assert_eq!(
            result,
            Err(String::from(
                "Could not encrypt payload: EncryptionError(EmptyKey)"
            ))
        );
    }

    #[test]
    fn expired_cores_package_is_created_correctly() {
        let immediate_neighbor = SocketAddr::from_str("1.2.3.4:1234").unwrap();
        let a_key = PublicKey::new(&[65, 65, 65]);
        let b_key = PublicKey::new(&[66, 66, 66]);
        let cryptde = main_cryptde();
        let paying_wallet = make_paying_wallet(b"wallet");
        let route = Route::one_way(
            RouteSegment::new(vec![&a_key, &b_key], Component::Neighborhood),
            cryptde,
            Some(paying_wallet.clone()),
            Some(TEST_DEFAULT_CHAIN.rec().contract),
        )
        .unwrap();
        let payload = make_meaningless_message_type(StreamKey::make_meaningless_stream_key());

        let subject: ExpiredCoresPackage<MessageType> = ExpiredCoresPackage::new(
            immediate_neighbor,
            Some(paying_wallet),
            route.clone(),
            payload.clone().into(),
            42,
        );

        assert_eq!(subject.immediate_neighbor, immediate_neighbor);
        assert_eq!(subject.paying_wallet, Some(make_paying_wallet(b"wallet")));
        assert_eq!(subject.remaining_route, route);
        assert_eq!(subject.payload, payload);
        assert_eq!(subject.payload_len, 42);
    }

    #[test]
    fn message_type_can_be_converted_in_to_message_type_lite() {
        let dns_resolve_failed =
            MessageType::DnsResolveFailed(VersionedData::test_new(dv!(0, 0), vec![]));
        let client_response =
            MessageType::ClientResponse(VersionedData::test_new(dv!(0, 0), vec![]));
        let client_request = MessageType::ClientRequest(VersionedData::test_new(dv!(0, 0), vec![]));
        let gossip_failure = MessageType::GossipFailure(VersionedData::test_new(dv!(0, 0), vec![]));
        let gossip = MessageType::Gossip(VersionedData::test_new(dv!(0, 0), vec![]));

        let dns_resolve_failed_result: MessageTypeLite = dns_resolve_failed.into();
        let client_response_result: MessageTypeLite = client_response.into();
        let client_request_result: MessageTypeLite = client_request.into();
        let gossip_failure_result: MessageTypeLite = gossip_failure.into();
        let gossip_result: MessageTypeLite = gossip.into();

        assert_eq!(dns_resolve_failed_result, MessageTypeLite::DnsResolveFailed);
        assert_eq!(client_response_result, MessageTypeLite::ClientResponse);
        assert_eq!(client_request_result, MessageTypeLite::ClientRequest);
        assert_eq!(gossip_failure_result, MessageTypeLite::GossipFailure);
        assert_eq!(gossip_result, MessageTypeLite::Gossip);
    }
}
