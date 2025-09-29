// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
use crate::bootstrapper::CryptDEPair;
use crate::sub_lib::hopper::{ExpiredCoresPackage, MessageType};
use crate::sub_lib::peer_actors::BindMessage;
use crate::sub_lib::proxy_server::ClientRequestPayload_0v1;
use crate::sub_lib::sequence_buffer::SequencedPacket;
use crate::sub_lib::stream_key::StreamKey;
use crate::sub_lib::versioned_data::VersionedData;
use actix::Message;
use actix::Recipient;
use masq_lib::ui_gateway::NodeFromUiMessage;
use serde_derive::{Deserialize, Serialize};
use std::fmt::{Debug, Formatter};
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::net::SocketAddrV4;

pub fn error_socket_addr() -> SocketAddr {
    SocketAddr::from(SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 0))
}

#[derive(Clone)]
pub struct ProxyClientConfig {
    pub cryptde_pair: CryptDEPair,
    pub dns_servers: Vec<SocketAddr>,
    pub exit_service_rate: u64,
    pub exit_byte_rate: u64,
    pub is_decentralized: bool,
    pub crashable: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[allow(non_camel_case_types)]
pub struct ClientResponsePayload_0v1 {
    pub stream_key: StreamKey,
    pub sequenced_packet: SequencedPacket,
}

#[derive(Message, Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[allow(non_camel_case_types)]
pub struct DnsResolveFailure_0v1 {
    pub stream_key: StreamKey,
}

impl DnsResolveFailure_0v1 {
    pub fn new(stream_key: StreamKey) -> Self {
        Self { stream_key }
    }
}

impl From<ClientResponsePayload_0v1> for MessageType {
    fn from(data: ClientResponsePayload_0v1) -> Self {
        MessageType::ClientResponse(VersionedData::new(
            &crate::sub_lib::migrations::client_response_payload::MIGRATIONS,
            &data,
        ))
    }
}

impl From<DnsResolveFailure_0v1> for MessageType {
    fn from(data: DnsResolveFailure_0v1) -> Self {
        MessageType::DnsResolveFailed(VersionedData::new(
            &crate::sub_lib::migrations::dns_resolve_failure::MIGRATIONS,
            &data,
        ))
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct ProxyClientSubs {
    pub bind: Recipient<BindMessage>,
    pub from_hopper: Recipient<ExpiredCoresPackage<ClientRequestPayload_0v1>>,
    pub inbound_server_data: Recipient<InboundServerData>,
    pub dns_resolve_failed: Recipient<DnsResolveFailure_0v1>,
    pub node_from_ui: Recipient<NodeFromUiMessage>,
}

impl Debug for ProxyClientSubs {
    fn fmt(&self, f: &mut Formatter) -> Result<(), std::fmt::Error> {
        write!(f, "ProxyClientSubs")
    }
}

impl ClientResponsePayload_0v1 {
    pub fn make_terminating_payload(stream_key: StreamKey) -> ClientResponsePayload_0v1 {
        ClientResponsePayload_0v1 {
            stream_key,
            sequenced_packet: SequencedPacket {
                data: vec![],
                sequence_number: 0,
                last_data: true,
            },
        }
    }
}

#[derive(PartialEq, Eq, Clone, Message, Debug)]
pub struct InboundServerData {
    pub stream_key: StreamKey,
    pub last_data: bool,
    pub sequence_number: u64,
    pub source: SocketAddr,
    pub data: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sub_lib::peer_actors::BindMessage;
    use crate::test_utils::recorder::Recorder;
    use actix::Actor;

    #[test]
    fn make_terminating_payload_makes_terminating_payload() {
        let stream_key: StreamKey = StreamKey::make_meaningless_stream_key();

        let payload = ClientResponsePayload_0v1::make_terminating_payload(stream_key);

        assert_eq!(
            payload,
            ClientResponsePayload_0v1 {
                stream_key,
                sequenced_packet: SequencedPacket {
                    data: vec!(),
                    sequence_number: 0,
                    last_data: true
                },
            }
        )
    }

    #[test]
    fn proxy_client_subs_debug() {
        let recorder = Recorder::new().start();

        let subject = ProxyClientSubs {
            bind: recipient!(recorder, BindMessage),
            from_hopper: recipient!(recorder, ExpiredCoresPackage<ClientRequestPayload_0v1>),
            inbound_server_data: recipient!(recorder, InboundServerData),
            dns_resolve_failed: recipient!(recorder, DnsResolveFailure_0v1),
            node_from_ui: recipient!(recorder, NodeFromUiMessage),
        };

        assert_eq!(format!("{:?}", subject), "ProxyClientSubs");
    }
}
