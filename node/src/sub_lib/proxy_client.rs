// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use crate::sub_lib::cryptde::CryptDE;
use crate::sub_lib::data_version::DataVersion;
use crate::sub_lib::hopper::{ExpiredCoresPackage, MessageType};
use crate::sub_lib::peer_actors::BindMessage;
use crate::sub_lib::proxy_server::ClientRequestPayload;
use crate::sub_lib::sequence_buffer::SequencedPacket;
use crate::sub_lib::stream_key::StreamKey;
use actix::Message;
use actix::Recipient;
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
    pub cryptde: &'static dyn CryptDE,
    pub dns_servers: Vec<SocketAddr>,
    pub exit_service_rate: u64,
    pub exit_byte_rate: u64,
}

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub struct ClientResponsePayload {
    pub version: DataVersion,
    pub stream_key: StreamKey,
    pub sequenced_packet: SequencedPacket,
}

#[derive(Message, Clone, Debug, PartialEq, Deserialize, Serialize)]
pub struct DnsResolveFailure {
    pub version: DataVersion,
    pub stream_key: StreamKey,
}

impl DnsResolveFailure {
    pub fn version() -> DataVersion {
        DataVersion::new(0, 0).expect("Internal Error")
    }

    pub fn new(stream_key: StreamKey) -> Self {
        Self {
            version: Self::version(),
            stream_key,
        }
    }
}

impl Into<MessageType> for ClientResponsePayload {
    fn into(self) -> MessageType {
        MessageType::ClientResponse(self)
    }
}

impl Into<MessageType> for DnsResolveFailure {
    fn into(self) -> MessageType {
        MessageType::DnsResolveFailed(self)
    }
}

#[derive(Clone)]
pub struct ProxyClientSubs {
    pub bind: Recipient<BindMessage>,
    pub from_hopper: Recipient<ExpiredCoresPackage<ClientRequestPayload>>,
    pub inbound_server_data: Recipient<InboundServerData>,
    pub dns_resolve_failed: Recipient<DnsResolveFailure>,
}

impl Debug for ProxyClientSubs {
    fn fmt(&self, f: &mut Formatter) -> Result<(), std::fmt::Error> {
        write!(f, "ProxyClientSubs")
    }
}

impl ClientResponsePayload {
    pub fn make_terminating_payload(stream_key: StreamKey) -> ClientResponsePayload {
        ClientResponsePayload {
            version: Self::version(),
            stream_key,
            sequenced_packet: SequencedPacket {
                data: vec![],
                sequence_number: 0,
                last_data: true,
            },
        }
    }

    pub fn version() -> DataVersion {
        DataVersion::new(0, 0).expect("Internal Error")
    }
}

#[derive(PartialEq, Clone, Message, Debug)]
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
    use crate::test_utils::make_meaningless_stream_key;
    use crate::test_utils::recorder::Recorder;
    use actix::Actor;

    #[test]
    fn make_terminating_payload_makes_terminating_payload() {
        let stream_key: StreamKey = make_meaningless_stream_key();

        let payload = ClientResponsePayload::make_terminating_payload(stream_key);

        assert_eq!(
            payload,
            ClientResponsePayload {
                version: ClientResponsePayload::version(),
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
            from_hopper: recipient!(recorder, ExpiredCoresPackage<ClientRequestPayload>),
            inbound_server_data: recipient!(recorder, InboundServerData),
            dns_resolve_failed: recipient!(recorder, DnsResolveFailure),
        };

        assert_eq!(format!("{:?}", subject), "ProxyClientSubs");
    }
}
