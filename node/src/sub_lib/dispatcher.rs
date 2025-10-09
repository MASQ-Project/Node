// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
use crate::proxy_server::http_protocol_pack::HttpProtocolPack;
use crate::stream_messages::RemovedStreamType;
use crate::sub_lib::cryptde::PublicKey;
use crate::sub_lib::peer_actors::{BindMessage, NewPublicIp};
use crate::sub_lib::stream_handler_pool::TransmitDataMsg;
use actix::Message;
use actix::Recipient;
use masq_lib::ui_gateway::NodeFromUiMessage;
use pretty_hex::PrettyHex;
use serde::de::Visitor;
use serde::Deserialize;
use serde::Deserializer;
use serde::Serialize;
use serde::Serializer;
use std::fmt;
use std::fmt::Debug;
use std::fmt::Formatter;
use std::net::SocketAddr;
use std::time::SystemTime;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Component {
    Neighborhood,
    Hopper,
    ProxyServer,
    ProxyClient,
}

impl Serialize for Component {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let index: u8 = match *self {
            Component::Neighborhood => 0,
            Component::Hopper => 1,
            Component::ProxyServer => 2,
            Component::ProxyClient => 3,
        };
        serializer.serialize_u8(index)
    }
}

impl<'de> Deserialize<'de> for Component {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_u8(ComponentVisitor)
    }
}

struct ComponentVisitor;

impl<'a> Visitor<'a> for ComponentVisitor {
    type Value = Component;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a Component enum")
    }

    fn visit_u8<E>(self, v: u8) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        match v {
            0 => Ok(Component::Neighborhood),
            1 => Ok(Component::Hopper),
            2 => Ok(Component::ProxyServer),
            3 => Ok(Component::ProxyClient),
            _ => Err(serde::de::Error::invalid_value(
                serde::de::Unexpected::Unsigned(u64::from(v)),
                &self,
            )),
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub enum Endpoint {
    Key(PublicKey),
    Socket(SocketAddr), // This SocketAddr can be either a neighbor Node or a browser stream, but not a server stream.
}

impl fmt::Debug for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Endpoint::Key(ref key) => write!(f, "PublicKey({})", key),
            Endpoint::Socket(ref socket_addr) => write!(f, "Socket({})", *socket_addr),
        }
    }
}

impl Component {
    pub fn values() -> Vec<Component> {
        vec![
            Component::Neighborhood,
            Component::Hopper,
            Component::ProxyServer,
            Component::ProxyClient,
        ]
    }
}

#[derive(Clone, Debug, Hash, Ord, PartialEq, Eq, PartialOrd)]
pub enum DispatcherError {
    IpAddressUnknown,
    StreamConnectError(String),
    StreamWriteError(String),
    StreamShutdownError(String),
    NeighborhoodPanicked,
}

#[derive(PartialEq, Eq, Clone, Message)]
pub struct InboundClientData {
    pub timestamp: SystemTime,
    pub client_addr: SocketAddr,
    pub reception_port_opt: Option<u16>,
    pub last_data: bool,
    pub is_clandestine: bool,
    pub sequence_number: Option<u64>,
    pub data: Vec<u8>,
}

impl Debug for InboundClientData {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let data_string = match String::from_utf8(self.data.clone()) {
            Ok(string) => string,
            Err(_) => self.data.hex_dump().to_string(),
        };
        write!(f, "InboundClientData {{ peer_addr: {:?}, reception_port: {:?}, last_data: {}, sequence_number: {:?}, {} bytes of data: {} }}",
               self.client_addr, self.reception_port_opt, self.last_data, self.sequence_number, self.data.len(), data_string)
    }
}

impl InboundClientData {
    pub fn clone_but_data(&self) -> InboundClientData {
        InboundClientData {
            timestamp: SystemTime::now(),
            client_addr: self.client_addr,
            reception_port_opt: self.reception_port_opt,
            last_data: self.last_data,
            is_clandestine: self.is_clandestine,
            sequence_number: self.sequence_number,
            data: vec![],
        }
    }

    pub fn is_connect(&self) -> bool {
        HttpProtocolPack::is_connect(self.data.as_slice())
    }
}

#[derive(PartialEq, Eq, Clone, Message, Debug)]
pub struct StreamShutdownMsg {
    pub peer_addr: SocketAddr,
    pub stream_type: RemovedStreamType,
    pub report_to_counterpart: bool,
}

#[derive(PartialEq, Eq)]
pub struct DispatcherSubs {
    pub ibcd_sub: Recipient<InboundClientData>,
    pub bind: Recipient<BindMessage>,
    pub from_dispatcher_client: Recipient<TransmitDataMsg>,
    pub stream_shutdown_sub: Recipient<StreamShutdownMsg>,
    pub ui_sub: Recipient<NodeFromUiMessage>,
    pub new_ip_sub: Recipient<NewPublicIp>,
}

impl Debug for DispatcherSubs {
    fn fmt(&self, f: &mut Formatter) -> Result<(), std::fmt::Error> {
        write!(f, "DispatcherSubs")
    }
}

impl Clone for DispatcherSubs {
    fn clone(&self) -> Self {
        DispatcherSubs {
            ibcd_sub: self.ibcd_sub.clone(),
            bind: self.bind.clone(),
            from_dispatcher_client: self.from_dispatcher_client.clone(),
            stream_shutdown_sub: self.stream_shutdown_sub.clone(),
            ui_sub: self.ui_sub.clone(),
            new_ip_sub: self.new_ip_sub.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::recorder::Recorder;
    use actix::Actor;
    use serde_cbor;
    use std::str::FromStr;

    #[test]
    fn dispatcher_subs_debug() {
        let addr = Recorder::new().start();

        let subject = DispatcherSubs {
            ibcd_sub: recipient!(addr, InboundClientData),
            bind: recipient!(addr, BindMessage),
            from_dispatcher_client: recipient!(addr, TransmitDataMsg),
            stream_shutdown_sub: recipient!(addr, StreamShutdownMsg),
            ui_sub: recipient!(addr, NodeFromUiMessage),
            new_ip_sub: recipient!(addr, NewPublicIp),
        };

        assert_eq!(format!("{:?}", subject), "DispatcherSubs");
    }

    #[test]
    fn debug_string_for_endpoint_with_utf8_key() {
        let subject = Endpoint::Key(PublicKey::new(b"blah"));

        let result = format!("{:?}", subject);

        assert_eq!(result, String::from("PublicKey(YmxhaA)"))
    }

    #[test]
    fn debug_string_for_endpoint_with_non_utf8_key() {
        let subject = Endpoint::Key(PublicKey::new(&[192, 193]));

        let result = format!("{:?}", subject);

        assert_eq!(result, String::from("PublicKey(wME)"))
    }

    #[test]
    fn debug_string_for_endpoint_with_socket() {
        let subject = Endpoint::Socket(SocketAddr::from_str("1.2.3.4:5678").unwrap());

        let result = format!("{:?}", subject);

        assert_eq!(result, String::from("Socket(1.2.3.4:5678)"))
    }

    #[test]
    fn component_serializer_and_deserializer_talk_to_each_other() {
        let neighborhood_data = serde_cbor::ser::to_vec(&Component::Neighborhood).unwrap();
        let hopper_data = serde_cbor::ser::to_vec(&Component::Hopper).unwrap();
        let proxy_server_data = serde_cbor::ser::to_vec(&Component::ProxyServer).unwrap();
        let proxy_client_data = serde_cbor::ser::to_vec(&Component::ProxyClient).unwrap();

        let neighborhood_result =
            serde_cbor::de::from_slice::<Component>(&neighborhood_data[..]).unwrap();
        let hopper_result = serde_cbor::de::from_slice::<Component>(&hopper_data[..]).unwrap();
        let proxy_server_result =
            serde_cbor::de::from_slice::<Component>(&proxy_server_data[..]).unwrap();
        let proxy_client_result =
            serde_cbor::de::from_slice::<Component>(&proxy_client_data[..]).unwrap();

        assert_eq!(neighborhood_result, Component::Neighborhood);
        assert_eq!(hopper_result, Component::Hopper);
        assert_eq!(proxy_server_result, Component::ProxyServer);
        assert_eq!(proxy_client_result, Component::ProxyClient);
    }

    #[test]
    fn component_deserializer_handles_unrecognized_component() {
        let unrecognized_data: &[u8] = &[4];

        let unrecognized_result = serde_cbor::de::from_slice::<Component>(unrecognized_data);

        assert_eq!(format!("{:?}", unrecognized_result), String::from("Err(ErrorImpl { code: Message(\"invalid value: integer `4`, expected a Component enum\"), offset: 0 })"))
    }

    #[test]
    fn inbound_client_data_is_identifiable_as_a_connect() {
        let subject = InboundClientData {
            timestamp: SystemTime::now(),
            client_addr: SocketAddr::from_str("1.4.3.2:9999").unwrap(),
            reception_port_opt: None,
            last_data: false,
            is_clandestine: false,
            sequence_number: None,
            data: b"CONNECT server.example.com:80 HTTP/1.1\r\nHost: server.example.com:80\r\nProxy-Authorization: basic aGVsbG86d29ybGQ=\r\n\r\n".to_vec(),
        };

        assert!(subject.is_connect());
    }

    #[test]
    fn inbound_client_data_is_not_connect() {
        let subject = InboundClientData {
            timestamp: SystemTime::now(),
            client_addr: SocketAddr::from_str("1.4.3.2:9999").unwrap(),
            reception_port_opt: None,
            last_data: false,
            is_clandestine: false,
            sequence_number: None,
            data: b"GET server.example.com:80 HTTP/1.1\r\nHost: server.example.com:80\r\nProxy-Authorization: basic aGVsbG86d29ybGQ=\r\n\r\n".to_vec(),
        };

        assert!(!subject.is_connect());
    }

    #[test]
    fn inbound_client_data_not_connect_if_no_space_after_method() {
        let subject = InboundClientData {
            timestamp: SystemTime::now(),
            client_addr: SocketAddr::from_str("1.4.3.2:9999").unwrap(),
            reception_port_opt: None,
            last_data: false,
            is_clandestine: false,
            sequence_number: None,
            data: b"CONNECTX".to_vec(),
        };

        assert!(!subject.is_connect());
    }
}
