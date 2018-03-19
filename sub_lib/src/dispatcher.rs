// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use std::boxed::Box;
use std::marker::Send;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::fmt;
use std::fmt::Debug;
use std::fmt::Formatter;
use actix::Subscriber;
use actix::ResponseType;
use serde;
use serde::Serialize;
use serde::Deserialize;
use serde::Serializer;
use serde::Deserializer;
use serde::de::Visitor;
use cryptde::Key;
use peer_actors::BindMessage;
use stream_handler_pool::TransmitDataMsg;
use utils::to_string;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Component {
    Neighborhood,
    Hopper,
    ProxyServer,
    ProxyClient,
}

impl Serialize for Component {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S: Serializer {
        let index: u8 = match *self {
            Component::Neighborhood => 0,
            Component::Hopper => 1,
            Component::ProxyServer => 2,
            Component::ProxyClient => 3
        };
        serializer.serialize_u8(index)
    }
}

impl<'de> Deserialize<'de> for Component {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error> where D: Deserializer<'de> {
        deserializer.deserialize_u8 (ComponentVisitor)
    }
}

struct ComponentVisitor;

impl<'a> Visitor<'a> for ComponentVisitor {
    type Value = Component;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a Component enum")
    }

    fn visit_u8<E>(self, v: u8) -> Result<Self::Value, E> where E: serde::de::Error {
        match v {
            0 => Ok (Component::Neighborhood),
            1 => Ok (Component::Hopper),
            2 => Ok (Component::ProxyServer),
            3 => Ok (Component::ProxyClient),
            _ => Err(serde::de::Error::invalid_value(serde::de::Unexpected::Unsigned(v as u64), &self))
        }
    }
}

#[derive (Clone, PartialEq, Eq)]
pub enum Endpoint {
    Key (Key),
    Ip (IpAddr),
    Socket (SocketAddr)
}

impl fmt::Debug for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &Endpoint::Key (ref key) => write! (f, "Key({})", to_string (&key.data)),
            &Endpoint::Ip (ref ip_addr) => write! (f, "Ip({})", *ip_addr),
            &Endpoint::Socket (ref socket_addr) => write! (f, "Socket({})", *socket_addr)
        }
    }
}

impl Component {
    pub fn as_str(&self) -> &str {
        match self {
            &Component::Neighborhood => "NBHD",
            &Component::Hopper => "HOPR",
            &Component::ProxyServer => "PXSV",
            &Component::ProxyClient => "PXCL"
        }
    }

    pub fn values() -> Vec<Component> {
        vec!(
            Component::Neighborhood,
            Component::Hopper,
            Component::ProxyServer,
            Component::ProxyClient
        )
    }

    pub fn from_str(string: &str) -> Option<Component> {
        for candidate in Component::values() {
            if candidate.as_str() == string {
                return Some(candidate);
            }
        }
        return None;
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum DispatcherError {
    IpAddressUnknown,
    StreamConnectError (String),
    StreamWriteError (String),
    StreamShutdownError (String),
    NeighborhoodPanicked,
}

#[derive (PartialEq, Clone)]
pub struct InboundClientData {
    pub socket_addr: SocketAddr,
    pub component: Component,
    pub data: Vec<u8>
}

impl ResponseType for InboundClientData {
    type Item = ();
    type Error = ();
}

impl Debug for InboundClientData {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let data_string = match String::from_utf8 (self.data.clone ()) {
            Ok (string) => string,
            Err (_) => format! ("{:?}", &self.data[..])
        };
        write! (f, "InboundClientData {{ socket_addr: {:?}, component: {:?}, data: {} }}",
                self.socket_addr, self.component, data_string)
    }
}

pub struct DispatcherSubs {
    pub ibcd_sub: Box<Subscriber<InboundClientData> + Send>,
    pub bind: Box<Subscriber<BindMessage> + Send>,
    pub from_proxy_server: Box<Subscriber<TransmitDataMsg> +Send>,
}

impl Clone for DispatcherSubs {
    fn clone(&self) -> Self {
        DispatcherSubs {
            ibcd_sub: self.ibcd_sub.clone (),
            bind: self.bind.clone(),
            from_proxy_server: self.from_proxy_server.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;
    use serde_cbor;

    #[test]
    fn component_can_convert_to_string() {
        assert_eq!(Component::Neighborhood.as_str(), "NBHD");
        assert_eq!(Component::Hopper.as_str(), "HOPR");
        assert_eq!(Component::ProxyServer.as_str(), "PXSV");
        assert_eq!(Component::ProxyClient.as_str(), "PXCL")
    }

    #[test]
    fn component_can_convert_from_string() {
        assert_eq!(Component::from_str("NBHD"), Some(Component::Neighborhood));
        assert_eq!(Component::from_str("HOPR"), Some(Component::Hopper));
        assert_eq!(Component::from_str("PXSV"), Some(Component::ProxyServer));
        assert_eq!(Component::from_str("PXCL"), Some(Component::ProxyClient));
        assert_eq!(Component::from_str("BOOGA"), None);
    }

    #[test]
    fn debug_string_for_endpoint_with_utf8_key () {
        let subject = Endpoint::Key (Key::new (b"blah"));

        let result = format! ("{:?}", subject);

        assert_eq! (result, String::from ("Key(blah)"))
    }

    #[test]
    fn debug_string_for_endpoint_with_non_utf8_key () {
        let subject = Endpoint::Key (Key::new (&[192, 193]));

        let result = format! ("{:?}", subject);

        assert_eq! (result, String::from ("Key([192, 193])"))
    }

    #[test]
    fn debug_string_for_endpoint_with_ip () {
        let subject = Endpoint::Ip (IpAddr::from_str ("1.2.3.4").unwrap ());

        let result = format! ("{:?}", subject);

        assert_eq! (result, String::from ("Ip(1.2.3.4)"))
    }

    #[test]
    fn debug_string_for_endpoint_with_socket () {
        let subject = Endpoint::Socket (SocketAddr::from_str ("1.2.3.4:5678").unwrap ());

        let result = format! ("{:?}", subject);

        assert_eq! (result, String::from ("Socket(1.2.3.4:5678)"))
    }

    #[test]
    fn component_serializer_and_deserializer_talk_to_each_other () {
        let neighborhood_data = serde_cbor::ser::to_vec (&Component::Neighborhood).unwrap ();
        let hopper_data = serde_cbor::ser::to_vec (&Component::Hopper).unwrap ();
        let proxy_server_data = serde_cbor::ser::to_vec (&Component::ProxyServer).unwrap ();
        let proxy_client_data = serde_cbor::ser::to_vec (&Component::ProxyClient).unwrap ();

        let neighborhood_result = serde_cbor::de::from_slice::<Component> (&neighborhood_data[..]).unwrap ();
        let hopper_result = serde_cbor::de::from_slice::<Component> (&hopper_data[..]).unwrap ();
        let proxy_server_result = serde_cbor::de::from_slice::<Component> (&proxy_server_data[..]).unwrap ();
        let proxy_client_result = serde_cbor::de::from_slice::<Component> (&proxy_client_data[..]).unwrap ();

        assert_eq! (neighborhood_result, Component::Neighborhood);
        assert_eq! (hopper_result, Component::Hopper);
        assert_eq! (proxy_server_result, Component::ProxyServer);
        assert_eq! (proxy_client_result, Component::ProxyClient);
    }

    #[test]
    fn component_deserializer_handles_unrecognized_component () {
        let unrecognized_data: &[u8] = &[4];

        let unrecognized_result = serde_cbor::de::from_slice::<Component> (unrecognized_data);

        assert_eq! (format! ("{:?}", unrecognized_result), String::from ("Err(ErrorImpl { code: Message(\"invalid value: integer `4`, expected a Component enum\"), offset: 0 })"))
    }
}
