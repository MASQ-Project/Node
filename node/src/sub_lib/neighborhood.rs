// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use crate::neighborhood::gossip::Gossip;
use crate::sub_lib::cryptde::{CryptDE, PublicKey};
use crate::sub_lib::dispatcher::{Component, StreamShutdownMsg};
use crate::sub_lib::hopper::ExpiredCoresPackage;
use crate::sub_lib::node_addr::NodeAddr;
use crate::sub_lib::peer_actors::BindMessage;
use crate::sub_lib::route::Route;
use crate::sub_lib::stream_handler_pool::DispatcherNodeQueryResponse;
use crate::sub_lib::stream_handler_pool::TransmitDataMsg;
use crate::sub_lib::wallet::Wallet;
use actix::Message;
use actix::Recipient;
use serde_derive::{Deserialize, Serialize};
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::str::FromStr;

pub const SENTINEL_IP_OCTETS: [u8; 4] = [255, 255, 255, 255];

pub const DEFAULT_RATE_PACK: RatePack = RatePack {
    routing_byte_rate: 100,
    routing_service_rate: 10000,
    exit_byte_rate: 101,
    exit_service_rate: 10001,
};

pub const ZERO_RATE_PACK: RatePack = RatePack {
    routing_byte_rate: 0,
    routing_service_rate: 0,
    exit_byte_rate: 0,
    exit_service_rate: 0,
};

pub fn sentinel_ip_addr() -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(
        SENTINEL_IP_OCTETS[0],
        SENTINEL_IP_OCTETS[1],
        SENTINEL_IP_OCTETS[2],
        SENTINEL_IP_OCTETS[3],
    ))
}

#[derive(Clone, PartialEq, Debug)]
pub struct NodeDescriptor {
    pub public_key: PublicKey,
    pub node_addr: NodeAddr,
}

impl NodeDescriptor {
    pub fn from_str(cryptde: &CryptDE, s: &str) -> Result<NodeDescriptor, String> {
        let pieces: Vec<&str> = s.splitn(2, ":").collect();

        if pieces.len() != 2 {
            return Err(String::from(s));
        }

        let public_key = match cryptde.descriptor_fragment_to_first_contact_public_key(pieces[0]) {
            Err(e) => return Err(format!("{}", e)),
            Ok(hpk) => hpk,
        };

        let node_addr = match NodeAddr::from_str(&pieces[1]) {
            Err(_) => return Err(String::from(s)),
            Ok(node_addr) => node_addr,
        };

        Ok(NodeDescriptor {
            public_key,
            node_addr,
        })
    }

    pub fn to_string(&self, cryptde: &CryptDE) -> String {
        let contact_public_key_string = cryptde.public_key_to_descriptor_fragment(&self.public_key);
        let node_addr_string = self.node_addr.to_string();
        format!("{}:{}", contact_public_key_string, node_addr_string)
    }
}

#[derive(Clone, PartialEq, Debug)]
pub struct NeighborhoodConfig {
    pub neighbor_configs: Vec<String>,
    pub local_ip_addr: IpAddr,
    pub clandestine_port_list: Vec<u16>,
    pub rate_pack: RatePack,
}

impl NeighborhoodConfig {
    pub fn is_decentralized(&self) -> bool {
        (self.local_ip_addr != sentinel_ip_addr()) && !self.clandestine_port_list.is_empty()
    }
}

#[derive(Clone)]
pub struct NeighborhoodSubs {
    pub bind: Recipient<BindMessage>,
    pub bootstrap: Recipient<BootstrapNeighborhoodNowMessage>,
    pub node_query: Recipient<NodeQueryMessage>,
    pub route_query: Recipient<RouteQueryMessage>,
    pub update_node_record_metadata: Recipient<NodeRecordMetadataMessage>,
    pub from_hopper: Recipient<ExpiredCoresPackage<Gossip>>,
    pub dispatcher_node_query: Recipient<DispatcherNodeQueryMessage>,
    pub remove_neighbor: Recipient<RemoveNeighborMessage>,
    pub stream_shutdown_sub: Recipient<StreamShutdownMsg>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct NodeQueryResponseMetadata {
    pub public_key: PublicKey,
    pub node_addr_opt: Option<NodeAddr>,
    pub rate_pack: RatePack,
}

impl NodeQueryResponseMetadata {
    pub fn new(
        public_key: PublicKey,
        node_addr_opt: Option<NodeAddr>,
        rate_pack: RatePack,
    ) -> NodeQueryResponseMetadata {
        NodeQueryResponseMetadata {
            public_key,
            node_addr_opt,
            rate_pack,
        }
    }
}

#[derive(Message, Clone)]
pub struct BootstrapNeighborhoodNowMessage {}

#[derive(Debug, PartialEq, Clone)]
pub enum NodeQueryMessage {
    IpAddress(IpAddr),
    PublicKey(PublicKey),
}

impl Message for NodeQueryMessage {
    type Result = Option<NodeQueryResponseMetadata>;
}

#[derive(Message, Clone)]
pub struct DispatcherNodeQueryMessage {
    pub query: NodeQueryMessage,
    pub context: TransmitDataMsg,
    pub recipient: Recipient<DispatcherNodeQueryResponse>,
}

#[derive(PartialEq, Debug)]
pub struct RouteQueryMessage {
    pub target_key_opt: Option<PublicKey>,
    pub target_component: Component,
    pub minimum_hop_count: usize,
    pub return_component_opt: Option<Component>,
}

impl Message for RouteQueryMessage {
    type Result = Option<RouteQueryResponse>;
}

impl RouteQueryMessage {
    pub fn data_indefinite_route_request(minimum_hop_count: usize) -> RouteQueryMessage {
        RouteQueryMessage {
            target_key_opt: None,
            target_component: Component::ProxyClient,
            minimum_hop_count,
            return_component_opt: Some(Component::ProxyServer),
        }
    }
}

#[derive(PartialEq, Eq, Debug, Clone)]
pub enum ExpectedService {
    Routing(PublicKey, Wallet, RatePack),
    Exit(PublicKey, Wallet, RatePack),
    Nothing,
}

#[derive(PartialEq, Debug, Clone)]
pub enum ExpectedServices {
    OneWay(Vec<ExpectedService>),
    RoundTrip(Vec<ExpectedService>, Vec<ExpectedService>, u32),
}

#[derive(PartialEq, Debug, Clone)]
pub struct RouteQueryResponse {
    pub route: Route,
    pub expected_services: ExpectedServices,
}

#[derive(PartialEq, Debug, Message, Clone)]
pub struct RemoveNeighborMessage {
    pub public_key: PublicKey,
}

#[derive(PartialEq, Debug, Message, Clone)]
pub enum NodeRecordMetadataMessage {
    Desirable(PublicKey, bool),
}

#[derive(Clone, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub struct RatePack {
    pub routing_byte_rate: u64,
    pub routing_service_rate: u64,
    pub exit_byte_rate: u64,
    pub exit_service_rate: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sub_lib::cryptde_null::CryptDENull;
    use std::str::FromStr;

    pub fn rate_pack(base_rate: u64) -> RatePack {
        RatePack {
            routing_byte_rate: base_rate + 1,
            routing_service_rate: base_rate + 2,
            exit_byte_rate: base_rate + 3,
            exit_service_rate: base_rate + 4,
        }
    }

    #[test]
    fn node_descriptor_from_str_requires_two_pieces_to_a_configuration() {
        let result = NodeDescriptor::from_str(&CryptDENull::new(), "only_one_piece");

        assert_eq!(result, Err(String::from("only_one_piece")));
    }

    #[test]
    fn node_descriptor_from_str_complains_about_bad_base_64() {
        let result = NodeDescriptor::from_str(&CryptDENull::new(), "bad_key:1.2.3.4:1234;2345");

        assert_eq!(
            result,
            Err(String::from("Invalid Base64 value for public key: bad_key"))
        );
    }

    #[test]
    fn node_descriptor_from_str_complains_about_blank_public_key() {
        let result = NodeDescriptor::from_str(&CryptDENull::new(), ":1.2.3.4:1234;2345");

        assert_eq!(result, Err(String::from("Public key cannot be empty")));
    }

    #[test]
    fn node_descriptor_from_str_complains_about_bad_node_addr() {
        let result = NodeDescriptor::from_str(&CryptDENull::new(), "R29vZEtleQ==:BadNodeAddr");

        assert_eq!(result, Err(String::from("R29vZEtleQ==:BadNodeAddr")));
    }

    #[test]
    fn node_descriptor_from_str_handles_the_happy_path() {
        let result =
            NodeDescriptor::from_str(&CryptDENull::new(), "R29vZEtleQ:1.2.3.4:1234;2345;3456");

        assert_eq!(
            result.unwrap(),
            NodeDescriptor {
                public_key: PublicKey::new(b"GoodKey"),
                node_addr: NodeAddr::new(
                    &IpAddr::from_str("1.2.3.4").unwrap(),
                    &vec!(1234, 2345, 3456),
                )
            },
        )
    }

    #[test]
    fn data_indefinite_route_request() {
        let result = RouteQueryMessage::data_indefinite_route_request(2);

        assert_eq!(
            result,
            RouteQueryMessage {
                target_key_opt: None,
                target_component: Component::ProxyClient,
                minimum_hop_count: 2,
                return_component_opt: Some(Component::ProxyServer),
            }
        );
    }

    #[test]
    fn neighborhood_config_is_not_decentralized_if_the_sentinel_ip_address_is_used() {
        let subject = NeighborhoodConfig {
            neighbor_configs: vec!["booga".to_string()],
            rate_pack: rate_pack(100),
            local_ip_addr: sentinel_ip_addr(),
            clandestine_port_list: vec![1234],
        };

        let result = subject.is_decentralized();

        assert_eq!(result, false);
    }

    #[test]
    fn neighborhood_config_is_not_decentralized_if_there_are_no_clandestine_ports() {
        let subject = NeighborhoodConfig {
            neighbor_configs: vec!["booga".to_string()],
            rate_pack: rate_pack(100),
            local_ip_addr: IpAddr::from_str("1.2.3.4").unwrap(),
            clandestine_port_list: vec![],
        };

        let result = subject.is_decentralized();

        assert_eq!(result, false);
    }

    #[test]
    fn neighborhood_config_is_decentralized_if_local_ip_addr_and_clandestine_port() {
        let subject = NeighborhoodConfig {
            neighbor_configs: vec![],
            rate_pack: rate_pack(100),
            local_ip_addr: IpAddr::from_str("1.2.3.4").unwrap(),
            clandestine_port_list: vec![1234],
        };

        let result = subject.is_decentralized();

        assert_eq!(result, true);
    }
}
