// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use actix::Message;
use actix::Recipient;
use actix::Syn;
use cryptde::Key;
use node_addr::NodeAddr;
use peer_actors::BindMessage;
use std::net::IpAddr;
use route::Route;
use hopper::ExpiredCoresPackage;
use dispatcher::Component;
use std::net::Ipv4Addr;
use stream_handler_pool::TransmitDataMsg;
use stream_handler_pool::DispatcherNodeQueryResponse;
use hopper::ExpiredCoresPackagePackage;

pub const SENTINEL_IP_OCTETS: [u8; 4] = [255, 255, 255, 255];

pub fn sentinel_ip_addr () -> IpAddr {
    IpAddr::V4 (Ipv4Addr::new (
        SENTINEL_IP_OCTETS[0],
        SENTINEL_IP_OCTETS[1],
        SENTINEL_IP_OCTETS[2],
        SENTINEL_IP_OCTETS[3],
    ))
}

#[derive (Clone, PartialEq, Debug)]
pub struct NeighborhoodConfig {
    pub neighbor_configs: Vec<(Key, NodeAddr)>,
    pub bootstrap_configs: Vec<(Key, NodeAddr)>,
    pub is_bootstrap_node: bool,
    pub local_ip_addr: IpAddr,
    pub clandestine_port_list: Vec<u16>,
}

impl NeighborhoodConfig {
    pub fn is_decentralized (&self) -> bool {
        (!self.neighbor_configs.is_empty () || !self.bootstrap_configs.is_empty ()) &&
        (self.local_ip_addr != sentinel_ip_addr()) &&
        !self.clandestine_port_list.is_empty ()
    }
}

#[derive(Clone)]
pub struct NeighborhoodSubs {
    pub bind: Recipient<Syn, BindMessage>,
    pub bootstrap: Recipient<Syn, BootstrapNeighborhoodNowMessage>,
    pub node_query: Recipient<Syn, NodeQueryMessage>,
    pub route_query: Recipient<Syn, RouteQueryMessage>,
    pub from_hopper: Recipient<Syn, ExpiredCoresPackagePackage>,
    pub dispatcher_node_query: Recipient<Syn, DispatcherNodeQueryMessage>,
}

#[derive (Clone, Debug, PartialEq)]
pub struct NodeDescriptor {
    pub public_key: Key,
    pub node_addr_opt: Option<NodeAddr>,
}

impl NodeDescriptor {
    pub fn new (public_key: Key, node_addr_opt: Option<NodeAddr>) -> NodeDescriptor {
        NodeDescriptor {
            public_key, node_addr_opt
        }
    }
}

#[derive (Message, Clone)]
pub struct BootstrapNeighborhoodNowMessage {}

#[derive(Debug, PartialEq, Clone)]
pub enum NodeQueryMessage {
    IpAddress (IpAddr),
    PublicKey (Key),
}

impl Message for NodeQueryMessage {
    type Result = Option<NodeDescriptor>;
}

#[derive (Message, Clone)]
pub struct DispatcherNodeQueryMessage {
    pub query: NodeQueryMessage,
    pub context: TransmitDataMsg,
    pub recipient: Recipient<Syn, DispatcherNodeQueryResponse>,
}

#[derive (PartialEq, Clone, Debug, Copy)]
pub enum RouteType {
    OneWay,
    RoundTrip,
}

#[derive (PartialEq, Clone, Debug, Copy)]
pub enum TargetType {
    Bootstrap,
    Standard,
}

#[derive (PartialEq, Debug)]
pub struct RouteQueryMessage {
    pub route_type: RouteType,
    pub target_type: TargetType,
    pub target_key_opt: Option<Key>,
    pub target_component: Component,
    pub minimum_hop_count: usize,
    pub return_component_opt: Option<Component>,
}

impl Message for RouteQueryMessage {
    type Result = Option<RouteQueryResponse>;
}

impl RouteQueryMessage {
    pub fn gossip_route_request (target_key_ref: &Key, minimum_hop_count: usize) -> RouteQueryMessage {
        RouteQueryMessage {
            route_type: RouteType::OneWay,
            target_type: TargetType::Bootstrap,
            target_key_opt: Some (target_key_ref.clone ()),
            target_component: Component::Neighborhood,
            minimum_hop_count,
            return_component_opt: None,
        }
    }

    pub fn data_indefinite_route_request (minimum_hop_count: usize) -> RouteQueryMessage {
        RouteQueryMessage {
            route_type: RouteType::RoundTrip,
            target_type: TargetType::Standard,
            target_key_opt: None,
            target_component: Component::ProxyClient,
            minimum_hop_count,
            return_component_opt: Some (Component::ProxyServer),
        }
    }
}

#[derive (PartialEq, Debug, Clone)]
pub struct RouteQueryResponse {
    pub route: Route,
    pub segment_endpoints: Vec<Key>,
}

#[derive (PartialEq, Debug, Message)]
pub struct RemoveNodeMessage {
    pub public_key: Key,
}

impl RemoveNodeMessage {
    pub fn new (public_key: Key) -> RemoveNodeMessage {
        RemoveNodeMessage {
            public_key
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn gossip_route_request () {
        let target = Key::new (&b"booga"[..]);

        let result = RouteQueryMessage::gossip_route_request (&target, 2);

        assert_eq! (result, RouteQueryMessage {
            route_type: RouteType::OneWay,
            target_type: TargetType::Bootstrap,
            target_key_opt: Some (target),
            target_component: Component::Neighborhood,
            minimum_hop_count: 2,
            return_component_opt: None,
        });
    }

    #[test]
    fn data_indefinite_route_request () {

        let result = RouteQueryMessage::data_indefinite_route_request (2);

        assert_eq! (result, RouteQueryMessage {
            route_type: RouteType::RoundTrip,
            target_type: TargetType::Standard,
            target_key_opt: None,
            target_component: Component::ProxyClient,
            minimum_hop_count: 2,
            return_component_opt: Some (Component::ProxyServer),
        });
    }

    #[test]
    fn neighborhood_config_is_not_decentralized_if_there_are_neither_neighbor_configs_nor_bootstrap_configs () {
        let subject = NeighborhoodConfig {
            neighbor_configs: vec! (),
            bootstrap_configs: vec! (),
            is_bootstrap_node: false,
            local_ip_addr: IpAddr::from_str ("1.2.3.4").unwrap (),
            clandestine_port_list: vec! (1234),
        };

        let result = subject.is_decentralized ();

        assert_eq! (result, false);
    }

    #[test]
    fn neighborhood_config_is_not_decentralized_if_the_sentinel_ip_address_is_used () {
        let subject = NeighborhoodConfig {
            neighbor_configs: vec! ((Key::new (&b"key"[..]), NodeAddr::new (&IpAddr::from_str ("2.3.4.5").unwrap (), &vec! (2345)))),
            bootstrap_configs: vec! (),
            is_bootstrap_node: false,
            local_ip_addr: sentinel_ip_addr(),
            clandestine_port_list: vec! (1234),
        };

        let result = subject.is_decentralized ();

        assert_eq! (result, false);
    }

    #[test]
    fn neighborhood_config_is_not_decentralized_if_there_are_no_clandestine_ports () {
        let subject = NeighborhoodConfig {
            neighbor_configs: vec! ((Key::new (&b"key"[..]), NodeAddr::new (&IpAddr::from_str ("2.3.4.5").unwrap (), &vec! (2345)))),
            bootstrap_configs: vec! (),
            is_bootstrap_node: false,
            local_ip_addr: IpAddr::from_str ("1.2.3.4").unwrap (),
            clandestine_port_list: vec! (),
        };

        let result = subject.is_decentralized ();

        assert_eq! (result, false);
    }

    #[test]
    fn neighborhood_config_is_decentralized_if_neighbor_config_and_local_ip_addr_and_clandestine_port () {
        let subject = NeighborhoodConfig {
            neighbor_configs: vec! ((Key::new (&b"key"[..]), NodeAddr::new (&IpAddr::from_str ("2.3.4.5").unwrap (), &vec! (2345)))),
            bootstrap_configs: vec! (),
            is_bootstrap_node: false,
            local_ip_addr: IpAddr::from_str ("1.2.3.4").unwrap (),
            clandestine_port_list: vec! (1234),
        };

        let result = subject.is_decentralized ();

        assert_eq! (result, true);
    }

    #[test]
    fn neighborhood_config_is_decentralized_if_bootstrap_config_and_local_ip_addr_and_clandestine_port () {
        let subject = NeighborhoodConfig {
            neighbor_configs: vec! (),
            bootstrap_configs: vec! ((Key::new (&b"key"[..]), NodeAddr::new (&IpAddr::from_str ("2.3.4.5").unwrap (), &vec! (2345)))),
            is_bootstrap_node: false,
            local_ip_addr: IpAddr::from_str ("1.2.3.4").unwrap (),
            clandestine_port_list: vec! (1234),
        };

        let result = subject.is_decentralized ();

        assert_eq! (result, true);
    }
}