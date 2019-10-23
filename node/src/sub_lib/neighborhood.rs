// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use crate::neighborhood::gossip::Gossip;
use crate::neighborhood::node_record::NodeRecord;
use crate::sub_lib::cryptde::{CryptDE, PublicKey};
use crate::sub_lib::dispatcher::{Component, StreamShutdownMsg};
use crate::sub_lib::hopper::ExpiredCoresPackage;
use crate::sub_lib::node_addr::NodeAddr;
use crate::sub_lib::peer_actors::{BindMessage, StartMessage};
use crate::sub_lib::route::Route;
use crate::sub_lib::set_consuming_wallet_message::SetConsumingWalletMessage;
use crate::sub_lib::stream_handler_pool::DispatcherNodeQueryResponse;
use crate::sub_lib::stream_handler_pool::TransmitDataMsg;
use crate::sub_lib::utils::node_descriptor_delimiter;
use crate::sub_lib::wallet::Wallet;
use actix::Message;
use actix::Recipient;
use core::fmt;
use lazy_static::lazy_static;
use serde_derive::{Deserialize, Serialize};
use std::fmt::{Debug, Formatter};
use std::net::IpAddr;
use std::str::FromStr;
use crate::blockchain::blockchain_interface::chain_id_from_name;

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

#[derive(Clone, Debug, PartialEq)]
pub enum NeighborhoodMode {
    // TODO: These Vec<String>s should now be able to be converted to Vec<NodeDescriptor>s.
    Standard(NodeAddr, Vec<String>, RatePack),
    ZeroHop,
    OriginateOnly(Vec<String>, RatePack),
    ConsumeOnly(Vec<String>),
}

impl NeighborhoodMode {
    pub fn is_decentralized(&self) -> bool {
        self != &NeighborhoodMode::ZeroHop
    }

    pub fn neighbor_configs(&self) -> &Vec<String> {
        match self {
            NeighborhoodMode::Standard(_, neighbor_configs, _) => neighbor_configs,
            NeighborhoodMode::ZeroHop => &EMPTY_CONFIGS,
            NeighborhoodMode::OriginateOnly(neighbor_configs, _) => neighbor_configs,
            NeighborhoodMode::ConsumeOnly(neighbor_configs) => neighbor_configs,
        }
    }

    pub fn node_addr_opt(&self) -> Option<NodeAddr> {
        match self {
            NeighborhoodMode::Standard(node_addr, _, _) => Some(node_addr.clone()),
            _ => None,
        }
    }

    pub fn rate_pack(&self) -> &RatePack {
        match self {
            NeighborhoodMode::Standard(_, _, rate_pack) => rate_pack,
            NeighborhoodMode::OriginateOnly(_, rate_pack) => rate_pack,
            _ => &ZERO_RATE_PACK,
        }
    }

    pub fn accepts_connections(&self) -> bool {
        match self {
            NeighborhoodMode::Standard(_, _, _) => true,
            _ => false,
        }
    }

    pub fn routes_data(&self) -> bool {
        match self {
            NeighborhoodMode::Standard(_, _, _) => true,
            NeighborhoodMode::OriginateOnly(_, _) => true,
            _ => false,
        }
    }

    pub fn is_standard(&self) -> bool {
        match self {
            NeighborhoodMode::Standard(_, _, _) => true,
            _ => false,
        }
    }

    pub fn is_originate_only(&self) -> bool {
        match self {
            NeighborhoodMode::OriginateOnly(_, _) => true,
            _ => false,
        }
    }

    pub fn is_consume_only(&self) -> bool {
        match self {
            NeighborhoodMode::ConsumeOnly(_) => true,
            _ => false,
        }
    }

    pub fn is_zero_hop(&self) -> bool {
        match self {
            NeighborhoodMode::ZeroHop => true,
            _ => false,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct NodeDescriptor {
    pub public_key: PublicKey,
    pub mainnet: bool,
    pub node_addr_opt: Option<NodeAddr>,
}

impl From<(&PublicKey, &NodeAddr, bool)> for NodeDescriptor {
    fn from(triple: (&PublicKey, &NodeAddr, bool)) -> Self {
        let (public_key, node_addr, mainnet) = triple;
        NodeDescriptor {
            public_key: public_key.clone(),
            mainnet,
            node_addr_opt: Some(node_addr.clone()),
        }
    }
}

impl From<(&PublicKey, bool)> for NodeDescriptor {
    fn from(pair: (&PublicKey, bool)) -> Self {
        let (public_key, mainnet) = pair;
        NodeDescriptor {
            public_key: public_key.clone(),
            mainnet,
            node_addr_opt: None,
        }
    }
}

impl From<(&NodeRecord, bool)> for NodeDescriptor {
    fn from(pair: (&NodeRecord, bool)) -> Self {
        let (node_record, mainnet) = pair;
        NodeDescriptor {
            public_key: node_record.public_key().clone(),
            mainnet,
            node_addr_opt: node_record.node_addr_opt(),
        }
    }
}

impl NodeDescriptor {
    pub fn from_str(
        cryptde: &dyn CryptDE,
        s: &str,
    ) -> Result<NodeDescriptor, String> {
        let (mainnet, pieces) = {
            let chain_id = chain_id_from_name("mainnet");
            let delimiter = node_descriptor_delimiter(chain_id);
            let pieces: Vec<&str> = s.splitn(2, delimiter).collect();
            if pieces.len() == 2 {
                (true, pieces)
            }
            else {
                let chain_id = chain_id_from_name("testnet");
                let delimiter = node_descriptor_delimiter(chain_id);
                let pieces: Vec<&str> = s.splitn(2, delimiter).collect();
                if pieces.len() == 2 {
                    (false, pieces)
                }
                else {
                    return Err(format!(
                        "Should be <public key>[@ | :]<node address>, not '{}'",
                        s
                    ));
                }
            }
        };

        let public_key = match cryptde.descriptor_fragment_to_first_contact_public_key(pieces[0]) {
            Err(e) => return Err(e),
            Ok(hpk) => hpk,
        };

        let node_addr_opt = {
            if pieces[1] == ":" {
                None
            } else {
                match NodeAddr::from_str(&pieces[1]) {
                    Err(e) => return Err(e),
                    Ok(node_addr) => Some(node_addr),
                }
            }
        };

        Ok(NodeDescriptor {
            public_key,
            mainnet,
            node_addr_opt,
        })
    }

    pub fn to_string(&self, cryptde: &dyn CryptDE) -> String {
        let contact_public_key_string = cryptde.public_key_to_descriptor_fragment(&self.public_key);
        let node_addr_string = match &self.node_addr_opt {
            Some(node_addr) => node_addr.to_string(),
            None => ":".to_string(),
        };
        let delimiter = if self.mainnet {"@"} else {":"};
        format!(
            "{}{}{}",
            contact_public_key_string, delimiter, node_addr_string
        )
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct NeighborhoodConfig {
    pub mode: NeighborhoodMode,
}

lazy_static! {
    static ref EMPTY_CONFIGS: Vec<String> = vec![];
}

#[derive(Clone)]
pub struct NeighborhoodSubs {
    pub bind: Recipient<BindMessage>,
    pub start: Recipient<StartMessage>,
    pub node_query: Recipient<NodeQueryMessage>,
    pub route_query: Recipient<RouteQueryMessage>,
    pub update_node_record_metadata: Recipient<NodeRecordMetadataMessage>,
    pub from_hopper: Recipient<ExpiredCoresPackage<Gossip>>,
    pub gossip_failure: Recipient<ExpiredCoresPackage<GossipFailure>>,
    pub dispatcher_node_query: Recipient<DispatcherNodeQueryMessage>,
    pub remove_neighbor: Recipient<RemoveNeighborMessage>,
    pub stream_shutdown_sub: Recipient<StreamShutdownMsg>,
    pub set_consuming_wallet_sub: Recipient<SetConsumingWalletMessage>,
    pub from_ui_gateway: Recipient<NeighborhoodDotGraphRequest>,
}

impl Debug for NeighborhoodSubs {
    fn fmt(&self, f: &mut Formatter) -> Result<(), std::fmt::Error> {
        write!(f, "NeighborhoodSubs")
    }
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

#[derive(Clone, Debug, Message, PartialEq)]
pub struct BootstrapNeighborhoodNowMessage {}

#[derive(Clone, Debug, Message, PartialEq)]
pub struct NeighborhoodDotGraphRequest {
    pub client_id: u64,
}

#[derive(Clone, Debug, PartialEq)]
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

#[derive(Debug, PartialEq)]
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExpectedService {
    Routing(PublicKey, Wallet, RatePack),
    Exit(PublicKey, Wallet, RatePack),
    Nothing,
}

#[derive(Clone, Debug, PartialEq)]
pub enum ExpectedServices {
    OneWay(Vec<ExpectedService>),
    RoundTrip(Vec<ExpectedService>, Vec<ExpectedService>, u32),
}

#[derive(Clone, Debug, PartialEq)]
pub struct RouteQueryResponse {
    pub route: Route,
    pub expected_services: ExpectedServices,
}

#[derive(Clone, Debug, Message, PartialEq)]
pub struct RemoveNeighborMessage {
    pub public_key: PublicKey,
}

#[derive(Clone, Debug, Message, PartialEq)]
pub enum NodeRecordMetadataMessage {
    Desirable(PublicKey, bool),
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct RatePack {
    pub routing_byte_rate: u64,
    pub routing_service_rate: u64,
    pub exit_byte_rate: u64,
    pub exit_service_rate: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum GossipFailure {
    NoNeighbors,
    NoSuitableNeighbors,
    ManualRejection,
}

impl fmt::Display for GossipFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        let msg = match self {
            GossipFailure::NoNeighbors => "No neighbors for Introduction or Pass",
            GossipFailure::NoSuitableNeighbors => {
                "No neighbors were suitable for Introduction or Pass"
            }
            GossipFailure::ManualRejection => "Node owner manually rejected your Debut",
        };
        write!(f, "{}", msg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sub_lib::utils::localhost;
    use crate::test_utils::recorder::Recorder;
    use crate::test_utils::{main_cryptde};
    use actix::Actor;
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
    fn neighborhood_subs_debug() {
        let recorder = Recorder::new().start();

        let subject = NeighborhoodSubs {
            bind: recipient!(recorder, BindMessage),
            start: recipient!(recorder, StartMessage),
            node_query: recipient!(recorder, NodeQueryMessage),
            route_query: recipient!(recorder, RouteQueryMessage),
            update_node_record_metadata: recipient!(recorder, NodeRecordMetadataMessage),
            from_hopper: recipient!(recorder, ExpiredCoresPackage<Gossip>),
            gossip_failure: recipient!(recorder, ExpiredCoresPackage<GossipFailure>),
            dispatcher_node_query: recipient!(recorder, DispatcherNodeQueryMessage),
            remove_neighbor: recipient!(recorder, RemoveNeighborMessage),
            stream_shutdown_sub: recipient!(recorder, StreamShutdownMsg),
            set_consuming_wallet_sub: recipient!(recorder, SetConsumingWalletMessage),
            from_ui_gateway: recipient!(recorder, NeighborhoodDotGraphRequest),
        };

        assert_eq!(format!("{:?}", subject), "NeighborhoodSubs");
    }

    #[test]
    fn node_descriptor_from_str_requires_two_pieces_to_a_configuration() {
        let result = NodeDescriptor::from_str(main_cryptde(), "only_one_piece");

        assert_eq!(
            result,
            Err(String::from(
                "Should be <public key>[@ | :]<node address>, not 'only_one_piece'"
            ))
        );
    }

    #[test]
    fn node_descriptor_from_str_complains_about_bad_base_64() {
        let result = NodeDescriptor::from_str(
            main_cryptde(),
            "bad_key:1.2.3.4:1234;2345",
        );

        assert_eq!(
            result,
            Err(String::from("Invalid Base64 value for public key: bad_key"))
        );
    }

    #[test]
    fn node_descriptor_from_str_complains_about_blank_public_key() {
        let result =
            NodeDescriptor::from_str(main_cryptde(), ":1.2.3.4:1234;2345");

        assert_eq!(result, Err(String::from("Public key cannot be empty")));
    }

    #[test]
    fn node_descriptor_from_str_complains_about_bad_node_addr() {
        let result =
            NodeDescriptor::from_str(main_cryptde(), "R29vZEtleQ==:BadNodeAddr");

        assert_eq!(result, Err(String::from("NodeAddr should be expressed as '<IP address>:<port>;<port>,...', not 'BadNodeAddr'")));
    }

    #[test]
    fn node_descriptor_from_str_handles_the_happy_path_with_node_addr() {
        let result = NodeDescriptor::from_str(
            main_cryptde(),
            "R29vZEtleQ:1.2.3.4:1234;2345;3456",
        );

        assert_eq!(
            result.unwrap(),
            NodeDescriptor {
                public_key: PublicKey::new(b"GoodKey"),
                mainnet: false,
                node_addr_opt: Some(NodeAddr::new(
                    &IpAddr::from_str("1.2.3.4").unwrap(),
                    &vec!(1234, 2345, 3456),
                ))
            },
        )
    }

    #[test]
    fn node_descriptor_from_str_handles_the_happy_path_without_node_addr() {
        let result = NodeDescriptor::from_str(main_cryptde(), "R29vZEtleQ::");

        assert_eq!(
            result.unwrap(),
            NodeDescriptor {
                public_key: PublicKey::new(b"GoodKey"),
                mainnet: false,
                node_addr_opt: None
            },
        )
    }

    #[test]
    fn node_descriptor_from_str_accepts_mainnet_delimiter() {
        let result = NodeDescriptor::from_str(
            main_cryptde(),
            "R29vZEtleQ@1.2.3.4:1234;2345;3456",
        );

        assert_eq!(
            result.unwrap(),
            NodeDescriptor {
                public_key: PublicKey::new(b"GoodKey"),
                mainnet: true,
                node_addr_opt: Some(NodeAddr::new(
                    &IpAddr::from_str("1.2.3.4").unwrap(),
                    &vec!(1234, 2345, 3456),
                ))
            },
        )
    }

    #[test]
    fn node_descriptor_from_key_node_addr_and_mainnet_flag_works() {
        let public_key = PublicKey::new(&[1, 2, 3, 4, 5, 6, 7, 8]);
        let node_addr = NodeAddr::new(
            &IpAddr::from_str("123.45.67.89").unwrap(),
            &vec![2345, 3456],
        );

        let result = NodeDescriptor::from((&public_key, &node_addr, true));

        assert_eq!(
            result,
            NodeDescriptor {
                public_key,
                mainnet: true,
                node_addr_opt: Some(node_addr),
            }
        );
    }

    #[test]
    fn node_descriptor_from_key_and_mainnet_flag_works() {
        let public_key = PublicKey::new(&[1, 2, 3, 4, 5, 6, 7, 8]);

        let result = NodeDescriptor::from((&public_key, true));

        assert_eq!(
            result,
            NodeDescriptor {
                public_key,
                mainnet: true,
                node_addr_opt: None,
            }
        );
    }

    #[test]
    fn node_descriptor_to_string_works_for_mainnet() {
        let public_key = PublicKey::new(&[1, 2, 3, 4, 5, 6, 7, 8]);
        let node_addr = NodeAddr::new(
            &IpAddr::from_str("123.45.67.89").unwrap(),
            &vec![2345, 3456],
        );
        let subject = NodeDescriptor::from((&public_key, &node_addr, true));

        let result = subject.to_string(main_cryptde());

        assert_eq!(result, "AQIDBAUGBwg@123.45.67.89:2345;3456".to_string());
    }

    #[test]
    fn node_descriptor_to_string_works_for_not_mainnet() {
        let public_key = PublicKey::new(&[1, 2, 3, 4, 5, 6, 7, 8]);
        let node_addr = NodeAddr::new(
            &IpAddr::from_str("123.45.67.89").unwrap(),
            &vec![2345, 3456],
        );
        let subject = NodeDescriptor::from((&public_key, &node_addr, false));

        let result = subject.to_string(main_cryptde());

        assert_eq!(result, "AQIDBAUGBwg:123.45.67.89:2345;3456".to_string());
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
    fn standard_mode_results() {
        let subject = NeighborhoodMode::Standard(
            NodeAddr::new(&localhost(), &vec![1234, 2345]),
            vec!["one neighbor".to_string(), "another neighbor".to_string()],
            rate_pack(100),
        );

        assert_eq!(
            subject.node_addr_opt(),
            Some(NodeAddr::new(&localhost(), &vec![1234, 2345]))
        );
        assert_eq!(
            subject.neighbor_configs(),
            &vec!["one neighbor".to_string(), "another neighbor".to_string()]
        );
        assert_eq!(subject.rate_pack(), &rate_pack(100));
        assert!(subject.accepts_connections());
        assert!(subject.routes_data());
        assert!(subject.is_standard());
        assert!(!subject.is_originate_only());
        assert!(!subject.is_consume_only());
        assert!(!subject.is_zero_hop());
    }

    #[test]
    fn originate_only_mode_results() {
        let subject = NeighborhoodMode::OriginateOnly(
            vec!["one neighbor".to_string(), "another neighbor".to_string()],
            rate_pack(100),
        );

        assert_eq!(subject.node_addr_opt(), None);
        assert_eq!(
            subject.neighbor_configs(),
            &vec!["one neighbor".to_string(), "another neighbor".to_string()]
        );
        assert_eq!(subject.rate_pack(), &rate_pack(100));
        assert!(!subject.accepts_connections());
        assert!(subject.routes_data());
        assert!(!subject.is_standard());
        assert!(subject.is_originate_only());
        assert!(!subject.is_consume_only());
        assert!(!subject.is_zero_hop());
    }

    #[test]
    fn consume_only_mode_results() {
        let subject = NeighborhoodMode::ConsumeOnly(vec![
            "one neighbor".to_string(),
            "another neighbor".to_string(),
        ]);

        assert_eq!(subject.node_addr_opt(), None);
        assert_eq!(
            subject.neighbor_configs(),
            &vec!["one neighbor".to_string(), "another neighbor".to_string()]
        );
        assert_eq!(subject.rate_pack(), &ZERO_RATE_PACK);
        assert!(!subject.accepts_connections());
        assert!(!subject.routes_data());
        assert!(!subject.is_standard());
        assert!(!subject.is_originate_only());
        assert!(subject.is_consume_only());
        assert!(!subject.is_zero_hop());
    }

    #[test]
    fn zero_hop_mode_results() {
        let subject = NeighborhoodMode::ZeroHop;

        assert_eq!(subject.node_addr_opt(), None);
        assert!(subject.neighbor_configs().is_empty());
        assert_eq!(subject.rate_pack(), &ZERO_RATE_PACK);
        assert!(!subject.accepts_connections());
        assert!(!subject.routes_data());
        assert!(!subject.is_standard());
        assert!(!subject.is_originate_only());
        assert!(!subject.is_consume_only());
        assert!(subject.is_zero_hop());
    }

    #[test]
    fn gossip_failure_display() {
        // Structured this way so that modifications to GossipFailure will draw attention here
        // so that the test can be updated
        vec![
            GossipFailure::NoNeighbors,
            GossipFailure::NoSuitableNeighbors,
            GossipFailure::ManualRejection,
        ]
        .into_iter()
        .for_each(|gf| {
            let expected_string = match gf {
                GossipFailure::NoNeighbors => "No neighbors for Introduction or Pass",
                GossipFailure::NoSuitableNeighbors => {
                    "No neighbors were suitable for Introduction or Pass"
                }
                GossipFailure::ManualRejection => "Node owner manually rejected your Debut",
            };
            assert_eq!(&gf.to_string(), expected_string);
        });
    }
}
