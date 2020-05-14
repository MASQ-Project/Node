// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use crate::blockchain::blockchain_interface::chain_id_from_name;
use crate::neighborhood::gossip::Gossip_0v1;
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
use masq_lib::ui_gateway::NodeFromUiMessage;
use serde_derive::{Deserialize, Serialize};
use std::fmt::{Debug, Display, Formatter};
use std::net::IpAddr;
use std::str::FromStr;

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
    Standard(NodeAddr, Vec<NodeDescriptor>, RatePack),
    ZeroHop,
    OriginateOnly(Vec<NodeDescriptor>, RatePack),
    ConsumeOnly(Vec<NodeDescriptor>),
}

impl Display for NeighborhoodMode {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            NeighborhoodMode::Standard(_, _, _) => write!(f, "Standard"),
            NeighborhoodMode::ZeroHop => write!(f, "ZeroHop"),
            NeighborhoodMode::OriginateOnly(_, _) => write!(f, "OriginateOnly"),
            NeighborhoodMode::ConsumeOnly(_) => write!(f, "ConsumeOnly"),
        }
    }
}

impl NeighborhoodMode {
    pub fn is_decentralized(&self) -> bool {
        self != &NeighborhoodMode::ZeroHop
    }

    pub fn neighbor_configs(&self) -> &Vec<NodeDescriptor> {
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

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NodeDescriptor {
    pub encryption_public_key: PublicKey,
    pub mainnet: bool,
    pub node_addr_opt: Option<NodeAddr>,
}

impl From<(&PublicKey, &NodeAddr, bool, &dyn CryptDE)> for NodeDescriptor {
    fn from(tuple: (&PublicKey, &NodeAddr, bool, &dyn CryptDE)) -> Self {
        let (public_key, node_addr, mainnet, cryptde) = tuple;
        NodeDescriptor {
            encryption_public_key: cryptde
                .descriptor_fragment_to_first_contact_public_key(
                    &cryptde.public_key_to_descriptor_fragment(public_key),
                )
                .expect("Internal error"),
            mainnet,
            node_addr_opt: Some(node_addr.clone()),
        }
    }
}

impl From<(&PublicKey, bool, &dyn CryptDE)> for NodeDescriptor {
    fn from(tuple: (&PublicKey, bool, &dyn CryptDE)) -> Self {
        let (public_key, mainnet, cryptde) = tuple;
        NodeDescriptor {
            encryption_public_key: cryptde
                .descriptor_fragment_to_first_contact_public_key(
                    &cryptde.public_key_to_descriptor_fragment(public_key),
                )
                .expect("Internal error"),
            mainnet,
            node_addr_opt: None,
        }
    }
}

impl From<(&NodeRecord, bool, &dyn CryptDE)> for NodeDescriptor {
    fn from(tuple: (&NodeRecord, bool, &dyn CryptDE)) -> Self {
        let (node_record, mainnet, cryptde) = tuple;
        NodeDescriptor {
            encryption_public_key: cryptde
                .descriptor_fragment_to_first_contact_public_key(
                    &cryptde.public_key_to_descriptor_fragment(node_record.public_key()),
                )
                .expect("Internal error"),
            mainnet,
            node_addr_opt: node_record.node_addr_opt(),
        }
    }
}

impl NodeDescriptor {
    pub fn from_str(cryptde: &dyn CryptDE, s: &str) -> Result<NodeDescriptor, String> {
        let (mainnet, pieces) = {
            let chain_id = chain_id_from_name("mainnet");
            let delimiter = node_descriptor_delimiter(chain_id);
            let pieces: Vec<&str> = s.splitn(2, delimiter).collect();
            if pieces.len() == 2 {
                (true, pieces)
            } else {
                let chain_id = chain_id_from_name("testnet");
                let delimiter = node_descriptor_delimiter(chain_id);
                let pieces: Vec<&str> = s.splitn(2, delimiter).collect();
                if pieces.len() == 2 {
                    (false, pieces)
                } else {
                    return Err(format!(
                        "Should be <public key>[@ | :]<node address>, not '{}'",
                        s
                    ));
                }
            }
        };

        let encryption_public_key =
            match cryptde.descriptor_fragment_to_first_contact_public_key(pieces[0]) {
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
            encryption_public_key,
            mainnet,
            node_addr_opt,
        })
    }

    pub fn to_string(&self, cryptde: &dyn CryptDE) -> String {
        let contact_public_key_string =
            cryptde.public_key_to_descriptor_fragment(&self.encryption_public_key);
        let node_addr_string = match &self.node_addr_opt {
            Some(node_addr) => node_addr.to_string(),
            None => ":".to_string(),
        };
        let delimiter = if self.mainnet { "@" } else { ":" };
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
    static ref EMPTY_CONFIGS: Vec<NodeDescriptor> = vec![];
}

#[derive(Clone)]
pub struct NeighborhoodSubs {
    pub bind: Recipient<BindMessage>,
    pub start: Recipient<StartMessage>,
    pub node_query: Recipient<NodeQueryMessage>,
    pub route_query: Recipient<RouteQueryMessage>,
    pub update_node_record_metadata: Recipient<NodeRecordMetadataMessage>,
    pub from_hopper: Recipient<ExpiredCoresPackage<Gossip_0v1>>,
    pub gossip_failure: Recipient<ExpiredCoresPackage<GossipFailure_0v1>>,
    pub dispatcher_node_query: Recipient<DispatcherNodeQueryMessage>,
    pub remove_neighbor: Recipient<RemoveNeighborMessage>,
    pub stream_shutdown_sub: Recipient<StreamShutdownMsg>,
    pub set_consuming_wallet_sub: Recipient<SetConsumingWalletMessage>,
    pub from_ui_gateway: Recipient<NeighborhoodDotGraphRequest>,
    pub from_ui_message_sub: Recipient<NodeFromUiMessage>,
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

impl fmt::Display for RatePack {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(
            f,
            "{}+{}b route {}+{}b exit",
            self.routing_service_rate,
            self.routing_byte_rate,
            self.exit_service_rate,
            self.exit_byte_rate
        )
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[allow(non_camel_case_types)]
pub enum GossipFailure_0v1 {
    NoNeighbors,
    NoSuitableNeighbors,
    ManualRejection,
    Unknown,
}

impl fmt::Display for GossipFailure_0v1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        let msg = match self {
            GossipFailure_0v1::NoNeighbors => "No neighbors for Introduction or Pass",
            GossipFailure_0v1::NoSuitableNeighbors => {
                "No neighbors were suitable for Introduction or Pass"
            }
            GossipFailure_0v1::ManualRejection => "Node owner manually rejected your Debut",
            GossipFailure_0v1::Unknown => "Unknown Debut failure",
        };
        write!(f, "{}", msg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sub_lib::cryptde_real::CryptDEReal;
    use crate::test_utils::recorder::Recorder;
    use crate::test_utils::{main_cryptde, DEFAULT_CHAIN_ID};
    use actix::Actor;
    use masq_lib::utils::localhost;
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
            from_hopper: recipient!(recorder, ExpiredCoresPackage<Gossip_0v1>),
            gossip_failure: recipient!(recorder, ExpiredCoresPackage<GossipFailure_0v1>),
            dispatcher_node_query: recipient!(recorder, DispatcherNodeQueryMessage),
            remove_neighbor: recipient!(recorder, RemoveNeighborMessage),
            stream_shutdown_sub: recipient!(recorder, StreamShutdownMsg),
            set_consuming_wallet_sub: recipient!(recorder, SetConsumingWalletMessage),
            from_ui_gateway: recipient!(recorder, NeighborhoodDotGraphRequest),
            from_ui_message_sub: recipient!(recorder, NodeFromUiMessage),
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
        let result = NodeDescriptor::from_str(main_cryptde(), "bad_key:1.2.3.4:1234;2345");

        assert_eq!(
            result,
            Err(String::from("Invalid Base64 value for public key: bad_key"))
        );
    }

    #[test]
    fn node_descriptor_from_str_complains_about_blank_public_key() {
        let result = NodeDescriptor::from_str(main_cryptde(), ":1.2.3.4:1234;2345");

        assert_eq!(result, Err(String::from("Public key cannot be empty")));
    }

    #[test]
    fn node_descriptor_from_str_complains_about_bad_node_addr() {
        let result = NodeDescriptor::from_str(main_cryptde(), "R29vZEtleQ==:BadNodeAddr");

        assert_eq!(result, Err(String::from("NodeAddr should be expressed as '<IP address>:<port>;<port>,...', not 'BadNodeAddr'")));
    }

    #[test]
    fn node_descriptor_from_str_handles_the_happy_path_with_node_addr() {
        let result = NodeDescriptor::from_str(main_cryptde(), "R29vZEtleQ:1.2.3.4:1234;2345;3456");

        assert_eq!(
            result.unwrap(),
            NodeDescriptor {
                encryption_public_key: PublicKey::new(b"GoodKey"),
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
                encryption_public_key: PublicKey::new(b"GoodKey"),
                mainnet: false,
                node_addr_opt: None
            },
        )
    }

    #[test]
    fn node_descriptor_from_str_accepts_mainnet_delimiter() {
        let result = NodeDescriptor::from_str(main_cryptde(), "R29vZEtleQ@1.2.3.4:1234;2345;3456");

        assert_eq!(
            result.unwrap(),
            NodeDescriptor {
                encryption_public_key: PublicKey::new(b"GoodKey"),
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
        let cryptde: &dyn CryptDE = main_cryptde();
        let public_key = PublicKey::new(&[1, 2, 3, 4, 5, 6, 7, 8]);
        let node_addr = NodeAddr::new(
            &IpAddr::from_str("123.45.67.89").unwrap(),
            &vec![2345, 3456],
        );

        let result = NodeDescriptor::from((&public_key, &node_addr, true, cryptde));

        assert_eq!(
            result,
            NodeDescriptor {
                encryption_public_key: public_key,
                mainnet: true,
                node_addr_opt: Some(node_addr),
            }
        );
    }

    #[test]
    fn node_descriptor_from_key_and_mainnet_flag_works_with_cryptde_null() {
        let cryptde: &dyn CryptDE = main_cryptde();
        let public_key = PublicKey::new(&[1, 2, 3, 4, 5, 6, 7, 8]);

        let result = NodeDescriptor::from((&public_key, true, cryptde));

        assert_eq!(
            result,
            NodeDescriptor {
                encryption_public_key: public_key,
                mainnet: true,
                node_addr_opt: None,
            }
        );
    }

    #[test]
    fn node_descriptor_from_key_and_mainnet_flag_works_with_cryptde_real() {
        let cryptde: &dyn CryptDE = &CryptDEReal::new(DEFAULT_CHAIN_ID);
        let encryption_public_key = cryptde
            .descriptor_fragment_to_first_contact_public_key(
                &cryptde.public_key_to_descriptor_fragment(cryptde.public_key()),
            )
            .unwrap();

        let result = NodeDescriptor::from((cryptde.public_key(), true, cryptde));

        assert_eq!(
            result,
            NodeDescriptor {
                encryption_public_key,
                mainnet: true,
                node_addr_opt: None,
            }
        );
    }

    #[test]
    fn node_descriptor_to_string_works_for_mainnet() {
        let cryptde: &dyn CryptDE = main_cryptde();
        let public_key = PublicKey::new(&[1, 2, 3, 4, 5, 6, 7, 8]);
        let node_addr = NodeAddr::new(
            &IpAddr::from_str("123.45.67.89").unwrap(),
            &vec![2345, 3456],
        );
        let subject = NodeDescriptor::from((&public_key, &node_addr, true, cryptde));

        let result = subject.to_string(main_cryptde());

        assert_eq!(result, "AQIDBAUGBwg@123.45.67.89:2345;3456".to_string());
    }

    #[test]
    fn node_descriptor_to_string_works_for_not_mainnet() {
        let cryptde: &dyn CryptDE = main_cryptde();
        let public_key = PublicKey::new(&[1, 2, 3, 4, 5, 6, 7, 8]);
        let node_addr = NodeAddr::new(
            &IpAddr::from_str("123.45.67.89").unwrap(),
            &vec![2345, 3456],
        );
        let subject = NodeDescriptor::from((&public_key, &node_addr, false, cryptde));

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
        let one_neighbor = NodeDescriptor::from_str(main_cryptde(), "AQIDBA:1.2.3.4:1234").unwrap();
        let another_neighbor =
            NodeDescriptor::from_str(main_cryptde(), "AgMEBQ:2.3.4.5:2345").unwrap();
        let subject = NeighborhoodMode::Standard(
            NodeAddr::new(&localhost(), &vec![1234, 2345]),
            vec![one_neighbor.clone(), another_neighbor.clone()],
            rate_pack(100),
        );

        assert_eq!(
            subject.node_addr_opt(),
            Some(NodeAddr::new(&localhost(), &vec![1234, 2345]))
        );
        assert_eq!(
            subject.neighbor_configs(),
            &vec![one_neighbor, another_neighbor]
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
        let one_neighbor = NodeDescriptor::from_str(main_cryptde(), "AQIDBA:1.2.3.4:1234").unwrap();
        let another_neighbor =
            NodeDescriptor::from_str(main_cryptde(), "AgMEBQ:2.3.4.5:2345").unwrap();
        let subject = NeighborhoodMode::OriginateOnly(
            vec![one_neighbor.clone(), another_neighbor.clone()],
            rate_pack(100),
        );

        assert_eq!(subject.node_addr_opt(), None);
        assert_eq!(
            subject.neighbor_configs(),
            &vec![one_neighbor, another_neighbor]
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
        let one_neighbor = NodeDescriptor::from_str(main_cryptde(), "AQIDBA:1.2.3.4:1234").unwrap();
        let another_neighbor =
            NodeDescriptor::from_str(main_cryptde(), "AgMEBQ:2.3.4.5:2345").unwrap();
        let subject =
            NeighborhoodMode::ConsumeOnly(vec![one_neighbor.clone(), another_neighbor.clone()]);

        assert_eq!(subject.node_addr_opt(), None);
        assert_eq!(
            subject.neighbor_configs(),
            &vec![one_neighbor, another_neighbor]
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
        // Structured this way so that modifications to GossipFailure_0v1 will draw attention here
        // so that the test can be updated
        vec![
            GossipFailure_0v1::NoNeighbors,
            GossipFailure_0v1::NoSuitableNeighbors,
            GossipFailure_0v1::ManualRejection,
        ]
        .into_iter()
        .for_each(|gf| {
            let expected_string = match gf {
                GossipFailure_0v1::NoNeighbors => "No neighbors for Introduction or Pass",
                GossipFailure_0v1::NoSuitableNeighbors => {
                    "No neighbors were suitable for Introduction or Pass"
                }
                GossipFailure_0v1::ManualRejection => "Node owner manually rejected your Debut",
                GossipFailure_0v1::Unknown => "Unknown Debut failure",
            };
            assert_eq!(&gf.to_string(), expected_string);
        });
    }
}
