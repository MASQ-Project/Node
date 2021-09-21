// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use crate::blockchain::blockchain_interface::{
    delimiter_from_blockchain, CHAIN_LABEL_DELIMITER, MAINNET_DELIMITER, TESTNET_DELIMITER,
};
use crate::neighborhood::gossip::Gossip_0v1;
use crate::neighborhood::node_record::NodeRecord;
use crate::sub_lib::configurator::NewPasswordMessage;
use crate::sub_lib::cryptde::{CryptDE, PublicKey};
use crate::sub_lib::dispatcher::{Component, StreamShutdownMsg};
use crate::sub_lib::hopper::ExpiredCoresPackage;
use crate::sub_lib::node_addr::NodeAddr;
use crate::sub_lib::peer_actors::{BindMessage, StartMessage};
use crate::sub_lib::route::Route;
use crate::sub_lib::set_consuming_wallet_message::SetConsumingWalletMessage;
use crate::sub_lib::stream_handler_pool::DispatcherNodeQueryResponse;
use crate::sub_lib::stream_handler_pool::TransmitDataMsg;
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
        matches!(self, NeighborhoodMode::Standard(_, _, _))
    }

    pub fn routes_data(&self) -> bool {
        matches!(
            self,
            NeighborhoodMode::Standard(_, _, _) | NeighborhoodMode::OriginateOnly(_, _)
        )
    }

    pub fn is_standard(&self) -> bool {
        matches!(self, NeighborhoodMode::Standard(_, _, _))
    }

    pub fn is_originate_only(&self) -> bool {
        matches!(self, NeighborhoodMode::OriginateOnly(_, _))
    }

    pub fn is_consume_only(&self) -> bool {
        matches!(self, NeighborhoodMode::ConsumeOnly(_))
    }

    pub fn is_zero_hop(&self) -> bool {
        matches!(self, NeighborhoodMode::ZeroHop)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub enum Blockchain {
    EthMainnet,
    EthRopsten,
    EthRinkeby,
    Null,
    Dev,
}

impl Display for Blockchain {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EthMainnet => write!(f, "ETH mainnet"),
            Self::EthRopsten => write!(f, "Ropsten"),
            Self::EthRinkeby => write!(f, "Rinkeby"),
            Self::Null => write!(f, "null"),
            Self::Dev => write!(f, "developer's"),
        }
    }
}

//TODO in terms of optimization we can make our own impl of serde for blockchain
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NodeDescriptor {
    pub blockchain: Blockchain,
    pub encryption_public_key: PublicKey,
    pub node_addr_opt: Option<NodeAddr>,
}

impl From<(&PublicKey, &NodeAddr, Blockchain, &dyn CryptDE)> for NodeDescriptor {
    fn from(tuple: (&PublicKey, &NodeAddr, Blockchain, &dyn CryptDE)) -> Self {
        let (public_key, node_addr, blockchain, cryptde) = tuple;
        NodeDescriptor {
            blockchain,
            encryption_public_key: cryptde
                .descriptor_fragment_to_first_contact_public_key(
                    &cryptde.public_key_to_descriptor_fragment(public_key),
                )
                .expect("Internal error"),
            node_addr_opt: Some(node_addr.clone()),
        }
    }
}

impl From<(&PublicKey, Blockchain, &dyn CryptDE)> for NodeDescriptor {
    fn from(tuple: (&PublicKey, Blockchain, &dyn CryptDE)) -> Self {
        let (public_key, blockchain, cryptde) = tuple;
        NodeDescriptor {
            blockchain,
            encryption_public_key: cryptde
                .descriptor_fragment_to_first_contact_public_key(
                    &cryptde.public_key_to_descriptor_fragment(public_key),
                )
                .expect("Internal error"),
            node_addr_opt: None,
        }
    }
}

impl From<(&NodeRecord, Blockchain, &dyn CryptDE)> for NodeDescriptor {
    fn from(tuple: (&NodeRecord, Blockchain, &dyn CryptDE)) -> Self {
        let (node_record, blockchain, cryptde) = tuple;
        NodeDescriptor {
            blockchain,
            encryption_public_key: cryptde
                .descriptor_fragment_to_first_contact_public_key(
                    &cryptde.public_key_to_descriptor_fragment(node_record.public_key()),
                )
                .expect("Internal error"),
            node_addr_opt: node_record.node_addr_opt(),
        }
    }
}

impl NodeDescriptor {
    pub fn from_str(cryptde: &dyn CryptDE, str_descriptor: &str) -> Result<NodeDescriptor, String> {
        let (key, blockchain, str_node_addr) = Self::try_dismantle_str(str_descriptor)?;
        let encryption_public_key = cryptde.descriptor_fragment_to_first_contact_public_key(key)?;
        let node_addr_opt = if str_node_addr == ":" {
            None
        } else {
            Some(NodeAddr::from_str(str_node_addr)?)
        };

        Ok(NodeDescriptor {
            blockchain,
            encryption_public_key,
            node_addr_opt,
        })
    }

    const ETH_MAINNET_LABEL: &'static str = "ETH";
    const ETH_ROPSTEN_LABEL: &'static str = "ETH~tA";
    const ETH_RINKEBY_LABEL: &'static str = "ETH~tB";
    const DEV_LABEL: &'static str = "DEV";

    //TODO should I change this to FROM pattern?
    pub fn label_from_blockchain(blockchain: Blockchain) -> &'static str {
        match blockchain {
            Blockchain::EthMainnet => Self::ETH_MAINNET_LABEL,
            Blockchain::EthRopsten => Self::ETH_ROPSTEN_LABEL,
            Blockchain::EthRinkeby => Self::ETH_RINKEBY_LABEL,
            Blockchain::Null => "",
            Blockchain::Dev => Self::DEV_LABEL, //TODO will this be right?
        }
    }

    //TODO should I change this to FROM pattern?
    //TODO untested
    pub fn blockchain_from_label(label: &str) -> Blockchain {
        match label {
            Self::ETH_MAINNET_LABEL => Blockchain::EthMainnet,
            Self::ETH_ROPSTEN_LABEL => Blockchain::EthRopsten,
            Self::ETH_RINKEBY_LABEL => Blockchain::EthRinkeby,
            "" => Blockchain::Null,
            Self::DEV_LABEL => Blockchain::Dev, //TODO will this be right?
            _ => unreachable!(),
        }
    }

    fn try_dismantle_str(str_descriptor: &str) -> Result<(&str, Blockchain, &str), String> {
        eprintln!("we received this descriptor to process: {}", str_descriptor);
        let (halves, mainnet): (Vec<&str>, bool) = if str_descriptor.contains(MAINNET_DELIMITER) {
            (str_descriptor.splitn(2, MAINNET_DELIMITER).collect(), true)
        } else {
            (str_descriptor.splitn(2, TESTNET_DELIMITER).collect(), false)
        };
        if halves.len() == 1 {
            return Err(format!("Should be <public key><chain label>[@ | :]<node address>, not '{}'; either '@' or ':' delimiter is missing",str_descriptor));
        };
        let first_half = halves[0];
        let second_half = halves[1];
        let blockchain_label = first_half
            .rsplitn(2, CHAIN_LABEL_DELIMITER)
            .collect::<Vec<&str>>()[0];
        let blockchain = match (blockchain_label, mainnet) {
            (Self::ETH_MAINNET_LABEL, true) => Blockchain::EthMainnet,
            (Self::ETH_MAINNET_LABEL, false) => {
                return Err(format!(
                    "Label '{}' means mainnet and therefore must be followed by '{}' delimiter",
                    blockchain_label, MAINNET_DELIMITER
                ))
            }
            (Self::ETH_ROPSTEN_LABEL, false) => Blockchain::EthRopsten,
            (Self::ETH_RINKEBY_LABEL, false) => Blockchain::EthRinkeby,
            (Self::DEV_LABEL,false) => Blockchain::Dev,
            (Self::ETH_ROPSTEN_LABEL | Self::ETH_RINKEBY_LABEL | Self::DEV_LABEL, true) => {
                return Err(format!(
                    "Label '{}' means testnet and therefore must be followed by '{}' delimiter",
                    blockchain_label, TESTNET_DELIMITER
                ))
            }
            _ => {
                return Err(format!(
                    "Label '{}' isn't valid; you can have only '{}', '{}','{}' while formatted as <public key><chain label>[@ | :]<node address>",
                    blockchain_label,
                    Self::ETH_MAINNET_LABEL,
                    Self::ETH_ROPSTEN_LABEL,
                    Self::ETH_RINKEBY_LABEL
                ))
            }
        };
        let key_offset = first_half.len() - (blockchain_label.len() + 1);
        let key = &first_half[0..key_offset];
        Ok((key, blockchain, second_half))
    }

    pub fn to_string(&self, cryptde: &dyn CryptDE) -> String {
        let contact_public_key_string = cryptde
            .public_key_to_descriptor_fragment(&self.encryption_public_key)
            .chars()
            .take(43)
            .collect::<String>();
        let node_addr_string = match &self.node_addr_opt {
            Some(node_addr) => node_addr.to_string(),
            None => ":".to_string(),
        };

        let delimiter = delimiter_from_blockchain(self.blockchain);
        let label = Self::label_from_blockchain(self.blockchain);
        format!(
            "{}{}{}{}{}",
            contact_public_key_string, CHAIN_LABEL_DELIMITER, label, delimiter, node_addr_string
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
    pub from_ui_message_sub: Recipient<NodeFromUiMessage>,
    pub new_password_sub: Recipient<NewPasswordMessage>,
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
    use crate::test_utils::main_cryptde;
    use crate::test_utils::recorder::Recorder;
    use actix::Actor;
    use masq_lib::test_utils::utils::TEST_DEFAULT_CHAIN_ID;
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
            from_ui_message_sub: recipient!(recorder, NodeFromUiMessage),
            new_password_sub: recipient!(recorder, NewPasswordMessage),
        };

        assert_eq!(format!("{:?}", subject), "NeighborhoodSubs");
    }

    #[test]
    fn try_dismantle_works_for_ethereum_mainnet() {
        let descriptor = "as45cs5c5$ETH@1.2.3.4:4444";

        let result = NodeDescriptor::try_dismantle_str(descriptor).unwrap();

        assert_eq!(
            result,
            ("as45cs5c5", Blockchain::EthMainnet, "1.2.3.4:4444")
        )
    }

    #[test]
    fn try_dismantle_str_works_for_ethereum_testnet_ropsten() {
        let descriptor = "as45cs5c5$ETH~tA:1.2.3.4:4444";

        let result = NodeDescriptor::try_dismantle_str(descriptor).unwrap();

        assert_eq!(
            result,
            ("as45cs5c5", Blockchain::EthRopsten, "1.2.3.4:4444")
        )
    }

    #[test]
    fn try_dismantle_str_works_for_ethereum_testnet_rinkeby() {
        let descriptor = "as45cs5c5$ETH~tB:1.2.3.4:4444";

        let result = NodeDescriptor::try_dismantle_str(descriptor).unwrap();

        assert_eq!(
            result,
            ("as45cs5c5", Blockchain::EthRinkeby, "1.2.3.4:4444")
        )
    }

    #[test]
    fn try_dismantle_str_works_for_dev_chain() {
        let descriptor = "as45cs5c5$DEV:1.2.3.4:4444";

        let result = NodeDescriptor::try_dismantle_str(descriptor).unwrap();

        assert_eq!(result, ("as45cs5c5", Blockchain::Dev, "1.2.3.4:4444"))
    }

    #[test]
    fn try_dismantle_str_refuses_dev_chain_with_mainnet_delimiter() {
        let descriptor = "as45cs5c5$DEV@1.2.3.4:4444";

        let result = NodeDescriptor::try_dismantle_str(descriptor);

        assert_eq!(
            result,
            Err(
                "Label 'DEV' means testnet and therefore must be followed by ':' delimiter"
                    .to_string()
            )
        )
    }

    #[test]
    fn try_dismantle_str_uncovers_fault_in_wrong_chain_delimiter_for_ethereum_mainnet() {
        let descriptor = "as45cs5c5$ETH:1.2.3.4:4444";

        assert_eq!(
            NodeDescriptor::try_dismantle_str(descriptor),
            Err(
                "Label 'ETH' means mainnet and therefore must be followed by '@' delimiter"
                    .to_string()
            )
        );
    }

    #[test]
    fn try_dismantle_str_uncovers_fault_in_wrong_chain_delimiter_for_rinkeby_and_ropsten() {
        let descriptors = [
            "as45cs5c5$ETH~tB@1.2.3.4:4444",
            "as45cs5c5$ETH~tB@1.2.3.4:4444",
        ];

        descriptors.iter().for_each(|descriptor| {
            assert_eq!(
                NodeDescriptor::try_dismantle_str(descriptor),
                Err(
                    "Label 'ETH~tB' means testnet and therefore must be followed by ':' delimiter"
                        .to_string()
                )
            )
        });
    }

    #[test]
    fn try_dismantle_str_complains_about_unknown_chain_label() {
        let descriptor = "as45cs5c5$bitcoin@1.2.3.4:4444";

        let result = NodeDescriptor::try_dismantle_str(descriptor);

        assert_eq!(
            result,
            Err(
                "Label 'bitcoin' isn't valid; you can have only 'ETH', 'ETH~tA','ETH~tB' while formatted as <public key><chain label>[@ | :]<node address>"
                    .to_string()
            )
        );
    }

    #[test]
    fn try_dismantle_str_complains_about_str_which_it_does_not_know_how_to_halve() {
        let descriptor = "as45cs5c5$ETH/1.4.4.5;4545";

        let result = NodeDescriptor::try_dismantle_str(descriptor);

        assert_eq!(
            result,
            Err("Should be <public key><chain label>[@ | :]<node address>, not 'as45cs5c5$ETH/1.4.4.5;4545'; either '@' or ':' delimiter is missing".to_string())
        );
    }

    #[test]
    fn label_from_blockchain_returns_right_labels() {
        assert_label(Blockchain::Null, "");
        assert_label(Blockchain::EthMainnet, NodeDescriptor::ETH_MAINNET_LABEL);
        assert_label(Blockchain::EthRopsten, NodeDescriptor::ETH_ROPSTEN_LABEL);
        assert_label(Blockchain::EthRinkeby, NodeDescriptor::ETH_RINKEBY_LABEL);
        //assert_label(Blockchain::Dev,NodeDescriptor::ETH_RINKEBY) //TODO finish this
    }

    fn assert_label(blockchain: Blockchain, expected: &str) {
        assert_eq!(NodeDescriptor::label_from_blockchain(blockchain), expected)
    }

    #[test]
    fn blockchain_implements_display() {
        assert_eq!(Blockchain::EthMainnet.to_string(), "ETH mainnet");
        assert_eq!(Blockchain::EthRopsten.to_string(), "Ropsten");
        assert_eq!(Blockchain::EthRinkeby.to_string(), "Rinkeby");
        assert_eq!(Blockchain::Null.to_string(), "null");
        assert_eq!(Blockchain::Null.to_string(), "developer's");
    }

    #[test]
    fn node_descriptor_from_str_complains_about_bad_base_64() {
        let result = NodeDescriptor::from_str(main_cryptde(), "bad_key$ETH~tA:1.2.3.4:1234;2345");

        assert_eq!(
            result,
            Err(String::from("Invalid Base64 value for public key: bad_key"))
        );
    }

    #[test]
    fn node_descriptor_from_str_complains_about_blank_public_key() {
        let result = NodeDescriptor::from_str(main_cryptde(), "$ETH~tB:1.2.3.4:1234;2345");

        assert_eq!(result, Err(String::from("Public key cannot be empty")));
    }

    #[test]
    fn node_descriptor_from_str_complains_about_bad_node_addr() {
        let result = NodeDescriptor::from_str(main_cryptde(), "R29vZEtleQ==$ETH@BadNodeAddr");

        assert_eq!(result, Err(String::from("NodeAddr should be expressed as '<IP address>:<port>;<port>,...', not 'BadNodeAddr'")));
    }

    #[test]
    fn node_descriptor_from_str_handles_the_happy_path_with_node_addr() {
        let result =
            NodeDescriptor::from_str(main_cryptde(), "R29vZEtleQ$ETH~tA:1.2.3.4:1234;2345;3456");

        assert_eq!(
            result.unwrap(),
            NodeDescriptor {
                encryption_public_key: PublicKey::new(b"GoodKey"),
                blockchain: Blockchain::EthRopsten,
                node_addr_opt: Some(NodeAddr::new(
                    &IpAddr::from_str("1.2.3.4").unwrap(),
                    &[1234, 2345, 3456],
                ))
            },
        )
    }

    #[test]
    fn node_descriptor_from_str_handles_the_happy_path_without_node_addr() {
        let result = NodeDescriptor::from_str(main_cryptde(), "R29vZEtleQ$ETH~tA::");

        assert_eq!(
            result.unwrap(),
            NodeDescriptor {
                encryption_public_key: PublicKey::new(b"GoodKey"),
                blockchain: Blockchain::EthRopsten,
                node_addr_opt: None
            },
        )
    }

    #[test]
    fn node_descriptor_from_str_accepts_mainnet_delimiter() {
        let result =
            NodeDescriptor::from_str(main_cryptde(), "R29vZEtleQ$ETH@1.2.3.4:1234;2345;3456");

        assert_eq!(
            result.unwrap(),
            NodeDescriptor {
                encryption_public_key: PublicKey::new(b"GoodKey"),
                blockchain: Blockchain::EthMainnet,
                node_addr_opt: Some(NodeAddr::new(
                    &IpAddr::from_str("1.2.3.4").unwrap(),
                    &[1234, 2345, 3456],
                ))
            },
        )
    }

    #[test]
    fn node_descriptor_from_key_node_addr_and_mainnet_flag_works() {
        let cryptde: &dyn CryptDE = main_cryptde();
        let public_key = PublicKey::new(&[1, 2, 3, 4, 5, 6, 7, 8]);
        let node_addr = NodeAddr::new(&IpAddr::from_str("123.45.67.89").unwrap(), &[2345, 3456]);

        let result =
            NodeDescriptor::from((&public_key, &node_addr, Blockchain::EthMainnet, cryptde));

        assert_eq!(
            result,
            NodeDescriptor {
                encryption_public_key: public_key,
                blockchain: Blockchain::EthMainnet,
                node_addr_opt: Some(node_addr),
            }
        );
    }

    #[test]
    fn node_descriptor_from_key_and_mainnet_flag_works_with_cryptde_null() {
        let cryptde: &dyn CryptDE = main_cryptde();
        let public_key = PublicKey::new(&[1, 2, 3, 4, 5, 6, 7, 8]);

        let result = NodeDescriptor::from((&public_key, Blockchain::EthMainnet, cryptde));

        assert_eq!(
            result,
            NodeDescriptor {
                encryption_public_key: public_key,
                blockchain: Blockchain::EthMainnet,
                node_addr_opt: None,
            }
        );
    }

    #[test]
    fn node_descriptor_from_key_and_mainnet_flag_works_with_cryptde_real() {
        let cryptde: &dyn CryptDE = &CryptDEReal::new(TEST_DEFAULT_CHAIN_ID);
        let encryption_public_key = cryptde
            .descriptor_fragment_to_first_contact_public_key(
                &cryptde.public_key_to_descriptor_fragment(cryptde.public_key()),
            )
            .unwrap();

        let result = NodeDescriptor::from((cryptde.public_key(), Blockchain::EthMainnet, cryptde));

        assert_eq!(
            result,
            NodeDescriptor {
                encryption_public_key,
                blockchain: Blockchain::EthMainnet,
                node_addr_opt: None,
            }
        );
    }

    #[test]
    fn node_descriptor_to_string_works_for_mainnet() {
        let cryptde: &dyn CryptDE = main_cryptde();
        let public_key = PublicKey::new(&[1, 2, 3, 4, 5, 6, 7, 8]);
        let node_addr = NodeAddr::new(&IpAddr::from_str("123.45.67.89").unwrap(), &[2345, 3456]);
        let subject =
            NodeDescriptor::from((&public_key, &node_addr, Blockchain::EthMainnet, cryptde));

        let result = subject.to_string(cryptde);

        assert_eq!(result, "AQIDBAUGBwg$ETH@123.45.67.89:2345;3456".to_string());
    }

    #[test]
    fn node_descriptor_to_string_works_for_not_mainnet() {
        let cryptde: &dyn CryptDE = main_cryptde();
        let public_key = PublicKey::new(&[1, 2, 3, 4, 5, 6, 7, 8]);
        let node_addr = NodeAddr::new(&IpAddr::from_str("123.45.67.89").unwrap(), &[2345, 3456]);
        let subject =
            NodeDescriptor::from((&public_key, &node_addr, Blockchain::EthRinkeby, cryptde));

        let result = subject.to_string(cryptde);

        assert_eq!(
            result,
            "AQIDBAUGBwg$ETH~tB:123.45.67.89:2345;3456".to_string()
        );
    }

    #[test]
    fn first_part_of_node_descriptor_must_not_be_longer_than_required() {
        let cryptde: &dyn CryptDE = main_cryptde();
        let public_key = PublicKey::new(&[
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8,
            9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
        ]);
        let node_addr = NodeAddr::new(&IpAddr::from_str("123.45.67.89").unwrap(), &[2345, 3456]);
        let required_number_of_characters = 43;
        let descriptor =
            NodeDescriptor::from((&public_key, &node_addr, Blockchain::EthMainnet, cryptde));
        let string_descriptor = descriptor.to_string(cryptde);

        let result = string_descriptor.chars().position(|l| l == '$').unwrap();

        assert_eq!(result, required_number_of_characters);
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
        let one_neighbor =
            NodeDescriptor::from_str(main_cryptde(), "AQIDBA$ETH@1.2.3.4:1234").unwrap();
        let another_neighbor =
            NodeDescriptor::from_str(main_cryptde(), "AgMEBQ$ETH@2.3.4.5:2345").unwrap();
        let subject = NeighborhoodMode::Standard(
            NodeAddr::new(&localhost(), &[1234, 2345]),
            vec![one_neighbor.clone(), another_neighbor.clone()],
            rate_pack(100),
        );

        assert_eq!(
            subject.node_addr_opt(),
            Some(NodeAddr::new(&localhost(), &[1234, 2345]))
        );
        assert_eq!(
            subject.neighbor_configs(),
            &[one_neighbor, another_neighbor]
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
        let one_neighbor =
            NodeDescriptor::from_str(main_cryptde(), "AQIDBA$ETH~tB:1.2.3.4:1234").unwrap();
        let another_neighbor =
            NodeDescriptor::from_str(main_cryptde(), "AgMEBQ$ETH~tB:2.3.4.5:2345").unwrap();
        let subject = NeighborhoodMode::OriginateOnly(
            vec![one_neighbor.clone(), another_neighbor.clone()],
            rate_pack(100),
        );

        assert_eq!(subject.node_addr_opt(), None);
        assert_eq!(
            subject.neighbor_configs(),
            &[one_neighbor, another_neighbor]
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
        let one_neighbor =
            NodeDescriptor::from_str(main_cryptde(), "AQIDBA$ETH@1.2.3.4:1234").unwrap();
        let another_neighbor =
            NodeDescriptor::from_str(main_cryptde(), "AgMEBQ$ETH@2.3.4.5:2345").unwrap();
        let subject =
            NeighborhoodMode::ConsumeOnly(vec![one_neighbor.clone(), another_neighbor.clone()]);

        assert_eq!(subject.node_addr_opt(), None);
        assert_eq!(
            subject.neighbor_configs(),
            &[one_neighbor, another_neighbor]
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
