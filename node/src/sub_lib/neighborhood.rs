// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::neighborhood::gossip::Gossip_0v1;
use crate::neighborhood::node_record::NodeRecord;
use crate::neighborhood::overall_connection_status::ConnectionProgress;
use crate::neighborhood::Neighborhood;
use crate::sub_lib::cryptde::{CryptDE, PublicKey};
use crate::sub_lib::cryptde_real::CryptDEReal;
use crate::sub_lib::dispatcher::{Component, StreamShutdownMsg};
use crate::sub_lib::hopper::ExpiredCoresPackage;
use crate::sub_lib::node_addr::NodeAddr;
use crate::sub_lib::peer_actors::{BindMessage, NewPublicIp, StartMessage};
use crate::sub_lib::route::Route;
use crate::sub_lib::stream_handler_pool::DispatcherNodeQueryResponse;
use crate::sub_lib::stream_handler_pool::TransmitDataMsg;
use crate::sub_lib::utils::{NotifyLaterHandle, NotifyLaterHandleReal};
use crate::sub_lib::wallet::Wallet;
use actix::Message;
use actix::Recipient;
use core::fmt;
use itertools::Itertools;
use lazy_static::lazy_static;
use masq_lib::blockchains::blockchain_records::CHAINS;
use masq_lib::blockchains::chains::{chain_from_chain_identifier_opt, Chain};
use masq_lib::constants::{CENTRAL_DELIMITER, CHAIN_IDENTIFIER_DELIMITER, MASQ_URL_PREFIX};
use masq_lib::ui_gateway::NodeFromUiMessage;
use masq_lib::utils::NeighborhoodModeLight;
use serde_derive::{Deserialize, Serialize};
use std::convert::TryFrom;
use std::fmt::{Debug, Display, Formatter};
use std::net::IpAddr;
use std::str::FromStr;
use std::time::Duration;

const ASK_ABOUT_GOSSIP_INTERVAL: Duration = Duration::from_secs(10);

pub const DEFAULT_RATE_PACK: RatePack = RatePack {
    routing_byte_rate: 172_300_000,
    routing_service_rate: 1_723_000_000,
    exit_byte_rate: 344_600_000,
    exit_service_rate: 3_446_000_000,
};

pub const ZERO_RATE_PACK: RatePack = RatePack {
    routing_byte_rate: 0,
    routing_service_rate: 0,
    exit_byte_rate: 0,
    exit_service_rate: 0,
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct RatePack {
    pub routing_byte_rate: u64,
    pub routing_service_rate: u64,
    pub exit_byte_rate: u64,
    pub exit_service_rate: u64,
}

impl RatePack {
    pub fn routing_charge(&self, payload_size: u64) -> u64 {
        self.routing_service_rate + (self.routing_byte_rate * payload_size)
    }

    pub fn exit_charge(&self, payload_size: u64) -> u64 {
        self.exit_service_rate + (self.exit_byte_rate * payload_size)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
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

#[allow(clippy::from_over_into)]
impl Into<NeighborhoodModeLight> for &NeighborhoodMode {
    fn into(self) -> NeighborhoodModeLight {
        match self {
            NeighborhoodMode::Standard(_, _, _) => NeighborhoodModeLight::Standard,
            NeighborhoodMode::ConsumeOnly(_) => NeighborhoodModeLight::ConsumeOnly,
            NeighborhoodMode::OriginateOnly(_, _) => NeighborhoodModeLight::OriginateOnly,
            NeighborhoodMode::ZeroHop => NeighborhoodModeLight::ZeroHop,
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

//TODO we could write our own impl of serde for Chain in order to optimize

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NodeDescriptor {
    pub blockchain: Chain,
    pub encryption_public_key: PublicKey,
    pub node_addr_opt: Option<NodeAddr>,
}

impl Default for NodeDescriptor {
    fn default() -> Self {
        Self::from((
            &PublicKey::from([0u8; 32].to_vec()),
            &NodeAddr::default(),
            Chain::default(),
            &CryptDEReal::new(Chain::default()) as &dyn CryptDE,
        ))
    }
}

//the public key's role as a separate arg is to enable the produced descriptor to be constant and reliable in tests
impl From<(&PublicKey, &NodeAddr, Chain, &dyn CryptDE)> for NodeDescriptor {
    fn from(tuple: (&PublicKey, &NodeAddr, Chain, &dyn CryptDE)) -> Self {
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

impl From<(&NodeRecord, Chain, &dyn CryptDE)> for NodeDescriptor {
    fn from(tuple: (&NodeRecord, Chain, &dyn CryptDE)) -> Self {
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

impl TryFrom<(&dyn CryptDE, &str)> for NodeDescriptor {
    type Error = String;

    fn try_from(tuple: (&dyn CryptDE, &str)) -> Result<Self, Self::Error> {
        let (cryptde, str_descriptor) = tuple;
        let (blockchain, key, str_node_addr) = NodeDescriptor::parse_url(str_descriptor)?;
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
}

impl NodeDescriptor {
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
        let chain_identifier = self.blockchain.rec().literal_identifier;
        format!(
            "{}{}{}{}{}{}",
            MASQ_URL_PREFIX,
            chain_identifier,
            CHAIN_IDENTIFIER_DELIMITER,
            contact_public_key_string,
            CENTRAL_DELIMITER,
            node_addr_string
        )
    }

    pub fn parse_url(descriptor: &str) -> Result<(Chain, &str, &str), String> {
        let (front_end, tail) = first_dividing(descriptor)?;
        let (chain, key) = second_dividing(front_end, descriptor)?;
        Ok((chain, key, tail))
    }
}

fn first_dividing(descriptor: &str) -> Result<(&str, &str), String> {
    let without_prefix = strip_prefix(descriptor)?;
    let halves = separate_by_delimiter(
        without_prefix,
        CENTRAL_DELIMITER,
        DescriptorParsingError::CentralDelimiterProbablyMissing(descriptor),
    )?;
    approx_position_assertion(descriptor, &halves)?;
    Ok((halves[0], halves[1]))
}

fn second_dividing<'a>(front: &'a str, descriptor: &str) -> Result<(Chain, &'a str), String> {
    let front_parts = separate_by_delimiter(
        front,
        CHAIN_IDENTIFIER_DELIMITER,
        DescriptorParsingError::ChainIdentifierDelimiter(descriptor),
    )?;
    let chain_identifier = front_parts[0];
    let chain = match chain_from_chain_identifier_opt(chain_identifier) {
        Some(ch) => ch,
        _ => {
            return Err(DescriptorParsingError::WrongChainIdentifier(chain_identifier).to_string())
        }
    };
    let key_offset = chain_identifier.len() + 1;
    let key = &front[key_offset..];
    Ok((chain, key))
}

fn strip_prefix(str_descriptor: &str) -> Result<&str, String> {
    if let Some(str) = str_descriptor.strip_prefix(MASQ_URL_PREFIX) {
        Ok(str)
    } else {
        Err(DescriptorParsingError::PrefixMissing(str_descriptor).to_string())
    }
}

fn separate_by_delimiter<'a>(
    str: &'a str,
    delimiter: char,
    error: DescriptorParsingError,
) -> Result<Vec<&'a str>, String> {
    let parts = str.splitn(2, delimiter).collect::<Vec<&str>>();
    if parts.len() == 1 {
        return Err(error.to_string());
    }
    Ok(parts)
}

fn approx_position_assertion(descriptor: &str, halves: &[&str]) -> Result<(), String> {
    let purely_numerical = assert_purely_numerical(halves[0]);
    if purely_numerical {
        return Err(DescriptorParsingError::CentralDelimOrIdentifier(descriptor).to_string());
    }
    let purely_numerical = assert_purely_numerical(halves[1]);
    if !purely_numerical && halves[1].chars().filter(|char| *char == ':').count() < 3
        || halves[1]
            .chars()
            .filter(|char| !char.is_ascii_punctuation())
            .any(|char| !char.is_ascii_hexdigit())
    {
        return Err(
            DescriptorParsingError::CentralDelimOrNodeAddr(descriptor, halves[1]).to_string(),
        );
    }
    Ok(())
}

fn assert_purely_numerical(string: &str) -> bool {
    string
        .chars()
        .filter(|char| !char.is_ascii_punctuation())
        .all(|char| !char.is_alphabetic())
}

enum DescriptorParsingError<'a> {
    CentralDelimiterProbablyMissing(&'a str),
    CentralDelimOrNodeAddr(&'a str, &'a str),
    CentralDelimOrIdentifier(&'a str),
    ChainIdentifierDelimiter(&'a str),
    PrefixMissing(&'a str),
    WrongChainIdentifier(&'a str),
}

impl Display for DescriptorParsingError<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        fn only_user_intended() -> String {
            CHAINS
                .iter()
                .map(|record| record.literal_identifier)
                .filter(|identifier| *identifier != "dev")
                .join("', '")
        }
        match self{
            Self::CentralDelimiterProbablyMissing(descriptor) =>
                write!(f, "Delimiter '@' probably missing. Should be 'masq://<chain identifier>:<public key>@<node address>', not '{}'", descriptor),
            Self::CentralDelimOrNodeAddr(descriptor,tail) =>
                write!(f, "Either '@' delimiter position or format of node address is wrong. Should be 'masq://<chain identifier>:<public key>@<node address>', not '{}'\nNodeAddr should be expressed as '<IP address>:<port>/<port>/...', probably not as '{}'", descriptor,tail),
            Self::CentralDelimOrIdentifier(descriptor) =>
                write!(f, "Either '@' delimiter position or format of chain identifier is wrong. Should be 'masq://<chain identifier>:<public key>@<node address>', not '{}'", descriptor),
            Self::ChainIdentifierDelimiter(descriptor) =>
                write!(f, "Chain identifier delimiter mismatch. Should be 'masq://<chain identifier>:<public key>@<node address>', not '{}'", descriptor),
            Self::PrefixMissing(descriptor) =>
                write!(f,"Prefix or more missing. Should be 'masq://<chain identifier>:<public key>@<node address>', not '{}'",descriptor),
            Self::WrongChainIdentifier(identifier) =>
                write!(f, "Chain identifier '{}' is not valid; possible values are '{}' while formatted as 'masq://<chain identifier>:<public key>@<node address>'",
                                             identifier, only_user_intended()

            )
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, PartialOrd, Eq)]
pub enum Hops {
    OneHop = 1,
    TwoHops = 2,
    ThreeHops = 3, // minimum for anonymity
    FourHops = 4,
    FiveHops = 5,
    SixHops = 6,
}

impl FromStr for Hops {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "1" => Ok(Hops::OneHop),
            "2" => Ok(Hops::TwoHops),
            "3" => Ok(Hops::ThreeHops),
            "4" => Ok(Hops::FourHops),
            "5" => Ok(Hops::FiveHops),
            "6" => Ok(Hops::SixHops),
            _ => Err("Invalid value for min hops provided".to_string()),
        }
    }
}

impl Display for Hops {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", *self as usize)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NeighborhoodConfig {
    pub mode: NeighborhoodMode,
    pub min_hops: Hops,
}

lazy_static! {
    static ref EMPTY_CONFIGS: Vec<NodeDescriptor> = vec![];
}

#[derive(Clone, PartialEq, Eq)]
pub struct NeighborhoodSubs {
    pub bind: Recipient<BindMessage>,
    pub start: Recipient<StartMessage>,
    pub new_public_ip: Recipient<NewPublicIp>,
    pub route_query: Recipient<RouteQueryMessage>,
    pub update_node_record_metadata: Recipient<UpdateNodeRecordMetadataMessage>,
    pub from_hopper: Recipient<ExpiredCoresPackage<Gossip_0v1>>,
    pub gossip_failure: Recipient<ExpiredCoresPackage<GossipFailure_0v1>>,
    pub dispatcher_node_query: Recipient<DispatcherNodeQueryMessage>,
    pub remove_neighbor: Recipient<RemoveNeighborMessage>,
    pub configuration_change_msg_sub: Recipient<ConfigurationChangeMessage>,
    pub stream_shutdown_sub: Recipient<StreamShutdownMsg>,
    pub from_ui_message_sub: Recipient<NodeFromUiMessage>,
    pub connection_progress_sub: Recipient<ConnectionProgressMessage>,
}

impl Debug for NeighborhoodSubs {
    fn fmt(&self, f: &mut Formatter) -> Result<(), std::fmt::Error> {
        write!(f, "NeighborhoodSubs")
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NodeQueryMessage {
    IpAddress(IpAddr),
    PublicKey(PublicKey),
}

#[derive(Message, Clone, PartialEq, Eq)]
pub struct DispatcherNodeQueryMessage {
    pub query: NodeQueryMessage,
    pub context: TransmitDataMsg,
    pub recipient: Recipient<DispatcherNodeQueryResponse>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct RouteQueryMessage {
    pub target_key_opt: Option<PublicKey>,
    pub target_component: Component,
    pub return_component_opt: Option<Component>,
    pub payload_size: usize,
    pub hostname_opt: Option<String>,
}

impl Message for RouteQueryMessage {
    type Result = Option<RouteQueryResponse>;
}

impl RouteQueryMessage {
    pub fn data_indefinite_route_request(
        hostname_opt: Option<String>,
        payload_size: usize,
    ) -> RouteQueryMessage {
        RouteQueryMessage {
            target_key_opt: None,
            target_component: Component::ProxyClient,
            return_component_opt: Some(Component::ProxyServer),
            payload_size,
            hostname_opt,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExpectedService {
    Routing(PublicKey, Wallet, RatePack),
    Exit(PublicKey, Wallet, RatePack),
    Nothing,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExpectedServices {
    OneWay(Vec<ExpectedService>),
    RoundTrip(Vec<ExpectedService>, Vec<ExpectedService>, u32),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteQueryResponse {
    pub route: Route,
    pub expected_services: ExpectedServices,
}

#[derive(Clone, Debug, Message, PartialEq, Eq)]
pub struct RemoveNeighborMessage {
    pub public_key: PublicKey,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConnectionProgressEvent {
    TcpConnectionSuccessful,
    TcpConnectionFailed,
    NoGossipResponseReceived,
    PassLoopFound,
    StandardGossipReceived,
    IntroductionGossipReceived(IpAddr),
    PassGossipReceived(IpAddr),
}

#[derive(Clone, Debug, Message, PartialEq, Eq)]
pub struct ConnectionProgressMessage {
    pub peer_addr: IpAddr,
    pub event: ConnectionProgressEvent,
}

#[derive(Clone, Debug, Message, PartialEq, Eq)]
pub struct AskAboutDebutGossipMessage {
    pub prev_connection_progress: ConnectionProgress,
}

#[derive(Clone, Debug, Message, PartialEq, Eq)]
pub struct UpdateNodeRecordMetadataMessage {
    pub public_key: PublicKey,
    pub metadata_change: NRMetadataChange,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NRMetadataChange {
    AddUnreachableHost { hostname: String },
}

#[derive(Clone, Debug, Message, PartialEq, Eq)]
pub struct ConfigurationChangeMessage {
    pub change: ConfigurationChange,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConfigurationChange {
    UpdateConsumingWallet(Wallet),
    UpdateMinHops(Hops),
    // UpdatePassword(String), // TODO: Use me
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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

// This metadata is only passed from Neighborhood to GossipHandler
pub struct NeighborhoodMetadata {
    pub connection_progress_peers: Vec<IpAddr>,
    pub cpm_recipient: Recipient<ConnectionProgressMessage>,
    pub db_patch_size: u8,
}

pub struct NeighborhoodTools {
    pub notify_later_ask_about_gossip:
        Box<dyn NotifyLaterHandle<AskAboutDebutGossipMessage, Neighborhood>>,
    pub ask_about_gossip_interval: Duration,
}

impl Default for NeighborhoodTools {
    fn default() -> Self {
        Self {
            notify_later_ask_about_gossip: Box::new(NotifyLaterHandleReal::new()),
            ask_about_gossip_interval: ASK_ABOUT_GOSSIP_INTERVAL,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sub_lib::cryptde_real::CryptDEReal;
    use crate::sub_lib::utils::NotifyLaterHandleReal;
    use crate::test_utils::main_cryptde;
    use crate::test_utils::recorder::Recorder;
    use actix::Actor;
    use masq_lib::constants::DEFAULT_CHAIN;
    use masq_lib::test_utils::utils::TEST_DEFAULT_CHAIN;
    use masq_lib::utils::{localhost, NeighborhoodModeLight};
    use std::str::FromStr;

    #[test]
    fn constants_have_correct_values() {
        assert_eq!(
            DEFAULT_RATE_PACK,
            RatePack {
                routing_byte_rate: 172_300_000,
                routing_service_rate: 1_723_000_000,
                exit_byte_rate: 344_600_000,
                exit_service_rate: 3_446_000_000,
            }
        );
        assert_eq!(
            ZERO_RATE_PACK,
            RatePack {
                routing_byte_rate: 0,
                routing_service_rate: 0,
                exit_byte_rate: 0,
                exit_service_rate: 0,
            }
        );
        assert_eq!(ASK_ABOUT_GOSSIP_INTERVAL, Duration::from_secs(10));
    }

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
            new_public_ip: recipient!(recorder, NewPublicIp),
            route_query: recipient!(recorder, RouteQueryMessage),
            update_node_record_metadata: recipient!(recorder, UpdateNodeRecordMetadataMessage),
            from_hopper: recipient!(recorder, ExpiredCoresPackage<Gossip_0v1>),
            gossip_failure: recipient!(recorder, ExpiredCoresPackage<GossipFailure_0v1>),
            dispatcher_node_query: recipient!(recorder, DispatcherNodeQueryMessage),
            remove_neighbor: recipient!(recorder, RemoveNeighborMessage),
            configuration_change_msg_sub: recipient!(recorder, ConfigurationChangeMessage),
            stream_shutdown_sub: recipient!(recorder, StreamShutdownMsg),
            from_ui_message_sub: recipient!(recorder, NodeFromUiMessage),
            connection_progress_sub: recipient!(recorder, ConnectionProgressMessage),
        };

        assert_eq!(format!("{:?}", subject), "NeighborhoodSubs");
    }

    #[test]
    fn parse_works_for_ethereum_mainnet() {
        let descriptor = "masq://eth-mainnet:as45cs5c5@1.2.3.4:4444";

        let result = NodeDescriptor::parse_url(descriptor).unwrap();

        assert_eq!(result, (Chain::EthMainnet, "as45cs5c5", "1.2.3.4:4444"))
    }

    #[test]
    fn parse_works_for_ropsten() {
        let descriptor = "masq://eth-ropsten:as45cs5c5@1.2.3.4:4444";

        let result = NodeDescriptor::parse_url(descriptor).unwrap();

        assert_eq!(result, (Chain::EthRopsten, "as45cs5c5", "1.2.3.4:4444"))
    }

    #[test]
    fn parse_works_for_dev_chain() {
        let descriptor = "masq://dev:as45cs5c5@1.2.3.4:4444";

        let result = NodeDescriptor::parse_url(descriptor).unwrap();

        assert_eq!(result, (Chain::Dev, "as45cs5c5", "1.2.3.4:4444"))
    }

    #[test]
    fn parse_works_for_polygon_mainnet() {
        let descriptor = "masq://polygon-mainnet:as45cs5c5@1.2.3.4:4444";

        let result = NodeDescriptor::parse_url(descriptor).unwrap();

        assert_eq!(result, (Chain::PolyMainnet, "as45cs5c5", "1.2.3.4:4444"))
    }

    #[test]
    fn parse_works_for_mumbai() {
        let descriptor = "masq://polygon-mumbai:as45cs5c5@1.2.3.4:4444";

        let result = NodeDescriptor::parse_url(descriptor).unwrap();

        assert_eq!(result, (Chain::PolyMumbai, "as45cs5c5", "1.2.3.4:4444"))
    }

    #[test]
    fn parse_complains_about_url_prefix_not_found() {
        let descriptor = "https://eth-mainnet:as45cs5c5@1.2.3.4:4444";

        let result = NodeDescriptor::parse_url(descriptor);

        assert_eq!(
            result,
            Err(
                "Prefix or more missing. Should be 'masq://<chain identifier>:<public key>@<node address>', not 'https://eth-mainnet:as45cs5c5@1.2.3.4:4444'"
                    .to_string()
            )
        );
    }

    #[test]
    fn parse_complains_about_unknown_chain_identifier() {
        let descriptor = "masq://bitcoin:as45cs5c5@1.2.3.4:4444";

        let result = NodeDescriptor::parse_url(descriptor);

        assert_eq!(
            result,
            Err(
                "Chain identifier 'bitcoin' is not valid; possible values are 'polygon-mainnet', 'eth-mainnet', 'polygon-mumbai', 'eth-ropsten' while formatted as 'masq://<chain identifier>:<public key>@<node address>'"
                    .to_string()
            )
        );
    }

    #[test]
    fn parse_complains_about_str_which_it_does_not_know_how_to_halve_because_no_at_sign() {
        let descriptor = "masq://dev.as45cs5c5/1.4.4.5;4545";

        let result = NodeDescriptor::parse_url(descriptor);

        assert_eq!(
            result,
            Err("Delimiter '@' probably missing. Should be 'masq://<chain identifier>:<public key>@<node address>', not 'masq://dev.as45cs5c5/1.4.4.5;4545'".to_string())
        );
    }

    #[test]
    fn parse_complains_about_unclear_identifier_delimiter() {
        let descriptor = "masq://dev.as45cs5c5@1.4.4.5:4545";

        let result = NodeDescriptor::parse_url(descriptor);

        assert_eq!(
            result,
            Err("Chain identifier delimiter mismatch. Should be 'masq://<chain identifier>:<public key>@<node address>', not 'masq://dev.as45cs5c5@1.4.4.5:4545'".to_string())
        );
    }

    #[test]
    fn approx_position_assertion_lets_good_halves_go() {
        let would_be_descriptor = "whole_descriptor";
        let halves = &["dev:assd5fa3c5ac4a6", "1.3.4.5:4565;9898"];

        let result = approx_position_assertion(would_be_descriptor, halves);

        assert_eq!(result, Ok(()))
    }

    #[test]
    fn approx_position_assertion_catches_bad_second_half() {
        let would_be_descriptor = "whole_descriptor";
        let halves = &["dev:assd5fa3c5ac", "a1.bf3.4.5:4565/9898"];

        let result = approx_position_assertion(would_be_descriptor, halves);

        assert_eq!(result,Err("Either '@' delimiter position or format of node address is wrong. Should be 'masq://<chain identifier>:<public key>@<node address>', not 'whole_descriptor'\nNodeAddr should be expressed as '<IP address>:<port>/<port>/...', probably not as 'a1.bf3.4.5:4565/9898'".to_string()))
    }

    #[test]
    fn approx_position_assertion_ignores_potential_ipv6() {
        let would_be_descriptor = "whole_descriptor";
        let halves = &["dev:assd5fa3c5ac", "2000:ab3:88f:4565;9898"];

        let result = approx_position_assertion(would_be_descriptor, halves);

        assert_eq!(result, Ok(()))
    }

    #[test]
    fn approx_position_assertion_catches_ipv6_with_too_few_colons() {
        let would_be_descriptor = "whole_descriptor";
        let halves = &["dev:assd5fa3c5ac", "2000:ab.4.5a.10:4565"];

        let result = approx_position_assertion(would_be_descriptor, halves);

        assert_eq!(result,Err("Either '@' delimiter position or format of node address is wrong. Should be 'masq://<chain identifier>:<public key>@<node address>', not 'whole_descriptor'\nNodeAddr should be expressed as '<IP address>:<port>/<port>/...', probably not as '2000:ab.4.5a.10:4565'".to_string()))
    }

    #[test]
    fn approx_position_assertion_catches_potential_ipv6_with_non_hex_values() {
        let would_be_descriptor = "whole_descriptor";
        let halves = &["dev:assd5fa3c5ac", "2000:qd3:88r:4565/9898"];

        let result = approx_position_assertion(would_be_descriptor, halves);

        assert_eq!(result, Err("Either '@' delimiter position or format of node address is wrong. Should be 'masq://<chain identifier>:<public key>@<node address>', not 'whole_descriptor'\nNodeAddr should be expressed as '<IP address>:<port>/<port>/...', probably not as '2000:qd3:88r:4565/9898'".to_string()))
    }

    #[test]
    fn approx_position_assertion_does_not_like_all_numeric_first_half() {
        let would_be_descriptor = "whole_descriptor";
        let halves = &["145:4511265", "2000:ad3:88a:4565;9898"];

        let result = approx_position_assertion(would_be_descriptor, halves);

        assert_eq!(result, Err("Either '@' delimiter position or format of chain identifier is wrong. Should be 'masq://<chain identifier>:<public key>@<node address>', not 'whole_descriptor'".to_string()))
    }

    #[test]
    fn wrong_chain_identifier_error_does_not_mention_dev_chain() {
        assert!(CHAINS
            .iter()
            .find(|record| record.literal_identifier == "dev")
            .is_some());

        let result = DescriptorParsingError::WrongChainIdentifier("blah").to_string();

        assert_eq!(result, "Chain identifier 'blah' is not valid; possible values are 'polygon-mainnet', 'eth-mainnet', 'polygon-mumbai', 'eth-ropsten' while formatted as 'masq://<chain identifier>:<public key>@<node address>'")
    }

    #[test]
    fn from_str_complains_about_bad_base_64() {
        let result = NodeDescriptor::try_from((
            main_cryptde(),
            "masq://eth-mainnet:bad_key@1.2.3.4:1234;2345",
        ));

        assert_eq!(
            result,
            Err(String::from("Invalid Base64 value for public key: bad_key"))
        );
    }

    #[test]
    fn from_str_complains_about_slash_in_the_key() {
        let result = NodeDescriptor::try_from((
            &CryptDEReal::new(TEST_DEFAULT_CHAIN) as &dyn CryptDE,
            "masq://eth-ropsten:abJ5XvhVbmVyGejkYUkmftF09pmGZGKg/PzRNnWQxFw@12.23.34.45:5678",
        ));

        assert_eq!(
            result,
            Err(String::from(
                "Invalid Base64 value for public key: abJ5XvhVbmVyGejkYUkmftF09pmGZGKg/PzRNnWQxFw"
            ))
        );
    }

    #[test]
    fn from_str_complains_about_plus_in_the_key() {
        let result = NodeDescriptor::try_from((
            &CryptDEReal::new(DEFAULT_CHAIN) as &dyn CryptDE,
            "masq://eth-ropsten:abJ5XvhVbmVy+GejkYUmftF09pmGZGKgkPzRNnWQxFw@12.23.34.45:5678",
        ));

        assert_eq!(
            result,
            Err(String::from(
                "Invalid Base64 value for public key: abJ5XvhVbmVy+GejkYUmftF09pmGZGKgkPzRNnWQxFw"
            ))
        );
    }

    #[test]
    fn from_str_complains_about_blank_public_key() {
        let result = NodeDescriptor::try_from((main_cryptde(), "masq://dev:@1.2.3.4:1234/2345"));

        assert_eq!(result, Err(String::from("Public key cannot be empty")));
    }

    #[test]
    fn from_str_complains_about_bad_node_addr() {
        let result = NodeDescriptor::try_from((
            main_cryptde(),
            "masq://eth-mainnet:R29vZEtleQ==@BadNodeAddr",
        ));

        assert_eq!(result, Err(String::from("Either '@' delimiter position or format of node address is wrong. Should be 'masq://<chain identifier>:<public key>@<node address>', not 'masq://eth-mainnet:R29vZEtleQ==@BadNodeAddr'\nNodeAddr should be expressed as '<IP address>:<port>/<port>/...', probably not as 'BadNodeAddr'")));
    }

    #[test]
    fn from_str_handles_the_happy_path_with_node_addr() {
        let result = NodeDescriptor::try_from((
            main_cryptde(),
            "masq://eth-ropsten:R29vZEtleQ@1.2.3.4:1234/2345/3456",
        ));

        assert_eq!(
            result.unwrap(),
            NodeDescriptor {
                encryption_public_key: PublicKey::new(b"GoodKey"),
                blockchain: Chain::EthRopsten,
                node_addr_opt: Some(NodeAddr::new(
                    &IpAddr::from_str("1.2.3.4").unwrap(),
                    &[1234, 2345, 3456],
                ))
            },
        )
    }

    #[test]
    fn from_str_handles_the_happy_path_without_node_addr() {
        let result = NodeDescriptor::try_from((main_cryptde(), "masq://eth-mainnet:R29vZEtleQ@:"));

        assert_eq!(
            result.unwrap(),
            NodeDescriptor {
                encryption_public_key: PublicKey::new(b"GoodKey"),
                blockchain: Chain::EthMainnet,
                node_addr_opt: None
            },
        )
    }

    #[test]
    fn rate_pack_routing_charge_works() {
        let subject = RatePack {
            routing_byte_rate: 100,
            routing_service_rate: 900_000,
            exit_byte_rate: 0,
            exit_service_rate: 0,
        };

        let result = subject.routing_charge(1000);

        assert_eq!(result, 1_000_000);
    }

    #[test]
    fn rate_pack_exit_charge_works() {
        let subject = RatePack {
            routing_byte_rate: 0,
            routing_service_rate: 0,
            exit_byte_rate: 100,
            exit_service_rate: 900_000,
        };

        let result = subject.exit_charge(1000);

        assert_eq!(result, 1_000_000);
    }

    #[test]
    fn node_descriptor_from_key_node_addr_and_mainnet_flag_works() {
        let cryptde: &dyn CryptDE = main_cryptde();
        let public_key = PublicKey::new(&[1, 2, 3, 4, 5, 6, 7, 8]);
        let node_addr = NodeAddr::new(&IpAddr::from_str("123.45.67.89").unwrap(), &[2345, 3456]);

        let result = NodeDescriptor::from((&public_key, &node_addr, Chain::EthMainnet, cryptde));

        assert_eq!(
            result,
            NodeDescriptor {
                encryption_public_key: public_key,
                blockchain: Chain::EthMainnet,
                node_addr_opt: Some(node_addr),
            }
        );
    }

    #[test]
    fn node_descriptor_to_string_works_for_mainnet() {
        let cryptde: &dyn CryptDE = main_cryptde();
        let public_key = PublicKey::new(&[1, 2, 3, 4, 5, 6, 7, 8]);
        let node_addr = NodeAddr::new(&IpAddr::from_str("123.45.67.89").unwrap(), &[2345, 3456]);
        let subject = NodeDescriptor::from((&public_key, &node_addr, Chain::EthMainnet, cryptde));

        let result = subject.to_string(cryptde);

        assert_eq!(
            result,
            "masq://eth-mainnet:AQIDBAUGBwg@123.45.67.89:2345/3456".to_string()
        );
    }

    #[test]
    fn node_descriptor_to_string_works_for_not_mainnet() {
        let cryptde: &dyn CryptDE = main_cryptde();
        let public_key = PublicKey::new(&[1, 2, 3, 4, 5, 6, 7, 8]);
        let node_addr = NodeAddr::new(&IpAddr::from_str("123.45.67.89").unwrap(), &[2345, 3456]);
        let subject = NodeDescriptor::from((&public_key, &node_addr, Chain::EthRopsten, cryptde));

        let result = subject.to_string(cryptde);

        assert_eq!(
            result,
            "masq://eth-ropsten:AQIDBAUGBwg@123.45.67.89:2345/3456".to_string()
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
            NodeDescriptor::from((&public_key, &node_addr, Chain::EthMainnet, cryptde));
        let string_descriptor = descriptor.to_string(cryptde);

        let result = string_descriptor
            .strip_prefix(MASQ_URL_PREFIX)
            .unwrap()
            .chars()
            .skip_while(|char| char != &CHAIN_IDENTIFIER_DELIMITER)
            .skip(1)
            .position(|l| l == CENTRAL_DELIMITER)
            .unwrap();

        assert_eq!(result, required_number_of_characters);
    }

    #[test]
    fn data_indefinite_route_request() {
        let result = RouteQueryMessage::data_indefinite_route_request(None, 7500);

        assert_eq!(
            result,
            RouteQueryMessage {
                target_key_opt: None,
                target_component: Component::ProxyClient,
                return_component_opt: Some(Component::ProxyServer),
                payload_size: 7500,
                hostname_opt: None
            }
        );
    }

    #[test]
    fn standard_mode_results() {
        let one_neighbor =
            NodeDescriptor::try_from((main_cryptde(), "masq://eth-mainnet:AQIDBA@1.2.3.4:1234"))
                .unwrap();
        let another_neighbor =
            NodeDescriptor::try_from((main_cryptde(), "masq://eth-mainnet:AgMEBQ@2.3.4.5:2345"))
                .unwrap();
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
            NodeDescriptor::try_from((main_cryptde(), "masq://eth-ropsten:AQIDBA@1.2.3.4:1234"))
                .unwrap();
        let another_neighbor =
            NodeDescriptor::try_from((main_cryptde(), "masq://eth-ropsten:AgMEBQ@2.3.4.5:2345"))
                .unwrap();
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
            NodeDescriptor::try_from((main_cryptde(), "masq://eth-mainnet:AQIDBA@1.2.3.4:1234"))
                .unwrap();
        let another_neighbor =
            NodeDescriptor::try_from((main_cryptde(), "masq://eth-mainnet:AgMEBQ@2.3.4.5:2345"))
                .unwrap();
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

    #[test]
    fn neighborhood_mode_light_tights_up_with_the_classic_enum() {
        let simple_standard = NeighborhoodModeLight::Standard.to_string().to_lowercase();
        let simple_consume_only = NeighborhoodModeLight::ConsumeOnly
            .to_string()
            .to_lowercase();
        let simple_originate_only = NeighborhoodModeLight::OriginateOnly
            .to_string()
            .to_lowercase();
        let simple_zero_hop = NeighborhoodModeLight::ZeroHop.to_string().to_lowercase();
        let classic_standard = NeighborhoodMode::Standard(
            NodeAddr::new(&localhost(), &[1234, 2345]),
            vec![],
            rate_pack(100),
        )
        .to_string()
        .to_lowercase();
        let classic_consume_only = NeighborhoodMode::ConsumeOnly(vec![])
            .to_string()
            .to_lowercase();
        let classic_originate_only = NeighborhoodMode::OriginateOnly(vec![], rate_pack(100))
            .to_string()
            .to_lowercase();
        let classic_zero_hop = NeighborhoodMode::ZeroHop.to_string().to_lowercase();
        assert_contain_words(simple_standard, classic_standard, &["standard"]);
        assert_contain_words(
            simple_consume_only,
            classic_consume_only,
            &["consume", "only"],
        );
        assert_contain_words(
            simple_originate_only,
            classic_originate_only,
            &["originate", "only"],
        );
        assert_contain_words(simple_zero_hop, classic_zero_hop, &["zero", "hop"]);
    }

    fn assert_contain_words(simple: String, classic: String, words: &[&str]) {
        words
            .iter()
            .for_each(|word| assert!(simple.contains(word) && classic.contains(word)))
    }

    #[test]
    fn neighborhood_mode_light_can_be_made_from_neighborhood_mode() {
        assert_make_light(
            &NeighborhoodMode::Standard(
                NodeAddr::new(&localhost(), &[1234, 2345]),
                vec![],
                rate_pack(100),
            ),
            NeighborhoodModeLight::Standard,
        );
        assert_make_light(
            &NeighborhoodMode::ConsumeOnly(vec![]),
            NeighborhoodModeLight::ConsumeOnly,
        );
        assert_make_light(
            &NeighborhoodMode::OriginateOnly(vec![], rate_pack(100)),
            NeighborhoodModeLight::OriginateOnly,
        );
        assert_make_light(&NeighborhoodMode::ZeroHop, NeighborhoodModeLight::ZeroHop)
    }

    fn assert_make_light(heavy: &NeighborhoodMode, expected_value: NeighborhoodModeLight) {
        let result: NeighborhoodModeLight = heavy.into();
        assert_eq!(result, expected_value)
    }

    #[test]
    fn neighborhood_tools_default_is_set_properly() {
        let subject = NeighborhoodTools::default();
        subject
            .notify_later_ask_about_gossip
            .as_any()
            .downcast_ref::<NotifyLaterHandleReal<AskAboutDebutGossipMessage>>()
            .unwrap();
        assert_eq!(subject.ask_about_gossip_interval, Duration::from_secs(10));
    }

    #[test]
    fn valid_hops_can_be_converted_from_str() {
        assert_eq!(Hops::from_str("1").unwrap(), Hops::OneHop);
        assert_eq!(Hops::from_str("2").unwrap(), Hops::TwoHops);
        assert_eq!(Hops::from_str("3").unwrap(), Hops::ThreeHops);
        assert_eq!(Hops::from_str("4").unwrap(), Hops::FourHops);
        assert_eq!(Hops::from_str("5").unwrap(), Hops::FiveHops);
        assert_eq!(Hops::from_str("6").unwrap(), Hops::SixHops);
    }

    #[test]
    fn invalid_hops_conversion_from_str_returns_error() {
        let result = Hops::from_str("100");

        assert_eq!(
            result,
            Err("Invalid value for min hops provided".to_string())
        )
    }

    #[test]
    fn display_is_implemented_for_hops() {
        assert_eq!(Hops::OneHop.to_string(), "1");
        assert_eq!(Hops::TwoHops.to_string(), "2");
        assert_eq!(Hops::ThreeHops.to_string(), "3");
        assert_eq!(Hops::FourHops.to_string(), "4");
        assert_eq!(Hops::FiveHops.to_string(), "5");
        assert_eq!(Hops::SixHops.to_string(), "6");
    }
}
