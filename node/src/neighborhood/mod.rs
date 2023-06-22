// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

pub mod dot_graph;
pub mod gossip;
pub mod gossip_acceptor;
pub mod gossip_producer;
pub mod neighborhood_database;
pub mod node_record;
pub mod overall_connection_status;

use std::collections::HashSet;
use std::convert::TryFrom;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;

use actix::Addr;
use actix::Context;
use actix::Handler;
use actix::MessageResult;
use actix::Recipient;
use actix::{Actor, System};
use itertools::{Either, Itertools};
use masq_lib::messages::{
    FromMessageBody, ToMessageBody, UiConnectionStage, UiConnectionStatusRequest,
};
use masq_lib::messages::{UiConnectionStatusResponse, UiShutdownRequest};
use masq_lib::ui_gateway::{MessageTarget, NodeFromUiMessage, NodeToUiMessage};
use masq_lib::utils::{exit_process, ExpectValue};

use crate::bootstrapper::BootstrapperConfig;
use crate::database::db_initializer::DbInitializationConfig;
use crate::database::db_initializer::{DbInitializer, DbInitializerReal};
use crate::db_config::persistent_configuration::{
    PersistentConfigError, PersistentConfiguration, PersistentConfigurationReal,
};
use crate::neighborhood::gossip::{DotGossipEndpoint, GossipNodeRecord, Gossip_0v1};
use crate::neighborhood::gossip_acceptor::GossipAcceptanceResult;
use crate::neighborhood::node_record::NodeRecordInner_0v1;
use crate::neighborhood::overall_connection_status::{
    OverallConnectionStage, OverallConnectionStatus,
};
use crate::stream_messages::{PoolBindMessage, RemovedStreamType};
use crate::sub_lib::configurator::NewPasswordMessage;
use crate::sub_lib::cryptde::PublicKey;
use crate::sub_lib::cryptde::{CryptDE, CryptData, PlainData};
use crate::sub_lib::dispatcher::{Component, StreamShutdownMsg};
use crate::sub_lib::hopper::{ExpiredCoresPackage, NoLookupIncipientCoresPackage};
use crate::sub_lib::hopper::{IncipientCoresPackage, MessageType};
use crate::sub_lib::neighborhood::NodeQueryResponseMetadata;
use crate::sub_lib::neighborhood::NodeRecordMetadataMessage;
use crate::sub_lib::neighborhood::RemoveNeighborMessage;
use crate::sub_lib::neighborhood::RouteQueryMessage;
use crate::sub_lib::neighborhood::RouteQueryResponse;
use crate::sub_lib::neighborhood::{AskAboutDebutGossipMessage, NodeDescriptor};
use crate::sub_lib::neighborhood::{ConnectionProgressEvent, ExpectedServices};
use crate::sub_lib::neighborhood::{ConnectionProgressMessage, ExpectedService};
use crate::sub_lib::neighborhood::{DispatcherNodeQueryMessage, GossipFailure_0v1};
use crate::sub_lib::neighborhood::{NRMetadataChange, NodeQueryMessage};
use crate::sub_lib::neighborhood::{NeighborhoodSubs, NeighborhoodTools};
use crate::sub_lib::node_addr::NodeAddr;
use crate::sub_lib::peer_actors::{BindMessage, NewPublicIp, StartMessage};
use crate::sub_lib::proxy_server::DEFAULT_MINIMUM_HOP_COUNT;
use crate::sub_lib::route::Route;
use crate::sub_lib::route::RouteSegment;
use crate::sub_lib::set_consuming_wallet_message::SetConsumingWalletMessage;
use crate::sub_lib::stream_handler_pool::DispatcherNodeQueryResponse;
use crate::sub_lib::utils::{handle_ui_crash_request, NODE_MAILBOX_CAPACITY};
use crate::sub_lib::versioned_data::VersionedData;
use crate::sub_lib::wallet::Wallet;
use gossip_acceptor::GossipAcceptor;
use gossip_acceptor::GossipAcceptorReal;
use gossip_producer::GossipProducer;
use gossip_producer::GossipProducerReal;
use masq_lib::blockchains::chains::Chain;
use masq_lib::crash_point::CrashPoint;
use masq_lib::logger::Logger;
use neighborhood_database::NeighborhoodDatabase;
use node_record::NodeRecord;

pub const CRASH_KEY: &str = "NEIGHBORHOOD";
pub const UNREACHABLE_HOST_PENALTY: i64 = 100_000_000;
pub const RESPONSE_UNDESIRABILITY_FACTOR: usize = 1_000; // assumed response length is request * this

#[derive(Clone)]
pub struct GossipAcceptorSubs {
    connection_progress_sub: Recipient<ConnectionProgressMessage>,
    stream_shutdown_sub: Recipient<StreamShutdownMsg>,
}

pub struct Neighborhood {
    cryptde: &'static dyn CryptDE,
    hopper_opt: Option<Recipient<IncipientCoresPackage>>,
    hopper_no_lookup_sub_opt: Option<Recipient<NoLookupIncipientCoresPackage>>,
    connected_signal_sub_opt: Option<Recipient<StartMessage>>,
    node_to_ui_sub_opt: Option<Recipient<NodeToUiMessage>>,
    gossip_acceptor_info_opt: Option<Either<Box<dyn GossipAcceptor>, GossipAcceptorSubs>>,
    gossip_producer_opt: Option<Box<dyn GossipProducer>>,
    neighborhood_database: NeighborhoodDatabase,
    consuming_wallet_opt: Option<Wallet>,
    next_return_route_id: u32,
    overall_connection_status: OverallConnectionStatus,
    chain: Chain,
    crashable: bool,
    data_directory: PathBuf,
    persistent_config_opt: Option<Box<dyn PersistentConfiguration>>,
    db_password_opt: Option<String>,
    logger: Logger,
    tools: NeighborhoodTools,
}

impl Actor for Neighborhood {
    type Context = Context<Self>;
}

impl Handler<BindMessage> for Neighborhood {
    type Result = ();

    fn handle(&mut self, msg: BindMessage, ctx: &mut Self::Context) -> Self::Result {
        ctx.set_mailbox_capacity(NODE_MAILBOX_CAPACITY);
        self.hopper_opt = Some(msg.peer_actors.hopper.from_hopper_client);
        self.hopper_no_lookup_sub_opt = Some(msg.peer_actors.hopper.from_hopper_client_no_lookup);
        self.connected_signal_sub_opt = Some(msg.peer_actors.accountant.start);
        self.gossip_acceptor_info_opt = Some(Either::Right(GossipAcceptorSubs {
            connection_progress_sub: msg.peer_actors.neighborhood.connection_progress_sub,
            stream_shutdown_sub: msg.peer_actors.dispatcher.stream_shutdown_sub,
        }));
        self.gossip_producer_opt = Some(Box::new(GossipProducerReal::new()));
        self.node_to_ui_sub_opt = Some(msg.peer_actors.ui_gateway.node_to_ui_message_sub);
    }
}

impl Handler<PoolBindMessage> for Neighborhood {
    type Result = ();

    fn handle(&mut self, msg: PoolBindMessage, _: &mut Self::Context) -> Self::Result {
        let gossip_acceptor_subs = self
            .gossip_acceptor_info_opt
            .take()
            .expect("Neighborhood never got its BindMessage")
            .right_or_else(|_| panic!("Neighborhood got multiple PoolBindMessages"));
        self.gossip_acceptor_info_opt = Some(Either::Left(Box::new(GossipAcceptorReal::new(
            self.cryptde,
            gossip_acceptor_subs.connection_progress_sub,
            msg.stream_handler_pool_subs.remove_stream_sub,
            gossip_acceptor_subs.stream_shutdown_sub,
        ))));
    }
}

impl Handler<StartMessage> for Neighborhood {
    type Result = ();

    fn handle(&mut self, _msg: StartMessage, _ctx: &mut Self::Context) -> Self::Result {
        self.handle_start_message();
    }
}

impl Handler<NewPublicIp> for Neighborhood {
    type Result = ();

    fn handle(&mut self, msg: NewPublicIp, _ctx: &mut Self::Context) -> Self::Result {
        self.handle_new_public_ip(msg);
    }
}

//TODO comes across as basically dead code
// I think the idea was to supply the wallet if wallets hadn't been generated until recently during the ongoing Node's run
impl Handler<SetConsumingWalletMessage> for Neighborhood {
    type Result = ();

    fn handle(&mut self, msg: SetConsumingWalletMessage, _ctx: &mut Self::Context) -> Self::Result {
        self.consuming_wallet_opt = Some(msg.wallet);
    }
}

impl Handler<NodeQueryMessage> for Neighborhood {
    type Result = MessageResult<NodeQueryMessage>;

    fn handle(
        &mut self,
        msg: NodeQueryMessage,
        _ctx: &mut Self::Context,
    ) -> <Self as Handler<NodeQueryMessage>>::Result {
        let node_record_ref_opt = match msg {
            NodeQueryMessage::IpAddress(ip_addr) => self.neighborhood_database.node_by_ip(ip_addr),
            NodeQueryMessage::PublicKey(key) => self.neighborhood_database.node_by_key(&key),
        };

        MessageResult(node_record_ref_opt.map(|node_record_ref| {
            NodeQueryResponseMetadata::new(
                node_record_ref.public_key().clone(),
                node_record_ref.node_addr_opt(),
                *node_record_ref.rate_pack(),
            )
        }))
    }
}

impl Handler<DispatcherNodeQueryMessage> for Neighborhood {
    type Result = ();

    fn handle(
        &mut self,
        msg: DispatcherNodeQueryMessage,
        _ctx: &mut Self::Context,
    ) -> <Self as Handler<DispatcherNodeQueryMessage>>::Result {
        let node_record_ref_opt = match msg.query {
            NodeQueryMessage::IpAddress(ip_addr) => self.neighborhood_database.node_by_ip(ip_addr),
            NodeQueryMessage::PublicKey(key) => self.neighborhood_database.node_by_key(&key),
        };

        let node_descriptor = node_record_ref_opt.map(|node_record_ref| {
            NodeQueryResponseMetadata::new(
                node_record_ref.public_key().clone(),
                node_record_ref.node_addr_opt(),
                *node_record_ref.rate_pack(),
            )
        });

        let response = DispatcherNodeQueryResponse {
            result: node_descriptor,
            context: msg.context,
        };

        msg.recipient
            .try_send(response)
            .expect("Dispatcher's StreamHandlerPool is dead");
    }
}

impl Handler<RouteQueryMessage> for Neighborhood {
    type Result = MessageResult<RouteQueryMessage>;

    fn handle(
        &mut self,
        msg: RouteQueryMessage,
        _ctx: &mut Self::Context,
    ) -> <Self as Handler<RouteQueryMessage>>::Result {
        let response = self.handle_route_query_message(msg);
        MessageResult(response)
    }
}

impl Handler<ExpiredCoresPackage<Gossip_0v1>> for Neighborhood {
    type Result = ();

    fn handle(
        &mut self,
        msg: ExpiredCoresPackage<Gossip_0v1>,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        let incoming_gossip = msg.payload;
        self.log_incoming_gossip(&incoming_gossip, msg.immediate_neighbor);
        self.handle_gossip(incoming_gossip, msg.immediate_neighbor);
    }
}

impl Handler<ExpiredCoresPackage<GossipFailure_0v1>> for Neighborhood {
    type Result = ();

    fn handle(
        &mut self,
        msg: ExpiredCoresPackage<GossipFailure_0v1>,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        self.handle_gossip_failure(msg.immediate_neighbor, msg.payload);
    }
}

impl Handler<RemoveNeighborMessage> for Neighborhood {
    type Result = ();

    fn handle(&mut self, msg: RemoveNeighborMessage, _ctx: &mut Self::Context) -> Self::Result {
        let public_key = &msg.public_key;
        match self.neighborhood_database.remove_neighbor(public_key) {
            Err(s) => error!(self.logger, "{}", s),
            Ok(db_changed) => {
                if db_changed {
                    self.gossip_to_neighbors();
                    info!(
                        self.logger,
                        "removed neighbor by public key: {}", public_key
                    )
                }
            }
        }
    }
}

impl Handler<ConnectionProgressMessage> for Neighborhood {
    type Result = ();

    fn handle(&mut self, msg: ConnectionProgressMessage, ctx: &mut Self::Context) -> Self::Result {
        match self
            .overall_connection_status
            .get_connection_progress_to_modify(&msg)
        {
            Ok(connection_progress) => {
                OverallConnectionStatus::update_connection_stage(
                    connection_progress,
                    msg.event.clone(),
                    &self.logger,
                );
                match msg.event {
                    ConnectionProgressEvent::TcpConnectionSuccessful => {
                        self.send_ask_about_debut_gossip_message(ctx, msg.peer_addr);
                    }
                    ConnectionProgressEvent::IntroductionGossipReceived(_)
                    | ConnectionProgressEvent::StandardGossipReceived => {
                        self.overall_connection_status
                            .update_ocs_stage_and_send_message_to_ui(
                                OverallConnectionStage::ConnectedToNeighbor,
                                self.node_to_ui_sub_opt
                                    .as_ref()
                                    .expect("UI Gateway is unbound"),
                                &self.logger,
                            );
                    }
                    _ => (),
                }
            }
            Err(e) => {
                trace!(
                    self.logger,
                    "Found unnecessary connection progress message - {}",
                    e
                );
            }
        }
    }
}

impl Handler<AskAboutDebutGossipMessage> for Neighborhood {
    type Result = ();

    fn handle(
        &mut self,
        msg: AskAboutDebutGossipMessage,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        let node_descriptor = &msg.prev_connection_progress.initial_node_descriptor;
        if let Ok(current_connection_progress) = self
            .overall_connection_status
            .get_connection_progress_by_desc(node_descriptor)
        {
            if msg.prev_connection_progress == *current_connection_progress {
                // No change, hence no response was received
                OverallConnectionStatus::update_connection_stage(
                    current_connection_progress,
                    ConnectionProgressEvent::NoGossipResponseReceived,
                    &self.logger,
                );
            }
        } else {
            trace!(
                self.logger,
                "Received an AskAboutDebutGossipMessage for an unknown node descriptor: {:?}; ignoring",
                node_descriptor
            )
        }
    }
}

impl Handler<NodeRecordMetadataMessage> for Neighborhood {
    type Result = ();

    fn handle(&mut self, msg: NodeRecordMetadataMessage, _ctx: &mut Self::Context) -> Self::Result {
        match msg.metadata_change {
            NRMetadataChange::AddUnreachableHost { hostname } => {
                let public_key = msg.public_key;
                let node_record = self
                    .neighborhood_database
                    .node_by_key_mut(&public_key)
                    .unwrap_or_else(|| {
                        panic!("No Node Record found for public_key: {:?}", public_key)
                    });
                debug!(
                    self.logger,
                    "Marking host {hostname} unreachable for the Node with public key {:?}",
                    public_key
                );
                node_record.metadata.unreachable_hosts.insert(hostname);
            }
        }
    }
}

impl Handler<StreamShutdownMsg> for Neighborhood {
    type Result = ();

    fn handle(&mut self, msg: StreamShutdownMsg, _ctx: &mut Self::Context) -> Self::Result {
        self.handle_stream_shutdown_msg(msg);
    }
}

impl Handler<NodeFromUiMessage> for Neighborhood {
    type Result = ();

    fn handle(&mut self, msg: NodeFromUiMessage, _ctx: &mut Self::Context) -> Self::Result {
        let client_id = msg.client_id;
        if let Ok((_, context_id)) = UiConnectionStatusRequest::fmb(msg.body.clone()) {
            self.handle_connection_status_message(client_id, context_id);
        } else if let Ok((body, _)) = UiShutdownRequest::fmb(msg.body.clone()) {
            self.handle_shutdown_order(client_id, body);
        } else {
            handle_ui_crash_request(msg, &self.logger, self.crashable, CRASH_KEY)
        }
    }
}

impl Handler<NewPasswordMessage> for Neighborhood {
    type Result = ();

    fn handle(&mut self, msg: NewPasswordMessage, _ctx: &mut Self::Context) -> Self::Result {
        self.handle_new_password(msg.new_password);
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct AccessibleGossipRecord {
    pub signed_gossip: PlainData,
    pub signature: CryptData,
    pub node_addr_opt: Option<NodeAddr>,
    pub inner: NodeRecordInner_0v1,
}

impl AccessibleGossipRecord {
    pub fn regenerate_signed_gossip(&mut self, cryptde: &dyn CryptDE) {
        let (signed_gossip, signature) = regenerate_signed_gossip(&self.inner, cryptde);
        self.signed_gossip = signed_gossip;
        self.signature = signature;
    }
}

impl TryFrom<GossipNodeRecord> for AccessibleGossipRecord {
    type Error = String;

    fn try_from(value: GossipNodeRecord) -> Result<Self, Self::Error> {
        match serde_cbor::de::from_slice(value.signed_data.as_slice()) {
            Ok(inner) => Ok(AccessibleGossipRecord {
                signed_gossip: value.signed_data,
                signature: value.signature,
                node_addr_opt: value.node_addr_opt,
                inner,
            }),
            Err(e) => Err(format!("{}", e)),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum RouteDirection {
    Over,
    Back,
}

impl Neighborhood {
    pub fn new(cryptde: &'static dyn CryptDE, config: &BootstrapperConfig) -> Self {
        let neighborhood_config = &config.neighborhood_config;
        if neighborhood_config.mode.is_zero_hop()
            && !neighborhood_config.mode.neighbor_configs().is_empty()
        {
            panic!(
                "A zero-hop MASQ Node is not decentralized and cannot have a --neighbors setting"
            )
        }
        let neighborhood_database = NeighborhoodDatabase::new(
            cryptde.public_key(),
            neighborhood_config.mode.clone(),
            config.earning_wallet.clone(),
            cryptde,
        );
        let is_mainnet = config.blockchain_bridge_config.chain.is_mainnet();
        let initial_neighbors: Vec<NodeDescriptor> = neighborhood_config
            .mode
            .neighbor_configs()
            .iter()
            .map(|nc| {
                let mainnet_nc = nc.blockchain.is_mainnet();
                if mainnet_nc != is_mainnet {
                    panic!(
                        "Neighbor {} is {}on the mainnet blockchain",
                        nc.to_string(cryptde),
                        if mainnet_nc { "" } else { "not " }
                    );
                }
                nc.clone()
            })
            .collect_vec();

        let overall_connection_status = OverallConnectionStatus::new(initial_neighbors);

        Neighborhood {
            cryptde,
            hopper_opt: None,
            hopper_no_lookup_sub_opt: None,
            connected_signal_sub_opt: None,
            node_to_ui_sub_opt: None,
            gossip_acceptor_info_opt: None,
            gossip_producer_opt: None,
            neighborhood_database,
            consuming_wallet_opt: config.consuming_wallet_opt.clone(),
            next_return_route_id: 0,
            overall_connection_status,
            chain: config.blockchain_bridge_config.chain,
            crashable: config.crash_point == CrashPoint::Message,
            data_directory: config.data_directory.clone(),
            persistent_config_opt: None,
            db_password_opt: config.db_password_opt.clone(),
            logger: Logger::new("Neighborhood"),
            tools: NeighborhoodTools::default(),
        }
    }

    pub fn make_subs_from(addr: &Addr<Neighborhood>) -> NeighborhoodSubs {
        NeighborhoodSubs {
            bind: addr.clone().recipient::<BindMessage>(),
            pool_bind: addr.clone().recipient::<PoolBindMessage>(),
            start: addr.clone().recipient::<StartMessage>(),
            new_public_ip: addr.clone().recipient::<NewPublicIp>(),
            node_query: addr.clone().recipient::<NodeQueryMessage>(),
            route_query: addr.clone().recipient::<RouteQueryMessage>(),
            update_node_record_metadata: addr.clone().recipient::<NodeRecordMetadataMessage>(),
            from_hopper: addr.clone().recipient::<ExpiredCoresPackage<Gossip_0v1>>(),
            gossip_failure: addr
                .clone()
                .recipient::<ExpiredCoresPackage<GossipFailure_0v1>>(),
            dispatcher_node_query: addr.clone().recipient::<DispatcherNodeQueryMessage>(),
            remove_neighbor: addr.clone().recipient::<RemoveNeighborMessage>(),
            stream_shutdown_sub: addr.clone().recipient::<StreamShutdownMsg>(),
            set_consuming_wallet_sub: addr.clone().recipient::<SetConsumingWalletMessage>(),
            from_ui_message_sub: addr.clone().recipient::<NodeFromUiMessage>(),
            new_password_sub: addr.clone().recipient::<NewPasswordMessage>(),
            connection_progress_sub: addr.clone().recipient::<ConnectionProgressMessage>(),
        }
    }

    fn handle_start_message(&mut self) {
        debug!(self.logger, "Connecting to persistent database");
        self.connect_database();
        self.send_debut_gossip_to_all_initial_descriptors();
    }

    fn handle_new_public_ip(&mut self, msg: NewPublicIp) {
        let new_public_ip = msg.new_ip;
        let old_public_ip = self
            .neighborhood_database
            .root()
            .node_addr_opt()
            .expectv("Root node")
            .ip_addr();
        self.neighborhood_database.new_public_ip(new_public_ip);
        info!(
            self.logger,
            "Changed public IP from {} to {}", old_public_ip, new_public_ip
        );
        self.neighborhood_database
            .root()
            .inner
            .neighbors
            .iter()
            .flat_map(|key| {
                self.neighborhood_database
                    .node_by_key(key)
                    .expect("Node disappeared!")
                    .node_addr_opt()
                    .map(|node_addr| (key, node_addr))
            })
            .for_each(|(key, node_addr)| {
                let gossip = self
                    .gossip_producer_opt
                    .as_ref()
                    .expect("No GossipProducer")
                    .produce_debut_or_ipchange(&self.neighborhood_database);
                let message_type = MessageType::Gossip(VersionedData::new(
                    &crate::sub_lib::migrations::gossip::MIGRATIONS,
                    &gossip,
                ));
                self.send_no_lookup_package(message_type, key, &node_addr);
            });
    }

    fn handle_route_query_message(&mut self, msg: RouteQueryMessage) -> Option<RouteQueryResponse> {
        let debug_msg_opt = self.logger.debug_enabled().then(|| format!("{:?}", msg));
        let route_result = if msg.minimum_hop_count == 0 {
            Ok(self.zero_hop_route_response())
        } else {
            self.make_round_trip_route(msg)
        };
        match route_result {
            Ok(response) => {
                let msg_str = debug_msg_opt.expect("Debug Message wasn't built but expected.");
                debug!(
                    self.logger,
                    "Processed {} into {}-hop response",
                    msg_str,
                    response.route.hops.len(),
                );
                Some(response)
            }
            Err(msg) => {
                error!(self.logger, "Unsatisfied route query: {}", msg);
                None
            }
        }
    }

    fn connect_database(&mut self) {
        if self.persistent_config_opt.is_none() {
            let db_initializer = DbInitializerReal::default();
            let conn = db_initializer
                .initialize(
                    &self.data_directory,
                    DbInitializationConfig::panic_on_migration(),
                )
                .expect("Neighborhood could not connect to database");
            self.persistent_config_opt = Some(Box::new(PersistentConfigurationReal::from(conn)));
        }
    }

    fn send_debut_gossip_to_all_initial_descriptors(&mut self) {
        if self.overall_connection_status.is_empty() {
            info!(self.logger, "Empty. No Nodes to report to; continuing");
            return;
        }

        let gossip = self
            .gossip_producer_opt
            .as_ref()
            .expect("Gossip Producer uninitialized")
            .produce_debut_or_ipchange(&self.neighborhood_database);
        self.overall_connection_status
            .iter_initial_node_descriptors()
            .for_each(|node_descriptor| {
                self.send_debut_gossip_to_descriptor(&gossip, node_descriptor)
            });
    }

    fn send_debut_gossip_to_descriptor(
        &self,
        debut_gossip: &Gossip_0v1,
        node_descriptor: &NodeDescriptor,
    ) {
        let node_addr = &node_descriptor
            .node_addr_opt
            .as_ref()
            .expect("Node descriptor without IP Address got through Neighborhood constructor.");
        self.send_no_lookup_package(
            MessageType::Gossip(debut_gossip.clone().into()),
            &node_descriptor.encryption_public_key,
            node_addr,
        );
        debug!(self.logger, "Debut Gossip sent to {:?}.", node_descriptor);
        trace!(
            self.logger,
            "Sent Gossip: {}",
            debut_gossip.to_dot_graph(
                self.neighborhood_database.root(),
                (
                    &node_descriptor.encryption_public_key,
                    &node_descriptor.node_addr_opt
                ),
            )
        )
    }

    fn log_incoming_gossip(&self, incoming_gossip: &Gossip_0v1, gossip_source: SocketAddr) {
        let source = match self.neighborhood_database.node_by_ip(gossip_source.ip()) {
            Some(node) => DotGossipEndpoint::from(node),
            None => DotGossipEndpoint::from(gossip_source),
        };
        trace!(
            self.logger,
            "Received Gossip: {}",
            incoming_gossip.to_dot_graph(source, self.neighborhood_database.root())
        );
    }

    fn handle_gossip(&mut self, incoming_gossip: Gossip_0v1, gossip_source: SocketAddr) {
        let record_count = incoming_gossip.node_records.len();
        info!(
            self.logger,
            "Processing Gossip about {} Nodes", record_count
        );
        let agrs: Vec<AccessibleGossipRecord> = incoming_gossip
            .node_records
            .into_iter()
            .flat_map(AccessibleGossipRecord::try_from)
            .collect();

        if agrs.len() < record_count {
            // TODO: Instead of ignoring non-deserializable Gossip, malefactor-ban the Node that sent it
            error!(
                self.logger,
                "Received non-deserializable Gossip from {}", gossip_source
            );
            self.announce_gossip_handling_completion(record_count);
            return;
        }

        let signature_invalid = |agr: &AccessibleGossipRecord| {
            !self.cryptde.verify_signature(
                &agr.signed_gossip,
                &agr.signature,
                &agr.inner.public_key,
            )
        };
        if agrs.iter().any(signature_invalid) {
            // TODO: Instead of ignoring badly-signed Gossip, ban the Node that sent it
            error!(
                self.logger,
                "Received Gossip with invalid signature from {}", gossip_source
            );
            self.announce_gossip_handling_completion(record_count);
            return;
        }

        self.handle_gossip_agrs(agrs, gossip_source);
        self.announce_gossip_handling_completion(record_count);
    }

    fn handle_gossip_failure(&mut self, failure_source: SocketAddr, failure: GossipFailure_0v1) {
        let tuple_opt = match self
            .overall_connection_status
            .iter_initial_node_descriptors()
            .find_position(|n| match &n.node_addr_opt {
                None => false,
                Some(node_addr) => node_addr.ip_addr() == failure_source.ip(),
            }) {
            None => unimplemented!("TODO: Test-drive me (or replace me with a panic)"),
            Some(tuple) => Some(tuple),
        };
        if let Some((position, node_descriptor)) = tuple_opt {
            warning!(
                self.logger,
                "Node at {} refused Debut: {}",
                node_descriptor
                    .node_addr_opt
                    .as_ref()
                    .expectv("NodeAddr")
                    .ip_addr(),
                failure
            );

            self.overall_connection_status.remove(position);
            if self.overall_connection_status.is_empty() {
                error!(self.logger, "None of the Nodes listed in the --neighbors parameter could accept your Debut; shutting down");
                System::current().stop_with_code(1)
            }
        };
    }

    fn to_node_descriptors(&self, keys: &[PublicKey]) -> Vec<NodeDescriptor> {
        keys.iter()
            .map(|k| {
                NodeDescriptor::from((
                    self.neighborhood_database
                        .node_by_key(k)
                        .expectv("NodeRecord"),
                    self.chain,
                    self.cryptde,
                ))
            })
            .collect()
    }

    fn handle_gossip_agrs(&mut self, agrs: Vec<AccessibleGossipRecord>, gossip_source: SocketAddr) {
        let neighbor_keys_before = self.neighbor_keys();
        self.handle_agrs(agrs, gossip_source);
        let neighbor_keys_after = self.neighbor_keys();
        self.handle_database_changes(neighbor_keys_before, neighbor_keys_after);
    }

    fn neighbor_keys(&self) -> HashSet<PublicKey> {
        self.neighborhood_database
            .root()
            .full_neighbor_keys(&self.neighborhood_database)
            .into_iter()
            .cloned()
            .collect()
    }

    fn handle_agrs(&mut self, agrs: Vec<AccessibleGossipRecord>, gossip_source: SocketAddr) {
        let gossip_source_name = self.gossip_source_name(&agrs, gossip_source);
        let gossip_record_count = agrs.len();
        let connection_progress_peers = self.overall_connection_status.get_peer_addrs();
        let acceptance_result = self
            .gossip_acceptor_info_opt
            .as_ref()
            .expect("Gossip Acceptor wasn't created.")
            .as_ref()
            .left_or_else(|_| panic!("Neighborhood never got its PoolBindMessage"))
            .handle(
                &mut self.neighborhood_database,
                agrs,
                gossip_source,
                &connection_progress_peers,
            );
        self.process_acceptance_result(acceptance_result, &gossip_source_name, gossip_record_count);
    }

    fn process_acceptance_result(
        &mut self,
        acceptance_result: GossipAcceptanceResult,
        gossip_source_key_or_addr: &str,
        gossip_record_count: usize,
    ) {
        match acceptance_result {
            GossipAcceptanceResult::Accepted => self.gossip_to_neighbors(),
            GossipAcceptanceResult::Reply(next_debut, target_key, target_node_addr) => {
                self.handle_gossip_reply(next_debut, &target_key, &target_node_addr)
            }
            GossipAcceptanceResult::Failed(failure, target_key, target_node_addr) => {
                self.handle_gossip_failed(failure, &target_key, &target_node_addr)
            }
            GossipAcceptanceResult::Ignored => {
                trace!(
                    self.logger,
                    "{}-Node Gossip from {} ignored",
                    gossip_record_count,
                    gossip_source_key_or_addr
                );
            }
            GossipAcceptanceResult::Absorbed => {
                trace!(
                    self.logger,
                    "{}-Node Gossip from {} absorbed",
                    gossip_record_count,
                    gossip_source_key_or_addr
                )
            }
            GossipAcceptanceResult::Ban(reason) => {
                warning!(self.logger, "Malefactor detected at {}, but malefactor bans not yet implemented; ignoring: {}", gossip_source_key_or_addr, reason);
            }
        }
    }

    fn handle_database_changes(
        &mut self,
        neighbor_keys_before: HashSet<PublicKey>,
        neighbor_keys_after: HashSet<PublicKey>,
    ) {
        self.curate_past_neighbors(neighbor_keys_before, neighbor_keys_after);
        self.check_connectedness();
    }

    fn curate_past_neighbors(
        &mut self,
        neighbor_keys_before: HashSet<PublicKey>,
        neighbor_keys_after: HashSet<PublicKey>,
    ) {
        if neighbor_keys_after != neighbor_keys_before {
            if let Some(db_password) = &self.db_password_opt {
                let nds = self
                    .to_node_descriptors(neighbor_keys_after.into_iter().collect_vec().as_slice());
                let node_descriptors_opt = if nds.is_empty() { None } else { Some(nds) };
                debug!(
                    self.logger,
                    "Saving neighbor list: {:?}", node_descriptors_opt
                );
                match self
                    .persistent_config_opt
                    .as_mut()
                    .expect("PersistentConfig was not set by StartMessage")
                    .set_past_neighbors(node_descriptors_opt, db_password)
                {
                    Ok(_) => info!(self.logger, "Persisted neighbor changes for next run"),
                    Err(PersistentConfigError::DatabaseError(msg))
                        if &msg == "database is locked" =>
                    {
                        warning! (
                        self.logger,
                        "Could not persist immediate-neighbor changes: database locked - skipping"
                    )
                    }
                    Err(e) => error!(
                        self.logger,
                        "Could not persist immediate-neighbor changes: {:?}", e
                    ),
                };
            } else {
                info!(self.logger, "Declining to persist neighbor changes for next run: no database password supplied")
            }
        } else {
            debug!(self.logger, "No neighbor changes; database is unchanged")
        }
    }

    fn check_connectedness(&mut self) {
        if self.overall_connection_status.can_make_routes() {
            return;
        }
        let msg = RouteQueryMessage {
            target_key_opt: None,
            target_component: Component::ProxyClient,
            minimum_hop_count: DEFAULT_MINIMUM_HOP_COUNT,
            return_component_opt: Some(Component::ProxyServer),
            payload_size: 10000,
            hostname_opt: None,
        };
        if self.handle_route_query_message(msg).is_some() {
            debug!(
                &self.logger,
                "The connectivity check has found a 3 hops route."
            );
            self.overall_connection_status
                .update_ocs_stage_and_send_message_to_ui(
                    OverallConnectionStage::ThreeHopsRouteFound,
                    self.node_to_ui_sub_opt.as_ref().expect("UI was not bound."),
                    &self.logger,
                );
            self.connected_signal_sub_opt
                .as_ref()
                .expect("Accountant was not bound")
                .try_send(StartMessage {})
                .expect("Accountant is dead")
        } else {
            debug!(
                &self.logger,
                "The connectivity check still can't find a good route."
            );
        }
    }

    fn announce_gossip_handling_completion(&self, record_count: usize) {
        info!(
            self.logger,
            "Finished processing Gossip about {} Nodes", record_count
        );
    }

    fn gossip_to_neighbors(&mut self) {
        self.neighborhood_database
            .root_mut()
            .regenerate_signed_gossip(self.cryptde);
        let neighbors = self
            .neighborhood_database
            .root()
            .half_neighbor_keys()
            .into_iter()
            .cloned()
            .collect_vec();
        neighbors.iter().for_each(|neighbor| {
            if let Some(gossip) = self
                .gossip_producer_opt
                .as_ref()
                .expect("Gossip Producer uninitialized")
                .produce(&mut self.neighborhood_database, neighbor)
            {
                self.gossip_to_neighbor(neighbor, gossip)
            }
        });
    }

    fn gossip_to_neighbor(&self, neighbor: &PublicKey, gossip: Gossip_0v1) {
        let gossip_len = gossip.node_records.len();
        let route = self.create_single_hop_route(neighbor);
        let package =
            IncipientCoresPackage::new(self.cryptde, route, gossip.clone().into(), neighbor)
                .expect("Key magically disappeared");
        info!(
            self.logger,
            "Sending update Gossip about {} Nodes to Node {}", gossip_len, neighbor
        );
        self.hopper_opt
            .as_ref()
            .expect("unbound hopper")
            .try_send(package)
            .expect("hopper is dead");
        trace!(
            self.logger,
            "Sent Gossip: {}",
            gossip.to_dot_graph(
                self.neighborhood_database.root(),
                self.neighborhood_database
                    .node_by_key(neighbor)
                    .expect("Node magically disappeared"),
            )
        );
    }

    fn create_single_hop_route(&self, destination: &PublicKey) -> Route {
        Route::one_way(
            RouteSegment::new(
                vec![self.cryptde.public_key(), destination],
                Component::Neighborhood,
            ),
            self.cryptde,
            None,
            None,
        )
        .expect("route creation error")
    }

    fn zero_hop_route_response(&mut self) -> RouteQueryResponse {
        let return_route_id = self.advance_return_route_id();
        let route = Route::round_trip(
            RouteSegment::new(
                vec![self.cryptde.public_key(), self.cryptde.public_key()],
                Component::ProxyClient,
            ),
            RouteSegment::new(
                vec![self.cryptde.public_key(), self.cryptde.public_key()],
                Component::ProxyServer,
            ),
            self.cryptde,
            None,
            return_route_id,
            None,
        )
        .expect("Couldn't create route");
        RouteQueryResponse {
            route,
            expected_services: ExpectedServices::RoundTrip(
                vec![ExpectedService::Nothing, ExpectedService::Nothing],
                vec![ExpectedService::Nothing, ExpectedService::Nothing],
                return_route_id,
            ),
        }
    }

    fn make_round_trip_route(
        &mut self,
        request_msg: RouteQueryMessage,
    ) -> Result<RouteQueryResponse, String> {
        let hostname_opt = request_msg.hostname_opt.as_deref();
        let over = self.make_route_segment(
            self.cryptde.public_key(),
            request_msg.target_key_opt.as_ref(),
            request_msg.minimum_hop_count,
            request_msg.target_component,
            request_msg.payload_size,
            RouteDirection::Over,
            hostname_opt,
        )?;
        debug!(self.logger, "Route over: {:?}", over);
        // Estimate for routing-undesirability calculations.
        // We don't know what the size of response will be.
        // So, we estimate the value by multiplying the payload_size of request with a constant value.
        let anticipated_response_payload_len =
            request_msg.payload_size * RESPONSE_UNDESIRABILITY_FACTOR;
        let back = self.make_route_segment(
            over.keys.last().expect("Empty segment"),
            Some(self.cryptde.public_key()),
            request_msg.minimum_hop_count,
            request_msg
                .return_component_opt
                .expect("No return component"),
            anticipated_response_payload_len,
            RouteDirection::Back,
            hostname_opt,
        )?;
        debug!(self.logger, "Route back: {:?}", back);
        self.compose_route_query_response(over, back)
    }

    fn compose_route_query_response(
        &mut self,
        over: RouteSegment,
        back: RouteSegment,
    ) -> Result<RouteQueryResponse, String> {
        let segments = vec![&over, &back];

        if segments.iter().any(|rs| rs.keys.is_empty()) {
            return Err("Cannot make multi-hop route without segment keys".to_string());
        }

        let has_long_segment = segments.iter().any(|segment| segment.keys.len() > 2);
        if self.consuming_wallet_opt.is_none() && has_long_segment {
            return Err("Cannot make multi-hop route segment without consuming wallet".to_string());
        }

        let expected_request_services = match self.make_expected_services(&over) {
            Ok(services) => services,
            Err(e) => return Err(e),
        };

        let expected_response_services = match self.make_expected_services(&back) {
            Ok(services) => services,
            Err(e) => return Err(e),
        };

        let return_route_id = self.advance_return_route_id();
        Ok(RouteQueryResponse {
            route: Route::round_trip(
                over,
                back,
                self.cryptde,
                self.consuming_wallet_opt.clone(),
                return_route_id,
                Some(self.chain.rec().contract),
            )
            .expect("Internal error: bad route"),
            expected_services: ExpectedServices::RoundTrip(
                expected_request_services,
                expected_response_services,
                return_route_id,
            ),
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn make_route_segment(
        &self,
        origin: &PublicKey,
        target_opt: Option<&PublicKey>,
        minimum_hop_count: usize,
        target_component: Component,
        payload_size: usize,
        direction: RouteDirection,
        hostname_opt: Option<&str>,
    ) -> Result<RouteSegment, String> {
        let route_opt = self.find_best_route_segment(
            origin,
            target_opt,
            minimum_hop_count,
            payload_size,
            direction,
            hostname_opt,
        );
        match route_opt {
            None => {
                let target_str = match target_opt {
                    Some(t) => format!(" {}", t),
                    None => String::from("Unknown"),
                };
                Err(format!(
                    "Couldn't find any routes: at least {}-hop from {} to {:?} at {}",
                    minimum_hop_count, origin, target_component, target_str
                ))
            }
            Some(route) => Ok(RouteSegment::new(route, target_component)),
        }
    }

    fn make_expected_services(
        &self,
        segment: &RouteSegment,
    ) -> Result<Vec<ExpectedService>, String> {
        segment
            .keys
            .iter()
            .map(|key| {
                self.calculate_expected_service(key, segment.keys.first(), segment.keys.last())
            })
            .collect()
    }

    fn calculate_expected_service(
        &self,
        route_segment_key: &PublicKey,
        originator_key: Option<&PublicKey>,
        exit_key: Option<&PublicKey>,
    ) -> Result<ExpectedService, String> {
        match self.neighborhood_database.node_by_key(route_segment_key) {
            Some(node) => {
                if route_segment_key == self.neighborhood_database.root().public_key() {
                    Ok(ExpectedService::Nothing)
                } else {
                    match (originator_key, exit_key) {
                        (Some(originator_key), Some(exit_key))
                            if route_segment_key == originator_key
                                || route_segment_key == exit_key =>
                        {
                            Ok(ExpectedService::Exit(
                                route_segment_key.clone(),
                                node.earning_wallet(),
                                *node.rate_pack(),
                            ))
                        }
                        (Some(_), Some(_)) => Ok(ExpectedService::Routing(
                            route_segment_key.clone(),
                            node.earning_wallet(),
                            *node.rate_pack(),
                        )),
                        _ => Err(
                            "cannot calculate expected service, no keys provided in route segment"
                                .to_string(),
                        ),
                    }
                }
            }
            None => Err("Cannot make multi_hop with unknown neighbor".to_string()),
        }
    }

    fn route_length_qualifies(&self, hops_remaining: usize) -> bool {
        hops_remaining == 0
    }

    fn last_key_qualifies(
        &self,
        last_node_ref: &NodeRecord,
        target_key_ref_opt: Option<&PublicKey>,
    ) -> bool {
        match target_key_ref_opt {
            Some(target_key_ref) => last_node_ref.public_key() == target_key_ref,
            None => true,
        }
    }

    fn validate_last_node_not_too_close_to_first_node(
        &self,
        prefix_len: usize,
        first_node_key: &PublicKey,
        candidate_node_key: &PublicKey,
    ) -> bool {
        if prefix_len <= 2 {
            true // Zero- and single-hop routes are not subject to exit-too-close restrictions
        } else {
            !self
                .neighborhood_database
                .has_half_neighbor(candidate_node_key, first_node_key)
        }
    }

    fn compute_undesirability(
        node_record: &NodeRecord,
        payload_size: u64,
        undesirability_type: UndesirabilityType,
        logger: &Logger,
    ) -> i64 {
        let mut rate_undesirability = match undesirability_type {
            UndesirabilityType::Relay => node_record.inner.rate_pack.routing_charge(payload_size),
            UndesirabilityType::ExitRequest(_) => {
                node_record.inner.rate_pack.exit_charge(payload_size)
            }
            UndesirabilityType::ExitAndRouteResponse => {
                node_record.inner.rate_pack.exit_charge(payload_size)
                    + node_record.inner.rate_pack.routing_charge(payload_size)
            }
        } as i64;
        if let UndesirabilityType::ExitRequest(Some(hostname)) = undesirability_type {
            if node_record.metadata.unreachable_hosts.contains(hostname) {
                trace!(
                    logger,
                    "Node with PubKey {:?} failed to reach host {:?} during ExitRequest; Undesirability: {} + {} = {}",
                    node_record.public_key(),
                    hostname,
                    rate_undesirability,
                    UNREACHABLE_HOST_PENALTY,
                    rate_undesirability + UNREACHABLE_HOST_PENALTY
                );
                rate_undesirability += UNREACHABLE_HOST_PENALTY;
            }
        }

        rate_undesirability
    }

    fn is_orig_node_on_back_leg(
        node: &NodeRecord,
        target_key_opt: Option<&PublicKey>,
        direction: RouteDirection,
    ) -> bool {
        match direction {
            RouteDirection::Over => false,
            RouteDirection::Back => match target_key_opt {
                None => false,
                Some(target_key) => node.public_key() == target_key,
            },
        }
    }

    fn advance_return_route_id(&mut self) -> u32 {
        let return_route_id = self.next_return_route_id;
        self.next_return_route_id = return_route_id.wrapping_add(1);
        return_route_id
    }

    // Interface to main routing engine. Supply source key, target key--if any--in target_opt,
    // minimum hops, size of payload in bytes, the route direction, and the hostname if you know it.
    //
    // Return value is the least undesirable route that will either go from the origin to the
    // target in hops_remaining or more hops with no cycles, or from the origin hops_remaining hops
    // out into the MASQ Network. No round trips; if you want a round trip, call this method twice.
    // If the return value is None, no qualifying route was found.
    fn find_best_route_segment<'a>(
        &'a self,
        source: &'a PublicKey,
        target_opt: Option<&'a PublicKey>,
        minimum_hops: usize,
        payload_size: usize,
        direction: RouteDirection,
        hostname_opt: Option<&str>,
    ) -> Option<Vec<&'a PublicKey>> {
        let mut minimum_undesirability = i64::MAX;
        let initial_undesirability =
            self.compute_initial_undesirability(source, payload_size as u64, direction);
        let result = self
            .routing_engine(
                vec![source],
                initial_undesirability,
                target_opt,
                minimum_hops,
                payload_size,
                direction,
                &mut minimum_undesirability,
                hostname_opt,
            )
            .into_iter()
            .filter_map(|cr| match cr.undesirability <= minimum_undesirability {
                true => Some(cr.nodes),
                false => None,
            })
            .next();

        result
    }

    #[allow(clippy::too_many_arguments)]
    fn routing_engine<'a>(
        &'a self,
        prefix: Vec<&'a PublicKey>,
        undesirability: i64,
        target_opt: Option<&'a PublicKey>,
        hops_remaining: usize,
        payload_size: usize,
        direction: RouteDirection,
        minimum_undesirability: &mut i64,
        hostname_opt: Option<&str>,
    ) -> Vec<ComputedRouteSegment<'a>> {
        if undesirability > *minimum_undesirability {
            return vec![];
        }
        let first_node_key = prefix.first().expect("Empty prefix");
        let previous_node = self
            .neighborhood_database
            .node_by_key(prefix.last().expect("Empty prefix"))
            .expect("Last Node magically disappeared");
        // Check to see if we're done. If we are, all three of these qualifications will pass.
        if self.route_length_qualifies(hops_remaining)
            && self.last_key_qualifies(previous_node, target_opt)
            && self.validate_last_node_not_too_close_to_first_node(
                prefix.len(),
                *first_node_key,
                previous_node.public_key(),
            )
        {
            if undesirability < *minimum_undesirability {
                *minimum_undesirability = undesirability;
            }
            vec![ComputedRouteSegment::new(prefix, undesirability)]
        } else if (hops_remaining == 0) && target_opt.is_none() {
            // don't continue a targetless search past the minimum hop count
            vec![]
        } else {
            // Go through all the neighbors and compute shorter routes through all the ones we're not already using.
            previous_node
                .full_neighbors(&self.neighborhood_database)
                .iter()
                .filter(|node_record| !prefix.contains(&node_record.public_key()))
                .filter(|node_record| {
                    node_record.routes_data()
                        || Self::is_orig_node_on_back_leg(**node_record, target_opt, direction)
                })
                .flat_map(|node_record| {
                    let mut new_prefix = prefix.clone();
                    new_prefix.push(node_record.public_key());

                    let new_hops_remaining = if hops_remaining == 0 {
                        0
                    } else {
                        hops_remaining - 1
                    };

                    let new_undesirability = self.compute_new_undesirability(
                        node_record,
                        undesirability,
                        target_opt,
                        new_hops_remaining,
                        payload_size as u64,
                        direction,
                        hostname_opt,
                    );

                    self.routing_engine(
                        new_prefix.clone(),
                        new_undesirability,
                        target_opt,
                        new_hops_remaining,
                        payload_size,
                        direction,
                        minimum_undesirability,
                        hostname_opt,
                    )
                })
                .collect()
        }
    }

    fn send_ask_about_debut_gossip_message(
        &mut self,
        ctx: &mut Context<Neighborhood>,
        current_peer_addr: IpAddr,
    ) {
        let message = AskAboutDebutGossipMessage {
            prev_connection_progress: self
                .overall_connection_status
                .get_connection_progress_by_ip(current_peer_addr)
                .unwrap()
                .clone(),
        };
        self.tools.notify_later_ask_about_gossip.notify_later(
            message,
            self.tools.ask_about_gossip_interval,
            ctx,
        );
    }

    fn compute_initial_undesirability(
        &self,
        public_key: &PublicKey,
        payload_size: u64,
        direction: RouteDirection,
    ) -> i64 {
        if direction == RouteDirection::Over {
            return 0;
        }
        let node_record = self
            .neighborhood_database
            .node_by_key(public_key)
            .expect("Exit node disappeared");
        Self::compute_undesirability(
            node_record,
            payload_size,
            UndesirabilityType::ExitAndRouteResponse,
            &self.logger,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn compute_new_undesirability(
        &self,
        node_record: &NodeRecord,
        undesirability: i64,
        target_opt: Option<&PublicKey>,
        hops_remaining: usize,
        payload_size: u64,
        direction: RouteDirection,
        hostname_opt: Option<&str>,
    ) -> i64 {
        let undesirability_type = match (direction, target_opt) {
            (RouteDirection::Over, None) if hops_remaining == 0 => {
                UndesirabilityType::ExitRequest(hostname_opt)
            }
            (RouteDirection::Over, _) => UndesirabilityType::Relay,
            // The exit-and-relay undesirability is initial_undesirability
            (RouteDirection::Back, _) => UndesirabilityType::Relay,
        };
        let node_undesirability = Self::compute_undesirability(
            node_record,
            payload_size,
            undesirability_type,
            &self.logger,
        );
        undesirability + node_undesirability
    }

    fn handle_gossip_reply(
        &self,
        gossip: Gossip_0v1,
        target_key: &PublicKey,
        target_node_addr: &NodeAddr,
    ) {
        self.send_no_lookup_package(
            MessageType::Gossip(gossip.clone().into()),
            target_key,
            target_node_addr,
        );
        trace!(
            self.logger,
            "Sent Gossip: {}",
            gossip.to_dot_graph(
                self.neighborhood_database.root(),
                (target_key, &Some(target_node_addr.clone())),
            )
        );
    }

    fn handle_gossip_failed(
        &self,
        gossip_failure: GossipFailure_0v1,
        target_key: &PublicKey,
        target_node_addr: &NodeAddr,
    ) {
        self.send_no_lookup_package(
            MessageType::GossipFailure(VersionedData::new(
                &crate::sub_lib::migrations::gossip_failure::MIGRATIONS,
                &gossip_failure,
            )),
            target_key,
            target_node_addr,
        );
        trace!(self.logger, "Sent GossipFailure_0v1: {}", gossip_failure);
    }

    fn send_no_lookup_package(
        &self,
        message_type: MessageType,
        target_key: &PublicKey,
        target_node_addr: &NodeAddr,
    ) {
        let package = match NoLookupIncipientCoresPackage::new(
            self.cryptde,
            target_key,
            target_node_addr,
            message_type,
        ) {
            Ok(p) => p,
            Err(e) => {
                error!(self.logger, "{}", e);
                return;
            }
        };
        self.hopper_no_lookup_sub_opt
            .as_ref()
            .expect("No-lookup Hopper is unbound")
            .try_send(package)
            .expect("Hopper is dead");
    }

    fn gossip_source_name(
        &self,
        accessible_gossip: &[AccessibleGossipRecord],
        gossip_source: SocketAddr,
    ) -> String {
        match accessible_gossip.iter().find(|agr| {
            if let Some(ref node_addr) = agr.node_addr_opt {
                node_addr.ip_addr() == gossip_source.ip()
            } else {
                false
            }
        }) {
            Some(agr) => format!("{}", agr.inner.public_key),
            None => format!("{}", gossip_source),
        }
    }

    fn handle_stream_shutdown_msg(&mut self, msg: StreamShutdownMsg) {
        if msg.stream_type != RemovedStreamType::Clandestine {
            panic!("Neighborhood should never get ShutdownStreamMsg about non-clandestine stream")
        }
        let neighbor_key = match self.neighborhood_database.node_by_ip(msg.peer_addr.ip()) {
            None => {
                warning!(self.logger, "Received shutdown notification for stream to {}, but no Node with that IP is in the database - ignoring", msg.peer_addr.ip());
                return;
            }
            Some(n) => (n.public_key().clone()),
        };
        self.remove_neighbor(&neighbor_key, &msg.peer_addr);
    }

    fn handle_connection_status_message(&self, client_id: u64, context_id: u64) {
        let stage: UiConnectionStage = self.overall_connection_status.stage.into();
        let message = NodeToUiMessage {
            target: MessageTarget::ClientId(client_id),
            body: UiConnectionStatusResponse { stage }.tmb(context_id),
        };

        self.node_to_ui_sub_opt
            .as_ref()
            .expect("UI Gateway is unbound")
            .try_send(message)
            .expect("UiGateway is dead");
    }

    fn remove_neighbor(&mut self, neighbor_key: &PublicKey, peer_addr: &SocketAddr) {
        match self.neighborhood_database.remove_neighbor(neighbor_key) {
            Err(e) => panic!("Node suddenly disappeared: {:?}", e),
            Ok(true) => {
                debug!(
                    self.logger,
                    "Received shutdown notification for {} at {}: removing neighborship",
                    neighbor_key,
                    peer_addr.ip()
                );
                self.gossip_to_neighbors()
            }
            Ok(false) => {
                debug!(self.logger, "Received shutdown notification for {} at {}, but that Node is no neighbor - ignoring", neighbor_key, peer_addr.ip());
            }
        };
    }

    #[allow(unreachable_code)]
    fn handle_shutdown_order(&self, client_id: u64, _msg: UiShutdownRequest) {
        info!(
            self.logger,
            "Received shutdown order from client {}: shutting down hard", client_id
        );
        exit_process(
            0,
            &format!(
                "Received shutdown order from client {}: shutting down hard",
                client_id
            ),
        );
    }

    fn handle_new_password(&mut self, new_password: String) {
        self.db_password_opt = Some(new_password);
    }
}

pub fn regenerate_signed_gossip(
    inner: &NodeRecordInner_0v1,
    cryptde: &dyn CryptDE, // Must be the correct CryptDE for the Node from which inner came: used for signing
) -> (PlainData, CryptData) {
    let signed_gossip =
        PlainData::from(serde_cbor::ser::to_vec(&inner).expect("Serialization failed"));
    let signature = match cryptde.sign(&signed_gossip) {
        Ok(sig) => sig,
        Err(e) => unimplemented!("TODO: Signing error: {:?}", e),
    };
    (signed_gossip, signature)
}

#[derive(PartialEq, Eq, Debug)]
enum UndesirabilityType<'hostname> {
    Relay,
    ExitRequest(Option<&'hostname str>),
    ExitAndRouteResponse,
}

struct ComputedRouteSegment<'a> {
    pub nodes: Vec<&'a PublicKey>,
    pub undesirability: i64,
}

impl<'a> ComputedRouteSegment<'a> {
    pub fn new(nodes: Vec<&'a PublicKey>, undesirability: i64) -> Self {
        Self {
            nodes,
            undesirability,
        }
    }
}

#[cfg(test)]
mod tests {
    use actix::dev::{MessageResponse, ResponseChannel};
    use actix::Message;
    use actix::Recipient;
    use actix::System;
    use itertools::Itertools;
    use serde_cbor;
    use std::any::TypeId;
    use std::cell::RefCell;
    use std::convert::TryInto;
    use std::net::{IpAddr, SocketAddr};
    use std::str::FromStr;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::Duration;
    use std::time::Instant;
    use tokio::prelude::Future;

    use masq_lib::constants::{DEFAULT_CHAIN, TEST_DEFAULT_CHAIN, TLS_PORT};
    use masq_lib::messages::{ToMessageBody, UiConnectionChangeBroadcast, UiConnectionStage};
    use masq_lib::test_utils::utils::ensure_node_home_directory_exists;
    use masq_lib::ui_gateway::MessageBody;
    use masq_lib::ui_gateway::MessagePath::Conversation;
    use masq_lib::ui_gateway::MessageTarget;
    use masq_lib::utils::running_test;

    use crate::db_config::persistent_configuration::PersistentConfigError;
    use crate::neighborhood::gossip::GossipBuilder;
    use crate::neighborhood::gossip::Gossip_0v1;
    use crate::neighborhood::node_record::NodeRecordInner_0v1;
    use crate::stream_messages::{NonClandestineAttributes, RemovedStreamType};
    use crate::sub_lib::cryptde::{decodex, encodex, CryptData};
    use crate::sub_lib::cryptde_null::CryptDENull;
    use crate::sub_lib::dispatcher::Endpoint;
    use crate::sub_lib::hop::LiveHop;
    use crate::sub_lib::hopper::MessageType;
    use crate::sub_lib::neighborhood::RatePack;
    use crate::sub_lib::neighborhood::{
        AskAboutDebutGossipMessage, ExpectedServices, NeighborhoodMode,
    };
    use crate::sub_lib::neighborhood::{NeighborhoodConfig, DEFAULT_RATE_PACK};
    use crate::sub_lib::peer_actors::PeerActors;
    use crate::sub_lib::stream_handler_pool::TransmitDataMsg;
    use crate::sub_lib::versioned_data::VersionedData;
    use crate::test_utils::assert_contains;
    use crate::test_utils::make_meaningless_route;
    use crate::test_utils::make_wallet;
    use crate::test_utils::neighborhood_test_utils::{
        db_from_node, make_global_cryptde_node_record, make_ip, make_node, make_node_descriptor,
        make_node_record, make_node_record_f, neighborhood_from_nodes,
    };
    use crate::test_utils::persistent_configuration_mock::PersistentConfigurationMock;
    use crate::test_utils::rate_pack;
    use crate::test_utils::recorder::peer_actors_builder;
    use crate::test_utils::recorder::Recorder;
    use crate::test_utils::recorder::Recording;
    use crate::test_utils::recorder::{make_recorder, pool_bind_message_builder};
    use crate::test_utils::unshared_test_utils::{
        make_node_to_ui_recipient, make_recipient_and_recording_arc,
        prove_that_crash_request_handler_is_hooked_up, AssertionsMessage,
    };
    use crate::test_utils::vec_to_set;
    use crate::test_utils::{main_cryptde, make_paying_wallet};

    use super::*;
    use crate::neighborhood::overall_connection_status::ConnectionStageErrors::{
        NoGossipResponseReceived, PassLoopFound, TcpConnectionFailed,
    };
    use crate::neighborhood::overall_connection_status::{
        ConnectionProgress, ConnectionStage, OverallConnectionStage,
    };
    use crate::test_utils::unshared_test_utils::notify_handlers::NotifyLaterHandleMock;
    use masq_lib::test_utils::logging::{init_test_logging, TestLogHandler};

    impl Handler<AssertionsMessage<Neighborhood>> for Neighborhood {
        type Result = ();

        fn handle(
            &mut self,
            msg: AssertionsMessage<Neighborhood>,
            _ctx: &mut Self::Context,
        ) -> Self::Result {
            (msg.assertions)(self)
        }
    }

    #[test]
    fn constants_have_correct_values() {
        assert_eq!(CRASH_KEY, "NEIGHBORHOOD");
    }

    #[test]
    #[should_panic(
        expected = "Neighbor masq://polygon-mumbai:AQIDBA@1.2.3.4:1234 is not on the mainnet blockchain"
    )]
    fn cant_create_mainnet_neighborhood_with_non_mainnet_neighbors() {
        let cryptde = main_cryptde();
        let earning_wallet = make_wallet("earning");
        let mut bc = bc_from_nc_plus(
            NeighborhoodConfig {
                mode: NeighborhoodMode::ConsumeOnly(vec![NodeDescriptor::try_from((
                    cryptde,
                    "masq://polygon-mumbai:AQIDBA@1.2.3.4:1234",
                ))
                .unwrap()]),
            },
            earning_wallet.clone(),
            None,
            "cant_create_mainnet_neighborhood_with_non_mainnet_neighbors",
        );
        bc.blockchain_bridge_config.chain = DEFAULT_CHAIN;

        let _ = Neighborhood::new(cryptde, &bc);
    }

    #[test]
    #[should_panic(
        expected = "Neighbor masq://eth-mainnet:AQIDBA@1.2.3.4:1234 is on the mainnet blockchain"
    )]
    fn cant_create_non_mainnet_neighborhood_with_mainnet_neighbors() {
        let cryptde = main_cryptde();
        let earning_wallet = make_wallet("earning");
        let mut bc = bc_from_nc_plus(
            NeighborhoodConfig {
                mode: NeighborhoodMode::ConsumeOnly(vec![NodeDescriptor::try_from((
                    cryptde,
                    "masq://eth-mainnet:AQIDBA@1.2.3.4:1234",
                ))
                .unwrap()]),
            },
            earning_wallet.clone(),
            None,
            "cant_create_non_mainnet_neighborhood_with_mainnet_neighbors",
        );
        bc.blockchain_bridge_config.chain = TEST_DEFAULT_CHAIN;

        let _ = Neighborhood::new(cryptde, &bc);
    }

    #[test]
    fn node_with_zero_hop_config_creates_single_node_database() {
        let cryptde = main_cryptde();
        let earning_wallet = make_wallet("earning");

        let subject = Neighborhood::new(
            cryptde,
            &bc_from_nc_plus(
                NeighborhoodConfig {
                    mode: NeighborhoodMode::ZeroHop,
                },
                earning_wallet.clone(),
                None,
                "node_with_zero_hop_config_creates_single_node_database",
            ),
        );

        let root_node_record_ref = subject.neighborhood_database.root();

        assert_eq!(root_node_record_ref.public_key(), cryptde.public_key());
        assert_eq!(root_node_record_ref.node_addr_opt(), None);
        assert_eq!(root_node_record_ref.half_neighbor_keys().len(), 0);
    }

    #[test]
    fn node_with_originate_only_config_is_decentralized_with_neighbor_but_not_ip() {
        let cryptde: &dyn CryptDE = main_cryptde();
        let neighbor: NodeRecord = make_node_record(1234, true);
        let earning_wallet = make_wallet("earning");

        let subject = Neighborhood::new(
            cryptde,
            &bc_from_nc_plus(
                NeighborhoodConfig {
                    mode: NeighborhoodMode::OriginateOnly(
                        vec![neighbor.node_descriptor(TEST_DEFAULT_CHAIN, cryptde)],
                        DEFAULT_RATE_PACK.clone(),
                    ),
                },
                earning_wallet.clone(),
                None,
                "node_with_originate_only_config_is_decentralized_with_neighbor_but_not_ip",
            ),
        );

        let root_node_record_ref = subject.neighborhood_database.root();

        assert_eq!(root_node_record_ref.public_key(), cryptde.public_key());
        assert_eq!(root_node_record_ref.accepts_connections(), false);
        assert_eq!(root_node_record_ref.routes_data(), true);
        assert_eq!(root_node_record_ref.node_addr_opt(), None);
        assert_eq!(root_node_record_ref.half_neighbor_keys().len(), 0);
    }

    #[test]
    fn gossip_acceptor_and_gossip_producer_are_properly_initialized_through_bind_messages() {
        let subject = make_standard_subject();
        let addr = subject.start();
        let peer_actors = peer_actors_builder().build();
        let system = System::new("test");
        let bind_message_assertions = Box::new(move |actor: &mut Neighborhood| {
            assert!(actor.gossip_acceptor_info_opt.as_ref().unwrap().is_right());
            assert!(actor.gossip_producer_opt.is_some());
        });
        let pool_bind_message_assertions = Box::new(move |actor: &mut Neighborhood| {
            assert!(actor.gossip_acceptor_info_opt.as_ref().unwrap().is_left());
        });
        let pool_bind_message = pool_bind_message_builder().build();

        addr.try_send(BindMessage { peer_actors }).unwrap();

        addr.try_send(AssertionsMessage {
            assertions: bind_message_assertions,
        })
        .unwrap();

        addr.try_send(pool_bind_message).unwrap();

        addr.try_send(AssertionsMessage {
            assertions: pool_bind_message_assertions,
        })
        .unwrap();
        System::current().stop();
        assert_eq!(system.run(), 0);
    }

    #[test]
    fn node_with_zero_hop_config_ignores_start_message() {
        init_test_logging();
        let data_dir = ensure_node_home_directory_exists(
            "neighborhood/mod",
            "node_with_zero_hop_config_ignores_start_message",
        );
        {
            let _ = DbInitializerReal::default()
                .initialize(&data_dir, DbInitializationConfig::test_default())
                .unwrap();
        }
        let cryptde = main_cryptde();
        let earning_wallet = make_wallet("earning");
        let consuming_wallet = Some(make_paying_wallet(b"consuming"));
        let system =
            System::new("node_with_no_neighbor_configs_ignores_bootstrap_neighborhood_now_message");
        let mut subject = Neighborhood::new(
            cryptde,
            &bc_from_nc_plus(
                NeighborhoodConfig {
                    mode: NeighborhoodMode::ZeroHop,
                },
                earning_wallet.clone(),
                consuming_wallet.clone(),
                "node_with_zero_hop_config_ignores_start_message",
            ),
        );
        subject.data_directory = data_dir;
        let addr = subject.start();
        let sub = addr.clone().recipient::<StartMessage>();
        let (hopper, _, hopper_recording_arc) = make_recorder();
        let peer_actors = peer_actors_builder().hopper(hopper).build();
        addr.try_send(BindMessage { peer_actors }).unwrap();
        addr.try_send(make_meaningless_pool_bind_message()).unwrap();

        sub.try_send(StartMessage {}).unwrap();

        System::current().stop_with_code(0);
        system.run();
        let recording = hopper_recording_arc.lock().unwrap();
        assert_eq!(recording.len(), 0);
        TestLogHandler::new()
            .exists_log_containing("INFO: Neighborhood: Empty. No Nodes to report to; continuing");
    }

    #[test]
    fn neighborhood_adds_nodes_and_links() {
        let cryptde: &dyn CryptDE = main_cryptde();
        let earning_wallet = make_wallet("earning");
        let consuming_wallet = Some(make_paying_wallet(b"consuming"));
        let one_neighbor_node = make_node_record(3456, true);
        let another_neighbor_node = make_node_record(4567, true);
        let this_node_addr = NodeAddr::new(&IpAddr::from_str("5.4.3.2").unwrap(), &[5678]);

        let subject = Neighborhood::new(
            cryptde,
            &bc_from_nc_plus(
                NeighborhoodConfig {
                    mode: NeighborhoodMode::Standard(
                        this_node_addr.clone(),
                        vec![
                            NodeDescriptor::from((&one_neighbor_node, Chain::PolyMumbai, cryptde)),
                            NodeDescriptor::from((
                                &another_neighbor_node,
                                Chain::PolyMumbai,
                                cryptde,
                            )),
                        ],
                        rate_pack(100),
                    ),
                },
                earning_wallet.clone(),
                consuming_wallet.clone(),
                "neighborhood_adds_nodes_and_links",
            ),
        );

        let root_node_record_ref = subject.neighborhood_database.root();

        assert_eq!(
            root_node_record_ref.node_addr_opt().unwrap().clone(),
            this_node_addr
        );

        assert_eq!(
            root_node_record_ref.has_half_neighbor(one_neighbor_node.public_key()),
            false,
        );
        assert_eq!(
            root_node_record_ref.has_half_neighbor(another_neighbor_node.public_key()),
            false,
        );
        assert_eq!(
            subject.overall_connection_status,
            OverallConnectionStatus::new(vec![
                NodeDescriptor::from((&one_neighbor_node, Chain::PolyMumbai, cryptde,)),
                NodeDescriptor::from((&another_neighbor_node, Chain::PolyMumbai, cryptde,))
            ])
        );
    }

    #[test]
    fn neighborhood_logs_with_trace_if_it_receives_a_cpm_with_an_unknown_peer_addr() {
        init_test_logging();
        let known_peer = make_ip(1);
        let unknown_peer = make_ip(2);
        let node_descriptor = make_node_descriptor(known_peer);
        let subject = make_subject_from_node_descriptor(
            &node_descriptor,
            "neighborhood_logs_with_trace_if_it_receives_a_cpm_with_an_unknown_peer_addr",
        );
        let initial_ocs = subject.overall_connection_status.clone();
        let addr = subject.start();
        let cpm_recipient = addr.clone().recipient::<ConnectionProgressMessage>();
        let system = System::new("testing");
        let cpm = ConnectionProgressMessage {
            peer_addr: unknown_peer,
            event: ConnectionProgressEvent::TcpConnectionSuccessful,
        };

        cpm_recipient.try_send(cpm).unwrap();

        let assertions = Box::new(move |actor: &mut Neighborhood| {
            assert_eq!(actor.overall_connection_status, initial_ocs);
        });
        addr.try_send(AssertionsMessage { assertions }).unwrap();
        System::current().stop();
        assert_eq!(system.run(), 0);
        TestLogHandler::new().exists_log_containing(&format!(
            "TRACE: Neighborhood: Found unnecessary connection progress message - No peer found with the IP Address: {:?}",
            unknown_peer
        ));
    }

    #[test]
    fn neighborhood_logs_with_trace_if_it_receives_a_cpm_with_a_pass_target_that_is_a_part_of_a_different_connection_progress(
    ) {
        init_test_logging();
        let peer_1 = make_ip(1);
        let peer_2 = make_ip(2);
        let this_node_addr = NodeAddr::new(&IpAddr::from_str("111.111.111.111").unwrap(), &[8765]);
        let initial_node_descriptors =
            vec![make_node_descriptor(peer_1), make_node_descriptor(peer_2)];
        let neighborhood_config = NeighborhoodConfig {
            mode: NeighborhoodMode::Standard(
                this_node_addr,
                initial_node_descriptors,
                rate_pack(100),
            ),
        };
        let bootstrap_config =
            bc_from_nc_plus(neighborhood_config, make_wallet("earning"), None, "test");
        let mut subject = Neighborhood::new(main_cryptde(), &bootstrap_config);
        subject
            .overall_connection_status
            .get_connection_progress_by_ip(peer_1)
            .unwrap()
            .connection_stage = ConnectionStage::TcpConnectionEstablished;
        subject
            .overall_connection_status
            .get_connection_progress_by_ip(peer_2)
            .unwrap()
            .connection_stage = ConnectionStage::TcpConnectionEstablished;
        let addr = subject.start();
        let cpm_recipient = addr.clone().recipient::<ConnectionProgressMessage>();
        let system = System::new("testing");
        let cpm = ConnectionProgressMessage {
            peer_addr: peer_2,
            event: ConnectionProgressEvent::PassGossipReceived(peer_1),
        };

        cpm_recipient.try_send(cpm).unwrap();

        System::current().stop();
        assert_eq!(system.run(), 0);
        TestLogHandler::new().exists_log_containing(&format!(
            "TRACE: Neighborhood: Found unnecessary connection progress message - Pass target with \
            IP Address: {:?} is already a part of different connection progress.",
            peer_1
        ));
    }

    #[test]
    pub fn neighborhood_handles_connection_progress_message_with_tcp_connection_established() {
        let (node_ip_addr, node_descriptor) = make_node(1);
        let mut subject = make_subject_from_node_descriptor(
            &node_descriptor,
            "neighborhood_handles_connection_progress_message_with_tcp_connection_established",
        );
        let notify_later_ask_about_gossip_params_arc = Arc::new(Mutex::new(vec![]));
        subject.tools.notify_later_ask_about_gossip = Box::new(
            NotifyLaterHandleMock::default()
                .notify_later_params(&notify_later_ask_about_gossip_params_arc),
        );
        subject.tools.ask_about_gossip_interval = Duration::from_millis(10);
        let addr = subject.start();
        let cpm_recipient = addr.clone().recipient();
        let beginning_connection_progress = ConnectionProgress {
            initial_node_descriptor: node_descriptor.clone(),
            current_peer_addr: node_ip_addr,
            connection_stage: ConnectionStage::TcpConnectionEstablished,
        };
        let beginning_connection_progress_clone = beginning_connection_progress.clone();
        let system = System::new("testing");
        let connection_progress_message = ConnectionProgressMessage {
            peer_addr: node_ip_addr,
            event: ConnectionProgressEvent::TcpConnectionSuccessful,
        };

        cpm_recipient.try_send(connection_progress_message).unwrap();

        let assertions = Box::new(move |actor: &mut Neighborhood| {
            assert_eq!(
                actor.overall_connection_status,
                OverallConnectionStatus {
                    stage: OverallConnectionStage::NotConnected,
                    progress: vec![beginning_connection_progress_clone]
                }
            );
        });
        addr.try_send(AssertionsMessage { assertions }).unwrap();
        System::current().stop();
        assert_eq!(system.run(), 0);
        let notify_later_ask_about_gossip_params =
            notify_later_ask_about_gossip_params_arc.lock().unwrap();
        assert_eq!(
            *notify_later_ask_about_gossip_params,
            vec![(
                AskAboutDebutGossipMessage {
                    prev_connection_progress: beginning_connection_progress,
                },
                Duration::from_millis(10)
            )]
        );
    }

    #[test]
    fn ask_about_debut_gossip_message_handles_timeout_in_case_no_response_is_received() {
        let (node_ip_addr, node_descriptor) = make_node(1);
        let mut subject = make_subject_from_node_descriptor(
            &node_descriptor,
            "ask_about_debut_gossip_message_handles_timeout_in_case_no_response_is_received",
        );
        let connection_progress_to_modify = subject
            .overall_connection_status
            .get_connection_progress_by_ip(node_ip_addr)
            .unwrap();
        OverallConnectionStatus::update_connection_stage(
            connection_progress_to_modify,
            ConnectionProgressEvent::TcpConnectionSuccessful,
            &subject.logger,
        );
        let beginning_connection_progress = ConnectionProgress {
            initial_node_descriptor: node_descriptor.clone(),
            current_peer_addr: node_ip_addr,
            connection_stage: ConnectionStage::TcpConnectionEstablished,
        };
        let addr = subject.start();
        let recipient: Recipient<AskAboutDebutGossipMessage> = addr.clone().recipient();
        let aadgrm = AskAboutDebutGossipMessage {
            prev_connection_progress: beginning_connection_progress.clone(),
        };
        let system = System::new("testing");

        recipient.try_send(aadgrm).unwrap();

        let assertions = Box::new(move |actor: &mut Neighborhood| {
            assert_eq!(
                actor.overall_connection_status,
                OverallConnectionStatus {
                    stage: OverallConnectionStage::NotConnected,
                    progress: vec![ConnectionProgress {
                        initial_node_descriptor: node_descriptor,
                        current_peer_addr: node_ip_addr,
                        connection_stage: ConnectionStage::Failed(NoGossipResponseReceived),
                    }]
                }
            );
        });
        addr.try_send(AssertionsMessage { assertions }).unwrap();
        System::current().stop();
        assert_eq!(system.run(), 0);
    }

    #[test]
    pub fn neighborhood_logs_with_trace_if_it_receives_ask_about_debut_message_from_unknown_descriptor(
    ) {
        init_test_logging();
        let (_known_ip, known_desc) = make_node(1);
        let (unknown_ip, unknown_desc) = make_node(2);
        let subject = make_subject_from_node_descriptor(&known_desc, "neighborhood_logs_with_trace_if_it_receives_ask_about_debut_message_from_unknown_descriptor");
        let initial_ocs = subject.overall_connection_status.clone();
        let addr = subject.start();
        let recipient: Recipient<AskAboutDebutGossipMessage> = addr.clone().recipient();
        let aadgrm = AskAboutDebutGossipMessage {
            prev_connection_progress: ConnectionProgress {
                initial_node_descriptor: unknown_desc.clone(),
                current_peer_addr: unknown_ip,
                connection_stage: ConnectionStage::TcpConnectionEstablished,
            },
        };
        let system = System::new("testing");

        recipient.try_send(aadgrm).unwrap();

        let assertions = Box::new(move |actor: &mut Neighborhood| {
            assert_eq!(actor.overall_connection_status, initial_ocs);
        });
        addr.try_send(AssertionsMessage { assertions }).unwrap();
        System::current().stop();
        assert_eq!(system.run(), 0);
        TestLogHandler::new()
            .exists_log_containing(
                &format!("TRACE: Neighborhood: Received an AskAboutDebutGossipMessage for an unknown node descriptor: {:?}; ignoring",
                         unknown_desc)
            );
    }

    #[test]
    pub fn neighborhood_handles_connection_progress_message_with_tcp_connection_failed() {
        let (node_ip_addr, node_descriptor) = make_node(1);
        let subject = make_subject_from_node_descriptor(
            &node_descriptor,
            "neighborhood_handles_connection_progress_message_with_tcp_connection_failed",
        );
        let addr = subject.start();
        let cpm_recipient = addr.clone().recipient();
        let system = System::new("testing");
        let connection_progress_message = ConnectionProgressMessage {
            peer_addr: node_ip_addr,
            event: ConnectionProgressEvent::TcpConnectionFailed,
        };

        cpm_recipient.try_send(connection_progress_message).unwrap();

        let assertions = Box::new(move |actor: &mut Neighborhood| {
            assert_eq!(
                actor.overall_connection_status,
                OverallConnectionStatus {
                    stage: OverallConnectionStage::NotConnected,
                    progress: vec![ConnectionProgress {
                        initial_node_descriptor: node_descriptor,
                        current_peer_addr: node_ip_addr,
                        connection_stage: ConnectionStage::Failed(TcpConnectionFailed)
                    }]
                }
            );
        });
        addr.try_send(AssertionsMessage { assertions }).unwrap();
        System::current().stop();
        assert_eq!(system.run(), 0);
    }

    #[test]
    fn neighborhood_handles_a_connection_progress_message_with_pass_gossip_received() {
        let (node_ip_addr, node_descriptor) = make_node(1);
        let mut subject = make_subject_from_node_descriptor(
            &node_descriptor,
            "neighborhood_handles_a_connection_progress_message_with_pass_gossip_received",
        );
        let connection_progress_to_modify = subject
            .overall_connection_status
            .get_connection_progress_by_ip(node_ip_addr)
            .unwrap();
        OverallConnectionStatus::update_connection_stage(
            connection_progress_to_modify,
            ConnectionProgressEvent::TcpConnectionSuccessful,
            &subject.logger,
        );
        let addr = subject.start();
        let cpm_recipient = addr.clone().recipient();
        let system = System::new("testing");
        let new_pass_target = make_ip(2);
        let connection_progress_message = ConnectionProgressMessage {
            peer_addr: node_ip_addr,
            event: ConnectionProgressEvent::PassGossipReceived(new_pass_target),
        };

        cpm_recipient.try_send(connection_progress_message).unwrap();

        let assertions = Box::new(move |actor: &mut Neighborhood| {
            assert_eq!(
                actor.overall_connection_status,
                OverallConnectionStatus {
                    stage: OverallConnectionStage::NotConnected,
                    progress: vec![ConnectionProgress {
                        initial_node_descriptor: node_descriptor,
                        current_peer_addr: new_pass_target,
                        connection_stage: ConnectionStage::StageZero
                    }]
                }
            );
        });
        addr.try_send(AssertionsMessage { assertions }).unwrap();
        System::current().stop();
        assert_eq!(system.run(), 0);
    }

    #[test]
    fn neighborhood_handles_a_connection_progress_message_with_pass_loop_found() {
        let (node_ip_addr, node_descriptor) = make_node(1);
        let mut subject = make_subject_from_node_descriptor(
            &node_descriptor,
            "neighborhood_handles_a_connection_progress_message_with_pass_loop_found",
        );
        let connection_progress_to_modify = subject
            .overall_connection_status
            .get_connection_progress_by_ip(node_ip_addr)
            .unwrap();
        OverallConnectionStatus::update_connection_stage(
            connection_progress_to_modify,
            ConnectionProgressEvent::TcpConnectionSuccessful,
            &subject.logger,
        );
        let addr = subject.start();
        let cpm_recipient = addr.clone().recipient();
        let system = System::new("testing");
        let connection_progress_message = ConnectionProgressMessage {
            peer_addr: node_ip_addr,
            event: ConnectionProgressEvent::PassLoopFound,
        };

        cpm_recipient.try_send(connection_progress_message).unwrap();

        let assertions = Box::new(move |actor: &mut Neighborhood| {
            assert_eq!(
                actor.overall_connection_status,
                OverallConnectionStatus {
                    stage: OverallConnectionStage::NotConnected,
                    progress: vec![ConnectionProgress {
                        initial_node_descriptor: node_descriptor,
                        current_peer_addr: node_ip_addr,
                        connection_stage: ConnectionStage::Failed(PassLoopFound)
                    }]
                }
            );
        });
        addr.try_send(AssertionsMessage { assertions }).unwrap();
        System::current().stop();
        assert_eq!(system.run(), 0);
    }

    #[test]
    fn neighborhood_handles_a_connection_progress_message_with_introduction_gossip_received() {
        let (node_ip_addr, node_descriptor) = make_node(1);
        let mut subject = make_subject_from_node_descriptor(
            &node_descriptor,
            "neighborhood_handles_a_connection_progress_message_with_introduction_gossip_received",
        );
        let (node_to_ui_recipient, node_to_ui_recording_arc) =
            make_recipient_and_recording_arc(Some(TypeId::of::<NodeToUiMessage>()));
        subject.node_to_ui_sub_opt = Some(node_to_ui_recipient);
        let connection_progress_to_modify = subject
            .overall_connection_status
            .get_connection_progress_by_ip(node_ip_addr)
            .unwrap();
        OverallConnectionStatus::update_connection_stage(
            connection_progress_to_modify,
            ConnectionProgressEvent::TcpConnectionSuccessful,
            &subject.logger,
        );
        let addr = subject.start();
        let cpm_recipient = addr.clone().recipient();
        let system = System::new("testing");
        let connection_progress_message = ConnectionProgressMessage {
            peer_addr: node_ip_addr,
            event: ConnectionProgressEvent::IntroductionGossipReceived(make_ip(2)),
        };

        cpm_recipient.try_send(connection_progress_message).unwrap();

        let assertions = Box::new(move |actor: &mut Neighborhood| {
            assert_eq!(
                actor.overall_connection_status,
                OverallConnectionStatus {
                    stage: OverallConnectionStage::ConnectedToNeighbor,
                    progress: vec![ConnectionProgress {
                        initial_node_descriptor: node_descriptor,
                        current_peer_addr: node_ip_addr,
                        connection_stage: ConnectionStage::NeighborshipEstablished
                    }]
                }
            );
        });
        addr.try_send(AssertionsMessage { assertions }).unwrap();
        assert_eq!(system.run(), 0);
        let node_to_ui_mutex = node_to_ui_recording_arc.lock().unwrap();
        let node_to_ui_message_opt = node_to_ui_mutex.get_record_opt::<NodeToUiMessage>(0);
        assert_eq!(node_to_ui_mutex.len(), 1);
        assert_eq!(
            node_to_ui_message_opt,
            Some(&NodeToUiMessage {
                target: MessageTarget::AllClients,
                body: UiConnectionChangeBroadcast {
                    stage: UiConnectionStage::ConnectedToNeighbor
                }
                .tmb(0)
            })
        );
    }

    #[test]
    fn neighborhood_handles_a_connection_progress_message_with_standard_gossip_received() {
        let (node_ip_addr, node_descriptor) = make_node(1);
        let mut subject = make_subject_from_node_descriptor(
            &node_descriptor,
            "neighborhood_handles_a_connection_progress_message_with_standard_gossip_received",
        );
        let (node_to_ui_recipient, node_to_ui_recording_arc) =
            make_recipient_and_recording_arc(Some(TypeId::of::<NodeToUiMessage>()));
        subject.node_to_ui_sub_opt = Some(node_to_ui_recipient);
        let connection_progress_to_modify = subject
            .overall_connection_status
            .get_connection_progress_by_ip(node_ip_addr)
            .unwrap();
        OverallConnectionStatus::update_connection_stage(
            connection_progress_to_modify,
            ConnectionProgressEvent::TcpConnectionSuccessful,
            &subject.logger,
        );
        let addr = subject.start();
        let cpm_recipient = addr.clone().recipient();
        let system = System::new("testing");
        let connection_progress_message = ConnectionProgressMessage {
            peer_addr: node_ip_addr,
            event: ConnectionProgressEvent::StandardGossipReceived,
        };

        cpm_recipient.try_send(connection_progress_message).unwrap();

        let assertions = Box::new(move |actor: &mut Neighborhood| {
            assert_eq!(
                actor.overall_connection_status,
                OverallConnectionStatus {
                    stage: OverallConnectionStage::ConnectedToNeighbor,
                    progress: vec![ConnectionProgress {
                        initial_node_descriptor: node_descriptor,
                        current_peer_addr: node_ip_addr,
                        connection_stage: ConnectionStage::NeighborshipEstablished
                    }]
                }
            );
        });
        addr.try_send(AssertionsMessage { assertions }).unwrap();
        assert_eq!(system.run(), 0);
        let node_to_ui_mutex = node_to_ui_recording_arc.lock().unwrap();
        let node_to_ui_message_opt = node_to_ui_mutex.get_record_opt::<NodeToUiMessage>(0);
        assert_eq!(node_to_ui_mutex.len(), 1);
        assert_eq!(
            node_to_ui_message_opt,
            Some(&NodeToUiMessage {
                target: MessageTarget::AllClients,
                body: UiConnectionChangeBroadcast {
                    stage: UiConnectionStage::ConnectedToNeighbor
                }
                .tmb(0)
            })
        );
    }

    #[test]
    fn neighborhood_handles_a_connection_progress_message_with_no_gossip_response_received() {
        let (node_ip_addr, node_descriptor) = make_node(1);
        let mut subject = make_subject_from_node_descriptor(
            &node_descriptor,
            "neighborhood_handles_a_connection_progress_message_with_no_gossip_response_received",
        );
        let connection_progress_to_modify = subject
            .overall_connection_status
            .get_connection_progress_by_ip(node_ip_addr)
            .unwrap();
        OverallConnectionStatus::update_connection_stage(
            connection_progress_to_modify,
            ConnectionProgressEvent::TcpConnectionSuccessful,
            &subject.logger,
        );
        let addr = subject.start();
        let cpm_recipient = addr.clone().recipient();
        let system = System::new("testing");
        let connection_progress_message = ConnectionProgressMessage {
            peer_addr: node_ip_addr,
            event: ConnectionProgressEvent::NoGossipResponseReceived,
        };

        cpm_recipient.try_send(connection_progress_message).unwrap();

        let assertions = Box::new(move |actor: &mut Neighborhood| {
            assert_eq!(
                actor.overall_connection_status,
                OverallConnectionStatus {
                    stage: OverallConnectionStage::NotConnected,
                    progress: vec![ConnectionProgress {
                        initial_node_descriptor: node_descriptor,
                        current_peer_addr: node_ip_addr,
                        connection_stage: ConnectionStage::Failed(NoGossipResponseReceived)
                    }]
                }
            );
        });
        addr.try_send(AssertionsMessage { assertions }).unwrap();
        System::current().stop();
        assert_eq!(system.run(), 0);
    }

    #[test]
    pub fn progress_in_the_stage_of_overall_connection_status_made_by_one_cpm_is_not_overridden_by_the_other(
    ) {
        let peer_1 = make_ip(1);
        let peer_2 = make_ip(2);
        let initial_node_descriptors =
            vec![make_node_descriptor(peer_1), make_node_descriptor(peer_2)];
        let neighborhood_config = NeighborhoodConfig {
            mode: NeighborhoodMode::Standard(
                NodeAddr::new(&make_ip(3), &[1234]),
                initial_node_descriptors,
                rate_pack(100),
            ),
        };
        let mut subject = Neighborhood::new(
            main_cryptde(),
            &bc_from_nc_plus(
                neighborhood_config,
                make_wallet("earning"),
                None,
                "progress_in_the_stage_of_overall_connection_status_made_by_one_cpm_is_not_overridden_by_the_other"),
        );
        let (node_to_ui_recipient, _) = make_node_to_ui_recipient();
        subject.node_to_ui_sub_opt = Some(node_to_ui_recipient);
        let addr = subject.start();
        let cpm_recipient = addr.clone().recipient();
        let system = System::new("testing");
        cpm_recipient
            .try_send(ConnectionProgressMessage {
                peer_addr: peer_1,
                event: ConnectionProgressEvent::TcpConnectionSuccessful,
            })
            .unwrap();
        cpm_recipient
            .try_send(ConnectionProgressMessage {
                peer_addr: peer_1,
                event: ConnectionProgressEvent::IntroductionGossipReceived(make_ip(4)),
            })
            .unwrap(); // By this step, the OverallConnectionStage will be changed from NotConnected to ConnectedToNeighbor
        cpm_recipient
            .try_send(ConnectionProgressMessage {
                peer_addr: peer_2,
                event: ConnectionProgressEvent::TcpConnectionSuccessful,
            })
            .unwrap();

        cpm_recipient
            .try_send(ConnectionProgressMessage {
                peer_addr: peer_2,
                event: ConnectionProgressEvent::PassGossipReceived(make_ip(5)),
            })
            .unwrap(); // This step won't override the stage as it doesn't lead to any stage advancement

        let assertions = Box::new(move |actor: &mut Neighborhood| {
            assert_eq!(
                actor.overall_connection_status.stage(),
                OverallConnectionStage::ConnectedToNeighbor
            );
        });
        addr.try_send(AssertionsMessage { assertions }).unwrap();
        System::current().stop();
        assert_eq!(system.run(), 0);
    }

    #[test]
    fn gossip_failures_eventually_stop_the_neighborhood() {
        init_test_logging();
        let cryptde: &dyn CryptDE = main_cryptde();
        let earning_wallet = make_wallet("earning");
        let one_neighbor_node: NodeRecord = make_node_record(3456, true);
        let another_neighbor_node: NodeRecord = make_node_record(4567, true);
        let this_node_addr = NodeAddr::new(&IpAddr::from_str("5.4.3.2").unwrap(), &[5678]);

        let subject = Neighborhood::new(
            cryptde,
            &bc_from_nc_plus(
                NeighborhoodConfig {
                    mode: NeighborhoodMode::Standard(
                        this_node_addr.clone(),
                        vec![
                            NodeDescriptor::from((&one_neighbor_node, Chain::PolyMumbai, cryptde)),
                            NodeDescriptor::from((
                                &another_neighbor_node,
                                Chain::PolyMumbai,
                                cryptde,
                            )),
                        ],
                        rate_pack(100),
                    ),
                },
                earning_wallet.clone(),
                None,
                "gossip_failures_eventually_stop_the_neighborhood",
            ),
        );
        let ecp1 = ExpiredCoresPackage::new(
            one_neighbor_node.node_addr_opt().unwrap().into(),
            None,
            make_meaningless_route(),
            GossipFailure_0v1::NoNeighbors,
            0,
        );
        let ecp2 = ExpiredCoresPackage::new(
            another_neighbor_node.node_addr_opt().unwrap().into(),
            None,
            make_meaningless_route(),
            GossipFailure_0v1::ManualRejection,
            0,
        );
        let system = System::new("responds_with_none_when_initially_configured_with_no_data");
        let addr = subject.start();
        let sub = addr.recipient::<ExpiredCoresPackage<GossipFailure_0v1>>();

        sub.try_send(ecp1).unwrap();
        sub.try_send(ecp2).unwrap();

        system.run(); // If this never halts, it's because the Neighborhood isn't properly killing its actor

        let tlh = TestLogHandler::new();
        tlh.exists_log_containing ("WARN: Neighborhood: Node at 3.4.5.6 refused Debut: No neighbors for Introduction or Pass");
        tlh.exists_log_containing ("WARN: Neighborhood: Node at 4.5.6.7 refused Debut: Node owner manually rejected your Debut");
        tlh.exists_log_containing ("ERROR: Neighborhood: None of the Nodes listed in the --neighbors parameter could accept your Debut; shutting down");
    }

    #[test]
    fn node_query_responds_with_none_when_initially_configured_with_no_data() {
        let system = System::new("responds_with_none_when_initially_configured_with_no_data");
        let subject = make_standard_subject();
        let addr = subject.start();
        let sub: Recipient<NodeQueryMessage> = addr.recipient::<NodeQueryMessage>();

        let future = sub.send(NodeQueryMessage::PublicKey(PublicKey::new(&b"booga"[..])));

        System::current().stop_with_code(0);
        system.run();
        let result = future.wait().unwrap();
        assert_eq!(result.is_none(), true);
    }

    #[test]
    fn node_query_responds_with_none_when_key_query_matches_no_configured_data() {
        let cryptde: &dyn CryptDE = main_cryptde();
        let earning_wallet = make_wallet("earning");
        let consuming_wallet = Some(make_paying_wallet(b"consuming"));
        let system =
            System::new("node_query_responds_with_none_when_key_query_matches_no_configured_data");
        let subject = Neighborhood::new(
            cryptde,
            &bc_from_nc_plus(
                NeighborhoodConfig {
                    mode: NeighborhoodMode::Standard(
                        NodeAddr::new(&IpAddr::from_str("5.4.3.2").unwrap(), &[5678]),
                        vec![NodeDescriptor::from((
                            &PublicKey::new(&b"booga"[..]),
                            &NodeAddr::new(&IpAddr::from_str("1.2.3.4").unwrap(), &[1234, 2345]),
                            Chain::PolyMumbai,
                            cryptde,
                        ))],
                        rate_pack(100),
                    ),
                },
                earning_wallet.clone(),
                consuming_wallet.clone(),
                "node_query_responds_with_none_when_key_query_matches_no_configured_data",
            ),
        );
        let addr: Addr<Neighborhood> = subject.start();
        let sub: Recipient<NodeQueryMessage> = addr.recipient::<NodeQueryMessage>();

        let future = sub.send(NodeQueryMessage::PublicKey(PublicKey::new(&b"blah"[..])));

        System::current().stop_with_code(0);
        system.run();
        let result = future.wait().unwrap();
        assert_eq!(result.is_none(), true);
    }

    #[test]
    fn node_query_responds_with_result_when_key_query_matches_configured_data() {
        let cryptde = main_cryptde();
        let earning_wallet = make_wallet("earning");
        let consuming_wallet = Some(make_paying_wallet(b"consuming"));
        let system =
            System::new("node_query_responds_with_result_when_key_query_matches_configured_data");
        let one_neighbor = make_node_record(2345, true);
        let another_neighbor = make_node_record(3456, true);
        let mut subject = Neighborhood::new(
            cryptde,
            &bc_from_nc_plus(
                NeighborhoodConfig {
                    mode: NeighborhoodMode::Standard(
                        NodeAddr::new(&IpAddr::from_str("5.4.3.2").unwrap(), &[5678]),
                        vec![node_record_to_neighbor_config(&one_neighbor)],
                        rate_pack(100),
                    ),
                },
                earning_wallet.clone(),
                consuming_wallet.clone(),
                "node_query_responds_with_result_when_key_query_matches_configured_data",
            ),
        );
        subject
            .neighborhood_database
            .add_node(another_neighbor.clone())
            .unwrap();
        let addr: Addr<Neighborhood> = subject.start();
        let sub: Recipient<NodeQueryMessage> = addr.recipient::<NodeQueryMessage>();

        let future = sub.send(NodeQueryMessage::PublicKey(
            another_neighbor.public_key().clone(),
        ));

        System::current().stop_with_code(0);
        system.run();
        let result = future.wait().unwrap();
        assert_eq!(
            result.unwrap(),
            NodeQueryResponseMetadata::new(
                another_neighbor.public_key().clone(),
                Some(another_neighbor.node_addr_opt().unwrap().clone()),
                another_neighbor.rate_pack().clone(),
            )
        );
    }

    #[test]
    fn node_query_responds_with_none_when_ip_address_query_matches_no_configured_data() {
        let cryptde: &dyn CryptDE = main_cryptde();
        let earning_wallet = make_wallet("earning");
        let consuming_wallet = Some(make_paying_wallet(b"consuming"));
        let system = System::new(
            "node_query_responds_with_none_when_ip_address_query_matches_no_configured_data",
        );
        let subject = Neighborhood::new(
            cryptde,
            &bc_from_nc_plus(
                NeighborhoodConfig {
                    mode: NeighborhoodMode::Standard(
                        NodeAddr::new(&IpAddr::from_str("5.4.3.2").unwrap(), &[5678]),
                        vec![NodeDescriptor::from((
                            &PublicKey::new(&b"booga"[..]),
                            &NodeAddr::new(&IpAddr::from_str("1.2.3.4").unwrap(), &[1234, 2345]),
                            Chain::PolyMumbai,
                            cryptde,
                        ))],
                        rate_pack(100),
                    ),
                },
                earning_wallet.clone(),
                consuming_wallet.clone(),
                "node_query_responds_with_none_when_ip_address_query_matches_no_configured_data",
            ),
        );
        let addr: Addr<Neighborhood> = subject.start();
        let sub: Recipient<NodeQueryMessage> = addr.recipient::<NodeQueryMessage>();

        let future = sub.send(NodeQueryMessage::IpAddress(
            IpAddr::from_str("2.3.4.5").unwrap(),
        ));

        System::current().stop_with_code(0);
        system.run();
        let result = future.wait().unwrap();
        assert_eq!(result.is_none(), true);
    }

    #[test]
    fn node_query_responds_with_result_when_ip_address_query_matches_configured_data() {
        let cryptde: &dyn CryptDE = main_cryptde();
        let system = System::new(
            "node_query_responds_with_result_when_ip_address_query_matches_configured_data",
        );
        let node_record = make_node_record(1234, true);
        let another_node_record = make_node_record(2345, true);
        let mut subject = Neighborhood::new(
            cryptde,
            &bc_from_nc_plus(
                NeighborhoodConfig {
                    mode: NeighborhoodMode::Standard(
                        node_record.node_addr_opt().unwrap(),
                        vec![NodeDescriptor::from((
                            &node_record,
                            Chain::PolyMumbai,
                            cryptde,
                        ))],
                        rate_pack(100),
                    ),
                },
                node_record.earning_wallet(),
                None,
                "node_query_responds_with_result_when_ip_address_query_matches_configured_data",
            ),
        );
        subject
            .neighborhood_database
            .add_node(another_node_record.clone())
            .unwrap();
        let addr: Addr<Neighborhood> = subject.start();
        let sub: Recipient<NodeQueryMessage> = addr.recipient::<NodeQueryMessage>();

        let future = sub.send(NodeQueryMessage::IpAddress(
            IpAddr::from_str("2.3.4.5").unwrap(),
        ));

        System::current().stop_with_code(0);
        system.run();
        let result = future.wait().unwrap();
        assert_eq!(
            result.unwrap(),
            NodeQueryResponseMetadata::new(
                another_node_record.public_key().clone(),
                Some(another_node_record.node_addr_opt().unwrap().clone()),
                another_node_record.rate_pack().clone(),
            )
        );
    }

    #[test]
    fn route_query_responds_with_none_when_asked_for_route_with_too_many_hops() {
        let system =
            System::new("route_query_responds_with_none_when_asked_for_route_with_too_many_hops");
        let subject = make_standard_subject();
        let addr: Addr<Neighborhood> = subject.start();
        let sub: Recipient<RouteQueryMessage> = addr.recipient::<RouteQueryMessage>();

        let future = sub.send(RouteQueryMessage::data_indefinite_route_request(
            None, 5, 400,
        ));

        System::current().stop_with_code(0);
        system.run();
        let result = future.wait().unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn route_query_responds_with_none_when_asked_for_two_hop_round_trip_route_without_consuming_wallet(
    ) {
        let system = System::new("route_query_responds_with_none_when_asked_for_two_hop_round_trip_route_without_consuming_wallet");
        let subject = make_standard_subject();
        let addr: Addr<Neighborhood> = subject.start();
        let sub: Recipient<RouteQueryMessage> = addr.recipient::<RouteQueryMessage>();

        let future = sub.send(RouteQueryMessage::data_indefinite_route_request(
            None, 2, 430,
        ));

        System::current().stop_with_code(0);
        system.run();
        let result = future.wait().unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn route_query_succeeds_when_asked_for_one_hop_round_trip_route_without_consuming_wallet() {
        let cryptde = main_cryptde();
        let earning_wallet = make_wallet("earning");
        let system = System::new(
            "route_query_succeeds_when_asked_for_one_hop_round_trip_route_without_consuming_wallet",
        );
        let mut subject = make_standard_subject();
        subject
            .neighborhood_database
            .root_mut()
            .set_earning_wallet(earning_wallet);
        subject.consuming_wallet_opt = None;
        // These happen to be extracted in the desired order. We could not think of a way to guarantee it.
        let desirable_exit_node = make_node_record(2345, false);
        let undesirable_exit_node = make_node_record(3456, true);
        let originating_node = &subject.neighborhood_database.root().clone();
        {
            let db = &mut subject.neighborhood_database;
            db.add_node(undesirable_exit_node.clone()).unwrap();
            db.add_node(desirable_exit_node.clone()).unwrap();
            db.add_arbitrary_full_neighbor(
                undesirable_exit_node.public_key(),
                originating_node.public_key(),
            );
            db.add_arbitrary_full_neighbor(
                desirable_exit_node.public_key(),
                originating_node.public_key(),
            );
        }
        let addr: Addr<Neighborhood> = subject.start();
        let sub: Recipient<RouteQueryMessage> = addr.recipient::<RouteQueryMessage>();
        let msg = RouteQueryMessage::data_indefinite_route_request(None, 1, 54000);

        let future = sub.send(msg);

        System::current().stop_with_code(0);
        system.run();
        let segment = |nodes: Vec<&NodeRecord>, component: Component| {
            RouteSegment::new(
                nodes.into_iter().map(|n| n.public_key()).collect(),
                component,
            )
        };
        let result = future.wait().unwrap().unwrap();
        let expected_response = RouteQueryResponse {
            route: Route::round_trip(
                segment(
                    vec![originating_node, &desirable_exit_node],
                    Component::ProxyClient,
                ),
                segment(
                    vec![&desirable_exit_node, originating_node],
                    Component::ProxyServer,
                ),
                cryptde,
                None,
                0,
                None,
            )
            .unwrap(),
            expected_services: ExpectedServices::RoundTrip(
                vec![
                    ExpectedService::Nothing,
                    ExpectedService::Exit(
                        desirable_exit_node.public_key().clone(),
                        desirable_exit_node.earning_wallet(),
                        rate_pack(2345),
                    ),
                ],
                vec![
                    ExpectedService::Exit(
                        desirable_exit_node.public_key().clone(),
                        desirable_exit_node.earning_wallet(),
                        rate_pack(2345),
                    ),
                    ExpectedService::Nothing,
                ],
                0,
            ),
        };
        assert_eq!(expected_response, result);
    }

    #[test]
    fn route_query_responds_with_none_when_asked_for_one_hop_round_trip_route_without_consuming_wallet_when_back_route_needs_two_hops(
    ) {
        let system = System::new("route_query_responds_with_none_when_asked_for_one_hop_round_trip_route_without_consuming_wallet_when_back_route_needs_two_hops");
        let mut subject = make_standard_subject();
        let a = &make_node_record(1234, true);
        let b = &subject.neighborhood_database.root().clone();
        let c = &make_node_record(3456, true);
        {
            let db = &mut subject.neighborhood_database;
            db.add_node(a.clone()).unwrap();
            db.add_node(c.clone()).unwrap();
            let mut single_edge = |a: &NodeRecord, b: &NodeRecord| {
                db.add_arbitrary_half_neighbor(a.public_key(), b.public_key())
            };
            single_edge(a, b);
            single_edge(b, c);
            single_edge(c, a);
        }
        let addr: Addr<Neighborhood> = subject.start();
        let sub: Recipient<RouteQueryMessage> = addr.recipient::<RouteQueryMessage>();
        let msg = RouteQueryMessage::data_indefinite_route_request(None, 1, 10000);

        let future = sub.send(msg);

        System::current().stop_with_code(0);
        system.run();
        let result = future.wait().unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn route_query_responds_with_none_when_asked_for_two_hop_one_way_route_without_consuming_wallet(
    ) {
        let system = System::new("route_query_responds_with_none_when_asked_for_two_hop_one_way_route_without_consuming_wallet");
        let subject = make_standard_subject();
        let addr: Addr<Neighborhood> = subject.start();
        let sub: Recipient<RouteQueryMessage> = addr.recipient::<RouteQueryMessage>();
        let msg = RouteQueryMessage::data_indefinite_route_request(None, 2, 20000);

        let future = sub.send(msg);

        System::current().stop_with_code(0);
        system.run();
        let result = future.wait().unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn route_query_responds_with_standard_zero_hop_route_when_requested() {
        let cryptde = main_cryptde();
        let system = System::new("responds_with_standard_zero_hop_route_when_requested");
        let subject = make_standard_subject();
        let addr: Addr<Neighborhood> = subject.start();
        let sub: Recipient<RouteQueryMessage> = addr.recipient::<RouteQueryMessage>();

        let future = sub.send(RouteQueryMessage::data_indefinite_route_request(
            None, 0, 12345,
        ));

        System::current().stop_with_code(0);
        system.run();
        let result = future.wait().unwrap().unwrap();
        let expected_response = RouteQueryResponse {
            route: Route::round_trip(
                RouteSegment::new(
                    vec![&cryptde.public_key(), &cryptde.public_key()],
                    Component::ProxyClient,
                ),
                RouteSegment::new(
                    vec![&cryptde.public_key(), &cryptde.public_key()],
                    Component::ProxyServer,
                ),
                cryptde,
                None,
                0,
                None,
            )
            .unwrap(),
            expected_services: ExpectedServices::RoundTrip(
                vec![ExpectedService::Nothing, ExpectedService::Nothing],
                vec![ExpectedService::Nothing, ExpectedService::Nothing],
                0,
            ),
        };
        assert_eq!(result, expected_response);
    }

    #[test]
    fn zero_hop_routing_handles_return_route_id_properly() {
        let mut subject = make_standard_subject();
        let result0 = subject.zero_hop_route_response();
        let result1 = subject.zero_hop_route_response();

        let return_route_id_0 = match result0.expected_services {
            ExpectedServices::RoundTrip(_, _, id) => id,
            _ => panic!("expected RoundTrip got OneWay"),
        };

        let return_route_id_1 = match result1.expected_services {
            ExpectedServices::RoundTrip(_, _, id) => id,
            _ => panic!("expected RoundTrip got OneWay"),
        };

        assert_eq!(return_route_id_0, 0);
        assert_eq!(return_route_id_1, 1);
    }

    /*
            Database:

                 P---Q---R---S
                     |
                     T

            Tests will be written from the viewpoint of P.
    */

    #[test]
    fn route_query_messages() {
        let cryptde = main_cryptde();
        let earning_wallet = make_wallet("earning");
        let system = System::new("route_query_messages");
        let mut subject = make_standard_subject();
        subject
            .neighborhood_database
            .root_mut()
            .set_earning_wallet(earning_wallet);
        let consuming_wallet_opt = subject.consuming_wallet_opt.clone();
        let p = &subject.neighborhood_database.root().clone();
        let q = &make_node_record(3456, true);
        let r = &make_node_record(4567, false);
        let s = &make_node_record(5678, false);
        let t = make_node_record(7777, false);
        {
            let db = &mut subject.neighborhood_database;
            db.add_node(q.clone()).unwrap();
            db.add_node(t.clone()).unwrap();
            db.add_node(r.clone()).unwrap();
            db.add_node(s.clone()).unwrap();
            let mut dual_edge = |a: &NodeRecord, b: &NodeRecord| {
                db.add_arbitrary_full_neighbor(a.public_key(), b.public_key());
            };
            dual_edge(p, q);
            dual_edge(q, &t);
            dual_edge(q, r);
            dual_edge(r, s);
        }

        let addr: Addr<Neighborhood> = subject.start();
        let sub: Recipient<RouteQueryMessage> = addr.recipient::<RouteQueryMessage>();

        let data_route = sub.send(RouteQueryMessage::data_indefinite_route_request(
            None, 2, 5000,
        ));

        System::current().stop_with_code(0);
        system.run();

        let result = data_route.wait().unwrap().unwrap();
        let contract_address = TEST_DEFAULT_CHAIN.rec().contract;
        let expected_response = RouteQueryResponse {
            route: Route::round_trip(
                segment(&[p, q, r], &Component::ProxyClient),
                segment(&[r, q, p], &Component::ProxyServer),
                cryptde,
                consuming_wallet_opt,
                0,
                Some(contract_address),
            )
            .unwrap(),
            expected_services: ExpectedServices::RoundTrip(
                vec![
                    ExpectedService::Nothing,
                    ExpectedService::Routing(
                        q.public_key().clone(),
                        q.earning_wallet(),
                        rate_pack(3456),
                    ),
                    ExpectedService::Exit(
                        r.public_key().clone(),
                        r.earning_wallet(),
                        rate_pack(4567),
                    ),
                ],
                vec![
                    ExpectedService::Exit(
                        r.public_key().clone(),
                        r.earning_wallet(),
                        rate_pack(4567),
                    ),
                    ExpectedService::Routing(
                        q.public_key().clone(),
                        q.earning_wallet(),
                        rate_pack(3456),
                    ),
                    ExpectedService::Nothing,
                ],
                0,
            ),
        };
        assert_eq!(expected_response, result);
    }

    #[test]
    fn compose_route_query_response_returns_an_error_when_route_segment_is_empty() {
        let mut subject = make_standard_subject();

        let result: Result<RouteQueryResponse, String> = subject.compose_route_query_response(
            RouteSegment::new(vec![], Component::Neighborhood),
            RouteSegment::new(vec![], Component::Neighborhood),
        );
        assert!(result.is_err());
        let error_expectation: String = result.expect_err("Expected an Err but got:");
        assert_eq!(
            error_expectation,
            "Cannot make multi-hop route without segment keys"
        );
    }

    #[test]
    fn next_return_route_id_wraps_around() {
        let mut subject = make_standard_subject();
        subject.next_return_route_id = 0xFFFFFFFF;

        let end = subject.advance_return_route_id();
        let beginning = subject.advance_return_route_id();

        assert_eq!(end, 0xFFFFFFFF);
        assert_eq!(beginning, 0x00000000);
    }

    /*
            Database:

                 O---R---E

            Tests will be written from the viewpoint of O.
    */

    #[test]
    fn return_route_ids_increase() {
        let cryptde = main_cryptde();
        let system = System::new("return_route_ids_increase");
        let (_, _, _, subject) = make_o_r_e_subject();

        let addr: Addr<Neighborhood> = subject.start();
        let sub: Recipient<RouteQueryMessage> = addr.recipient::<RouteQueryMessage>();

        let data_route_0 = sub.send(RouteQueryMessage::data_indefinite_route_request(
            None, 2, 2000,
        ));
        let data_route_1 = sub.send(RouteQueryMessage::data_indefinite_route_request(
            None, 2, 3000,
        ));

        System::current().stop_with_code(0);
        system.run();

        let result_0 = data_route_0.wait().unwrap().unwrap();
        let result_1 = data_route_1.wait().unwrap().unwrap();
        let juicy_parts = |result: RouteQueryResponse| {
            let last_element = result.route.hops.last().unwrap();
            let last_element_dec = cryptde.decode(last_element).unwrap();
            let network_return_route_id: u32 =
                serde_cbor::de::from_slice(last_element_dec.as_slice()).unwrap();
            let metadata_return_route_id = match result.expected_services {
                ExpectedServices::RoundTrip(_, _, id) => id,
                _ => panic!("expected RoundTrip got OneWay"),
            };
            (network_return_route_id, metadata_return_route_id)
        };
        assert_eq!(juicy_parts(result_0), (0, 0));
        assert_eq!(juicy_parts(result_1), (1, 1));
    }

    #[test]
    fn can_update_consuming_wallet() {
        let cryptde = main_cryptde();
        let system = System::new("can_update_consuming_wallet");
        let (o, r, e, subject) = make_o_r_e_subject();
        let addr: Addr<Neighborhood> = subject.start();
        let set_wallet_sub = addr.clone().recipient::<SetConsumingWalletMessage>();
        let route_sub = addr.recipient::<RouteQueryMessage>();
        let expected_new_wallet = make_paying_wallet(b"new consuming wallet");
        let expected_before_route = Route::round_trip(
            segment(&[&o, &r, &e], &Component::ProxyClient),
            segment(&[&e, &r, &o], &Component::ProxyServer),
            cryptde,
            Some(make_paying_wallet(b"consuming")),
            0,
            Some(TEST_DEFAULT_CHAIN.rec().contract),
        )
        .unwrap();
        let expected_after_route = Route::round_trip(
            segment(&[&o, &r, &e], &Component::ProxyClient),
            segment(&[&e, &r, &o], &Component::ProxyServer),
            cryptde,
            Some(expected_new_wallet.clone()),
            1,
            Some(TEST_DEFAULT_CHAIN.rec().contract),
        )
        .unwrap();

        let route_request_1 = route_sub.send(RouteQueryMessage::data_indefinite_route_request(
            None, 2, 1000,
        ));
        let _ = set_wallet_sub.try_send(SetConsumingWalletMessage {
            wallet: expected_new_wallet,
        });
        let route_request_2 = route_sub.send(RouteQueryMessage::data_indefinite_route_request(
            None, 2, 2000,
        ));

        System::current().stop();
        system.run();

        let route_1 = route_request_1.wait().unwrap().unwrap().route;
        let route_2 = route_request_2.wait().unwrap().unwrap().route;

        assert_eq!(route_1, expected_before_route);
        assert_eq!(route_2, expected_after_route);
    }

    #[test]
    fn compose_route_query_response_returns_an_error_when_route_segment_keys_is_empty() {
        let mut subject = make_standard_subject();

        let result: Result<RouteQueryResponse, String> = subject.compose_route_query_response(
            RouteSegment::new(vec![], Component::ProxyClient),
            RouteSegment::new(vec![], Component::ProxyServer),
        );
        assert!(result.is_err());
        let error_expectation: String = result.expect_err("Expected an Err but got:");
        assert_eq!(
            error_expectation,
            "Cannot make multi-hop route without segment keys"
        );
    }

    #[test]
    fn compose_route_query_response_returns_an_error_when_the_neighbor_is_none() {
        let mut subject = make_standard_subject();

        let result: Result<RouteQueryResponse, String> = subject.compose_route_query_response(
            RouteSegment::new(vec![&PublicKey::new(&[3, 3, 8])], Component::ProxyClient),
            RouteSegment::new(vec![&PublicKey::new(&[8, 3, 3])], Component::ProxyServer),
        );
        assert!(result.is_err());
        let error_expectation: String = result.expect_err("Expected an Err but got:");
        assert_eq!(
            error_expectation,
            "Cannot make multi_hop with unknown neighbor"
        );
        assert_eq!(subject.next_return_route_id, 0);
    }

    #[test]
    fn calculate_expected_service_returns_error_when_given_empty_segment() {
        let mut subject = make_standard_subject();
        let a = &make_node_record(3456, true);
        let db = &mut subject.neighborhood_database;
        db.add_node(a.clone()).unwrap();

        let result = subject.calculate_expected_service(a.public_key(), None, None);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "cannot calculate expected service, no keys provided in route segment"
        );
    }

    /*
            Database:

            Q---p---R
                |   |
            t---S---+

            p is consume-only, t is originate-only.
    */

    #[test]
    fn complete_routes_exercise() {
        let mut subject = make_standard_subject();
        let db = &mut subject.neighborhood_database;
        db.root_mut().inner.accepts_connections = false;
        db.root_mut().inner.routes_data = false;
        let p = &db.root_mut().public_key().clone(); // 9e7p7un06eHs6frl5A
        let q = &db.add_node(make_node_record(3456, true)).unwrap(); // AwQFBg
        let r = &db.add_node(make_node_record(4567, true)).unwrap(); // BAUGBw
        let s = &db.add_node(make_node_record(5678, true)).unwrap(); // BQYHCA
        let t = &db
            .add_node(make_node_record_f(6789, true, false, true))
            .unwrap(); // BgcICQ
        db.add_arbitrary_full_neighbor(q, p);
        db.add_arbitrary_full_neighbor(p, r);
        db.add_arbitrary_full_neighbor(p, s);
        db.add_arbitrary_full_neighbor(t, s);
        db.add_arbitrary_full_neighbor(s, r);

        // At least two hops from p to anywhere standard
        let route_opt =
            subject.find_best_route_segment(p, None, 2, 10000, RouteDirection::Over, None);

        assert_eq!(route_opt.unwrap(), vec![p, s, t]);
        // no [p, r, s] or [p, s, r] because s and r are both neighbors of p and can't exit for it

        // At least two hops over from p to t
        let route_opt =
            subject.find_best_route_segment(p, Some(t), 2, 10000, RouteDirection::Over, None);

        assert_eq!(route_opt.unwrap(), vec![p, s, t]);

        // At least two hops over from t to p
        let route_opt =
            subject.find_best_route_segment(t, Some(p), 2, 10000, RouteDirection::Over, None);

        assert_eq!(route_opt, None);
        // p is consume-only; can't be an exit Node.

        // At least two hops back from t to p
        let route_opt =
            subject.find_best_route_segment(t, Some(p), 2, 10000, RouteDirection::Back, None);

        assert_eq!(route_opt.unwrap(), vec![t, s, p]);
        // p is consume-only, but it's the originating Node, so including it is okay

        // At least two hops from p to Q - impossible
        let route_opt =
            subject.find_best_route_segment(p, Some(q), 2, 10000, RouteDirection::Over, None);

        assert_eq!(route_opt, None);
    }

    /*
            Database:

            A---B---C---D---E
            |   |   |   |   |
            F---G---H---I---J
            |   |   |   |   |
            K---L---M---N---O
            |   |   |   |   |
            P---Q---R---S---T
            |   |   |   |   |
            U---V---W---X---Y

            All these Nodes are standard-mode. L is the root Node. We'll be looking for routes
            from L to N.
    */

    #[test]
    fn route_optimization_test() {
        let mut subject = make_standard_subject();
        let db = &mut subject.neighborhood_database;
        let mut generator = 1000;
        let mut make_node = |db: &mut NeighborhoodDatabase| {
            let node = &db.add_node(make_node_record(generator, true)).unwrap();
            generator += 1;
            node.clone()
        };
        let mut make_row = |db: &mut NeighborhoodDatabase| {
            let n1 = make_node(db);
            let n2 = make_node(db);
            let n3 = make_node(db);
            let n4 = make_node(db);
            let n5 = make_node(db);
            db.add_arbitrary_full_neighbor(&n1, &n2);
            db.add_arbitrary_full_neighbor(&n2, &n3);
            db.add_arbitrary_full_neighbor(&n3, &n4);
            db.add_arbitrary_full_neighbor(&n4, &n5);
            (n1, n2, n3, n4, n5)
        };
        let join_rows = |db: &mut NeighborhoodDatabase, first_row, second_row| {
            let (f1, f2, f3, f4, f5) = first_row;
            let (s1, s2, s3, s4, s5) = second_row;
            db.add_arbitrary_full_neighbor(f1, s1);
            db.add_arbitrary_full_neighbor(f2, s2);
            db.add_arbitrary_full_neighbor(f3, s3);
            db.add_arbitrary_full_neighbor(f4, s4);
            db.add_arbitrary_full_neighbor(f5, s5);
        };
        let designate_root_node = |db: &mut NeighborhoodDatabase, key| {
            let root_node_key = db.root().public_key().clone();
            let node = db.node_by_key(key).unwrap().clone();
            db.root_mut().inner = node.inner.clone();
            db.root_mut().metadata = node.metadata.clone();
            db.remove_node(&root_node_key);
        };
        let (a, b, c, d, e) = make_row(db);
        let (f, g, h, i, j) = make_row(db);
        let (k, l, m, n, o) = make_row(db);
        let (p, q, r, s, t) = make_row(db);
        let (u, v, w, x, y) = make_row(db);
        join_rows(db, (&a, &b, &c, &d, &e), (&f, &g, &h, &i, &j));
        join_rows(db, (&f, &g, &h, &i, &j), (&k, &l, &m, &n, &o));
        join_rows(db, (&k, &l, &m, &n, &o), (&p, &q, &r, &s, &t));
        join_rows(db, (&p, &q, &r, &s, &t), (&u, &v, &w, &x, &y));
        designate_root_node(db, &l);
        let limit_ms = 50;
        // Sometimes a system delay might run this over the limit. Give it three chances.
        let total_chances = 3;
        let mut retries_left = total_chances - 1;
        let mut intervals: Vec<u128> = vec![];
        let route = loop {
            let before = Instant::now();

            // All the target-designated routes from L to N
            let route = subject
                .find_best_route_segment(&l, Some(&n), 3, 10000, RouteDirection::Back, None)
                .unwrap();

            let after = Instant::now();
            let interval = after.duration_since(before);
            if interval.as_millis() > limit_ms {
                intervals.push(interval.as_millis());
                if retries_left == 0 {
                    panic!(
                        "Should have calculated route in <= {}ms, but failed after {} tries: {:?}",
                        limit_ms, total_chances, intervals
                    )
                } else {
                    retries_left -= 1
                }
            } else {
                break route;
            }
        };
        assert_eq!(route, vec![&l, &g, &h, &i, &n]); // Cheaper than [&l, &q, &r, &s, &n]
    }

    /*
            Database:

            P---q---R

            Test is written from the standpoint of P. Node q is non-routing.
    */

    #[test]
    fn cant_route_through_non_routing_node() {
        let mut subject = make_standard_subject();
        let db = &mut subject.neighborhood_database;
        let p = &db.root_mut().public_key().clone(); // 9e7p7un06eHs6frl5A
        let q = &db
            .add_node(make_node_record_f(4567, true, false, false))
            .unwrap(); // BAUGBw
        let r = &db.add_node(make_node_record(5678, true)).unwrap(); // BQYHCA
        db.add_arbitrary_full_neighbor(p, q);
        db.add_arbitrary_full_neighbor(q, r);

        // At least two hops from P to anywhere standard
        let route_opt =
            subject.find_best_route_segment(p, None, 2, 10000, RouteDirection::Over, None);

        assert_eq!(route_opt, None);
    }

    #[test]
    fn computing_undesirability_works_for_relay_on_over_leg() {
        let node_record = make_node_record(1234, false);
        let subject = make_standard_subject();

        let new_undesirability = subject.compute_new_undesirability(
            &node_record,
            1_000_000, // Nonzero undesirability: on our way
            None,
            5, // Lots of hops to go yet
            1_000,
            RouteDirection::Over,
            Some("hostname.com"),
        );

        let rate_pack = node_record.rate_pack();
        // node_record will charge us for the link beyond
        assert_eq!(
            new_undesirability,
            1_000_000 // existing undesirability
                + rate_pack.routing_charge (1_000) as i64 // charge to route packet
        );
    }

    #[test]
    fn computing_undesirability_works_for_exit_on_over_leg_for_non_blacklisted_host() {
        let node_record = make_node_record(2345, false);
        let subject = make_standard_subject();

        let new_undesirability = subject.compute_new_undesirability(
            &node_record,
            1_000_000,
            None,
            0, // Last hop
            1_000,
            RouteDirection::Over,
            Some("hostname.com"),
        );

        let rate_pack = node_record.rate_pack();
        assert_eq!(
            new_undesirability,
            1_000_000 // existing undesirability
                    + rate_pack.exit_charge (1_000) as i64 // charge to exit request
        );
    }

    #[test]
    fn computing_undesirability_works_for_exit_on_over_leg_for_blacklisted_host() {
        init_test_logging();
        let mut node_record = make_node_record(2345, false);
        node_record
            .metadata
            .unreachable_hosts
            .insert("hostname.com".to_string());
        let subject = make_standard_subject();

        let new_undesirability = subject.compute_new_undesirability(
            &node_record,
            1_000_000,
            None,
            0, // Last hop
            1_000,
            RouteDirection::Over,
            Some("hostname.com"),
        );

        let rate_pack = node_record.rate_pack();
        assert_eq!(
            new_undesirability,
            1_000_000 // existing undesirability
                    + rate_pack.exit_charge (1_000) as i64 // charge to exit request
                    + UNREACHABLE_HOST_PENALTY // because host is blacklisted
        );
        TestLogHandler::new().exists_log_containing(
            "TRACE: Neighborhood: Node with PubKey 0x02030405 \
                      failed to reach host \"hostname.com\" during ExitRequest; \
                      Undesirability: 2350745 + 100000000 = 102350745",
        );
    }

    #[test]
    fn computing_initial_undesirability_works_for_origin_on_over_leg() {
        let node_record = make_node_record(4567, false);
        let mut subject = make_standard_subject();
        subject
            .neighborhood_database
            .add_node(node_record.clone())
            .unwrap();

        let initial_undesirability = subject.compute_initial_undesirability(
            node_record.public_key(),
            1_000,
            RouteDirection::Over,
        );

        assert_eq!(
            initial_undesirability,
            0 // Origin does not charge itself for routing
        );
    }

    #[test]
    fn computing_initial_undesirability_works_for_exit_on_back_leg() {
        let node_record = make_node_record(4567, false);
        let mut subject = make_standard_subject();
        subject
            .neighborhood_database
            .add_node(node_record.clone())
            .unwrap();

        let initial_undesirability = subject.compute_initial_undesirability(
            node_record.public_key(),
            1_000,
            RouteDirection::Back,
        );

        let rate_pack = node_record.rate_pack();
        assert_eq!(
            initial_undesirability,
            rate_pack.exit_charge (1_000) as i64 // charge to exit response
                + rate_pack.routing_charge (1_000) as i64 // charge to route response
        );
    }

    #[test]
    fn computing_undesirability_works_for_relay_on_back_leg() {
        let node_record = make_node_record(4567, false);
        let subject = make_standard_subject();

        let new_undesirability = subject.compute_new_undesirability(
            &node_record,
            1_000_000, // Nonzero undesirability: we're on our way
            Some(&PublicKey::new(b"Booga")),
            5, // Plenty of hops remaining: not there yet
            1_000,
            RouteDirection::Back,
            None,
        );

        let rate_pack = node_record.rate_pack();
        assert_eq!(
            new_undesirability,
            1_000_000 // existing undesirability
                + rate_pack.routing_charge (1_000) as i64 // charge to route response
        );
    }

    #[test]
    fn gossips_after_removing_a_neighbor() {
        let (hopper, hopper_awaiter, hopper_recording) = make_recorder();
        let cryptde = main_cryptde();
        let earning_wallet = make_wallet("earning");
        let consuming_wallet = Some(make_paying_wallet(b"consuming"));
        let this_node = NodeRecord::new_for_tests(
            &cryptde.public_key(),
            Some(&NodeAddr::new(
                &IpAddr::from_str("5.4.3.2").unwrap(),
                &[1234],
            )),
            100,
            true,
            true,
        );
        let this_node_inside = this_node.clone();
        let removed_neighbor = make_node_record(2345, true);
        let removed_neighbor_inside = removed_neighbor.clone();
        let other_neighbor = make_node_record(3456, true);
        let other_neighbor_inside = other_neighbor.clone();

        thread::spawn(move || {
            let system = System::new("gossips_after_removing_a_neighbor");
            let mut subject = Neighborhood::new(
                cryptde,
                &bc_from_nc_plus(
                    NeighborhoodConfig {
                        mode: NeighborhoodMode::Standard(
                            this_node_inside.node_addr_opt().unwrap(),
                            vec![],
                            rate_pack(100),
                        ),
                    },
                    earning_wallet.clone(),
                    consuming_wallet.clone(),
                    "gossips_after_removing_a_neighbor",
                ),
            );
            let db = &mut subject.neighborhood_database;

            db.add_node(removed_neighbor_inside.clone()).unwrap();
            db.add_node(other_neighbor_inside.clone()).unwrap();
            db.add_arbitrary_full_neighbor(
                &cryptde.public_key(),
                removed_neighbor_inside.public_key(),
            );
            db.add_arbitrary_full_neighbor(
                &cryptde.public_key(),
                other_neighbor_inside.public_key(),
            );
            db.add_arbitrary_full_neighbor(
                removed_neighbor_inside.public_key(),
                other_neighbor_inside.public_key(),
            );

            let addr: Addr<Neighborhood> = subject.start();
            let peer_actors = peer_actors_builder().hopper(hopper).build();
            addr.try_send(BindMessage { peer_actors }).unwrap();
            addr.try_send(make_meaningless_pool_bind_message()).unwrap();

            let sub: Recipient<RemoveNeighborMessage> = addr.recipient::<RemoveNeighborMessage>();
            sub.try_send(RemoveNeighborMessage {
                public_key: removed_neighbor_inside.public_key().clone(),
            })
            .unwrap();

            system.run();
        });

        let other_neighbor_cryptde =
            CryptDENull::from(other_neighbor.public_key(), TEST_DEFAULT_CHAIN);
        hopper_awaiter.await_message_count(1);
        let locked_recording = hopper_recording.lock().unwrap();
        let package: &IncipientCoresPackage = locked_recording.get_record(0);
        let gossip = match decodex(&other_neighbor_cryptde, &package.payload).unwrap() {
            MessageType::Gossip(vd) => Gossip_0v1::try_from(vd).unwrap(),
            x => panic!("Expected MessageType::Gossip, got {:?}", x),
        };
        type Digest = (PublicKey, Vec<u8>, bool, u32, Vec<PublicKey>);
        let to_actual_digest = |gnr: GossipNodeRecord| {
            let node_addr_opt = gnr.node_addr_opt.clone();
            let inner = NodeRecordInner_0v1::try_from(gnr).unwrap();
            let neighbors_vec = inner.neighbors.into_iter().collect::<Vec<PublicKey>>();
            (
                inner.public_key.clone(),
                inner.public_key.into(),
                node_addr_opt.is_some(),
                inner.version,
                neighbors_vec,
            )
        };

        let sort_digests = |digests: Vec<Digest>| {
            let mut digests = digests
                .into_iter()
                .map(|mut d| {
                    d.4.sort_unstable_by(|a, b| a.cmp(&b));
                    d
                })
                .collect_vec();
            digests.sort_unstable_by(|a, b| a.0.cmp(&b.0));
            digests
        };

        let actual_digests = sort_digests(
            gossip
                .node_records
                .into_iter()
                .map(|gnr| to_actual_digest(gnr))
                .collect::<Vec<Digest>>(),
        );

        let expected_digests = sort_digests(vec![
            (
                removed_neighbor.public_key().clone(),
                removed_neighbor.public_key().clone().into(),
                false,
                0,
                vec![
                    other_neighbor.public_key().clone(),
                    this_node.public_key().clone(),
                ],
            ),
            (
                this_node.public_key().clone(),
                this_node.public_key().clone().into(),
                true,
                1,
                vec![other_neighbor.public_key().clone()],
            ),
        ]);

        assert_eq!(expected_digests, actual_digests);
    }

    #[test]
    fn neighborhood_calls_gossip_acceptor_when_gossip_is_received() {
        let handle_params_arc = Arc::new(Mutex::new(vec![]));
        let gossip_acceptor = GossipAcceptorMock::new()
            .handle_params(&handle_params_arc)
            .handle_result(GossipAcceptanceResult::Ignored);
        let subject_node = make_global_cryptde_node_record(1234, true); // 9e7p7un06eHs6frl5A
        let neighbor = make_node_record(1111, true);
        let mut subject = neighborhood_from_nodes(&subject_node, Some(&neighbor));
        subject.gossip_acceptor_info_opt = Some(Either::Left(Box::new(gossip_acceptor)));
        let gossip = GossipBuilder::new(&subject.neighborhood_database)
            .node(subject_node.public_key(), true)
            .build();
        let cores_package = ExpiredCoresPackage {
            immediate_neighbor: subject_node.node_addr_opt().unwrap().into(),
            paying_wallet: None,
            remaining_route: make_meaningless_route(),
            payload: gossip.clone(),
            payload_len: 0,
        };
        let system = System::new("test");
        let addr: Addr<Neighborhood> = subject.start();
        let sub = addr.recipient::<ExpiredCoresPackage<Gossip_0v1>>();

        sub.try_send(cores_package).unwrap();

        System::current().stop();
        system.run();
        let mut handle_params = handle_params_arc.lock().unwrap();
        let (call_database, call_agrs, call_gossip_source, connection_progress_peers) =
            handle_params.remove(0);
        assert!(handle_params.is_empty());
        assert_eq!(&subject_node, call_database.root());
        assert_eq!(1, call_database.keys().len());
        let agrs: Vec<AccessibleGossipRecord> = gossip.try_into().unwrap();
        assert_eq!(agrs, call_agrs);
        let actual_gossip_source: SocketAddr = subject_node.node_addr_opt().unwrap().into();
        assert_eq!(actual_gossip_source, call_gossip_source);
        let neighbor_ip = neighbor.node_addr_opt().unwrap().ip_addr();
        assert_eq!(connection_progress_peers, vec![neighbor_ip]);
    }

    #[test]
    fn neighborhood_sends_only_an_acceptance_debut_when_an_acceptance_debut_is_provided() {
        let introduction_target_node = make_node_record(7345, true);
        let subject_node = make_global_cryptde_node_record(5555, true); // 9e7p7un06eHs6frl5A
        let neighbor = make_node_record(1050, true);
        let mut subject = neighborhood_from_nodes(&subject_node, Some(&neighbor));
        subject
            .neighborhood_database
            .add_node(introduction_target_node.clone())
            .unwrap();

        subject.neighborhood_database.add_arbitrary_half_neighbor(
            subject_node.public_key(),
            introduction_target_node.public_key(),
        );
        let debut = GossipBuilder::new(&subject.neighborhood_database)
            .node(subject_node.public_key(), true)
            .build();
        let gossip_acceptor =
            GossipAcceptorMock::new().handle_result(GossipAcceptanceResult::Reply(
                debut.clone(),
                introduction_target_node.public_key().clone(),
                introduction_target_node.node_addr_opt().unwrap(),
            ));
        subject.gossip_acceptor_info_opt = Some(Either::Left(Box::new(gossip_acceptor)));
        let (hopper, _, hopper_recording_arc) = make_recorder();
        let peer_actors = peer_actors_builder().hopper(hopper).build();
        let system = System::new("");
        subject.hopper_no_lookup_sub_opt = Some(peer_actors.hopper.from_hopper_client_no_lookup);

        subject.handle_gossip(
            Gossip_0v1::new(vec![]),
            SocketAddr::from_str("1.1.1.1:1111").unwrap(),
        );

        System::current().stop();
        system.run();
        let hopper_recording = hopper_recording_arc.lock().unwrap();
        let package = hopper_recording.get_record::<NoLookupIncipientCoresPackage>(0);
        assert_eq!(1, hopper_recording.len());
        assert_eq!(introduction_target_node.public_key(), &package.public_key);
        let gossip = match decodex::<MessageType>(
            &CryptDENull::from(introduction_target_node.public_key(), TEST_DEFAULT_CHAIN),
            &package.payload,
        ) {
            Ok(MessageType::Gossip(vd)) => Gossip_0v1::try_from(vd).unwrap(),
            x => panic!("Wanted Gossip, found {:?}", x),
        };
        assert_eq!(debut, gossip);
    }

    #[test]
    fn neighborhood_transmits_gossip_failure_properly() {
        let subject_node = make_global_cryptde_node_record(5555, true); // 9e7p7un06eHs6frl5A
        let neighbor = make_node_record(1111, true);
        let public_key = PublicKey::new(&[1, 2, 3, 4]);
        let node_addr = NodeAddr::from_str("1.2.3.4:1234").unwrap();
        let gossip_acceptor =
            GossipAcceptorMock::new().handle_result(GossipAcceptanceResult::Failed(
                GossipFailure_0v1::NoSuitableNeighbors,
                public_key.clone(),
                node_addr.clone(),
            ));
        let mut subject: Neighborhood = neighborhood_from_nodes(&subject_node, Some(&neighbor));
        let (hopper, _, hopper_recording_arc) = make_recorder();
        let system = System::new("neighborhood_transmits_gossip_failure_properly");
        let peer_actors = peer_actors_builder().hopper(hopper).build();
        subject.hopper_no_lookup_sub_opt = Some(peer_actors.hopper.from_hopper_client_no_lookup);
        subject.gossip_acceptor_info_opt = Some(Either::Left(Box::new(gossip_acceptor)));

        subject.handle_gossip_agrs(vec![], SocketAddr::from_str("1.2.3.4:1234").unwrap());

        System::current().stop();
        system.run();
        let hopper_recording = hopper_recording_arc.lock().unwrap();
        let package = hopper_recording.get_record::<NoLookupIncipientCoresPackage>(0);
        assert_eq!(1, hopper_recording.len());
        assert_eq!(package.node_addr, node_addr);
        let payload = decodex::<MessageType>(
            &CryptDENull::from(&public_key, TEST_DEFAULT_CHAIN),
            &package.payload,
        )
        .unwrap();
        assert_eq!(
            payload,
            MessageType::GossipFailure(VersionedData::new(
                &crate::sub_lib::migrations::gossip_failure::MIGRATIONS,
                &GossipFailure_0v1::NoSuitableNeighbors
            ))
        );
    }

    struct DatabaseReplacementGossipAcceptor {
        pub replacement_database: NeighborhoodDatabase,
    }

    impl GossipAcceptor for DatabaseReplacementGossipAcceptor {
        fn handle(
            &self,
            database: &mut NeighborhoodDatabase,
            _agrs: Vec<AccessibleGossipRecord>,
            _gossip_source: SocketAddr,
            _connection_progress_peers: &[IpAddr],
        ) -> GossipAcceptanceResult {
            let non_root_database_keys = database
                .keys()
                .into_iter()
                .filter(|k| *k != database.root().public_key())
                .map(|k| k.clone())
                .collect_vec();
            non_root_database_keys
                .into_iter()
                .for_each(|k| database.remove_node(&k));
            let database_root_neighbor_keys = database
                .root()
                .half_neighbor_keys()
                .into_iter()
                .map(|k| k.clone())
                .collect_vec();
            database_root_neighbor_keys.into_iter().for_each(|k| {
                database.root_mut().remove_half_neighbor_key(&k);
            });
            self.replacement_database
                .keys()
                .into_iter()
                .filter(|k| *k != self.replacement_database.root().public_key())
                .for_each(|k| {
                    database
                        .add_node(self.replacement_database.node_by_key(k).unwrap().clone())
                        .unwrap();
                });
            self.replacement_database.keys().into_iter().for_each(|k| {
                let node_record = self.replacement_database.node_by_key(k).unwrap();
                node_record.half_neighbor_keys().into_iter().for_each(|n| {
                    database.add_arbitrary_half_neighbor(k, n);
                });
            });
            GossipAcceptanceResult::Ignored
        }
    }

    fn bind_subject(subject: &mut Neighborhood, peer_actors: PeerActors) {
        subject.hopper_opt = Some(peer_actors.hopper.from_hopper_client);
        subject.hopper_no_lookup_sub_opt = Some(peer_actors.hopper.from_hopper_client_no_lookup);
        subject.connected_signal_sub_opt = Some(peer_actors.accountant.start);
    }

    #[test]
    fn neighborhood_does_not_start_accountant_if_no_route_can_be_made() {
        let subject_node = make_global_cryptde_node_record(5555, true); // 9e7p7un06eHs6frl5A
        let neighbor = make_node_record(1111, true);
        let mut subject: Neighborhood = neighborhood_from_nodes(&subject_node, Some(&neighbor));
        let mut replacement_database = subject.neighborhood_database.clone();
        replacement_database.add_node(neighbor.clone()).unwrap();
        replacement_database
            .add_arbitrary_half_neighbor(subject_node.public_key(), neighbor.public_key());
        subject.gossip_acceptor_info_opt =
            Some(Either::Left(Box::new(DatabaseReplacementGossipAcceptor {
                replacement_database,
            })));
        let (accountant, _, accountant_recording_arc) = make_recorder();
        let system = System::new("neighborhood_does_not_start_accountant_if_no_route_can_be_made");
        let peer_actors = peer_actors_builder().accountant(accountant).build();
        bind_subject(&mut subject, peer_actors);

        subject.handle_gossip_agrs(vec![], SocketAddr::from_str("1.2.3.4:1234").unwrap());

        System::current().stop();
        system.run();
        let accountant_recording = accountant_recording_arc.lock().unwrap();
        assert_eq!(accountant_recording.len(), 0);
        assert_eq!(subject.overall_connection_status.can_make_routes(), false);
    }

    #[test]
    fn neighborhood_does_not_start_accountant_if_already_connected() {
        let subject_node = make_global_cryptde_node_record(5555, true); // 9e7p7un06eHs6frl5A
        let neighbor = make_node_record(1111, true);
        let mut subject: Neighborhood = neighborhood_from_nodes(&subject_node, Some(&neighbor));
        let replacement_database = subject.neighborhood_database.clone();
        subject.gossip_acceptor_info_opt =
            Some(Either::Left(Box::new(DatabaseReplacementGossipAcceptor {
                replacement_database,
            })));
        let (accountant, _, accountant_recording_arc) = make_recorder();
        let system = System::new("neighborhood_does_not_start_accountant_if_already_connected");
        let peer_actors = peer_actors_builder().accountant(accountant).build();
        bind_subject(&mut subject, peer_actors);

        subject.handle_gossip_agrs(vec![], SocketAddr::from_str("1.2.3.4:1234").unwrap());

        System::current().stop();
        system.run();
        let accountant_recording = accountant_recording_arc.lock().unwrap();
        assert_eq!(accountant_recording.len(), 0);
    }

    #[test]
    fn neighborhood_starts_accountant_when_first_route_can_be_made() {
        let (accountant, _, accountant_recording_arc) = make_recorder();
        let (ui_gateway, _, _) = make_recorder();
        let mut subject = make_neighborhood_linearly_connected_with_nodes(3);
        subject.node_to_ui_sub_opt = Some(ui_gateway.start().recipient());
        let peer_actors = peer_actors_builder().accountant(accountant).build();
        bind_subject(&mut subject, peer_actors);
        let system = System::new("neighborhood_does_not_start_accountant_if_no_route_can_be_made");

        subject.handle_gossip_agrs(vec![], SocketAddr::from_str("1.2.3.4:1234").unwrap());

        System::current().stop();
        system.run();
        let accountant_recording = accountant_recording_arc.lock().unwrap();
        assert_eq!(accountant_recording.len(), 1);
    }

    #[test]
    fn neighborhood_ignores_gossip_if_it_receives_a_pass_target_which_is_a_part_of_a_different_connection_progress(
    ) {
        init_test_logging();
        let handle_params_arc = Arc::new(Mutex::new(vec![]));
        let gossip_acceptor = GossipAcceptorMock::new()
            .handle_params(&handle_params_arc)
            .handle_result(GossipAcceptanceResult::Ignored);
        let (node_to_ui_recipient, _) = make_node_to_ui_recipient();
        let peer_1 = make_node_record(1234, true);
        let peer_2 = make_node_record(6721, true);
        let desc_1 = peer_1.node_descriptor(Chain::Dev, main_cryptde());
        let desc_2 = peer_2.node_descriptor(Chain::Dev, main_cryptde());
        let this_node = make_node_record(7777, true);
        let initial_node_descriptors = vec![desc_1, desc_2];
        let neighborhood_config = NeighborhoodConfig {
            mode: NeighborhoodMode::Standard(
                this_node.node_addr_opt().unwrap(),
                initial_node_descriptors,
                rate_pack(100),
            ),
        };
        let bootstrap_config =
            bc_from_nc_plus(neighborhood_config, make_wallet("earning"), None, "test");
        let mut subject = Neighborhood::new(main_cryptde(), &bootstrap_config);
        subject.node_to_ui_sub_opt = Some(node_to_ui_recipient);
        subject.gossip_acceptor_info_opt = Some(Either::Left(Box::new(gossip_acceptor)));
        let mut peer_2_db = db_from_node(&peer_2);
        peer_2_db.add_node(peer_1.clone()).unwrap();
        peer_2_db.add_arbitrary_full_neighbor(peer_2.public_key(), peer_1.public_key());
        let peer_2_socket_addr: SocketAddr = peer_2.metadata.node_addr_opt.unwrap().into();
        let pass_gossip = GossipBuilder::new(&peer_2_db)
            .node(peer_1.public_key(), true)
            .build();
        let agrs: Vec<AccessibleGossipRecord> = pass_gossip.try_into().unwrap();

        subject.handle_agrs(agrs, peer_2_socket_addr);

        TestLogHandler::new()
            .exists_log_containing(&format!("Gossip from {} ignored", peer_2_socket_addr));
    }

    #[test]
    fn neighborhood_can_absorb_gossip_without_sending_responses() {
        init_test_logging();
        let neighborhood_config = NeighborhoodConfig {
            mode: NeighborhoodMode::Standard(
                NodeAddr::new(&IpAddr::from_str("2.2.2.2").unwrap(), &[2222u16]),
                vec![],
                rate_pack(100),
            ),
        };
        let bootstrap_config =
            bc_from_nc_plus(neighborhood_config, make_wallet("earning"), None, "test");
        let mut subject = Neighborhood::new(main_cryptde(), &bootstrap_config);
        subject.logger = Logger::new("neighborhood_can_absorb_gossip_without_sending_responses");

        subject.process_acceptance_result(GossipAcceptanceResult::Absorbed, "new-IP Node", 1);

        TestLogHandler::new().exists_log_containing("TRACE: neighborhood_can_absorb_gossip_without_sending_responses: 1-Node Gossip from new-IP Node absorbed");
    }

    #[test]
    fn neighborhood_updates_ocs_stage_and_sends_message_to_the_ui_when_first_route_can_be_made() {
        init_test_logging();
        let test_name = "neighborhood_updates_ocs_stage_and_sends_message_to_the_ui_when_first_route_can_be_made";
        let mut subject: Neighborhood = make_neighborhood_linearly_connected_with_nodes(3);
        let (ui_gateway, _, ui_gateway_arc) = make_recorder();
        let (accountant, _, _) = make_recorder();
        let node_to_ui_recipient = ui_gateway.start().recipient::<NodeToUiMessage>();
        let connected_signal = accountant.start().recipient();
        subject.logger = Logger::new(test_name);
        subject.node_to_ui_sub_opt = Some(node_to_ui_recipient);
        subject.connected_signal_sub_opt = Some(connected_signal);
        let system = System::new(test_name);

        subject.handle_gossip_agrs(vec![], SocketAddr::from_str("1.2.3.4:1234").unwrap());

        System::current().stop();
        system.run();
        let ui_recording = ui_gateway_arc.lock().unwrap();
        let node_to_ui_message = ui_recording.get_record::<NodeToUiMessage>(0);
        assert_eq!(ui_recording.len(), 1);
        assert_eq!(subject.overall_connection_status.can_make_routes(), true);
        assert_eq!(
            subject.overall_connection_status.stage(),
            OverallConnectionStage::ThreeHopsRouteFound
        );
        assert_eq!(
            node_to_ui_message,
            &NodeToUiMessage {
                target: MessageTarget::AllClients,
                body: UiConnectionChangeBroadcast {
                    stage: UiConnectionStage::ThreeHopsRouteFound
                }
                .tmb(0),
            }
        );
        TestLogHandler::new().exists_log_containing(&format!(
            "DEBUG: {}: The connectivity check has found a 3 hops route.",
            test_name
        ));
    }

    #[test]
    fn neighborhood_logs_when_three_hops_route_can_not_be_made() {
        init_test_logging();
        let test_name = "neighborhood_logs_when_three_hops_route_can_not_be_made";
        let mut subject: Neighborhood = make_neighborhood_linearly_connected_with_nodes(2);
        let (ui_gateway, _, ui_gateway_arc) = make_recorder();
        let (accountant, _, _) = make_recorder();
        let node_to_ui_recipient = ui_gateway.start().recipient::<NodeToUiMessage>();
        let connected_signal = accountant.start().recipient();
        subject.logger = Logger::new(test_name);
        subject.node_to_ui_sub_opt = Some(node_to_ui_recipient);
        subject.connected_signal_sub_opt = Some(connected_signal);
        let system = System::new(test_name);

        subject.handle_gossip_agrs(vec![], SocketAddr::from_str("1.2.3.4:1234").unwrap());

        System::current().stop();
        system.run();
        let ui_recording = ui_gateway_arc.lock().unwrap();
        assert_eq!(ui_recording.len(), 0);
        assert_eq!(subject.overall_connection_status.can_make_routes(), false);
        TestLogHandler::new().exists_log_containing(&format!(
            "DEBUG: {}: The connectivity check still can't find a good route.",
            test_name
        ));
    }

    struct NeighborReplacementGossipAcceptor {
        pub new_neighbors: Vec<NodeRecord>,
    }

    impl GossipAcceptor for NeighborReplacementGossipAcceptor {
        fn handle(
            &self,
            database: &mut NeighborhoodDatabase,
            _agrs: Vec<AccessibleGossipRecord>,
            _gossip_source: SocketAddr,
            _connection_progress_peers: &[IpAddr],
        ) -> GossipAcceptanceResult {
            let half_neighbor_keys = database
                .root()
                .half_neighbor_keys()
                .into_iter()
                .map(|k| k.clone())
                .collect_vec();
            half_neighbor_keys
                .into_iter()
                .for_each(|k| database.remove_node(&k));
            let root_key = database.root().public_key().clone();
            self.new_neighbors.iter().for_each(|nr| {
                database.add_node(nr.clone()).unwrap();
                database.add_arbitrary_full_neighbor(&root_key, nr.public_key());
            });
            GossipAcceptanceResult::Ignored
        }
    }

    #[test]
    fn neighborhood_updates_past_neighbors_when_neighbor_list_changes() {
        let cryptde: &dyn CryptDE = main_cryptde();
        let subject_node = make_global_cryptde_node_record(5555, true); // 9e7p7un06eHs6frl5A
        let old_neighbor = make_node_record(1111, true);
        let new_neighbor = make_node_record(2222, true);
        let mut subject: Neighborhood = neighborhood_from_nodes(&subject_node, Some(&old_neighbor));
        subject
            .neighborhood_database
            .add_node(old_neighbor.clone())
            .unwrap();
        subject
            .neighborhood_database
            .add_arbitrary_full_neighbor(subject_node.public_key(), old_neighbor.public_key());
        let gossip_acceptor = NeighborReplacementGossipAcceptor {
            new_neighbors: vec![old_neighbor.clone(), new_neighbor.clone()],
        };
        let set_past_neighbors_params_arc = Arc::new(Mutex::new(vec![]));
        let persistent_config = PersistentConfigurationMock::new()
            .set_past_neighbors_params(&set_past_neighbors_params_arc)
            .set_past_neighbors_result(Ok(()));
        subject.gossip_acceptor_info_opt = Some(Either::Left(Box::new(gossip_acceptor)));
        subject.persistent_config_opt = Some(Box::new(persistent_config));

        subject.handle_gossip_agrs(vec![], SocketAddr::from_str("1.2.3.4:1234").unwrap());

        let mut set_past_neighbors_params = set_past_neighbors_params_arc.lock().unwrap();
        let (neighbors_opt, db_password) = set_past_neighbors_params.remove(0);
        let neighbors = neighbors_opt.unwrap();
        assert_contains(
            &neighbors,
            &NodeDescriptor::from((&old_neighbor, TEST_DEFAULT_CHAIN, cryptde)),
        );
        assert_contains(
            &neighbors,
            &NodeDescriptor::from((&new_neighbor, TEST_DEFAULT_CHAIN, cryptde)),
        );
        assert_eq!(neighbors.len(), 2);
        assert_eq!(db_password, "password".to_string());
    }

    #[test]
    fn neighborhood_removes_past_neighbors_when_neighbor_list_goes_empty() {
        let subject_node = make_global_cryptde_node_record(5555, true); // 9e7p7un06eHs6frl5A
        let neighbor = make_node_record(1111, true);
        let mut subject: Neighborhood = neighborhood_from_nodes(&subject_node, Some(&neighbor));
        subject
            .neighborhood_database
            .add_node(neighbor.clone())
            .unwrap();
        subject
            .neighborhood_database
            .add_arbitrary_full_neighbor(subject_node.public_key(), neighbor.public_key());
        let gossip_acceptor = NeighborReplacementGossipAcceptor {
            new_neighbors: vec![],
        };
        let set_past_neighbors_params_arc = Arc::new(Mutex::new(vec![]));
        let persistent_config = PersistentConfigurationMock::new()
            .set_past_neighbors_params(&set_past_neighbors_params_arc)
            .set_past_neighbors_result(Ok(()));
        subject.gossip_acceptor_info_opt = Some(Either::Left(Box::new(gossip_acceptor)));
        subject.persistent_config_opt = Some(Box::new(persistent_config));

        subject.handle_gossip_agrs(vec![], SocketAddr::from_str("1.2.3.4:1234").unwrap());

        let mut set_past_neighbors_params = set_past_neighbors_params_arc.lock().unwrap();
        let (neighbors_opt, db_password) = set_past_neighbors_params.remove(0);
        assert_eq!(neighbors_opt, None);
        assert_eq!(db_password, "password".to_string());
    }

    #[test]
    fn neighborhood_does_not_update_past_neighbors_when_neighbor_list_does_not_change() {
        let subject_node = make_global_cryptde_node_record(5555, true); // 9e7p7un06eHs6frl5A
        let steadfast_neighbor = make_node_record(1111, true);
        let mut subject: Neighborhood =
            neighborhood_from_nodes(&subject_node, Some(&steadfast_neighbor));
        subject
            .neighborhood_database
            .add_node(steadfast_neighbor.clone())
            .unwrap();
        subject.neighborhood_database.add_arbitrary_full_neighbor(
            subject_node.public_key(),
            steadfast_neighbor.public_key(),
        );
        let gossip_acceptor = NeighborReplacementGossipAcceptor {
            new_neighbors: vec![steadfast_neighbor.clone()],
        };
        let set_past_neighbors_params_arc = Arc::new(Mutex::new(vec![]));
        let persistent_config = PersistentConfigurationMock::new()
            .set_past_neighbors_params(&set_past_neighbors_params_arc);
        subject.gossip_acceptor_info_opt = Some(Either::Left(Box::new(gossip_acceptor)));
        subject.persistent_config_opt = Some(Box::new(persistent_config));

        subject.handle_gossip_agrs(vec![], SocketAddr::from_str("1.2.3.4:1234").unwrap());

        let set_past_neighbors_params = set_past_neighbors_params_arc.lock().unwrap();
        assert!(set_past_neighbors_params.is_empty());
    }

    #[test]
    fn neighborhood_does_not_update_past_neighbors_without_password_even_when_neighbor_list_changes(
    ) {
        let subject_node = make_global_cryptde_node_record(5555, true); // 9e7p7un06eHs6frl5A
        let old_neighbor = make_node_record(1111, true);
        let new_neighbor = make_node_record(2222, true);
        let mut subject: Neighborhood = neighborhood_from_nodes(&subject_node, Some(&old_neighbor));
        subject
            .neighborhood_database
            .add_node(old_neighbor.clone())
            .unwrap();
        subject
            .neighborhood_database
            .add_arbitrary_full_neighbor(subject_node.public_key(), old_neighbor.public_key());
        let gossip_acceptor = NeighborReplacementGossipAcceptor {
            new_neighbors: vec![old_neighbor.clone(), new_neighbor.clone()],
        };
        let set_past_neighbors_params_arc = Arc::new(Mutex::new(vec![]));
        let persistent_config = PersistentConfigurationMock::new()
            .set_past_neighbors_params(&set_past_neighbors_params_arc);
        subject.gossip_acceptor_info_opt = Some(Either::Left(Box::new(gossip_acceptor)));
        subject.persistent_config_opt = Some(Box::new(persistent_config));
        subject.db_password_opt = None;

        subject.handle_gossip_agrs(vec![], SocketAddr::from_str("1.2.3.4:1234").unwrap());

        let set_past_neighbors_params = set_past_neighbors_params_arc.lock().unwrap();
        assert!(set_past_neighbors_params.is_empty());
    }

    #[test]
    fn neighborhood_warns_when_past_neighbors_update_fails_because_of_database_lock() {
        init_test_logging();
        let subject_node = make_global_cryptde_node_record(5555, true); // 9e7p7un06eHs6frl5A
        let old_neighbor = make_node_record(1111, true);
        let new_neighbor = make_node_record(2222, true);
        let mut subject: Neighborhood = neighborhood_from_nodes(&subject_node, Some(&old_neighbor));
        subject
            .neighborhood_database
            .add_node(old_neighbor.clone())
            .unwrap();
        subject
            .neighborhood_database
            .add_arbitrary_full_neighbor(subject_node.public_key(), old_neighbor.public_key());
        let gossip_acceptor = NeighborReplacementGossipAcceptor {
            new_neighbors: vec![old_neighbor.clone(), new_neighbor.clone()],
        };
        let persistent_config = PersistentConfigurationMock::new().set_past_neighbors_result(Err(
            PersistentConfigError::DatabaseError("database is locked".to_string()),
        ));
        subject.gossip_acceptor_info_opt = Some(Either::Left(Box::new(gossip_acceptor)));
        subject.persistent_config_opt = Some(Box::new(persistent_config));

        subject.handle_gossip_agrs(vec![], SocketAddr::from_str("1.2.3.4:1234").unwrap());

        TestLogHandler::new().exists_log_containing("WARN: Neighborhood: Could not persist immediate-neighbor changes: database locked - skipping");
    }

    #[test]
    fn neighborhood_logs_error_when_past_neighbors_update_fails_for_another_reason() {
        init_test_logging();
        let subject_node = make_global_cryptde_node_record(5555, true); // 9e7p7un06eHs6frl5A
        let old_neighbor = make_node_record(1111, true);
        let new_neighbor = make_node_record(2222, true);
        let mut subject: Neighborhood = neighborhood_from_nodes(&subject_node, Some(&old_neighbor));
        subject
            .neighborhood_database
            .add_node(old_neighbor.clone())
            .unwrap();
        subject
            .neighborhood_database
            .add_arbitrary_full_neighbor(subject_node.public_key(), old_neighbor.public_key());
        let gossip_acceptor = NeighborReplacementGossipAcceptor {
            new_neighbors: vec![old_neighbor.clone(), new_neighbor.clone()],
        };
        let persistent_config = PersistentConfigurationMock::new().set_past_neighbors_result(Err(
            PersistentConfigError::DatabaseError("Booga".to_string()),
        ));
        subject.gossip_acceptor_info_opt = Some(Either::Left(Box::new(gossip_acceptor)));
        subject.persistent_config_opt = Some(Box::new(persistent_config));

        subject.handle_gossip_agrs(vec![], SocketAddr::from_str("1.2.3.4:1234").unwrap());

        TestLogHandler::new().exists_log_containing("ERROR: Neighborhood: Could not persist immediate-neighbor changes: DatabaseError(\"Booga\")");
    }

    #[test]
    fn handle_new_public_ip_changes_public_ip_and_announces_the_change() {
        init_test_logging();
        let subject_node = make_global_cryptde_node_record(1234, true);
        let new_public_ip = IpAddr::from_str("4.3.2.1").unwrap();
        let (hopper, _, hopper_recording_arc) = make_recorder();
        let (subject, one_neighbor, another_neighbor) = {
            let mut subject: Neighborhood =
                neighborhood_from_nodes(&subject_node, Some(&make_node_record(7654, true)));
            subject.gossip_producer_opt = Some(Box::new(GossipProducerReal::new()));
            subject.hopper_no_lookup_sub_opt = Some(hopper.start().recipient());
            let db = &mut subject.neighborhood_database;
            let one_neighbor = db.add_node(make_node_record(1234, true)).unwrap();
            let another_neighbor = db.add_node(make_node_record(2345, true)).unwrap();
            let originate_only_neighbor = db.add_node(make_node_record(3456, false)).unwrap();
            let not_a_neighbor = db.add_node(make_node_record(4567, false)).unwrap();
            db.add_arbitrary_full_neighbor(subject_node.public_key(), &one_neighbor);
            db.add_arbitrary_full_neighbor(subject_node.public_key(), &another_neighbor);
            db.add_arbitrary_full_neighbor(subject_node.public_key(), &originate_only_neighbor);
            db.add_arbitrary_full_neighbor(&not_a_neighbor, &another_neighbor);
            let system = System::new("test");

            subject.handle_new_public_ip(NewPublicIp {
                new_ip: new_public_ip,
            });

            System::current().stop();
            system.run();
            (subject, one_neighbor, another_neighbor)
        };
        let db = &subject.neighborhood_database;
        assert_eq!(db.root().node_addr_opt().unwrap().ip_addr(), new_public_ip);
        TestLogHandler::new()
            .exists_log_containing("INFO: Neighborhood: Changed public IP from 1.2.3.4 to 4.3.2.1");
        let hopper_recording = hopper_recording_arc.lock().unwrap();
        assert_eq!(hopper_recording.len(), 2);
        let check_hopper_message = |idx: usize, expected_key: &PublicKey| {
            let pkg: &NoLookupIncipientCoresPackage = hopper_recording.get_record(idx);
            assert_eq!(&pkg.public_key, expected_key);
            let expected_node_addr = db
                .node_by_key(expected_key)
                .as_ref()
                .unwrap()
                .metadata
                .node_addr_opt
                .as_ref()
                .unwrap();
            assert_eq!(&pkg.node_addr, expected_node_addr);
            let payload = decodex::<MessageType>(
                &CryptDENull::from(expected_key, TEST_DEFAULT_CHAIN),
                &pkg.payload,
            )
            .unwrap();
            let expected_data = Gossip_0v1 {
                node_records: vec![GossipNodeRecord::from((
                    db,
                    subject_node.public_key(),
                    true,
                ))],
            };
            let expected_payload = MessageType::Gossip(VersionedData::new(
                &crate::sub_lib::migrations::gossip::MIGRATIONS,
                &expected_data,
            ));
            assert_eq!(payload, expected_payload);
        };
        check_hopper_message(0, &one_neighbor);
        check_hopper_message(1, &another_neighbor);
    }

    #[test]
    fn neighborhood_sends_from_gossip_producer_when_acceptance_introductions_are_not_provided() {
        init_test_logging();
        let subject_node = make_global_cryptde_node_record(5555, true); // 9e7p7un06eHs6frl5A
        let neighbor = make_node_record(1050, true);
        let mut subject = neighborhood_from_nodes(&subject_node, Some(&neighbor));
        let full_neighbor = make_node_record(1234, true);
        let half_neighbor = make_node_record(2345, true);
        subject
            .neighborhood_database
            .add_node(full_neighbor.clone())
            .unwrap();
        subject
            .neighborhood_database
            .add_node(half_neighbor.clone())
            .unwrap();
        subject
            .neighborhood_database
            .add_arbitrary_full_neighbor(subject_node.public_key(), full_neighbor.public_key());
        subject
            .neighborhood_database
            .add_arbitrary_half_neighbor(subject_node.public_key(), half_neighbor.public_key());
        let gossip_acceptor =
            GossipAcceptorMock::new().handle_result(GossipAcceptanceResult::Accepted);
        subject.gossip_acceptor_info_opt = Some(Either::Left(Box::new(gossip_acceptor)));
        let gossip = Gossip_0v1::new(vec![]);
        let produce_params_arc = Arc::new(Mutex::new(vec![]));
        let gossip_producer = GossipProducerMock::new()
            .produce_params(&produce_params_arc)
            .produce_result(Some(gossip.clone()))
            .produce_result(Some(gossip.clone()));
        subject.gossip_producer_opt = Some(Box::new(gossip_producer));
        let (hopper, _, hopper_recording_arc) = make_recorder();
        let peer_actors = peer_actors_builder().hopper(hopper).build();

        let system = System::new("");
        subject.hopper_opt = Some(peer_actors.hopper.from_hopper_client);

        subject.handle_gossip(
            Gossip_0v1::new(vec![]),
            SocketAddr::from_str("1.1.1.1:1111").unwrap(),
        );

        System::current().stop();
        system.run();

        let hopper_recording = hopper_recording_arc.lock().unwrap();
        let package_1 = hopper_recording.get_record::<IncipientCoresPackage>(0);
        let package_2 = hopper_recording.get_record::<IncipientCoresPackage>(1);
        assert_eq!(hopper_recording.len(), 2);
        fn digest(package: IncipientCoresPackage) -> (PublicKey, CryptData) {
            (
                package.route.next_hop(main_cryptde()).unwrap().public_key,
                package.payload,
            )
        }
        let digest_set = vec_to_set(vec![digest(package_1.clone()), digest(package_2.clone())]);
        assert_eq!(
            vec_to_set(vec![
                (
                    full_neighbor.public_key().clone(),
                    encodex(
                        main_cryptde(),
                        full_neighbor.public_key(),
                        &MessageType::Gossip(gossip.clone().into()),
                    )
                    .unwrap()
                ),
                (
                    half_neighbor.public_key().clone(),
                    encodex(
                        main_cryptde(),
                        half_neighbor.public_key(),
                        &MessageType::Gossip(gossip.into()),
                    )
                    .unwrap()
                ),
            ]),
            digest_set
        );
        let tlh = TestLogHandler::new();
        tlh.exists_log_containing(
            format!(
                "INFO: Neighborhood: Sending update Gossip about 0 Nodes to Node {}",
                full_neighbor.public_key()
            )
            .as_str(),
        );
        tlh.exists_log_containing(
            format!(
                "INFO: Neighborhood: Sending update Gossip about 0 Nodes to Node {}",
                half_neighbor.public_key()
            )
            .as_str(),
        );
        let key_as_str = format!("{}", main_cryptde().public_key());
        tlh.exists_log_containing(&format!("Sent Gossip: digraph db {{ \"src\" [label=\"Gossip From:\\n{}\\n5.5.5.5\"]; \"dest\" [label=\"Gossip To:\\nAQIDBA\\n1.2.3.4\"]; \"src\" -> \"dest\" [arrowhead=empty]; }}", &key_as_str[..8]));
        tlh.exists_log_containing(&format!("Sent Gossip: digraph db {{ \"src\" [label=\"Gossip From:\\n{}\\n5.5.5.5\"]; \"dest\" [label=\"Gossip To:\\nAgMEBQ\\n2.3.4.5\"]; \"src\" -> \"dest\" [arrowhead=empty]; }}", &key_as_str[..8]));
    }

    #[test]
    fn neighborhood_sends_no_gossip_when_target_does_not_exist() {
        let subject_node = make_global_cryptde_node_record(5555, true); // 9e7p7un06eHs6frl5A
                                                                        // This is ungossippable not because of any attribute of its own, but because the
                                                                        // GossipProducerMock is set to return None when ordered to target it.
        let ungossippable = make_node_record(1050, true);
        let mut subject = neighborhood_from_nodes(&subject_node, Some(&ungossippable));
        subject
            .neighborhood_database
            .add_node(ungossippable.clone())
            .unwrap();
        subject
            .neighborhood_database
            .add_arbitrary_full_neighbor(subject_node.public_key(), ungossippable.public_key());
        let gossip_acceptor =
            GossipAcceptorMock::new().handle_result(GossipAcceptanceResult::Accepted);
        subject.gossip_acceptor_info_opt = Some(Either::Left(Box::new(gossip_acceptor)));
        let produce_params_arc = Arc::new(Mutex::new(vec![]));
        let gossip_producer = GossipProducerMock::new()
            .produce_params(&produce_params_arc)
            .produce_result(None);
        subject.gossip_producer_opt = Some(Box::new(gossip_producer));
        let (hopper, _, hopper_recording_arc) = make_recorder();
        let peer_actors = peer_actors_builder().hopper(hopper).build();

        let system = System::new("");
        subject.hopper_opt = Some(peer_actors.hopper.from_hopper_client);

        subject.handle_gossip(
            Gossip_0v1::new(vec![]),
            SocketAddr::from_str("1.1.1.1:1111").unwrap(),
        );

        System::current().stop();
        system.run();

        let hopper_recording = hopper_recording_arc.lock().unwrap();
        assert_eq!(hopper_recording.len(), 0);
    }

    #[test]
    fn neighborhood_sends_only_relay_gossip_when_gossip_acceptor_relays() {
        let subject_node = make_global_cryptde_node_record(5555, true); // 9e7p7un06eHs6frl5A
        let mut subject =
            neighborhood_from_nodes(&subject_node, Some(&make_node_record(1111, true)));
        let debut_node = make_node_record(1234, true);
        let debut_gossip = GossipBuilder::new(&subject.neighborhood_database)
            .node(subject_node.public_key(), true)
            .build();
        let gossip_acceptor =
            GossipAcceptorMock::new().handle_result(GossipAcceptanceResult::Reply(
                debut_gossip.clone(),
                debut_node.public_key().clone(),
                debut_node.node_addr_opt().unwrap(),
            ));
        subject.gossip_acceptor_info_opt = Some(Either::Left(Box::new(gossip_acceptor)));
        let (hopper, _, hopper_recording_arc) = make_recorder();
        let peer_actors = peer_actors_builder().hopper(hopper).build();
        let system = System::new("");
        subject.hopper_no_lookup_sub_opt = Some(peer_actors.hopper.from_hopper_client_no_lookup);
        let gossip_source = SocketAddr::from_str("8.6.5.4:8654").unwrap();

        subject.handle_gossip(
            // In real life this would be Relay Gossip from gossip_source to debut_node.
            Gossip_0v1::new(vec![]),
            gossip_source,
        );

        System::current().stop();
        system.run();
        let hopper_recording = hopper_recording_arc.lock().unwrap();
        let package = hopper_recording.get_record::<NoLookupIncipientCoresPackage>(0);
        assert_eq!(1, hopper_recording.len());
        assert_eq!(debut_node.public_key(), &package.public_key);
        assert_eq!(
            debut_node.node_addr_opt().as_ref().unwrap(),
            &package.node_addr
        );
        assert_eq!(
            debut_gossip,
            match decodex::<MessageType>(
                &CryptDENull::from(debut_node.public_key(), TEST_DEFAULT_CHAIN),
                &package.payload,
            ) {
                Ok(MessageType::Gossip(vd)) => Gossip_0v1::try_from(vd).unwrap(),
                x => panic!("Expected Gossip, but found {:?}", x),
            },
        );
    }

    #[test]
    fn neighborhood_sends_no_gossip_when_gossip_acceptor_ignores() {
        let subject_node = make_global_cryptde_node_record(5555, true); // 9e7p7un06eHs6frl5A
        let neighbor = make_node_record(1111, true);
        let mut subject = neighborhood_from_nodes(&subject_node, Some(&neighbor));
        let gossip_acceptor =
            GossipAcceptorMock::new().handle_result(GossipAcceptanceResult::Ignored);
        subject.gossip_acceptor_info_opt = Some(Either::Left(Box::new(gossip_acceptor)));
        let subject_node = subject.neighborhood_database.root().clone();
        let (hopper, _, hopper_recording_arc) = make_recorder();
        let peer_actors = peer_actors_builder().hopper(hopper).build();
        let system = System::new("");
        subject.hopper_opt = Some(peer_actors.hopper.from_hopper_client);

        subject.handle_gossip(
            Gossip_0v1::new(vec![]),
            subject_node.node_addr_opt().unwrap().into(),
        );

        System::current().stop();
        system.run();
        let hopper_recording = hopper_recording_arc.lock().unwrap();
        assert_eq!(0, hopper_recording.len());
    }

    #[test]
    fn neighborhood_complains_about_inability_to_ban_when_gossip_acceptor_requests_it() {
        init_test_logging();
        let subject_node = make_global_cryptde_node_record(5555, true); // 9e7p7un06eHs6frl5A
        let neighbor = make_node_record(1111, true);
        let mut subject = neighborhood_from_nodes(&subject_node, Some(&neighbor));
        let gossip_acceptor = GossipAcceptorMock::new()
            .handle_result(GossipAcceptanceResult::Ban("Bad guy".to_string()));
        subject.gossip_acceptor_info_opt = Some(Either::Left(Box::new(gossip_acceptor)));
        let subject_node = subject.neighborhood_database.root().clone();
        let (hopper, _, hopper_recording_arc) = make_recorder();
        let peer_actors = peer_actors_builder().hopper(hopper).build();
        let system = System::new("");
        subject.hopper_opt = Some(peer_actors.hopper.from_hopper_client);

        subject.handle_gossip(
            Gossip_0v1::new(vec![]),
            subject_node.node_addr_opt().unwrap().into(),
        );

        System::current().stop();
        system.run();
        let hopper_recording = hopper_recording_arc.lock().unwrap();
        assert_eq!(0, hopper_recording.len());
        let tlh = TestLogHandler::new();
        tlh.exists_log_containing("WARN: Neighborhood: Malefactor detected at 5.5.5.5:5555, but malefactor bans not yet implemented; ignoring: Bad guy");
    }

    #[test]
    fn neighborhood_does_not_accept_gossip_if_a_record_is_non_deserializable() {
        init_test_logging();
        let mut subject = make_standard_subject();
        let gossip_acceptor = GossipAcceptorMock::new();
        subject.gossip_acceptor_info_opt = Some(Either::Left(Box::new(gossip_acceptor)));
        let db = &mut subject.neighborhood_database;
        let one_node_key = &db.add_node(make_node_record(2222, true)).unwrap();
        let another_node_key = &db.add_node(make_node_record(3333, true)).unwrap();
        let mut gossip = GossipBuilder::new(db)
            .node(one_node_key, true)
            .node(another_node_key, false)
            .build();
        gossip.node_records[1].signed_data = PlainData::new(&[1, 2, 3, 4]); // corrupt second record
        let gossip_source = SocketAddr::from_str("1.2.3.4:1234").unwrap();

        subject.handle_gossip(gossip, gossip_source);

        // No panic means that subject didn't try to invoke the GossipAcceptorMock: test passes!
        TestLogHandler::new().exists_log_containing(&format!(
            "ERROR: Neighborhood: Received non-deserializable Gossip from {}",
            gossip_source
        ));
    }

    #[test]
    fn neighborhood_does_not_accept_gossip_if_a_record_signature_is_invalid() {
        init_test_logging();
        let mut subject = make_standard_subject();
        let gossip_acceptor = GossipAcceptorMock::new();
        subject.gossip_acceptor_info_opt = Some(Either::Left(Box::new(gossip_acceptor)));
        let db = &mut subject.neighborhood_database;
        let one_node_key = &db.add_node(make_node_record(2222, true)).unwrap();
        let another_node_key = &db.add_node(make_node_record(3333, true)).unwrap();
        let mut gossip = GossipBuilder::new(db)
            .node(one_node_key, true)
            .node(another_node_key, false)
            .build();
        gossip.node_records[1].signature = CryptData::new(&[1, 2, 3, 4]); // corrupt second record
        let gossip_source = SocketAddr::from_str("1.2.3.4:1234").unwrap();

        subject.handle_gossip(gossip, gossip_source);

        // No panic means that subject didn't try to invoke the GossipAcceptorMock: test passes!
        TestLogHandler::new().exists_log_containing(&format!(
            "ERROR: Neighborhood: Received Gossip with invalid signature from {}",
            gossip_source
        ));
    }

    #[test]
    fn neighborhood_logs_received_gossip_in_dot_graph_format() {
        init_test_logging();
        let cryptde = main_cryptde();
        let this_node = NodeRecord::new_for_tests(
            &cryptde.public_key(),
            Some(&NodeAddr::new(
                &IpAddr::from_str("5.4.3.2").unwrap(),
                &[1234],
            )),
            100,
            true,
            true,
        );
        let mut db = db_from_node(&this_node);
        let far_neighbor = make_node_record(1324, true);
        let gossip_neighbor = make_node_record(4657, true);
        db.add_node(far_neighbor.clone()).unwrap();
        db.add_node(gossip_neighbor.clone()).unwrap();
        db.add_arbitrary_full_neighbor(this_node.public_key(), gossip_neighbor.public_key());
        db.add_arbitrary_full_neighbor(gossip_neighbor.public_key(), far_neighbor.public_key());
        db.node_by_key_mut(this_node.public_key()).unwrap().resign();
        db.node_by_key_mut(gossip_neighbor.public_key())
            .unwrap()
            .resign();
        db.node_by_key_mut(far_neighbor.public_key())
            .unwrap()
            .resign();

        let gossip = GossipBuilder::new(&db)
            .node(gossip_neighbor.public_key(), true)
            .node(far_neighbor.public_key(), false)
            .build();
        let cores_package = ExpiredCoresPackage {
            immediate_neighbor: SocketAddr::from_str("1.2.3.4:1234").unwrap(),
            paying_wallet: Some(make_paying_wallet(b"consuming")),
            remaining_route: make_meaningless_route(),
            payload: gossip,
            payload_len: 0,
        };
        let hopper = Recorder::new();
        let this_node_inside = this_node.clone();
        thread::spawn(move || {
            let system = System::new("");
            let subject = Neighborhood::new(
                cryptde,
                &bc_from_nc_plus(
                    NeighborhoodConfig {
                        mode: NeighborhoodMode::Standard(
                            this_node_inside.node_addr_opt().unwrap(),
                            vec![],
                            rate_pack(100),
                        ),
                    },
                    this_node_inside.earning_wallet(),
                    None,
                    "neighborhood_logs_received_gossip_in_dot_graph_format",
                ),
            );

            let addr: Addr<Neighborhood> = subject.start();
            let peer_actors = peer_actors_builder().hopper(hopper).build();
            addr.try_send(BindMessage { peer_actors }).unwrap();
            addr.try_send(make_meaningless_pool_bind_message()).unwrap();

            let sub = addr.recipient::<ExpiredCoresPackage<Gossip_0v1>>();
            sub.try_send(cores_package).unwrap();

            system.run();
        });
        let tlh = TestLogHandler::new();
        tlh.await_log_containing(
            &format!("\"BAYFBw\" [label=\"AR v0\\nBAYFBw\\n4.6.5.7:4657\"];"),
            5000,
        );

        tlh.exists_log_containing("Received Gossip: digraph db { ");
        tlh.exists_log_containing("\"AQMCBA\" [label=\"AR v0\\nAQMCBA\"];");
        tlh.exists_log_containing(&format!(
            "\"{}\" [label=\"{}\"] [shape=none];",
            cryptde.public_key(),
            &format!("{}", cryptde.public_key())[..8]
        ));
        tlh.exists_log_containing(&format!("\"BAYFBw\" -> \"{}\";", cryptde.public_key()));
        tlh.exists_log_containing("\"AQMCBA\" -> \"BAYFBw\";");
        tlh.exists_log_containing("\"BAYFBw\" -> \"AQMCBA\";");
    }

    #[test]
    fn node_gossips_to_neighbors_on_startup() {
        init_test_logging();
        let data_dir = ensure_node_home_directory_exists(
            "neighborhood/mod",
            "node_gossips_to_neighbors_on_startup",
        );
        {
            let _ = DbInitializerReal::default()
                .initialize(&data_dir, DbInitializationConfig::test_default())
                .unwrap();
        }
        let cryptde: &dyn CryptDE = main_cryptde();
        let debut_target = NodeDescriptor::try_from((
            main_cryptde(), // Used to provide default cryptde
            "masq://polygon-mumbai:AQIDBA@1.2.3.4:1234",
        ))
        .unwrap();
        let (hopper, _, hopper_recording) = make_recorder();
        let mut subject = Neighborhood::new(
            cryptde,
            &bc_from_nc_plus(
                NeighborhoodConfig {
                    mode: NeighborhoodMode::Standard(
                        NodeAddr::new(&IpAddr::from_str("5.4.3.2").unwrap(), &[1234]),
                        vec![debut_target.clone()],
                        rate_pack(100),
                    ),
                },
                NodeRecord::earning_wallet_from_key(&cryptde.public_key()),
                NodeRecord::consuming_wallet_from_key(&cryptde.public_key()),
                "node_gossips_to_neighbors_on_startup",
            ),
        );
        subject.data_directory = data_dir;
        subject.logger = Logger::new("node_gossips_to_neighbors_on_startup");
        let this_node = subject.neighborhood_database.root().clone();
        let system = System::new("node_gossips_to_neighbors_on_startup");
        let addr: Addr<Neighborhood> = subject.start();
        let peer_actors = peer_actors_builder().hopper(hopper).build();
        addr.try_send(BindMessage { peer_actors }).unwrap();
        addr.try_send(make_meaningless_pool_bind_message()).unwrap();
        let sub = addr.recipient::<StartMessage>();

        sub.try_send(StartMessage {}).unwrap();

        System::current().stop();
        system.run();
        let locked_recording = hopper_recording.lock().unwrap();
        let package_ref: &NoLookupIncipientCoresPackage = locked_recording.get_record(0);
        let neighbor_node_cryptde =
            CryptDENull::from(&debut_target.encryption_public_key, TEST_DEFAULT_CHAIN);
        let decrypted_payload = neighbor_node_cryptde.decode(&package_ref.payload).unwrap();
        let gossip = match serde_cbor::de::from_slice(decrypted_payload.as_slice()).unwrap() {
            MessageType::Gossip(vd) => Gossip_0v1::try_from(vd).unwrap(),
            x => panic!("Should have been MessageType::Gossip, but was {:?}", x),
        };
        let temp_db = db_from_node(&this_node);
        let expected_gnr = GossipNodeRecord::from((&temp_db, this_node.public_key(), true));
        assert_contains(&gossip.node_records, &expected_gnr);
        assert_eq!(1, gossip.node_records.len());
        TestLogHandler::new().exists_log_containing(&format!(
            "DEBUG: node_gossips_to_neighbors_on_startup: Debut Gossip sent to {:?}",
            debut_target
        ));
    }

    /*
            Database, where we'll fail to make a three-hop route to C after removing A:

                 NN--------+
                 NN        |
                 |         |
                 v         v
                 AA-->BB-->CC
                 AA<--BB<--CC

                 after removing A as neighbor...

                 NN--------+
                 NN        |
                           |
                           v
                 AA-->BB-->CC
                 AA<--BB<--CC

            Tests will be written from the viewpoint of N.
    */

    #[test]
    fn neighborhood_removes_neighbor_when_directed_to() {
        let system = System::new("neighborhood_removes_neighbor_when_directed_to");
        let hopper = Recorder::new();
        let mut subject = make_standard_subject();
        let n = &subject.neighborhood_database.root().clone();
        let a = &make_node_record(3456, true);
        let b = &make_node_record(4567, false);
        let c = &make_node_record(5678, true);
        {
            let db = &mut subject.neighborhood_database;
            db.add_node(a.clone()).unwrap();
            db.add_node(b.clone()).unwrap();
            db.add_node(c.clone()).unwrap();
            let mut single_edge = |a: &NodeRecord, b: &NodeRecord| {
                db.add_arbitrary_half_neighbor(a.public_key(), b.public_key())
            };
            single_edge(n, a);
            single_edge(n, c);
            single_edge(a, b);
            single_edge(b, a);
            single_edge(b, c);
            single_edge(c, b);
        }

        let addr: Addr<Neighborhood> = subject.start();
        let peer_actors = peer_actors_builder().hopper(hopper).build();
        addr.try_send(BindMessage { peer_actors }).unwrap();
        addr.try_send(make_meaningless_pool_bind_message()).unwrap();

        addr.try_send(RemoveNeighborMessage {
            public_key: a.public_key().clone(),
        })
        .unwrap();

        let three_hop_route_request = RouteQueryMessage {
            target_key_opt: Some(c.public_key().clone()),
            target_component: Component::ProxyClient,
            minimum_hop_count: 3,
            return_component_opt: None,
            payload_size: 10000,
            hostname_opt: None,
        };
        let unsuccessful_three_hop_route = addr.send(three_hop_route_request);
        let public_key_query = addr.send(NodeQueryMessage::PublicKey(a.public_key().clone()));
        let failed_ip_address_query = addr.send(NodeQueryMessage::IpAddress(
            a.node_addr_opt().unwrap().ip_addr(),
        ));
        System::current().stop_with_code(0);

        system.run();
        assert_eq!(None, unsuccessful_three_hop_route.wait().unwrap());
        assert_eq!(
            a.public_key(),
            &public_key_query.wait().unwrap().unwrap().public_key
        );
        assert_eq!(None, failed_ip_address_query.wait().unwrap());
    }

    fn node_record_to_neighbor_config(node_record_ref: &NodeRecord) -> NodeDescriptor {
        let cryptde: &dyn CryptDE = main_cryptde();
        NodeDescriptor::from((node_record_ref, Chain::PolyMumbai, cryptde))
    }

    #[test]
    fn neighborhood_sends_node_query_response_with_none_when_initially_configured_with_no_data() {
        let cryptde = main_cryptde();
        let (recorder, awaiter, recording_arc) = make_recorder();
        thread::spawn(move || {
            let system = System::new("responds_with_none_when_initially_configured_with_no_data");

            let addr: Addr<Recorder> = recorder.start();
            let recipient: Recipient<DispatcherNodeQueryResponse> =
                addr.recipient::<DispatcherNodeQueryResponse>();

            let subject = make_standard_subject();
            let addr: Addr<Neighborhood> = subject.start();
            let sub: Recipient<DispatcherNodeQueryMessage> =
                addr.recipient::<DispatcherNodeQueryMessage>();

            sub.try_send(DispatcherNodeQueryMessage {
                query: NodeQueryMessage::PublicKey(PublicKey::new(&b"booga"[..])),
                context: TransmitDataMsg {
                    endpoint: Endpoint::Key(cryptde.public_key().clone()),
                    last_data: false,
                    sequence_number: None,
                    data: Vec::new(),
                },
                recipient,
            })
            .unwrap();

            system.run();
        });

        awaiter.await_message_count(1);
        let recording = recording_arc.lock().unwrap();
        assert_eq!(recording.len(), 1);
        let message = recording.get_record::<DispatcherNodeQueryResponse>(0);
        assert_eq!(message.result, None);
    }

    #[test]
    fn neighborhood_sends_node_query_response_with_none_when_key_query_matches_no_configured_data()
    {
        let cryptde: &dyn CryptDE = main_cryptde();
        let earning_wallet = make_wallet("earning");
        let consuming_wallet = Some(make_paying_wallet(b"consuming"));
        let (recorder, awaiter, recording_arc) = make_recorder();
        thread::spawn(move || {
            let system = System::new("neighborhood_sends_node_query_response_with_none_when_key_query_matches_no_configured_data");
            let addr: Addr<Recorder> = recorder.start();
            let recipient: Recipient<DispatcherNodeQueryResponse> =
                addr.recipient::<DispatcherNodeQueryResponse>();

            let subject = Neighborhood::new(
                cryptde,
                &bc_from_nc_plus(
                    NeighborhoodConfig {
                        mode: NeighborhoodMode::Standard(
                            NodeAddr::new(&IpAddr::from_str("5.4.3.2").unwrap(), &[5678]),
                            vec![NodeDescriptor::from((
                                &PublicKey::new(&b"booga"[..]),
                                &NodeAddr::new(
                                    &IpAddr::from_str("1.2.3.4").unwrap(),
                                    &[1234, 2345],
                                ),
                                Chain::PolyMumbai,
                                cryptde,
                            ))],
                            rate_pack(100),
                        ),
                    },
                    earning_wallet.clone(),
                    consuming_wallet.clone(),
                    "neighborhood_sends_node_query_response_with_none_when_key_query_matches_no_configured_data"
                ),
            );
            let addr: Addr<Neighborhood> = subject.start();
            let sub: Recipient<DispatcherNodeQueryMessage> =
                addr.recipient::<DispatcherNodeQueryMessage>();

            sub.try_send(DispatcherNodeQueryMessage {
                query: NodeQueryMessage::PublicKey(PublicKey::new(&b"blah"[..])),
                context: TransmitDataMsg {
                    endpoint: Endpoint::Key(cryptde.public_key().clone()),
                    last_data: false,
                    sequence_number: None,
                    data: Vec::new(),
                },
                recipient,
            })
            .unwrap();

            system.run();
        });

        awaiter.await_message_count(1);
        let recording = recording_arc.lock().unwrap();
        assert_eq!(recording.len(), 1);
        let message = recording.get_record::<DispatcherNodeQueryResponse>(0);
        assert_eq!(message.result, None);
    }

    #[test]
    fn neighborhood_sends_node_query_response_with_result_when_key_query_matches_configured_data() {
        let cryptde = main_cryptde();
        let earning_wallet = make_wallet("earning");
        let consuming_wallet = Some(make_paying_wallet(b"consuming"));
        let (recorder, awaiter, recording_arc) = make_recorder();
        let one_neighbor = make_node_record(2345, true);
        let another_neighbor = make_node_record(3456, true);
        let another_neighbor_a = another_neighbor.clone();
        let context = TransmitDataMsg {
            endpoint: Endpoint::Key(cryptde.public_key().clone()),
            last_data: false,
            sequence_number: None,
            data: Vec::new(),
        };
        let context_a = context.clone();
        thread::spawn(move || {
            let system = System::new("neighborhood_sends_node_query_response_with_result_when_key_query_matches_configured_data");
            let addr: Addr<Recorder> = recorder.start();
            let recipient = addr.recipient::<DispatcherNodeQueryResponse>();
            let mut subject = Neighborhood::new(
                cryptde,
                &bc_from_nc_plus(
                    NeighborhoodConfig {
                        mode: NeighborhoodMode::Standard(
                            NodeAddr::new(&IpAddr::from_str("5.4.3.2").unwrap(), &[5678]),
                            vec![node_record_to_neighbor_config(&one_neighbor)],
                            rate_pack(100),
                        ),
                    },
                    earning_wallet.clone(),
                    consuming_wallet.clone(),
                    "neighborhood_sends_node_query_response_with_result_when_key_query_matches_configured_data"
                ),
            );
            subject
                .neighborhood_database
                .add_node(another_neighbor.clone())
                .unwrap();
            let addr: Addr<Neighborhood> = subject.start();
            let sub: Recipient<DispatcherNodeQueryMessage> =
                addr.recipient::<DispatcherNodeQueryMessage>();

            sub.try_send(DispatcherNodeQueryMessage {
                query: NodeQueryMessage::PublicKey(another_neighbor.public_key().clone()),
                context,
                recipient,
            })
            .unwrap();

            system.run();
        });

        awaiter.await_message_count(1);
        let message = Recording::get::<DispatcherNodeQueryResponse>(&recording_arc, 0);
        assert_eq!(
            message.result.unwrap(),
            NodeQueryResponseMetadata::new(
                another_neighbor_a.public_key().clone(),
                Some(another_neighbor_a.node_addr_opt().unwrap().clone()),
                another_neighbor_a.rate_pack().clone(),
            )
        );
        assert_eq!(message.context, context_a);
    }

    #[test]
    fn neighborhood_sends_node_query_response_with_none_when_ip_address_query_matches_no_configured_data(
    ) {
        let cryptde: &dyn CryptDE = main_cryptde();
        let earning_wallet = make_wallet("earning");
        let consuming_wallet = Some(make_paying_wallet(b"consuming"));
        let (recorder, awaiter, recording_arc) = make_recorder();
        thread::spawn(move || {
            let system = System::new("neighborhood_sends_node_query_response_with_none_when_ip_address_query_matches_no_configured_data");
            let addr: Addr<Recorder> = recorder.start();
            let recipient: Recipient<DispatcherNodeQueryResponse> =
                addr.recipient::<DispatcherNodeQueryResponse>();
            let subject = Neighborhood::new(
                cryptde,
                &bc_from_nc_plus(
                    NeighborhoodConfig {
                        mode: NeighborhoodMode::Standard(
                            NodeAddr::new(&IpAddr::from_str("5.4.3.2").unwrap(), &[5678]),
                            vec![NodeDescriptor::from((
                                &PublicKey::new(&b"booga"[..]),
                                &NodeAddr::new(
                                    &IpAddr::from_str("1.2.3.4").unwrap(),
                                    &[1234, 2345],
                                ),
                                Chain::PolyMumbai,
                                cryptde,
                            ))],
                            rate_pack(100),
                        ),
                    },
                    earning_wallet.clone(),
                    consuming_wallet.clone(),
                    "neighborhood_sends_node_query_response_with_none_when_ip_address_query_matches_no_configured_data"
                ),
            );
            let addr: Addr<Neighborhood> = subject.start();
            let sub: Recipient<DispatcherNodeQueryMessage> =
                addr.recipient::<DispatcherNodeQueryMessage>();

            sub.try_send(DispatcherNodeQueryMessage {
                query: NodeQueryMessage::IpAddress(IpAddr::from_str("2.3.4.5").unwrap()),
                context: TransmitDataMsg {
                    endpoint: Endpoint::Key(cryptde.public_key().clone()),
                    last_data: false,
                    sequence_number: None,
                    data: Vec::new(),
                },
                recipient,
            })
            .unwrap();

            system.run();
        });

        awaiter.await_message_count(1);
        let recording = recording_arc.lock().unwrap();
        assert_eq!(recording.len(), 1);
        let message = recording.get_record::<DispatcherNodeQueryResponse>(0);
        assert_eq!(message.result, None);
    }

    #[test]
    fn neighborhood_sends_node_query_response_with_result_when_ip_address_query_matches_configured_data(
    ) {
        let cryptde: &dyn CryptDE = main_cryptde();
        let (recorder, awaiter, recording_arc) = make_recorder();
        let node_record = make_node_record(1234, true);
        let another_node_record = make_node_record(2345, true);
        let another_node_record_a = another_node_record.clone();
        let context = TransmitDataMsg {
            endpoint: Endpoint::Key(cryptde.public_key().clone()),
            last_data: false,
            sequence_number: None,
            data: Vec::new(),
        };
        let context_a = context.clone();
        thread::spawn(move || {
            let system = System::new("neighborhood_sends_node_query_response_with_result_when_ip_address_query_matches_configured_data");
            let addr: Addr<Recorder> = recorder.start();
            let recipient: Recipient<DispatcherNodeQueryResponse> =
                addr.recipient::<DispatcherNodeQueryResponse>();
            let config = bc_from_nc_plus(
                NeighborhoodConfig {
                    mode: NeighborhoodMode::Standard(
                        node_record.node_addr_opt().unwrap(),
                        vec![NodeDescriptor::from((
                            &node_record,
                            Chain::PolyMumbai,
                            cryptde,
                        ))],
                        rate_pack(100),
                    ),
                },
                node_record.earning_wallet(),
                None,
                "neighborhood_sends_node_query_response_with_result_when_ip_address_query_matches_configured_data"
            );
            let mut subject = Neighborhood::new(cryptde, &config);
            subject
                .neighborhood_database
                .add_node(another_node_record_a)
                .unwrap();
            let addr: Addr<Neighborhood> = subject.start();
            let sub: Recipient<DispatcherNodeQueryMessage> =
                addr.recipient::<DispatcherNodeQueryMessage>();

            sub.try_send(DispatcherNodeQueryMessage {
                query: NodeQueryMessage::IpAddress(IpAddr::from_str("2.3.4.5").unwrap()),
                context,
                recipient,
            })
            .unwrap();

            system.run();
        });

        awaiter.await_message_count(1);
        let message = Recording::get::<DispatcherNodeQueryResponse>(&recording_arc, 0);

        assert_eq!(
            message.result.unwrap(),
            NodeQueryResponseMetadata::new(
                another_node_record.public_key().clone(),
                Some(another_node_record.node_addr_opt().unwrap().clone()),
                another_node_record.rate_pack().clone(),
            )
        );
        assert_eq!(message.context, context_a);
    }

    #[test]
    fn make_round_trip_route_returns_error_when_no_non_next_door_neighbor_found() {
        // Make a triangle of Nodes
        let one_next_door_neighbor = make_node_record(3333, true);
        let another_next_door_neighbor = make_node_record(4444, true);
        let subject_node = make_global_cryptde_node_record(5555, true); // 9e7p7un06eHs6frl5A
        let mut subject = neighborhood_from_nodes(&subject_node, Some(&one_next_door_neighbor));

        subject
            .neighborhood_database
            .add_node(one_next_door_neighbor.clone())
            .unwrap();
        subject
            .neighborhood_database
            .add_node(another_next_door_neighbor.clone())
            .unwrap();

        subject.neighborhood_database.add_arbitrary_full_neighbor(
            subject_node.public_key(),
            one_next_door_neighbor.public_key(),
        );
        subject.neighborhood_database.add_arbitrary_full_neighbor(
            subject_node.public_key(),
            another_next_door_neighbor.public_key(),
        );
        subject.neighborhood_database.add_arbitrary_full_neighbor(
            one_next_door_neighbor.public_key(),
            another_next_door_neighbor.public_key(),
        );

        let minimum_hop_count = 2;

        let result = subject.make_round_trip_route(RouteQueryMessage {
            target_key_opt: None,
            target_component: Component::ProxyClient,
            minimum_hop_count,
            return_component_opt: Some(Component::ProxyServer),
            payload_size: 10000,
            hostname_opt: None,
        });

        assert_eq!(
            Err(format!(
                "Couldn't find any routes: at least {}-hop from {} to ProxyClient at Unknown",
                minimum_hop_count,
                main_cryptde().public_key()
            )),
            result
        );
    }

    #[test]
    fn make_round_trip_succeeds_when_it_finds_non_next_door_neighbor_exit_node() {
        let next_door_neighbor = make_node_record(3333, true);
        let exit_node = make_node_record(5, false);

        let subject_node = make_global_cryptde_node_record(666, true); // 9e7p7un06eHs6frl5A
        let mut subject = neighborhood_from_nodes(&subject_node, Some(&next_door_neighbor));

        subject
            .neighborhood_database
            .add_node(next_door_neighbor.clone())
            .unwrap();
        subject
            .neighborhood_database
            .add_node(exit_node.clone())
            .unwrap();

        subject.neighborhood_database.add_arbitrary_full_neighbor(
            subject_node.public_key(),
            next_door_neighbor.public_key(),
        );

        subject
            .neighborhood_database
            .add_arbitrary_full_neighbor(next_door_neighbor.public_key(), exit_node.public_key());

        let minimum_hop_count = 2;

        let result = subject.make_round_trip_route(RouteQueryMessage {
            target_key_opt: None,
            target_component: Component::ProxyClient,
            minimum_hop_count,
            return_component_opt: Some(Component::ProxyServer),
            payload_size: 10000,
            hostname_opt: None,
        });

        let next_door_neighbor_cryptde =
            CryptDENull::from(&next_door_neighbor.public_key(), TEST_DEFAULT_CHAIN);
        let exit_node_cryptde = CryptDENull::from(&exit_node.public_key(), TEST_DEFAULT_CHAIN);

        let hops = result.clone().unwrap().route.hops;
        let actual_keys: Vec<PublicKey> = match hops.as_slice() {
            [hop, exit, hop_back, origin, empty, _accounting] => vec![
                decodex::<LiveHop>(main_cryptde(), hop)
                    .expect("hop")
                    .public_key,
                decodex::<LiveHop>(&next_door_neighbor_cryptde, exit)
                    .expect("exit")
                    .public_key,
                decodex::<LiveHop>(&exit_node_cryptde, hop_back)
                    .expect("hop_back")
                    .public_key,
                decodex::<LiveHop>(&next_door_neighbor_cryptde, origin)
                    .expect("origin")
                    .public_key,
                decodex::<LiveHop>(main_cryptde(), empty)
                    .expect("empty")
                    .public_key,
            ],
            l => panic!("our match is wrong, real size is {}, {:?}", l.len(), l),
        };
        let expected_public_keys = vec![
            next_door_neighbor.public_key().clone(),
            exit_node.public_key().clone(),
            next_door_neighbor.public_key().clone(),
            subject_node.public_key().clone(),
            PublicKey::new(b""),
        ];
        assert_eq!(expected_public_keys, actual_keys);
    }

    /*
           For the next two tests, the database looks like this:

           +---A---+
           |       |
           O       X
           |       |
           +---B---+

           O is the originating Node, X is the exit Node. Minimum hop count is 2.
           Node A offers low per-packet rates and high per-byte rates; Node B offers
           low per-byte rates and high per-packet rates. Small packets should prefer
           route O -> A -> X -> A -> O; large packets should prefer route
           O -> B -> X -> B -> O.
    */

    #[test]
    fn handle_route_query_message_prefers_low_service_fees_for_small_packet() {
        check_fee_preference(100, true);
    }

    #[test]
    fn handle_route_query_message_prefers_low_byte_fees_for_large_packet() {
        check_fee_preference(100_000, false);
    }

    fn check_fee_preference(payload_size: usize, a_not_b: bool) {
        let mut subject = make_standard_subject();
        let db = &mut subject.neighborhood_database;
        let o = &db.root().public_key().clone();
        let a = &db.add_node(make_node_record(2345, true)).unwrap();
        let b = &db.add_node(make_node_record(3456, true)).unwrap();
        let x = &db.add_node(make_node_record(4567, true)).unwrap();
        db.add_arbitrary_full_neighbor(o, a);
        db.add_arbitrary_full_neighbor(a, x);
        db.add_arbitrary_full_neighbor(x, b);
        db.add_arbitrary_full_neighbor(b, o);
        // Small packages should prefer A
        db.node_by_key_mut(a).unwrap().inner.rate_pack = RatePack {
            routing_byte_rate: 100,     // high
            routing_service_rate: 1000, // low
            exit_byte_rate: 0,
            exit_service_rate: 0,
        };
        // Large packages should prefer B
        db.node_by_key_mut(b).unwrap().inner.rate_pack = RatePack {
            routing_byte_rate: 1,          // low
            routing_service_rate: 100_000, // high
            exit_byte_rate: 0,
            exit_service_rate: 0,
        };

        let response = subject
            .handle_route_query_message(RouteQueryMessage {
                target_key_opt: Some(x.clone()),
                target_component: Component::ProxyClient,
                minimum_hop_count: 2,
                return_component_opt: Some(Component::ProxyServer),
                payload_size,
                hostname_opt: None,
            })
            .unwrap();

        let (over, back) = match response.expected_services {
            ExpectedServices::OneWay(_) => panic!("Expecting RoundTrip"),
            ExpectedServices::RoundTrip(o, b, _) => (o[1].clone(), b[1].clone()),
        };
        let extract_key = |es: ExpectedService| match es {
            ExpectedService::Routing(pk, _, _) => pk,
            x => panic!("Expecting Routing, found {:?}", x),
        };
        let expected_relay_key = if a_not_b { a.clone() } else { b.clone() };
        assert_eq!(extract_key(over), expected_relay_key);
        // All response packages are "large," so they'll all want B on the way back.
        assert_eq!(extract_key(back), *b);
    }

    #[test]
    fn node_record_metadata_message_is_handled_properly() {
        init_test_logging();
        let subject_node = make_global_cryptde_node_record(1345, true);
        let public_key = PublicKey::from(&b"exit_node"[..]);
        let node_record = NodeRecord::new(
            &public_key,
            make_wallet("earning"),
            rate_pack(100),
            true,
            true,
            0,
            main_cryptde(),
        );
        let unreachable_host = String::from("facebook.com");
        let mut subject = neighborhood_from_nodes(&subject_node, None);
        let _ = subject.neighborhood_database.add_node(node_record);
        let addr = subject.start();
        let system = System::new("test");

        let _ = addr.try_send(NodeRecordMetadataMessage {
            public_key: public_key.clone(),
            metadata_change: NRMetadataChange::AddUnreachableHost {
                hostname: unreachable_host.clone(),
            },
        });

        let assertions = Box::new(move |actor: &mut Neighborhood| {
            let updated_node_record = actor
                .neighborhood_database
                .node_by_key(&public_key)
                .unwrap();
            assert!(updated_node_record
                .metadata
                .unreachable_hosts
                .contains(&unreachable_host));
            TestLogHandler::new().exists_log_matching(&format!(
                "DEBUG: Neighborhood: Marking host facebook.com unreachable for the Node with public key 0x657869745F6E6F6465"
            ));
        });
        addr.try_send(AssertionsMessage { assertions }).unwrap();
        System::current().stop();
        assert_eq!(system.run(), 0);
    }

    #[test]
    #[should_panic(
        expected = "Neighborhood should never get ShutdownStreamMsg about non-clandestine stream"
    )]
    fn handle_stream_shutdown_complains_about_non_clandestine_message() {
        let subject_node = make_global_cryptde_node_record(1345, true);
        let mut subject = neighborhood_from_nodes(&subject_node, None);

        subject.handle_stream_shutdown_msg(StreamShutdownMsg {
            peer_addr: SocketAddr::from_str("1.2.3.4:5678").unwrap(),
            stream_type: RemovedStreamType::NonClandestine(NonClandestineAttributes {
                reception_port: TLS_PORT,
                sequence_number: 1234,
            }),
            report_to_counterpart: false,
        });
    }

    #[test]
    fn handle_stream_shutdown_handles_socket_addr_with_unknown_ip() {
        init_test_logging();
        let (hopper, _, hopper_recording_arc) = make_recorder();
        let system = System::new("test");
        let unrecognized_node = make_node_record(3123, true);
        let unrecognized_node_addr = unrecognized_node.node_addr_opt().unwrap();
        let unrecognized_socket_addr = SocketAddr::new(
            unrecognized_node_addr.ip_addr(),
            unrecognized_node_addr.ports()[0],
        );
        let subject_node = make_global_cryptde_node_record(1345, true);
        let mut subject = neighborhood_from_nodes(&subject_node, None);
        let peer_actors = peer_actors_builder().hopper(hopper).build();
        subject.hopper_opt = Some(peer_actors.hopper.from_hopper_client);

        subject.handle_stream_shutdown_msg(StreamShutdownMsg {
            peer_addr: unrecognized_socket_addr,
            stream_type: RemovedStreamType::Clandestine,
            report_to_counterpart: true,
        });

        System::current().stop_with_code(0);
        system.run();

        assert_eq!(subject.neighborhood_database.keys().len(), 1);
        let hopper_recording = hopper_recording_arc.lock().unwrap();
        assert_eq!(hopper_recording.len(), 0);
        TestLogHandler::new().exists_log_containing(&format!("WARN: Neighborhood: Received shutdown notification for stream to {}, but no Node with that IP is in the database - ignoring", unrecognized_socket_addr.ip()));
    }

    #[test]
    fn handle_stream_shutdown_handles_already_inactive_node() {
        init_test_logging();
        let (hopper, _, hopper_recording_arc) = make_recorder();
        let system = System::new("test");
        let gossip_neighbor_node = make_node_record(2456, true);
        let inactive_neighbor_node = make_node_record(3123, true);
        let inactive_neighbor_node_addr = inactive_neighbor_node.node_addr_opt().unwrap();
        let inactive_neighbor_node_socket_addr = SocketAddr::new(
            inactive_neighbor_node_addr.ip_addr(),
            inactive_neighbor_node_addr.ports()[0],
        );
        let subject_node = make_global_cryptde_node_record(1345, true);
        let mut subject = neighborhood_from_nodes(&subject_node, None);
        subject
            .neighborhood_database
            .add_node(gossip_neighbor_node.clone())
            .unwrap();
        subject
            .neighborhood_database
            .add_node(inactive_neighbor_node.clone())
            .unwrap();
        subject.neighborhood_database.add_arbitrary_full_neighbor(
            subject_node.public_key(),
            gossip_neighbor_node.public_key(),
        );
        subject.neighborhood_database.add_arbitrary_half_neighbor(
            inactive_neighbor_node.public_key(),
            subject_node.public_key(),
        );
        let peer_actors = peer_actors_builder().hopper(hopper).build();
        subject.hopper_opt = Some(peer_actors.hopper.from_hopper_client);

        subject.handle_stream_shutdown_msg(StreamShutdownMsg {
            peer_addr: inactive_neighbor_node_socket_addr,
            stream_type: RemovedStreamType::Clandestine,
            report_to_counterpart: true,
        });

        System::current().stop_with_code(0);
        system.run();

        assert_eq!(subject.neighborhood_database.keys().len(), 3);
        assert_eq!(
            subject.neighborhood_database.has_half_neighbor(
                subject_node.public_key(),
                inactive_neighbor_node.public_key(),
            ),
            false
        );
        let hopper_recording = hopper_recording_arc.lock().unwrap();
        assert_eq!(hopper_recording.len(), 0);
        TestLogHandler::new().exists_log_containing(&format!("DEBUG: Neighborhood: Received shutdown notification for {} at {}, but that Node is no neighbor - ignoring", inactive_neighbor_node.public_key(), inactive_neighbor_node_socket_addr.ip()));
    }

    #[test]
    fn handle_stream_shutdown_handles_existing_socket_addr() {
        init_test_logging();
        let (hopper, _, hopper_recording_arc) = make_recorder();
        let system = System::new("test");
        let gossip_neighbor_node = make_node_record(2456, true);
        let shutdown_neighbor_node = make_node_record(3123, true);
        let shutdown_neighbor_node_addr = shutdown_neighbor_node.node_addr_opt().unwrap();
        let shutdown_neighbor_node_socket_addr = SocketAddr::new(
            shutdown_neighbor_node_addr.ip_addr(),
            shutdown_neighbor_node_addr.ports()[0],
        );
        let subject_node = make_global_cryptde_node_record(1345, true);
        let mut subject = neighborhood_from_nodes(&subject_node, None);
        subject
            .neighborhood_database
            .add_node(gossip_neighbor_node.clone())
            .unwrap();
        subject
            .neighborhood_database
            .add_node(shutdown_neighbor_node.clone())
            .unwrap();
        subject.neighborhood_database.add_arbitrary_full_neighbor(
            subject_node.public_key(),
            gossip_neighbor_node.public_key(),
        );
        subject.neighborhood_database.add_arbitrary_full_neighbor(
            subject_node.public_key(),
            shutdown_neighbor_node.public_key(),
        );
        let peer_actors = peer_actors_builder().hopper(hopper).build();
        subject.hopper_opt = Some(peer_actors.hopper.from_hopper_client);
        subject.gossip_producer_opt = Some(Box::new(GossipProducerReal::new()));

        subject.handle_stream_shutdown_msg(StreamShutdownMsg {
            peer_addr: shutdown_neighbor_node_socket_addr,
            stream_type: RemovedStreamType::Clandestine,
            report_to_counterpart: true,
        });

        System::current().stop_with_code(0);
        system.run();
        assert_eq!(subject.neighborhood_database.keys().len(), 3);
        assert_eq!(
            subject.neighborhood_database.has_half_neighbor(
                subject_node.public_key(),
                shutdown_neighbor_node.public_key(),
            ),
            false
        );
        let hopper_recording = hopper_recording_arc.lock().unwrap();
        assert_eq!(hopper_recording.len(), 1);
        TestLogHandler::new().exists_log_containing(&format!(
            "DEBUG: Neighborhood: Received shutdown notification for {} at {}: removing neighborship",
            shutdown_neighbor_node.public_key(),
            shutdown_neighbor_node_socket_addr.ip()
        ));
    }

    #[should_panic(expected = "0: Received shutdown order from client 1234: shutting down hard")]
    #[test]
    fn shutdown_instruction_generates_log() {
        running_test();
        init_test_logging();
        let system = System::new("test");
        let subject = Neighborhood::new(
            main_cryptde(),
            &bc_from_nc_plus(
                NeighborhoodConfig {
                    mode: NeighborhoodMode::ZeroHop,
                },
                make_wallet("earning"),
                None,
                "shutdown_instruction_generates_log",
            ),
        );
        let (ui_gateway, _, ui_gateway_recording_arc) = make_recorder();
        let subject_addr = subject.start();
        let peer_actors = peer_actors_builder().ui_gateway(ui_gateway).build();
        subject_addr.try_send(BindMessage { peer_actors }).unwrap();
        subject_addr
            .try_send(make_meaningless_pool_bind_message())
            .unwrap();

        subject_addr
            .try_send(NodeFromUiMessage {
                client_id: 1234,
                body: MessageBody {
                    opcode: "shutdown".to_string(),
                    path: Conversation(4321),
                    payload: Ok("{}".to_string()),
                },
            })
            .unwrap();

        System::current().stop();
        system.run();
        let ui_gateway_recording = ui_gateway_recording_arc.lock().unwrap();
        assert_eq!(ui_gateway_recording.len(), 0);
        TestLogHandler::new()
            .exists_log_containing("INFO: Neighborhood: Received shutdown order from client 1234");
    }

    #[test]
    fn connection_status_message_is_handled_properly_for_not_connected() {
        let stage = OverallConnectionStage::NotConnected;
        let client_id = 1234;
        let context_id = 4321;

        let message_opt = connection_status_message_received_by_ui(
            stage,
            client_id,
            context_id,
            "connection_status_message_is_handled_properly_for_not_connected",
        );

        assert_eq!(
            message_opt,
            Some(NodeToUiMessage {
                target: MessageTarget::ClientId(client_id),
                body: UiConnectionStatusResponse {
                    stage: stage.into()
                }
                .tmb(context_id),
            })
        )
    }

    #[test]
    fn connection_status_message_is_handled_properly_for_connected_to_neighbor() {
        let stage = OverallConnectionStage::ConnectedToNeighbor;
        let client_id = 1235;
        let context_id = 4322;

        let message_opt = connection_status_message_received_by_ui(
            stage,
            client_id,
            context_id,
            "connection_status_message_is_handled_properly_for_connected_to_neighbor",
        );

        assert_eq!(
            message_opt,
            Some(NodeToUiMessage {
                target: MessageTarget::ClientId(client_id),
                body: UiConnectionStatusResponse {
                    stage: stage.into()
                }
                .tmb(context_id),
            })
        )
    }

    #[test]
    fn connection_status_message_is_handled_properly_for_three_hops_route_found() {
        let stage = OverallConnectionStage::ThreeHopsRouteFound;
        let client_id = 1236;
        let context_id = 4323;

        let message_opt = connection_status_message_received_by_ui(
            stage,
            client_id,
            context_id,
            "connection_status_message_is_handled_properly_for_three_hops_route_found",
        );

        assert_eq!(
            message_opt,
            Some(NodeToUiMessage {
                target: MessageTarget::ClientId(client_id),
                body: UiConnectionStatusResponse {
                    stage: stage.into()
                }
                .tmb(context_id),
            })
        )
    }

    #[test]
    fn new_password_message_works() {
        let system = System::new("test");
        let mut subject = make_standard_subject();
        let root_node_record = subject.neighborhood_database.root().clone();
        let set_past_neighbors_params_arc = Arc::new(Mutex::new(vec![]));
        let persistent_config = PersistentConfigurationMock::new()
            .set_past_neighbors_params(&set_past_neighbors_params_arc)
            .set_past_neighbors_result(Ok(()));
        subject.persistent_config_opt = Some(Box::new(persistent_config));
        let subject_addr = subject.start();
        let peer_actors = peer_actors_builder().build();
        subject_addr.try_send(BindMessage { peer_actors }).unwrap();
        subject_addr
            .try_send(make_meaningless_pool_bind_message())
            .unwrap();

        subject_addr
            .try_send(NewPasswordMessage {
                new_password: "borkety-bork".to_string(),
            })
            .unwrap();

        let mut db = db_from_node(&root_node_record);
        let new_neighbor = make_node_record(1324, true);
        db.add_node(new_neighbor.clone()).unwrap();
        db.add_arbitrary_half_neighbor(new_neighbor.public_key(), root_node_record.public_key());
        db.node_by_key_mut(root_node_record.public_key())
            .unwrap()
            .resign();
        db.node_by_key_mut(new_neighbor.public_key())
            .unwrap()
            .resign();
        let gossip = GossipBuilder::new(&db)
            .node(new_neighbor.public_key(), true)
            .build();
        let cores_package = ExpiredCoresPackage {
            immediate_neighbor: new_neighbor.node_addr_opt().unwrap().into(),
            paying_wallet: None,
            remaining_route: make_meaningless_route(),
            payload: gossip,
            payload_len: 0,
        };
        subject_addr.try_send(cores_package).unwrap();
        System::current().stop();
        system.run();
        let set_past_neighbors_params = set_past_neighbors_params_arc.lock().unwrap();
        assert_eq!(set_past_neighbors_params[0].1, "borkety-bork");
    }

    #[test]
    #[should_panic(
        expected = "panic message (processed with: node_lib::sub_lib::utils::crash_request_analyzer)"
    )]
    fn neighborhood_can_be_crashed_properly_but_not_improperly() {
        let mut neighborhood = make_standard_subject();
        neighborhood.crashable = true;

        prove_that_crash_request_handler_is_hooked_up(neighborhood, CRASH_KEY);
    }

    #[test]
    fn curate_past_neighbors_does_not_write_to_database_if_neighbors_are_same_but_order_has_changed(
    ) {
        let mut subject = make_standard_subject();
        // This mock is completely unprepared: any call to it should cause a panic
        let persistent_config = PersistentConfigurationMock::new();
        subject.persistent_config_opt = Some(Box::new(persistent_config));
        let neighbor_keys_before = vec![PublicKey::new(b"ABCDE"), PublicKey::new(b"FGHIJ")]
            .into_iter()
            .collect();
        let neighbor_keys_after = vec![PublicKey::new(b"FGHIJ"), PublicKey::new(b"ABCDE")]
            .into_iter()
            .collect();

        subject.curate_past_neighbors(neighbor_keys_before, neighbor_keys_after);

        // No panic; therefore no attempt was made to persist: test passes!
    }

    fn make_standard_subject() -> Neighborhood {
        let root_node = make_global_cryptde_node_record(9999, true);
        let neighbor_node = make_node_record(9998, true);
        let mut subject = neighborhood_from_nodes(&root_node, Some(&neighbor_node));
        let persistent_config = PersistentConfigurationMock::new();
        subject.persistent_config_opt = Some(Box::new(persistent_config));
        assert!(subject.gossip_acceptor_info_opt.is_none());
        subject
    }

    fn make_o_r_e_subject() -> (NodeRecord, NodeRecord, NodeRecord, Neighborhood) {
        let mut subject = make_standard_subject();
        let o = &subject.neighborhood_database.root().clone();
        let r = &make_node_record(4567, false);
        let e = &make_node_record(5678, false);
        {
            let db = &mut subject.neighborhood_database;
            db.add_node(r.clone()).unwrap();
            db.add_node(e.clone()).unwrap();
            let mut dual_edge = |a: &NodeRecord, b: &NodeRecord| {
                db.add_arbitrary_full_neighbor(a.public_key(), b.public_key())
            };
            dual_edge(o, r);
            dual_edge(r, e);
        }
        (o.clone(), r.clone(), e.clone(), subject)
    }

    fn make_meaningless_pool_bind_message() -> PoolBindMessage {
        pool_bind_message_builder()
            .stream_handler_pool(make_recorder().0)
            .dispatcher(make_recorder().0)
            .build()
    }

    fn segment(nodes: &[&NodeRecord], component: &Component) -> RouteSegment {
        RouteSegment::new(
            nodes.into_iter().map(|n| n.public_key()).collect(),
            component.clone(),
        )
    }

    pub struct GossipAcceptorMock {
        handle_params: Arc<
            Mutex<
                Vec<(
                    NeighborhoodDatabase,
                    Vec<AccessibleGossipRecord>,
                    SocketAddr,
                    Vec<IpAddr>,
                )>,
            >,
        >,
        handle_results: RefCell<Vec<GossipAcceptanceResult>>,
    }

    impl GossipAcceptor for GossipAcceptorMock {
        fn handle(
            &self,
            database: &mut NeighborhoodDatabase,
            agrs: Vec<AccessibleGossipRecord>,
            gossip_source: SocketAddr,
            connection_progress_peers: &[IpAddr],
        ) -> GossipAcceptanceResult {
            self.handle_params.lock().unwrap().push((
                database.clone(),
                agrs,
                gossip_source,
                connection_progress_peers.to_vec(),
            ));
            self.handle_results.borrow_mut().remove(0)
        }
    }

    impl GossipAcceptorMock {
        pub fn new() -> GossipAcceptorMock {
            GossipAcceptorMock {
                handle_params: Arc::new(Mutex::new(vec![])),
                handle_results: RefCell::new(vec![]),
            }
        }

        pub fn handle_params(
            mut self,
            params_arc: &Arc<
                Mutex<
                    Vec<(
                        NeighborhoodDatabase,
                        Vec<AccessibleGossipRecord>,
                        SocketAddr,
                        Vec<IpAddr>,
                    )>,
                >,
            >,
        ) -> Self {
            self.handle_params = params_arc.clone();
            self
        }

        pub fn handle_result(self, result: GossipAcceptanceResult) -> GossipAcceptorMock {
            self.handle_results.borrow_mut().push(result);
            self
        }
    }

    #[derive(Default)]
    pub struct GossipProducerMock {
        produce_params: Arc<Mutex<Vec<(NeighborhoodDatabase, PublicKey)>>>,
        produce_results: RefCell<Vec<Option<Gossip_0v1>>>,
    }

    impl GossipProducer for GossipProducerMock {
        fn produce(
            &self,
            database: &mut NeighborhoodDatabase,
            target: &PublicKey,
        ) -> Option<Gossip_0v1> {
            self.produce_params
                .lock()
                .unwrap()
                .push((database.clone(), target.clone()));
            self.produce_results.borrow_mut().remove(0)
        }

        fn produce_debut_or_ipchange(&self, _database: &NeighborhoodDatabase) -> Gossip_0v1 {
            unimplemented!()
        }
    }

    impl GossipProducerMock {
        pub fn new() -> GossipProducerMock {
            Self::default()
        }

        pub fn produce_params(
            mut self,
            params_arc: &Arc<Mutex<Vec<(NeighborhoodDatabase, PublicKey)>>>,
        ) -> GossipProducerMock {
            self.produce_params = params_arc.clone();
            self
        }

        pub fn produce_result(self, result: Option<Gossip_0v1>) -> GossipProducerMock {
            self.produce_results.borrow_mut().push(result);
            self
        }
    }

    fn bc_from_nc_plus(
        nc: NeighborhoodConfig,
        earning_wallet: Wallet,
        consuming_wallet_opt: Option<Wallet>,
        test_name: &str,
    ) -> BootstrapperConfig {
        let home_dir = ensure_node_home_directory_exists("neighborhood", test_name);
        let mut config = BootstrapperConfig::new();
        config.neighborhood_config = nc;
        config.earning_wallet = earning_wallet;
        config.consuming_wallet_opt = consuming_wallet_opt;
        config.data_directory = home_dir;
        config
    }

    fn make_subject_from_node_descriptor(
        node_descriptor: &NodeDescriptor,
        test_name: &str,
    ) -> Neighborhood {
        let this_node_addr = NodeAddr::new(&IpAddr::from_str("111.111.111.111").unwrap(), &[8765]);
        let initial_node_descriptors = vec![node_descriptor.clone()];
        let neighborhood_config = NeighborhoodConfig {
            mode: NeighborhoodMode::Standard(
                this_node_addr,
                initial_node_descriptors,
                rate_pack(100),
            ),
        };
        let bootstrap_config =
            bc_from_nc_plus(neighborhood_config, make_wallet("earning"), None, test_name);

        let mut neighborhood = Neighborhood::new(main_cryptde(), &bootstrap_config);

        let (node_to_ui_recipient, _) = make_node_to_ui_recipient();
        neighborhood.node_to_ui_sub_opt = Some(node_to_ui_recipient);
        neighborhood
    }

    fn connection_status_message_received_by_ui(
        stage: OverallConnectionStage,
        client_id: u64,
        context_id: u64,
        test_name: &str,
    ) -> Option<NodeToUiMessage> {
        let system = System::new("test");
        let mut subject = Neighborhood::new(
            main_cryptde(),
            &bc_from_nc_plus(
                NeighborhoodConfig {
                    mode: NeighborhoodMode::ConsumeOnly(vec![make_node_descriptor(make_ip(1))]),
                },
                make_wallet("earning"),
                None,
                test_name,
            ),
        );
        subject.overall_connection_status.stage = stage;
        let (ui_gateway, _, ui_gateway_recording_arc) = make_recorder();
        let subject_addr = subject.start();
        let peer_actors = peer_actors_builder().ui_gateway(ui_gateway).build();
        subject_addr.try_send(BindMessage { peer_actors }).unwrap();
        subject_addr
            .try_send(make_meaningless_pool_bind_message())
            .unwrap();

        subject_addr
            .try_send(NodeFromUiMessage {
                client_id,
                body: MessageBody {
                    opcode: "connectionStatus".to_string(),
                    path: Conversation(context_id),
                    payload: Ok("{}".to_string()),
                },
            })
            .unwrap();

        System::current().stop();
        system.run();
        let ui_gateway_recording = ui_gateway_recording_arc.lock().unwrap();
        let message_opt = ui_gateway_recording
            .get_record_opt::<NodeToUiMessage>(0)
            .cloned();

        message_opt
    }

    fn make_neighborhood_linearly_connected_with_nodes(hops: u16) -> Neighborhood {
        let subject_node = make_global_cryptde_node_record(1234, true);
        let relay1 = make_node_record(1111, true);
        let mut nodes = vec![
            subject_node.public_key().clone(),
            relay1.public_key().clone(),
        ];
        let mut neighborhood: Neighborhood = neighborhood_from_nodes(&subject_node, Some(&relay1));
        let mut replacement_database = neighborhood.neighborhood_database.clone();

        fn nonce(x: u16) -> u16 {
            x + (10 * x) + (100 * x) + (1000 * x)
        }

        for i in 1..=hops {
            match i {
                1 => {
                    replacement_database.add_node(relay1.clone()).unwrap();
                }
                i if i < hops => {
                    let relay_node = make_node_record(nonce(i), false);
                    replacement_database.add_node(relay_node.clone()).unwrap();
                    nodes.push(relay_node.public_key().clone());
                }
                i if i == hops => {
                    let exit_node = make_node_record(nonce(i), false);
                    replacement_database.add_node(exit_node.clone()).unwrap();
                    nodes.push(exit_node.public_key().clone());
                }
                _ => panic!("The match statement should be exhaustive."),
            }
            replacement_database
                .add_arbitrary_full_neighbor(&nodes[i as usize - 1], &nodes[i as usize]);
        }

        neighborhood.gossip_acceptor_info_opt =
            Some(Either::Left(Box::new(DatabaseReplacementGossipAcceptor {
                replacement_database,
            })));
        neighborhood.persistent_config_opt = Some(Box::new(
            PersistentConfigurationMock::new().set_past_neighbors_result(Ok(())),
        ));

        neighborhood
    }

    pub struct NeighborhoodDatabaseMessage {}

    impl Message for NeighborhoodDatabaseMessage {
        type Result = NeighborhoodDatabase;
    }

    impl<A, M> MessageResponse<A, M> for NeighborhoodDatabase
    where
        A: Actor,
        M: Message<Result = NeighborhoodDatabase>,
    {
        fn handle<R: ResponseChannel<M>>(self, _: &mut A::Context, tx: Option<R>) {
            if let Some(tx) = tx {
                tx.send(self);
            }
        }
    }

    impl Handler<NeighborhoodDatabaseMessage> for Neighborhood {
        type Result = NeighborhoodDatabase;

        fn handle(
            &mut self,
            _msg: NeighborhoodDatabaseMessage,
            _ctx: &mut Self::Context,
        ) -> Self::Result {
            self.neighborhood_database.clone()
        }
    }
}
