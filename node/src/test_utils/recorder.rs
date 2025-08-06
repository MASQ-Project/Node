// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
#![cfg(test)]

use crate::accountant::scanners::payable_scanner::data_structures::{
    BlockchainAgentWithContextMessage, QualifiedPayablesMessage,
};
use crate::accountant::{
    ReceivedPayments, RequestTransactionReceipts, ScanError, ScanForNewPayables,
    ScanForReceivables, SentPayables,
};
use crate::accountant::{ReportTransactionReceipts, ScanForPendingPayables, ScanForRetryPayables};
use crate::blockchain::blockchain_bridge::PendingPayableFingerprintSeeds;
use crate::blockchain::blockchain_bridge::RetrieveTransactions;
use crate::daemon::crash_notification::CrashNotification;
use crate::daemon::DaemonBindMessage;
use crate::neighborhood::gossip::Gossip_0v1;
use crate::stream_messages::{AddStreamMsg, PoolBindMessage, RemoveStreamMsg};
use crate::sub_lib::accountant::AccountantSubs;
use crate::sub_lib::accountant::ReportExitServiceProvidedMessage;
use crate::sub_lib::accountant::ReportRoutingServiceProvidedMessage;
use crate::sub_lib::accountant::ReportServicesConsumedMessage;
use crate::sub_lib::blockchain_bridge::BlockchainBridgeSubs;
use crate::sub_lib::blockchain_bridge::OutboundPaymentsInstructions;
use crate::sub_lib::configurator::ConfiguratorSubs;
use crate::sub_lib::dispatcher::InboundClientData;
use crate::sub_lib::dispatcher::{DispatcherSubs, StreamShutdownMsg};
use crate::sub_lib::hopper::IncipientCoresPackage;
use crate::sub_lib::hopper::{ExpiredCoresPackage, NoLookupIncipientCoresPackage};
use crate::sub_lib::hopper::{HopperSubs, MessageType};
use crate::sub_lib::neighborhood::NeighborhoodSubs;
use crate::sub_lib::neighborhood::NodeQueryResponseMetadata;
use crate::sub_lib::neighborhood::RemoveNeighborMessage;
use crate::sub_lib::neighborhood::RouteQueryMessage;
use crate::sub_lib::neighborhood::RouteQueryResponse;
use crate::sub_lib::neighborhood::UpdateNodeRecordMetadataMessage;
use crate::sub_lib::neighborhood::{ConfigChangeMsg, ConnectionProgressMessage};
use crate::sub_lib::neighborhood::{DispatcherNodeQueryMessage, GossipFailure_0v1};
use crate::sub_lib::peer_actors::PeerActors;
use crate::sub_lib::peer_actors::{BindMessage, NewPublicIp, StartMessage};
use crate::sub_lib::proxy_client::{ClientResponsePayload_0v1, InboundServerData};
use crate::sub_lib::proxy_client::{DnsResolveFailure_0v1, ProxyClientSubs};
use crate::sub_lib::proxy_server::{
    AddReturnRouteMessage, ClientRequestPayload_0v1, StreamKeyPurge,
};
use crate::sub_lib::proxy_server::{AddRouteResultMessage, ProxyServerSubs};
use crate::sub_lib::stream_handler_pool::DispatcherNodeQueryResponse;
use crate::sub_lib::stream_handler_pool::TransmitDataMsg;
use crate::sub_lib::ui_gateway::UiGatewaySubs;
use crate::sub_lib::utils::MessageScheduler;
use crate::test_utils::recorder_counter_msgs::{
    CounterMessages, CounterMsgGear, SingleTypeCounterMsgSetup,
};
use crate::test_utils::recorder_stop_conditions::{
    ForcedMatchable, MsgIdentification, PretendedMatchableWrapper, StopConditions,
};
use crate::test_utils::to_millis;
use crate::test_utils::unshared_test_utils::system_killer_actor::SystemKillerActor;
use actix::Addr;
use actix::Context;
use actix::Handler;
use actix::MessageResult;
use actix::System;
use actix::{Actor, Message};
use masq_lib::ui_gateway::{NodeFromUiMessage, NodeToUiMessage};
use std::any::{type_name, Any, TypeId};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use std::time::Instant;

#[derive(Default)]
pub struct Recorder {
    recording: Arc<Mutex<Recording>>,
    node_query_responses: Vec<Option<NodeQueryResponseMetadata>>,
    route_query_responses: Vec<Option<RouteQueryResponse>>,
    counter_msgs_opt: Option<CounterMessages>,
    stop_conditions_opt: Option<StopConditions>,
}

#[derive(Default)]
pub struct Recording {
    messages: Vec<Box<dyn Any + Send>>,
}

pub struct RecordAwaiter {
    recording: Arc<Mutex<Recording>>,
}

impl Actor for Recorder {
    type Context = Context<Self>;
}

macro_rules! message_handler_common {
    ($message_type: ty, $handling_fn: ident) => {
        impl Handler<$message_type> for Recorder {
            type Result = ();

            fn handle(&mut self, msg: $message_type, _ctx: &mut Self::Context) {
                self.$handling_fn(msg)
            }
        }
    };
}

macro_rules! matchable {
    ($message_type: ty) => {
        impl ForcedMatchable<$message_type> for $message_type {
            fn trigger_msg_type_id(&self) -> TypeId {
                TypeId::of::<$message_type>()
            }
        }
    };
}

// t, m, p (type, match, predicate) represents a list of the possible system stop conditions

macro_rules! recorder_message_handler_t_m_p {
    ($message_type: ty) => {
        message_handler_common!($message_type, handle_msg_t_m_p);
        matchable!($message_type);
    };
}

macro_rules! recorder_message_handler_t_p {
    ($message_type: ty) => {
        message_handler_common!($message_type, handle_msg_t_p);
    };
}

recorder_message_handler_t_m_p!(AddReturnRouteMessage);
recorder_message_handler_t_m_p!(AddRouteResultMessage);
recorder_message_handler_t_p!(AddStreamMsg);
recorder_message_handler_t_m_p!(BindMessage);
recorder_message_handler_t_p!(BlockchainAgentWithContextMessage);
recorder_message_handler_t_m_p!(ConfigChangeMsg);
recorder_message_handler_t_m_p!(ConnectionProgressMessage);
recorder_message_handler_t_m_p!(CrashNotification);
recorder_message_handler_t_m_p!(DaemonBindMessage);
recorder_message_handler_t_m_p!(DispatcherNodeQueryMessage);
recorder_message_handler_t_m_p!(DispatcherNodeQueryResponse);
recorder_message_handler_t_m_p!(DnsResolveFailure_0v1);
recorder_message_handler_t_m_p!(ExpiredCoresPackage<ClientRequestPayload_0v1>);
recorder_message_handler_t_m_p!(ExpiredCoresPackage<ClientResponsePayload_0v1>);
recorder_message_handler_t_m_p!(ExpiredCoresPackage<DnsResolveFailure_0v1>);
recorder_message_handler_t_m_p!(ExpiredCoresPackage<Gossip_0v1>);
recorder_message_handler_t_m_p!(ExpiredCoresPackage<GossipFailure_0v1>);
recorder_message_handler_t_m_p!(ExpiredCoresPackage<MessageType>);
recorder_message_handler_t_m_p!(InboundClientData);
recorder_message_handler_t_m_p!(InboundServerData);
recorder_message_handler_t_m_p!(IncipientCoresPackage);
recorder_message_handler_t_m_p!(NewPublicIp);
recorder_message_handler_t_m_p!(NodeFromUiMessage);
recorder_message_handler_t_m_p!(NodeToUiMessage);
recorder_message_handler_t_m_p!(NoLookupIncipientCoresPackage);
recorder_message_handler_t_p!(OutboundPaymentsInstructions);
recorder_message_handler_t_m_p!(PendingPayableFingerprintSeeds);
recorder_message_handler_t_m_p!(PoolBindMessage);
recorder_message_handler_t_m_p!(QualifiedPayablesMessage);
recorder_message_handler_t_m_p!(ReceivedPayments);
recorder_message_handler_t_m_p!(RemoveNeighborMessage);
recorder_message_handler_t_m_p!(RemoveStreamMsg);
recorder_message_handler_t_m_p!(ReportExitServiceProvidedMessage);
recorder_message_handler_t_m_p!(ReportRoutingServiceProvidedMessage);
recorder_message_handler_t_m_p!(ReportServicesConsumedMessage);
recorder_message_handler_t_m_p!(ReportTransactionReceipts);
recorder_message_handler_t_m_p!(RequestTransactionReceipts);
recorder_message_handler_t_m_p!(RetrieveTransactions);
recorder_message_handler_t_m_p!(ScanError);
recorder_message_handler_t_m_p!(ScanForNewPayables);
recorder_message_handler_t_m_p!(ScanForRetryPayables);
recorder_message_handler_t_m_p!(ScanForPendingPayables);
recorder_message_handler_t_m_p!(ScanForReceivables);
recorder_message_handler_t_m_p!(SentPayables);
recorder_message_handler_t_m_p!(StartMessage);
recorder_message_handler_t_m_p!(StreamShutdownMsg);
recorder_message_handler_t_m_p!(TransmitDataMsg);
recorder_message_handler_t_m_p!(UpdateNodeRecordMetadataMessage);

impl<M> Handler<MessageScheduler<M>> for Recorder
where
    M: Message + PartialEq + Send + 'static,
{
    type Result = ();

    fn handle(&mut self, msg: MessageScheduler<M>, _ctx: &mut Self::Context) {
        self.handle_msg_t_m_p(msg)
    }
}

impl<OuterM, InnerM> ForcedMatchable<OuterM> for MessageScheduler<InnerM>
where
    OuterM: PartialEq + 'static,
    InnerM: PartialEq + Send + Message,
{
    fn trigger_msg_type_id(&self) -> TypeId {
        TypeId::of::<OuterM>()
    }
}

impl Handler<RouteQueryMessage> for Recorder {
    type Result = MessageResult<RouteQueryMessage>;

    fn handle(
        &mut self,
        msg: RouteQueryMessage,
        _ctx: &mut Self::Context,
    ) -> <Self as Handler<RouteQueryMessage>>::Result {
        self.handle_msg_t_m_p(msg);
        MessageResult(extract_response(
            &mut self.route_query_responses,
            "No RouteQueryResponses prepared for RouteQueryMessage",
        ))
    }
}

matchable!(RouteQueryMessage);

impl Handler<SetUpCounterMsgs> for Recorder {
    type Result = ();

    fn handle(&mut self, msg: SetUpCounterMsgs, _ctx: &mut Self::Context) -> Self::Result {
        msg.setups
            .into_iter()
            .for_each(|msg_setup| self.add_counter_msg(msg_setup))
    }
}

fn extract_response<T>(responses: &mut Vec<T>, err_msg: &str) -> T
where
    T: Clone,
{
    match responses.len() {
        n if n == 0 => panic!("{}", err_msg),
        n if n == 1 => responses[0].clone(),
        _ => responses.remove(0),
    }
}

impl Recorder {
    pub fn new() -> Recorder {
        Self::default()
    }

    pub fn record<T>(&mut self, item: T)
    where
        T: Any + Send,
    {
        let mut recording = self.recording.lock().unwrap();
        let messages: &mut Vec<Box<dyn Any + Send>> = &mut recording.messages;
        let item_box = Box::new(item);
        messages.push(item_box);
    }

    pub fn get_recording(&self) -> Arc<Mutex<Recording>> {
        self.recording.clone()
    }

    pub fn get_awaiter(&self) -> RecordAwaiter {
        RecordAwaiter {
            recording: self.recording.clone(),
        }
    }

    pub fn node_query_response(mut self, response: Option<NodeQueryResponseMetadata>) -> Recorder {
        self.node_query_responses.push(response);
        self
    }

    pub fn route_query_response(mut self, response: Option<RouteQueryResponse>) -> Recorder {
        self.route_query_responses.push(response);
        self
    }

    pub fn system_stop_conditions(mut self, stop_conditions: StopConditions) -> Recorder {
        if self.stop_conditions_opt.is_none() {
            self.start_system_killer();
            self.stop_conditions_opt = Some(stop_conditions)
        } else {
            panic!("Stop conditions must be set by a single method call. Consider using StopConditions::All")
        };
        self
    }

    fn add_counter_msg(&mut self, counter_msg_setup: SingleTypeCounterMsgSetup) {
        if let Some(counter_msgs) = self.counter_msgs_opt.as_mut() {
            counter_msgs.add_msg(counter_msg_setup)
        } else {
            let mut counter_msgs = CounterMessages::default();
            counter_msgs.add_msg(counter_msg_setup);
            self.counter_msgs_opt = Some(counter_msgs)
        }
    }

    fn start_system_killer(&mut self) {
        let system_killer = SystemKillerActor::new(Duration::from_secs(15));
        system_killer.start();
    }

    fn handle_msg_t_m_p<M>(&mut self, msg: M)
    where
        M: 'static + ForcedMatchable<M> + Send,
    {
        let counter_msg_opt = self.check_on_counter_msg(&msg);

        let stop_system = if let Some(stop_conditions) = &mut self.stop_conditions_opt {
            stop_conditions.resolve_stop_conditions::<M>(&msg)
        } else {
            false
        };

        self.record(msg);

        if let Some(sendable_msgs) = counter_msg_opt {
            sendable_msgs.into_iter().for_each(|msg| msg.try_send())
        }

        if stop_system {
            System::current().stop()
        }
    }

    //for messages that cannot implement PartialEq
    fn handle_msg_t_p<M>(&mut self, msg: M)
    where
        M: 'static + Send,
    {
        self.handle_msg_t_m_p(PretendedMatchableWrapper(msg))
    }

    fn check_on_counter_msg<M>(&mut self, msg: &M) -> Option<Vec<Box<dyn CounterMsgGear>>>
    where
        M: ForcedMatchable<M> + 'static,
    {
        if let Some(counter_msgs) = self.counter_msgs_opt.as_mut() {
            counter_msgs.search_for_msg_gear(msg)
        } else {
            None
        }
    }
}

impl Recording {
    pub fn len(&self) -> usize {
        self.messages.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn get<T: Any + Send + Clone + Message>(
        recording_arc: &Arc<Mutex<Recording>>,
        index: usize,
    ) -> T {
        let recording_arc_clone = recording_arc.clone();
        let recording = recording_arc_clone.lock().unwrap();
        recording.get_record::<T>(index).clone()
    }

    pub fn get_record<T>(&self, index: usize) -> &T
    where
        T: Any + Send,
    {
        self.get_record_inner_body(index)
            .unwrap_or_else(|e| panic!("{}", e))
    }

    pub fn get_record_opt<T>(&self, index: usize) -> Option<&T>
    where
        T: Any + Send,
    {
        self.get_record_inner_body(index).ok()
    }

    fn get_record_inner_body<T: 'static + Send>(&self, index: usize) -> Result<&T, String> {
        let item_box = match self.messages.get(index) {
            Some(item_box) => item_box,
            None => {
                return Err(format!(
                    "Only {} messages recorded: no message #{} in the recording",
                    self.messages.len(),
                    index
                ))
            }
        };
        match item_box.downcast_ref::<T>() {
            Some(item) => Ok(item),
            None => {
                // double-checking for an uncommon, yet possible other type of actor message, which doesn't implement PartialEq
                let item_opt = item_box.downcast_ref::<PretendedMatchableWrapper<T>>();

                match item_opt {
                    Some(item) => Ok(&item.0),
                    None => Err(format!(
                        "Message {:?} could not be downcast to the expected type {}.",
                        item_box,
                        type_name::<T>()
                    )),
                }
            }
        }
    }
}

impl RecordAwaiter {
    pub fn await_message_count(&self, count: usize) {
        let limit = 10_000u64;
        let mut prev_len: usize = 0;
        let begin = Instant::now();
        loop {
            let cur_len = { self.recording.lock().unwrap().len() };
            if cur_len != prev_len {
                println!("Recorder has received {} messages", cur_len)
            }
            let latency_so_far = to_millis(&Instant::now().duration_since(begin));
            if latency_so_far > limit {
                panic!(
                    "After {}ms, recorder has received only {} messages, not {}",
                    limit, cur_len, count
                );
            }
            prev_len = cur_len;
            if cur_len >= count {
                return;
            }
            thread::sleep(Duration::from_millis(50))
        }
    }
}

#[derive(Message)]
pub struct SetUpCounterMsgs {
    // Trigger msg - it arrives at the Recorder from the Actor being tested and matches one of the
    //               msg ID methods.
    // Counter msg - it is sent back from the Recorder when a trigger msg is recognized
    //
    // In general, the triggering is data driven. Shuffling with the setups of differently typed
    // trigger messages can't have any adverse effect.
    //
    // However, setups of the same trigger message types compose clusters.
    // Keep in mind these are tested over their ID method sequentially, according to the order
    // in which they are fed into this vector, with the other messages ignored.
    setups: Vec<SingleTypeCounterMsgSetup>,
}

impl SetUpCounterMsgs {
    pub fn new(setups: Vec<SingleTypeCounterMsgSetup>) -> Self {
        Self { setups }
    }
}

pub fn make_recorder() -> (Recorder, RecordAwaiter, Arc<Mutex<Recording>>) {
    let recorder = Recorder::new();
    let awaiter = recorder.get_awaiter();
    let recording = recorder.get_recording();
    (recorder, awaiter, recording)
}

pub fn make_proxy_server_subs_from_recorder(addr: &Addr<Recorder>) -> ProxyServerSubs {
    ProxyServerSubs {
        bind: recipient!(addr, BindMessage),
        from_dispatcher: recipient!(addr, InboundClientData),
        from_hopper: recipient!(addr, ExpiredCoresPackage<ClientResponsePayload_0v1>),
        dns_failure_from_hopper: recipient!(addr, ExpiredCoresPackage<DnsResolveFailure_0v1>),
        add_return_route: recipient!(addr, AddReturnRouteMessage),
        stream_shutdown_sub: recipient!(addr, StreamShutdownMsg),
        node_from_ui: recipient!(addr, NodeFromUiMessage),
        route_result_sub: recipient!(addr, AddRouteResultMessage),
        schedule_stream_key_purge: recipient!(addr, MessageScheduler<StreamKeyPurge>),
    }
}

pub fn make_dispatcher_subs_from_recorder(addr: &Addr<Recorder>) -> DispatcherSubs {
    DispatcherSubs {
        ibcd_sub: recipient!(addr, InboundClientData),
        bind: recipient!(addr, BindMessage),
        from_dispatcher_client: recipient!(addr, TransmitDataMsg),
        stream_shutdown_sub: recipient!(addr, StreamShutdownMsg),
        ui_sub: recipient!(addr, NodeFromUiMessage),
        new_ip_sub: recipient!(addr, NewPublicIp),
    }
}

pub fn make_hopper_subs_from_recorder(addr: &Addr<Recorder>) -> HopperSubs {
    HopperSubs {
        bind: recipient!(addr, BindMessage),
        from_hopper_client: recipient!(addr, IncipientCoresPackage),
        from_hopper_client_no_lookup: recipient!(addr, NoLookupIncipientCoresPackage),
        from_dispatcher: recipient!(addr, InboundClientData),
        node_from_ui: recipient!(addr, NodeFromUiMessage),
    }
}

pub fn make_proxy_client_subs_from_recorder(addr: &Addr<Recorder>) -> ProxyClientSubs {
    ProxyClientSubs {
        bind: recipient!(addr, BindMessage),
        from_hopper: recipient!(addr, ExpiredCoresPackage<ClientRequestPayload_0v1>),
        inbound_server_data: recipient!(addr, InboundServerData),
        dns_resolve_failed: recipient!(addr, DnsResolveFailure_0v1),
        node_from_ui: recipient!(addr, NodeFromUiMessage),
    }
}

pub fn make_neighborhood_subs_from_recorder(addr: &Addr<Recorder>) -> NeighborhoodSubs {
    NeighborhoodSubs {
        bind: recipient!(addr, BindMessage),
        start: recipient!(addr, StartMessage),
        new_public_ip: recipient!(addr, NewPublicIp),
        route_query: recipient!(addr, RouteQueryMessage),
        update_node_record_metadata: recipient!(addr, UpdateNodeRecordMetadataMessage),
        from_hopper: recipient!(addr, ExpiredCoresPackage<Gossip_0v1>),
        gossip_failure: recipient!(addr, ExpiredCoresPackage<GossipFailure_0v1>),
        dispatcher_node_query: recipient!(addr, DispatcherNodeQueryMessage),
        remove_neighbor: recipient!(addr, RemoveNeighborMessage),
        config_change_msg_sub: recipient!(addr, ConfigChangeMsg),
        stream_shutdown_sub: recipient!(addr, StreamShutdownMsg),
        from_ui_message_sub: recipient!(addr, NodeFromUiMessage),
        connection_progress_sub: recipient!(addr, ConnectionProgressMessage),
    }
}

pub fn make_accountant_subs_from_recorder(addr: &Addr<Recorder>) -> AccountantSubs {
    AccountantSubs {
        bind: recipient!(addr, BindMessage),
        config_change_msg_sub: recipient!(addr, ConfigChangeMsg),
        start: recipient!(addr, StartMessage),
        report_routing_service_provided: recipient!(addr, ReportRoutingServiceProvidedMessage),
        report_exit_service_provided: recipient!(addr, ReportExitServiceProvidedMessage),
        report_services_consumed: recipient!(addr, ReportServicesConsumedMessage),
        report_payable_payments_setup: recipient!(addr, BlockchainAgentWithContextMessage),
        report_inbound_payments: recipient!(addr, ReceivedPayments),
        init_pending_payable_fingerprints: recipient!(addr, PendingPayableFingerprintSeeds),
        report_transaction_receipts: recipient!(addr, ReportTransactionReceipts),
        report_sent_payments: recipient!(addr, SentPayables),
        scan_errors: recipient!(addr, ScanError),
        ui_message_sub: recipient!(addr, NodeFromUiMessage),
    }
}

pub fn make_ui_gateway_subs_from_recorder(addr: &Addr<Recorder>) -> UiGatewaySubs {
    UiGatewaySubs {
        bind: recipient!(addr, BindMessage),
        node_from_ui_message_sub: recipient!(addr, NodeFromUiMessage),
        node_to_ui_message_sub: recipient!(addr, NodeToUiMessage),
    }
}

pub fn make_blockchain_bridge_subs_from_recorder(addr: &Addr<Recorder>) -> BlockchainBridgeSubs {
    BlockchainBridgeSubs {
        bind: recipient!(addr, BindMessage),
        outbound_payments_instructions: recipient!(addr, OutboundPaymentsInstructions),
        qualified_payables: recipient!(addr, QualifiedPayablesMessage),
        retrieve_transactions: recipient!(addr, RetrieveTransactions),
        ui_sub: recipient!(addr, NodeFromUiMessage),
        request_transaction_receipts: recipient!(addr, RequestTransactionReceipts),
    }
}

pub fn make_configurator_subs_from_recorder(addr: &Addr<Recorder>) -> ConfiguratorSubs {
    ConfiguratorSubs {
        bind: recipient!(addr, BindMessage),
        node_from_ui_sub: recipient!(addr, NodeFromUiMessage),
    }
}

pub fn peer_actors_builder() -> PeerActorsBuilder {
    PeerActorsBuilder::new()
}

#[derive(Default)]
pub struct PeerActorsBuilder {
    proxy_server: Recorder,
    dispatcher: Recorder,
    hopper: Recorder,
    proxy_client: Recorder,
    neighborhood: Recorder,
    accountant: Recorder,
    ui_gateway: Recorder,
    blockchain_bridge: Recorder,
    configurator: Recorder,
}

impl PeerActorsBuilder {
    pub fn new() -> PeerActorsBuilder {
        PeerActorsBuilder {
            proxy_server: Recorder::new(),
            dispatcher: Recorder::new(),
            hopper: Recorder::new(),
            proxy_client: Recorder::new(),
            neighborhood: Recorder::new(),
            accountant: Recorder::new(),
            ui_gateway: Recorder::new(),
            blockchain_bridge: Recorder::new(),
            configurator: Recorder::new(),
        }
    }

    pub fn proxy_server(mut self, recorder: Recorder) -> PeerActorsBuilder {
        self.proxy_server = recorder;
        self
    }

    pub fn dispatcher(mut self, recorder: Recorder) -> PeerActorsBuilder {
        self.dispatcher = recorder;
        self
    }

    pub fn hopper(mut self, recorder: Recorder) -> PeerActorsBuilder {
        self.hopper = recorder;
        self
    }

    pub fn proxy_client(mut self, recorder: Recorder) -> PeerActorsBuilder {
        self.proxy_client = recorder;
        self
    }

    pub fn neighborhood(mut self, recorder: Recorder) -> PeerActorsBuilder {
        self.neighborhood = recorder;
        self
    }

    pub fn accountant(mut self, recorder: Recorder) -> PeerActorsBuilder {
        self.accountant = recorder;
        self
    }

    pub fn ui_gateway(mut self, recorder: Recorder) -> PeerActorsBuilder {
        self.ui_gateway = recorder;
        self
    }

    pub fn blockchain_bridge(mut self, recorder: Recorder) -> PeerActorsBuilder {
        self.blockchain_bridge = recorder;
        self
    }

    pub fn configurator(mut self, recorder: Recorder) -> PeerActorsBuilder {
        self.configurator = recorder;
        self
    }

    // This must be called after System.new and before System.run.
    // These addresses may be helpful for setting up the Counter Messages.
    pub fn build_and_provide_addresses(self) -> (PeerActors, PeerActorAddrs) {
        let proxy_server_addr = self.proxy_server.start();
        let dispatcher_addr = self.dispatcher.start();
        let hopper_addr = self.hopper.start();
        let proxy_client_addr = self.proxy_client.start();
        let neighborhood_addr = self.neighborhood.start();
        let accountant_addr = self.accountant.start();
        let ui_gateway_addr = self.ui_gateway.start();
        let blockchain_bridge_addr = self.blockchain_bridge.start();
        let configurator_addr = self.configurator.start();

        (
            PeerActors {
                proxy_server: make_proxy_server_subs_from_recorder(&proxy_server_addr),
                dispatcher: make_dispatcher_subs_from_recorder(&dispatcher_addr),
                hopper: make_hopper_subs_from_recorder(&hopper_addr),
                proxy_client_opt: Some(make_proxy_client_subs_from_recorder(&proxy_client_addr)),
                neighborhood: make_neighborhood_subs_from_recorder(&neighborhood_addr),
                accountant: make_accountant_subs_from_recorder(&accountant_addr),
                ui_gateway: make_ui_gateway_subs_from_recorder(&ui_gateway_addr),
                blockchain_bridge: make_blockchain_bridge_subs_from_recorder(
                    &blockchain_bridge_addr,
                ),
                configurator: make_configurator_subs_from_recorder(&configurator_addr),
            },
            PeerActorAddrs {
                proxy_server_addr,
                dispatcher_addr,
                hopper_addr,
                proxy_client_addr,
                neighborhood_addr,
                accountant_addr,
                ui_gateway_addr,
                blockchain_bridge_addr,
                configurator_addr,
            },
        )
    }

    // This must be called after System.new and before System.run
    pub fn build(self) -> PeerActors {
        let (peer_actors, _) = self.build_and_provide_addresses();
        peer_actors
    }
}

pub struct PeerActorAddrs {
    pub proxy_server_addr: Addr<Recorder>,
    pub dispatcher_addr: Addr<Recorder>,
    pub hopper_addr: Addr<Recorder>,
    pub proxy_client_addr: Addr<Recorder>,
    pub neighborhood_addr: Addr<Recorder>,
    pub accountant_addr: Addr<Recorder>,
    pub ui_gateway_addr: Addr<Recorder>,
    pub blockchain_bridge_addr: Addr<Recorder>,
    pub configurator_addr: Addr<Recorder>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blockchain::blockchain_bridge::BlockchainBridge;
    use crate::sub_lib::neighborhood::{ConfigChange, Hops, WalletPair};
    use crate::test_utils::make_wallet;
    use crate::test_utils::recorder_counter_msgs::SendableCounterMsgWithRecipient;
    use crate::{
        match_lazily_every_type_id, setup_for_counter_msg_triggered_via_specific_msg_id_method,
        setup_for_counter_msg_triggered_via_type_id,
    };
    use actix::Message;
    use actix::System;
    use masq_lib::messages::{
        SerializableLogLevel, ToMessageBody, UiLogBroadcast, UiUnmarshalError,
    };
    use masq_lib::ui_gateway::MessageTarget;
    use std::any::TypeId;
    use std::net::{IpAddr, Ipv4Addr};
    use std::vec;

    #[derive(Debug, PartialEq, Eq, Message)]
    struct FirstMessageType {
        string: String,
    }

    recorder_message_handler_t_m_p!(FirstMessageType);

    #[derive(Debug, PartialEq, Eq, Message)]
    struct SecondMessageType {
        size: usize,
        flag: bool,
    }

    recorder_message_handler_t_m_p!(SecondMessageType);

    #[test]
    fn recorder_records_different_messages() {
        let system = System::new("test");
        let recorder = Recorder::new();
        let recording_arc = recorder.get_recording();

        let rec_addr: Addr<Recorder> = recorder.start();

        rec_addr
            .try_send(FirstMessageType {
                string: String::from("String"),
            })
            .unwrap();
        rec_addr
            .try_send(SecondMessageType {
                size: 42,
                flag: false,
            })
            .unwrap();
        System::current().stop_with_code(0);

        system.run();

        let recording = recording_arc.lock().unwrap();
        assert_eq!(
            recording.get_record::<FirstMessageType>(0),
            &FirstMessageType {
                string: String::from("String")
            }
        );
        assert_eq!(
            recording.get_record::<SecondMessageType>(1),
            &SecondMessageType {
                size: 42,
                flag: false
            }
        );
        assert_eq!(recording.len(), 2);
    }

    #[test]
    fn recorder_can_be_stopped_on_a_particular_message() {
        let system = System::new("recorder_can_be_stopped_on_a_particular_message");
        let recorder =
            Recorder::new().system_stop_conditions(match_lazily_every_type_id!(FirstMessageType));
        let recording_arc = recorder.get_recording();
        let rec_addr: Addr<Recorder> = recorder.start();

        rec_addr
            .try_send(FirstMessageType {
                string: String::from("String"),
            })
            .unwrap();

        system.run();
        let recording = recording_arc.lock().unwrap();
        assert_eq!(
            recording.get_record::<FirstMessageType>(0),
            &FirstMessageType {
                string: String::from("String")
            }
        );
        assert_eq!(recording.len(), 1);
    }

    struct ExampleMsgA;

    struct ExampleMsgB;

    #[test]
    fn different_messages_in_pretending_matchable_have_different_type_ids() {
        assert_eq!(
            TypeId::of::<PretendedMatchableWrapper<ExampleMsgA>>(),
            TypeId::of::<PretendedMatchableWrapper<ExampleMsgA>>()
        );
        assert_ne!(
            TypeId::of::<PretendedMatchableWrapper<ExampleMsgA>>(),
            TypeId::of::<PretendedMatchableWrapper<ExampleMsgB>>()
        )
    }

    #[test]
    fn counter_msgs_with_diff_id_methods_are_used_together_and_one_was_not_triggered() {
        let (respondent, _, respondent_recording_arc) = make_recorder();
        let respondent = respondent.system_stop_conditions(match_lazily_every_type_id!(
            ScanForReceivables,
            NodeToUiMessage
        ));
        let respondent_addr = respondent.start();
        // Case 1
        // This msg will trigger as the recorder will detect the arrival of StartMessage (no more
        // requirement).
        let (trigger_message_1, cm_setup_1) = {
            let trigger_msg = StartMessage {};
            let counter_msg = ScanForReceivables {
                response_skeleton_opt: None,
            };
            // Taking an opportunity to test a setup via the macro for the simplest identification,
            // by the TypeId.
            (
                trigger_msg,
                setup_for_counter_msg_triggered_via_type_id!(
                    StartMessage,
                    counter_msg,
                    &respondent_addr
                ),
            )
        };
        // Case two
        // This msg will not trigger as it is declared with a wrong TypeId of the supposed trigger
        // msg. The supplied ID does not even belong to an Actor msg type.
        let cm_setup_2 = {
            let counter_msg_strayed = StartMessage {};
            let screwed_id = TypeId::of::<BlockchainBridge>();
            let id_method = MsgIdentification::ByType(screwed_id);
            SingleTypeCounterMsgSetup::new(
                screwed_id,
                id_method,
                vec![Box::new(SendableCounterMsgWithRecipient::new(
                    counter_msg_strayed,
                    respondent_addr.clone().recipient(),
                ))],
            )
        };
        // Case three
        // This msg will not trigger as it is declared to have to be matched entirely (The message
        // type, plus the data of the message). The expected msg and the actual sent msg bear
        // different IP addresses.
        let (trigger_msg_3_unmatching, cm_setup_3) = {
            let trigger_msg = NewPublicIp {
                new_ip: IpAddr::V4(Ipv4Addr::new(7, 7, 7, 7)),
            };
            let type_id = trigger_msg.type_id();
            let counter_msg = NodeToUiMessage {
                target: MessageTarget::ClientId(4),
                body: UiUnmarshalError {
                    message: "abc".to_string(),
                    bad_data: "456".to_string(),
                }
                .tmb(0),
            };
            let id_method = MsgIdentification::ByMatch {
                exemplar: Box::new(NewPublicIp {
                    new_ip: IpAddr::V4(Ipv4Addr::new(7, 6, 5, 4)),
                }),
            };
            (
                trigger_msg,
                SingleTypeCounterMsgSetup::new(
                    type_id,
                    id_method,
                    vec![Box::new(SendableCounterMsgWithRecipient::new(
                        counter_msg,
                        respondent_addr.clone().recipient(),
                    ))],
                ),
            )
        };
        // Case four
        // This msg will trigger as the performed msg is an exact match of the expected msg.
        let (trigger_msg_4_matching, cm_setup_4, counter_msg_4) = {
            let trigger_msg = NewPublicIp {
                new_ip: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            };
            let msg_type_id = trigger_msg.type_id();
            let counter_msg = NodeToUiMessage {
                target: MessageTarget::ClientId(234),
                body: UiLogBroadcast {
                    msg: "Good one".to_string(),
                    log_level: SerializableLogLevel::Error,
                }
                .tmb(0),
            };
            let id_method = MsgIdentification::ByMatch {
                exemplar: Box::new(trigger_msg.clone()),
            };
            (
                trigger_msg,
                SingleTypeCounterMsgSetup::new(
                    msg_type_id,
                    id_method,
                    vec![Box::new(SendableCounterMsgWithRecipient::new(
                        counter_msg.clone(),
                        respondent_addr.clone().recipient(),
                    ))],
                ),
                counter_msg,
            )
        };
        let system = System::new("test");
        let (subject, _, subject_recording_arc) = make_recorder();
        let subject_addr = subject.start();
        // Supplying messages deliberately in a tangled manner to express that the mechanism is
        // robust enough to compensate for it.
        // This works because we don't supply overlapping setups, such as that could apply to
        // a single trigger msg.
        subject_addr
            .try_send(SetUpCounterMsgs {
                setups: vec![cm_setup_3, cm_setup_1, cm_setup_2, cm_setup_4],
            })
            .unwrap();

        subject_addr.try_send(trigger_message_1).unwrap();
        subject_addr
            .try_send(trigger_msg_3_unmatching.clone())
            .unwrap();
        subject_addr
            .try_send(trigger_msg_4_matching.clone())
            .unwrap();

        system.run();
        // Actual counter-messages that flew in this test
        let respondent_recording = respondent_recording_arc.lock().unwrap();
        let _first_counter_msg_recorded = respondent_recording.get_record::<ScanForReceivables>(0);
        let second_counter_msg_recorded = respondent_recording.get_record::<NodeToUiMessage>(1);
        assert_eq!(second_counter_msg_recorded, &counter_msg_4);
        assert_eq!(respondent_recording.len(), 2);
        // Recorded trigger messages
        let subject_recording = subject_recording_arc.lock().unwrap();
        let _first_recorded_trigger_msg = subject_recording.get_record::<StartMessage>(0);
        let second_recorded_trigger_msg = subject_recording.get_record::<NewPublicIp>(1);
        assert_eq!(second_recorded_trigger_msg, &trigger_msg_3_unmatching);
        let third_recorded_trigger_msg = subject_recording.get_record::<NewPublicIp>(2);
        assert_eq!(third_recorded_trigger_msg, &trigger_msg_4_matching);
        assert_eq!(subject_recording.len(), 3)
    }

    #[test]
    fn counter_msgs_evaluate_lazily_so_the_msgs_with_the_same_triggers_are_eliminated_sequentially()
    {
        // This test demonstrates the need for caution in setups where multiple messages are sent
        // at different times and should be responded to by different counter-messages. However,
        // the trigger methods of these setups also apply to each other. Which setup gets
        // triggered depends purely on the order used to supply them to the recorder
        // in SetUpCounterMsgs.

        // Notice that three of the messages share the same data type, with one additional message
        // serving a special purpose in assertions. Two of the three use only TypeId for
        // identification. This already requires greater caution since you probably need the three
        // messages to be dispatched in a specific sequence. However, this wasn't considered
        // properly and, as you can see in the test, the trigger messages aren't sent in the same
        // order as the counter-message setups were supplied.

        // This results in an inevitable mismatch. The first counter-message that was sent should
        // have belonged to the second trigger message, but was triggered by the third trigger
        // message (which actually introduces the test). Similarly, the second trigger message
        // activates a message rightfully meant for the first trigger message. To complete
        // the picture, even the first trigger message is matched with the third counter-message.

        // This shows how important it is to avoid ambiguous setups. When operating with multiple
        // calls of the same typed message as triggers, it is highly recommended not to use
        // MsgIdentification::ByTypeId but to use more specific, unmistakable settings instead:
        // MsgIdentification::ByMatch or MsgIdentification::ByPredicate.
        let (respondent, _, respondent_recording_arc) = make_recorder();
        let respondent = respondent.system_stop_conditions(match_lazily_every_type_id!(
            ConfigChangeMsg,
            ConfigChangeMsg,
            ConfigChangeMsg
        ));
        let respondent_addr = respondent.start();
        // Case 1
        let (trigger_msg_1, cm_setup_1) = {
            let trigger_msg = CrashNotification {
                process_id: 7777777,
                exit_code: None,
                stderr: Some("blah".to_string()),
            };
            let counter_msg = ConfigChangeMsg {
                change: ConfigChange::UpdateMinHops(Hops::SixHops),
            };
            let id_method = MsgIdentification::ByPredicate {
                predicate: Box::new(|msg_boxed| {
                    let msg = msg_boxed.downcast_ref::<CrashNotification>().unwrap();
                    msg.process_id == 1010
                }),
            };
            (
                trigger_msg,
                // Taking an opportunity to test a setup via the macro allowing more specific
                // identification methods.
                setup_for_counter_msg_triggered_via_specific_msg_id_method!(
                    CrashNotification,
                    id_method,
                    counter_msg,
                    &respondent_addr
                ),
            )
        };
        // Case two
        let (trigger_msg_2, cm_setup_2) = {
            let trigger_msg = CrashNotification {
                process_id: 1010,
                exit_code: Some(11),
                stderr: None,
            };
            let counter_msg = ConfigChangeMsg {
                change: ConfigChange::UpdatePassword("betterPassword".to_string()),
            };
            (
                trigger_msg,
                setup_for_counter_msg_triggered_via_type_id!(
                    CrashNotification,
                    counter_msg,
                    &respondent_addr
                ),
            )
        };
        // Case three
        let (trigger_msg_3, cm_setup_3) = {
            let trigger_msg = CrashNotification {
                process_id: 9999999,
                exit_code: None,
                stderr: None,
            };
            let counter_msg = ConfigChangeMsg {
                change: ConfigChange::UpdateWallets(WalletPair {
                    consuming_wallet: make_wallet("abc"),
                    earning_wallet: make_wallet("def"),
                }),
            };
            (
                trigger_msg,
                setup_for_counter_msg_triggered_via_type_id!(
                    CrashNotification,
                    counter_msg,
                    &respondent_addr
                ),
            )
        };
        // Case four
        let (trigger_msg_4, cm_setup_4) = {
            let trigger_msg = StartMessage {};
            let counter_msg = ScanForReceivables {
                response_skeleton_opt: None,
            };
            (
                trigger_msg,
                setup_for_counter_msg_triggered_via_type_id!(
                    StartMessage,
                    counter_msg,
                    &respondent_addr
                ),
            )
        };
        let system = System::new("test");
        let (subject, _, subject_recording_arc) = make_recorder();
        let subject_addr = subject.start();
        // Adding messages in standard order
        subject_addr
            .try_send(SetUpCounterMsgs {
                setups: vec![cm_setup_1, cm_setup_2, cm_setup_3, cm_setup_4],
            })
            .unwrap();

        // Now the fun begins, the trigger messages are shuffled
        subject_addr.try_send(trigger_msg_3.clone()).unwrap();
        // The fourth message demonstrates that the previous trigger didn't activate two messages
        // at once, even though this trigger actually matches two different setups. This shows
        // that each trigger can only be matched with one setup at a time, consuming it. If you
        // want to trigger multiple messages in response, you must configure that setup with
        // multiple counter-messages (a one-to-many scenario).
        subject_addr.try_send(trigger_msg_4.clone()).unwrap();
        subject_addr.try_send(trigger_msg_2.clone()).unwrap();
        subject_addr.try_send(trigger_msg_1.clone()).unwrap();

        system.run();
        // Actual counter-messages that flew in this test
        let respondent_recording = respondent_recording_arc.lock().unwrap();
        let first_counter_msg_recorded = respondent_recording.get_record::<ConfigChangeMsg>(0);
        assert_eq!(
            first_counter_msg_recorded.change,
            ConfigChange::UpdatePassword("betterPassword".to_string())
        );
        let _ = respondent_recording.get_record::<ScanForReceivables>(1);
        let third_counter_msg_recorded = respondent_recording.get_record::<ConfigChangeMsg>(2);
        assert_eq!(
            third_counter_msg_recorded.change,
            ConfigChange::UpdateMinHops(Hops::SixHops)
        );
        let fourth_counter_msg_recorded = respondent_recording.get_record::<ConfigChangeMsg>(3);
        assert_eq!(
            fourth_counter_msg_recorded.change,
            ConfigChange::UpdateWallets(WalletPair {
                consuming_wallet: make_wallet("abc"),
                earning_wallet: make_wallet("def")
            })
        );
        assert_eq!(respondent_recording.len(), 4);
        // Recorded trigger messages
        let subject_recording = subject_recording_arc.lock().unwrap();
        let first_recorded_trigger_msg = subject_recording.get_record::<CrashNotification>(0);
        assert_eq!(first_recorded_trigger_msg, &trigger_msg_3);
        let second_recorded_trigger_msg = subject_recording.get_record::<StartMessage>(1);
        assert_eq!(second_recorded_trigger_msg, &trigger_msg_4);
        let third_recorded_trigger_msg = subject_recording.get_record::<CrashNotification>(2);
        assert_eq!(third_recorded_trigger_msg, &trigger_msg_2);
        let fourth_recorded_trigger_msg = subject_recording.get_record::<CrashNotification>(3);
        assert_eq!(fourth_recorded_trigger_msg, &trigger_msg_1);
        assert_eq!(subject_recording.len(), 4)
    }
}
