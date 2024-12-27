// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
#![cfg(test)]
use crate::accountant::{ConsumingWalletBalancesAndQualifiedPayables, ReportTransactionReceipts};
use crate::accountant::{
    ReceivedPayments, RequestTransactionReceipts, ScanError, ScanForPayables,
    ScanForPendingPayables, ScanForReceivables, SentPayables,
};
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
use crate::sub_lib::blockchain_bridge::ReportAccountsPayable;
use crate::sub_lib::blockchain_bridge::{BlockchainBridgeSubs, RequestBalancesToPayPayables};
use crate::sub_lib::configurator::{ConfiguratorSubs, NewPasswordMessage};
use crate::sub_lib::dispatcher::InboundClientData;
use crate::sub_lib::dispatcher::{DispatcherSubs, StreamShutdownMsg};
use crate::sub_lib::hopper::IncipientCoresPackage;
use crate::sub_lib::hopper::{ExpiredCoresPackage, NoLookupIncipientCoresPackage};
use crate::sub_lib::hopper::{HopperSubs, MessageType};
use crate::sub_lib::neighborhood::ConnectionProgressMessage;
use crate::sub_lib::neighborhood::NeighborhoodSubs;

use crate::sub_lib::neighborhood::NodeQueryResponseMetadata;
use crate::sub_lib::neighborhood::NodeRecordMetadataMessage;
use crate::sub_lib::neighborhood::RemoveNeighborMessage;
use crate::sub_lib::neighborhood::RouteQueryMessage;
use crate::sub_lib::neighborhood::RouteQueryResponse;
use crate::sub_lib::neighborhood::{DispatcherNodeQueryMessage, GossipFailure_0v1};
use crate::sub_lib::peer_actors::PeerActors;
use crate::sub_lib::peer_actors::{BindMessage, NewPublicIp, StartMessage};
use crate::sub_lib::proxy_client::{ClientResponsePayload_0v1, InboundServerData};
use crate::sub_lib::proxy_client::{DnsResolveFailure_0v1, ProxyClientSubs};
use crate::sub_lib::proxy_server::ProxyServerSubs;
use crate::sub_lib::proxy_server::{
    AddReturnRouteMessage, AddRouteMessage, ClientRequestPayload_0v1,
};
use crate::sub_lib::set_consuming_wallet_message::SetConsumingWalletMessage;
use crate::sub_lib::stream_handler_pool::DispatcherNodeQueryResponse;
use crate::sub_lib::stream_handler_pool::TransmitDataMsg;
use crate::sub_lib::ui_gateway::UiGatewaySubs;
use crate::sub_lib::utils::MessageScheduler;
use crate::proxy_client::stream_handler_pool_new::{AddStreamPair, DataReadError, DataReadSuccess, DataWriteError, DataWriteSuccess, KillStream, StreamCreationError};
use crate::test_utils::recorder_stop_conditions::StopConditions;
use crate::test_utils::to_millis;
use crate::test_utils::unshared_test_utils::system_killer_actor::SystemKillerActor;
use actix::Addr;
use actix::Context;
use actix::Handler;
use actix::MessageResult;
use actix::System;
use actix::{Actor, Message};
use masq_lib::ui_gateway::{NodeFromUiMessage, NodeToUiMessage};
use std::any::Any;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use std::time::Instant;

#[derive(Default)]
pub struct Recorder {
    recording: Arc<Mutex<Recording>>,
    node_query_responses: Vec<Option<NodeQueryResponseMetadata>>,
    route_query_responses: Vec<Option<RouteQueryResponse>>,
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

macro_rules! recorder_message_handler {
    ($message_type: ty) => {
        impl Handler<$message_type> for Recorder {
            type Result = ();

            fn handle(&mut self, msg: $message_type, _ctx: &mut Self::Context) {
                self.handle_msg(msg)
            }
        }
    };
}

recorder_message_handler!(AddReturnRouteMessage);
recorder_message_handler!(AddRouteMessage);
recorder_message_handler!(AddStreamMsg);
recorder_message_handler!(AddStreamPair);
recorder_message_handler!(BindMessage);
recorder_message_handler!(CrashNotification);
recorder_message_handler!(DataReadError);
recorder_message_handler!(DataReadSuccess);
recorder_message_handler!(DataWriteError);
recorder_message_handler!(DataWriteSuccess);
recorder_message_handler!(DaemonBindMessage);
recorder_message_handler!(DispatcherNodeQueryMessage);
recorder_message_handler!(DispatcherNodeQueryResponse);
recorder_message_handler!(DnsResolveFailure_0v1);
recorder_message_handler!(ExpiredCoresPackage<ClientRequestPayload_0v1>);
recorder_message_handler!(ExpiredCoresPackage<ClientResponsePayload_0v1>);
recorder_message_handler!(ExpiredCoresPackage<DnsResolveFailure_0v1>);
recorder_message_handler!(ExpiredCoresPackage<Gossip_0v1>);
recorder_message_handler!(ExpiredCoresPackage<GossipFailure_0v1>);
recorder_message_handler!(ExpiredCoresPackage<MessageType>);
recorder_message_handler!(InboundClientData);
recorder_message_handler!(InboundServerData);
recorder_message_handler!(IncipientCoresPackage);
recorder_message_handler!(KillStream);
recorder_message_handler!(NewPasswordMessage);
recorder_message_handler!(NewPublicIp);
recorder_message_handler!(NodeFromUiMessage);
recorder_message_handler!(NodeToUiMessage);
recorder_message_handler!(NodeRecordMetadataMessage);
recorder_message_handler!(NoLookupIncipientCoresPackage);
recorder_message_handler!(PoolBindMessage);
recorder_message_handler!(ReceivedPayments);
recorder_message_handler!(RemoveNeighborMessage);
recorder_message_handler!(RemoveStreamMsg);
recorder_message_handler!(ReportServicesConsumedMessage);
recorder_message_handler!(ReportExitServiceProvidedMessage);
recorder_message_handler!(ReportRoutingServiceProvidedMessage);
recorder_message_handler!(ScanError);
recorder_message_handler!(StreamCreationError);
recorder_message_handler!(ConsumingWalletBalancesAndQualifiedPayables);
recorder_message_handler!(SentPayables);
recorder_message_handler!(SetConsumingWalletMessage);
recorder_message_handler!(RequestBalancesToPayPayables);
recorder_message_handler!(StartMessage);
recorder_message_handler!(StreamShutdownMsg);
recorder_message_handler!(TransmitDataMsg);
recorder_message_handler!(PendingPayableFingerprintSeeds);
recorder_message_handler!(RetrieveTransactions);
recorder_message_handler!(RequestTransactionReceipts);
recorder_message_handler!(ReportTransactionReceipts);
recorder_message_handler!(ReportAccountsPayable);
recorder_message_handler!(ScanForReceivables);
recorder_message_handler!(ScanForPayables);
recorder_message_handler!(ConnectionProgressMessage);
recorder_message_handler!(ScanForPendingPayables);

impl<M> Handler<MessageScheduler<M>> for Recorder
where
    M: Message + PartialEq + Send + 'static,
{
    type Result = ();

    fn handle(&mut self, msg: MessageScheduler<M>, _ctx: &mut Self::Context) {
        self.handle_msg(msg)
    }
}

impl Handler<RouteQueryMessage> for Recorder {
    type Result = MessageResult<RouteQueryMessage>;

    fn handle(
        &mut self,
        msg: RouteQueryMessage,
        _ctx: &mut Self::Context,
    ) -> <Self as Handler<RouteQueryMessage>>::Result {
        self.record(msg);
        MessageResult(extract_response(
            &mut self.route_query_responses,
            "No RouteQueryResponses prepared for RouteQueryMessage",
        ))
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
            panic!("Stop conditions must be set by a single method call. Consider to use StopConditions::All")
        };
        self
    }

    fn start_system_killer(&mut self) {
        let system_killer = SystemKillerActor::new(Duration::from_secs(15));
        system_killer.start();
    }

    fn handle_msg<T: 'static + PartialEq + Send>(&mut self, msg: T) {
        let kill_system = if let Some(stop_conditions) = &mut self.stop_conditions_opt {
            stop_conditions.resolve_stop_conditions::<T>(&msg)
        } else {
            false
        };

        self.record(msg);

        if kill_system {
            System::current().stop()
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

    pub fn get_clone<T: Any + Send + Clone + Message>(
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

    fn get_record_inner_body<T: 'static>(&self, index: usize) -> Result<&T, String> {
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
        let item_opt = item_box.downcast_ref::<T>();

        match item_opt {
            Some(item) => Ok(item),
            None => Err(format!(
                "Message {:?} could not be downcast to the expected type",
                item_box
            )),
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

pub fn make_recorder() -> (Recorder, RecordAwaiter, Arc<Mutex<Recording>>) {
    let recorder = Recorder::new();
    let awaiter = recorder.get_awaiter();
    let recording_arc = recorder.get_recording();
    (recorder, awaiter, recording_arc)
}

pub fn make_proxy_server_subs_from(addr: &Addr<Recorder>) -> ProxyServerSubs {
    ProxyServerSubs {
        bind: recipient!(addr, BindMessage),
        from_dispatcher: recipient!(addr, InboundClientData),
        from_hopper: recipient!(addr, ExpiredCoresPackage<ClientResponsePayload_0v1>),
        dns_failure_from_hopper: recipient!(addr, ExpiredCoresPackage<DnsResolveFailure_0v1>),
        add_return_route: recipient!(addr, AddReturnRouteMessage),
        add_route: recipient!(addr, AddRouteMessage),
        stream_shutdown_sub: recipient!(addr, StreamShutdownMsg),
        set_consuming_wallet_sub: recipient!(addr, SetConsumingWalletMessage),
        node_from_ui: recipient!(addr, NodeFromUiMessage),
    }
}

pub fn make_dispatcher_subs_from(addr: &Addr<Recorder>) -> DispatcherSubs {
    DispatcherSubs {
        ibcd_sub: recipient!(addr, InboundClientData),
        bind: recipient!(addr, BindMessage),
        from_dispatcher_client: recipient!(addr, TransmitDataMsg),
        stream_shutdown_sub: recipient!(addr, StreamShutdownMsg),
        ui_sub: recipient!(addr, NodeFromUiMessage),
        new_ip_sub: recipient!(addr, NewPublicIp),
    }
}

pub fn make_hopper_subs_from(addr: &Addr<Recorder>) -> HopperSubs {
    HopperSubs {
        bind: recipient!(addr, BindMessage),
        from_hopper_client: recipient!(addr, IncipientCoresPackage),
        from_hopper_client_no_lookup: recipient!(addr, NoLookupIncipientCoresPackage),
        from_dispatcher: recipient!(addr, InboundClientData),
        node_from_ui: recipient!(addr, NodeFromUiMessage),
    }
}

pub fn make_proxy_client_subs_from(addr: &Addr<Recorder>) -> ProxyClientSubs {
    ProxyClientSubs {
        bind: recipient!(addr, BindMessage),
        from_hopper: recipient!(addr, ExpiredCoresPackage<ClientRequestPayload_0v1>),
        inbound_server_data: recipient!(addr, InboundServerData),
        dns_resolve_failed: recipient!(addr, DnsResolveFailure_0v1),
        node_from_ui: recipient!(addr, NodeFromUiMessage),
    }
}

pub fn make_neighborhood_subs_from(addr: &Addr<Recorder>) -> NeighborhoodSubs {
    NeighborhoodSubs {
        bind: recipient!(addr, BindMessage),
        start: recipient!(addr, StartMessage),
        new_public_ip: recipient!(addr, NewPublicIp),
        route_query: recipient!(addr, RouteQueryMessage),
        update_node_record_metadata: recipient!(addr, NodeRecordMetadataMessage),
        from_hopper: recipient!(addr, ExpiredCoresPackage<Gossip_0v1>),
        gossip_failure: recipient!(addr, ExpiredCoresPackage<GossipFailure_0v1>),
        dispatcher_node_query: recipient!(addr, DispatcherNodeQueryMessage),
        remove_neighbor: recipient!(addr, RemoveNeighborMessage),
        stream_shutdown_sub: recipient!(addr, StreamShutdownMsg),
        set_consuming_wallet_sub: recipient!(addr, SetConsumingWalletMessage),
        from_ui_message_sub: recipient!(addr, NodeFromUiMessage),
        new_password_sub: recipient!(addr, NewPasswordMessage),
        connection_progress_sub: recipient!(addr, ConnectionProgressMessage),
    }
}

pub fn make_accountant_subs_from_recorder(addr: &Addr<Recorder>) -> AccountantSubs {
    AccountantSubs {
        bind: recipient!(addr, BindMessage),
        start: recipient!(addr, StartMessage),
        report_routing_service_provided: recipient!(addr, ReportRoutingServiceProvidedMessage),
        report_exit_service_provided: recipient!(addr, ReportExitServiceProvidedMessage),
        report_services_consumed: recipient!(addr, ReportServicesConsumedMessage),
        report_consuming_wallet_balances_and_qualified_payables: recipient!(
            addr,
            ConsumingWalletBalancesAndQualifiedPayables
        ),
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

pub fn make_blockchain_bridge_subs_from(addr: &Addr<Recorder>) -> BlockchainBridgeSubs {
    BlockchainBridgeSubs {
        bind: recipient!(addr, BindMessage),
        report_accounts_payable: recipient!(addr, ReportAccountsPayable),
        request_balances_to_pay_payables: recipient!(addr, RequestBalancesToPayPayables),
        retrieve_transactions: recipient!(addr, RetrieveTransactions),
        ui_sub: recipient!(addr, NodeFromUiMessage),
        request_transaction_receipts: recipient!(addr, RequestTransactionReceipts),
    }
}

pub fn make_configurator_subs_from(addr: &Addr<Recorder>) -> ConfiguratorSubs {
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

    // This must be called after System.new and before System.run
    pub fn build(self) -> PeerActors {
        let proxy_server_addr = self.proxy_server.start();
        let dispatcher_addr = self.dispatcher.start();
        let hopper_addr = self.hopper.start();
        let proxy_client_addr = self.proxy_client.start();
        let neighborhood_addr = self.neighborhood.start();
        let accountant_addr = self.accountant.start();
        let ui_gateway_addr = self.ui_gateway.start();
        let blockchain_bridge_addr = self.blockchain_bridge.start();
        let configurator_addr = self.configurator.start();

        PeerActors {
            proxy_server: make_proxy_server_subs_from(&proxy_server_addr),
            dispatcher: make_dispatcher_subs_from(&dispatcher_addr),
            hopper: make_hopper_subs_from(&hopper_addr),
            proxy_client_opt: Some(make_proxy_client_subs_from(&proxy_client_addr)),
            neighborhood: make_neighborhood_subs_from(&neighborhood_addr),
            accountant: make_accountant_subs_from_recorder(&accountant_addr),
            ui_gateway: make_ui_gateway_subs_from_recorder(&ui_gateway_addr),
            blockchain_bridge: make_blockchain_bridge_subs_from(&blockchain_bridge_addr),
            configurator: make_configurator_subs_from(&configurator_addr),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix::Message;
    use actix::System;

    #[derive(Debug, PartialEq, Eq, Message)]
    #[rtype(result = "()")]
    struct FirstMessageType {
        string: String,
    }

    recorder_message_handler!(FirstMessageType);

    #[derive(Debug, PartialEq, Eq, Message)]
    #[rtype(result = "()")]
    struct SecondMessageType {
        size: usize,
        flag: bool,
    }

    recorder_message_handler!(SecondMessageType);

    #[test]
    fn recorder_records_different_messages() {
        let system = System::new();
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
}
