// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use crate::accountant::payable_dao::Payment;
use crate::accountant::{ReceivedPayments, SentPayments};
use crate::blockchain::blockchain_bridge::RetrieveTransactions;
use crate::blockchain::blockchain_interface::{BlockchainError, BlockchainResult, Transaction};
use crate::daemon::crash_notification::CrashNotification;
use crate::daemon::DaemonBindMessage;
use crate::neighborhood::gossip::Gossip_0v1;
use crate::stream_messages::{AddStreamMsg, PoolBindMessage, RemoveStreamMsg};
use crate::sub_lib::accountant::ReportExitServiceConsumedMessage;
use crate::sub_lib::accountant::ReportExitServiceProvidedMessage;
use crate::sub_lib::accountant::ReportRoutingServiceConsumedMessage;
use crate::sub_lib::accountant::ReportRoutingServiceProvidedMessage;
use crate::sub_lib::accountant::{AccountantSubs, GetFinancialStatisticsMessage};
use crate::sub_lib::blockchain_bridge::{BlockchainBridgeSubs, SetDbPasswordMsg};
use crate::sub_lib::blockchain_bridge::{ReportAccountsPayable, SetGasPriceMsg};
use crate::sub_lib::dispatcher::InboundClientData;
use crate::sub_lib::dispatcher::{DispatcherSubs, StreamShutdownMsg};
use crate::sub_lib::hopper::IncipientCoresPackage;
use crate::sub_lib::hopper::{ExpiredCoresPackage, NoLookupIncipientCoresPackage};
use crate::sub_lib::hopper::{HopperSubs, MessageType};
use crate::sub_lib::neighborhood::NeighborhoodDotGraphRequest;
use crate::sub_lib::neighborhood::NeighborhoodSubs;
use crate::sub_lib::neighborhood::NodeQueryMessage;
use crate::sub_lib::neighborhood::NodeQueryResponseMetadata;
use crate::sub_lib::neighborhood::NodeRecordMetadataMessage;
use crate::sub_lib::neighborhood::RemoveNeighborMessage;
use crate::sub_lib::neighborhood::RouteQueryMessage;
use crate::sub_lib::neighborhood::RouteQueryResponse;
use crate::sub_lib::neighborhood::{DispatcherNodeQueryMessage, GossipFailure_0v1};
use crate::sub_lib::peer_actors::PeerActors;
use crate::sub_lib::peer_actors::{BindMessage, StartMessage};
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
use crate::sub_lib::ui_gateway::{FromUiMessage, UiCarrierMessage};
use crate::test_utils::to_millis;
use actix::Actor;
use actix::Addr;
use actix::Context;
use actix::Handler;
use actix::MessageResult;
use masq_lib::ui_gateway::{NodeFromUiMessage, NodeToUiMessage};
use std::any::Any;
use std::sync::Arc;
use std::sync::Mutex;
use std::thread;
use std::time::Duration;
use std::time::Instant;

#[derive(Default)]
pub struct Recorder {
    recording: Arc<Mutex<Recording>>,
    node_query_responses: Vec<Option<NodeQueryResponseMetadata>>,
    route_query_responses: Vec<Option<RouteQueryResponse>>,
    retrieve_transactions_responses: Vec<Result<Vec<Transaction>, BlockchainError>>,
    report_accounts_payable_responses: Vec<Result<Vec<BlockchainResult<Payment>>, String>>,
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
                self.record(msg);
            }
        }
    };
}

recorder_message_handler!(AddReturnRouteMessage);
recorder_message_handler!(AddRouteMessage);
recorder_message_handler!(AddStreamMsg);
recorder_message_handler!(BindMessage);
recorder_message_handler!(CrashNotification);
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
recorder_message_handler!(FromUiMessage);
recorder_message_handler!(GetFinancialStatisticsMessage);
recorder_message_handler!(InboundClientData);
recorder_message_handler!(InboundServerData);
recorder_message_handler!(IncipientCoresPackage);
recorder_message_handler!(NeighborhoodDotGraphRequest);
recorder_message_handler!(NodeFromUiMessage);
recorder_message_handler!(NodeToUiMessage);
recorder_message_handler!(NodeRecordMetadataMessage);
recorder_message_handler!(NoLookupIncipientCoresPackage);
recorder_message_handler!(PoolBindMessage);
recorder_message_handler!(ReceivedPayments);
recorder_message_handler!(RemoveNeighborMessage);
recorder_message_handler!(RemoveStreamMsg);
recorder_message_handler!(ReportExitServiceConsumedMessage);
recorder_message_handler!(ReportExitServiceProvidedMessage);
recorder_message_handler!(ReportRoutingServiceConsumedMessage);
recorder_message_handler!(ReportRoutingServiceProvidedMessage);
recorder_message_handler!(SentPayments);
recorder_message_handler!(SetConsumingWalletMessage);
recorder_message_handler!(SetDbPasswordMsg);
recorder_message_handler!(SetGasPriceMsg);
recorder_message_handler!(StartMessage);
recorder_message_handler!(StreamShutdownMsg);
recorder_message_handler!(TransmitDataMsg);
recorder_message_handler!(UiCarrierMessage);

impl Handler<NodeQueryMessage> for Recorder {
    type Result = MessageResult<NodeQueryMessage>;

    fn handle(
        &mut self,
        msg: NodeQueryMessage,
        _ctx: &mut Self::Context,
    ) -> <Self as Handler<NodeQueryMessage>>::Result {
        self.record(msg);
        MessageResult(extract_response(
            &mut self.node_query_responses,
            "No NodeDescriptors prepared for NodeQueryMessage",
        ))
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

impl Handler<RetrieveTransactions> for Recorder {
    type Result = MessageResult<RetrieveTransactions>;

    fn handle(
        &mut self,
        msg: RetrieveTransactions,
        _ctx: &mut Self::Context,
    ) -> <Self as Handler<RetrieveTransactions>>::Result {
        self.record(msg);
        MessageResult(extract_response(
            &mut self.retrieve_transactions_responses,
            "No RetrieveTransactionsResponses prepared for RetrieveTransactions",
        ))
    }
}

impl Handler<ReportAccountsPayable> for Recorder {
    type Result = MessageResult<ReportAccountsPayable>;

    fn handle(
        &mut self,
        msg: ReportAccountsPayable,
        _ctx: &mut Self::Context,
    ) -> <Self as Handler<ReportAccountsPayable>>::Result {
        self.record(msg);
        MessageResult(extract_response(
            &mut self.report_accounts_payable_responses,
            "No ReportAccountsPayableResponses prepared for ReportAccountsPayable",
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

    pub fn retrieve_transactions_response(
        mut self,
        response: Result<Vec<Transaction>, BlockchainError>,
    ) -> Recorder {
        self.retrieve_transactions_responses.push(response);
        self
    }

    pub fn report_accounts_payable_response(
        mut self,
        response: Result<Vec<BlockchainResult<Payment>>, String>,
    ) -> Recorder {
        self.report_accounts_payable_responses.push(response);
        self
    }
}

impl Recording {
    pub fn len(&self) -> usize {
        self.messages.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn get<T: Any + Send + Clone>(recording_arc: &Arc<Mutex<Recording>>, index: usize) -> T {
        let recording_arc_clone = recording_arc.clone();
        let recording = recording_arc_clone.lock().unwrap();
        recording.get_record::<T>(index).clone()
    }

    pub fn get_record<T>(&self, index: usize) -> &T
    where
        T: Any + Send,
    {
        let item_box = match self.messages.get(index) {
            Some(item_box) => item_box,
            None => panic!(
                "Only {} messages recorded: no message #{} in the recording",
                self.messages.len(),
                index
            ),
        };
        let item_opt = item_box.downcast_ref::<T>();

        match item_opt {
            Some(item) => item,
            None => panic!(
                "Message {:?} could not be downcast to the expected type",
                item_box
            ),
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
    let recording = recorder.get_recording();
    (recorder, awaiter, recording)
}

pub fn make_proxy_server_subs_from(addr: &Addr<Recorder>) -> ProxyServerSubs {
    ProxyServerSubs {
        bind: recipient!(addr, BindMessage),
        from_dispatcher: recipient!(addr, InboundClientData),
        from_hopper: addr
            .clone()
            .recipient::<ExpiredCoresPackage<ClientResponsePayload_0v1>>(),
        dns_failure_from_hopper: addr
            .clone()
            .recipient::<ExpiredCoresPackage<DnsResolveFailure_0v1>>(),
        add_return_route: recipient!(addr, AddReturnRouteMessage),
        add_route: recipient!(addr, AddRouteMessage),
        stream_shutdown_sub: recipient!(addr, StreamShutdownMsg),
        set_consuming_wallet_sub: recipient!(addr, SetConsumingWalletMessage),
    }
}

pub fn make_dispatcher_subs_from(addr: &Addr<Recorder>) -> DispatcherSubs {
    DispatcherSubs {
        ibcd_sub: recipient!(addr, InboundClientData),
        bind: recipient!(addr, BindMessage),
        from_dispatcher_client: recipient!(addr, TransmitDataMsg),
        stream_shutdown_sub: recipient!(addr, StreamShutdownMsg),
        ui_sub: recipient!(addr, NodeFromUiMessage),
    }
}

pub fn make_hopper_subs_from(addr: &Addr<Recorder>) -> HopperSubs {
    HopperSubs {
        bind: recipient!(addr, BindMessage),
        from_hopper_client: recipient!(addr, IncipientCoresPackage),
        from_hopper_client_no_lookup: recipient!(addr, NoLookupIncipientCoresPackage),
        from_dispatcher: recipient!(addr, InboundClientData),
    }
}

pub fn make_proxy_client_subs_from(addr: &Addr<Recorder>) -> ProxyClientSubs {
    ProxyClientSubs {
        bind: recipient!(addr, BindMessage),
        from_hopper: addr
            .clone()
            .recipient::<ExpiredCoresPackage<ClientRequestPayload_0v1>>(),
        inbound_server_data: recipient!(addr, InboundServerData),
        dns_resolve_failed: recipient!(addr, DnsResolveFailure_0v1),
    }
}

pub fn make_neighborhood_subs_from(addr: &Addr<Recorder>) -> NeighborhoodSubs {
    NeighborhoodSubs {
        bind: recipient!(addr, BindMessage),
        start: recipient!(addr, StartMessage),
        node_query: recipient!(addr, NodeQueryMessage),
        route_query: recipient!(addr, RouteQueryMessage),
        update_node_record_metadata: recipient!(addr, NodeRecordMetadataMessage),
        from_hopper: addr.clone().recipient::<ExpiredCoresPackage<Gossip_0v1>>(),
        gossip_failure: addr
            .clone()
            .recipient::<ExpiredCoresPackage<GossipFailure_0v1>>(),
        dispatcher_node_query: recipient!(addr, DispatcherNodeQueryMessage),
        remove_neighbor: recipient!(addr, RemoveNeighborMessage),
        stream_shutdown_sub: recipient!(addr, StreamShutdownMsg),
        set_consuming_wallet_sub: recipient!(addr, SetConsumingWalletMessage),
        from_ui_gateway: addr.clone().recipient::<NeighborhoodDotGraphRequest>(),
        from_ui_message_sub: addr.clone().recipient::<NodeFromUiMessage>(),
    }
}

pub fn make_accountant_subs_from(addr: &Addr<Recorder>) -> AccountantSubs {
    AccountantSubs {
        bind: recipient!(addr, BindMessage),
        start: recipient!(addr, StartMessage),
        report_routing_service_provided: addr
            .clone()
            .recipient::<ReportRoutingServiceProvidedMessage>(),
        report_exit_service_provided: recipient!(addr, ReportExitServiceProvidedMessage),
        report_routing_service_consumed: addr
            .clone()
            .recipient::<ReportRoutingServiceConsumedMessage>(),
        report_exit_service_consumed: recipient!(addr, ReportExitServiceConsumedMessage),
        report_new_payments: recipient!(addr, ReceivedPayments),
        report_sent_payments: recipient!(addr, SentPayments),
        get_financial_statistics_sub: recipient!(addr, GetFinancialStatisticsMessage),
        ui_message_sub: recipient!(addr, NodeFromUiMessage),
    }
}

pub fn make_ui_gateway_subs_from(addr: &Addr<Recorder>) -> UiGatewaySubs {
    UiGatewaySubs {
        bind: recipient!(addr, BindMessage),
        ui_message_sub: recipient!(addr, UiCarrierMessage),
        from_ui_message_sub: recipient!(addr, FromUiMessage),
        node_from_ui_message_sub: recipient!(addr, NodeFromUiMessage),
        node_to_ui_message_sub: recipient!(addr, NodeToUiMessage),
    }
}

pub fn make_blockchain_bridge_subs_from(addr: &Addr<Recorder>) -> BlockchainBridgeSubs {
    BlockchainBridgeSubs {
        bind: recipient!(addr, BindMessage),
        report_accounts_payable: recipient!(addr, ReportAccountsPayable),
        retrieve_transactions: recipient!(addr, RetrieveTransactions),
        set_gas_price_sub: recipient!(addr, SetGasPriceMsg),
        set_consuming_db_password_sub: recipient!(addr, SetDbPasswordMsg),
        ui_sub: recipient!(addr, NodeFromUiMessage),
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

        PeerActors {
            proxy_server: make_proxy_server_subs_from(&proxy_server_addr),
            dispatcher: make_dispatcher_subs_from(&dispatcher_addr),
            hopper: make_hopper_subs_from(&hopper_addr),
            proxy_client: make_proxy_client_subs_from(&proxy_client_addr),
            neighborhood: make_neighborhood_subs_from(&neighborhood_addr),
            accountant: make_accountant_subs_from(&accountant_addr),
            ui_gateway: make_ui_gateway_subs_from(&ui_gateway_addr),
            blockchain_bridge: make_blockchain_bridge_subs_from(&blockchain_bridge_addr),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix::Message;
    use actix::System;

    #[derive(Debug, PartialEq, Message)]
    struct FirstMessageType {
        string: String,
    }

    recorder_message_handler!(FirstMessageType);

    #[derive(Debug, PartialEq, Message)]
    struct SecondMessageType {
        size: usize,
        flag: bool,
    }

    recorder_message_handler!(SecondMessageType);

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
}
