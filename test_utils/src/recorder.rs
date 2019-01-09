// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use actix::Actor;
use actix::Addr;
use actix::Context;
use actix::Handler;
use actix::MessageResult;
use actix::Syn;
use std::any::Any;
use std::sync::Arc;
use std::sync::Mutex;
use std::thread;
use std::time::Duration;
use std::time::Instant;
use sub_lib::dispatcher::DispatcherSubs;
use sub_lib::dispatcher::InboundClientData;
use sub_lib::hopper::ExpiredCoresPackage;
use sub_lib::hopper::ExpiredCoresPackagePackage;
use sub_lib::hopper::HopperSubs;
use sub_lib::hopper::IncipientCoresPackage;
use sub_lib::neighborhood::BootstrapNeighborhoodNowMessage;
use sub_lib::neighborhood::DispatcherNodeQueryMessage;
use sub_lib::neighborhood::NeighborhoodSubs;
use sub_lib::neighborhood::NodeDescriptor;
use sub_lib::neighborhood::NodeQueryMessage;
use sub_lib::neighborhood::RemoveNeighborMessage;
use sub_lib::neighborhood::RouteQueryMessage;
use sub_lib::neighborhood::RouteQueryResponse;
use sub_lib::peer_actors::BindMessage;
use sub_lib::peer_actors::PeerActors;
use sub_lib::proxy_client::ProxyClientSubs;
use sub_lib::proxy_server::ProxyServerSubs;
use sub_lib::stream_handler_pool::DispatcherNodeQueryResponse;
use sub_lib::stream_handler_pool::TransmitDataMsg;
use test_utils::to_millis;

pub struct Recorder {
    recording: Arc<Mutex<Recording>>,
    node_query_responses: Vec<Option<NodeDescriptor>>,
    route_query_responses: Vec<Option<RouteQueryResponse>>,
}

pub struct Recording {
    messages: Vec<Box<Any + Send>>,
}

pub struct RecordAwaiter {
    recording: Arc<Mutex<Recording>>,
}

impl Actor for Recorder {
    type Context = Context<Self>;
}

impl Handler<TransmitDataMsg> for Recorder {
    type Result = ();

    fn handle(&mut self, msg: TransmitDataMsg, _ctx: &mut Self::Context) {
        self.record(msg);
    }
}

impl Handler<BindMessage> for Recorder {
    type Result = ();

    fn handle(&mut self, msg: BindMessage, _ctx: &mut Self::Context) {
        self.record(msg);
    }
}

impl Handler<IncipientCoresPackage> for Recorder {
    type Result = ();

    fn handle(&mut self, msg: IncipientCoresPackage, _ctx: &mut Self::Context) {
        self.record(msg);
    }
}

impl Handler<ExpiredCoresPackage> for Recorder {
    type Result = ();

    fn handle(&mut self, msg: ExpiredCoresPackage, _ctx: &mut Self::Context) {
        self.record(msg);
    }
}

impl Handler<ExpiredCoresPackagePackage> for Recorder {
    type Result = ();

    fn handle(&mut self, msg: ExpiredCoresPackagePackage, _ctx: &mut Self::Context) {
        self.record(msg);
    }
}

impl Handler<InboundClientData> for Recorder {
    type Result = ();

    fn handle(&mut self, msg: InboundClientData, _ctx: &mut Self::Context) {
        self.record(msg)
    }
}

impl Handler<BootstrapNeighborhoodNowMessage> for Recorder {
    type Result = ();

    fn handle(&mut self, msg: BootstrapNeighborhoodNowMessage, _ctx: &mut Self::Context) {
        self.record(msg);
    }
}

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

impl Handler<DispatcherNodeQueryResponse> for Recorder {
    type Result = ();

    fn handle(&mut self, msg: DispatcherNodeQueryResponse, _ctx: &mut Self::Context) {
        self.record(msg);
    }
}

impl Handler<DispatcherNodeQueryMessage> for Recorder {
    type Result = ();

    fn handle(&mut self, msg: DispatcherNodeQueryMessage, _ctx: &mut Self::Context) {
        self.record(msg);
    }
}

impl Handler<RemoveNeighborMessage> for Recorder {
    type Result = ();

    fn handle(&mut self, msg: RemoveNeighborMessage, _ctx: &mut Self::Context) {
        self.record(msg);
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
        Recorder {
            recording: Arc::new(Mutex::new(Recording { messages: vec![] })),
            node_query_responses: vec![],
            route_query_responses: vec![],
        }
    }

    pub fn record<T>(&mut self, item: T)
    where
        T: Any + Send,
    {
        let mut recording = self.recording.lock().unwrap();
        let messages: &mut Vec<Box<Any + Send>> = &mut recording.messages;
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

    pub fn node_query_response(mut self, response: Option<NodeDescriptor>) -> Recorder {
        self.node_query_responses.push(response);
        self
    }

    pub fn route_query_response(mut self, response: Option<RouteQueryResponse>) -> Recorder {
        self.route_query_responses.push(response);
        self
    }
}

impl Recording {
    pub fn len(&self) -> usize {
        return self.messages.len();
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
        let item_success_ref = match item_opt {
            Some(item) => item,
            None => panic!("Message {} could not be downcast to the expected type"),
        };
        item_success_ref
    }
}

impl RecordAwaiter {
    pub fn await_message_count(&self, count: usize) {
        let limit = 1000u64;
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

pub fn make_proxy_server_subs_from(addr: &Addr<Syn, Recorder>) -> ProxyServerSubs {
    ProxyServerSubs {
        bind: addr.clone().recipient::<BindMessage>(),
        from_dispatcher: addr.clone().recipient::<InboundClientData>(),
        from_hopper: addr.clone().recipient::<ExpiredCoresPackage>(),
    }
}

pub fn make_dispatcher_subs_from(addr: &Addr<Syn, Recorder>) -> DispatcherSubs {
    DispatcherSubs {
        ibcd_sub: addr.clone().recipient::<InboundClientData>(),
        bind: addr.clone().recipient::<BindMessage>(),
        from_dispatcher_client: addr.clone().recipient::<TransmitDataMsg>(),
    }
}

pub fn make_hopper_subs_from(addr: &Addr<Syn, Recorder>) -> HopperSubs {
    HopperSubs {
        bind: addr.clone().recipient::<BindMessage>(),
        from_hopper_client: addr.clone().recipient::<IncipientCoresPackage>(),
        from_dispatcher: addr.clone().recipient::<InboundClientData>(),
    }
}

pub fn make_proxy_client_subs_from(addr: &Addr<Syn, Recorder>) -> ProxyClientSubs {
    ProxyClientSubs {
        bind: addr.clone().recipient::<BindMessage>(),
        from_hopper: addr.clone().recipient::<ExpiredCoresPackage>(),
    }
}

pub fn make_neighborhood_subs_from(addr: &Addr<Syn, Recorder>) -> NeighborhoodSubs {
    NeighborhoodSubs {
        bind: addr.clone().recipient::<BindMessage>(),
        bootstrap: addr.clone().recipient::<BootstrapNeighborhoodNowMessage>(),
        node_query: addr.clone().recipient::<NodeQueryMessage>(),
        route_query: addr.clone().recipient::<RouteQueryMessage>(),
        from_hopper: addr.clone().recipient::<ExpiredCoresPackagePackage>(),
        dispatcher_node_query: addr.clone().recipient::<DispatcherNodeQueryMessage>(),
        remove_neighbor: addr.clone().recipient::<RemoveNeighborMessage>(),
    }
}

// This must be called after System.new and before System.run
pub fn make_peer_actors_from(
    proxy_server: Option<Recorder>,
    dispatcher: Option<Recorder>,
    hopper: Option<Recorder>,
    proxy_client: Option<Recorder>,
    neighborhood: Option<Recorder>,
) -> PeerActors {
    let proxy_server = match proxy_server {
        Some(proxy_server) => proxy_server,
        None => Recorder::new(),
    };

    let dispatcher = match dispatcher {
        Some(dispatcher) => dispatcher,
        None => Recorder::new(),
    };

    let hopper = match hopper {
        Some(hopper) => hopper,
        None => Recorder::new(),
    };

    let proxy_client = match proxy_client {
        Some(proxy_client) => proxy_client,
        None => Recorder::new(),
    };

    let neighborhood = match neighborhood {
        Some(neighborhood) => neighborhood,
        None => Recorder::new(),
    };

    make_peer_actors_from_recorders(proxy_server, dispatcher, hopper, proxy_client, neighborhood)
}

// This must be called after System.new and before System.run
pub fn make_peer_actors() -> PeerActors {
    make_peer_actors_from_recorders(
        Recorder::new(),
        Recorder::new(),
        Recorder::new(),
        Recorder::new(),
        Recorder::new(),
    )
}

fn make_peer_actors_from_recorders(
    proxy_server: Recorder,
    dispatcher: Recorder,
    hopper: Recorder,
    proxy_client: Recorder,
    neighborhood: Recorder,
) -> PeerActors {
    let proxy_server_addr = proxy_server.start();
    let dispatcher_addr = dispatcher.start();
    let hopper_addr = hopper.start();
    let proxy_client_addr = proxy_client.start();
    let neighborhood_addr = neighborhood.start();

    PeerActors {
        proxy_server: make_proxy_server_subs_from(&proxy_server_addr),
        dispatcher: make_dispatcher_subs_from(&dispatcher_addr),
        hopper: make_hopper_subs_from(&hopper_addr),
        proxy_client: make_proxy_client_subs_from(&proxy_client_addr),
        neighborhood: make_neighborhood_subs_from(&neighborhood_addr),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix::msgs;
    use actix::Arbiter;
    use actix::System;

    #[derive(Debug, PartialEq, Message)]
    struct FirstMessageType {
        string: String,
    }

    impl Handler<FirstMessageType> for Recorder {
        type Result = ();

        fn handle(&mut self, msg: FirstMessageType, _ctx: &mut Context<Self>) -> () {
            self.record(msg)
        }
    }

    #[derive(Debug, PartialEq, Message)]
    struct SecondMessageType {
        size: usize,
        flag: bool,
    }

    impl Handler<SecondMessageType> for Recorder {
        type Result = ();

        fn handle(&mut self, msg: SecondMessageType, _ctx: &mut Context<Self>) -> () {
            self.record(msg)
        }
    }

    #[test]
    fn recorder_records_different_messages() {
        let system = System::new("test");
        let recorder = Recorder::new();
        let recording_arc = recorder.get_recording();

        let rec_addr: Addr<Syn, Recorder> = recorder.start();

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
        Arbiter::system().try_send(msgs::SystemExit(0)).unwrap();

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
