// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::communications::broadcast_handler::{
    BroadcastHandle, BroadcastHandler, StreamFactory, StreamFactoryReal,
};
use crate::communications::client_listener_thread::{ClientListener, ClientListenerError};
use crate::communications::node_conversation::{NodeConversation, NodeConversationTermination};
use async_channel::Sender as WSSender;
use async_trait::async_trait;
use crossbeam_channel::{unbounded, RecvTimeoutError};
use masq_lib::messages::{CrashReason, FromMessageBody, ToMessageBody, UiNodeCrashedBroadcast};
use masq_lib::messages::{UiRedirect, NODE_UI_PROTOCOL};
use masq_lib::ui_gateway::{MessageBody, MessagePath};
use masq_lib::ui_traffic_converter::UiTrafficConverter;
use masq_lib::utils::localhost;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use tokio::task::JoinHandle;
use workflow_websocket::client::{
    Ack, ConnectOptions, ConnectStrategy, Error, Handshake, Message, WebSocket, WebSocketConfig,
};

pub const COMPONENT_RESPONSE_TIMEOUT_MILLIS: u64 = 100;
pub const REDIRECT_TIMEOUT_MILLIS: u64 = 500;
pub const FALLBACK_TIMEOUT_MILLIS: u64 = 5000; //used to be 1000; but we have suspicion that Actions doesn't make it and needs more

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutgoingMessageType {
    ConversationMessage(MessageBody),
    FireAndForgetMessage(MessageBody, u64),
    SignOff(u64),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Demand {
    Conversation,
    ActivePort,
    Close,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedirectOrder {
    port: u16,
    context_id: u64,
    timeout_millis: u64,
}

impl RedirectOrder {
    pub fn new(port: u16, context_id: u64, timeout_millis: u64) -> Self {
        Self {
            port,
            context_id,
            timeout_millis,
        }
    }
}

pub struct ConnectionManager {
    connectors: ConnectionManagerConnectors,
}

#[derive(Default)]
pub struct ConnectionManagerBootstrapper {}

impl ConnectionManagerBootstrapper {
    pub async fn spawn_event_loop(
        &self,
        port: u16,
        standard_broadcast_handle: Box<dyn BroadcastHandle>,
        timeout_millis: u64,
    ) -> Result<ConnectionManagerConnectors, ClientListenerError> {
        let (demand_tx, demand_rx) = unbounded_channel();
        let (listener_to_manager_tx, listener_to_manager_rx) = unbounded_channel();
        let closing_stage = Arc::new(AtomicBool::new(false));
        let talker_half = make_client_listener(
            port,
            listener_to_manager_tx,
            closing_stage.clone(),
            timeout_millis,
        )
        .await?;
        let (conversation_return_tx, conversation_return_rx) = unbounded();
        let (redirect_order_tx, redirect_order_rx) = unbounded_channel();
        let (redirect_response_tx, redirect_response_rx) = unbounded();
        let (active_port_response_tx, active_port_response_rx) = unbounded();
        let redirect_broadcast_handler =
            RedirectBroadcastHandler::new(standard_broadcast_handle, redirect_order_tx);
        // self.demand_tx = demand_tx;
        // self.conversation_return_rx = conversation_return_rx;
        // self.redirect_response_rx = redirect_response_rx;
        // self.active_port_response_rx = active_port_response_rx;
        let inner = CmsInner {
            active_port: Some(port),
            daemon_port: port,
            node_port: None,
            conversations: HashMap::new(),
            conversations_waiting: HashSet::new(),
            next_context_id: 1,
            demand_rx,
            conversation_return_tx,
            conversations_to_manager_tx: unbounded_channel().0,
            conversations_to_manager_rx: unbounded_channel().1,
            listener_to_manager_rx,
            talker_half,
            broadcast_handle: redirect_broadcast_handler.start(Box::new(StreamFactoryReal::new())),
            redirect_order_rx,
            redirect_response_tx,
            active_port_response_tx,
            closing_stage,
        };

        ConnectionManagerEventLoop::start(inner);

        let connectors = ConnectionManagerConnectors {
            demand_tx,
            conversation_return_rx,
            redirect_response_rx,
            active_port_response_rx,
        };

        Ok(connectors)
    }
}

pub struct ConnectionManagerConnectors {
    demand_tx: UnboundedSender<Demand>,
    conversation_return_rx: crossbeam_channel::Receiver<NodeConversation>,
    //TODO we never use this!!! ... it should probably print a message or something
    redirect_response_rx: crossbeam_channel::Receiver<Result<(), ClientListenerError>>,
    active_port_response_rx: crossbeam_channel::Receiver<Option<u16>>,
}

impl ConnectionManager {
    pub fn new(connectors: ConnectionManagerConnectors) -> Self {
        Self { connectors }
    }
    pub fn active_ui_port(&self) -> Option<u16> {
        self.connectors
            .demand_tx
            .send(Demand::ActivePort)
            .expect("ConnectionManagerThread is dead");
        match self
            .connectors
            .active_port_response_rx
            .recv_timeout(Duration::from_millis(COMPONENT_RESPONSE_TIMEOUT_MILLIS))
        {
            Ok(ui_port_opt) => ui_port_opt,
            Err(RecvTimeoutError::Disconnected) => panic!("ConnectionManager is not connected"),
            Err(RecvTimeoutError::Timeout) => panic!("ConnectionManager is not responding"),
        }
    }

    pub fn start_conversation(&self) -> NodeConversation {
        self.connectors
            .demand_tx
            .send(Demand::Conversation)
            .expect("ConnectionManager is not connected");
        self.connectors
            .conversation_return_rx
            .recv()
            .expect("ConnectionManager is not connected")
    }

    pub fn close(&self) {
        self.connectors
            .demand_tx
            .send(Demand::Close)
            .expect("ConnectionManagerThread is dead");
    }
}

async fn make_client_listener(
    port: u16,
    listener_to_manager_tx: tokio::sync::mpsc::UnboundedSender<
        Result<MessageBody, ClientListenerError>,
    >,
    closing_stage: Arc<AtomicBool>,
    timeout_millis: u64,
) -> Result<WSSender<(Message, Ack)>, ClientListenerError> {
    let url = format!("ws://{}:{}", localhost(), port);
    // TODO should the values be set in this config comprehensively tested?
    let mut ws_config = WebSocketConfig::default();
    ws_config.handshake = Some(Arc::new(WSClientHandshakeHandler::default()));
    let websocket: WebSocket = match WebSocket::new(Some(&url), Some(ws_config)) {
        Ok(ws) => ws,
        Err(e) => todo!(),
    };
    // TODO should the values be set in this config comprehensively tested?
    let mut connect_options = ConnectOptions::default();
    connect_options.block_async_connect = false;
    connect_options.strategy = ConnectStrategy::Fallback;
    connect_options.connect_timeout = Some(Duration::from_millis(timeout_millis));

    match websocket.connect(connect_options).await {
        Ok(_) => (),
        Err(Error::NotConnected) => return Err(ClientListenerError::Closed),
        Err(Error::ConnectionTimeout) => return Err(ClientListenerError::Timeout),
        Err(e) => return Err(ClientListenerError::Broken(format!("{:?}", e))),
    };

    let listener_half = websocket.receiver_rx().clone();
    let talker_half = websocket.sender_tx().clone();
    let client_listener = ClientListener::new();
    client_listener
        .start(listener_half, closing_stage, listener_to_manager_tx)
        .await;
    Ok(talker_half)
}

//hack a time-out around connection attempt to the Node or Daemon. Leaks a thread if the attempt times out
// fn connect_insecure_timeout(
//     mut builder: ClientBuilder<'static>,
//     timeout_millis: u64,
// ) -> Result<WebSocketResult<Client<TcpStream>>, RecvTimeoutError> {
//     let (tx, rx) = unbounded();
//     thread::spawn(move || {
//         let result = builder.connect_insecure();
//         let _ = tx.send(result);
//     });
//     rx.recv_timeout(Duration::from_millis(timeout_millis))
// }

#[derive(Default)]
pub struct WSClientHandshakeHandler {}

#[async_trait]
impl Handshake for WSClientHandshakeHandler {
    async fn handshake(
        &self,
        sender: &async_channel::Sender<Message>,
        receiver: &async_channel::Receiver<Message>,
    ) -> workflow_websocket::client::Result<()> {
        let incoming_msg = receiver.recv().await.unwrap();
        match incoming_msg {
            Message::Text(text) if text.contains(NODE_UI_PROTOCOL) => {
                todo!()
                //sender.send(Message::Open).await.unwrap();
                //Ok(())
            }
            _ => {
                todo!()
                //sender.send(Message::Close).await.unwrap();
                //Err(NegotiationFailure)
            }
        }
    }
}

struct CmsInner {
    active_port: Option<u16>,
    daemon_port: u16,
    node_port: Option<u16>,
    conversations:
        HashMap<u64, crossbeam_channel::Sender<Result<MessageBody, NodeConversationTermination>>>,
    conversations_waiting: HashSet<u64>,
    next_context_id: u64,
    demand_rx: UnboundedReceiver<Demand>,
    conversation_return_tx: crossbeam_channel::Sender<NodeConversation>,
    conversations_to_manager_tx: UnboundedSender<OutgoingMessageType>,
    conversations_to_manager_rx: UnboundedReceiver<OutgoingMessageType>,
    listener_to_manager_rx: UnboundedReceiver<Result<MessageBody, ClientListenerError>>,
    talker_half: WSSender<(Message, Ack)>,
    broadcast_handle: Box<dyn BroadcastHandle>,
    redirect_order_rx: UnboundedReceiver<RedirectOrder>,
    redirect_response_tx: crossbeam_channel::Sender<Result<(), ClientListenerError>>,
    active_port_response_tx: crossbeam_channel::Sender<Option<u16>>,
    closing_stage: Arc<AtomicBool>,
}

pub struct ConnectionManagerEventLoop {}

impl ConnectionManagerEventLoop {
    fn start(mut inner: CmsInner) {
        let (conversations_to_manager_tx, conversations_to_manager_rx) = unbounded_channel();
        inner.conversations_to_manager_tx = conversations_to_manager_tx;
        inner.conversations_to_manager_rx = conversations_to_manager_rx;
        let _join_handle = Self::spawn_loop(inner);
    }

    fn spawn_loop(mut inner: CmsInner) -> JoinHandle<()> {
        tokio::task::spawn(async move {
            loop {
                match (
                    inner.closing_stage.load(Ordering::Relaxed),
                    inner.active_port,
                ) {
                    (true, _) => break,
                    (false, None) => {
                        Self::send_daemon_crashed(&inner);
                        break;
                    }
                    _ => inner = Self::loop_guts(inner).await,
                }
            }
        })
    }

    async fn loop_guts(mut inner: CmsInner) -> CmsInner {
        tokio::select! {
            demand_result = inner.demand_rx.recv() => Self::handle_demand (inner, demand_result).await,
            message_body_result_result = inner.conversations_to_manager_rx.recv() => Self::handle_outgoing_message_body (inner, message_body_result_result).await,
            redirect_order_result = inner.redirect_order_rx.recv() => Self::handle_redirect_order (inner, redirect_order_result).await,
            message_body_result_result = inner.listener_to_manager_rx.recv() => Self::handle_incoming_message_body (inner, message_body_result_result).await,
        }
    }

    async fn handle_demand(mut inner: CmsInner, demand_opt: Option<Demand>) -> CmsInner {
        match demand_opt {
            Some(Demand::Conversation) => Self::handle_conversation_trigger(inner),
            Some(Demand::ActivePort) => Self::handle_active_port_request(inner),
            Some(Demand::Close) => Self::handle_close(inner).await,
            None => {
                inner.active_port = None;
                inner
            }
        }
    }

    fn handle_conversation_trigger(mut inner: CmsInner) -> CmsInner {
        let (manager_to_conversation_tx, manager_to_conversation_rx) = unbounded();
        let context_id = inner.next_context_id;
        inner.next_context_id += 1;
        let conversation = NodeConversation::new(
            context_id,
            inner.conversations_to_manager_tx.clone(),
            manager_to_conversation_rx,
        );
        inner
            .conversations
            .insert(context_id, manager_to_conversation_tx);
        match inner.conversation_return_tx.send(conversation) {
            Ok(_) => (),
            Err(_) => {
                inner.conversations.remove(&context_id);
            }
        };
        inner
    }

    async fn handle_incoming_message_body(
        mut inner: CmsInner,
        msg_result_opt: Option<Result<MessageBody, ClientListenerError>>,
    ) -> CmsInner {
        match msg_result_opt {
            Some(msg_result) => match msg_result {
                Ok(message_body) => match message_body.path {
                    MessagePath::Conversation(context_id) => {
                        if let Some(manager_to_conversation_tx) =
                            inner.conversations.get(&context_id)
                        {
                            match manager_to_conversation_tx.send(Ok(message_body)) {
                                Ok(_) => {
                                    inner.conversations_waiting.remove(&context_id);
                                }
                                Err(_) => {
                                    // The conversation waiting for this message died
                                    let _ = inner.conversations.remove(&context_id);
                                    let _ = inner.conversations_waiting.remove(&context_id);
                                }
                            }
                        }
                    }
                    MessagePath::FireAndForget => inner.broadcast_handle.send(message_body),
                },
                Err(e) => {
                    if e.is_fatal() {
                        // Fatal connection error: connection is dead, need to reestablish
                        return Self::fallback(inner, NodeConversationTermination::Fatal).await;
                    } else {
                        // Non-fatal connection error: connection to server is still up, but we have
                        // no idea which conversation the message was meant for
                        // Should we print something to stderr here? We don't have a stderr handy...
                    }
                }
            },
            None => {
                todo!("what here?");
                return Self::fallback(inner, NodeConversationTermination::Fatal).await;
            }
        };
        inner
    }

    async fn handle_outgoing_message_body(
        mut inner: CmsInner,
        msg_opt: Option<OutgoingMessageType>,
    ) -> CmsInner {
        match msg_opt {
            None => todo!(),
            Some(OutgoingMessageType::ConversationMessage (message_body)) => match message_body.path {
                MessagePath::Conversation(context_id) => {
                    let conversation_result = inner.conversations.get(&context_id);
                    if conversation_result.is_some() {
                        let send_message_result = inner.talker_half.send((Message::Text(UiTrafficConverter::new_marshal(message_body)), None)).await;
                        match send_message_result {
                            Ok(_) => {
                                inner.conversations_waiting.insert(context_id);
                            },
                            Err(_) => {
                                inner = Self::fallback(inner, NodeConversationTermination::Fatal).await;
                            },
                        }
                    };
                },
                MessagePath::FireAndForget => panic!("NodeConversation should have prevented sending a FireAndForget message with transact()"),
            },
            Some(OutgoingMessageType::FireAndForgetMessage(message_body, context_id)) => match message_body.path {
                MessagePath::FireAndForget => {
                    match inner.talker_half.send((Message::Text(UiTrafficConverter::new_marshal(message_body)), None)).await {
                        Ok (_) => {
                            if let Some(manager_to_conversation_tx) = inner.conversations.get(&context_id) {
                                match manager_to_conversation_tx.send(Err(NodeConversationTermination::FiredAndForgotten)) {
                                    Ok(_) => (),
                                    Err(_) => {
                                        // The conversation waiting for this message died
                                        let _ = inner.conversations.remove(&context_id);
                                    }
                                }
                            }
                        },
                        Err (_) => inner = Self::fallback(inner, NodeConversationTermination::Fatal).await,
                    }
                }
                MessagePath::Conversation(_) => panic!("NodeConversation should have prevented sending a Conversation message with send()"),
            },
            Some(OutgoingMessageType::SignOff(context_id)) => {
                let _ = inner.conversations.remove (&context_id);
                let _ = inner.conversations_waiting.remove (&context_id);
            },
        };
        inner
    }

    async fn handle_redirect_order(
        mut inner: CmsInner,
        redirect_order_opt: Option<RedirectOrder>,
    ) -> CmsInner {
        let redirect_order = match redirect_order_opt {
            Some(ro) => ro,
            None => return inner, // Sender died; ignore
        };
        let (listener_to_manager_tx, listener_to_manager_rx) = unbounded_channel();
        let talker_half = match make_client_listener(
            redirect_order.port,
            listener_to_manager_tx,
            inner.closing_stage.clone(),
            redirect_order.timeout_millis,
        )
        .await
        {
            Ok(th) => th,
            Err(e) => {
                let _ = inner
                    .redirect_response_tx
                    .send(Err(ClientListenerError::Broken(format!("{:?}", e))));
                return inner;
            }
        };
        inner.node_port = Some(redirect_order.port);
        inner.active_port = Some(redirect_order.port);
        inner.listener_to_manager_rx = listener_to_manager_rx;
        inner.talker_half = talker_half;
        //TODO this is a working solution for conversations; know that a redirected fire-and-forget is just ignored and it does not resend if it's the absolutely first message: GH-487
        inner.conversations_waiting.iter().for_each(|context_id| {
            let error = if *context_id == redirect_order.context_id {
                NodeConversationTermination::Resend
            } else {
                NodeConversationTermination::Graceful
            };
            let _ = inner
                .conversations
                .get(context_id)
                .expect("conversations_waiting mishandled")
                .send(Err(error));
        });
        inner.conversations_waiting.clear();
        inner
            .redirect_response_tx
            .send(Ok(()))
            .expect("ConnectionManager is dead");
        inner
    }

    fn handle_active_port_request(inner: CmsInner) -> CmsInner {
        inner
            .active_port_response_tx
            .send(inner.active_port)
            .expect("ConnectionManager is dead");
        inner
    }

    async fn handle_close(mut inner: CmsInner) -> CmsInner {
        inner.closing_stage.store(true, Ordering::Relaxed);
        let _ = inner.talker_half.send((Message::Close, None));
        let _ = inner.talker_half.close();
        inner = Self::fallback(inner, NodeConversationTermination::Graceful).await;
        inner
    }

    async fn fallback(mut inner: CmsInner, termination: NodeConversationTermination) -> CmsInner {
        inner.node_port = None;
        match &inner.active_port {
            None => {
                inner = Self::disappoint_all_conversations(inner, termination);
                return inner;
            }
            Some(active_port) if *active_port == inner.daemon_port => {
                inner.active_port = None;
                inner = Self::disappoint_all_conversations(inner, termination);
                return inner;
            }
            Some(_) => inner.active_port = Some(inner.daemon_port),
        }
        let (listener_to_manager_tx, listener_to_manager_rx) = unbounded_channel();
        inner.listener_to_manager_rx = listener_to_manager_rx;
        match make_client_listener(
            inner.active_port.expect("Active port disappeared!"),
            listener_to_manager_tx,
            inner.closing_stage.clone(),
            FALLBACK_TIMEOUT_MILLIS,
        )
        .await
        {
            Ok(talker_half) => inner.talker_half = talker_half,
            Err(e) => panic!("ClientListenerThread could not be restarted: {:?}", e),
        };
        inner = Self::disappoint_waiting_conversations(inner, NodeConversationTermination::Fatal);
        inner
    }

    fn disappoint_waiting_conversations(
        mut inner: CmsInner,
        error: NodeConversationTermination,
    ) -> CmsInner {
        inner.conversations_waiting.iter().for_each(|context_id| {
            let _ = inner
                .conversations
                .get(context_id)
                .expect("conversations_waiting mishandled")
                .send(Err(error));
        });
        inner.conversations_waiting.clear();
        inner
    }

    fn disappoint_all_conversations(
        mut inner: CmsInner,
        error: NodeConversationTermination,
    ) -> CmsInner {
        inner.conversations.iter().for_each(|(_, sender)| {
            let _ = sender.send(Err(error));
        });
        inner.conversations.clear();
        inner.conversations_waiting.clear();
        inner
    }

    fn send_daemon_crashed(inner: &CmsInner) {
        let crash_msg = UiNodeCrashedBroadcast {
            process_id: 0,
            crash_reason: CrashReason::DaemonCrashed,
        };
        inner.broadcast_handle.send(crash_msg.tmb(0))
    }
}

struct BroadcastHandleRedirect {
    next_handle: Box<dyn BroadcastHandle>,
    redirect_order_tx: UnboundedSender<RedirectOrder>,
}

impl BroadcastHandle for BroadcastHandleRedirect {
    fn send(&self, message_body: MessageBody) {
        match UiRedirect::fmb(message_body.clone()) {
            Ok((redirect, _)) => {
                let context_id = redirect.context_id.unwrap_or(0);
                self.redirect_order_tx
                    .send(RedirectOrder::new(
                        redirect.port,
                        context_id,
                        REDIRECT_TIMEOUT_MILLIS,
                    ))
                    .expect("ConnectionManagerThread is dead");
            }
            Err(_) => {
                self.next_handle.send(message_body);
            }
        };
    }
}

struct RedirectBroadcastHandler {
    next_handle: Box<dyn BroadcastHandle>,
    redirect_order_tx: UnboundedSender<RedirectOrder>,
}

impl BroadcastHandler for RedirectBroadcastHandler {
    fn start(self, _stream_factory: Box<dyn StreamFactory>) -> Box<dyn BroadcastHandle> {
        Box::new(BroadcastHandleRedirect {
            next_handle: self.next_handle,
            redirect_order_tx: self.redirect_order_tx,
        })
    }
}

impl RedirectBroadcastHandler {
    pub fn new(
        next_handle: Box<dyn BroadcastHandle>,
        redirect_order_tx: UnboundedSender<RedirectOrder>,
    ) -> Self {
        Self {
            next_handle,
            redirect_order_tx,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::communications::node_conversation::ClientError;
    use crate::test_utils::client_utils::WSTestClient;
    use crossbeam_channel::TryRecvError;
    use masq_lib::messages::{
        CrashReason, FromMessageBody, ToMessageBody, UiFinancialStatistics, UiNodeCrashedBroadcast,
        UiSetupBroadcast,
    };
    use masq_lib::messages::{
        UiFinancialsRequest, UiFinancialsResponse, UiRedirect, UiSetupRequest, UiSetupResponse,
        UiShutdownRequest, UiShutdownResponse, UiStartOrder, UiStartResponse, UiUnmarshalError,
    };
    use masq_lib::test_utils::mock_websockets_server::{
        MockWebSocketsServer, MockWebSocketsServerStopHandle,
    };
    #[cfg(target_os = "windows")]
    use masq_lib::test_utils::utils::is_running_under_github_actions;
    use masq_lib::test_utils::utils::{make_multi_thread_rt, make_rt};
    use masq_lib::utils::{find_free_port, running_test};
    use std::hash::Hash;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::Duration;
    use tokio::runtime::Runtime;

    #[test]
    fn constants_have_correct_values() {
        assert_eq!(COMPONENT_RESPONSE_TIMEOUT_MILLIS, 100);
        assert_eq!(REDIRECT_TIMEOUT_MILLIS, 500);
        assert_eq!(FALLBACK_TIMEOUT_MILLIS, 5000);
    }

    struct BroadcastHandleMock {
        send_params: Arc<Mutex<Vec<MessageBody>>>,
    }

    impl BroadcastHandle for BroadcastHandleMock {
        fn send(&self, message_body: MessageBody) -> () {
            self.send_params.lock().unwrap().push(message_body);
        }
    }

    impl BroadcastHandleMock {
        pub fn new() -> Self {
            Self {
                send_params: Arc::new(Mutex::new(vec![])),
            }
        }

        pub fn send_params(mut self, params: &Arc<Mutex<Vec<MessageBody>>>) -> Self {
            self.send_params = params.clone();
            self
        }
    }

    async fn make_subject(
        server: MockWebSocketsServer,
    ) -> (ConnectionManager, MockWebSocketsServerStopHandle) {
        let port = server.port();
        let stop_handle = server.start().await;
        tokio::time::sleep(Duration::from_millis(400)).await; // let the server get started
        let connectors = ConnectionManagerBootstrapper::default()
            .spawn_event_loop(port, Box::new(BroadcastHandleMock::new()), 1000)
            .await
            .unwrap();
        let subject = ConnectionManager::new(connectors);
        (subject, stop_handle)
    }

    #[test]
    fn handle_demand_brings_the_party_to_a_close_if_the_channel_fails() {
        let rt = make_rt();
        let inner = make_inner(&rt);

        let inner = make_rt().block_on(ConnectionManagerEventLoop::handle_demand(inner, None));

        assert_eq!(inner.active_port, None);
    }

    #[test]
    fn handles_interleaved_conversations() {
        #[cfg(target_os = "windows")]
        {
            if is_running_under_github_actions() {
                eprintln!("Skipping this test for Windows in Actions");
                return;
            }
        }
        let server = MockWebSocketsServer::new(find_free_port())
            .queue_response(UiShutdownResponse {}.tmb(2))
            .queue_response(UiShutdownResponse {}.tmb(1))
            .queue_response(
                UiStartResponse {
                    new_process_id: 11,
                    redirect_ui_port: 12,
                }
                .tmb(1),
            )
            .queue_response(
                UiStartResponse {
                    new_process_id: 21,
                    redirect_ui_port: 22,
                }
                .tmb(2),
            );
        let rt = make_multi_thread_rt();
        let (subject, stop_handle) = rt.block_on(make_subject(server));
        let conversation1 = subject.start_conversation();
        let conversation2 = subject.start_conversation();

        let conversation1_handle = thread::spawn(move || {
            let response1 = conversation1
                .transact(UiShutdownRequest {}.tmb(0), 1001)
                .unwrap();
            let response2 = conversation1
                .transact(UiStartOrder {}.tmb(0), 1002)
                .unwrap();
            (response1, response2)
        });
        let conversation2_handle = thread::spawn(move || {
            let response1 = conversation2
                .transact(UiShutdownRequest {}.tmb(0), 1003)
                .unwrap();
            let response2 = conversation2
                .transact(UiStartOrder {}.tmb(0), 1004)
                .unwrap();
            (response1, response2)
        });

        let (conversation1_response1, conversation1_response2) =
            conversation1_handle.join().unwrap();
        let (conversation2_response1, conversation2_response2) =
            conversation2_handle.join().unwrap();
        assert_eq!(conversation1_response1, UiShutdownResponse {}.tmb(1));
        assert_eq!(
            conversation1_response2,
            UiStartResponse {
                new_process_id: 11,
                redirect_ui_port: 12
            }
            .tmb(1)
        );
        assert_eq!(conversation2_response1, UiShutdownResponse {}.tmb(2));
        assert_eq!(
            conversation2_response2,
            UiStartResponse {
                new_process_id: 21,
                redirect_ui_port: 22
            }
            .tmb(2)
        );
        let _ = stop_handle.stop();
    }

    #[test]
    fn handles_sending_fire_and_forget_messages() {
        let server = MockWebSocketsServer::new(find_free_port());
        let rt = make_multi_thread_rt();
        let (subject, stop_handle) = rt.block_on(make_subject(server));
        let conversation = subject.start_conversation();
        let message1 = UiUnmarshalError {
            message: "Message 1".to_string(),
            bad_data: "Data 1".to_string(),
        };
        let message2 = UiUnmarshalError {
            message: "Message 2".to_string(),
            bad_data: "Data 2".to_string(),
        };

        conversation.send(message1.clone().tmb(0)).unwrap();
        conversation.send(message2.clone().tmb(0)).unwrap();

        //TODO how to do this right?
        rt.block_on(tokio::time::sleep(Duration::from_millis(1000)));
        let mut outgoing_messages = stop_handle.stop();
        assert_eq!(
            UiUnmarshalError::fmb(outgoing_messages.remove(0).unwrap()).unwrap(),
            (message1, 0)
        );
        assert_eq!(
            UiUnmarshalError::fmb(outgoing_messages.remove(0).unwrap()).unwrap(),
            (message2, 0)
        );
        assert_eq!(outgoing_messages.is_empty(), true);
    }

    #[test]
    fn conversations_waiting_is_set_correctly_for_normal_operation() {
        let port = find_free_port();
        let rt = make_rt();
        let server = MockWebSocketsServer::new(port)
            .queue_string("irrelevant")
            .queue_string("irrelevant");
        let stop_handle = rt.block_on(server.start());
        let (_, talker_half) = WSTestClient::new(port).split();
        let (demand_tx, demand_rx) = unbounded_channel();
        let (listener_to_manager_tx, listener_to_manager_rx) = unbounded_channel();
        let (conversations_to_manager_tx, conversations_to_manager_rx) = unbounded_channel();
        let (conversation_return_tx, conversation_return_rx) = unbounded();
        let (_redirect_order_tx, redirect_order_rx) = unbounded_channel();
        let mut inner = make_inner(&rt);
        inner.next_context_id = 1;
        inner.conversation_return_tx = conversation_return_tx;
        inner.listener_to_manager_rx = listener_to_manager_rx;
        inner.conversations_to_manager_tx = conversations_to_manager_tx;
        inner.conversations_to_manager_rx = conversations_to_manager_rx;
        inner.talker_half = talker_half;
        inner.redirect_order_rx = redirect_order_rx;
        inner.demand_rx = demand_rx;
        demand_tx.send(Demand::Conversation).unwrap();
        inner = rt.block_on(ConnectionManagerEventLoop::loop_guts(inner));
        let conversation1 = conversation_return_rx.try_recv().unwrap();
        let (conversation1_tx, conversation1_rx) = conversation1.tx_rx();
        demand_tx.send(Demand::Conversation).unwrap();
        inner = rt.block_on(ConnectionManagerEventLoop::loop_guts(inner));
        let conversation2 = conversation_return_rx.try_recv().unwrap();
        let (conversation2_tx, conversation2_rx) = conversation2.tx_rx();
        let get_existing_keys = |inner: &CmsInner| {
            inner
                .conversations
                .iter()
                .map(|(k, _)| *k)
                .collect::<HashSet<u64>>()
        };

        // Conversations 1 and 2, nobody waiting
        assert_eq!(get_existing_keys(&inner), vec_to_set(vec![1, 2]));
        assert_eq!(inner.conversations_waiting, vec_to_set(vec![]));

        // Send request from Conversation 1 and process it
        conversation1_tx
            .send(OutgoingMessageType::ConversationMessage(
                UiShutdownRequest {}.tmb(1),
            ))
            .unwrap();
        inner = rt.block_on(ConnectionManagerEventLoop::loop_guts(inner)); // send request 1

        // Conversations 1 and 2, 1 waiting
        assert_eq!(get_existing_keys(&inner), vec_to_set(vec![1, 2]));
        assert_eq!(inner.conversations_waiting, vec_to_set(vec![1]));

        // Send request from Conversation 2 and process it
        conversation2_tx
            .send(OutgoingMessageType::ConversationMessage(
                UiShutdownRequest {}.tmb(2),
            ))
            .unwrap();
        inner = rt.block_on(ConnectionManagerEventLoop::loop_guts(inner));

        // Conversations 1 and 2, 1 and 2 waiting
        assert_eq!(get_existing_keys(&inner), vec_to_set(vec![1, 2]));
        assert_eq!(inner.conversations_waiting, vec_to_set(vec![1, 2]));

        // Receive response for Conversation 2, process it, pull it out
        let response2 = UiShutdownResponse {}.tmb(2);
        assert_eq!(response2.path, MessagePath::Conversation(2));
        listener_to_manager_tx.send(Ok(response2)).unwrap();
        inner = rt.block_on(ConnectionManagerEventLoop::loop_guts(inner));
        let result2 = conversation2_rx.try_recv().unwrap().unwrap();

        // Conversations 1 and 2, 1 still waiting
        assert_eq!(result2, UiShutdownResponse {}.tmb(2));
        assert_eq!(get_existing_keys(&inner), vec_to_set(vec![1, 2]));
        assert_eq!(inner.conversations_waiting, vec_to_set(vec![1]));

        // Receive response for Conversation 1, process it, pull it out
        let response1 = UiShutdownResponse {}.tmb(1);
        assert_eq!(response1.path, MessagePath::Conversation(1));
        listener_to_manager_tx.send(Ok(response1)).unwrap();
        inner = rt.block_on(ConnectionManagerEventLoop::loop_guts(inner));
        let result1 = conversation1_rx.try_recv().unwrap().unwrap();

        // Conversations 1 and 2, nobody waiting
        assert_eq!(result1, UiShutdownResponse {}.tmb(1));
        assert_eq!(result2, UiShutdownResponse {}.tmb(2));
        assert_eq!(get_existing_keys(&inner), vec_to_set(vec![1, 2]));
        assert_eq!(inner.conversations_waiting, vec_to_set(vec![]));

        // Conversation 1 signals exit; process it
        conversation1_tx
            .send(OutgoingMessageType::SignOff(1))
            .unwrap();
        inner = rt.block_on(ConnectionManagerEventLoop::loop_guts(inner));

        // Only Conversation 2, nobody waiting
        assert_eq!(get_existing_keys(&inner), vec_to_set(vec![2]));
        assert_eq!(inner.conversations_waiting, vec_to_set(vec![]));

        // Conversation 2 signals exit; process it
        conversation2_tx
            .send(OutgoingMessageType::SignOff(2))
            .unwrap();
        inner = rt.block_on(ConnectionManagerEventLoop::loop_guts(inner));

        // No more conversations, nobody waiting
        assert_eq!(get_existing_keys(&inner), vec_to_set(vec![]));
        assert_eq!(inner.conversations_waiting, vec_to_set(vec![]));

        let _ = stop_handle.stop();
    }

    #[test]
    fn when_fallback_fails_daemon_crash_broadcast_is_sent() {
        let rt = make_rt();
        let mut inner = make_inner(&rt);
        let broadcast_handle_send_params_arc = Arc::new(Mutex::new(vec![]));
        let broadcast_handle =
            BroadcastHandleMock::new().send_params(&broadcast_handle_send_params_arc);
        inner.active_port = None;
        inner.broadcast_handle = Box::new(broadcast_handle);

        let join_handle = {
            let _enter_guard = rt.enter();
            ConnectionManagerEventLoop::spawn_loop(inner)
        };

        let _ = rt.block_on(join_handle);
        let mut broadcast_handle_send_params = broadcast_handle_send_params_arc.lock().unwrap();
        let message_body: MessageBody = (*broadcast_handle_send_params).remove(0);
        let crash_broadcast = UiNodeCrashedBroadcast::fmb(message_body).unwrap().0;
        assert_eq!(crash_broadcast.crash_reason, CrashReason::DaemonCrashed);
    }

    #[test]
    fn handles_listener_fallback_from_node() {
        let daemon_port = find_free_port();
        let expected_incoming_message = UiSetupResponse {
            running: false,
            values: vec![],
            errors: vec![],
        }
        .tmb(4);
        let rt = make_rt();
        let daemon = MockWebSocketsServer::new(daemon_port)
            .queue_response(expected_incoming_message.clone());
        let stop_handle = rt.block_on(daemon.start());
        let node_port = find_free_port();
        let (conversation_tx, conversation_rx) = unbounded();
        let (decoy_tx, decoy_rx) = unbounded();
        let mut inner = make_inner(&rt);
        inner.active_port = Some(node_port);
        inner.daemon_port = daemon_port;
        inner.node_port = Some(node_port);
        inner.conversations.insert(4, conversation_tx);
        inner.conversations.insert(5, decoy_tx);
        inner.conversations_waiting.insert(4);

        let inner = rt.block_on(ConnectionManagerEventLoop::handle_incoming_message_body(
            inner, None,
        ));

        let disconnect_notification = conversation_rx.try_recv().unwrap();
        assert_eq!(
            disconnect_notification,
            Err(NodeConversationTermination::Fatal)
        );
        assert_eq!(decoy_rx.try_recv().is_err(), true); // no disconnect notification sent to conversation not waiting
        assert_eq!(inner.active_port, Some(daemon_port));
        assert_eq!(inner.daemon_port, daemon_port);
        assert_eq!(inner.node_port, None);
        assert_eq!(inner.conversations_waiting.is_empty(), true);
        let _ = rt.block_on(ConnectionManagerEventLoop::handle_outgoing_message_body(
            inner,
            Some(OutgoingMessageType::ConversationMessage(
                UiSetupRequest { values: vec![] }.tmb(4),
            )),
        ));
        let mut outgoing_messages = stop_handle.stop();
        assert_eq!(
            outgoing_messages.remove(0),
            Ok(UiSetupRequest { values: vec![] }.tmb(4))
        );
    }

    #[test]
    fn doesnt_fall_back_from_daemon() {
        let unoccupied_port = find_free_port();
        let (waiting_conversation_tx, waiting_conversation_rx) = unbounded();
        let (idle_conversation_tx, idle_conversation_rx) = unbounded();
        let rt = make_rt();
        let mut inner = make_inner(&rt);
        inner.daemon_port = unoccupied_port;
        inner.active_port = Some(unoccupied_port);
        inner.node_port = None;
        inner.conversations.insert(4, waiting_conversation_tx);
        inner.conversations.insert(5, idle_conversation_tx);
        inner.conversations_waiting.insert(4);

        let inner = rt.block_on(ConnectionManagerEventLoop::fallback(
            inner,
            NodeConversationTermination::Fatal,
        ));

        let disconnect_notification = waiting_conversation_rx.try_recv().unwrap();
        assert_eq!(
            disconnect_notification,
            Err(NodeConversationTermination::Fatal)
        );
        let disconnect_notification = idle_conversation_rx.try_recv().unwrap();
        assert_eq!(
            disconnect_notification,
            Err(NodeConversationTermination::Fatal)
        );
        assert_eq!(inner.daemon_port, unoccupied_port);
        assert_eq!(inner.active_port, None);
        assert_eq!(inner.node_port, None);
    }

    #[test]
    fn doesnt_fall_back_from_disconnected() {
        let unoccupied_port = find_free_port();
        let (waiting_conversation_tx, waiting_conversation_rx) = unbounded();
        let (idle_conversation_tx, idle_conversation_rx) = unbounded();
        let rt = make_rt();
        let mut inner = make_inner(&rt);
        inner.daemon_port = unoccupied_port;
        inner.active_port = None;
        inner.node_port = None;
        inner.conversations.insert(4, waiting_conversation_tx);
        inner.conversations.insert(5, idle_conversation_tx);
        inner.conversations_waiting.insert(4);

        let inner = rt.block_on(ConnectionManagerEventLoop::fallback(
            inner,
            NodeConversationTermination::Fatal,
        ));

        let disconnect_notification = waiting_conversation_rx.try_recv().unwrap();
        assert_eq!(
            disconnect_notification,
            Err(NodeConversationTermination::Fatal)
        );
        let disconnect_notification = idle_conversation_rx.try_recv().unwrap();
        assert_eq!(
            disconnect_notification,
            Err(NodeConversationTermination::Fatal)
        );
        assert_eq!(inner.daemon_port, unoccupied_port);
        assert_eq!(inner.active_port, None);
        assert_eq!(inner.node_port, None);
    }

    #[test]
    fn handle_redirect_order_handles_rejection_from_node() {
        let node_port = find_free_port(); // won't put anything on this port
        let (redirect_response_tx, redirect_response_rx) = unbounded();
        let rt = make_rt();
        let mut inner = make_inner(&rt);
        inner.redirect_response_tx = redirect_response_tx;

        make_rt().block_on(ConnectionManagerEventLoop::handle_redirect_order(
            inner,
            Some(RedirectOrder::new(node_port, 0, 1000)),
        ));

        let response = redirect_response_rx.try_recv().unwrap();
        match response {
            Err(ClientListenerError::Broken(_)) => (), //the string pasted in is OS-dependent
            x => panic!(
                "we expected ClientListenerError::Broken but got this: {:?}",
                x
            ),
        }
    }

    #[test]
    fn handle_redirect_order_disappoints_waiting_conversations_with_resend_or_graceful() {
        let node_port = find_free_port();
        let rt = make_rt();
        let server = MockWebSocketsServer::new(node_port);
        let server_stop_handle = rt.block_on(server.start());
        let (redirect_response_tx, redirect_response_rx) = unbounded();
        let (conversation1_tx, conversation1_rx) = unbounded();
        let (conversation2_tx, conversation2_rx) = unbounded();
        let conversations = vec![(1, conversation1_tx), (2, conversation2_tx)]
            .into_iter()
            .collect();
        let conversations_waiting = vec_to_set(vec![1, 2]);
        let mut inner = make_inner(&rt);
        inner.redirect_response_tx = redirect_response_tx;
        inner.conversations = conversations;
        inner.conversations_waiting = conversations_waiting;

        inner = rt.block_on(ConnectionManagerEventLoop::handle_redirect_order(
            inner,
            Some(RedirectOrder::new(node_port, 1, 1000)),
        ));

        let get_existing_keys = |inner: &CmsInner| {
            inner
                .conversations
                .iter()
                .map(|(k, _)| *k)
                .collect::<HashSet<u64>>()
        };
        assert_eq!(get_existing_keys(&inner), vec_to_set(vec![1, 2]));
        assert_eq!(inner.conversations_waiting.is_empty(), true);
        assert_eq!(
            conversation1_rx.try_recv().unwrap(),
            Err(NodeConversationTermination::Resend)
        );
        assert_eq!(
            conversation2_rx.try_recv().unwrap(),
            Err(NodeConversationTermination::Graceful)
        );
        assert_eq!(redirect_response_rx.try_recv().unwrap(), Ok(()));
        let _ = server_stop_handle.stop();
    }

    #[test]
    fn handles_listener_fallback_from_daemon() {
        let daemon_port = find_free_port();
        let (conversation_tx, conversation_rx) = unbounded();
        let (decoy_tx, decoy_rx) = unbounded();
        let rt = make_rt();
        let mut inner = make_inner(&rt);
        inner.active_port = Some(daemon_port);
        inner.daemon_port = daemon_port;
        inner.node_port = None;
        inner.conversations.insert(4, conversation_tx);
        inner.conversations.insert(5, decoy_tx);
        inner.conversations_waiting.insert(4);

        let _ = rt.block_on(ConnectionManagerEventLoop::handle_incoming_message_body(
            inner, None,
        ));

        let disappointment = conversation_rx.try_recv().unwrap();
        assert_eq!(disappointment, Err(NodeConversationTermination::Fatal));
        let disappointment = decoy_rx.try_recv().unwrap();
        assert_eq!(disappointment, Err(NodeConversationTermination::Fatal));
    }

    #[test]
    fn handles_fatal_reception_failure() {
        let daemon_port = find_free_port();
        let expected_incoming_message = UiSetupResponse {
            running: false,
            values: vec![],
            errors: vec![],
        }
        .tmb(4);
        let daemon = MockWebSocketsServer::new(daemon_port)
            .queue_response(expected_incoming_message.clone());
        let rt = make_rt();
        let stop_handle = rt.block_on(daemon.start());
        let node_port = find_free_port();
        let (conversation_tx, conversation_rx) = unbounded();
        let (decoy_tx, decoy_rx) = unbounded();
        let mut inner = make_inner(&rt);
        inner.active_port = Some(node_port);
        inner.daemon_port = daemon_port;
        inner.node_port = Some(node_port);
        inner.conversations.insert(4, conversation_tx);
        inner.conversations.insert(5, decoy_tx);
        inner.conversations_waiting.insert(4);

        let inner = rt.block_on(ConnectionManagerEventLoop::handle_incoming_message_body(
            inner,
            Some(Err(ClientListenerError::Broken("Booga".to_string()))),
        ));

        let disconnect_notification = conversation_rx.try_recv().unwrap();
        assert_eq!(
            disconnect_notification,
            Err(NodeConversationTermination::Fatal)
        );
        assert_eq!(decoy_rx.try_recv().is_err(), true); // no disconnect notification sent to conversation not waiting
        assert_eq!(inner.active_port, Some(daemon_port));
        assert_eq!(inner.daemon_port, daemon_port);
        assert_eq!(inner.node_port, None);
        assert_eq!(inner.conversations_waiting.is_empty(), true);
        let _ = rt.block_on(ConnectionManagerEventLoop::handle_outgoing_message_body(
            inner,
            Some(OutgoingMessageType::ConversationMessage(
                UiSetupRequest { values: vec![] }.tmb(4),
            )),
        ));
        let mut outgoing_messages = stop_handle.stop();
        assert_eq!(
            outgoing_messages.remove(0),
            Ok(UiSetupRequest { values: vec![] }.tmb(4))
        );
    }

    #[test]
    fn handles_nonfatal_reception_failure() {
        let daemon_port = find_free_port();
        let node_port = find_free_port();
        let (conversation_tx, conversation_rx) = unbounded();
        let rt = make_rt();
        let mut inner = make_inner(&rt);
        inner.active_port = Some(node_port);
        inner.daemon_port = daemon_port;
        inner.node_port = Some(node_port);
        inner.conversations.insert(4, conversation_tx);
        inner.conversations_waiting.insert(4);

        let inner = rt.block_on(ConnectionManagerEventLoop::handle_incoming_message_body(
            inner,
            Some(Err(ClientListenerError::UnexpectedPacket)),
        ));

        assert_eq!(conversation_rx.try_recv().is_err(), true); // no disconnect notification sent
        assert_eq!(inner.active_port, Some(node_port));
        assert_eq!(inner.daemon_port, daemon_port);
        assert_eq!(inner.node_port, Some(node_port));
        assert_eq!(inner.conversations_waiting.is_empty(), false);
    }

    #[test]
    fn handles_broadcast() {
        let incoming_message = UiSetupBroadcast {
            running: false,
            values: vec![],
            errors: vec![],
        }
        .tmb(0);
        let rt = make_rt();
        let (conversation_tx, conversation_rx) = unbounded();
        let send_params_arc = Arc::new(Mutex::new(vec![]));
        let broadcast_handler = BroadcastHandleMock::new().send_params(&send_params_arc);
        let mut inner = make_inner(&rt);
        inner.conversations.insert(4, conversation_tx);
        inner.conversations_waiting.insert(4);
        inner.broadcast_handle =
            RedirectBroadcastHandler::new(Box::new(broadcast_handler), unbounded_channel().0)
                .start(Box::new(StreamFactoryReal::new()));

        let inner = rt.block_on(ConnectionManagerEventLoop::handle_incoming_message_body(
            inner,
            Some(Ok(incoming_message.clone())),
        ));

        assert_eq!(conversation_rx.try_recv().is_err(), true); // no message to any conversation
        assert_eq!(inner.conversations_waiting.is_empty(), false);
        let send_params = send_params_arc.lock().unwrap();
        assert_eq!(*send_params, vec![incoming_message]);
    }

    #[test]
    fn can_follow_redirect() {
        #[cfg(target_os = "windows")]
        {
            if is_running_under_github_actions() {
                eprintln!("Skipping this test for Windows in Actions");
                return;
            }
        }
        let node_port = find_free_port();
        let node_server = MockWebSocketsServer::new(node_port).queue_response(
            UiFinancialsResponse {
                stats_opt: Some(UiFinancialStatistics {
                    total_unpaid_and_pending_payable_gwei: 10,
                    total_paid_payable_gwei: 22,
                    total_unpaid_receivable_gwei: 29,
                    total_paid_receivable_gwei: 32,
                }),
                query_results_opt: None,
            }
            .tmb(1),
        );
        let rt = make_multi_thread_rt();
        let node_stop_handle = rt.block_on(node_server.start());
        let daemon_port = find_free_port();
        let daemon_server = MockWebSocketsServer::new (daemon_port)
            .queue_response (UiRedirect {
                port: node_port,
                opcode: "financials".to_string(),
                context_id: Some(1),
                payload: r#"{"payableMinimumAmount":12,"payableMaximumAge":23,"receivableMinimumAmount":34,"receivableMaximumAge":45}"#.to_string()
            }.tmb(0));
        let daemon_stop_handle = rt.block_on(daemon_server.start());
        let request = UiFinancialsRequest {
            stats_required: true,
            top_records_opt: None,
            custom_queries_opt: None,
        }
        .tmb(1);
        let send_params_arc = Arc::new(Mutex::new(vec![]));
        let broadcast_handler = BroadcastHandleMock::new().send_params(&send_params_arc);
        let connectors = make_rt()
            .block_on(ConnectionManagerBootstrapper::default().spawn_event_loop(
                daemon_port,
                Box::new(broadcast_handler),
                1000,
            ))
            .unwrap();
        let subject = ConnectionManager::new(connectors);
        let conversation = subject.start_conversation();

        let result = conversation.transact(request, 1000).unwrap();

        let request_body = node_stop_handle.stop()[0].clone().unwrap();
        UiFinancialsRequest::fmb(request_body).unwrap();
        let (response, context_id) = UiFinancialsResponse::fmb(result).unwrap();
        assert_eq!(
            response,
            UiFinancialsResponse {
                stats_opt: Some(UiFinancialStatistics {
                    total_unpaid_and_pending_payable_gwei: 10,
                    total_paid_payable_gwei: 22,
                    total_unpaid_receivable_gwei: 29,
                    total_paid_receivable_gwei: 32,
                }),
                query_results_opt: None
            }
        );
        assert_eq!(context_id, 1);
        let send_params = send_params_arc.lock().unwrap();
        assert_eq!(*send_params, vec![]);
        daemon_stop_handle.stop();
    }

    #[test]
    fn handles_response_to_nonexistent_conversation() {
        let incoming_message = UiSetupResponse {
            running: false,
            values: vec![],
            errors: vec![],
        }
        .tmb(3);
        let rt = make_rt();
        let (conversation_tx, conversation_rx) = unbounded();
        let mut inner = make_inner(&rt);
        inner.conversations.insert(4, conversation_tx);
        inner.conversations_waiting.insert(4);

        let inner = rt.block_on(ConnectionManagerEventLoop::handle_incoming_message_body(
            inner,
            Some(Ok(incoming_message.clone())),
        ));

        assert_eq!(conversation_rx.try_recv().is_err(), true); // no message to any conversation
        assert_eq!(inner.conversations_waiting.is_empty(), false);
    }

    #[test]
    fn handles_response_to_dead_conversation() {
        let incoming_message = UiSetupResponse {
            running: false,
            values: vec![],
            errors: vec![],
        }
        .tmb(4);
        let rt = make_rt();
        let (conversation_tx, _) = unbounded();
        let mut inner = make_inner(&rt);
        inner.conversations.insert(4, conversation_tx);
        inner.conversations_waiting.insert(4);

        let inner = rt.block_on(ConnectionManagerEventLoop::handle_incoming_message_body(
            inner,
            Some(Ok(incoming_message.clone())),
        ));

        assert_eq!(inner.conversations.is_empty(), true);
        assert_eq!(inner.conversations_waiting.is_empty(), true);
    }

    #[test]
    fn handles_failed_conversation_requester() {
        let rt = make_rt();
        let mut inner = make_inner(&rt);
        let (conversation_return_tx, _) = unbounded();
        inner.next_context_id = 42;
        inner.conversation_return_tx = conversation_return_tx;

        let inner = ConnectionManagerEventLoop::handle_conversation_trigger(inner);

        assert_eq!(inner.next_context_id, 43);
        assert_eq!(inner.conversations.is_empty(), true);
    }

    #[test]
    fn handles_fire_and_forget_outgoing_message() {
        let port = find_free_port();
        let rt = make_rt();
        let server = MockWebSocketsServer::new(port);
        let stop_handle = rt.block_on(server.start());
        let (_, talker_half) = WSTestClient::new(port).split();
        let (conversations_to_manager_tx, conversations_to_manager_rx) = unbounded_channel();
        let (_listener_to_manager_tx, listener_to_manager_rx) = unbounded_channel();
        let (_redirect_order_tx, redirect_order_rx) = unbounded_channel();
        let mut inner = make_inner(&rt);
        inner.next_context_id = 1;
        inner.conversations_to_manager_tx = conversations_to_manager_tx;
        inner.conversations_to_manager_rx = conversations_to_manager_rx;
        inner.listener_to_manager_rx = listener_to_manager_rx;
        inner.talker_half = talker_half;
        inner.redirect_order_rx = redirect_order_rx;
        let outgoing_message = UiUnmarshalError {
            message: "".to_string(),
            bad_data: "".to_string(),
        }
        .tmb(0);

        let _ = rt.block_on(ConnectionManagerEventLoop::handle_outgoing_message_body(
            inner,
            Some(OutgoingMessageType::FireAndForgetMessage(
                outgoing_message.clone(),
                1,
            )),
        ));

        let mut outgoing_messages = stop_handle.stop();
        assert_eq!(
            UiUnmarshalError::fmb(outgoing_messages.remove(0).unwrap()),
            UiUnmarshalError::fmb(outgoing_message)
        );
    }

    #[test]
    fn handles_outgoing_conversation_messages_to_dead_server() {
        let daemon_port = find_free_port();
        let rt = make_rt();
        let daemon_server = MockWebSocketsServer::new(daemon_port).queue_string("disconnect");
        let daemon_stop_handle = rt.block_on(daemon_server.start());
        let (conversation1_tx, conversation1_rx) = unbounded();
        let (conversation2_tx, conversation2_rx) = unbounded();
        let (conversation3_tx, conversation3_rx) = unbounded();
        let conversations =
            vec![
                (1, conversation1_tx),
                (2, conversation2_tx),
                (3, conversation3_tx),
            ]
            .into_iter()
            .collect::<HashMap<
                u64,
                crossbeam_channel::Sender<Result<MessageBody, NodeConversationTermination>>,
            >>();
        let mut inner = make_inner(&rt);
        inner.daemon_port = daemon_port;
        inner.conversations = conversations;
        inner.conversations_waiting = vec_to_set(vec![2, 3]);
        #[cfg(target_os = "macos")]
        {
            // macOS doesn't fail sends until some time after the pipe is broken: weird! Sick!
            let _ = inner.talker_half.sender.send_message(
                &mut inner.talker_half.stream,
                &OwnedMessage::Text("booga".to_string()),
            );
            thread::sleep(Duration::from_millis(500));
        }

        inner = rt.block_on(ConnectionManagerEventLoop::handle_outgoing_message_body(
            inner,
            Some(OutgoingMessageType::ConversationMessage(
                UiSetupRequest { values: vec![] }.tmb(2),
            )),
        ));

        assert_eq!(conversation1_rx.try_recv(), Err(TryRecvError::Empty)); // Wasn't waiting
        assert_eq!(
            conversation2_rx.try_recv(),
            Ok(Err(NodeConversationTermination::Fatal))
        ); // sender
        assert_eq!(
            conversation3_rx.try_recv(),
            Ok(Err(NodeConversationTermination::Fatal))
        ); // innocent bystander
        assert_eq!(inner.conversations_waiting.is_empty(), true);
        let _ = daemon_stop_handle.stop();
    }

    #[test]
    fn handles_outgoing_conversation_message_from_nonexistent_conversation() {
        let conversations = vec![(1, unbounded().0), (2, unbounded().0)]
            .into_iter()
            .collect::<HashMap<
                u64,
                crossbeam_channel::Sender<Result<MessageBody, NodeConversationTermination>>,
            >>();
        let rt = make_rt();
        let mut inner = make_inner(&rt);
        inner.conversations = conversations;
        inner.conversations_waiting = vec_to_set(vec![1]);

        inner = rt.block_on(ConnectionManagerEventLoop::handle_outgoing_message_body(
            inner,
            Some(OutgoingMessageType::ConversationMessage(
                UiSetupRequest { values: vec![] }.tmb(42),
            )),
        ));

        assert_eq!(inner.conversations.len(), 2);
        assert_eq!(inner.conversations_waiting.len(), 1);
    }

    #[test]
    fn handles_outgoing_fire_and_forget_messages_to_dead_server() {
        let daemon_port = find_free_port();
        let rt = make_rt();
        let daemon_server = MockWebSocketsServer::new(daemon_port);
        let daemon_stop_handle = rt.block_on(daemon_server.start());
        let (conversation1_tx, conversation1_rx) = unbounded();
        let (conversation2_tx, conversation2_rx) = unbounded();
        let (conversation3_tx, conversation3_rx) = unbounded();
        let conversations =
            vec![
                (1, conversation1_tx),
                (2, conversation2_tx),
                (3, conversation3_tx),
            ]
            .into_iter()
            .collect::<HashMap<
                u64,
                crossbeam_channel::Sender<Result<MessageBody, NodeConversationTermination>>,
            >>();
        let mut inner = make_inner(&rt);
        inner.daemon_port = daemon_port;
        inner.conversations = conversations;
        inner.conversations_waiting = vec_to_set(vec![2, 3]);
        #[cfg(target_os = "macos")]
        {
            // macOS doesn't fail sends until some time after the pipe is broken: weird! Sick!
            let _ = inner.talker_half.sender.send_message(
                &mut inner.talker_half.stream,
                &OwnedMessage::Text("booga".to_string()),
            );
            thread::sleep(Duration::from_millis(500));
        }

        inner = rt.block_on(ConnectionManagerEventLoop::handle_outgoing_message_body(
            inner,
            Some(OutgoingMessageType::FireAndForgetMessage(
                UiUnmarshalError {
                    message: String::new(),
                    bad_data: String::new(),
                }
                .tmb(0),
                2,
            )),
        ));

        let _ = daemon_stop_handle.stop();
        assert_eq!(conversation1_rx.try_recv(), Err(TryRecvError::Empty)); // Wasn't waiting
        assert_eq!(
            conversation2_rx.try_recv(),
            Ok(Err(NodeConversationTermination::Fatal))
        ); // sender
        assert_eq!(
            conversation3_rx.try_recv(),
            Ok(Err(NodeConversationTermination::Fatal))
        ); // innocent bystander
        assert_eq!(inner.conversations_waiting.is_empty(), true);
    }

    #[test]
    fn handles_close_order() {
        running_test();
        let port = find_free_port();
        let rt = make_multi_thread_rt();
        let server = MockWebSocketsServer::new(port);
        let stop_handle = rt.block_on(server.start());
        thread::sleep(Duration::from_millis(500)); // let the server get started
        let connectors = rt
            .block_on(ConnectionManagerBootstrapper::default().spawn_event_loop(
                port,
                Box::new(BroadcastHandleMock::new()),
                1000,
            ))
            .unwrap();
        let subject = ConnectionManager::new(connectors);
        let conversation1 = subject.start_conversation();
        let conversation2 = subject.start_conversation();

        subject.close();

        thread::sleep(Duration::from_millis(100)); // let the disappointment message show up
        let result = conversation1.transact(UiShutdownRequest {}.tmb(0), 1000);
        assert_eq!(result, Err(ClientError::ConnectionDropped));
        let result = conversation2.send(
            UiUnmarshalError {
                message: "".to_string(),
                bad_data: "".to_string(),
            }
            .tmb(0),
        );
        assert_eq!(result, Err(ClientError::ConnectionDropped));
        let received = stop_handle.stop();
        assert_eq!(received, vec![Err("Close(None)".to_string())]);
    }

    fn make_inner(rt: &Runtime) -> CmsInner {
        CmsInner {
            active_port: Some(0),
            daemon_port: 0,
            node_port: None,
            conversations: HashMap::new(),
            conversations_waiting: HashSet::new(),
            next_context_id: 0,
            demand_rx: unbounded_channel().1,
            conversation_return_tx: unbounded().0,
            conversations_to_manager_tx: unbounded_channel().0,
            conversations_to_manager_rx: unbounded_channel().1,
            listener_to_manager_rx: unbounded_channel().1,
            talker_half: rt.block_on(make_broken_talker_half()),
            broadcast_handle: Box::new(BroadcastHandleMock::new()),
            redirect_order_rx: unbounded_channel().1,
            redirect_response_tx: unbounded().0,
            active_port_response_tx: unbounded().0,
            closing_stage: Arc::new(AtomicBool::new(false)),
        }
    }

    pub async fn make_broken_talker_half() -> WSSender<(Message, Ack)> {
        let port = find_free_port();
        let server = MockWebSocketsServer::new(port);
        let stop_handle = server.start().await;
        let client = WSTestClient::new(port);
        let (_, talker_half) = client.split();
        let _ = stop_handle.kill();
        let _ = talker_half.close();
        talker_half
    }

    pub fn vec_to_set<T>(vec: Vec<T>) -> HashSet<T>
    where
        T: Eq + Hash,
    {
        let set: HashSet<T> = vec.into_iter().collect();
        set
    }
}
