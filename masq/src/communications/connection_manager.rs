// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::communications::broadcast_handlers::{
    BroadcastHandle, BroadcastHandler, BroadcastHandles, RedirectBroadcastHandle,
    RedirectBroadcastHandleFactory, RedirectBroadcastHandleFactoryReal,
    StandardBroadcastHandlerFactory, StandardBroadcastHandlerFactoryReal,
};
use crate::communications::client_listener_thread::{
    ClientListener, ClientListenerError, WSClientHandle,
};
use crate::communications::node_conversation::{NodeConversation, NodeConversationTermination};
use crate::terminal::terminal_interface_factory::TerminalInterfaceFactory;
use crate::terminal::{WTermInterface, WTermInterfaceImplementingSend};
use async_channel::{RecvError, Sender as WSSender};
use async_trait::async_trait;
use futures::future::{join_all, try_maybe_done};
use futures::FutureExt;
use masq_lib::messages::{CrashReason, FromMessageBody, ToMessageBody, UiNodeCrashedBroadcast};
use masq_lib::messages::{UiRedirect, NODE_UI_PROTOCOL};
use masq_lib::ui_gateway::{MessageBody, MessagePath};
use masq_lib::ui_traffic_converter::UiTrafficConverter;
use masq_lib::websockets_handshake::WSClientConnInitiator;
use std::cell::{RefCell, RefMut};
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::ops::DerefMut;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::broadcast::Sender as BroadcastSender;
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

pub struct ConnectionManagerBootstrapper {
    pub standard_broadcast_handler_factory: Box<dyn StandardBroadcastHandlerFactory>,
    pub redirect_broadcast_handle_factory: Box<dyn RedirectBroadcastHandleFactory>,
}

impl Default for ConnectionManagerBootstrapper {
    fn default() -> Self {
        Self::new(
            Box::new(StandardBroadcastHandlerFactoryReal::new()),
            Box::new(RedirectBroadcastHandleFactoryReal::default()),
        )
    }
}

impl ConnectionManagerBootstrapper {
    fn new(
        standard_broadcast_handler_factory: Box<dyn StandardBroadcastHandlerFactory>,
        redirect_broadcast_handle_factory: Box<dyn RedirectBroadcastHandleFactory>,
    ) -> Self {
        Self {
            standard_broadcast_handler_factory,
            redirect_broadcast_handle_factory,
        }
    }

    pub async fn spawn_background_loops(
        &self,
        port: u16,
        terminal_interface_opt: Option<Box<dyn WTermInterfaceImplementingSend>>,
        timeout_millis: u64,
    ) -> Result<ConnManagerLinksToSubordinates, ClientListenerError> {
        let (launcher, connectors) =
            self.prepare_launch(port, terminal_interface_opt, timeout_millis);

        //TODO you can have a method on launcher that can run these three following calls;
        // before that, clone the receiver and
        //TODO is this question mark tested?
        let talker_half = (launcher.spawn_ws_client_listener)().await?;

        let standard_broadcast_handle = (launcher.spawn_standard_broadcast_handler)();

        (launcher.spawn_cms_event_loop)(talker_half, standard_broadcast_handle);

        launcher.event_loop_ready_rx.borrow_mut().recv().await;

        Ok(connectors)
    }

    fn prepare_launch(
        &self,
        port: u16,
        terminal_interface_opt: Option<Box<dyn WTermInterfaceImplementingSend>>,
        timeout_millis: u64,
    ) -> (Launcher, ConnManagerLinksToSubordinates) {
        let (listener_to_manager_tx, listener_to_manager_rx) = unbounded_channel();
        let close_sync_flag = Arc::new(AtomicBool::new(false));
        let (async_close_signal_tx, async_close_signal_rx) = tokio::sync::broadcast::channel(10);
        let close_sig = CloseSignalling::new(async_close_signal_rx, close_sync_flag.clone());
        let close_sig_client_listener = close_sig.dup_receiver();
        //TODO how should I test that all these channels are interconnected?
        let close_sig_standard_broadcast_handler = close_sig.dup_receiver();

        // TODO does this future have to be in the closure?
        let spawn_ws_client_listener: SpawnClientListenerFuture = Box::new(move || {
            Box::pin(make_client_listener(
                port,
                listener_to_manager_tx,
                close_sig_client_listener,
                timeout_millis,
            ))
        });

        let spawn_standard_broadcast_handler = {
            let mut standard_broadcast_handler = self
                .standard_broadcast_handler_factory
                .make(terminal_interface_opt, close_sig_standard_broadcast_handler);
            Box::new(move || standard_broadcast_handler.spawn())
        };

        let (redirect_order_tx, redirect_order_rx) = unbounded_channel();
        let redirect_broadcast_handle = Box::new(RedirectBroadcastHandle::new(redirect_order_tx));

        let (demand_tx, demand_rx) = unbounded_channel();
        let (conversation_return_tx, conversation_return_rx) = unbounded_channel();
        let (redirect_response_tx, redirect_response_rx) = unbounded_channel();
        let (active_port_response_tx, active_port_response_rx) = unbounded_channel();
        let (conversations_to_manager_tx, conversations_to_manager_rx) = async_channel::unbounded();
        let (event_loop_ready_tx, event_loop_ready_rx) = unbounded_channel();

        let spawn_cms_event_loop = Box::new(
            move |ws_client_handle: Box<dyn WSClientHandle>,
                  standard_broadcast_handle: Box<dyn BroadcastHandle<MessageBody>>| {
                let broadcast_handles =
                    BroadcastHandles::new(standard_broadcast_handle, redirect_broadcast_handle);

                let inner = CmsManagerInner {
                    active_port: Some(port),
                    daemon_port: port,
                    node_port: None,
                    conversations: HashMap::new(),
                    conversations_waiting: HashSet::new(),
                    next_context_id: 1,
                    demand_rx,
                    conversation_return_tx,
                    conversations_to_manager_tx,
                    conversations_to_manager_rx,
                    listener_to_manager_rx,
                    ws_client_handle,
                    broadcast_handles,
                    redirect_order_rx,
                    redirect_response_tx,
                    active_port_response_tx,
                    close_sig,
                };

                let _join_handle = ConnectionsEventLoop::spawn(inner, event_loop_ready_tx);
            },
        );

        let launch_platform = Launcher::new(
            spawn_ws_client_listener,
            spawn_standard_broadcast_handler,
            spawn_cms_event_loop,
            event_loop_ready_rx,
        );

        let connection_manager_connectors = ConnectionManagerConnectors::new(
            demand_tx,
            conversation_return_rx,
            redirect_response_rx,
            active_port_response_rx,
        );

        let connection_manager_internal_communications = ConnManagerLinksToSubordinates {
            communication_channels: connection_manager_connectors,
            close_signaler: CloseSignaler::new(async_close_signal_tx, close_sync_flag),
        };

        (launch_platform, connection_manager_internal_communications)
    }
}

type SpawnClientListenerFuture = Box<
    dyn FnOnce() -> Pin<
        Box<dyn Future<Output = Result<Box<dyn WSClientHandle>, ClientListenerError>>>,
    >,
>;

type SpawnStandardBroadcastHandler = Box<dyn FnOnce() -> Box<dyn BroadcastHandle<MessageBody>>>;

type SpawnCMSEventLoop =
    Box<dyn FnOnce(Box<dyn WSClientHandle>, Box<dyn BroadcastHandle<MessageBody>>)>;

//TODO create a part called Spawning, containing those three...you can later call .spawn_loops(self) on it to finish the launch and take the last item of
// launcher out, with no cloning...
struct Launcher {
    spawn_ws_client_listener: SpawnClientListenerFuture,
    spawn_standard_broadcast_handler: SpawnStandardBroadcastHandler,
    spawn_cms_event_loop: SpawnCMSEventLoop,
    event_loop_ready_rx: RefCell<UnboundedReceiver<()>>,
}

impl Launcher {
    pub fn new(
        spawn_ws_client_listener: SpawnClientListenerFuture,
        spawn_standard_broadcast_handler: SpawnStandardBroadcastHandler,
        spawn_cms_event_loop: SpawnCMSEventLoop,
        event_loop_ready_rx: UnboundedReceiver<()>,
    ) -> Self {
        let event_loop_ready_rx = RefCell::new(event_loop_ready_rx);
        Self {
            spawn_ws_client_listener,
            spawn_standard_broadcast_handler,
            spawn_cms_event_loop,
            event_loop_ready_rx,
        }
    }
}

pub struct ConnManagerLinksToSubordinates {
    communication_channels: ConnectionManagerConnectors,
    close_signaler: CloseSignaler,
}

pub struct ConnectionManagerConnectors {
    demand_tx: UnboundedSender<Demand>,
    receivers: RefCell<ConnectionManagerReceivers>,
}

struct ConnectionManagerReceivers {
    conversation_return_rx: UnboundedReceiver<NodeConversation>,
    //TODO we never use this!!! ... it should probably print a message or something
    redirect_response_rx: UnboundedReceiver<Result<(), ClientListenerError>>,
    active_port_response_rx: UnboundedReceiver<Option<u16>>,
}

impl ConnectionManagerConnectors {
    pub fn new(
        demand_tx: UnboundedSender<Demand>,
        conversation_return_rx: UnboundedReceiver<NodeConversation>,
        redirect_response_rx: UnboundedReceiver<Result<(), ClientListenerError>>,
        active_port_response_rx: UnboundedReceiver<Option<u16>>,
    ) -> Self {
        let receivers = RefCell::new(ConnectionManagerReceivers {
            conversation_return_rx,
            redirect_response_rx,
            active_port_response_rx,
        });
        Self {
            demand_tx,
            receivers,
        }
    }

    pub fn receivers_mut(&self) -> RefMut<'_, ConnectionManagerReceivers> {
        self.receivers.borrow_mut()
    }
}

pub struct ConnectionManager {
    communication_channels: ConnectionManagerConnectors,
    closing_signaler: CloseSignaler,
}

impl ConnectionManager {
    pub fn new(internal_communication: ConnManagerLinksToSubordinates) -> Self {
        Self {
            communication_channels: internal_communication.communication_channels,
            closing_signaler: internal_communication.close_signaler,
        }
    }

    pub async fn active_ui_port(&self) -> Option<u16> {
        self.communication_channels
            .demand_tx
            .send(Demand::ActivePort)
            .expect("ConnectionManagerThread is dead");
        let mut receivers = self.communication_channels.receivers_mut();
        let request_fut = receivers.active_port_response_rx.recv();
        // (Duration::from_millis(COMPONENT_RESPONSE_TIMEOUT_MILLIS))
        // {
        //     Ok(ui_port_opt) => ui_port_opt,
        // Err(RecvTimeoutError::Timeout) => panic!("ConnectionManager is not responding"),
        //     // None => panic!("ConnectionManager is disconnected"),
        // };
        match tokio::time::timeout(
            Duration::from_millis(COMPONENT_RESPONSE_TIMEOUT_MILLIS),
            request_fut,
        )
        .await
        {
            Ok(Some(active_port_opt)) => active_port_opt,
            Ok(None) => todo!(),
            Err(elapsed) => todo!(),
        }
    }

    pub async fn start_conversation(&self) -> NodeConversation {
        self.communication_channels
            .demand_tx
            .send(Demand::Conversation)
            .expect("ConnectionManager is not connected");
        self.communication_channels
            .receivers_mut()
            .conversation_return_rx
            .recv()
            .await
            .expect("ConnectionManager is not connected")
    }

    pub fn close(&self) {
        self.closing_signaler.signalize_close();
        self.communication_channels
            .demand_tx
            .send(Demand::Close)
            .expect("ConnectionManagerThread is dead");
    }

    #[cfg(test)]
    pub fn is_closing(&self) -> bool {
        self.closing_signaler.is_closing()
    }
}

async fn make_client_listener(
    port: u16,
    listener_to_manager_tx: UnboundedSender<Result<MessageBody, ClientListenerError>>,
    close_sig: BroadcastReceiver<()>,
    timeout_millis: u64,
) -> Result<Box<dyn WSClientHandle>, ClientListenerError> {
    let conn_initiator = WSClientConnInitiator::new(port);
    //
    // let url = format!("ws://{}:{}", localhost(), port);
    // // TODO should the values be set in this config comprehensively tested?
    // let mut ws_config = WebSocketConfig::default();
    //
    // // TODO implement the handshake when ready
    // // ws_config.handshake = Some(Arc::new(WSClientHandshakeHandler::default()));
    // let websocket: WebSocket = match WebSocket::new(Some(&url), Some(ws_config)) {
    //     Ok(ws) => ws,
    //     Err(e) => todo!(),
    // };
    //
    // // TODO should the values be set in this config comprehensively tested?
    // let mut connect_options = ConnectOptions::default();
    // connect_options.block_async_connect = true;
    // connect_options.strategy = ConnectStrategy::Fallback;
    // connect_options.connect_timeout = Some(Duration::from_millis(timeout_millis));

    let ws = match conn_initiator.connect_with_timeout().await {
        Ok(ws) => ws,
        Err(Error::NotConnected) => todo!(), //return Err(ClientListenerError::Closed),
        Err(Error::ConnectionTimeout) => todo!(), // return Err(ClientListenerError::Timeout),
        Err(e) => return Err(ClientListenerError::Broken(format!("{:?}", e))),
    };

    let mut client_listener = ClientListener::new(ws);
    let talker_half = client_listener
        .start(close_sig, listener_to_manager_tx)
        .await;

    Ok(talker_half)
}

struct CmsManagerInner {
    active_port: Option<u16>,
    daemon_port: u16,
    node_port: Option<u16>,
    conversations:
        HashMap<u64, async_channel::Sender<Result<MessageBody, NodeConversationTermination>>>,
    conversations_waiting: HashSet<u64>,
    next_context_id: u64,
    demand_rx: UnboundedReceiver<Demand>,
    conversation_return_tx: UnboundedSender<NodeConversation>,
    conversations_to_manager_tx: async_channel::Sender<OutgoingMessageType>,
    conversations_to_manager_rx: async_channel::Receiver<OutgoingMessageType>,
    listener_to_manager_rx: UnboundedReceiver<Result<MessageBody, ClientListenerError>>,
    ws_client_handle: Box<dyn WSClientHandle>,
    broadcast_handles: BroadcastHandles,
    redirect_order_rx: UnboundedReceiver<RedirectOrder>,
    redirect_response_tx: UnboundedSender<Result<(), ClientListenerError>>,
    active_port_response_tx: UnboundedSender<Option<u16>>,
    close_sig: CloseSignalling,
}

pub struct ConnectionsEventLoop {}

impl ConnectionsEventLoop {
    fn spawn(
        mut inner: CmsManagerInner,
        event_loop_ready_tx: UnboundedSender<()>,
    ) -> JoinHandle<()> {
        tokio::task::spawn(async move {
            // TODO do we need this?
            event_loop_ready_tx.send(()).expect("cannot send pong");

            loop {
                match (
                    inner.close_sig.sync_state().load(Ordering::Relaxed),
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

    async fn loop_guts(mut inner: CmsManagerInner) -> CmsManagerInner {
        tokio::select! {
            demand_result = inner.demand_rx.recv() => Self::handle_demand (inner, demand_result).await,
            message_body_result_result = inner.conversations_to_manager_rx.recv() => Self::handle_outgoing_message_body (inner, message_body_result_result).await,
            redirect_order_result = inner.redirect_order_rx.recv() => Self::handle_redirect_order (inner, redirect_order_result).await,
            message_body_result_result = inner.listener_to_manager_rx.recv() => Self::handle_incoming_message_body (inner, message_body_result_result).await,
        }
    }

    async fn handle_demand(
        mut inner: CmsManagerInner,
        demand_opt: Option<Demand>,
    ) -> CmsManagerInner {
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

    fn handle_conversation_trigger(mut inner: CmsManagerInner) -> CmsManagerInner {
        let (manager_to_conversation_tx, manager_to_conversation_rx) = async_channel::unbounded();
        let context_id = inner.next_context_id;
        inner.next_context_id += 1;
        let conversation = NodeConversation::new(
            context_id,
            inner.conversations_to_manager_tx.clone(),
            manager_to_conversation_rx,
            inner.close_sig.sync_state().clone(),
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
        mut inner: CmsManagerInner,
        msg_result_opt: Option<Result<MessageBody, ClientListenerError>>,
    ) -> CmsManagerInner {
        match msg_result_opt {
            Some(msg_result) => match msg_result {
                Ok(message_body) => match message_body.path {
                    MessagePath::Conversation(context_id) => {
                        if let Some(manager_to_conversation_tx) =
                            inner.conversations.get(&context_id)
                        {
                            match manager_to_conversation_tx.send(Ok(message_body)).await {
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
                    MessagePath::FireAndForget => {
                        inner.broadcast_handles.handle_broadcast(message_body)
                    }
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
                return Self::fallback(inner, NodeConversationTermination::Fatal).await;
            }
        };
        inner
    }

    async fn handle_outgoing_message_body(
        mut inner: CmsManagerInner,
        msg_opt: Result<OutgoingMessageType, RecvError>,
    ) -> CmsManagerInner {
        match msg_opt {
            Err(e) => todo!(),
            Ok(OutgoingMessageType::ConversationMessage (message_body)) => match message_body.path {
                MessagePath::Conversation(context_id) => {
                    if let Some(_) = inner.conversations.get(&context_id){
                        let send_message_result = inner.ws_client_handle.send(Message::Text(UiTrafficConverter::new_marshal(message_body))).await;
                        match send_message_result {
                            Ok(_) => {
                                inner.conversations_waiting.insert(context_id);
                            },
                            Err(e) => {
                                inner = Self::fallback(inner, NodeConversationTermination::Fatal).await;
                            },
                        }
                    }
                // TODO we shouldn't probably only ignore that we did not find a conversation that definitely should've been triggered elsewhere
                },
                MessagePath::FireAndForget => panic!("NodeConversation should have prevented sending a FireAndForget message with transact()"),
            },
            Ok(OutgoingMessageType::FireAndForgetMessage(message_body, context_id)) => match message_body.path {
                MessagePath::FireAndForget => {
                    match inner.ws_client_handle.send(Message::Text(UiTrafficConverter::new_marshal(message_body))).await {
                        Ok (_) => {
                            if let Some(manager_to_conversation_tx) = inner.conversations.get(&context_id) {
                                match manager_to_conversation_tx.send(Err(NodeConversationTermination::FiredAndForgotten)).await {
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
            Ok(OutgoingMessageType::SignOff(context_id)) => {
                let _ = inner.conversations.remove (&context_id);
                let _ = inner.conversations_waiting.remove (&context_id);
            },
        };
        inner
    }

    async fn handle_redirect_order(
        mut inner: CmsManagerInner,
        redirect_order_opt: Option<RedirectOrder>,
    ) -> CmsManagerInner {
        let redirect_order = match redirect_order_opt {
            Some(ro) => ro,
            None => return inner, // Sender died; ignore
        };
        let (listener_to_manager_tx, listener_to_manager_rx) = unbounded_channel();
        let talker_half = match make_client_listener(
            redirect_order.port,
            listener_to_manager_tx,
            inner.close_sig.async_signal.resubscribe(),
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
        inner.ws_client_handle = talker_half;
        //TODO this is a working solution for conversations; know that a redirected fire-and-forget is just ignored and it does not resend if it's the absolutely first message: GH-487
        join_all(inner.conversations_waiting.iter().map(|context_id| {
            let error = if *context_id == redirect_order.context_id {
                NodeConversationTermination::Resend
            } else {
                NodeConversationTermination::Graceful
            };
            inner
                .conversations
                .get(context_id)
                .expect("conversations_waiting mishandled")
                .send(Err(error))
        }))
        .await;
        inner.conversations_waiting.clear();
        inner
            .redirect_response_tx
            .send(Ok(()))
            .expect("ConnectionManager is dead");
        inner
    }

    fn handle_active_port_request(inner: CmsManagerInner) -> CmsManagerInner {
        inner
            .active_port_response_tx
            .send(inner.active_port)
            .expect("ConnectionManager is dead");
        inner
    }

    async fn handle_close(mut inner: CmsManagerInner) -> CmsManagerInner {
        let _ = inner.ws_client_handle.disconnect().await;
        let _ = inner.ws_client_handle.close_talker_half();
        inner = Self::fallback(inner, NodeConversationTermination::Graceful).await;
        inner
    }

    async fn fallback(
        mut inner: CmsManagerInner,
        termination: NodeConversationTermination,
    ) -> CmsManagerInner {
        inner.node_port = None;
        match &inner.active_port {
            None => {
                inner = Self::disappoint_all_conversations(inner, termination).await;
                return inner;
            }
            Some(active_port) if *active_port == inner.daemon_port => {
                inner.active_port = None;
                inner = Self::disappoint_all_conversations(inner, termination).await;
                return inner;
            }
            Some(_) => inner.active_port = Some(inner.daemon_port),
        }
        let (listener_to_manager_tx, listener_to_manager_rx) = unbounded_channel();
        inner.listener_to_manager_rx = listener_to_manager_rx;
        match make_client_listener(
            inner.active_port.expect("Active port disappeared!"),
            listener_to_manager_tx,
            inner.close_sig.dup_receiver(),
            FALLBACK_TIMEOUT_MILLIS,
        )
        .await
        {
            Ok(talker_half) => inner.ws_client_handle = talker_half,
            Err(e) => panic!("ClientListenerThread could not be restarted: {:?}", e),
        };
        inner =
            Self::disappoint_waiting_conversations(inner, NodeConversationTermination::Fatal).await;
        inner
    }

    async fn disappoint_waiting_conversations(
        mut inner: CmsManagerInner,
        error: NodeConversationTermination,
    ) -> CmsManagerInner {
        join_all(inner.conversations_waiting.iter().map(|context_id| {
            inner
                .conversations
                .get(context_id)
                .expect("conversations_waiting mishandled")
                .send(Err(error))
        }))
        .await;
        inner.conversations_waiting.clear();
        inner
    }

    async fn disappoint_all_conversations(
        mut inner: CmsManagerInner,
        error: NodeConversationTermination,
    ) -> CmsManagerInner {
        join_all(
            inner
                .conversations
                .iter()
                .map(|(_, sender)| sender.send(Err(error))),
        )
        .await;
        inner.conversations.clear();
        inner.conversations_waiting.clear();
        inner
    }

    fn send_daemon_crashed(inner: &CmsManagerInner) {
        let crash_msg = UiNodeCrashedBroadcast {
            process_id: 0,
            crash_reason: CrashReason::DaemonCrashed,
        };
        inner.broadcast_handles.notify(crash_msg)
    }
}

pub struct CloseSignaler {
    async_signal: BroadcastSender<()>,
    sync_flag: Arc<AtomicBool>,
}

impl CloseSignaler {
    fn new(async_signal: BroadcastSender<()>, sync_flag: Arc<AtomicBool>) -> Self {
        Self {
            async_signal,
            sync_flag,
        }
    }

    pub fn signalize_close(&self) {
        self.sync_flag.store(true, Ordering::Relaxed);
        let _ = self.async_signal.send(());
    }

    #[cfg(test)]
    fn is_closing(&self) -> bool {
        self.sync_flag.load(Ordering::Relaxed)
    }
}

pub type BroadcastReceiver<T> = tokio::sync::broadcast::Receiver<T>;

pub struct CloseSignalling {
    async_signal: BroadcastReceiver<()>,
    sync_flag: Arc<AtomicBool>,
}

impl CloseSignalling {
    pub fn new(async_signal: BroadcastReceiver<()>, sync_flag: Arc<AtomicBool>) -> Self {
        Self {
            async_signal,
            sync_flag,
        }
    }
    pub fn dup_receiver(&self) -> BroadcastReceiver<()> {
        self.async_signal.resubscribe()
    }

    pub fn sync_state(&self) -> &Arc<AtomicBool> {
        &self.sync_flag
    }
}

#[cfg(test)]
impl CloseSignalling {
    pub fn make_for_test() -> (CloseSignaler, CloseSignalling) {
        let (tx, rx) = tokio::sync::broadcast::channel(10);
        let sync_flag = Arc::new(AtomicBool::new(false));
        let close_sig = CloseSignalling {
            async_signal: rx,
            sync_flag: sync_flag.clone(),
        };

        let signaler = CloseSignaler::new(tx, sync_flag);

        (signaler, close_sig)
    }
}

impl Clone for CloseSignalling {
    fn clone(&self) -> Self {
        CloseSignalling {
            async_signal: self.async_signal.resubscribe(),
            sync_flag: self.sync_flag.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::communications::client_listener_thread::WSClientHandleReal;
    use crate::communications::node_conversation::{ClientError, ManagerToConversationSender};
    use crate::test_utils::mocks::{
        RedirectBroadcastHandleFactoryMock, StandardBroadcastHandlerFactoryMock,
        StandardBroadcastHandlerMock, WSClientHandleMock,
    };
    use async_channel::TryRecvError;
    use masq_lib::messages::{
        CrashReason, FromMessageBody, ToMessageBody, UiDescriptorRequest, UiFinancialStatistics,
        UiNodeCrashedBroadcast, UiSetupBroadcast,
    };
    use masq_lib::messages::{
        UiFinancialsRequest, UiFinancialsResponse, UiRedirect, UiSetupRequest, UiSetupResponse,
        UiShutdownRequest, UiShutdownResponse, UiStartOrder, UiStartResponse, UiUnmarshalError,
    };
    use masq_lib::test_utils::mock_websockets_server::{
        MockWebSocketsServer, MockWebSocketsServerHandle,
    };
    #[cfg(target_os = "windows")]
    use masq_lib::test_utils::utils::is_running_under_github_actions;
    use masq_lib::test_utils::utils::{make_multi_thread_rt, make_rt};
    use masq_lib::test_utils::websockets_utils::{
        establish_ws_conn_with_handshake, websocket_utils,
    };
    use masq_lib::utils::{find_free_port, running_test};
    use std::hash::Hash;
    use std::process::Termination;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::thread::spawn;
    use std::time::{Duration, SystemTime};
    use tokio::runtime::Runtime;
    use tokio::select;
    use tokio::sync::mpsc::error::TryRecvError as TokioTryRecvError;
    use tokio::task::JoinError;

    #[test]
    fn constants_have_correct_values() {
        assert_eq!(COMPONENT_RESPONSE_TIMEOUT_MILLIS, 100);
        assert_eq!(REDIRECT_TIMEOUT_MILLIS, 500);
        assert_eq!(FALLBACK_TIMEOUT_MILLIS, 5000);
    }

    struct BroadcastHandleMock<Message> {
        send_params: Arc<Mutex<Vec<Message>>>,
    }

    impl<Message> Default for BroadcastHandleMock<Message> {
        fn default() -> Self {
            Self {
                send_params: Arc::new(Mutex::new(vec![])),
            }
        }
    }

    #[async_trait(?Send)]
    impl<Message: Send> BroadcastHandle<Message> for BroadcastHandleMock<Message> {
        fn send(&self, message: Message) -> () {
            self.send_params.lock().unwrap().push(message);
        }

        async fn wait_to_finish(&self) -> Result<(), JoinError> {
            todo!()
        }
    }

    impl<Message> BroadcastHandleMock<Message> {
        pub fn send_params(mut self, params: &Arc<Mutex<Vec<Message>>>) -> Self {
            self.send_params = params.clone();
            self
        }
    }

    async fn make_subject(
        server: MockWebSocketsServer,
    ) -> (ConnectionManager, MockWebSocketsServerHandle) {
        let port = server.port();
        let stop_handle = server.start().await;
        let connectors = ConnectionManagerBootstrapper::default()
            .spawn_background_loops(port, None, 1000)
            .await
            .unwrap();
        let subject = ConnectionManager::new(connectors);
        (subject, stop_handle)
    }

    #[tokio::test]
    async fn handle_demand_brings_the_party_to_a_close_if_the_channel_fails() {
        let inner = make_inner().await;

        let inner = ConnectionsEventLoop::handle_demand(inner, None).await;

        assert_eq!(inner.active_port, None);
    }

    #[tokio::test]
    async fn handles_interleaved_conversations() {
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
        let (mut subject, stop_handle) = make_subject(server).await;
        stop_handle.await_conn_established(None).await;
        let mut conversation1 = subject.start_conversation().await;
        let mut conversation2 = subject.start_conversation().await;

        let conversation1_handle = tokio::task::spawn(async move {
            let response1 = conversation1
                .transact(UiShutdownRequest {}.tmb(0), 1001)
                .await
                .unwrap();
            let response2 = conversation1
                .transact(UiStartOrder {}.tmb(0), 1002)
                .await
                .unwrap();
            (response1, response2)
        });
        let conversation2_handle = tokio::task::spawn(async move {
            let response1 = conversation2
                .transact(UiShutdownRequest {}.tmb(0), 1003)
                .await
                .unwrap();
            let response2 = conversation2
                .transact(UiStartOrder {}.tmb(0), 1004)
                .await
                .unwrap();
            (response1, response2)
        });

        let (conversation1_response1, conversation1_response2) =
            conversation1_handle.await.unwrap();
        let (conversation2_response1, conversation2_response2) =
            conversation2_handle.await.unwrap();
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
    }

    #[tokio::test]
    async fn handles_sending_fire_and_forget_messages() {
        let server = MockWebSocketsServer::new(find_free_port());
        let (mut subject, stop_handle) = make_subject(server).await;
        let mut conversation = subject.start_conversation().await;
        let message1 = UiUnmarshalError {
            message: "Message 1".to_string(),
            bad_data: "Data 1".to_string(),
        };
        let message2 = UiUnmarshalError {
            message: "Message 2".to_string(),
            bad_data: "Data 2".to_string(),
        };

        conversation.send(message1.clone().tmb(0)).await.unwrap();
        conversation.send(message2.clone().tmb(0)).await.unwrap();

        let mut outgoing_messages = stop_handle.retrieve_recorded_requests(Some(2)).await;
        assert_eq!(
            UiUnmarshalError::fmb(outgoing_messages.remove(0).expect_masq_msg()).unwrap(),
            (message1, 0)
        );
        assert_eq!(
            UiUnmarshalError::fmb(outgoing_messages.remove(0).expect_masq_msg()).unwrap(),
            (message2, 0)
        );
        assert_eq!(outgoing_messages.is_empty(), true);
    }

    #[tokio::test]
    async fn conversations_waiting_is_set_correctly_for_normal_operation() {
        let port = find_free_port();
        let server = MockWebSocketsServer::new(port)
            .queue_string("irrelevant")
            .queue_string("irrelevant");
        let stop_handle = server.start().await;
        let (_, close_sig) = CloseSignalling::make_for_test();
        let (demand_tx, demand_rx) = unbounded_channel();
        let (listener_to_manager_tx, listener_to_manager_rx) = unbounded_channel();
        let client_listener_handle = make_client_listener(
            port,
            listener_to_manager_tx.clone(),
            close_sig.async_signal,
            4_000,
        )
        .await
        .unwrap();
        let (conversations_to_manager_tx, conversations_to_manager_rx) = async_channel::unbounded();
        let (conversation_return_tx, mut conversation_return_rx) = unbounded_channel();
        let (_redirect_order_tx, redirect_order_rx) = unbounded_channel();
        let mut inner = make_inner().await;
        inner.next_context_id = 1;
        inner.conversation_return_tx = conversation_return_tx;
        inner.listener_to_manager_rx = listener_to_manager_rx;
        inner.conversations_to_manager_tx = conversations_to_manager_tx;
        inner.conversations_to_manager_rx = conversations_to_manager_rx;
        inner.ws_client_handle = client_listener_handle;
        inner.redirect_order_rx = redirect_order_rx;
        inner.demand_rx = demand_rx;
        demand_tx.send(Demand::Conversation).unwrap();
        inner = ConnectionsEventLoop::loop_guts(inner).await;
        let conversation1 = conversation_return_rx.try_recv().unwrap();
        let (conversation1_tx, mut conversation1_rx) = conversation1.tx_rx();
        demand_tx.send(Demand::Conversation).unwrap();
        inner = ConnectionsEventLoop::loop_guts(inner).await;
        let conversation2 = conversation_return_rx.try_recv().unwrap();
        let (conversation2_tx, mut conversation2_rx) = conversation2.tx_rx();
        let get_existing_keys = |inner: &CmsManagerInner| {
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
            .await
            .unwrap();
        inner = ConnectionsEventLoop::loop_guts(inner).await; // send request 1

        // Conversations 1 and 2, 1 waiting
        assert_eq!(get_existing_keys(&inner), vec_to_set(vec![1, 2]));
        assert_eq!(inner.conversations_waiting, vec_to_set(vec![1]));

        // Send request from Conversation 2 and process it
        conversation2_tx
            .send(OutgoingMessageType::ConversationMessage(
                UiShutdownRequest {}.tmb(2),
            ))
            .await
            .unwrap();
        inner = ConnectionsEventLoop::loop_guts(inner).await;

        // Conversations 1 and 2, 1 and 2 waiting
        assert_eq!(get_existing_keys(&inner), vec_to_set(vec![1, 2]));
        assert_eq!(inner.conversations_waiting, vec_to_set(vec![1, 2]));

        // Receive response for Conversation 2, process it, pull it out
        let response2 = UiShutdownResponse {}.tmb(2);
        assert_eq!(response2.path, MessagePath::Conversation(2));
        listener_to_manager_tx.send(Ok(response2)).unwrap();
        inner = ConnectionsEventLoop::loop_guts(inner).await;
        let result2 = conversation2_rx.try_recv().unwrap().unwrap();

        // Conversations 1 and 2, 1 still waiting
        assert_eq!(result2, UiShutdownResponse {}.tmb(2));
        assert_eq!(get_existing_keys(&inner), vec_to_set(vec![1, 2]));
        assert_eq!(inner.conversations_waiting, vec_to_set(vec![1]));

        // Receive response for Conversation 1, process it, pull it out
        let response1 = UiShutdownResponse {}.tmb(1);
        assert_eq!(response1.path, MessagePath::Conversation(1));
        listener_to_manager_tx.send(Ok(response1)).unwrap();
        inner = ConnectionsEventLoop::loop_guts(inner).await;
        let result1 = conversation1_rx.try_recv().unwrap().unwrap();

        // Conversations 1 and 2, nobody waiting
        assert_eq!(result1, UiShutdownResponse {}.tmb(1));
        assert_eq!(result2, UiShutdownResponse {}.tmb(2));
        assert_eq!(get_existing_keys(&inner), vec_to_set(vec![1, 2]));
        assert_eq!(inner.conversations_waiting, vec_to_set(vec![]));

        // Conversation 1 signals exit; process it
        conversation1_tx
            .send(OutgoingMessageType::SignOff(1))
            .await
            .unwrap();
        inner = ConnectionsEventLoop::loop_guts(inner).await;

        // Only Conversation 2, nobody waiting
        assert_eq!(get_existing_keys(&inner), vec_to_set(vec![2]));
        assert_eq!(inner.conversations_waiting, vec_to_set(vec![]));

        // Conversation 2 signals exit; process it
        conversation2_tx
            .send(OutgoingMessageType::SignOff(2))
            .await
            .unwrap();
        inner = ConnectionsEventLoop::loop_guts(inner).await;

        // No more conversations, nobody waiting
        assert_eq!(get_existing_keys(&inner), vec_to_set(vec![]));
        assert_eq!(inner.conversations_waiting, vec_to_set(vec![]));
    }

    #[tokio::test]
    async fn when_fallback_fails_daemon_crash_broadcast_is_sent() {
        let mut inner = make_inner().await;
        let (event_loop_ready_tx, mut event_loop_ready_rx) = unbounded_channel();
        let broadcast_handle_send_params_arc = Arc::new(Mutex::new(vec![]));
        let broadcast_handle =
            BroadcastHandleMock::default().send_params(&broadcast_handle_send_params_arc);
        inner.active_port = None;
        inner.broadcast_handles.standard = Box::new(broadcast_handle);

        ConnectionsEventLoop::spawn(inner, event_loop_ready_tx)
            .await
            .unwrap();

        event_loop_ready_rx.recv().await.unwrap();
        let mut broadcast_handle_send_params = broadcast_handle_send_params_arc.lock().unwrap();
        let message_body: MessageBody = (*broadcast_handle_send_params).remove(0);
        let crash_broadcast = UiNodeCrashedBroadcast::fmb(message_body).unwrap().0;
        assert_eq!(crash_broadcast.crash_reason, CrashReason::DaemonCrashed);
    }

    #[tokio::test]
    async fn handles_listener_fallback_from_node() {
        let daemon_port = find_free_port();
        let daemon = MockWebSocketsServer::new(daemon_port);
        let stop_handle = daemon.start().await;
        let node_port = find_free_port();
        let (conversation_tx, mut conversation_rx) = async_channel::unbounded();
        let (decoy_tx, mut decoy_rx) = async_channel::unbounded();
        let mut inner = make_inner().await;
        inner.active_port = Some(node_port);
        inner.daemon_port = daemon_port;
        inner.node_port = Some(node_port);
        inner.conversations.insert(4, conversation_tx);
        inner.conversations.insert(5, decoy_tx);
        inner.conversations_waiting.insert(4);

        let inner = ConnectionsEventLoop::handle_incoming_message_body(inner, None).await;

        wait_on_establishing_connection(inner.ws_client_handle.as_ref()).await;
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
        let _ = ConnectionsEventLoop::handle_outgoing_message_body(
            inner,
            Ok(OutgoingMessageType::ConversationMessage(
                UiSetupRequest { values: vec![] }.tmb(4),
            )),
        )
        .await;
        let mut outgoing_messages = stop_handle.retrieve_recorded_requests(Some(1)).await;
        assert_eq!(
            outgoing_messages.remove(0).expect_masq_msg(),
            UiSetupRequest { values: vec![] }.tmb(4)
        );
    }

    #[tokio::test]
    async fn doesnt_fall_back_from_daemon() {
        let unoccupied_port = find_free_port();
        let (waiting_conversation_tx, mut waiting_conversation_rx) = async_channel::unbounded();
        let (idle_conversation_tx, mut idle_conversation_rx) = async_channel::unbounded();
        let mut inner = make_inner().await;
        inner.daemon_port = unoccupied_port;
        inner.active_port = Some(unoccupied_port);
        inner.node_port = None;
        inner.conversations.insert(4, waiting_conversation_tx);
        inner.conversations.insert(5, idle_conversation_tx);
        inner.conversations_waiting.insert(4);

        let inner = ConnectionsEventLoop::fallback(inner, NodeConversationTermination::Fatal).await;

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

    #[tokio::test]
    async fn doesnt_fall_back_from_disconnected() {
        let unoccupied_port = find_free_port();
        let (waiting_conversation_tx, mut waiting_conversation_rx) = async_channel::unbounded();
        let (idle_conversation_tx, mut idle_conversation_rx) = async_channel::unbounded();
        let mut inner = make_inner().await;
        inner.daemon_port = unoccupied_port;
        inner.active_port = None;
        inner.node_port = None;
        inner.conversations.insert(4, waiting_conversation_tx);
        inner.conversations.insert(5, idle_conversation_tx);
        inner.conversations_waiting.insert(4);

        let inner = ConnectionsEventLoop::fallback(inner, NodeConversationTermination::Fatal).await;

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

    #[tokio::test]
    async fn handle_redirect_order_handles_rejection_from_node() {
        let node_port = find_free_port(); // won't put anything on this port
        let (redirect_response_tx, mut redirect_response_rx) = unbounded_channel();
        let mut inner = make_inner().await;
        inner.redirect_response_tx = redirect_response_tx;

        ConnectionsEventLoop::handle_redirect_order(
            inner,
            Some(RedirectOrder::new(node_port, 0, 1000)),
        )
        .await;

        let response = redirect_response_rx.try_recv().unwrap();
        match response {
            Err(ClientListenerError::Broken(_)) => (), //the string pasted in is OS-dependent
            x => panic!(
                "we expected ClientListenerError::Broken but got this: {:?}",
                x
            ),
        }
    }

    #[tokio::test]
    async fn handle_redirect_order_disappoints_waiting_conversations_with_resend_or_graceful() {
        let node_port = find_free_port();
        let server = MockWebSocketsServer::new(node_port);
        let server_stop_handle = server.start().await;
        let (redirect_response_tx, mut redirect_response_rx) = unbounded_channel();
        let (conversation1_tx, mut conversation1_rx) = async_channel::unbounded();
        let (conversation2_tx, mut conversation2_rx) = async_channel::unbounded();
        let conversations = vec![(1, conversation1_tx), (2, conversation2_tx)]
            .into_iter()
            .collect();
        let conversations_waiting = vec_to_set(vec![1, 2]);
        let mut inner = make_inner().await;
        inner.redirect_response_tx = redirect_response_tx;
        inner.conversations = conversations;
        inner.conversations_waiting = conversations_waiting;

        inner = ConnectionsEventLoop::handle_redirect_order(
            inner,
            Some(RedirectOrder::new(node_port, 1, 1000)),
        )
        .await;

        wait_on_establishing_connection(inner.ws_client_handle.as_ref()).await;
        let get_existing_keys = |inner: &CmsManagerInner| {
            inner
                .conversations
                .iter()
                .map(|(k, _)| *k)
                .collect::<HashSet<u64>>()
        };
        assert_eq!(get_existing_keys(&inner), vec_to_set(vec![1, 2]));
        assert_eq!(inner.conversations_waiting.is_empty(), true);
        assert_eq!(
            conversation1_rx.recv().await.unwrap(),
            Err(NodeConversationTermination::Resend)
        );
        assert_eq!(
            conversation2_rx.recv().await.unwrap(),
            Err(NodeConversationTermination::Graceful)
        );
        assert_eq!(redirect_response_rx.recv().await.unwrap(), Ok(()));
    }

    #[tokio::test]
    async fn handles_listener_fallback_from_daemon() {
        let daemon_port = find_free_port();
        let (conversation_tx, mut conversation_rx) = async_channel::unbounded();
        let (decoy_tx, mut decoy_rx) = async_channel::unbounded();
        let mut inner = make_inner().await;
        inner.active_port = Some(daemon_port);
        inner.daemon_port = daemon_port;
        inner.node_port = None;
        inner.conversations.insert(4, conversation_tx);
        inner.conversations.insert(5, decoy_tx);
        inner.conversations_waiting.insert(4);

        let _ = ConnectionsEventLoop::handle_incoming_message_body(inner, None).await;

        let disappointment = conversation_rx.try_recv().unwrap();
        assert_eq!(disappointment, Err(NodeConversationTermination::Fatal));
        let disappointment = decoy_rx.try_recv().unwrap();
        assert_eq!(disappointment, Err(NodeConversationTermination::Fatal));
    }

    #[tokio::test]
    async fn handles_fatal_reception_failure() {
        let daemon_port = find_free_port();
        let daemon = MockWebSocketsServer::new(daemon_port);
        let stop_handle = daemon.start().await;
        let node_port = find_free_port();
        let (conversation_tx, mut conversation_rx) = async_channel::unbounded();
        let (decoy_tx, mut decoy_rx) = async_channel::unbounded();
        let mut inner = make_inner().await;
        inner.active_port = Some(node_port);
        inner.daemon_port = daemon_port;
        inner.node_port = Some(node_port);
        inner.conversations.insert(4, conversation_tx);
        inner.conversations.insert(5, decoy_tx);
        inner.conversations_waiting.insert(4);

        let inner = ConnectionsEventLoop::handle_incoming_message_body(
            inner,
            Some(Err(ClientListenerError::Broken("Booga".to_string()))),
        )
        .await;

        wait_on_establishing_connection(inner.ws_client_handle.as_ref()).await;
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
        let _ = ConnectionsEventLoop::handle_outgoing_message_body(
            inner,
            Ok(OutgoingMessageType::ConversationMessage(
                UiSetupRequest { values: vec![] }.tmb(4),
            )),
        )
        .await;
        let mut outgoing_messages = stop_handle.retrieve_recorded_requests(Some(1)).await;
        assert_eq!(
            outgoing_messages.remove(0).expect_masq_msg(),
            UiSetupRequest { values: vec![] }.tmb(4)
        );
    }

    #[tokio::test]
    async fn handles_nonfatal_reception_failure() {
        let daemon_port = find_free_port();
        let node_port = find_free_port();
        let (conversation_tx, mut conversation_rx) = async_channel::unbounded();
        let mut inner = make_inner().await;
        inner.active_port = Some(node_port);
        inner.daemon_port = daemon_port;
        inner.node_port = Some(node_port);
        inner.conversations.insert(4, conversation_tx);
        inner.conversations_waiting.insert(4);

        let inner = ConnectionsEventLoop::handle_incoming_message_body(
            inner,
            Some(Err(ClientListenerError::UnexpectedPacket)),
        )
        .await;

        assert_eq!(conversation_rx.try_recv().is_err(), true); // no disconnect notification sent
        assert_eq!(inner.active_port, Some(node_port));
        assert_eq!(inner.daemon_port, daemon_port);
        assert_eq!(inner.node_port, Some(node_port));
        assert_eq!(inner.conversations_waiting.is_empty(), false);
    }

    #[tokio::test]
    async fn handles_broadcast() {
        let incoming_message = UiSetupBroadcast {
            running: false,
            values: vec![],
            errors: vec![],
        }
        .tmb(0);
        let (conversation_tx, mut conversation_rx) = async_channel::unbounded();
        let send_params_arc = Arc::new(Mutex::new(vec![]));
        let broadcast_handler = BroadcastHandleMock::default().send_params(&send_params_arc);
        let mut inner = make_inner().await;
        inner.conversations.insert(4, conversation_tx);
        inner.conversations_waiting.insert(4);
        inner.broadcast_handles.standard = Box::new(broadcast_handler);

        let inner = ConnectionsEventLoop::handle_incoming_message_body(
            inner,
            Some(Ok(incoming_message.clone())),
        )
        .await;

        assert_eq!(conversation_rx.try_recv().is_err(), true); // no message to any conversation
        assert_eq!(inner.conversations_waiting.is_empty(), false);
        let send_params = send_params_arc.lock().unwrap();
        assert_eq!(*send_params, vec![incoming_message]);
    }

    #[tokio::test]
    async fn can_follow_redirect() {
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
        let node_stop_handle = node_server.start().await;
        let daemon_port = find_free_port();
        let (release_opening_broadcast_msg_tx, release_opening_broadcast_msg_rx) =
            tokio::sync::oneshot::channel();
        let daemon_server = MockWebSocketsServer::new (daemon_port)
            .inject_opening_broadcasts_signal_receiver(release_opening_broadcast_msg_rx)
            .queue_response (UiRedirect {
                port: node_port,
                opcode: "financials".to_string(),
                context_id: Some(1),
                payload: r#"{"payableMinimumAmount":12,"payableMaximumAge":23,"receivableMinimumAmount":34,"receivableMaximumAge":45}"#.to_string()
            }.tmb(0));
        let daemon_stop_handle = daemon_server.start().await;
        let request = UiFinancialsRequest {
            stats_required: true,
            top_records_opt: None,
            custom_queries_opt: None,
        }
        .tmb(1);
        // let send_params_arc = Arc::new(Mutex::new(vec![]));
        let mut bootstrapper = ConnectionManagerBootstrapper::default();
        // bootstrapper.redirect_broadcast_handle_factory = Box::new(
        //     RedirectBroadcastHandleFactoryMock::default().make_result(Box::new(
        //         BroadcastHandleMock::default().send_params(&send_params_arc),
        //     )),
        // );
        let connectors = bootstrapper
            .spawn_background_loops(daemon_port, None, 1000)
            .await
            .unwrap();
        daemon_stop_handle.await_conn_established(None).await;
        release_opening_broadcast_msg_tx.send(()).unwrap();
        let mut subject = ConnectionManager::new(connectors);
        let mut conversation = subject.start_conversation().await;

        let result = conversation.transact(request, 1000).await.unwrap();

        let request_body = node_stop_handle.retrieve_recorded_requests(Some(1)).await[0]
            .clone()
            .expect_masq_msg();
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
        // let send_params = send_params_arc.lock().unwrap();
        // assert_eq!(*send_params, vec![]);
    }

    #[tokio::test]
    async fn handles_response_to_nonexistent_conversation() {
        let incoming_message = UiSetupResponse {
            running: false,
            values: vec![],
            errors: vec![],
        }
        .tmb(3);
        let (conversation_tx, mut conversation_rx) = async_channel::unbounded();
        let mut inner = make_inner().await;
        inner.conversations.insert(4, conversation_tx);
        inner.conversations_waiting.insert(4);

        let inner = ConnectionsEventLoop::handle_incoming_message_body(
            inner,
            Some(Ok(incoming_message.clone())),
        )
        .await;

        assert_eq!(conversation_rx.try_recv().is_err(), true); // no message to any conversation
        assert_eq!(inner.conversations_waiting.is_empty(), false);
    }

    #[tokio::test]
    async fn handles_response_to_dead_conversation() {
        let incoming_message = UiSetupResponse {
            running: false,
            values: vec![],
            errors: vec![],
        }
        .tmb(4);
        let (conversation_tx, _) = async_channel::unbounded();
        let mut inner = make_inner().await;
        inner.conversations.insert(4, conversation_tx);
        inner.conversations_waiting.insert(4);

        let inner = ConnectionsEventLoop::handle_incoming_message_body(
            inner,
            Some(Ok(incoming_message.clone())),
        )
        .await;

        assert_eq!(inner.conversations.is_empty(), true);
        assert_eq!(inner.conversations_waiting.is_empty(), true);
    }

    #[tokio::test]
    async fn handles_failed_conversation_requester() {
        let mut inner = make_inner().await;
        let (conversation_return_tx, _) = unbounded_channel();
        inner.next_context_id = 42;
        inner.conversation_return_tx = conversation_return_tx;

        let inner = ConnectionsEventLoop::handle_conversation_trigger(inner);

        assert_eq!(inner.next_context_id, 43);
        assert_eq!(inner.conversations.is_empty(), true);
    }

    #[tokio::test]
    async fn handles_fire_and_forget_outgoing_message() {
        let port = find_free_port();
        let server = MockWebSocketsServer::new(port);
        let stop_handle = server.start().await;
        let (_, close_sig) = CloseSignalling::make_for_test();
        let (listener_to_manager_tx, listener_to_manager_rx) = unbounded_channel();
        let client_listener_handle = make_client_listener(
            port,
            listener_to_manager_tx.clone(),
            close_sig.async_signal,
            4_000,
        )
        .await
        .unwrap();
        let (conversations_to_manager_tx, conversations_to_manager_rx) = async_channel::unbounded();
        let (_listener_to_manager_tx, listener_to_manager_rx) = unbounded_channel();
        let (_redirect_order_tx, redirect_order_rx) = unbounded_channel();
        let mut inner = make_inner().await;
        inner.next_context_id = 1;
        inner.conversations_to_manager_tx = conversations_to_manager_tx;
        inner.conversations_to_manager_rx = conversations_to_manager_rx;
        inner.listener_to_manager_rx = listener_to_manager_rx;
        inner.ws_client_handle = client_listener_handle;
        inner.redirect_order_rx = redirect_order_rx;
        let outgoing_message = UiUnmarshalError {
            message: "".to_string(),
            bad_data: "".to_string(),
        }
        .tmb(0);

        let _ = ConnectionsEventLoop::handle_outgoing_message_body(
            inner,
            Ok(OutgoingMessageType::FireAndForgetMessage(
                outgoing_message.clone(),
                1,
            )),
        )
        .await;

        let mut outgoing_messages = stop_handle.retrieve_recorded_requests(Some(1)).await;
        assert_eq!(
            UiUnmarshalError::fmb(outgoing_messages.remove(0).expect_masq_msg()),
            UiUnmarshalError::fmb(outgoing_message)
        );
    }

    #[tokio::test]
    async fn handles_outgoing_conversation_messages_to_dead_server() {
        let daemon_port = find_free_port();
        let daemon_server = MockWebSocketsServer::new(daemon_port);
        let daemon_stop_handle = daemon_server.start().await;
        let (conversation1_tx, mut conversation1_rx) = async_channel::unbounded();
        let (conversation2_tx, mut conversation2_rx) = async_channel::unbounded();
        let (conversation3_tx, mut conversation3_rx) = async_channel::unbounded();
        let conversations = vec![
            (1, conversation1_tx),
            (2, conversation2_tx),
            (3, conversation3_tx),
        ]
        .into_iter()
        .collect::<HashMap<u64, ManagerToConversationSender>>();
        let client_listener_handle =
            Box::new(WSClientHandleMock::default().send_result(Err(Arc::new(Error::NotConnected))));
        let mut inner = make_inner().await;
        inner.daemon_port = daemon_port;
        inner.conversations = conversations;
        inner.conversations_waiting = vec_to_set(vec![2, 3]);
        inner.ws_client_handle = client_listener_handle;

        inner = ConnectionsEventLoop::handle_outgoing_message_body(
            inner,
            Ok(OutgoingMessageType::ConversationMessage(
                UiSetupRequest { values: vec![] }.tmb(2),
            )),
        )
        .await;

        assert_eq!(conversation1_rx.try_recv(), Err(TryRecvError::Empty)); // Wasn't waiting
        assert_eq!(
            conversation2_rx.recv().await,
            Ok(Err(NodeConversationTermination::Fatal))
        ); // sender
        assert_eq!(
            conversation3_rx.recv().await,
            Ok(Err(NodeConversationTermination::Fatal))
        ); // innocent bystander
        assert_eq!(inner.conversations_waiting.is_empty(), true);
    }

    #[tokio::test]
    async fn handles_outgoing_conversation_message_from_nonexistent_conversation() {
        let conversations = vec![
            (1, async_channel::unbounded().0),
            (2, async_channel::unbounded().0),
        ]
        .into_iter()
        .collect::<HashMap<u64, ManagerToConversationSender>>();
        let mut inner = make_inner().await;
        inner.conversations = conversations;
        inner.conversations_waiting = vec_to_set(vec![1]);

        inner = ConnectionsEventLoop::handle_outgoing_message_body(
            inner,
            Ok(OutgoingMessageType::ConversationMessage(
                UiSetupRequest { values: vec![] }.tmb(42),
            )),
        )
        .await;

        assert_eq!(inner.conversations.len(), 2);
        assert_eq!(inner.conversations_waiting.len(), 1);
    }

    #[tokio::test]
    async fn handles_outgoing_fire_and_forget_messages_to_dead_server() {
        let daemon_port = find_free_port();
        let daemon_server = MockWebSocketsServer::new(daemon_port);
        let daemon_stop_handle = daemon_server.start().await;
        let (conversation1_tx, mut conversation1_rx) = async_channel::unbounded();
        let (conversation2_tx, mut conversation2_rx) = async_channel::unbounded();
        let (conversation3_tx, mut conversation3_rx) = async_channel::unbounded();
        let conversations = vec![
            (1, conversation1_tx),
            (2, conversation2_tx),
            (3, conversation3_tx),
        ]
        .into_iter()
        .collect::<HashMap<u64, ManagerToConversationSender>>();
        let ws_client_handle =
            Box::new(WSClientHandleMock::default().send_result(Err(Arc::new(Error::NotConnected))));
        let mut inner = make_inner().await;
        inner.daemon_port = daemon_port;
        inner.conversations = conversations;
        inner.conversations_waiting = vec_to_set(vec![2, 3]);
        inner.ws_client_handle = ws_client_handle;
        //TODO remove me if it works on MasOs without
        // #[cfg(target_os = "macos")]
        // {
        //     // macOS doesn't fail sends until some time after the pipe is broken: weird! Sick!
        //     let _ = inner.talker_half.sender.send_message(
        //         &mut inner.talker_half.stream,
        //         &OwnedMessage::Text("booga".to_string()),
        //     );
        //     thread::sleep(Duration::from_millis(500));
        // }

        inner = ConnectionsEventLoop::handle_outgoing_message_body(
            inner,
            Ok(OutgoingMessageType::FireAndForgetMessage(
                UiUnmarshalError {
                    message: String::new(),
                    bad_data: String::new(),
                }
                .tmb(0),
                2,
            )),
        )
        .await;

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

    #[tokio::test]
    async fn close_signaler_signalizes_properly() {
        let (tx, mut rx) = tokio::sync::broadcast::channel(10);
        let sync_flag = Arc::new(AtomicBool::new(false));
        let subject = CloseSignaler::new(tx, sync_flag.clone());

        subject.signalize_close();

        rx.recv().await.unwrap();
        assert_eq!(sync_flag.load(Ordering::Relaxed), true)
    }

    #[tokio::test]
    async fn handles_close_order() {
        running_test();
        let port = find_free_port();
        let server = MockWebSocketsServer::new(port);
        let server_handle = server.start().await;
        let mut bootstrapper = ConnectionManagerBootstrapper::default();
        let connectors = bootstrapper
            .spawn_background_loops(port, None, 1000)
            .await
            .unwrap();
        let mut subject = ConnectionManager::new(connectors);
        let mut conversation1 = subject.start_conversation().await;
        let mut conversation2 = subject.start_conversation().await;

        subject.close();

        assert_eq!(subject.closing_signaler.is_closing(), true);
        let result = conversation1
            .transact(UiShutdownRequest {}.tmb(0), 1000)
            .await;
        assert_eq!(result, Err(ClientError::ConnectionDropped));
        let result = conversation2
            .send(
                UiUnmarshalError {
                    message: "".to_string(),
                    bad_data: "".to_string(),
                }
                .tmb(0),
            )
            .await;
        assert_eq!(result, Err(ClientError::ConnectionDropped));
        server_handle.await_conn_disconnected(None).await;
    }

    async fn make_inner() -> CmsManagerInner {
        let broadcast_handles = BroadcastHandles::new(
            Box::new(BroadcastHandleMock::default()),
            Box::new(BroadcastHandleMock::default()),
        );
        CmsManagerInner {
            active_port: Some(0),
            daemon_port: 0,
            node_port: None,
            conversations: HashMap::new(),
            conversations_waiting: HashSet::new(),
            next_context_id: 0,
            demand_rx: unbounded_channel().1,
            conversation_return_tx: unbounded_channel().0,
            conversations_to_manager_tx: async_channel::unbounded().0,
            conversations_to_manager_rx: async_channel::unbounded().1,
            listener_to_manager_rx: unbounded_channel().1,
            ws_client_handle: Box::new(WSClientHandleMock::default()),
            broadcast_handles,
            redirect_order_rx: unbounded_channel().1,
            redirect_response_tx: unbounded_channel().0,
            active_port_response_tx: unbounded_channel().0,
            close_sig: CloseSignalling::make_for_test().1,
        }
    }

    async fn wait_on_establishing_connection(handle: &dyn WSClientHandle) {
        let start = SystemTime::now();
        let hard_limit = Duration::from_millis(2_000);
        loop {
            if handle.is_connection_open() {
                break;
            }

            if start.elapsed().expect("travelling in time") < hard_limit {
                tokio::time::sleep(Duration::from_millis(50)).await
            } else {
                panic!(
                    "Waiting for connection to establish in test but {} ms wasn't enough",
                    hard_limit.as_millis()
                )
            }
        }
    }

    // async fn make_broken_talker_half() -> WSClientHandle {
    //     let port = find_free_port();
    //     let server = MockWebSocketsServer::new(port);
    //     let stop_handle = server.start().await;
    //     let client_listener_handle =
    //         make_client_listener_handler_with_meaningless_event_loop_handle(port).await;
    //     while !client_listener_handle.is_connection_open() {
    //         tokio::time::sleep(Duration::from_millis(1)).await
    //     }
    //     let _ = stop_handle.kill(None).await;
    //     while client_listener_handle
    //         .send(Message::Text(UiTrafficConverter::new_marshal(
    //             UiDescriptorRequest {}.tmb(12),
    //         )))
    //         .await
    //         .is_ok()
    //     {
    //         tokio::time::sleep(Duration::from_millis(50)).await
    //     }
    //     client_listener_handle
    // }

    // async fn make_client_listener_handler_with_meaningless_event_loop_handle(
    //     port: u16,
    // ) -> WSClientHandle {
    //     let (websocket, talker_half, _) = websocket_utils(port).await;
    //     let meaningless_spawn_handle = tokio::task::spawn(async {
    //         loop {
    //             tokio::time::sleep(Duration::from_millis(1000)).await;
    //         }
    //     });
    //     WSClientHandle::new(websocket, meaningless_spawn_handle)
    // }

    fn vec_to_set<T>(vec: Vec<T>) -> HashSet<T>
    where
        T: Eq + Hash,
    {
        let set: HashSet<T> = vec.into_iter().collect();
        set
    }
}
