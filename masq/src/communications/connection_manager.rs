// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::communications::broadcast_handlers::{
    BroadcastHandles, RedirectBroadcastHandle, StandardBroadcastHandlerFactory,
    StandardBroadcastHandlerFactoryReal,
};
use crate::communications::node_conversation::{NodeConversation, NodeConversationTermination};
use crate::communications::websockets_client::{
    make_connection_with_timeout, ClientListener, ClientListenerError, WSClientHandle,
    WSHandshakeError, WSSenderWrapperReal,
};
use crate::terminal::WTermInterfaceDupAndSend;
use async_channel::RecvError;
use futures::future::join_all;
use masq_lib::messages::{CrashReason, UiNodeCrashedBroadcast};
use masq_lib::ui_gateway::{MessageBody, MessagePath};
use soketto::connection::Error;
use std::cell::{RefCell, RefMut};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::broadcast::Sender as BroadcastSender;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use tokio::task::JoinHandle;

pub const COMPONENT_RESPONSE_TIMEOUT_MILLIS: u64 = 100;
pub const CLIENT_WS_CONNECT_TIMEOUT_MS: u64 = 1500;
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

#[derive(Debug)]
pub enum BootstrapperError {
    ClientListener(ClientListenerError),
}

pub struct CMBootstrapper {
    pub standard_broadcast_handler_factory: Box<dyn StandardBroadcastHandlerFactory>,
}

impl Default for CMBootstrapper {
    fn default() -> Self {
        Self::new(Box::new(StandardBroadcastHandlerFactoryReal::default()))
    }
}

impl CMBootstrapper {
    fn new(standard_broadcast_handler_factory: Box<dyn StandardBroadcastHandlerFactory>) -> Self {
        Self {
            standard_broadcast_handler_factory,
        }
    }

    pub async fn establish_connection_manager(
        self,
        port: u16,
        terminal_interface_opt: Option<Box<dyn WTermInterfaceDupAndSend>>,
    ) -> Result<ConnectionManager, BootstrapperError> {
        let (listener_to_manager_tx, listener_to_manager_rx) = unbounded_channel();
        let close_sync_flag = SyncCloseFlag::default();
        let (async_close_signal_tx, async_close_signal_rx) = tokio::sync::broadcast::channel(10);
        let close_sig = ClosingStageDetector::new(async_close_signal_rx, close_sync_flag.clone());
        let close_sig_client_listener = close_sig.dup_receiver();
        let close_sig_standard_broadcast_handler = close_sig.dup_receiver();

        let ws_client_handle = match establish_client_listener(
            port,
            listener_to_manager_tx,
            close_sig_client_listener,
            CLIENT_WS_CONNECT_TIMEOUT_MS,
        )
        .await
        {
            Ok(ch) => ch,
            Err(e) => return Err(BootstrapperError::ClientListener(e)),
        };

        let standard_broadcast_handler = self
            .standard_broadcast_handler_factory
            .make(terminal_interface_opt, close_sig_standard_broadcast_handler)
            .spawn();

        let (redirect_order_tx, redirect_order_rx) = unbounded_channel();
        let redirect_broadcast_handle = Box::new(RedirectBroadcastHandle::new(redirect_order_tx));

        let (demand_tx, demand_rx) = unbounded_channel();
        let (conversation_return_tx, conversation_return_rx) = unbounded_channel();
        let (redirect_response_tx, redirect_response_rx) = unbounded_channel();
        let (active_port_response_tx, active_port_response_rx) = unbounded_channel();
        let (conversations_to_manager_tx, conversations_to_manager_rx) = async_channel::unbounded();

        let broadcast_handles =
            BroadcastHandles::new(standard_broadcast_handler, redirect_broadcast_handle);

        let services = ConnectionServices {
            active_port_opt: Some(port),
            daemon_port: port,
            node_port_opt: None,
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

        let central_even_loop_join_handle = CentralEventLoop::spawn(services);

        let internal_communications = CMChannelsToSubordinates::new(
            demand_tx,
            conversation_return_rx,
            redirect_response_rx,
            active_port_response_rx,
        );

        let close_signaler = CloseSignaler::new(async_close_signal_tx, close_sync_flag);

        let manager = ConnectionManager::new(
            internal_communications,
            close_signaler,
            central_even_loop_join_handle,
        );

        Ok(manager)
    }
}

struct CMChannelsToSubordinates {
    demand_tx: UnboundedSender<Demand>,
    response_receivers: RefCell<CMReceivers>,
}

struct CMReceivers {
    conversation_return_rx: UnboundedReceiver<NodeConversation>,
    // TODO We don't do anything useful with this
    redirect_response_rx: UnboundedReceiver<Result<(), ClientListenerError>>,
    active_port_response_rx: UnboundedReceiver<Option<u16>>,
}

impl CMChannelsToSubordinates {
    fn new(
        demand_tx: UnboundedSender<Demand>,
        conversation_return_rx: UnboundedReceiver<NodeConversation>,
        redirect_response_rx: UnboundedReceiver<Result<(), ClientListenerError>>,
        active_port_response_rx: UnboundedReceiver<Option<u16>>,
    ) -> Self {
        let receivers = RefCell::new(CMReceivers {
            conversation_return_rx,
            redirect_response_rx,
            active_port_response_rx,
        });
        Self {
            demand_tx,
            response_receivers: receivers,
        }
    }

    pub fn receivers_mut(&self) -> RefMut<'_, CMReceivers> {
        self.response_receivers.borrow_mut()
    }
}

pub struct ConnectionManager {
    internal_communications: CMChannelsToSubordinates,
    closing_signaler: CloseSignaler,
    central_even_loop_join_handle: JoinHandle<()>,
    timeouts: Timeouts,
}

impl ConnectionManager {
    fn new(
        internal_communications: CMChannelsToSubordinates,
        closing_signaler: CloseSignaler,
        central_even_loop_join_handle: JoinHandle<()>,
    ) -> Self {
        Self {
            internal_communications,
            closing_signaler,
            central_even_loop_join_handle,
            timeouts: Timeouts::default(),
        }
    }

    pub async fn active_ui_port(&self) -> Option<u16> {
        self.internal_communications
            .demand_tx
            .send(Demand::ActivePort)
            .expect("ConnectionManagerThread is dead");
        let mut receivers = self.internal_communications.receivers_mut();
        let request_fut = receivers.active_port_response_rx.recv();
        let timeout = self.timeouts.component_response_millis;

        match tokio::time::timeout(Duration::from_millis(timeout), request_fut).await {
            Ok(Some(active_port_opt)) => active_port_opt,
            Ok(None) => panic!("active_ui_port(): ConnectionManager is disconnected"),
            Err(_) => panic!(
                "active_ui_port(): ConnectionManager is not responding after {} ms",
                timeout
            ),
        }
    }

    pub async fn start_conversation(&self) -> NodeConversation {
        self.internal_communications
            .demand_tx
            .send(Demand::Conversation)
            .expect("ConnectionManager is not connected");
        self.internal_communications
            .receivers_mut()
            .conversation_return_rx
            .recv()
            .await
            .expect("ConnectionManager is not connected")
    }

    pub fn close(&self) {
        self.closing_signaler.signalize_close();
        self.internal_communications
            .demand_tx
            .send(Demand::Close)
            .expect("CMDepartment not working");
    }
}

async fn establish_client_listener(
    port: u16,
    listener_to_manager_tx: UnboundedSender<Result<MessageBody, ClientListenerError>>,
    close_sig_rx: BroadcastReceiver<()>,
    timeout_millis: u64,
) -> Result<WSClientHandle, ClientListenerError> {
    let (talker_half, listener_half) =
        match make_connection_with_timeout(port, timeout_millis).await {
            Ok(ws) => ws,
            Err(WSHandshakeError::Timeout) => {
                return Err(ClientListenerError::Timeout {
                    elapsed_ms: timeout_millis,
                })
            }
            Err(e) => return Err(ClientListenerError::Broken(format!("{:?}", &e))),
        };

    let client_listener = ClientListener::new(listener_half);
    let abort_handle = client_listener
        .start(close_sig_rx, listener_to_manager_tx)
        .await;

    let sender_wrapper = Box::new(WSSenderWrapperReal::new(talker_half));

    let handle = WSClientHandle::new(sender_wrapper, abort_handle);

    Ok(handle)
}

struct ConnectionServices {
    active_port_opt: Option<u16>,
    daemon_port: u16,
    node_port_opt: Option<u16>,
    conversations:
        HashMap<u64, async_channel::Sender<Result<MessageBody, NodeConversationTermination>>>,
    conversations_waiting: HashSet<u64>,
    next_context_id: u64,
    demand_rx: UnboundedReceiver<Demand>,
    conversation_return_tx: UnboundedSender<NodeConversation>,
    conversations_to_manager_tx: async_channel::Sender<OutgoingMessageType>,
    conversations_to_manager_rx: async_channel::Receiver<OutgoingMessageType>,
    listener_to_manager_rx: UnboundedReceiver<Result<MessageBody, ClientListenerError>>,
    ws_client_handle: WSClientHandle,
    broadcast_handles: BroadcastHandles,
    redirect_order_rx: UnboundedReceiver<RedirectOrder>,
    redirect_response_tx: UnboundedSender<Result<(), ClientListenerError>>,
    active_port_response_tx: UnboundedSender<Option<u16>>,
    close_sig: ClosingStageDetector,
}

pub struct CentralEventLoop {}

impl CentralEventLoop {
    fn spawn(mut services: ConnectionServices) -> JoinHandle<()> {
        tokio::task::spawn(async move {
            loop {
                match services.active_port_opt {
                    None => {
                        Self::send_daemon_crashed(&services);
                        break;
                    }
                    _ => match Self::loop_guts(services).await {
                        Some(returned_inner) => services = returned_inner,
                        None => break,
                    },
                }
            }
        })
    }

    // TODO can it be done somehow better, these Options?
    async fn loop_guts(mut services: ConnectionServices) -> Option<ConnectionServices> {
        tokio::select! {
            demand_result = services.demand_rx.recv() => Self::handle_demand (services, demand_result).await,
            message_body_result_result = services.conversations_to_manager_rx.recv() => Some(Self::handle_outgoing_message_body (services, message_body_result_result).await),
            redirect_order_result = services.redirect_order_rx.recv() => Some(Self::handle_redirect_order (services, redirect_order_result).await),
            message_body_result_result = services.listener_to_manager_rx.recv() => Some(Self::handle_incoming_message_body (services, message_body_result_result).await),
        }
    }

    async fn handle_demand(
        mut services: ConnectionServices,
        demand_opt: Option<Demand>,
    ) -> Option<ConnectionServices> {
        match demand_opt {
            Some(Demand::Conversation) => Some(Self::handle_conversation_trigger(services)),
            Some(Demand::ActivePort) => Some(Self::handle_active_port_request(services)),
            Some(Demand::Close) => {
                Self::handle_close(services).await;
                None
            }
            None => {
                services.active_port_opt = None;
                Some(services)
            }
        }
    }

    fn handle_conversation_trigger(mut services: ConnectionServices) -> ConnectionServices {
        let (manager_to_conversation_tx, manager_to_conversation_rx) = async_channel::unbounded();
        let context_id = services.next_context_id;
        services.next_context_id += 1;
        let conversation = NodeConversation::new(
            context_id,
            services.conversations_to_manager_tx.clone(),
            manager_to_conversation_rx,
            services.close_sig.sync_flag_ref().clone(),
        );
        services
            .conversations
            .insert(context_id, manager_to_conversation_tx);
        match services.conversation_return_tx.send(conversation) {
            Ok(_) => (),
            Err(_) => {
                services.conversations.remove(&context_id);
            }
        };
        services
    }

    async fn handle_incoming_message_body(
        mut services: ConnectionServices,
        msg_result_opt: Option<Result<MessageBody, ClientListenerError>>,
    ) -> ConnectionServices {
        match msg_result_opt {
            Some(msg_result) => match msg_result {
                Ok(message_body) => match message_body.path {
                    MessagePath::Conversation(context_id) => {
                        if let Some(manager_to_conversation_tx) =
                            services.conversations.get(&context_id)
                        {
                            match manager_to_conversation_tx.send(Ok(message_body)).await {
                                Ok(_) => {
                                    services.conversations_waiting.remove(&context_id);
                                }
                                Err(_) => {
                                    // The conversation waiting for this message died
                                    let _ = services.conversations.remove(&context_id);
                                    let _ = services.conversations_waiting.remove(&context_id);
                                }
                            }
                        }
                    }
                    MessagePath::FireAndForget => {
                        services.broadcast_handles.handle_broadcast(message_body)
                    }
                },
                Err(e) => {
                    if e.is_fatal() {
                        if e == ClientListenerError::Closed {
                            let _ = services.ws_client_handle.close().await;
                        }
                        // Fatal connection error: connection is dead, need to reestablish
                        return Self::fallback(services, NodeConversationTermination::Fatal).await;
                    } else {
                        // Non-fatal connection error: connection to server is still up, but we have
                        // no idea which conversation the message was meant for
                        // Should we print something to stderr here? We don't have a stderr handy...
                    }
                }
            },
            None => {
                if !services.close_sig.sync_flag.masq_is_closing() {
                    return Self::fallback(services, NodeConversationTermination::Fatal).await;
                }
            }
        };
        services
    }

    async fn handle_outgoing_message_body(
        mut services: ConnectionServices,
        msg_opt: Result<OutgoingMessageType, RecvError>,
    ) -> ConnectionServices {
        match msg_opt {
            Err(_) => panic!("Conversations to manager channel died unexpectedly"),
            Ok(OutgoingMessageType::ConversationMessage (message_body)) => match message_body.path {
                MessagePath::Conversation(context_id) => {
                    if let Some(_) = services.conversations.get(&context_id){
                        let send_message_result = services.ws_client_handle.send_msg(message_body).await;
                        match send_message_result {
                            Ok(_) => {
                                services.conversations_waiting.insert(context_id);
                            },
                            Err(_) => {
                                services = Self::fallback(services, NodeConversationTermination::Fatal).await;
                            },
                        }
                    }
                // TODO we probably shouldn't only ignore that we didn't find a conversation that
                // must've been triggered somehow; however, we don't have logging in here
                },
                MessagePath::FireAndForget => panic!("NodeConversation should have prevented sending a FireAndForget message with transact()"),
            },
            Ok(OutgoingMessageType::FireAndForgetMessage(message_body, context_id)) => match message_body.path {
                MessagePath::FireAndForget => {
                    match services.ws_client_handle.send_msg(message_body).await {
                        Ok (_) => {
                            if let Some(manager_to_conversation_tx) = services.conversations.get(&context_id) {
                                match manager_to_conversation_tx.send(Err(NodeConversationTermination::FiredAndForgotten)).await {
                                    Ok(_) => (),
                                    Err(_) => {
                                        // The conversation waiting for this message died
                                        let _ = services.conversations.remove(&context_id);
                                    }
                                }
                            }
                        },
                        Err (_) => services = Self::fallback(services, NodeConversationTermination::Fatal).await,
                    }
                }
                MessagePath::Conversation(_) => panic!("NodeConversation should have prevented sending a Conversation message with send()"),
            },
            Ok(OutgoingMessageType::SignOff(context_id)) => {
                let _ = services.conversations.remove (&context_id);
                let _ = services.conversations_waiting.remove (&context_id);
            },
        };
        services
    }

    async fn handle_redirect_order(
        mut services: ConnectionServices,
        redirect_order_opt: Option<RedirectOrder>,
    ) -> ConnectionServices {
        let redirect_order = match redirect_order_opt {
            Some(ro) => ro,
            None => return services, // Sender died; ignore
        };
        let (listener_to_manager_tx, listener_to_manager_rx) = unbounded_channel();
        let talker_half = match establish_client_listener(
            redirect_order.port,
            listener_to_manager_tx,
            services.close_sig.async_signal.resubscribe(),
            redirect_order.timeout_millis,
        )
        .await
        {
            Ok(th) => th,
            Err(e) => {
                // TODO is this ever tested?
                let _ = services.redirect_response_tx.send(Err(e));
                return services;
            }
        };
        services.node_port_opt = Some(redirect_order.port);
        services.active_port_opt = Some(redirect_order.port);
        services.listener_to_manager_rx = listener_to_manager_rx;
        services.ws_client_handle = talker_half;
        //TODO this is a working solution for conversations; know that a redirected fire-and-forget is just ignored and it does not resend if it's the absolutely first message: GH-487
        join_all(services.conversations_waiting.iter().map(|context_id| {
            let error = if *context_id == redirect_order.context_id {
                NodeConversationTermination::Resend
            } else {
                NodeConversationTermination::Graceful
            };
            services
                .conversations
                .get(context_id)
                .expect("conversations_waiting mishandled")
                .send(Err(error))
        }))
        .await;
        services.conversations_waiting.clear();
        services
            .redirect_response_tx
            .send(Ok(()))
            .expect("ConnectionManager is dead");
        services
    }

    fn handle_active_port_request(services: ConnectionServices) -> ConnectionServices {
        services
            .active_port_response_tx
            .send(services.active_port_opt)
            .expect("ConnectionManager is dead");
        services
    }

    async fn handle_close(mut services: ConnectionServices) {
        let _ = services.ws_client_handle.close().await;
    }

    async fn fallback(
        mut services: ConnectionServices,
        termination: NodeConversationTermination,
    ) -> ConnectionServices {
        services.node_port_opt = None;
        match &services.active_port_opt {
            None => {
                services = Self::disappoint_all_conversations(services, termination).await;
                return services;
            }
            Some(active_port) if *active_port == services.daemon_port => {
                services.active_port_opt = None;
                services = Self::disappoint_all_conversations(services, termination).await;
                return services;
            }
            Some(_) => services.active_port_opt = Some(services.daemon_port),
        }
        let (listener_to_manager_tx, listener_to_manager_rx) = unbounded_channel();
        services.listener_to_manager_rx = listener_to_manager_rx;
        match establish_client_listener(
            services.active_port_opt.expect("Active port disappeared!"),
            listener_to_manager_tx,
            services.close_sig.dup_receiver(),
            FALLBACK_TIMEOUT_MILLIS,
        )
        .await
        {
            Ok(talker_half) => services.ws_client_handle = talker_half,
            Err(e) => panic!("ClientListenerThread could not be restarted: {:?}", e),
        };
        services =
            Self::disappoint_waiting_conversations(services, NodeConversationTermination::Fatal)
                .await;
        services
    }

    async fn disappoint_waiting_conversations(
        mut services: ConnectionServices,
        error: NodeConversationTermination,
    ) -> ConnectionServices {
        join_all(services.conversations_waiting.iter().map(|context_id| {
            services
                .conversations
                .get(context_id)
                .expect("conversations_waiting mishandled")
                .send(Err(error))
        }))
        .await;
        services.conversations_waiting.clear();
        services
    }

    async fn disappoint_all_conversations(
        mut services: ConnectionServices,
        error: NodeConversationTermination,
    ) -> ConnectionServices {
        join_all(
            services
                .conversations
                .iter()
                .map(|(_, sender)| sender.send(Err(error))),
        )
        .await;
        services.conversations.clear();
        services.conversations_waiting.clear();
        services
    }

    fn send_daemon_crashed(services: &ConnectionServices) {
        let crash_msg = UiNodeCrashedBroadcast {
            process_id: 0,
            crash_reason: CrashReason::DaemonCrashed,
        };
        services.broadcast_handles.notify(crash_msg)
    }
}

pub struct CloseSignaler {
    async_signal: BroadcastSender<()>,
    sync_flag: SyncCloseFlag,
}

impl CloseSignaler {
    fn new(async_signal: BroadcastSender<()>, sync_flag: SyncCloseFlag) -> Self {
        Self {
            async_signal,
            sync_flag,
        }
    }

    pub fn signalize_close(&self) {
        self.sync_flag.services.store(true, Ordering::Relaxed);
        let _ = self.async_signal.send(());
    }
}

pub type BroadcastReceiver<T> = tokio::sync::broadcast::Receiver<T>;

pub struct ClosingStageDetector {
    // This is meant to be used mostly in select!() macros. It allows to terminate loops with
    // an async task which is being awaited but not ready at the moment.
    async_signal: BroadcastReceiver<()>,
    // This works as a simple check in code not being intercepted by async calls.
    sync_flag: SyncCloseFlag,
}

impl ClosingStageDetector {
    pub fn new(async_signal: BroadcastReceiver<()>, sync_flag: SyncCloseFlag) -> Self {
        Self {
            async_signal,
            sync_flag,
        }
    }
    pub fn dup_receiver(&self) -> BroadcastReceiver<()> {
        self.async_signal.resubscribe()
    }

    pub fn sync_flag_ref(&self) -> &SyncCloseFlag {
        &self.sync_flag
    }
}

impl Clone for ClosingStageDetector {
    fn clone(&self) -> Self {
        ClosingStageDetector {
            async_signal: self.async_signal.resubscribe(),
            sync_flag: self.sync_flag.clone(),
        }
    }
}

#[derive(Clone)]
pub struct SyncCloseFlag {
    services: Arc<AtomicBool>,
}

impl Default for SyncCloseFlag {
    fn default() -> Self {
        Self {
            services: Arc::new(AtomicBool::new(false)),
        }
    }
}

impl SyncCloseFlag {
    pub fn masq_is_closing(&self) -> bool {
        self.services.load(Ordering::Relaxed)
    }
}

struct Timeouts {
    component_response_millis: u64,
}

impl Default for Timeouts {
    fn default() -> Self {
        Self {
            component_response_millis: COMPONENT_RESPONSE_TIMEOUT_MILLIS,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::communications::node_conversation::{ClientError, ManagerToConversationSender};
    use crate::test_utils::mocks::{BroadcastHandleMock, WSSenderWrapperMock};
    use async_channel::TryRecvError;
    use futures::io::{BufReader, BufWriter};
    use masq_lib::messages::{
        CrashReason, FromMessageBody, ToMessageBody, UiFinancialStatistics, UiNodeCrashedBroadcast,
        UiSetupBroadcast, NODE_UI_PROTOCOL,
    };
    use masq_lib::messages::{
        UiFinancialsRequest, UiFinancialsResponse, UiRedirect, UiSetupRequest, UiSetupResponse,
        UiShutdownRequest, UiShutdownResponse, UiStartOrder, UiStartResponse, UiUnmarshalError,
    };
    use masq_lib::test_utils::mock_websockets_server::{
        MWSSMessage, MockServerHandshakeResponse, MockWebSocketsServer, MockWebSocketsServerHandle,
    };
    #[cfg(target_os = "windows")]
    use masq_lib::test_utils::utils::is_running_under_github_actions;
    use masq_lib::utils::{find_free_port, localhost, running_test};
    use soketto::handshake::Server;
    use std::hash::Hash;
    use std::io::ErrorKind;
    use std::net::SocketAddr;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use std::{io, vec};
    use tokio::net::TcpListener;
    use tokio_util::compat::TokioAsyncReadCompatExt;

    impl ConnectionManager {
        pub fn is_closing(&self) -> bool {
            self.closing_signaler.is_closing()
        }
    }

    impl CloseSignaler {
        pub fn is_closing(&self) -> bool {
            self.sync_flag.masq_is_closing()
        }
    }

    impl ClosingStageDetector {
        pub fn make_for_test() -> (CloseSignaler, ClosingStageDetector) {
            let (tx, rx) = tokio::sync::broadcast::channel(10);
            let sync_flag = SyncCloseFlag {
                services: Arc::new(AtomicBool::new(false)),
            };
            let close_sig = ClosingStageDetector {
                async_signal: rx,
                sync_flag: sync_flag.clone(),
            };

            let signaler = CloseSignaler::new(tx, sync_flag);

            (signaler, close_sig)
        }
    }

    #[test]
    fn constants_have_correct_values() {
        assert_eq!(COMPONENT_RESPONSE_TIMEOUT_MILLIS, 100);
        assert_eq!(CLIENT_WS_CONNECT_TIMEOUT_MS, 1500);
        assert_eq!(FALLBACK_TIMEOUT_MILLIS, 5000);
    }

    async fn make_subject(
        server: MockWebSocketsServer,
    ) -> (ConnectionManager, MockWebSocketsServerHandle) {
        let port = server.port();
        let stop_handle = server.start().await;
        let subject = CMBootstrapper::default()
            .establish_connection_manager(port, None)
            .await
            .unwrap();
        (subject, stop_handle)
    }

    #[tokio::test]
    async fn connection_manager_attributes_are_properly_set_up() {
        let server = MockWebSocketsServer::new(find_free_port());

        let (manager, _) = make_subject(server).await;

        assert_eq!(manager.timeouts.component_response_millis, 100)
    }

    #[tokio::test]
    async fn handle_demand_brings_the_party_to_a_close_if_the_channel_fails() {
        let services = make_inner().await;

        let services = CentralEventLoop::handle_demand(services, None)
            .await
            .unwrap();

        assert_eq!(services.active_port_opt, None);
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
        let (subject, _server_stop_handle) = make_subject(server).await;
        let conversation1 = subject.start_conversation().await;
        let conversation2 = subject.start_conversation().await;

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
        let (subject, stop_handle) = make_subject(server).await;
        let conversation = subject.start_conversation().await;
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

        let mut recorded = stop_handle.stop().await;
        let faf_1 = recorded.requests.remove(0);
        assert_eq!(
            UiUnmarshalError::fmb(faf_1.message_body()).unwrap().0,
            message1
        );
        let faf_2 = recorded.requests.remove(0);
        assert_eq!(
            UiUnmarshalError::fmb(faf_2.message_body()).unwrap().0,
            message2
        );
        assert!(recorded.requests.is_empty());
    }

    #[tokio::test]
    async fn conversations_waiting_is_set_correctly_for_normal_operation() {
        let port = find_free_port();
        let server = MockWebSocketsServer::new(port);
        let _server_stop_handle = server.start().await;
        let (_, close_sig) = ClosingStageDetector::make_for_test();
        let (demand_tx, demand_rx) = unbounded_channel();
        let (listener_to_manager_tx, listener_to_manager_rx) = unbounded_channel();
        let client_listener_handle = establish_client_listener(
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
        let mut services = make_inner().await;
        services.next_context_id = 1;
        services.conversation_return_tx = conversation_return_tx;
        services.listener_to_manager_rx = listener_to_manager_rx;
        services.conversations_to_manager_tx = conversations_to_manager_tx;
        services.conversations_to_manager_rx = conversations_to_manager_rx;
        services.ws_client_handle = client_listener_handle;
        services.redirect_order_rx = redirect_order_rx;
        services.demand_rx = demand_rx;
        demand_tx.send(Demand::Conversation).unwrap();
        services = CentralEventLoop::loop_guts(services).await.unwrap();
        let conversation1 = conversation_return_rx.try_recv().unwrap();
        let (conversation1_tx, conversation1_rx) = conversation1.tx_rx();
        demand_tx.send(Demand::Conversation).unwrap();
        services = CentralEventLoop::loop_guts(services).await.unwrap();
        let conversation2 = conversation_return_rx.try_recv().unwrap();
        let (conversation2_tx, conversation2_rx) = conversation2.tx_rx();
        let get_existing_keys = |services: &ConnectionServices| {
            services
                .conversations
                .iter()
                .map(|(k, _)| *k)
                .collect::<HashSet<u64>>()
        };

        // Conversations 1 and 2, nobody waiting
        assert_eq!(get_existing_keys(&services), vec_to_set(vec![1, 2]));
        assert_eq!(services.conversations_waiting, vec_to_set(vec![]));

        // Send request from Conversation 1 and process it
        conversation1_tx
            .send(OutgoingMessageType::ConversationMessage(
                UiShutdownRequest {}.tmb(1),
            ))
            .await
            .unwrap();
        services = CentralEventLoop::loop_guts(services).await.unwrap(); // send request 1

        // Conversations 1 and 2, 1 waiting
        assert_eq!(get_existing_keys(&services), vec_to_set(vec![1, 2]));
        assert_eq!(services.conversations_waiting, vec_to_set(vec![1]));

        // Send request from Conversation 2 and process it
        conversation2_tx
            .send(OutgoingMessageType::ConversationMessage(
                UiShutdownRequest {}.tmb(2),
            ))
            .await
            .unwrap();
        services = CentralEventLoop::loop_guts(services).await.unwrap();

        // Conversations 1 and 2, 1 and 2 waiting
        assert_eq!(get_existing_keys(&services), vec_to_set(vec![1, 2]));
        assert_eq!(services.conversations_waiting, vec_to_set(vec![1, 2]));

        // Receive response for Conversation 2, process it, pull it out
        let response2 = UiShutdownResponse {}.tmb(2);
        assert_eq!(response2.path, MessagePath::Conversation(2));
        listener_to_manager_tx.send(Ok(response2)).unwrap();
        services = CentralEventLoop::loop_guts(services).await.unwrap();
        let result2 = conversation2_rx.try_recv().unwrap().unwrap();

        // Conversations 1 and 2, 1 still waiting
        assert_eq!(result2, UiShutdownResponse {}.tmb(2));
        assert_eq!(get_existing_keys(&services), vec_to_set(vec![1, 2]));
        assert_eq!(services.conversations_waiting, vec_to_set(vec![1]));

        // Receive response for Conversation 1, process it, pull it out
        let response1 = UiShutdownResponse {}.tmb(1);
        assert_eq!(response1.path, MessagePath::Conversation(1));
        listener_to_manager_tx.send(Ok(response1)).unwrap();
        services = CentralEventLoop::loop_guts(services).await.unwrap();
        let result1 = conversation1_rx.try_recv().unwrap().unwrap();

        // Conversations 1 and 2, nobody waiting
        assert_eq!(result1, UiShutdownResponse {}.tmb(1));
        assert_eq!(result2, UiShutdownResponse {}.tmb(2));
        assert_eq!(get_existing_keys(&services), vec_to_set(vec![1, 2]));
        assert_eq!(services.conversations_waiting, vec_to_set(vec![]));

        // Conversation 1 signals exit; process it
        conversation1_tx
            .send(OutgoingMessageType::SignOff(1))
            .await
            .unwrap();
        services = CentralEventLoop::loop_guts(services).await.unwrap();

        // Only Conversation 2, nobody waiting
        assert_eq!(get_existing_keys(&services), vec_to_set(vec![2]));
        assert_eq!(services.conversations_waiting, vec_to_set(vec![]));

        // Conversation 2 signals exit; process it
        conversation2_tx
            .send(OutgoingMessageType::SignOff(2))
            .await
            .unwrap();
        services = CentralEventLoop::loop_guts(services).await.unwrap();

        // No more conversations, nobody waiting
        assert_eq!(get_existing_keys(&services), vec_to_set(vec![]));
        assert_eq!(services.conversations_waiting, vec_to_set(vec![]));
    }

    #[tokio::test]
    async fn when_fallback_fails_daemon_crash_broadcast_is_sent() {
        let mut services = make_inner().await;
        let broadcast_handle_send_params_arc = Arc::new(Mutex::new(vec![]));
        let standard_broadcast_handle =
            BroadcastHandleMock::default().send_params(&broadcast_handle_send_params_arc);
        services.active_port_opt = None;
        services.broadcast_handles = BroadcastHandles::new(
            Box::new(standard_broadcast_handle),
            Box::new(BroadcastHandleMock::default()),
        );

        CentralEventLoop::spawn(services).await.unwrap();

        let mut broadcast_handle_send_params = broadcast_handle_send_params_arc.lock().unwrap();
        let message_body: MessageBody = (*broadcast_handle_send_params).remove(0);
        let crash_broadcast = UiNodeCrashedBroadcast::fmb(message_body).unwrap().0;
        assert_eq!(crash_broadcast.crash_reason, CrashReason::DaemonCrashed);
    }

    #[tokio::test]
    async fn handles_listener_fallback_from_node() {
        let daemon_port = find_free_port();
        let daemon = MockWebSocketsServer::new(daemon_port);
        let deamon_stop_handle = daemon.start().await;
        let node_port = find_free_port();
        let (conversation_tx, conversation_rx) = async_channel::unbounded();
        let (decoy_tx, decoy_rx) = async_channel::unbounded();
        let mut services = make_inner().await;
        services.active_port_opt = Some(node_port);
        services.daemon_port = daemon_port;
        services.node_port_opt = Some(node_port);
        services.conversations.insert(4, conversation_tx);
        services.conversations.insert(5, decoy_tx);
        services.conversations_waiting.insert(4);

        let services = CentralEventLoop::handle_incoming_message_body(services, None).await;

        let disconnect_notification = conversation_rx.try_recv().unwrap();
        assert_eq!(
            disconnect_notification,
            Err(NodeConversationTermination::Fatal)
        );
        assert_eq!(decoy_rx.try_recv().is_err(), true); // no disconnect notification sent to conversation not waiting
        assert_eq!(services.active_port_opt, Some(daemon_port));
        assert_eq!(services.daemon_port, daemon_port);
        assert_eq!(services.node_port_opt, None);
        assert_eq!(services.conversations_waiting.is_empty(), true);
        let _inner = CentralEventLoop::handle_outgoing_message_body(
            services,
            Ok(OutgoingMessageType::ConversationMessage(
                UiSetupRequest { values: vec![] }.tmb(4),
            )),
        )
        .await;
        let requests = deamon_stop_handle.stop().await;
        assert_eq!(
            requests.requests,
            vec![MWSSMessage::MessageBody(
                UiSetupRequest { values: vec![] }.tmb(4)
            )]
        )
    }

    #[tokio::test]
    async fn doesnt_fall_back_from_daemon() {
        let unoccupied_port = find_free_port();
        let (waiting_conversation_tx, waiting_conversation_rx) = async_channel::unbounded();
        let (idle_conversation_tx, idle_conversation_rx) = async_channel::unbounded();
        let mut services = make_inner().await;
        services.daemon_port = unoccupied_port;
        services.active_port_opt = Some(unoccupied_port);
        services.node_port_opt = None;
        services.conversations.insert(4, waiting_conversation_tx);
        services.conversations.insert(5, idle_conversation_tx);
        services.conversations_waiting.insert(4);

        let services =
            CentralEventLoop::fallback(services, NodeConversationTermination::Fatal).await;

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
        assert_eq!(services.daemon_port, unoccupied_port);
        assert_eq!(services.active_port_opt, None);
        assert_eq!(services.node_port_opt, None);
    }

    #[tokio::test]
    async fn doesnt_fall_back_from_disconnected() {
        let unoccupied_port = find_free_port();
        let (waiting_conversation_tx, waiting_conversation_rx) = async_channel::unbounded();
        let (idle_conversation_tx, idle_conversation_rx) = async_channel::unbounded();
        let mut services = make_inner().await;
        services.daemon_port = unoccupied_port;
        services.active_port_opt = None;
        services.node_port_opt = None;
        services.conversations.insert(4, waiting_conversation_tx);
        services.conversations.insert(5, idle_conversation_tx);
        services.conversations_waiting.insert(4);

        let services =
            CentralEventLoop::fallback(services, NodeConversationTermination::Fatal).await;

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
        assert_eq!(services.daemon_port, unoccupied_port);
        assert_eq!(services.active_port_opt, None);
        assert_eq!(services.node_port_opt, None);
    }

    #[tokio::test]
    async fn handle_redirect_order_handles_rejection_from_node() {
        let node_port = find_free_port(); // won't put anything on this port
        let (redirect_response_tx, mut redirect_response_rx) = unbounded_channel();
        let mut services = make_inner().await;
        services.redirect_response_tx = redirect_response_tx;

        CentralEventLoop::handle_redirect_order(
            services,
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
        let _server_stop_handle = server.start().await;
        let (redirect_response_tx, mut redirect_response_rx) = unbounded_channel();
        let (conversation1_tx, conversation1_rx) = async_channel::unbounded();
        let (conversation2_tx, conversation2_rx) = async_channel::unbounded();
        let conversations = vec![(1, conversation1_tx), (2, conversation2_tx)]
            .into_iter()
            .collect();
        let conversations_waiting = vec_to_set(vec![1, 2]);
        let mut services = make_inner().await;
        services.redirect_response_tx = redirect_response_tx;
        services.conversations = conversations;
        services.conversations_waiting = conversations_waiting;

        services = CentralEventLoop::handle_redirect_order(
            services,
            Some(RedirectOrder::new(node_port, 1, 1000)),
        )
        .await;

        let get_existing_keys = |services: &ConnectionServices| {
            services
                .conversations
                .iter()
                .map(|(k, _)| *k)
                .collect::<HashSet<u64>>()
        };
        assert_eq!(get_existing_keys(&services), vec_to_set(vec![1, 2]));
        assert_eq!(services.conversations_waiting.is_empty(), true);
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
        let (conversation_tx, conversation_rx) = async_channel::unbounded();
        let (decoy_tx, decoy_rx) = async_channel::unbounded();
        let mut services = make_inner().await;
        services.active_port_opt = Some(daemon_port);
        services.daemon_port = daemon_port;
        services.node_port_opt = None;
        services.conversations.insert(4, conversation_tx);
        services.conversations.insert(5, decoy_tx);
        services.conversations_waiting.insert(4);

        let _ = CentralEventLoop::handle_incoming_message_body(services, None).await;

        let disappointment = conversation_rx.try_recv().unwrap();
        assert_eq!(disappointment, Err(NodeConversationTermination::Fatal));
        let disappointment = decoy_rx.try_recv().unwrap();
        assert_eq!(disappointment, Err(NodeConversationTermination::Fatal));
    }

    #[tokio::test]
    async fn handles_fatal_reception_failure() {
        let daemon_port = find_free_port();
        let daemon = MockWebSocketsServer::new(daemon_port);
        let deamon_stop_handle = daemon.start().await;
        let node_port = find_free_port();
        let (conversation_tx, conversation_rx) = async_channel::unbounded();
        let (decoy_tx, decoy_rx) = async_channel::unbounded();
        let mut services = make_inner().await;
        services.active_port_opt = Some(node_port);
        services.daemon_port = daemon_port;
        services.node_port_opt = Some(node_port);
        services.conversations.insert(4, conversation_tx);
        services.conversations.insert(5, decoy_tx);
        services.conversations_waiting.insert(4);

        let services = CentralEventLoop::handle_incoming_message_body(
            services,
            Some(Err(ClientListenerError::Broken("Booga".to_string()))),
        )
        .await;

        // TODO remove the commented out code
        // wait_on_establishing_connection(services.ws_client_handle.as_ref()).await;
        let disconnect_notification = conversation_rx.try_recv().unwrap();
        assert_eq!(
            disconnect_notification,
            Err(NodeConversationTermination::Fatal)
        );
        assert_eq!(decoy_rx.try_recv().is_err(), true); // no disconnect notification sent to conversation not waiting
        assert_eq!(services.active_port_opt, Some(daemon_port));
        assert_eq!(services.daemon_port, daemon_port);
        assert_eq!(services.node_port_opt, None);
        assert_eq!(services.conversations_waiting.is_empty(), true);
        let _inner = CentralEventLoop::handle_outgoing_message_body(
            services,
            Ok(OutgoingMessageType::ConversationMessage(
                UiSetupRequest { values: vec![] }.tmb(4),
            )),
        )
        .await;
        let mut outgoing_messages = deamon_stop_handle.stop().await;
        let request = outgoing_messages.requests.remove(0);
        assert_eq!(
            UiSetupRequest::fmb(request.message_body()).unwrap(),
            (UiSetupRequest { values: vec![] }, 4)
        );
        let none_other = outgoing_messages.requests.is_empty();
        assert_eq!(none_other, true)
    }

    #[tokio::test]
    async fn handles_nonfatal_reception_failure() {
        let daemon_port = find_free_port();
        let node_port = find_free_port();
        let (conversation_tx, conversation_rx) = async_channel::unbounded();
        let mut services = make_inner().await;
        services.active_port_opt = Some(node_port);
        services.daemon_port = daemon_port;
        services.node_port_opt = Some(node_port);
        services.conversations.insert(4, conversation_tx);
        services.conversations_waiting.insert(4);

        let services = CentralEventLoop::handle_incoming_message_body(
            services,
            Some(Err(ClientListenerError::UnexpectedPacket)),
        )
        .await;

        assert_eq!(conversation_rx.try_recv().is_err(), true); // no disconnect notification sent
        assert_eq!(services.active_port_opt, Some(node_port));
        assert_eq!(services.daemon_port, daemon_port);
        assert_eq!(services.node_port_opt, Some(node_port));
        assert_eq!(services.conversations_waiting.is_empty(), false);
    }

    #[tokio::test]
    async fn handles_broadcast() {
        let incoming_message = UiSetupBroadcast {
            running: false,
            values: vec![],
            errors: vec![],
        }
        .tmb(0);
        let (conversation_tx, conversation_rx) = async_channel::unbounded();
        let send_params_arc = Arc::new(Mutex::new(vec![]));
        let standard_broadcast_handle =
            BroadcastHandleMock::default().send_params(&send_params_arc);
        let mut services = make_inner().await;
        services.conversations.insert(4, conversation_tx);
        services.conversations_waiting.insert(4);
        services.broadcast_handles = BroadcastHandles::new(
            Box::new(standard_broadcast_handle),
            Box::new(BroadcastHandleMock::default()),
        );

        let services = CentralEventLoop::handle_incoming_message_body(
            services,
            Some(Ok(incoming_message.clone())),
        )
        .await;

        assert_eq!(conversation_rx.try_recv().is_err(), true); // no message to any conversation
        assert_eq!(services.conversations_waiting.is_empty(), false);
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
        let daemon_server = MockWebSocketsServer::new (daemon_port)
            .opening_faf_triggered_by_msg()
            .queue_response(UiRedirect {
                port: node_port,
                opcode: "financials".to_string(),
                context_id: Some(1),
                payload: r#"{"payableMinimumAmount":12,"payableMaximumAge":23,"receivableMinimumAmount":34,"receivableMaximumAge":45}"#.to_string()
            }.tmb(0));
        let _daemon_stop_handle = daemon_server.start().await;
        let request = UiFinancialsRequest {
            stats_required: true,
            top_records_opt: None,
            custom_queries_opt: None,
        };
        let bootstrapper = CMBootstrapper::default();
        let subject = bootstrapper
            .establish_connection_manager(daemon_port, None)
            .await
            .unwrap();
        let active_ui_port_before_redirect = subject.active_ui_port().await.unwrap();
        let conversation = subject.start_conversation().await;

        let result = conversation
            .transact(request.clone().tmb(1), 1000)
            .await
            .unwrap();

        let active_ui_port_after_redirect = subject.active_ui_port().await.unwrap();
        let mut recorded = node_stop_handle.stop().await;
        let recorded_request = recorded.requests.remove(0);
        assert_eq!(
            UiFinancialsRequest::fmb(recorded_request.message_body()).unwrap(),
            (request, 1)
        );
        assert!(recorded.requests.is_empty());
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
        assert_eq!(active_ui_port_before_redirect, daemon_port);
        assert_eq!(active_ui_port_after_redirect, node_port)
    }

    #[tokio::test]
    async fn handles_response_to_nonexistent_conversation() {
        let incoming_message = UiSetupResponse {
            running: false,
            values: vec![],
            errors: vec![],
        }
        .tmb(3);
        let (conversation_tx, conversation_rx) = async_channel::unbounded();
        let mut services = make_inner().await;
        services.conversations.insert(4, conversation_tx);
        services.conversations_waiting.insert(4);

        let services = CentralEventLoop::handle_incoming_message_body(
            services,
            Some(Ok(incoming_message.clone())),
        )
        .await;

        assert_eq!(conversation_rx.try_recv().is_err(), true); // no message to any conversation
        assert_eq!(services.conversations_waiting.is_empty(), false);
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
        let mut services = make_inner().await;
        services.conversations.insert(4, conversation_tx);
        services.conversations_waiting.insert(4);

        let services = CentralEventLoop::handle_incoming_message_body(
            services,
            Some(Ok(incoming_message.clone())),
        )
        .await;

        assert_eq!(services.conversations.is_empty(), true);
        assert_eq!(services.conversations_waiting.is_empty(), true);
    }

    #[tokio::test]
    async fn handles_failed_conversation_requester() {
        let mut services = make_inner().await;
        let (conversation_return_tx, _) = unbounded_channel();
        services.next_context_id = 42;
        services.conversation_return_tx = conversation_return_tx;

        let services = CentralEventLoop::handle_conversation_trigger(services);

        assert_eq!(services.next_context_id, 43);
        assert_eq!(services.conversations.is_empty(), true);
    }

    #[tokio::test]
    async fn handles_fire_and_forget_outgoing_message() {
        let port = find_free_port();
        let server = MockWebSocketsServer::new(port);
        let server_stop_handle = server.start().await;
        let (_, close_sig) = ClosingStageDetector::make_for_test();
        let (listener_to_manager_tx, listener_to_manager_rx) = unbounded_channel();
        let client_listener_handle =
            establish_client_listener(port, listener_to_manager_tx, close_sig.async_signal, 4_000)
                .await
                .unwrap();
        let (conversations_to_manager_tx, conversations_to_manager_rx) = async_channel::unbounded();
        let (_redirect_order_tx, redirect_order_rx) = unbounded_channel();
        let mut services = make_inner().await;
        services.next_context_id = 1;
        services.conversations_to_manager_tx = conversations_to_manager_tx;
        services.conversations_to_manager_rx = conversations_to_manager_rx;
        services.listener_to_manager_rx = listener_to_manager_rx;
        services.ws_client_handle = client_listener_handle;
        services.redirect_order_rx = redirect_order_rx;
        let outgoing_message = UiUnmarshalError {
            message: "".to_string(),
            bad_data: "".to_string(),
        };

        let _inner = CentralEventLoop::handle_outgoing_message_body(
            services,
            Ok(OutgoingMessageType::FireAndForgetMessage(
                outgoing_message.clone().tmb(0),
                1,
            )),
        )
        .await;

        let mut recorded = server_stop_handle.stop().await;
        let faf = recorded.requests.remove(0);
        assert_eq!(
            UiUnmarshalError::fmb(faf.message_body()).unwrap().0,
            outgoing_message
        );
        let none_other = recorded.requests.is_empty();
        assert_eq!(none_other, true)
    }

    #[tokio::test]
    async fn handles_outgoing_conversation_messages_to_dead_server() {
        let daemon_port = find_free_port();
        let daemon_server = MockWebSocketsServer::new(daemon_port);
        let _daemon_stop_handle = daemon_server.start().await;
        let (conversation1_tx, conversation1_rx) = async_channel::unbounded();
        let (conversation2_tx, conversation2_rx) = async_channel::unbounded();
        let (conversation3_tx, conversation3_rx) = async_channel::unbounded();
        let conversations = vec![
            (1, conversation1_tx),
            (2, conversation2_tx),
            (3, conversation3_tx),
        ]
        .into_iter()
        .collect::<HashMap<u64, ManagerToConversationSender>>();
        let send_error = Err(Error::Io(io::Error::from(ErrorKind::NotConnected)));
        let abort_handle = tokio::spawn(async {}).abort_handle();
        let client_listener_handle = WSClientHandle::new(
            Box::new(WSSenderWrapperMock::default().send_text_owned_result(send_error)),
            abort_handle,
        );
        let mut services = make_inner().await;
        services.daemon_port = daemon_port;
        services.conversations = conversations;
        services.conversations_waiting = vec_to_set(vec![2, 3]);
        services.ws_client_handle = client_listener_handle;

        services = CentralEventLoop::handle_outgoing_message_body(
            services,
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
        assert_eq!(services.conversations_waiting.is_empty(), true);
    }

    #[tokio::test]
    async fn handles_outgoing_conversation_message_from_nonexistent_conversation() {
        let conversations = vec![
            (1, async_channel::unbounded().0),
            (2, async_channel::unbounded().0),
        ]
        .into_iter()
        .collect::<HashMap<u64, ManagerToConversationSender>>();
        let mut services = make_inner().await;
        services.conversations = conversations;
        services.conversations_waiting = vec_to_set(vec![1]);

        services = CentralEventLoop::handle_outgoing_message_body(
            services,
            Ok(OutgoingMessageType::ConversationMessage(
                UiSetupRequest { values: vec![] }.tmb(42),
            )),
        )
        .await;

        assert_eq!(services.conversations.len(), 2);
        assert_eq!(services.conversations_waiting.len(), 1);
    }

    #[tokio::test]
    async fn handles_outgoing_fire_and_forget_messages_to_dead_server() {
        let daemon_port = find_free_port();
        let daemon_server = MockWebSocketsServer::new(daemon_port);
        let _daemon_stop_handle = daemon_server.start().await;
        let (conversation1_tx, conversation1_rx) = async_channel::unbounded();
        let (conversation2_tx, conversation2_rx) = async_channel::unbounded();
        let (conversation3_tx, conversation3_rx) = async_channel::unbounded();
        let conversations = vec![
            (1, conversation1_tx),
            (2, conversation2_tx),
            (3, conversation3_tx),
        ]
        .into_iter()
        .collect::<HashMap<u64, ManagerToConversationSender>>();
        let send_error = Err(Error::Io(io::Error::from(ErrorKind::NotConnected)));
        let abort_handle = tokio::spawn(async {}).abort_handle();
        let ws_client_handle = WSClientHandle::new(
            Box::new(WSSenderWrapperMock::default().send_text_owned_result(send_error)),
            abort_handle,
        );
        let mut services = make_inner().await;
        services.daemon_port = daemon_port;
        services.conversations = conversations;
        services.conversations_waiting = vec_to_set(vec![2, 3]);
        services.ws_client_handle = ws_client_handle;
        //TODO remove me if it works on MasOs without
        // #[cfg(target_os = "macos")]
        // {
        //     // macOS doesn't fail sends until some time after the pipe is broken: weird! Sick!
        //     let _ = services.talker_half.sender.send_message(
        //         &mut services.talker_half.stream,
        //         &OwnedMessage::Text("booga".to_string()),
        //     );
        //     thread::sleep(Duration::from_millis(500));
        // }

        services = CentralEventLoop::handle_outgoing_message_body(
            services,
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
        assert_eq!(services.conversations_waiting.is_empty(), true);
    }

    #[tokio::test]
    async fn close_signaler_signalizes_properly() {
        let (tx, mut rx) = tokio::sync::broadcast::channel(10);
        let sync_flag = SyncCloseFlag::default();
        let subject = CloseSignaler::new(tx, sync_flag.clone());

        subject.signalize_close();

        rx.recv().await.unwrap();
        assert_eq!(sync_flag.masq_is_closing(), true)
    }

    #[tokio::test]
    async fn handles_close_order() {
        running_test();
        let port = find_free_port();
        let server = MockWebSocketsServer::new(port);
        let server_handle = server.start().await;
        let bootstrapper = CMBootstrapper::default();
        let subject = bootstrapper
            .establish_connection_manager(port, None)
            .await
            .unwrap();
        let conversation1 = subject.start_conversation().await;
        let conversation2 = subject.start_conversation().await;

        subject.close();

        assert_eq!(subject.closing_signaler.is_closing(), true);
        let result = conversation1
            .transact(UiShutdownRequest {}.tmb(0), 1000)
            .await;
        assert_eq!(result, Err(ClientError::ClosingStage));
        let result = conversation2
            .send(
                UiUnmarshalError {
                    message: "".to_string(),
                    bad_data: "".to_string(),
                }
                .tmb(0),
            )
            .await;
        assert_eq!(result, Err(ClientError::ClosingStage));
        let recorded = server_handle.stop().await;
        assert_eq!(recorded.requests, vec![MWSSMessage::Close]);
        match tokio::time::timeout(
            Duration::from_secs(1),
            subject.central_even_loop_join_handle,
        )
        .await
        {
            Ok(Ok(())) => (),
            x => panic!(
                "Central event loop didn't vanish quickly enough or gracefully: {:?}",
                x
            ),
        };
    }

    #[tokio::test]
    async fn handles_close_from_server() {
        running_test();
        let port = find_free_port();
        let server = MockWebSocketsServer::new(port).await_close_handshake_completion();
        let server_stop_handle = server.start().await;
        let bootstrapper = CMBootstrapper::default();
        let _subject = bootstrapper
            .establish_connection_manager(port, None)
            .await
            .unwrap();

        let recorded = server_stop_handle.stop().await;

        assert_eq!(recorded.requests, vec![MWSSMessage::Close])
    }

    #[tokio::test]
    async fn establish_client_listener_times_out() {
        let port = find_free_port();
        let (tx, _rx) = unbounded_channel();
        let (_close_tx, close_rx) = tokio::sync::broadcast::channel(10);
        let (background_task_ready_tx, background_task_ready_rx) = tokio::sync::oneshot::channel();
        let (finish_background_task_tx, finish_background_task_rx) =
            tokio::sync::oneshot::channel();
        let timeout_ms = 1;
        let _server = tokio::task::spawn(async move {
            background_task_ready_tx.send(()).unwrap();
            let listener = TcpListener::bind(SocketAddr::new(localhost(), port))
                .await
                .unwrap();
            let (stream, _) = listener.accept().await.unwrap();
            let mut server = Server::new(BufReader::new(BufWriter::new(stream.compat())));
            server.add_protocol(NODE_UI_PROTOCOL);
            let _req = server.receive_request().await;
            finish_background_task_rx.await
        });
        background_task_ready_rx.await.unwrap();

        let result = establish_client_listener(port, tx, close_rx, timeout_ms).await;

        finish_background_task_tx.send(()).unwrap();
        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("We expected an error but got ok"),
        };
        assert_eq!(err, ClientListenerError::Timeout { elapsed_ms: 1 })
    }

    #[tokio::test]
    async fn make_connection_with_timeout_connection_reset_during_handshake() {
        let port = find_free_port();
        let server = MockWebSocketsServer::new(port);
        let _server_stop_handle = server
            .set_socket_to_no_linger()
            .drop_conn_during_handshake()
            .start()
            .await;
        let (tx, _rx) = unbounded_channel();
        let (_close_tx, close_rx) = tokio::sync::broadcast::channel(10);

        let result = establish_client_listener(port, tx, close_rx, 5000).await;

        match result {
            Err(ClientListenerError::Broken(msg)) => {
                assert!(
                    msg.contains("Socketto(\"Io(")
                        && msg.contains("kind: ConnectionReset, message:"),
                    "We expected ConnectionReset error but got {}",
                    msg
                )
            }
            Err(e) => panic!("We expected WSHandshakeError::Socketto but got {:?}", e),
            Ok(_) => {
                panic!("We expected ConnectionReset error but got Ok()")
            }
        }
    }

    #[tokio::test]
    async fn make_connection_with_timeout_server_replies_without_selected_protocol() {
        let port = find_free_port();
        let server = MockWebSocketsServer::new(port);
        let _server_stop_handle = server
            .send_specific_handshake_response(MockServerHandshakeResponse::Accept {
                accepted_protocol_opt: None,
                replace_correct_websocket_key_with_opt: None,
            })
            .start()
            .await;
        let (tx, _rx) = unbounded_channel();
        let (_close_tx, close_rx) = tokio::sync::broadcast::channel(10);

        let result = establish_client_listener(port, tx, close_rx, 5000).await;

        assert_error_msg(result, "ServerResponse(\"Accept contains no protocol\")")
    }

    #[tokio::test]
    async fn make_connection_with_timeout_server_replies_without_mismatched_protocol() {
        let port = find_free_port();
        let server = MockWebSocketsServer::new(port);
        let _server_stop_handle = server
            .send_specific_handshake_response(MockServerHandshakeResponse::Accept {
                accepted_protocol_opt: Some("Blah".to_string()),
                replace_correct_websocket_key_with_opt: None,
            })
            .start()
            .await;
        let (tx, _rx) = unbounded_channel();
        let (_close_tx, close_rx) = tokio::sync::broadcast::channel(10);

        let result = establish_client_listener(port, tx, close_rx, 5000).await;

        assert_error_msg(result, "Socketto(\"UnsolicitedProtocol\")")
    }

    #[tokio::test]
    async fn make_connection_with_timeout_server_replies_by_rejection() {
        let port = find_free_port();
        let server = MockWebSocketsServer::new(port);
        let _server_stop_handle = server
            .send_specific_handshake_response(MockServerHandshakeResponse::Reject {
                status_code: 410,
            })
            .start()
            .await;
        let (tx, _rx) = unbounded_channel();
        let (_close_tx, close_rx) = tokio::sync::broadcast::channel(10);

        let result = establish_client_listener(port, tx, close_rx, 5000).await;

        assert_error_msg(result, "ServerResponse(\"Rejected with code 410\")")
    }

    #[tokio::test]
    async fn make_connection_with_timeout_server_replies_by_redirect() {
        let port = find_free_port();
        let server = MockWebSocketsServer::new(port);
        let http_redirect = "\
        HTTP/1.1 301 Moved Permanently\n\
        Server: someserver\n\
        Connection: keep-alive\n\
        Location: https://www.someserver2.com/\n\n";
        let _server_stop_handle = server
            .send_unexpected_http_when_tcp_established(http_redirect.to_string())
            .start()
            .await;
        let (tx, _rx) = unbounded_channel();
        let (_close_tx, close_rx) = tokio::sync::broadcast::channel(10);

        let result = establish_client_listener(port, tx, close_rx, 5000).await;

        assert_error_msg(
            result,
            "ServerResponse(\"Redirect with code 301 to https://www.someserver2.com/\")",
        )
    }

    fn assert_error_msg(
        result: Result<WSClientHandle, ClientListenerError>,
        expected_err_msg: &str,
    ) {
        match result {
            Err(ClientListenerError::Broken(msg)) => {
                assert_eq!(
                    msg, expected_err_msg,
                    "We expected {} but got {}",
                    expected_err_msg, msg
                )
            }
            Err(e) => panic!("We expected WSHandshakeError::Socketto but got {:?}", e),
            Ok(_) => {
                panic!("We expected ConnectionReset error but got Ok()")
            }
        }
    }

    #[tokio::test]
    #[should_panic(expected = "Conversations to manager channel died unexpectedly")]
    async fn handle_outgoing_message_body_detects_dead_channel() {
        let services = make_inner().await;

        let _ = CentralEventLoop::handle_outgoing_message_body(services, Err(RecvError)).await;
    }

    #[tokio::test]
    #[should_panic(expected = "active_ui_port(): ConnectionManager is disconnected")]
    async fn active_ui_port_in_connection_manager_senses_dead_channel() {
        let (demand_tx, _demand_rx) = unbounded_channel();
        let mut connection_manager = make_disconnected_subject();
        connection_manager.internal_communications.demand_tx = demand_tx;

        let _ = connection_manager.active_ui_port().await;
    }

    #[tokio::test]
    #[should_panic(expected = "active_ui_port(): ConnectionManager is not responding after 10 ms")]
    async fn active_ui_port_demand_times_out() {
        let (demand_tx, _demand_rx) = unbounded_channel();
        let (_active_port_response_tx, active_port_response_rx) = unbounded_channel();
        let mut connection_manager = make_disconnected_subject();
        connection_manager.internal_communications.demand_tx = demand_tx;
        connection_manager
            .internal_communications
            .response_receivers
            .borrow_mut()
            .active_port_response_rx = active_port_response_rx;
        connection_manager.timeouts.component_response_millis = 10;

        let _ = connection_manager.active_ui_port().await;
    }

    fn make_disconnected_subject() -> ConnectionManager {
        let (demand_tx, _) = tokio::sync::mpsc::unbounded_channel();
        let (_, conversation_return_rx) = tokio::sync::mpsc::unbounded_channel();
        let (_, redirect_response_rx) = tokio::sync::mpsc::unbounded_channel();
        let (_, active_port_response_rx) = tokio::sync::mpsc::unbounded_channel();
        let internal_communications = CMChannelsToSubordinates::new(
            demand_tx,
            conversation_return_rx,
            redirect_response_rx,
            active_port_response_rx,
        );
        let meaningless_spawn_handle = tokio::spawn(async {});
        let (close_signaler, _) = ClosingStageDetector::make_for_test();

        ConnectionManager::new(
            internal_communications,
            close_signaler,
            meaningless_spawn_handle,
        )
    }

    async fn make_inner() -> ConnectionServices {
        let abort_handle = tokio::spawn(async {}).abort_handle();
        let broadcast_handles = BroadcastHandles::new(
            Box::new(BroadcastHandleMock::default()),
            Box::new(BroadcastHandleMock::default()),
        );
        ConnectionServices {
            active_port_opt: Some(0),
            daemon_port: 0,
            node_port_opt: None,
            conversations: HashMap::new(),
            conversations_waiting: HashSet::new(),
            next_context_id: 0,
            demand_rx: unbounded_channel().1,
            conversation_return_tx: unbounded_channel().0,
            conversations_to_manager_tx: async_channel::unbounded().0,
            conversations_to_manager_rx: async_channel::unbounded().1,
            listener_to_manager_rx: unbounded_channel().1,
            ws_client_handle: WSClientHandle::new(
                Box::new(WSSenderWrapperMock::default()),
                abort_handle,
            ),
            broadcast_handles,
            redirect_order_rx: unbounded_channel().1,
            redirect_response_tx: unbounded_channel().0,
            active_port_response_tx: unbounded_channel().0,
            close_sig: ClosingStageDetector::make_for_test().1,
        }
    }

    fn vec_to_set<T>(vec: Vec<T>) -> HashSet<T>
    where
        T: Eq + Hash,
    {
        let set: HashSet<T> = vec.into_iter().collect();
        set
    }
}
