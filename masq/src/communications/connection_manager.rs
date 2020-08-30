// Copyright (c) 2019-2020, MASQ (https://masq.ai). All rights reserved.

use crate::communications::broadcast_handler::{
    BroadcastHandle, BroadcastHandler, StreamFactory, StreamFactoryReal,
};
use crate::communications::client_listener_thread::{ClientListener, ClientListenerError};
use crate::communications::node_conversation::{NodeConversation, NodeConversationTermination};
use crossbeam_channel::unbounded;
use crossbeam_channel::{Receiver, RecvError, Sender};
use masq_lib::messages::FromMessageBody;
use masq_lib::messages::{UiRedirect, NODE_UI_PROTOCOL};
use masq_lib::ui_gateway::{MessageBody, MessagePath};
use masq_lib::ui_traffic_converter::UiTrafficConverter;
use masq_lib::utils::localhost;
use std::collections::{HashMap, HashSet};
use std::net::TcpStream;
use std::thread;
use websocket::sender::Writer;
use websocket::ws::sender::Sender as WsSender;
use websocket::ClientBuilder;
use websocket::OwnedMessage;

#[derive(Debug, Clone, PartialEq)]
pub enum OutgoingMessageType {
    ConversationMessage(MessageBody),
    FireAndForgetMessage(MessageBody, u64),
    SignOff(u64),
}

#[derive(Debug, Clone, PartialEq)]
enum Demand {
    Conversation,
    ActivePort,
    Close,
}

pub struct ConnectionManager {
    demand_tx: Sender<Demand>,
    conversation_return_rx: Receiver<NodeConversation>,
    redirect_response_rx: Receiver<Result<(), ClientListenerError>>,
    active_port_response_rx: Receiver<u16>,
}

impl Default for ConnectionManager {
    fn default() -> Self {
        Self::new()
    }
}

impl ConnectionManager {
    pub fn new() -> ConnectionManager {
        ConnectionManager {
            demand_tx: unbounded().0,
            conversation_return_rx: unbounded().1,
            redirect_response_rx: unbounded().1,
            active_port_response_rx: unbounded().1,
        }
    }

    pub fn connect(
        &mut self,
        port: u16,
        broadcast_handle: Box<dyn BroadcastHandle>,
    ) -> Result<(), ClientListenerError> {
        let (demand_tx, demand_rx) = unbounded();
        let (listener_to_manager_tx, listener_to_manager_rx) = unbounded();
        let talker_half = make_client_listener(port, listener_to_manager_tx)?;
        let (conversation_return_tx, conversation_return_rx) = unbounded();
        let (redirect_order_tx, redirect_order_rx) = unbounded();
        let (redirect_response_tx, redirect_response_rx) = unbounded();
        let (active_port_response_tx, active_port_response_rx) = unbounded();
        let redirect_broadcast_handler =
            RedirectBroadcastHandler::new(broadcast_handle, redirect_order_tx);
        self.demand_tx = demand_tx;
        self.conversation_return_rx = conversation_return_rx;
        self.redirect_response_rx = redirect_response_rx;
        self.active_port_response_rx = active_port_response_rx;
        let inner = CmsInner {
            active_port: port,
            daemon_port: port,
            node_port: None,
            conversations: HashMap::new(),
            conversations_waiting: HashSet::new(),
            next_context_id: 1,
            demand_rx,
            conversation_return_tx,
            conversations_to_manager_tx: unbounded().0,
            conversations_to_manager_rx: unbounded().1,
            listener_to_manager_rx,
            talker_half,
            broadcast_handle: redirect_broadcast_handler.start(Box::new(StreamFactoryReal::new())),
            redirect_order_rx,
            redirect_response_tx,
            active_port_response_tx,
        };
        ConnectionManagerThread::start(inner);
        Ok(())
    }

    pub fn active_ui_port(&self) -> u16 {
        self.demand_tx
            .send(Demand::ActivePort)
            .expect("ConnectionManagerThread is dead");
        self.active_port_response_rx
            .recv()
            .expect("ConnectionManagerThread is dead")
    }

    pub fn start_conversation(&self) -> NodeConversation {
        self.demand_tx
            .send(Demand::Conversation)
            .expect("ConnectionManager is not connected");
        self.conversation_return_rx
            .recv()
            .expect("ConnectionManager is not connected")
    }

    pub fn close(&self) {
        self.demand_tx
            .send(Demand::Close)
            .expect("ConnectionManagerThread is dead");
    }
}

fn make_client_listener(
    port: u16,
    listener_to_manager_tx: Sender<Result<MessageBody, ClientListenerError>>,
) -> Result<Writer<TcpStream>, ClientListenerError> {
    let builder =
        ClientBuilder::new(format!("ws://{}:{}", localhost(), port).as_str()).expect("Bad URL");
    let result = builder.add_protocol(NODE_UI_PROTOCOL).connect_insecure();
    let client = match result {
        Ok(c) => c,
        Err(_) => return Err(ClientListenerError::Broken),
    };
    let (listener_half, talker_half) = client.split().unwrap();
    let client_listener = ClientListener::new();
    client_listener.start(listener_half, listener_to_manager_tx);
    Ok(talker_half)
}

struct CmsInner {
    active_port: u16,
    daemon_port: u16,
    node_port: Option<u16>,
    conversations: HashMap<u64, Sender<Result<MessageBody, NodeConversationTermination>>>,
    conversations_waiting: HashSet<u64>,
    next_context_id: u64,
    demand_rx: Receiver<Demand>,
    conversation_return_tx: Sender<NodeConversation>,
    conversations_to_manager_tx: Sender<OutgoingMessageType>,
    conversations_to_manager_rx: Receiver<OutgoingMessageType>,
    listener_to_manager_rx: Receiver<Result<MessageBody, ClientListenerError>>,
    talker_half: Writer<TcpStream>,
    broadcast_handle: Box<dyn BroadcastHandle>,
    redirect_order_rx: Receiver<(u16, u64)>,
    redirect_response_tx: Sender<Result<(), ClientListenerError>>,
    active_port_response_tx: Sender<u16>,
}

pub struct ConnectionManagerThread {}

impl ConnectionManagerThread {
    fn start(mut inner: CmsInner) {
        let (conversations_to_manager_tx, conversations_to_manager_rx) = unbounded();
        inner.conversations_to_manager_tx = conversations_to_manager_tx;
        inner.conversations_to_manager_rx = conversations_to_manager_rx;
        Self::spawn_thread(inner);
    }

    fn spawn_thread(mut inner: CmsInner) {
        thread::spawn(move || loop {
            inner = Self::thread_loop_guts(inner)
        });
    }

    fn thread_loop_guts(inner: CmsInner) -> CmsInner {
        select! {
            recv(inner.demand_rx) -> demand_result => Self::handle_demand (inner, demand_result),
            recv(inner.listener_to_manager_rx) -> message_body_result_result => Self::handle_incoming_message_body (inner, message_body_result_result),
            recv(inner.conversations_to_manager_rx) -> message_body_result_result => Self::handle_outgoing_message_body (inner, message_body_result_result),
            recv(inner.redirect_order_rx) -> redirect_order_result => Self::handle_redirect_order (inner, redirect_order_result),
        }
    }

    fn handle_demand(inner: CmsInner, demand_result: Result<Demand, RecvError>) -> CmsInner {
        match demand_result {
            Ok(Demand::Conversation) => Self::handle_conversation_trigger(inner),
            Ok(Demand::ActivePort) => Self::handle_active_port_request(inner),
            Ok(Demand::Close) => Self::handle_close(inner),
            Err(_) => inner, // do nothing if there's a RecvError
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

    fn handle_incoming_message_body(
        mut inner: CmsInner,
        msg_result_result: Result<Result<MessageBody, ClientListenerError>, RecvError>,
    ) -> CmsInner {
        match msg_result_result {
            Ok(msg_result) => match msg_result {
                Ok(message_body) => match message_body.path {
                    MessagePath::Conversation(context_id) => {
                        if let Some(sender) = inner.conversations.get(&context_id) {
                            match sender.send(Ok(message_body)) {
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
                        return Self::fallback(inner);
                    } else {
                        // Non-fatal connection error: connection to server is still up, but we have
                        // no idea which conversation the message was meant for
                        // Should we print something to stderr here? We don't have a stderr handy...
                    }
                }
            },
            Err(_) => return Self::fallback(inner),
        };
        inner
    }

    fn handle_outgoing_message_body(
        mut inner: CmsInner,
        msg_result_result: Result<OutgoingMessageType, RecvError>,
    ) -> CmsInner {
        match msg_result_result.expect ("Received message from beyond the grave") {
            OutgoingMessageType::ConversationMessage (message_body) => match message_body.path {
                MessagePath::Conversation(context_id) => {
                    let conversation_result = inner.conversations.get(&context_id);
                    if conversation_result.is_some() {
                        let send_message_result = inner.talker_half.sender.send_message(&mut inner.talker_half.stream, &OwnedMessage::Text(UiTrafficConverter::new_marshal(message_body)));
                        match send_message_result {
                            Ok(_) => {
                                inner.conversations_waiting.insert(context_id);
                            },
                            Err(_) => {
                                inner = Self::fallback(inner);
                            },
                        }
                    };
                },
                MessagePath::FireAndForget => panic!("NodeConversation should have prevented sending a FireAndForget message with transact()"),
            },
            OutgoingMessageType::FireAndForgetMessage(message_body, context_id) => match message_body.path {
                MessagePath::FireAndForget => if let Some (conversation_tx) = inner.conversations.get (&context_id) {
                    match inner.talker_half.sender.send_message(&mut inner.talker_half.stream, &OwnedMessage::Text(UiTrafficConverter::new_marshal(message_body))) {
                        Ok (_) => {let _ = conversation_tx.send(Err(NodeConversationTermination::FiredAndForgotten));},
                        Err (_) => inner = Self::fallback(inner),
                    }
                }
                MessagePath::Conversation(_) => panic!("NodeConversation should have prevented sending a Conversation message with send()"),
            },
            OutgoingMessageType::SignOff(context_id) => {
                let _ = inner.conversations.remove (&context_id);
                let _ = inner.conversations_waiting.remove (&context_id);
            },
        };
        inner
    }

    fn handle_redirect_order(
        mut inner: CmsInner,
        redirect_order: Result<(u16, u64), RecvError>,
    ) -> CmsInner {
        let (node_port, redirecting_context_id) =
            redirect_order.expect("Received message from beyond the grave");
        let (listener_to_manager_tx, listener_to_manager_rx) = unbounded();
        let talker_half = match make_client_listener(node_port, listener_to_manager_tx) {
            Ok(th) => th,
            Err(_) => {
                let _ = inner
                    .redirect_response_tx
                    .send(Err(ClientListenerError::Broken));
                return inner;
            }
        };
        inner.node_port = Some(node_port);
        inner.active_port = node_port;
        inner.listener_to_manager_rx = listener_to_manager_rx;
        inner.talker_half = talker_half;
        inner.conversations_waiting.iter().for_each(|context_id| {
            let error = if *context_id == redirecting_context_id {
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

    fn handle_close(mut inner: CmsInner) -> CmsInner {
        inner = Self::disappoint_all_conversations(inner, NodeConversationTermination::Graceful);
        let _ = inner
            .talker_half
            .sender
            .send_message(&mut inner.talker_half.stream, &OwnedMessage::Close(None));
        let _ = inner.talker_half.shutdown_all();
        inner
    }

    fn fallback(mut inner: CmsInner) -> CmsInner {
        inner.node_port = None;
        inner.active_port = inner.daemon_port;
        let (listener_to_manager_tx, listener_to_manager_rx) = unbounded();
        inner.listener_to_manager_rx = listener_to_manager_rx;
        let talker_half = match make_client_listener(inner.active_port, listener_to_manager_tx) {
            Ok(th) => th,
            Err(e) => panic!("Lost connection, couldn't fall back to Daemon: {:?}", e),
        };
        inner.talker_half = talker_half;
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
}

struct BroadcastHandleRedirect {
    next_handle: Box<dyn BroadcastHandle>,
    redirect_order_tx: Sender<(u16, u64)>,
}

impl BroadcastHandle for BroadcastHandleRedirect {
    fn send(&self, message_body: MessageBody) {
        match UiRedirect::fmb(message_body.clone()) {
            Ok((redirect, _)) => {
                let context_id = redirect.context_id.unwrap_or(0);
                self.redirect_order_tx
                    .send((redirect.port, context_id))
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
    redirect_order_tx: Sender<(u16, u64)>,
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
        redirect_order_tx: Sender<(u16, u64)>,
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
    use crate::communications::broadcast_handler::{BroadcastHandler, StreamFactoryReal};
    use crate::communications::node_conversation::ClientError;
    use crate::test_utils::client_utils::make_client;
    use crate::test_utils::mock_websockets_server::{
        MockWebSocketsServer, MockWebSocketsServerStopHandle,
    };
    use crossbeam_channel::TryRecvError;
    use masq_lib::messages::{FromMessageBody, ToMessageBody};
    use masq_lib::messages::{
        UiFinancialsRequest, UiFinancialsResponse, UiRedirect, UiSetupBroadcast, UiSetupRequest,
        UiSetupResponse, UiShutdownRequest, UiShutdownResponse, UiStartOrder, UiStartResponse,
        UiUnmarshalError,
    };
    use masq_lib::utils::find_free_port;
    use std::hash::Hash;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::Duration;

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

    fn make_subject(
        server: MockWebSocketsServer,
    ) -> (ConnectionManager, MockWebSocketsServerStopHandle) {
        let port = server.port();
        let stop_handle = server.start();
        let mut subject = ConnectionManager::new();
        subject
            .connect(port, Box::new(BroadcastHandleMock::new()))
            .unwrap();
        (subject, stop_handle)
    }

    #[test]
    fn handles_interleaved_conversations() {
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
        let (subject, stop_handle) = make_subject(server);
        let conversation1 = subject.start_conversation();
        let conversation2 = subject.start_conversation();

        let conversation1_handle = thread::spawn(move || {
            let response1 = conversation1.transact(UiShutdownRequest {}.tmb(0)).unwrap();
            let response2 = conversation1.transact(UiStartOrder {}.tmb(0)).unwrap();
            (response1, response2)
        });
        let conversation2_handle = thread::spawn(move || {
            let response1 = conversation2.transact(UiShutdownRequest {}.tmb(0)).unwrap();
            let response2 = conversation2.transact(UiStartOrder {}.tmb(0)).unwrap();
            (response1, response2)
        });

        let (conversation1_response1, conversation1_response2) =
            conversation1_handle.join().unwrap();
        let (conversation2_response1, conversation2_response2) =
            conversation2_handle.join().unwrap();
        assert_eq!(conversation1_response1, UiShutdownRequest {}.tmb(1));
        assert_eq!(
            conversation1_response2,
            UiStartResponse {
                new_process_id: 11,
                redirect_ui_port: 12
            }
            .tmb(1)
        );
        assert_eq!(conversation2_response1, UiShutdownRequest {}.tmb(2));
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
        let (subject, stop_handle) = make_subject(server);
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

        thread::sleep(Duration::from_millis(200));
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
        let server = MockWebSocketsServer::new(port)
            .queue_string("irrelevant")
            .queue_string("irrelevant");
        let stop_handle = server.start();
        let (_, talker_half) = make_client(port).split().unwrap();
        let (demand_tx, demand_rx) = unbounded();
        let (listener_to_manager_tx, listener_to_manager_rx) = unbounded();
        let (conversations_to_manager_tx, conversations_to_manager_rx) = unbounded();
        let (conversation_return_tx, conversation_return_rx) = unbounded();
        let (_redirect_order_tx, redirect_order_rx) = unbounded();
        let mut inner = make_inner();
        inner.next_context_id = 1;
        inner.conversation_return_tx = conversation_return_tx;
        inner.listener_to_manager_rx = listener_to_manager_rx;
        inner.conversations_to_manager_tx = conversations_to_manager_tx;
        inner.conversations_to_manager_rx = conversations_to_manager_rx;
        inner.talker_half = talker_half;
        inner.redirect_order_rx = redirect_order_rx;
        inner.demand_rx = demand_rx;
        demand_tx.send(Demand::Conversation).unwrap();
        inner = ConnectionManagerThread::thread_loop_guts(inner);
        let conversation1 = conversation_return_rx.try_recv().unwrap();
        let (conversation1_tx, conversation1_rx) = conversation1.tx_rx();
        demand_tx.send(Demand::Conversation).unwrap();
        inner = ConnectionManagerThread::thread_loop_guts(inner);
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
        inner = ConnectionManagerThread::thread_loop_guts(inner); // send request 1

        // Conversations 1 and 2, 1 waiting
        assert_eq!(get_existing_keys(&inner), vec_to_set(vec![1, 2]));
        assert_eq!(inner.conversations_waiting, vec_to_set(vec![1]));

        // Send request from Conversation 2 and process it
        conversation2_tx
            .send(OutgoingMessageType::ConversationMessage(
                UiShutdownRequest {}.tmb(2),
            ))
            .unwrap();
        inner = ConnectionManagerThread::thread_loop_guts(inner);

        // Conversations 1 and 2, 1 and 2 waiting
        assert_eq!(get_existing_keys(&inner), vec_to_set(vec![1, 2]));
        assert_eq!(inner.conversations_waiting, vec_to_set(vec![1, 2]));

        // Receive response for Conversation 2, process it, pull it out
        let response2 = UiShutdownResponse {}.tmb(2);
        assert_eq!(response2.path, MessagePath::Conversation(2));
        listener_to_manager_tx.send(Ok(response2)).unwrap();
        inner = ConnectionManagerThread::thread_loop_guts(inner);
        let result2 = conversation2_rx.try_recv().unwrap().unwrap();

        // Conversations 1 and 2, 1 still waiting
        assert_eq!(result2, UiShutdownResponse {}.tmb(2));
        assert_eq!(get_existing_keys(&inner), vec_to_set(vec![1, 2]));
        assert_eq!(inner.conversations_waiting, vec_to_set(vec![1]));

        // Receive response for Conversation 1, process it, pull it out
        let response1 = UiShutdownResponse {}.tmb(1);
        assert_eq!(response1.path, MessagePath::Conversation(1));
        listener_to_manager_tx.send(Ok(response1)).unwrap();
        inner = ConnectionManagerThread::thread_loop_guts(inner);
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
        inner = ConnectionManagerThread::thread_loop_guts(inner);

        // Only Conversation 2, nobody waiting
        assert_eq!(get_existing_keys(&inner), vec_to_set(vec![2]));
        assert_eq!(inner.conversations_waiting, vec_to_set(vec![]));

        // Conversation 2 signals exit; process it
        conversation2_tx
            .send(OutgoingMessageType::SignOff(2))
            .unwrap();
        inner = ConnectionManagerThread::thread_loop_guts(inner);

        // No more conversations, nobody waiting
        assert_eq!(get_existing_keys(&inner), vec_to_set(vec![]));
        assert_eq!(inner.conversations_waiting, vec_to_set(vec![]));

        let _ = stop_handle.stop();
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
        let daemon = MockWebSocketsServer::new(daemon_port)
            .queue_response(expected_incoming_message.clone());
        let stop_handle = daemon.start();
        let node_port = find_free_port();
        let (conversation_tx, conversation_rx) = unbounded();
        let (decoy_tx, decoy_rx) = unbounded();
        let mut inner = make_inner();
        inner.active_port = node_port;
        inner.daemon_port = daemon_port;
        inner.node_port = Some(node_port);
        inner.conversations.insert(4, conversation_tx);
        inner.conversations.insert(5, decoy_tx);
        inner.conversations_waiting.insert(4);

        let inner = ConnectionManagerThread::handle_incoming_message_body(inner, Err(RecvError));

        let disconnect_notification = conversation_rx.try_recv().unwrap();
        assert_eq!(
            disconnect_notification,
            Err(NodeConversationTermination::Fatal)
        );
        assert_eq!(decoy_rx.try_recv().is_err(), true); // no disconnect notification sent to conversation not waiting
        assert_eq!(inner.active_port, daemon_port);
        assert_eq!(inner.daemon_port, daemon_port);
        assert_eq!(inner.node_port, None);
        assert_eq!(inner.conversations_waiting.is_empty(), true);
        let _ = ConnectionManagerThread::handle_outgoing_message_body(
            inner,
            Ok(OutgoingMessageType::ConversationMessage(
                UiSetupRequest { values: vec![] }.tmb(4),
            )),
        );
        let mut outgoing_messages = stop_handle.stop();
        assert_eq!(
            outgoing_messages.remove(0),
            Ok(UiSetupRequest { values: vec![] }.tmb(4))
        );
    }

    #[test]
    fn handle_redirect_order_handles_rejection_from_node() {
        let node_port = find_free_port(); // won't put anything on this port
        let (redirect_response_tx, redirect_response_rx) = unbounded();
        let mut inner = make_inner();
        inner.redirect_response_tx = redirect_response_tx;

        ConnectionManagerThread::handle_redirect_order(inner, Ok((node_port, 0)));

        let response = redirect_response_rx.try_recv().unwrap();
        assert_eq!(response, Err(ClientListenerError::Broken));
    }

    #[test]
    fn handle_redirect_order_disappoints_waiting_conversations_with_resend_or_graceful() {
        let node_port = find_free_port();
        let server = MockWebSocketsServer::new(node_port);
        let server_stop_handle = server.start();
        let (redirect_response_tx, redirect_response_rx) = unbounded();
        let (conversation1_tx, conversation1_rx) = unbounded();
        let (conversation2_tx, conversation2_rx) = unbounded();
        let conversations = vec![(1, conversation1_tx), (2, conversation2_tx)]
            .into_iter()
            .collect();
        let conversations_waiting = vec_to_set(vec![1, 2]);
        let mut inner = make_inner();
        inner.redirect_response_tx = redirect_response_tx;
        inner.conversations = conversations;
        inner.conversations_waiting = conversations_waiting;

        inner = ConnectionManagerThread::handle_redirect_order(inner, Ok((node_port, 1)));

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
    #[should_panic(expected = "Lost connection, couldn't fall back to Daemon")]
    fn handles_listener_fallback_from_daemon() {
        let daemon_port = find_free_port();
        let (conversation_tx, _) = unbounded();
        let (decoy_tx, _) = unbounded();
        let mut inner = make_inner();
        inner.active_port = daemon_port;
        inner.daemon_port = daemon_port;
        inner.node_port = None;
        inner.conversations.insert(4, conversation_tx);
        inner.conversations.insert(5, decoy_tx);
        inner.conversations_waiting.insert(4);

        let _ = ConnectionManagerThread::handle_incoming_message_body(inner, Err(RecvError));
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
        let stop_handle = daemon.start();
        let node_port = find_free_port();
        let (conversation_tx, conversation_rx) = unbounded();
        let (decoy_tx, decoy_rx) = unbounded();
        let mut inner = make_inner();
        inner.active_port = node_port;
        inner.daemon_port = daemon_port;
        inner.node_port = Some(node_port);
        inner.conversations.insert(4, conversation_tx);
        inner.conversations.insert(5, decoy_tx);
        inner.conversations_waiting.insert(4);

        let inner = ConnectionManagerThread::handle_incoming_message_body(
            inner,
            Ok(Err(ClientListenerError::Broken)),
        );

        let disconnect_notification = conversation_rx.try_recv().unwrap();
        assert_eq!(
            disconnect_notification,
            Err(NodeConversationTermination::Fatal)
        );
        assert_eq!(decoy_rx.try_recv().is_err(), true); // no disconnect notification sent to conversation not waiting
        assert_eq!(inner.active_port, daemon_port);
        assert_eq!(inner.daemon_port, daemon_port);
        assert_eq!(inner.node_port, None);
        assert_eq!(inner.conversations_waiting.is_empty(), true);
        let _ = ConnectionManagerThread::handle_outgoing_message_body(
            inner,
            Ok(OutgoingMessageType::ConversationMessage(
                UiSetupRequest { values: vec![] }.tmb(4),
            )),
        );
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
        let mut inner = make_inner();
        inner.active_port = node_port;
        inner.daemon_port = daemon_port;
        inner.node_port = Some(node_port);
        inner.conversations.insert(4, conversation_tx);
        inner.conversations_waiting.insert(4);

        let inner = ConnectionManagerThread::handle_incoming_message_body(
            inner,
            Ok(Err(ClientListenerError::UnexpectedPacket)),
        );

        assert_eq!(conversation_rx.try_recv().is_err(), true); // no disconnect notification sent
        assert_eq!(inner.active_port, node_port);
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
        let (conversation_tx, conversation_rx) = unbounded();
        let send_params_arc = Arc::new(Mutex::new(vec![]));
        let broadcast_handler = BroadcastHandleMock::new().send_params(&send_params_arc);
        let mut inner = make_inner();
        inner.conversations.insert(4, conversation_tx);
        inner.conversations_waiting.insert(4);
        inner.broadcast_handle =
            RedirectBroadcastHandler::new(Box::new(broadcast_handler), unbounded().0)
                .start(Box::new(StreamFactoryReal::new()));

        let inner = ConnectionManagerThread::handle_incoming_message_body(
            inner,
            Ok(Ok(incoming_message.clone())),
        );

        assert_eq!(conversation_rx.try_recv().is_err(), true); // no message to any conversation
        assert_eq!(inner.conversations_waiting.is_empty(), false);
        let send_params = send_params_arc.lock().unwrap();
        assert_eq!(*send_params, vec![incoming_message]);
    }

    #[test]
    fn can_follow_redirect() {
        let node_port = find_free_port();
        let node_server = MockWebSocketsServer::new(node_port).queue_response(
            UiFinancialsResponse {
                payables: vec![],
                total_payable: 21,
                receivables: vec![],
                total_receivable: 32,
            }
            .tmb(1),
        );
        let node_stop_handle = node_server.start();
        let daemon_port = find_free_port();
        let daemon_server = MockWebSocketsServer::new (daemon_port)
            .queue_response (UiRedirect {
                port: node_port,
                opcode: "financials".to_string(),
                context_id: Some(1),
                payload: r#"{"payableMinimumAmount":12,"payableMaximumAge":23,"receivableMinimumAmount":34,"receivableMaximumAge":45}"#.to_string()
            }.tmb(0));
        let daemon_stop_handle = daemon_server.start();
        let request = UiFinancialsRequest {
            payable_minimum_amount: 12,
            payable_maximum_age: 23,
            receivable_minimum_amount: 34,
            receivable_maximum_age: 45,
        }
        .tmb(1);
        let send_params_arc = Arc::new(Mutex::new(vec![]));
        let broadcast_handler = BroadcastHandleMock::new().send_params(&send_params_arc);
        let mut subject = ConnectionManager::new();
        subject
            .connect(daemon_port, Box::new(broadcast_handler))
            .unwrap();
        let conversation = subject.start_conversation();

        let result = conversation.transact(request).unwrap();

        let request_body = node_stop_handle.stop()[0].clone().unwrap();
        daemon_stop_handle.stop();
        assert_eq!(
            UiFinancialsRequest::fmb(request_body).unwrap().0,
            UiFinancialsRequest {
                payable_minimum_amount: 12,
                payable_maximum_age: 23,
                receivable_minimum_amount: 34,
                receivable_maximum_age: 45,
            }
        );
        let (response, context_id) = UiFinancialsResponse::fmb(result).unwrap();
        assert_eq!(
            response,
            UiFinancialsResponse {
                payables: vec![],
                total_payable: 21,
                receivables: vec![],
                total_receivable: 32
            }
        );
        assert_eq!(context_id, 1);
        let send_params = send_params_arc.lock().unwrap();
        assert_eq!(*send_params, vec![]);
    }

    #[test]
    fn handles_response_to_nonexistent_conversation() {
        let incoming_message = UiSetupResponse {
            running: false,
            values: vec![],
            errors: vec![],
        }
        .tmb(3);
        let (conversation_tx, conversation_rx) = unbounded();
        let mut inner = make_inner();
        inner.conversations.insert(4, conversation_tx);
        inner.conversations_waiting.insert(4);

        let inner = ConnectionManagerThread::handle_incoming_message_body(
            inner,
            Ok(Ok(incoming_message.clone())),
        );

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
        let (conversation_tx, _) = unbounded();
        let mut inner = make_inner();
        inner.conversations.insert(4, conversation_tx);
        inner.conversations_waiting.insert(4);

        let inner = ConnectionManagerThread::handle_incoming_message_body(
            inner,
            Ok(Ok(incoming_message.clone())),
        );

        assert_eq!(inner.conversations.is_empty(), true);
        assert_eq!(inner.conversations_waiting.is_empty(), true);
    }

    #[test]
    fn handles_failed_conversation_requester() {
        let mut inner = make_inner();
        let (conversation_return_tx, _) = unbounded();
        inner.next_context_id = 42;
        inner.conversation_return_tx = conversation_return_tx;

        let inner = ConnectionManagerThread::handle_conversation_trigger(inner);

        assert_eq!(inner.next_context_id, 43);
        assert_eq!(inner.conversations.is_empty(), true);
    }

    #[test]
    fn handles_fire_and_forget_outgoing_message() {
        let port = find_free_port();
        let server = MockWebSocketsServer::new(port);
        let stop_handle = server.start();
        let (_, talker_half) = make_client(port).split().unwrap();
        let (demand_tx, demand_rx) = unbounded();
        let (conversations_to_manager_tx, conversations_to_manager_rx) = unbounded();
        let (conversation_return_tx, conversation_return_rx) = unbounded();
        let (_listener_to_manager_tx, listener_to_manager_rx) = unbounded();
        let (_redirect_order_tx, redirect_order_rx) = unbounded();
        let mut inner = make_inner();
        inner.next_context_id = 1;
        inner.conversation_return_tx = conversation_return_tx;
        inner.conversations_to_manager_tx = conversations_to_manager_tx;
        inner.conversations_to_manager_rx = conversations_to_manager_rx;
        inner.listener_to_manager_rx = listener_to_manager_rx;
        inner.talker_half = talker_half;
        inner.demand_rx = demand_rx;
        inner.redirect_order_rx = redirect_order_rx;
        demand_tx.send(Demand::Conversation).unwrap();
        inner = ConnectionManagerThread::thread_loop_guts(inner);
        let conversation = conversation_return_rx.try_recv().unwrap();
        let outgoing_message = UiUnmarshalError {
            message: "".to_string(),
            bad_data: "".to_string(),
        }
        .tmb(0);

        let inner = ConnectionManagerThread::handle_outgoing_message_body(
            inner,
            Ok(OutgoingMessageType::FireAndForgetMessage(
                outgoing_message.clone(),
                conversation.context_id(),
            )),
        );

        assert_eq!(inner.conversations.len(), 1);
        assert_eq!(inner.conversations_waiting.is_empty(), true);
        let mut outgoing_messages = stop_handle.stop();
        assert_eq!(
            UiUnmarshalError::fmb(outgoing_messages.remove(0).unwrap()),
            UiUnmarshalError::fmb(outgoing_message)
        );
    }

    #[test]
    fn handles_outgoing_conversation_messages_to_dead_server() {
        let daemon_port = find_free_port();
        let daemon_server = MockWebSocketsServer::new(daemon_port)
            .queue_string("disconnect")
            .write_logs();
        let daemon_stop_handle = daemon_server.start();
        let (conversation1_tx, conversation1_rx) = unbounded();
        let (conversation2_tx, conversation2_rx) = unbounded();
        let (conversation3_tx, conversation3_rx) = unbounded();
        let conversations = vec![
            (1, conversation1_tx),
            (2, conversation2_tx),
            (3, conversation3_tx),
        ]
        .into_iter()
        .collect::<HashMap<u64, Sender<Result<MessageBody, NodeConversationTermination>>>>();
        let mut inner = make_inner();
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

        inner = ConnectionManagerThread::handle_outgoing_message_body(
            inner,
            Ok(OutgoingMessageType::ConversationMessage(
                UiSetupRequest { values: vec![] }.tmb(2),
            )),
        );

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
    fn handles_outgoing_conversation_message_from_nonexistent_conversation() {
        let conversations = vec![(1, unbounded().0), (2, unbounded().0)]
            .into_iter()
            .collect::<HashMap<u64, Sender<Result<MessageBody, NodeConversationTermination>>>>();
        let mut inner = make_inner();
        inner.conversations = conversations;
        inner.conversations_waiting = vec_to_set(vec![1]);

        inner = ConnectionManagerThread::handle_outgoing_message_body(
            inner,
            Ok(OutgoingMessageType::ConversationMessage(
                UiSetupRequest { values: vec![] }.tmb(42),
            )),
        );

        assert_eq!(inner.conversations.len(), 2);
        assert_eq!(inner.conversations_waiting.len(), 1);
    }

    #[test]
    fn handles_outgoing_fire_and_forget_messages_to_dead_server() {
        let daemon_port = find_free_port();
        let daemon_server = MockWebSocketsServer::new(daemon_port);
        let daemon_stop_handle = daemon_server.start();
        let (conversation1_tx, conversation1_rx) = unbounded();
        let (conversation2_tx, conversation2_rx) = unbounded();
        let (conversation3_tx, conversation3_rx) = unbounded();
        let conversations = vec![
            (1, conversation1_tx),
            (2, conversation2_tx),
            (3, conversation3_tx),
        ]
        .into_iter()
        .collect::<HashMap<u64, Sender<Result<MessageBody, NodeConversationTermination>>>>();
        let mut inner = make_inner();
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

        inner = ConnectionManagerThread::handle_outgoing_message_body(
            inner,
            Ok(OutgoingMessageType::FireAndForgetMessage(
                UiUnmarshalError {
                    message: String::new(),
                    bad_data: String::new(),
                }
                .tmb(0),
                2,
            )),
        );

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
    fn handles_outgoing_fire_and_forget_message_from_nonexistent_conversation() {
        let conversations = vec![(1, unbounded().0), (2, unbounded().0)]
            .into_iter()
            .collect::<HashMap<u64, Sender<Result<MessageBody, NodeConversationTermination>>>>();
        let mut inner = make_inner();
        inner.conversations = conversations;
        inner.conversations_waiting = vec_to_set(vec![1]);

        inner = ConnectionManagerThread::handle_outgoing_message_body(
            inner,
            Ok(OutgoingMessageType::FireAndForgetMessage(
                UiUnmarshalError {
                    message: String::new(),
                    bad_data: String::new(),
                }
                .tmb(0),
                42,
            )),
        );

        assert_eq!(inner.conversations.len(), 2);
        assert_eq!(inner.conversations_waiting.len(), 1);
    }

    #[test]
    fn handles_close_order() {
        let port = find_free_port();
        let server = MockWebSocketsServer::new(port).queue_owned_message(OwnedMessage::Close(None));
        let stop_handle = server.start();
        let mut subject = ConnectionManager::new();
        subject
            .connect(port, Box::new(BroadcastHandleMock::new()))
            .unwrap();
        let conversation1 = subject.start_conversation();
        let conversation2 = subject.start_conversation();

        subject.close();

        let _ = stop_handle.stop();
        let result = conversation1.transact(UiShutdownRequest {}.tmb(0));
        assert_eq!(result, Err(ClientError::ConnectionDropped));
        let result = conversation2.send(
            UiUnmarshalError {
                message: "".to_string(),
                bad_data: "".to_string(),
            }
            .tmb(0),
        );
        assert_eq!(result, Err(ClientError::ConnectionDropped));
    }

    fn make_inner() -> CmsInner {
        CmsInner {
            active_port: 0,
            daemon_port: 0,
            node_port: None,
            conversations: HashMap::new(),
            conversations_waiting: HashSet::new(),
            next_context_id: 0,
            demand_rx: unbounded().1,
            conversation_return_tx: unbounded().0,
            conversations_to_manager_tx: unbounded().0,
            conversations_to_manager_rx: unbounded().1,
            listener_to_manager_rx: unbounded().1,
            talker_half: make_broken_talker_half(),
            broadcast_handle: Box::new(BroadcastHandleMock::new()),
            redirect_order_rx: unbounded().1,
            redirect_response_tx: unbounded().0,
            active_port_response_tx: unbounded().0,
        }
    }

    pub fn make_broken_talker_half() -> Writer<TcpStream> {
        let port = find_free_port();
        let server = MockWebSocketsServer::new(port);
        let stop_handle = server.start();
        let client = make_client(port);
        let (_, talker_half) = client.split().unwrap();
        let _ = stop_handle.kill();
        let _ = talker_half.shutdown_all();
        let _ = talker_half.shutdown_all();
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
