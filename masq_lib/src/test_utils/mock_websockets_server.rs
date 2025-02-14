// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::messages::NODE_UI_PROTOCOL;
use crate::ui_gateway::{MessageBody, MessagePath, MessageTarget};
use crate::ui_traffic_converter::UiTrafficConverter;
use crate::utils::localhost;
use crate::websockets_handshake::{WSSender, WSReceiver};
use async_trait::async_trait;
use lazy_static::lazy_static;
use std::fmt::Debug;
use std::net::SocketAddr;
use std::ops::Not;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime};
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio::task::JoinHandle;
use std::io::Write;
use soketto::Incoming as SokettoIncomingType;
use soketto::Data as SokettoDataType;
use soketto::{handshake::{Server, ClientRequest, server::Response}};
use soketto::connection::{Sender, Receiver, Error};
use tokio_util::compat::{Compat, TokioAsyncReadCompatExt};
use futures::io::{BufReader, BufWriter};
use rustc_hex::ToHex;

lazy_static! {
    static ref MWSS_INDEX: Mutex<u64> = Mutex::new(0);
}


// struct NodeUiProtocolWebSocketHandlerOld {
//     requests_arc: Arc<Mutex<Vec<MockWSServerRecordedRequest>>>,
//     responses_arc: Arc<Mutex<Vec<Message>>>,
//     opening_broadcasts_signal_rx_opt: Mutex<Option<tokio::sync::oneshot::Receiver<()>>>,
//     counters: Arc<WebSocketCounters>,
//     listener_stop_tx: Arc<Mutex<Option<async_channel::Sender<()>>>>,
//     panicking_conn_obj_opt: Option<PanickingConn>,
//     logger: MWSSLogger,
// }

// #[async_trait]
// impl WebSocketHandler for NodeUiProtocolWebSocketHandlerOld {
//     type Context = SocketAddr;
//
//     fn accept(&self, _peer: &SocketAddr) -> bool {
// eprintln!("accept() called with peer: {:?}", _peer);
// std::io::stderr().flush().unwrap();
//         self.check_connection_not_restarted()
//     }
//
//     async fn connect(
//         self: &Arc<Self>,
//         _peer: &SocketAddr,
//     ) -> workflow_websocket::server::Result<()> {
//         if let Some(object) = self.panicking_conn_obj_opt.as_ref() {
//             object.test_server_reliability()
//         }
//         Ok(())
//     }
//
//     async fn handshake(
//         self: &Arc<Self>,
//         peer: &SocketAddr,
//         sender: &mut WebSocketSender,
//         receiver: &mut WebSocketReceiver,
//         sink: &WebSocketSink,
//     ) -> workflow_websocket::server::Result<Self::Context> {
//         self.logger
//             .log(format!("Awaiting handshake msg from {}", peer).as_str());
//
//         node_server_greeting(Duration::from_millis(3_000), *peer, sender, receiver).await?;
//
//         self.logger
//             .log("Checking for exposed, initial fire-and-forget messages to push them off");
//
//         self.handle_opening_broadcasts(sink);
//
//         Ok(*peer)
//     }
//
//     async fn message(
//         self: &Arc<Self>,
//         _ctx: &Self::Context,
//         msg: Message,
//         sink: &WebSocketSink,
//     ) -> workflow_websocket::server::Result<()> {
//         self.logger.log("Checking for message from client");
//
//         let incoming = self.handle_incoming_msg(msg);
//
//         let cash_for_panic_opt = self.record_incoming_msg(
//             incoming.received_data_is_wrong_and_fatal(),
//             incoming.request_as_it_will_be_recorded,
//         );
//
//         match incoming.resolution {
//             IncomingMsgResolution::MASQProtocolMsg(message_body) => {
//                 match message_body.path {
//                     MessagePath::Conversation(_) => {
//                         self.handle_conversational_incoming_message(sink)
//                     }
//                     MessagePath::FireAndForget => {
//                         self.logger
//                             .log("Responding to FireAndForget message by forgetting");
//                     }
//                 }
//
//                 self.logger.log(
//                     "Checking for fire-and-forget messages having been blocked by a conversational one until now",
//                 );
//                 self.release_fire_and_forget_messages_introducing_the_queue(sink);
//
//                 Ok(())
//             }
//             IncomingMsgResolution::UnrecognizedMsgErr(unexpected_impulse_from_test) => {
//                 self.logger
//                     .log("Going to panic: Unrecognizable form of a text message");
//                 panic!(
//                     "Unrecognizable incoming message received; you should refrain from sending some \
//                     meaningless garbage to the test server: {:?}",
//                     cash_for_panic_opt
//                         .expect("panic expected but the cached data to be print can not be found")
//                 )
//             }
//             IncomingMsgResolution::ServerNativeInstruction(polite_instruction_to_server) => {
//                 Err(polite_instruction_to_server)
//             }
//         }
//     }
// }
//
// impl NodeUiProtocolWebSocketHandlerOld {
//     fn release_fire_and_forget_messages_introducing_the_queue(&self, sink: &WebSocketSink) {
//         let mut counter = 0usize;
//         loop {
//             if self.responses_arc.lock().unwrap().is_empty() {
//                 break;
//             }
//             let temporarily_owned_possible_f_f = self.responses_arc.lock().unwrap().remove(0);
//             if match &temporarily_owned_possible_f_f {
//                 Message::Text(text) => {
//                     match UiTrafficConverter::new_unmarshal_to_ui(text, MessageTarget::AllClients) {
//                         Ok(msg) => match msg.body.path {
//                             MessagePath::FireAndForget => {
//                                 let f_f_message = temporarily_owned_possible_f_f.clone();
//                                 sink.send(f_f_message).unwrap();
//                                 self.logger
//                                     .log("Sending a fire-and-forget message to the UI");
//                                 true
//                             }
//                             _ => false,
//                         },
//                         _ => false,
//                     }
//                 }
//                 _ => false,
//             }
//             .not()
//             {
//                 self.responses_arc
//                     .lock()
//                     .unwrap()
//                     .insert(0, temporarily_owned_possible_f_f);
//                 self.logger.log(
//                     "No fire-and-forget message found; heading over to conversational messages",
//                 );
//                 break;
//             }
//             thread::sleep(Duration::from_millis(1));
//             counter += 1;
//             //for true, we keep looping
//         }
//     }
//
//     fn record_incoming_msg(
//         &self,
//         processing_is_going_wrong: bool,
//         request_to_be_recorded: MockWSServerRecordedRequest,
//     ) -> Option<MockWSServerRecordedRequest> {
//         self.logger.log(&format!(
//             "Recording incoming message: {:?}",
//             request_to_be_recorded
//         ));
//
//         let cash_for_panic_opt = if processing_is_going_wrong {
//             Some(request_to_be_recorded.clone())
//         } else {
//             None
//         };
//
//         self.requests_arc
//             .lock()
//             .unwrap()
//             .push(request_to_be_recorded);
//
//         cash_for_panic_opt
//     }
//
//     fn handle_incoming_msg(&self, incoming: Message) -> ProcessedIncomingMsg {
//         let text_msg = match self.handle_non_textual_messages(incoming) {
//             Err(already_fully_processed) => return already_fully_processed,
//             Ok(message_body_json) => message_body_json,
//         };
//
//         self.handle_incoming_msg_raw(text_msg)
//     }
//
//     fn handle_non_textual_messages(
//         &self,
//         incoming: Message,
//     ) -> Result<String, ProcessedIncomingMsg> {
//         match &incoming {
//             Message::Text(string) => Ok(string.to_string()),
//             Message::Close(..) => Err(ProcessedIncomingMsg::new(
//                 IncomingMsgResolution::ServerNativeInstruction(WebsocketServerError::ServerClose),
//                 MockWSServerRecordedRequest::WSNonTextual(incoming.clone()),
//             )),
//             msg => {
//                 self.logger.log(&format!(
//                     "Received unexpected message {:?} - discarding",
//                     msg
//                 ));
//                 let result = UnrecognizedMessageErr::new(format!("{:?}", msg));
//                 Err(ProcessedIncomingMsg::new(
//                     IncomingMsgResolution::UnrecognizedMsgErr(result),
//                     MockWSServerRecordedRequest::WSNonTextual(incoming.clone()),
//                 ))
//             }
//         }
//     }
//
//     fn handle_incoming_msg_raw(&self, msg_text: String) -> ProcessedIncomingMsg {
//         self.logger.log(&format!("Received '{}'", msg_text));
//         match UiTrafficConverter::new_unmarshal_from_ui(&msg_text, 0) {
//             Ok(msg) => ProcessedIncomingMsg::new(
//                 IncomingMsgResolution::MASQProtocolMsg(msg.body.clone()),
//                 MockWSServerRecordedRequest::MASQNodeUIv2Protocol(msg.body.clone()),
//             ),
//             Err(e) => ProcessedIncomingMsg::new(
//                 IncomingMsgResolution::UnrecognizedMsgErr(UnrecognizedMessageErr::new(
//                     e.to_string(),
//                 )),
//                 MockWSServerRecordedRequest::WSTextual {
//                     unexpected_string: msg_text,
//                 },
//             ),
//         }
//     }
//
//     fn handle_conversational_incoming_message(&self, sink: &WebSocketSink) {
//         let mut temporary_access_to_responses = self.responses_arc.lock().unwrap();
//         if temporary_access_to_responses.len() != 0 {
//             let owned_msg = temporary_access_to_responses.remove(0);
//             self.logger
//                 .log(&format!("Responding with preset Message: {:?}", owned_msg));
//             sink.send(owned_msg).unwrap()
//         } else {
//             self.logger.log("No more messages to send back");
//             sink.send(Message::Binary(b"EMPTY QUEUE".to_vec())).unwrap()
//         }
//     }
//
//     fn handle_opening_broadcasts(self: &Arc<Self>, sink: &WebSocketSink) {
//         if let Some(receiver) = self.opening_broadcasts_signal_rx_opt.lock().unwrap().take() {
//             let detached_server_clone = self.clone();
//             let sink_clone = sink.clone();
//             let _ = tokio::spawn(async move {
//                 receiver
//                     .await
//                     .expect("Failed to release broadcasts on signal");
//                 detached_server_clone
//                     .release_fire_and_forget_messages_introducing_the_queue(&sink_clone)
//             });
//         } else {
//             self.release_fire_and_forget_messages_introducing_the_queue(sink)
//         }
//     }
//
//     fn check_connection_not_restarted(&self) -> bool {
//         // The native design of this server is loose on panics, it catches them and throws away. It
//         // could panic and restart the connection. We wouldn't notice from outside so we regard
//         // a single connection as a universal goal in a test. (If a need for repeated connections
//         // arises, we can further configure this).
//
//         // Reaching a second connection indicates that one has probably already panicked
//         let total_conn_count_before_incrementing =
//             self.counters.total_connections.load(Ordering::Relaxed);
//
//         if total_conn_count_before_incrementing > 0 {
//             let _ = self
//                 .listener_stop_tx
//                 .lock()
//                 .expect("stop signaler mutex poisoned")
//                 .as_ref()
//                 .expect("stop signaler is missing")
//                 .try_send(());
//             false
//         } else {
//             true
//         }
//     }
// }

#[derive(Debug, Clone)]
enum MWSSMessage {
    // If you have a MessageBody, put it in one of these.
    MessageBody (MessageBody),
    // If you have a non-MessageBody "response" that you want to be sent without being
    // specifically requested, put it here.
    FAFData (SokettoDataType, Vec<u8>),
    // If you have a non-MessageBody request, or a non-MessageBody response that must be
    // triggered by a request, put it here.
    ConversationData(SokettoDataType, Vec<u8>),
}

impl MWSSMessage {
    fn is_fire_and_forget(&self) -> bool {
        match self {
            MWSSMessage::MessageBody (body) => body.path == MessagePath::FireAndForget,
            MWSSMessage::FAFData(_, _) => true,
            MWSSMessage::ConversationData(_, _) => false,
        }
    }

    fn message_body(self) -> MessageBody {
        match self {
            MWSSMessage::MessageBody (body) => body,
            _ => panic!("Expected MWSSMessage::MessageBody, got {:?} instead", self),
        }
    }
}

pub struct MockWebsocketServerHandle {
    requests_arc: Arc<Mutex<Vec<MWSSMessage>>>,
    proposed_protocols_arc: Arc<Mutex<Vec<String>>>,
    responses: Vec<MWSSMessage>,
    opening_broadcast_signal_rx_opt: Option<tokio::sync::oneshot::Receiver<()>>,
    logger: MWSSLogger,
    join_handle: JoinHandle<()>,
}

pub struct MockWebSocketsServer {
    port: u16,
    accepted_protocol_opt: Option<String>,
    responses: Vec<MWSSMessage>,
    do_log: bool,
}

impl MockWebSocketsServer {
    pub fn new(port: u16) -> Self {
        Self {
            port,
            accepted_protocol_opt: Some(NODE_UI_PROTOCOL.to_string()),
            responses: vec![],
            do_log: false,
        }
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn accepted_protocol(mut self, protocol_opt: Option<&str>) -> Self {
        self.accepted_protocol_opt = protocol_opt.map(|p| p.to_string());
        self
    }

    pub fn queue_response(mut self, message: MessageBody) -> Self {
        self.responses.push(MWSSMessage::MessageBody(message));
        self
    }

    pub fn queue_faf_string(mut self, string: &str) -> Self {
        self.responses.push(MWSSMessage::FAFData(SokettoDataType::Text(string.len()), string.as_bytes().to_vec()));
        self
    }

    pub fn queue_conv_string(mut self, string: &str) -> Self {
        self.responses.push(MWSSMessage::ConversationData(SokettoDataType::Text(string.len()), string.as_bytes().to_vec()));
        self
    }

    pub fn queue_faf_owned_message(mut self, data_type: SokettoDataType, data: Vec<u8>) -> Self {
        self.responses.push(MWSSMessage::FAFData(data_type.clone(), data));
        self
    }

    pub fn queue_conv_owned_message(mut self, data_type: SokettoDataType, data: Vec<u8>) -> Self {
        self.responses.push(MWSSMessage::ConversationData(data_type.clone(), data));
        self
    }

    pub fn write_logs(mut self) -> Self {
        self.do_log = true;
        self
    }

    // I marked it async to make obvious that it must be called inside a runtime context due to its
    // reliance on spawning a background task
    pub async fn start(self) -> MockWebSocketsServerHandle {
        let logger = MWSSLogger::new(self.do_log);
        let requests_arc = Arc::new(Mutex::new(vec![]));
        let proposed_protocols_arc = Arc::new(Mutex::new(vec![]));
        let (termination_tx, mut termination_rx) = tokio::sync::oneshot::channel::<StopStrategy>();

        let socket_addr = SocketAddr::new(localhost(), self.port);
        let tcp_listener = tokio::net::TcpListener::bind(socket_addr)
            .await
            .unwrap_or_else(|e| panic!("Could not create listener for {}: {:?}", socket_addr, e));

        let proposed_protocols_inner_arc = proposed_protocols_arc.clone();
        let requests_inner_arc = requests_arc.clone();
        let mut responses = self.responses;
        let connection_future = async move {
            let (mut sender, mut receiver) = Self::make_connection(
                tcp_listener,
                proposed_protocols_inner_arc,
                self.accepted_protocol_opt.clone(),
            ).await;
            let mut data = Vec::new();
            Self::send_faf_messages(&mut sender, &mut responses).await;
            loop {
                data.clear();
                let data_type = tokio::select! {
                    data_type_res = receiver.receive_data(&mut data) => {
                        eprintln! ("Server received {:?} data: {:?}", data_type_res, data.to_hex::<String>());
                        match (data_type_res) {
                            Ok(data_type) => data_type,
                            Err(e) => panic!("Error receiving data from client: {}", e),
                        }
                    }
                    stop_strategy = &mut termination_rx => {
                        eprintln! ("Received termination signal");
                        stop_strategy.expect("Error receiving termination signal").apply(sender).await;
                        break;
                    }
                };
                Self::process_data(
                    &data_type,
                    data.as_slice(),
                    &mut sender,
                    requests_inner_arc.clone(),
                    &mut responses,
                ).await;
            }
        };

        let join_handle = tokio::spawn(connection_future);

        logger.log(&format!("Started listening on: {}", socket_addr));

        MockWebSocketsServerHandle {
            requests_arc,
            proposed_protocols_arc,
            termination_tx,
            join_handle,
        }
    }

    async fn make_connection(
        tcp_listener: TcpListener,
        proposed_protocols_arc: Arc<Mutex<Vec<String>>>,
        accepted_protocol_opt: Option<String>,
    ) -> (WSSender, WSReceiver) {
        // TODO: Eventually add the capability to abort at any important stage along in here so that
        // we can test client code against misbehaving servers.
        let (stream, peer_addr) = tcp_listener.accept().await.expect("Error accepting incoming connection to MockWebsocketsServer");
        let mut server = Server::new(BufReader::new(BufWriter::new(stream.compat())));
        if let Some(protocol) = accepted_protocol_opt.as_ref() {
            server.add_protocol(protocol.as_str());
        }
        let websocket_key = {
            let req = server.receive_request().await.expect("Error receiving request from client");
            proposed_protocols_arc.lock().unwrap().extend(req.protocols().map(|p| p.to_string()));
            req.key()
        };

        let accept = Response::Accept { key: websocket_key, protocol: accepted_protocol_opt.as_ref().map(|p| p.as_str()) };
        server.send_response(&accept).await.expect("Error sending handshake acceptance to client");

        let (sender, receiver) = server.into_builder().finish();
        (sender, receiver)
    }

    async fn process_data(
        data_type: &SokettoDataType,
        data: &[u8],
        sender: &mut WSSender,
        requests_arc: Arc<Mutex<Vec<MWSSMessage>>>,
        responses: &mut Vec<MWSSMessage>,
    ) {
        Self::parse_and_save_incoming_message(data_type, data, requests_arc);
        Self::send_next_message(sender, responses).await;
        Self::send_faf_messages(sender, responses).await;
    }

    fn parse_and_save_incoming_message(
        data_type: &SokettoDataType,
        data: &[u8],
        requests_arc: Arc<Mutex<Vec<MWSSMessage>>>
    ) {
        let message = match data_type {
            SokettoDataType::Text(_) => {
                let text = std::str::from_utf8(data).expect("Error converting data to text");
                match UiTrafficConverter::new_unmarshal_from_ui(text, 0) {
                    Ok(msg) => MWSSMessage::MessageBody(msg.body),
                    Err(_) => MWSSMessage::ConversationData(data_type.clone(), data.to_vec()),
                }
            },
            SokettoDataType::Binary(_) => MWSSMessage::ConversationData(data_type.clone(), data.to_vec()),
        };
        requests_arc.lock().unwrap().push(message);
    }

    async fn send_faf_messages(
        sender: &mut WSSender,
        responses: &mut Vec<MWSSMessage>,
    ) {
        while let Some(response) = responses.first() {
            if response.is_fire_and_forget() {
                let response = responses.remove(0);
                let (data_type, data) = match response {
                    MWSSMessage::MessageBody(body) => Self::sendable_message_body(body),
                    MWSSMessage::FAFData(data_type, data) => (data_type, data),
                    MWSSMessage::ConversationData(_, _) => panic!("ConversationData shouldn't have gotten here"),
                };
                Self::send_data(sender, data_type, data).await;
            } else {
                break;
            }
        }
    }

    async fn send_next_message(
        sender: &mut WSSender,
        responses: &mut Vec<MWSSMessage>,
    ) {
        eprintln! ("send_next_message");
        if responses.is_empty() {
            eprintln! ("No more responses; sending EMPTY_QUEUE");
            let msg = b"EMPTY_QUEUE".to_vec();
            Self::send_data(sender, SokettoDataType::Binary(msg.len()), msg).await;
            eprintln! ("Sent EMPTY_QUEUE");
            return;
        }
        let (data_type, data) = match responses.remove(0) {
            MWSSMessage::MessageBody(body) => Self::sendable_message_body(body),
            MWSSMessage::ConversationData(data_type, data) => (data_type, data),
            MWSSMessage::FAFData(data_type, data) => panic!("FAFData shouldn't have gotten here"),
        };
        Self::send_data(sender, data_type, data).await;
    }

    async fn send_data(sender: &mut WSSender, data_type: SokettoDataType, data: Vec<u8>) {
        match data_type {
            SokettoDataType::Text(len) => {
                let text = std::str::from_utf8(&data).expect("Error converting data to text");
                sender.send_text(text).await.expect("Error sending data to client");
                sender.flush().await.expect("Error flushing text to client");
            },
            SokettoDataType::Binary(len) => {
                eprintln! ("Calling send_binary ({})", len);
                sender.send_binary(&data).await.expect("Error sending data to client");
                eprintln! ("send_binary complete");
                sender.flush().await.expect("Error flushing binary data to client");
                eprintln! ("flush complete");
            },
        }
    }

    fn sendable_message_body(body: MessageBody) -> (SokettoDataType, Vec<u8>) {
        let json = UiTrafficConverter::new_marshal(body);
        (SokettoDataType::Text(json.len()), json.into_bytes())
    }
}

pub type ServerJoinHandle = JoinHandle<workflow_websocket::server::result::Result<()>>;

#[derive(Debug)]
pub struct MockWebSocketsServerResult {
    pub requests: Vec<MWSSMessage>,
    pub proposed_protocols: Vec<String>,
}

#[derive(Debug, Copy, Clone)]
pub enum StopStrategy {
    CloseWebSockets,
    FinTcp,
    Abort
}

impl StopStrategy {
    pub async fn apply (self, mut sender: WSSender) {
        match self {
            StopStrategy::CloseWebSockets => {Self::close_web_sockets(sender);},
            StopStrategy::FinTcp => {Self::fin_tcp(sender);},
            StopStrategy::Abort => {Self::abort(sender);},
        }
    }

    async fn close_web_sockets(mut sender: WSSender) {
        sender.close().await.expect("Error closing WebSocket connection");
    }

    async fn fin_tcp(mut sender: WSSender) {
        todo!("You may have to preserve the TcpStream or equivalent that goes into the Server");
        // sender.writer.lock().await.close().expect("Error closing TCP connection");
    }

    async fn abort(mut sender: WSSender) {
        drop (sender);
    }
}

pub struct MockWebSocketsServerHandle {
    requests_arc: Arc<Mutex<Vec<MWSSMessage>>>,
    proposed_protocols_arc: Arc<Mutex<Vec<String>>>,
    termination_tx: tokio::sync::oneshot::Sender<StopStrategy>,
    join_handle: JoinHandle<()>,
}

impl MockWebSocketsServerHandle {
    pub async fn stop(mut self, strategy: StopStrategy) -> MockWebSocketsServerResult {
        match self.termination_tx.send(strategy) {
            Ok(_) => {},
            Err(e) => eprintln!("Failed to send {:?} stop signal ({:?}); assuming server already stopped", strategy, e),
        }
        eprintln! ("Beginning join");
        let _ = tokio::time::timeout(Duration::from_secs(10), self.join_handle).await;
        eprintln! ("Join complete or timed out");
        MockWebSocketsServerResult {
            requests: (*(self.requests_arc.lock().unwrap())).clone(),
            proposed_protocols: (*(self.proposed_protocols_arc.lock().unwrap())).clone(),
        }
    }
}

struct PanickingConn {
    mutex_to_sense_panic: Arc<Mutex<()>>,
}

impl PanickingConn {
    fn test_server_reliability(&self) {
        // This mutex signalizes towards outside the server that the panic occurred
        let _open_mutex = self
            .mutex_to_sense_panic
            .lock()
            .expect("Signalling Mutex already poisoned");
        panic!("Testing server's internal panic on its connection")
    }
}

#[derive(Clone)]
struct MWSSLogger {
    do_log: bool,
    server_idx: u64,
}

impl MWSSLogger {
    fn new(do_log: bool) -> Self {
        let server_idx = {
            let mut guard = MWSS_INDEX.lock().unwrap();
            let index = *guard;
            *guard += 1;
            index
        };
        Self { do_log, server_idx }
    }

    fn log(&self, msg: &str) {
        if self.do_log {
            eprintln!("MockWebSocketsServer {}: {}", self.server_idx, msg);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messages::{
        CrashReason, FromMessageBody, ToMessageBody, UiChangePasswordRequest,
        UiChangePasswordResponse, UiCheckPasswordRequest, UiCheckPasswordResponse,
        UiConfigurationChangedBroadcast, UiDescriptorRequest, UiDescriptorResponse,
        UiNewPasswordBroadcast, UiNodeCrashedBroadcast, NODE_UI_PROTOCOL,
    };
    use crate::test_utils::ui_connection::UiConnection;
    use crate::test_utils::utils::make_rt;
    use crate::utils::find_free_port;

    #[tokio::test]
    async fn conversational_communication_happy_path_with_full_assertion() {
        let port = find_free_port();
        let expected_response = UiCheckPasswordResponse { matches: false };
        let stop_handle = MockWebSocketsServer::new(port)
            .queue_response(expected_response.clone().tmb(123))
            .start()
            .await;
        let mut connection = UiConnection::new(port, NODE_UI_PROTOCOL).await.unwrap();
        let request = UiCheckPasswordRequest {
            db_password_opt: None,
        };

        let actual_response: UiCheckPasswordResponse = connection
            .transact_with_context_id(request.clone(), 123)
            .await
            .unwrap();

        let mut requests = stop_handle.stop(StopStrategy::CloseWebSockets).await.requests;
        let captured_request = requests.remove(0).message_body();
        let actual_message_gotten_by_the_server =
            UiCheckPasswordRequest::fmb(captured_request).unwrap().0;
        assert_eq!(actual_message_gotten_by_the_server, request);
        assert_eq!(
            (actual_response, 123),
            UiCheckPasswordResponse::fmb(expected_response.tmb(123)).unwrap()
        );
    }

    #[tokio::test]
    async fn conversational_and_broadcast_messages_work_together() {
        // Queue:
        // Conversation 1
        // Conversation 2
        // Broadcast 1
        // Broadcast 2
        // Conversation 3
        // Broadcast 3

        // Code:
        // connection.transact(stimulus) -> Conversation 1
        // connection.transact(stimulus) -> Conversation 2
        // connection.receive() -> Broadcast 1
        // connection.receive() -> Broadcast 2
        // connection.transact(stimulus) -> Conversation 3
        // connection.receive() -> Broadcast 3

        //Content of those messages is practically irrelevant because it's not in the scope of this test.

        //You may consider some lines of this test as if they were highlighted with "TESTED BY COMPLETING THE TASK - NO ADDITIONAL ASSERTION NEEDED"

        //A) All messages "sent from UI to D/N", an exact order
        ////////////////////////////////////////////////////////////////////////////////////////////
        eprintln!("One");
        let conversation_number_one_request = UiCheckPasswordRequest {
            db_password_opt: None,
        };
        let conversation_number_two_request = UiCheckPasswordRequest {
            db_password_opt: Some("ShallNotPass".to_string()),
        };

        let conversation_number_three_request = UiDescriptorRequest {};

        //B) All messages "responding the opposite way", an exact order
        ////////////////////////////////////////////////////////////////////////////////////////////
        let conversation_number_one_response = UiCheckPasswordResponse { matches: false };
        let conversation_number_two_response = UiCheckPasswordResponse { matches: true };
        let broadcast_number_one = UiConfigurationChangedBroadcast {}.tmb(0);
        let broadcast_number_two = UiNodeCrashedBroadcast {
            process_id: 0,
            crash_reason: CrashReason::NoInformation,
        }
        .tmb(0);
        let conversation_number_three_response = UiDescriptorResponse {
            node_descriptor_opt: Some("ae15fe6".to_string()),
        }
        .tmb(3);
        let broadcast_number_three = UiNewPasswordBroadcast {}.tmb(0);
        ////////////////////////////////////////////////////////////////////////////////////////////
        let port = find_free_port();
        eprintln!("Two");
        let server = MockWebSocketsServer::new(port)
            .queue_response(conversation_number_one_response.clone().tmb(1))
            .queue_response(conversation_number_two_response.clone().tmb(2))
            .queue_response(broadcast_number_one)
            .queue_response(broadcast_number_two)
            .queue_response(conversation_number_three_response)
            .queue_response(broadcast_number_three);
        eprintln!("Three");
        let stop_handle = server.start().await;
        eprintln!("Four");
        let mut connection = UiConnection::new(port, NODE_UI_PROTOCOL).await.unwrap();
        eprintln!("Five");

        let received_message_number_one: UiCheckPasswordResponse = connection
            .transact_with_context_id(conversation_number_one_request.clone(), 1)
            .await
            .unwrap();
        eprintln!("Six");
        assert_eq!(
            received_message_number_one.matches,
            conversation_number_one_response.matches
        );

        let received_message_number_two: UiCheckPasswordResponse = connection
            .transact_with_context_id(conversation_number_two_request.clone(), 2)
            .await
            .unwrap();
        eprintln!("Seven");
        assert_eq!(
            received_message_number_two.matches,
            conversation_number_two_response.matches
        );
        let _received_message_number_three: UiConfigurationChangedBroadcast =
            connection.skip_until_received().await.unwrap();

        let _received_message_number_four: UiNodeCrashedBroadcast =
            connection.skip_until_received().await.unwrap();

        let received_message_number_five: UiDescriptorResponse = connection
            .transact_with_context_id(conversation_number_three_request.clone(), 3)
            .await
            .unwrap();
        assert_eq!(
            received_message_number_five.node_descriptor_opt,
            Some("ae15fe6".to_string())
        );

        let _received_message_number_six: UiNewPasswordBroadcast =
            connection.skip_until_received().await.unwrap();

        let requests = stop_handle.stop(StopStrategy::CloseWebSockets).await.requests;

        assert_eq!(
            requests
                .into_iter()
                .map(|x| x.message_body())
                .collect::<Vec<MessageBody>>(),
            vec![
                conversation_number_one_request.tmb(1),
                conversation_number_two_request.tmb(2),
                conversation_number_three_request.tmb(3)
            ]
        )
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[should_panic(expected = "The queue is empty; all messages are gone.")]
    async fn attempt_to_get_a_message_from_an_empty_queue_causes_a_panic() {
        let port = find_free_port();
        let server = MockWebSocketsServer::new(port);
        let server_handle = server.start().await;
        let mut conn = UiConnection::new(port, NODE_UI_PROTOCOL).await.unwrap();
        let conversation_request = UiChangePasswordRequest {
            old_password_opt: None,
            new_password: "password".to_string(),
        };

        let _ = conn
            .transact::<UiChangePasswordRequest, UiChangePasswordResponse>(conversation_request)
            .await
            .unwrap();
    }
}
