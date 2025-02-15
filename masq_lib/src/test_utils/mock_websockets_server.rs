// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::messages::NODE_UI_PROTOCOL;
use crate::ui_gateway::{MessageBody, MessagePath, MessageTarget};
use crate::ui_traffic_converter::UiTrafficConverter;
use crate::utils::localhost;
use crate::websockets_types::{WSSender, WSReceiver};
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
use soketto::connection::{Sender, Receiver, Error, CloseReason};
use tokio_util::compat::{Compat, TokioAsyncReadCompatExt};
use futures::io::{BufReader, BufWriter};
use rustc_hex::ToHex;
use soketto::base::OpCode;
use soketto::data::ByteSlice125;

lazy_static! {
    static ref MWSS_INDEX: Mutex<u64> = Mutex::new(0);
}

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
    // If you have a close message, put it here.
    Close(),
}

impl MWSSMessage {
    pub fn is_fire_and_forget(&self) -> bool {
        match self {
            MWSSMessage::MessageBody (body) => body.path == MessagePath::FireAndForget,
            MWSSMessage::FAFData(_, _) => true,
            _ => false,
        }
    }

    pub fn message_body(self) -> MessageBody {
        match self {
            MWSSMessage::MessageBody (body) => body,
            _ => panic!("Expected MWSSMessage::MessageBody, got {:?} instead", self),
        }
    }

    pub async fn send(self, sender: &mut WSSender) {
        match self {
            MWSSMessage::MessageBody(body) => {
                let opcode = body.opcode.clone();
                let json = UiTrafficConverter::new_marshal(body);
                Self::send_data_message(sender, SokettoDataType::Text(json.len()), json.into_bytes()).await;
            },
            MWSSMessage::FAFData(data_type, data) => {
                Self::send_data_message(sender, data_type, data).await;
            },
            MWSSMessage::ConversationData(data_type, data) => {
                Self::send_data_message(sender, data_type, data).await;
            },
            MWSSMessage::Close() => {
                sender.close().await.expect("Failed to send close message");
            },
        }
    }

    async fn send_data_message(sender: &mut WSSender, data_type: SokettoDataType, data: Vec<u8>) {
        match data_type {
            SokettoDataType::Text(_) => {
                let text = std::str::from_utf8(&data).expect("Error converting data to text");
                sender.send_text(text).await.expect("Error sending data to client");
                sender.flush().await.expect("Error flushing text to client");
            },
            SokettoDataType::Binary(_) => {
                sender.send_binary(&data).await.expect("Error sending data to client");
                sender.flush().await.expect("Error flushing binary data to client");
            },
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

    pub fn queue_close(mut self, code_opt: Option<u16>, reason_opt: Option<&str>) -> Self {
        self.responses.push(MWSSMessage::FAFData(SokettoDataType::Binary(0), vec![]));
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
                        match (data_type_res) {
                            Ok(data_type) => data_type,
                            Err(e) => panic!("Error receiving data from client: {}", e),
                        }
                    }
                    stop_strategy = &mut termination_rx => {
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
                response.send(sender).await;
            } else {
                break;
            }
        }
    }

    async fn send_next_message(
        sender: &mut WSSender,
        responses: &mut Vec<MWSSMessage>,
    ) {
        if responses.is_empty() {
            let msg = b"EMPTY_QUEUE".to_vec();
            Self::send_data(sender, SokettoDataType::Binary(msg.len()), msg).await;
            return;
        }
        let response = responses.remove(0);
        response.send(sender).await;
    }

    async fn send_data(sender: &mut WSSender, data_type: SokettoDataType, data: Vec<u8>) {
        match data_type {
            SokettoDataType::Text(len) => {
                let text = std::str::from_utf8(&data).expect("Error converting data to text");
                sender.send_text(text).await.expect("Error sending data to client");
                sender.flush().await.expect("Error flushing text to client");
            },
            SokettoDataType::Binary(len) => {
                sender.send_binary(&data).await.expect("Error sending data to client");
                sender.flush().await.expect("Error flushing binary data to client");
            },
        }
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
    Close,
    Abort
}

impl StopStrategy {
    pub async fn apply (self, mut sender: WSSender) {
        match self {
            StopStrategy::Close => {Self::close(sender);},
            StopStrategy::Abort => {Self::abort(sender);},
        }
    }

    async fn close(mut sender: WSSender) {
        sender.close().await.expect("Error closing WebSocket connection");
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
        let _ = tokio::time::timeout(Duration::from_secs(10), self.join_handle).await;
        MockWebSocketsServerResult {
            requests: (*(self.requests_arc.lock().unwrap())).clone(),
            proposed_protocols: (*(self.proposed_protocols_arc.lock().unwrap())).clone(),
        }
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
            .unwrap()
            .1;

        let mut requests = stop_handle.stop(StopStrategy::Close).await.requests;
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
            .unwrap()
            .1;
        eprintln!("Six");
        assert_eq!(
            received_message_number_one.matches,
            conversation_number_one_response.matches
        );

        let received_message_number_two: UiCheckPasswordResponse = connection
            .transact_with_context_id(conversation_number_two_request.clone(), 2)
            .await
            .unwrap()
            .1;
        eprintln!("Seven");
        assert_eq!(
            received_message_number_two.matches,
            conversation_number_two_response.matches
        );
        let _received_message_number_three: UiConfigurationChangedBroadcast =
            connection.skip_until_received().await.unwrap().1;

        let _received_message_number_four: UiNodeCrashedBroadcast =
            connection.skip_until_received().await.unwrap().1;

        let received_message_number_five: UiDescriptorResponse = connection
            .transact_with_context_id(conversation_number_three_request.clone(), 3)
            .await
            .unwrap()
            .1;
        assert_eq!(
            received_message_number_five.node_descriptor_opt,
            Some("ae15fe6".to_string())
        );

        let _received_message_number_six: UiNewPasswordBroadcast =
            connection.skip_until_received().await.unwrap().1;

        let requests = stop_handle.stop(StopStrategy::Close).await.requests;

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

    #[tokio::test]
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
