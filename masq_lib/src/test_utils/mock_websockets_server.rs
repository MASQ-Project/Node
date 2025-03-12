// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::messages::NODE_UI_PROTOCOL;
use crate::test_utils::forced_tcp_reset::SocketHandle;
use crate::ui_gateway::{MessageBody, MessagePath};
use crate::ui_traffic_converter::UiTrafficConverter;
use crate::utils::localhost;
use crate::websockets_types::{WSReceiver, WSSender};
use futures::io::{BufReader, BufWriter};
use lazy_static::lazy_static;
use soketto::base::OpCode;
use soketto::connection::Error;
use soketto::handshake::{server::Response, Server};
use soketto::{Data as SokettoDataType, Incoming};
use std::fmt::Debug;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::sync::oneshot::Receiver as OneShotReceiver;
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tokio_util::compat::TokioAsyncReadCompatExt;

lazy_static! {
    static ref MWSS_INDEX: Mutex<u64> = Mutex::new(0);
}

#[derive(Debug, PartialEq, Clone)]
pub enum MWSSMessage {
    // If you have a MessageBody, put it in one of these.
    MessageBody(MessageBody),
    // If you have a non-MessageBody "response" that you want to be sent without being
    // specifically requested, put it here.
    FAFData(SokettoDataType, Vec<u8>),
    // If you have a non-MessageBody request, or a non-MessageBody response that must be
    // triggered by a request, put it here.
    ConversationData(SokettoDataType, Vec<u8>),
    // If you have a close message, put it here.
    Close,
}

impl MWSSMessage {
    pub fn is_fire_and_forget(&self) -> bool {
        match self {
            MWSSMessage::MessageBody(body) => body.path == MessagePath::FireAndForget,
            MWSSMessage::FAFData(_, _) => true,
            _ => false,
        }
    }

    pub fn message_body(self) -> MessageBody {
        match self {
            MWSSMessage::MessageBody(body) => body,
            _ => panic!("Expected MWSSMessage::MessageBody, got {:?} instead", self),
        }
    }

    pub async fn send(self, sender: &mut WSSender) {
        match self {
            MWSSMessage::MessageBody(body) => {
                let json = UiTrafficConverter::new_marshal(body);
                Self::send_data_message(
                    sender,
                    SokettoDataType::Text(json.len()),
                    json.into_bytes(),
                )
                    .await;
            }
            MWSSMessage::FAFData(data_type, data) => {
                Self::send_data_message(sender, data_type, data).await;
            }
            MWSSMessage::ConversationData(data_type, data) => {
                Self::send_data_message(sender, data_type, data).await;
            }
            MWSSMessage::Close => {
                sender.close().await.expect("Failed to send close message");
            }
        }
    }

    async fn send_data_message(sender: &mut WSSender, data_type: SokettoDataType, data: Vec<u8>) {
        match data_type {
            SokettoDataType::Text(_) => {
                let text = std::str::from_utf8(&data).expect("Error converting data to text");
                sender
                    .send_text(text)
                    .await
                    .expect("Error sending data to client");
                sender.flush().await.expect("Error flushing text to client");
            }
            SokettoDataType::Binary(_) => {
                sender
                    .send_binary(&data)
                    .await
                    .expect("Error sending data to client");
                sender
                    .flush()
                    .await
                    .expect("Error flushing binary data to client");
            }
        }
    }
}

pub struct MockWebSocketsServer {
    port: u16,
    responses: Vec<MWSSMessage>,
    edge_cases: EdgeCaseConfig,
    do_log: bool,
}

impl MockWebSocketsServer {
    pub fn new(port: u16) -> Self {
        Self {
            port,
            responses: vec![],
            edge_cases: EdgeCaseConfig::default(),
            do_log: false,
        }
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn send_unexpected_http_when_tcp_established(mut self, http_response: String) -> Self {
        self.edge_cases.unexpected_http_when_tcp_established_opt = Some(http_response);
        self
    }

    pub fn send_specific_handshake_response(
        mut self,
        response: MockServerHandshakeResponse,
    ) -> Self {
        self.edge_cases.specific_handshake_response_opt = Some(response);
        self
    }

    // E.g. required for testing a redirect where a conversational message is followed by a faf msg
    pub fn opening_faf_triggered_by_msg(mut self) -> Self {
        self.edge_cases.opening_faf_triggered_by_msg = true;
        self
    }

    pub fn await_close_handshake_completion(mut self) -> Self {
        self.edge_cases.await_close_handshake_completion = true;
        self
    }

    pub fn drop_conn_during_handshake(mut self) -> Self {
        self.edge_cases.drop_conn_during_handshake = true;
        self
    }

    pub fn set_socket_to_no_linger(mut self) -> Self {
        self.edge_cases.set_socket_to_no_linger = true;
        self
    }

    pub fn queue_response(mut self, message: MessageBody) -> Self {
        self.responses.push(MWSSMessage::MessageBody(message));
        self
    }

    pub fn queue_faf_string(mut self, string: &str) -> Self {
        self.responses.push(MWSSMessage::FAFData(
            SokettoDataType::Text(string.len()),
            string.as_bytes().to_vec(),
        ));
        self
    }

    pub fn queue_conv_string(mut self, string: &str) -> Self {
        self.responses.push(MWSSMessage::ConversationData(
            SokettoDataType::Text(string.len()),
            string.as_bytes().to_vec(),
        ));
        self
    }

    pub fn queue_faf_owned_message(mut self, data_type: SokettoDataType, data: Vec<u8>) -> Self {
        self.responses
            .push(MWSSMessage::FAFData(data_type.clone(), data));
        self
    }

    pub fn queue_conv_owned_message(mut self, data_type: SokettoDataType, data: Vec<u8>) -> Self {
        self.responses
            .push(MWSSMessage::ConversationData(data_type.clone(), data));
        self
    }

    pub fn write_logs(mut self) -> Self {
        self.do_log = true;
        self
    }

    pub async fn start(mut self) -> MockWebSocketsServerHandle {
        let logger = MWSSLogger::new(self.do_log);
        let requests_arc = Arc::new(Mutex::new(vec![]));
        let proposed_protocols_arc = Arc::new(Mutex::new(vec![]));
        let (termination_tx, termination_rx) = tokio::sync::oneshot::channel();

        let socket_addr = SocketAddr::new(localhost(), self.port);
        let tcp_listener = tokio::net::TcpListener::bind(socket_addr)
            .await
            .unwrap_or_else(|e| panic!("Could not create listener for {}: {:?}", socket_addr, e));

        let proposed_protocols_inner_arc = proposed_protocols_arc.clone();
        let requests_inner_arc = requests_arc.clone();

        let connection_future = async move {
            let (mut sender, receiver) = match self
                .make_connection(tcp_listener, proposed_protocols_inner_arc)
                .await
            {
                ConnectionResult::ComponentsInitialized { sender, receiver } => (sender, receiver),
                ConnectionResult::IntentionalExit => return,
                };
            if !self.edge_cases.opening_faf_triggered_by_msg {
                Self::send_faf_messages(&mut sender, &mut self.responses).await;
            }
            Self::handling_loop(
                sender,
                receiver,
                requests_inner_arc,
                &mut self.responses,
                termination_rx,
                self.edge_cases,
            )
                .await
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

    async fn handling_loop(
        mut sender: WSSender,
        mut receiver: WSReceiver,
        requests_inner_arc: Arc<Mutex<Vec<MWSSMessage>>>,
        responses: &mut Vec<MWSSMessage>,
        termination_rx: OneShotReceiver<()>,
        edge_cases: EdgeCaseConfig,
    ) {
        let deadline_if_no_termination_received = Duration::from_millis(10_000);
        let timeout = tokio::time::sleep(deadline_if_no_termination_received);
        tokio::pin!(timeout);

        type TerminationOrderFuture = Pin<Box<dyn Future<Output = ()> + Send>>;
        let mut termination_order_future: TerminationOrderFuture = Box::pin(async {
            termination_rx
                .await
                .expect("Error receiving termination signal")
        });
        let mut stop_already_ordered = false;
        let mut data = Vec::new();

        loop {
            data.clear();
            let data_type = tokio::select! {
                    data_type_res = receiver.receive_data(&mut data) => {
                        match data_type_res {
                            Ok(data_type) => data_type,
                            Err(Error::Closed) => {
                                Self::process_close(&requests_inner_arc);
                                return;
                            },
                            Err(Error::UnexpectedOpCode(OpCode::Continue)) => continue,
                            Err(e) => panic!("Error receiving data from client: {}", e),
                        }
                    }

                    _ = &mut timeout => {
                        if stop_already_ordered {
                            Self::handle_server_stop(sender, receiver, requests_inner_arc, edge_cases.await_close_handshake_completion).await;
                            return;
                        } else {
                            panic!(
                                "Reached global test timeout {} ms without receiving a proper \
                                termination order", deadline_if_no_termination_received.as_millis()
                            )
                        }
                    }

                    _ = termination_order_future.as_mut() => {
                        stop_already_ordered = true;
                        // Resetting to a future which never resolves
                        termination_order_future = Box::pin(std::future::pending());
                        // Now we're giving time for processing any piled up messages in
                        // the Websockets channel. Each unprocessed msg must be pulled within
                        // this new timeout or the server terminates before all request were
                        // recorded
                        timeout.as_mut().reset(Instant::now() + Duration::from_millis(10));
                        continue
                    }
            };
            Self::process_data(
                &data_type,
                &data,
                &mut sender,
                requests_inner_arc.clone(),
                responses,
            )
                .await;
        }
    }

    async fn make_connection(
        &self,
        tcp_listener: TcpListener,
        proposed_protocols_arc: Arc<Mutex<Vec<String>>>,
    ) -> ConnectionResult {
        let (mut stream, _) = tcp_listener
            .accept()
            .await
            .expect("Error accepting incoming connection to MockWebsocketsServer");

        if self.edge_cases.set_socket_to_no_linger {
            SocketHandle::new(&stream).set_socket_to_no_linger();
        }

        if let Some(http) = self
            .edge_cases
            .unexpected_http_when_tcp_established_opt
            .as_ref()
        {
            stream.write_all(http.as_bytes()).await.unwrap();
            stream.flush().await.unwrap()
        }

        let mut server = Server::new(BufReader::new(BufWriter::new(stream.compat())));

        let protocol = if let Some(protocol) = self.arbitrary_protocol_opt() {
            protocol
        } else {
            NODE_UI_PROTOCOL
        };

        server.add_protocol(protocol);

        let websocket_key = {
            let req = server
                .receive_request()
                .await
                .expect("Error receiving request from client");
            proposed_protocols_arc
                .lock()
                .unwrap()
                .extend(req.protocols().map(|p| p.to_string()));
            req.key()
        };

        if self.edge_cases.drop_conn_during_handshake {
            // Dropping server and thus the connection terminates
            // (You may want to combine it with set_socket_to_no_linger() for a violate reset)
            return ConnectionResult::IntentionalExit;
        }

        let server_response =
            if let Some(response) = &self.edge_cases.specific_handshake_response_opt {
                match response {
                    MockServerHandshakeResponse::Accept {
                        accepted_protocol_opt,
                        replace_correct_websocket_key_with_opt,
                    } => Response::Accept {
                        key: if let Some(key) = replace_correct_websocket_key_with_opt {
                            key.clone()
                        } else {
                            websocket_key
                        },
                        protocol: accepted_protocol_opt.as_ref().map(|p| p.as_str()),
                    },
                    MockServerHandshakeResponse::Reject { status_code } => Response::Reject {
                        status_code: *status_code,
                    },
                }
            } else {
                Response::Accept {
                    key: websocket_key,
                    protocol: Some(NODE_UI_PROTOCOL),
                }
            };

        server
            .send_response(&server_response)
            .await
            .expect("Error sending handshake acceptance to client");

        let (sender, receiver) = server.into_builder().finish();

        ConnectionResult::ComponentsInitialized { sender, receiver }
    }

    fn arbitrary_protocol_opt(&self) -> Option<&str> {
        if let Some(response) = &self.edge_cases.specific_handshake_response_opt {
            if let MockServerHandshakeResponse::Accept {
                accepted_protocol_opt,
                ..
            } = response
            {
                if let Some(protocol) = accepted_protocol_opt {
                    return Some(protocol.as_str());
                }
            }
        }

        None
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

    fn process_close(requests: &Arc<Mutex<Vec<MWSSMessage>>>) {
        requests.lock().unwrap().push(MWSSMessage::Close);
    }

    fn parse_and_save_incoming_message(
        data_type: &SokettoDataType,
        data: &[u8],
        requests_arc: Arc<Mutex<Vec<MWSSMessage>>>,
    ) {
        let message = match data_type {
            SokettoDataType::Text(_) => {
                let text = std::str::from_utf8(data).expect("Error converting data to text");
                match UiTrafficConverter::new_unmarshal_from_ui(text, 0) {
                    Ok(msg) => MWSSMessage::MessageBody(msg.body),
                    Err(_) => MWSSMessage::ConversationData(data_type.clone(), data.to_vec()),
                }
            }
            SokettoDataType::Binary(_) => {
                MWSSMessage::ConversationData(data_type.clone(), data.to_vec())
            }
        };
        requests_arc.lock().unwrap().push(message);
    }

    async fn send_faf_messages(sender: &mut WSSender, responses: &mut Vec<MWSSMessage>) {
        while let Some(response) = responses.first() {
            if response.is_fire_and_forget() {
                let response = responses.remove(0);
                response.send(sender).await;
            } else {
                break;
            }
        }
    }

    async fn send_next_message(sender: &mut WSSender, responses: &mut Vec<MWSSMessage>) {
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
            SokettoDataType::Text(_) => {
                let text = std::str::from_utf8(&data).expect("Error converting data to text");
                sender
                    .send_text(text)
                    .await
                    .unwrap_or_else(|_| panic!("Error sending text msg '{:?}' to client", text));
                sender
                    .flush()
                    .await
                    .unwrap_or_else(|_| panic!("Error flushing text msg '{:?}' to client", text));
            }
            SokettoDataType::Binary(_) => {
                sender
                    .send_binary(&data)
                    .await
                    .unwrap_or_else(|_| panic!("Error sending binary data '{:?}' to client", data));
                sender.flush().await.unwrap_or_else(|_| {
                    panic!("Error flushing binary data '{:?}' to client", data)
                });
            }
        }
    }

    async fn handle_server_stop(
        sender: WSSender,
        receiver: WSReceiver,
        requests_inner_arc: Arc<Mutex<Vec<MWSSMessage>>>,
        await_close_handshake_completion: bool,
    ) {
        // Other than graceful Close cannot be easily implemented, do not try. Dropping the Sender
        // results in the same Close detection on the remote end like when calling sender.close().
        Self::close(sender).await;

        if await_close_handshake_completion {
            Self::try_record_close_response(receiver, requests_inner_arc).await
        }
    }

    async fn close(mut sender: WSSender) {
        sender
            .close()
            .await
            .expect("Error closing WebSocket connection");
    }

    async fn try_record_close_response(
        mut receiver: WSReceiver,
        requests_arc: Arc<Mutex<Vec<MWSSMessage>>>,
    ) {
        let fut = async move {
            let mut msg = Vec::new();
            loop {
                match receiver.receive(&mut msg).await {
                    Err(Error::Closed) => {requests_arc.lock().unwrap().push(MWSSMessage::Close); break},
                    Err(Error::UnexpectedOpCode(OpCode::Continue)) => continue,
                    Ok(Incoming::Closed(_)) => panic!("Received new Close from the Client, but we expected Err(Error::Closed) handled by Soketto"),
                    Ok(x) => panic!(
                        "Unexpected msg received when waiting for the Client to finish the Close handshake: {:?}",
                        x
                    ),
                    Err(e) => panic!("Unexpected error reading incoming data when waiting for the Client to finish the Close handshake: {:?}", e)
                }
            }
        };

        let timeout = Duration::from_millis(1_500);
        if let Err(_) = tokio::time::timeout(timeout, fut).await {
            panic!(
                "Timeout elapsed waiting for the Client to finish the Close handshake after: {}ms",
                timeout.as_millis()
            )
        }
    }
}

pub type ServerJoinHandle = JoinHandle<workflow_websocket::server::result::Result<()>>;

#[derive(Debug)]
pub struct MockWebSocketsServerResult {
    pub requests: Vec<MWSSMessage>,
    pub proposed_protocols: Vec<String>,
}

pub struct MockWebSocketsServerHandle {
    requests_arc: Arc<Mutex<Vec<MWSSMessage>>>,
    proposed_protocols_arc: Arc<Mutex<Vec<String>>>,
    termination_tx: tokio::sync::oneshot::Sender<()>,
    join_handle: JoinHandle<()>,
}

impl MockWebSocketsServerHandle {
    pub async fn stop(self) -> MockWebSocketsServerResult {
        match self.termination_tx.send(()) {
            Ok(_) => {}
            Err(e) => eprintln!(
                "Failed to send stop signal ({:?}); assuming server already stopped",
                e
            ),
        }
        let _ = tokio::time::timeout(Duration::from_secs(10), self.join_handle).await;
        MockWebSocketsServerResult {
            requests: (*(self.requests_arc.lock().unwrap())).clone(),
            proposed_protocols: (*(self.proposed_protocols_arc.lock().unwrap())).clone(),
        }
    }
}

pub enum MockServerHandshakeResponse {
    Accept {
        accepted_protocol_opt: Option<String>,
        replace_correct_websocket_key_with_opt: Option<[u8; 24]>,
    },
    Reject {
        status_code: u16,
    },
}

struct EdgeCaseConfig {
    opening_faf_triggered_by_msg: bool,
    await_close_handshake_completion: bool,
    drop_conn_during_handshake: bool,
    set_socket_to_no_linger: bool,
    specific_handshake_response_opt: Option<MockServerHandshakeResponse>,
    unexpected_http_when_tcp_established_opt: Option<String>,
}

impl Default for EdgeCaseConfig {
    fn default() -> Self {
        Self {
            opening_faf_triggered_by_msg: false,
            await_close_handshake_completion: false,
            drop_conn_during_handshake: false,
            set_socket_to_no_linger: false,
            specific_handshake_response_opt: None,
            unexpected_http_when_tcp_established_opt: None,
        }
    }
}

enum ConnectionResult {
    ComponentsInitialized {
        sender: WSSender,
        receiver: WSReceiver,
    },
    IntentionalExit,
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

        let mut requests = stop_handle.stop().await.requests;
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
        // connection.close() -> Close

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
            process_id: 11,
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
        let server = MockWebSocketsServer::new(port)
            .queue_response(conversation_number_one_response.clone().tmb(1))
            .queue_response(conversation_number_two_response.clone().tmb(2))
            .queue_response(broadcast_number_one)
            .queue_response(broadcast_number_two.clone())
            .queue_response(conversation_number_three_response)
            .queue_response(broadcast_number_three);
        let stop_handle = server.start().await;
        let mut connection = UiConnection::new(port, NODE_UI_PROTOCOL).await.unwrap();

        let received_message_number_one: UiCheckPasswordResponse = connection
            .transact_with_context_id(conversation_number_one_request.clone(), 1)
            .await
            .unwrap()
            .1;
        assert_eq!(
            received_message_number_one.matches,
            conversation_number_one_response.matches
        );

        let received_message_number_two: UiCheckPasswordResponse = connection
            .transact_with_context_id(conversation_number_two_request.clone(), 2)
            .await
            .unwrap()
            .1;
        assert_eq!(
            received_message_number_two.matches,
            conversation_number_two_response.matches
        );
        // This message has no body, so we don't need to assert further on it
        let _received_message_number_three: UiConfigurationChangedBroadcast =
            connection.skip_until_received().await.unwrap().1;

        let received_message_number_four: (MessagePath, UiNodeCrashedBroadcast) = connection
            .skip_until_received::<UiNodeCrashedBroadcast>()
            .await
            .unwrap();
        assert_eq!(
            received_message_number_four,
            (
                MessagePath::FireAndForget,
                UiNodeCrashedBroadcast::fmb(broadcast_number_two).unwrap().0
            )
        );

        let received_message_number_five: UiDescriptorResponse = connection
            .transact_with_context_id(conversation_number_three_request.clone(), 3)
            .await
            .unwrap()
            .1;
        assert_eq!(
            received_message_number_five.node_descriptor_opt,
            Some("ae15fe6".to_string())
        );

        // This message has no body, so we don't need to assert further on it
        let _received_message_number_six: UiNewPasswordBroadcast =
            connection.skip_until_received().await.unwrap().1;

        connection.send_close().await;
        let closed_error = connection.receive().await.unwrap_err();
        assert!(matches!(closed_error, soketto::connection::Error::Closed));

        let requests = stop_handle.stop().await.requests;

        let last_request = requests.last().unwrap();
        assert_eq!(last_request, &MWSSMessage::Close);
        assert_eq!(
            requests
                .into_iter()
                .take(3)
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

    #[tokio::test]
    async fn incoming_messages_always_beat_termination_signal() {
        let attempt_count = 100;
        let cluster_count = 100;
        let mut actual_request_counts: Vec<usize> = vec![];
        let mut expected_request_counts: Vec<usize> = vec![];
        for i in 0..attempt_count {
            let port = find_free_port();
            let server = MockWebSocketsServer::new(port);
            let server_handle = server.start().await;
            let mut conn = UiConnection::new(port, NODE_UI_PROTOCOL).await.unwrap();

            for j in 0..cluster_count {
                conn.send_string("Booga!".to_string()).await;
            }
            let result = server_handle.stop().await;

            actual_request_counts.push(result.requests.len());
            expected_request_counts.push(attempt_count);
        }
        assert_eq!(actual_request_counts, expected_request_counts);
    }
}
