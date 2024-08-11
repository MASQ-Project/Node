// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::messages::NODE_UI_PROTOCOL;
use crate::ui_gateway::{MessageBody, MessagePath, MessageTarget};
use crate::ui_traffic_converter::{UiTrafficConverter, UnmarshalError};
use crate::utils::localhost;
use async_trait::async_trait;
use crossbeam_channel::{unbounded, Receiver, Sender};
use itertools::Either;
use lazy_static::lazy_static;
use std::fmt::{format, Debug};
use std::net::SocketAddr;
use std::ops::{Deref, DerefMut};
use std::ops::Not;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};
use std::{mem, thread};
use std::collections::HashMap;
use std::time::{Duration, Instant, SystemTime};
use std::str::FromStr;
use actix::dev::MessageResponse;
use workflow_websocket::server::error::Error as WebsocketServerError;
use workflow_websocket::server::{Error, Message, WebSocketConfig, WebSocketCounters, WebSocketHandler, WebSocketReceiver, WebSocketSender, WebSocketServer, WebSocketServerTrait, WebSocketSink};
use workflow_websocket::server::handshake::greeting;
use crate::test_utils::websockets_utils::{establish_bare_ws_conn, establish_ws_conn_with_handshake};
use crate::websockets_handshake::verify_masq_ws_subprotocol;

lazy_static! {
    static ref MWSS_INDEX: Mutex<u64> = Mutex::new(0);
}

struct NodeUiProtocolWebSocketHandler {
    requests_arc: Arc<Mutex<Vec<MockWSServerRecordedRequest>>>,
    responses_arc: Arc<Mutex<Vec<Message>>>,
    opening_broadcasts_signal_rx_opt: Mutex<Option<tokio::sync::oneshot::Receiver<()>>>,
    do_log: bool,
    index: u64,
}

#[async_trait]
impl WebSocketHandler for NodeUiProtocolWebSocketHandler {
    type Context = SocketAddr;

    async fn connect(self: &Arc<Self>, peer: &SocketAddr) -> workflow_websocket::server::Result<()> {
        log(
            self.do_log,
            self.index,
            format!("Accepted TCP connection from {}", peer).as_str(),
        );
        Ok(())
    }

    async fn handshake(
        self: &Arc<Self>,
        peer: &SocketAddr,
        sender: &mut WebSocketSender,
        receiver: &mut WebSocketReceiver,
        sink: &WebSocketSink,
    ) -> workflow_websocket::server::Result<Self::Context> {
        log(
            self.do_log,
            self.index,
            format!("Awaiting handshake msg from {}", peer).as_str(),
        );

        greeting(
            Duration::from_millis(5000),
            sender,
            receiver,
            Box::pin(verify_masq_ws_subprotocol),
        ).await?;

        log(
            self.do_log,
            self.index,
            "Checking for exposed, initial fire-and-forget messages to push them off",
        );
        self.handle_opening_broadcasts(sink);

        Ok(*peer)
    }

    async fn message(
        self: &Arc<Self>,
        _ctx: &Self::Context,
        msg: Message,
        sink: &WebSocketSink,
    ) -> workflow_websocket::server::Result<()> {
        log(
            self.do_log,
            self.index,
            "Checking for fire-and-forget messages",
        );
        self.release_fire_and_forget_messages_introducing_the_queue(sink);

        log(self.do_log, self.index, "Checking for message from client");

        let incoming = self.handle_incoming_msg(msg);

        let cash_for_panic_opt = self.record_incoming_msg(
            incoming.received_wrong_data_is_fatal(),
            incoming.request_to_be_recorded,
        );

        match incoming.incoming_message_resolution {
            Either::Left(Ok(message_body)) => {
                match message_body.path {
                    MessagePath::Conversation(_) => {
                        self.handle_conversational_incoming_message(sink)
                    }
                    MessagePath::FireAndForget => {
                        log(
                            self.do_log,
                            self.index,
                            "Responding to FireAndForget message by forgetting",
                        );
                    }
                }
                Ok(())
            }
            Either::Left(Err(unexpected_impulse_from_test)) => {
                log(
                    self.do_log,
                    self.index,
                    "Going to panic: Unrecognizable form of a text message",
                );
                panic!(
                    "Unrecognizable incoming message received; you should refrain from sending some \
                    meaningless garbage to the test server: {:?}",
                    cash_for_panic_opt
                        .expect("panic expected but the cached data to be print can not be found")
                )
            }
            Either::Right(polite_instruction_to_server) => Err(polite_instruction_to_server),
        }
    }
}

impl NodeUiProtocolWebSocketHandler {
    fn release_fire_and_forget_messages_introducing_the_queue(&self, sink: &WebSocketSink) {
        let mut counter = 0usize;
        loop {
            if self.responses_arc.lock().unwrap().is_empty() {
                break;
            }
            let temporarily_owned_possible_f_f = self.responses_arc.lock().unwrap().remove(0);
            if match &temporarily_owned_possible_f_f {
                Message::Text(text) =>
                    match UiTrafficConverter::new_unmarshal_to_ui(text, MessageTarget::AllClients)
                    {
                        Ok(msg) => match msg.body.path {
                            MessagePath::FireAndForget => {
                                let f_f_message = temporarily_owned_possible_f_f.clone();
                                sink.send(f_f_message).unwrap();
                                log(self.do_log, self.index, "Sending a fire-and-forget message to the UI");
                                true
                            }
                            _ => false
                        }
                        _ => false
                    }
                _ => false
            }.not() {
                self.responses_arc.lock().unwrap().insert(0, temporarily_owned_possible_f_f);
                log(self.do_log, self.index, "No fire-and-forget message found; heading over to conversational messages");
                break
            }
            thread::sleep(Duration::from_millis(1));
            counter += 1;
            //for true, we keep looping
        }
    }

    fn record_incoming_msg(
        &self,
        processing_is_going_wrong: bool,
        request_to_be_recorded: MockWSServerRecordedRequest,
    ) -> Option<MockWSServerRecordedRequest> {
        log(
            self.do_log,
            self.index,
            &format!("Recording incoming message: {:?}", request_to_be_recorded),
        );

        let cash_for_panic_opt = if processing_is_going_wrong {
            Some(request_to_be_recorded.clone())
        } else {
            None
        };

        self.requests_arc
            .lock()
            .unwrap()
            .push(request_to_be_recorded);

        cash_for_panic_opt
    }

    fn handle_incoming_msg(&self, incoming: Message) -> ProcessedIncomingMessage {
        let text_msg = match self.handle_non_textual_messages(incoming) {
            Err(already_fully_processed) => return already_fully_processed,
            Ok(message_body_json) => message_body_json,
        };

        self.handle_incoming_msg_raw(text_msg)
    }

    fn handle_non_textual_messages(
        &self,
        incoming: Message,
    ) -> Result<String, ProcessedIncomingMessage> {
        match &incoming {
            Message::Text(string) => Ok(string.to_string()),
            Message::Close(..) => Err(ProcessedIncomingMessage::new(
                Either::Right(WebsocketServerError::ServerClose),
                MockWSServerRecordedRequest::WSNonTextual(incoming.clone()),
            )),
            msg => {
                log(
                    self.do_log,
                    self.index,
                    &format!("Received unexpected message {:?} - discarding", msg),
                );
                let result = Err(UnrecognizedMessageErr::new(format!("{:?}", msg)));
                Err(ProcessedIncomingMessage::new(
                    Either::Left(result),
                    MockWSServerRecordedRequest::WSNonTextual(incoming.clone()),
                ))
            }
        }
    }

    fn handle_incoming_msg_raw(&self, msg_text: String) -> ProcessedIncomingMessage {
        log(self.do_log, self.index, &format!("Received '{}'", msg_text));
        match UiTrafficConverter::new_unmarshal_from_ui(&msg_text, 0) {
            Ok(msg) => ProcessedIncomingMessage::new(
                Either::Left(Ok(msg.body.clone())),
                MockWSServerRecordedRequest::MASQNodeUIv2Protocol(msg.body.clone()),
            ),
            Err(e) => ProcessedIncomingMessage::new(
                Either::Left(Err(UnrecognizedMessageErr::new(e.to_string()))),
                MockWSServerRecordedRequest::WSTextual {
                    unexpected_string: msg_text,
                },
            ),
        }
    }

    fn handle_conversational_incoming_message(&self, sink: &WebSocketSink) {
        let mut temporary_access_to_responses = self.responses_arc.lock().unwrap();
        if temporary_access_to_responses.len() != 0 {
            let owned_msg = temporary_access_to_responses.remove(0);
            log(
                self.do_log,
                self.index,
                &format!("Responding with preset Message: {:?}", owned_msg),
            );
            sink.send(owned_msg).unwrap()
        } else {
            log(self.do_log, self.index, "No more messages to send back");
            sink.send(Message::Binary(b"EMPTY QUEUE".to_vec())).unwrap()
        }
    }

    fn handle_opening_broadcasts(self: &Arc<Self>, sink: &WebSocketSink){
        if let Some(receiver) = self.opening_broadcasts_signal_rx_opt.lock().unwrap().take() {
            let detached_server_clone = self.clone();
            let sink_clone = sink.clone();
            let _ = tokio::spawn(async move {
                receiver.await.expect("Failed to release broadcasts on signal");
                detached_server_clone.release_fire_and_forget_messages_introducing_the_queue(&sink_clone)
            });
        } else {
            self.release_fire_and_forget_messages_introducing_the_queue(sink)
        }
    }
}

pub struct MockWebSocketsServer {
    do_log: bool,
    port: u16,
    protocol: String,
    responses: Vec<Message>,
    //TODO remove this eventually
    opening_broadcast_signal_rx_opt: Option<tokio::sync::oneshot::Receiver<()>>,
}

impl MockWebSocketsServer {
    pub fn new(port: u16) -> Self {
        Self {
            do_log: false,
            port,
            protocol: NODE_UI_PROTOCOL.to_string(),
            responses: vec![],
            opening_broadcast_signal_rx_opt: None,
        }
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn queue_response(self, message: MessageBody) -> Self {
        self.queue_string(&UiTrafficConverter::new_marshal(message))
    }

    pub fn queue_string(self, string: &str) -> Self {
        self.queue_owned_message(Message::Text(string.to_string()))
    }

    pub fn queue_owned_message(mut self, msg: Message) -> Self {
        self.responses.push(msg);
        self
    }

    pub fn inject_opening_broadcasts_signal_receiver(mut self, receiver: tokio::sync::oneshot::Receiver<()>) -> Self {
        self.opening_broadcast_signal_rx_opt = Some(receiver);
        self
    }

    pub fn write_logs(mut self) -> Self {
        self.do_log = true;
        self
    }

    pub async fn start(self) -> MockWebSocketsServerStopHandle {
        let index = {
            let mut guard = MWSS_INDEX.lock().unwrap();
            let index = *guard;
            *guard += 1;
            index
        };
        let requests_arc = Arc::new(Mutex::new(vec![]));
        let counters = Arc::new(WebSocketCounters::default());

        let handler = NodeUiProtocolWebSocketHandler {
            requests_arc: requests_arc.clone(),
            responses_arc: Arc::new(Mutex::new(self.responses)),
            opening_broadcasts_signal_rx_opt: Mutex::new(self.opening_broadcast_signal_rx_opt),
            do_log: self.do_log,
            index,
        };

        let ws_server_handle = WebSocketServer::new(Arc::new(handler), Some(counters.clone()));
        let ws_server_handle_clone = ws_server_handle.clone();
        let socket_addr = SocketAddr::new(localhost(), self.port);
        let static_socket_addr_str: &'static str = Box::leak(socket_addr.to_string().into_boxed_str());
        let server_task =
            ws_server_handle_clone.listen(static_socket_addr_str, None);
        tokio::spawn(server_task);

        log(
            self.do_log,
            index,
            format!("Started listening on: {}", socket_addr).as_str(),
        );

        MockWebSocketsServerStopHandle {
            index,
            log: self.do_log,
            requests_arc,
            counters,
            server_port: self.port,
        }
    }
}

type IncomingMsgResolution = Either<Result<MessageBody, UnrecognizedMessageErr>, WebsocketServerError>;

#[derive(Debug)]
struct ProcessedIncomingMessage {
    incoming_message_resolution: IncomingMsgResolution,
    request_to_be_recorded: MockWSServerRecordedRequest,
}

impl ProcessedIncomingMessage {
    fn new(
        processing_resolution: IncomingMsgResolution,
        request_to_be_recorded: MockWSServerRecordedRequest,
    ) -> Self {
        Self {
            incoming_message_resolution: processing_resolution,
            request_to_be_recorded,
        }
    }

    fn received_wrong_data_is_fatal(&self) -> bool {
        matches!(self.incoming_message_resolution, Either::Left(Err(..)))
    }
}

#[derive(Debug)]
struct UnrecognizedMessageErr {
    err_msg: String,
}

impl UnrecognizedMessageErr {
    fn new(err_msg: String) -> Self {
        Self { err_msg }
    }
}

#[derive(Clone, Debug)]
pub enum MockWSServerRecordedRequest {
    WSNonTextual(Message),
    WSTextual { unexpected_string: String },
    MASQNodeUIv2Protocol(MessageBody),
}

impl MockWSServerRecordedRequest {
    pub fn expect_masq_ws_protocol_msg(self) -> MessageBody {
        if let Self::MASQNodeUIv2Protocol(unmarshal_result) = self {
            unmarshal_result
        } else {
            panic!(
                "We expected a websocket message of our MASQNode-UIv2 but found {:?}",
                self
            )
        }
    }
}

pub struct MockWebSocketsServerStopHandle {
    index: u64,
    log: bool,
    requests_arc: Arc<Mutex<Vec<MockWSServerRecordedRequest>>>,
    counters: Arc<WebSocketCounters>,
    server_port: u16,
}

impl MockWebSocketsServerStopHandle {
    pub async fn retrieve_recorded_requests(&self, required_msg_count_opt: Option<usize>)->Vec<MockWSServerRecordedRequest>{
        let recorded_requests_waiting_start = SystemTime::now();
        let recorded_requests_waiting_hard_limit = Duration::from_millis(2500);
        let obtain_guard = || self.requests_arc.lock().unwrap_or_else(|poison_error| poison_error.into_inner());
        loop {

            if let Some(required_msg_count) = required_msg_count_opt {
                let guard_len = obtain_guard().len();
                if required_msg_count <= guard_len {
                    if recorded_requests_waiting_start.elapsed().expect("travelling in time") >= recorded_requests_waiting_hard_limit {
                        panic!("We waited for {} expected requests but the queue contained only {:?} after {} ms timeout", required_msg_count, *obtain_guard(), recorded_requests_waiting_hard_limit.as_millis())
                    } else {
                        let sleep_ms = 50;
                        log(
                            self.log,
                            self.index,
                            &format!("Sleeping {} ms before another attempt to fetch the expected requests", sleep_ms),
                        );
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        continue
                    }
                }
            }

            log(
                self.log,
                self.index,
                "Retrieving recorded requests by the server",
            );

            break obtain_guard().drain(..).collect()
        }
    }

    pub async fn await_conn_established(&self, biased_by_other_connections_opt: Option<usize>){
        let allowed_parallel_conn = biased_by_other_connections_opt.unwrap_or(0);
        self.await_loop(|counters|(counters.active_connections.load(Ordering::Relaxed) - allowed_parallel_conn) > 0).await
    }

    // pub async fn await_disconnection(&self, biased_by_other_connections_opt: Option<usize>){
    //     let allowed_parallel_conn = biased_by_other_connections_opt.unwrap_or(0);
    //     self.await_loop(|counters|counters.active_connections.load(Ordering::Relaxed) == (0 + allowed_parallel_conn)).await
    // }

    async fn await_loop<F>(&self, test_desired_condition: F) where F: Fn(&Arc<WebSocketCounters>)->bool{
        let fut = async {
            loop {
                if test_desired_condition(&self.counters) {
                    break
                }
                tokio::time::sleep(Duration::from_millis(100)).await
            }
        };
        tokio::time::timeout(Duration::from_millis(5_000), fut).await.expect("Timed out waiting for server connection's status change")
    }
}

// TODO: This should really be an object, not a function, and the object should hold do_log and index.
fn log(do_log: bool, index: u64, msg: &str) {
    if do_log {
        eprintln!("MockWebSocketsServer {}: {}", index, msg);
    }
}

#[cfg(test)]
mod tests {
    use futures_util::FutureExt;
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

        let mut requests = stop_handle.retrieve_recorded_requests(None).await;
        let captured_request = requests.remove(0).expect_masq_ws_protocol_msg();
        let actual_message_gotten_by_the_server =
            UiCheckPasswordRequest::fmb(captured_request)
                .unwrap()
                .0;
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
            db_password_opt: Some("Titanic".to_string()),
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
        eprintln!("Before freeze");

        let _received_message_number_three: UiConfigurationChangedBroadcast = // TODO: Freezes here
            connection.skip_until_received().await.unwrap();

        eprintln!("After freeze");
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

        let requests = stop_handle.retrieve_recorded_requests(None).await;

        assert_eq!(
            requests
                .into_iter()
                .map(|x| x.expect_masq_ws_protocol_msg())
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
        let stop_handle = server.start().await;
        let mut connection = UiConnection::new(port, NODE_UI_PROTOCOL).await.unwrap();
        let conversation_request = UiChangePasswordRequest {
            old_password_opt: None,
            new_password: "password".to_string(),
        };

        let _ = connection
            .transact::<UiChangePasswordRequest, UiChangePasswordResponse>(conversation_request)
            .await
            .unwrap();
    }
}
