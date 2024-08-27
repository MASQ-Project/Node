// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::messages::NODE_UI_PROTOCOL;
use crate::ui_gateway::{MessageBody, MessagePath, MessageTarget};
use crate::ui_traffic_converter::UiTrafficConverter;
use crate::utils::localhost;
use crate::websockets_handshake::node_server_greeting;
use actix::dev::MessageResponse;
use async_trait::async_trait;
use lazy_static::lazy_static;
use std::fmt::Debug;
use std::net::SocketAddr;
use std::ops::Not;
use std::ops::{Deref, DerefMut};
use std::str::FromStr;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use workflow_websocket::server::error::Error as WebsocketServerError;
use workflow_websocket::server::{
    Message, WebSocketCounters, WebSocketHandler, WebSocketReceiver, WebSocketSender,
    WebSocketServer, WebSocketServerTrait, WebSocketSink,
};

lazy_static! {
    static ref MWSS_INDEX: Mutex<u64> = Mutex::new(0);
}

struct NodeUiProtocolWebSocketHandler {
    requests_arc: Arc<Mutex<Vec<MockWSServerRecordedRequest>>>,
    responses_arc: Arc<Mutex<Vec<Message>>>,
    opening_broadcasts_signal_rx_opt: Mutex<Option<tokio::sync::oneshot::Receiver<()>>>,
    counters: Arc<WebSocketCounters>,
    listener_stop_tx: Arc<Mutex<Option<async_channel::Sender<()>>>>,
    panicking_conn_obj_opt: Option<PanickingConn>,
    logger: MWSSLogger
}

#[async_trait]
impl WebSocketHandler for NodeUiProtocolWebSocketHandler {
    type Context = ();

    fn accept(&self, _peer: &SocketAddr) -> bool {
        self.check_connection_not_restarted()
    }

    async fn connect(
        self: &Arc<Self>,
        _peer: &SocketAddr,
    ) -> workflow_websocket::server::Result<()> {
        if let Some(object) = self.panicking_conn_obj_opt.as_ref() {
            let _open_mutex = object
                .mutex_to_sense_panic
                .lock()
                .expect("Mutex already poisoned");
            panic!("Testing internal panic")
        }
        Ok(())
    }

    async fn handshake(
        self: &Arc<Self>,
        peer: &SocketAddr,
        sender: &mut WebSocketSender,
        receiver: &mut WebSocketReceiver,
        sink: &WebSocketSink,
    ) -> workflow_websocket::server::Result<Self::Context> {
        self.logger.
        log(format!("Awaiting handshake msg from {}", peer).as_str());

        node_server_greeting(Duration::from_millis(5_000), *peer, sender, receiver).await?;

        self.logger.log(
            "Checking for exposed, initial fire-and-forget messages to push them off",
        );

        self.handle_opening_broadcasts(sink);

        Ok(())
    }

    async fn message(
        self: &Arc<Self>,
        _ctx: &Self::Context,
        msg: Message,
        sink: &WebSocketSink,
    ) -> workflow_websocket::server::Result<()> {
        self.logger.log("Checking for message from client");

        let incoming = self.handle_incoming_msg(msg);

        let cash_for_panic_opt = self.record_incoming_msg(
            incoming.received_data_is_wrong_and_fatal(),
            incoming.request_as_it_will_be_recorded,
        );

        match incoming.resolution {
            IncomingMsgResolution::MASQProtocolMsg(message_body) => {
                match message_body.path {
                    MessagePath::Conversation(_) => {
                        self.handle_conversational_incoming_message(sink)
                    }
                    MessagePath::FireAndForget => {
                        self.logger.log(
                            "Responding to FireAndForget message by forgetting",
                        );
                    }
                }

                self.logger.log(
                    "Checking for fire-and-forget messages having been blocked by a conversational one until now",
                );
                self.release_fire_and_forget_messages_introducing_the_queue(sink);

                Ok(())
            }
            IncomingMsgResolution::UnrecognizedMsgErr(unexpected_impulse_from_test) => {
                self.logger.log(
                    "Going to panic: Unrecognizable form of a text message",
                );
                panic!(
                    "Unrecognizable incoming message received; you should refrain from sending some \
                    meaningless garbage to the test server: {:?}",
                    cash_for_panic_opt
                        .expect("panic expected but the cached data to be print can not be found")
                )
            }
            IncomingMsgResolution::ServerNativeInstruction(polite_instruction_to_server) => Err(polite_instruction_to_server),
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
                Message::Text(text) => {
                    match UiTrafficConverter::new_unmarshal_to_ui(text, MessageTarget::AllClients) {
                        Ok(msg) => match msg.body.path {
                            MessagePath::FireAndForget => {
                                let f_f_message = temporarily_owned_possible_f_f.clone();
                                sink.send(f_f_message).unwrap();
                                self.logger.log(
                                    "Sending a fire-and-forget message to the UI",
                                );
                                true
                            }
                            _ => false,
                        },
                        _ => false,
                    }
                }
                _ => false,
            }
            .not()
            {
                self.responses_arc
                    .lock()
                    .unwrap()
                    .insert(0, temporarily_owned_possible_f_f);
                self.logger.log(
                    "No fire-and-forget message found; heading over to conversational messages",
                );
                break;
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
        self.logger.log(
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

    fn handle_incoming_msg(&self, incoming: Message) -> ProcessedIncomingMsg {
        let text_msg = match self.handle_non_textual_messages(incoming) {
            Err(already_fully_processed) => return already_fully_processed,
            Ok(message_body_json) => message_body_json,
        };

        self.handle_incoming_msg_raw(text_msg)
    }

    fn handle_non_textual_messages(
        &self,
        incoming: Message,
    ) -> Result<String, ProcessedIncomingMsg> {
        match &incoming {
            Message::Text(string) => Ok(string.to_string()),
            Message::Close(..) => Err(ProcessedIncomingMsg::new(
                IncomingMsgResolution::ServerNativeInstruction(WebsocketServerError::ServerClose),
                MockWSServerRecordedRequest::WSNonTextual(incoming.clone()),
            )),
            msg => {
                self.logger.log(
                    &format!("Received unexpected message {:?} - discarding", msg),
                );
                let result = UnrecognizedMessageErr::new(format!("{:?}", msg));
                Err(ProcessedIncomingMsg::new(
                    IncomingMsgResolution::UnrecognizedMsgErr(result),
                    MockWSServerRecordedRequest::WSNonTextual(incoming.clone()),
                ))
            }
        }
    }

    fn handle_incoming_msg_raw(&self, msg_text: String) -> ProcessedIncomingMsg {
        self.logger.log(&format!("Received '{}'", msg_text));
        match UiTrafficConverter::new_unmarshal_from_ui(&msg_text, 0) {
            Ok(msg) => ProcessedIncomingMsg::new(
                IncomingMsgResolution::MASQProtocolMsg(msg.body.clone()),
                MockWSServerRecordedRequest::MASQNodeUIv2Protocol(msg.body.clone()),
            ),
            Err(e) => ProcessedIncomingMsg::new(
                IncomingMsgResolution::UnrecognizedMsgErr(UnrecognizedMessageErr::new(e.to_string())),
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
            self.logger.log(
                &format!("Responding with preset Message: {:?}", owned_msg),
            );
            sink.send(owned_msg).unwrap()
        } else {
            self.logger.log("No more messages to send back");
            sink.send(Message::Binary(b"EMPTY QUEUE".to_vec())).unwrap()
        }
    }

    fn handle_opening_broadcasts(self: &Arc<Self>, sink: &WebSocketSink) {
        if let Some(receiver) = self.opening_broadcasts_signal_rx_opt.lock().unwrap().take() {
            let detached_server_clone = self.clone();
            let sink_clone = sink.clone();
            let _ = tokio::spawn(async move {
                receiver
                    .await
                    .expect("Failed to release broadcasts on signal");
                detached_server_clone
                    .release_fire_and_forget_messages_introducing_the_queue(&sink_clone)
            });
        } else {
            self.release_fire_and_forget_messages_introducing_the_queue(sink)
        }
    }

    fn check_connection_not_restarted(&self)-> bool{
        // The native design of this server is loose on panics, it catches them and throws away. It
        // could panic and restart the connection. We wouldn't notice from outside so we regard
        // a single connection as a universal goal in a test. (If a need for repeated connections
        // arises, we can further configure this).

        // Reaching a second connection indicates that one has probably already panicked
        let total_conn_count_before_incrementing =
            self.counters.total_connections.load(Ordering::Relaxed);

        if total_conn_count_before_incrementing > 0 {
            let _ = self
                .listener_stop_tx
                .lock()
                .expect("stop signaler mutex poisoned")
                .as_ref()
                .expect("stop signaler is missing")
                .try_send(());
            false
        } else {
            true
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
    test_panicking_conn_opt: Option<PanickingConn>,
}

impl MockWebSocketsServer {
    pub fn new(port: u16) -> Self {
        Self {
            do_log: false,
            port,
            protocol: NODE_UI_PROTOCOL.to_string(),
            responses: vec![],
            opening_broadcast_signal_rx_opt: None,
            test_panicking_conn_opt: None,
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

    pub fn inject_opening_broadcasts_signal_receiver(
        mut self,
        receiver: tokio::sync::oneshot::Receiver<()>,
    ) -> Self {
        self.opening_broadcast_signal_rx_opt = Some(receiver);
        self
    }

    pub fn write_logs(mut self) -> Self {
        self.do_log = true;
        self
    }

    // Marked async so it's obvious that it must be called inside a runtime context
    // due to the spawned background task
    pub async fn start(self) -> MockWebSocketsServerHandle {
        let logger = MWSSLogger::new(self.do_log);
        let requests_arc = Arc::new(Mutex::new(vec![]));
        let counters_arc = Arc::new(WebSocketCounters::default());
        let mut listener_stop_tx = Arc::new(Mutex::new(None));

        let handler = NodeUiProtocolWebSocketHandler {
            requests_arc: requests_arc.clone(),
            responses_arc: Arc::new(Mutex::new(self.responses)),
            opening_broadcasts_signal_rx_opt: Mutex::new(self.opening_broadcast_signal_rx_opt),
            counters: counters_arc.clone(),
            listener_stop_tx: listener_stop_tx.clone(),
            panicking_conn_obj_opt: self.test_panicking_conn_opt,
            logger: logger.clone()
        };

        let ws_server_handle = WebSocketServer::new(Arc::new(handler), Some(counters_arc.clone()));

        listener_stop_tx
            .lock()
            .unwrap()
            .replace(ws_server_handle.stop.request.sender.clone());

        let ws_server_handle_clone = ws_server_handle.clone();
        let socket_addr = SocketAddr::new(localhost(), self.port);
        let tcp_listener = TcpListener::bind(socket_addr)
            .await
            .unwrap_or_else(|e| panic!("Could not create listener for {}: {:?}", socket_addr, e));
        let server_task = ws_server_handle_clone.listen(tcp_listener, None);

        let server_background_thread_join_handle = tokio::spawn(server_task);

        logger.log(
            &format!("Started listening on: {}", socket_addr)
        );

        MockWebSocketsServerHandle {
            logger,
            requests_arc,
            server_background_thread_join_handle,
            counters: counters_arc,
            server_port: self.port,
        }
    }
}

#[derive(Debug)]
enum IncomingMsgResolution{
    MASQProtocolMsg(MessageBody),
    UnrecognizedMsgErr(UnrecognizedMessageErr),
    ServerNativeInstruction(WebsocketServerError)
}

#[derive(Debug)]
struct ProcessedIncomingMsg {
    resolution: IncomingMsgResolution,
    request_as_it_will_be_recorded: MockWSServerRecordedRequest,
}

impl ProcessedIncomingMsg {
    fn new(
        resolution: IncomingMsgResolution,
        request_as_it_will_be_recorded: MockWSServerRecordedRequest,
    ) -> Self {
        Self {
            resolution,
            request_as_it_will_be_recorded,
        }
    }

    fn received_data_is_wrong_and_fatal(&self) -> bool {
        matches!(self.resolution, IncomingMsgResolution::UnrecognizedMsgErr(..))
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
    pub fn expect_masq_msg(self) -> MessageBody {
        if let Self::MASQNodeUIv2Protocol(unmarshal_result) = self {
            unmarshal_result
        } else {
            panic!(
                "We expected a websocket message of our MASQNode-UIv2 but found {:?}",
                self
            )
        }
    }
    pub fn expect_textual_msg(self) -> String {
        if let Self::WSTextual { unexpected_string } = self {
            unexpected_string
        } else {
            panic!(
                "We expected a websocket message with string in an unrecognizable format but found {:?}",
                self
            )
        }
    }
    pub fn expect_non_textual_msg(self) -> Message{
        if let Self::WSNonTextual(ws_msg) = self {
            ws_msg
        } else {
            panic!(
                "We expected a generic websocket message but found {:?}",
                self
            )
        }
    }
}

pub type ServerJoinHandle = JoinHandle<workflow_websocket::server::result::Result<()>>;

pub struct MockWebSocketsServerHandle {
    logger: MWSSLogger,
    requests_arc: Arc<Mutex<Vec<MockWSServerRecordedRequest>>>,
    // A use of this join handle should be well-thought. Most of the time, all you need to do is
    // letting the test go to its end which will deconstruct the server as the async runtime dies.
    server_background_thread_join_handle: ServerJoinHandle,
    counters: Arc<WebSocketCounters>,
    server_port: u16,
}

impl MockWebSocketsServerHandle {
    pub async fn retrieve_recorded_requests(
        &self,
        required_msg_count_opt: Option<usize>,
    ) -> Vec<MockWSServerRecordedRequest> {
        let recorded_requests_waiting_start = SystemTime::now();
        let recorded_requests_waiting_hard_limit = Duration::from_millis(2500);
        let obtain_guard = || {
            self.requests_arc
                .lock()
                .unwrap_or_else(|poison_error| poison_error.into_inner())
        };
        loop {
            if let Some(required_msg_count) = required_msg_count_opt {
                let guard_len = obtain_guard().len();
                if required_msg_count > guard_len {
                    if recorded_requests_waiting_start
                        .elapsed()
                        .expect("travelling in time")
                        >= recorded_requests_waiting_hard_limit
                    {
                        panic!("We waited for {} expected requests but the queue contained only {:?} after {} ms timeout", required_msg_count, *obtain_guard(), recorded_requests_waiting_hard_limit.as_millis())
                    } else {
                        let sleep_ms = 50;
                        self.logger.log(
                            &format!("Sleeping {} ms before another attempt to fetch the expected requests", sleep_ms),
                        );
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        continue;
                    }
                }
            }

            self.logger.log(
                "Retrieving recorded requests by the server",
            );

            break obtain_guard().drain(..).collect();
        }
    }

    pub async fn await_conn_established(&self, biased_by_other_connections_opt: Option<usize>) {
        let allowed_parallel_conn = biased_by_other_connections_opt.unwrap_or(0);
        let condition = |counters: &Arc<WebSocketCounters>| {
            (counters.active_connections.load(Ordering::Relaxed) - allowed_parallel_conn) > 0
        };
        self.await_loop(condition).await
    }

    pub async fn await_conn_disconnected(&self, biased_by_other_connections_opt: Option<usize>) {
        let allowed_parallel_conn = biased_by_other_connections_opt.unwrap_or(0);
        let condition = |counters: &Arc<WebSocketCounters>| {
            counters.active_connections.load(Ordering::Relaxed) == (0 + allowed_parallel_conn)
        };
        self.await_loop(condition).await
    }

    async fn await_loop<F>(&self, test_desired_condition: F)
    where
        F: Fn(&Arc<WebSocketCounters>) -> bool,
    {
        let fut = async {
            loop {
                if test_desired_condition(&self.counters) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await
            }
        };
        tokio::time::timeout(Duration::from_millis(5_000), fut)
            .await
            .expect("Timed out waiting for server connection's status change")
    }
}

struct PanickingConn {
    // Deliberate poisoning a Mutex by a panic
    mutex_to_sense_panic: Arc<Mutex<()>>,
}

#[derive(Clone)]
struct MWSSLogger {
    do_log: bool,
    server_idx: u64
}

impl MWSSLogger {
    fn new(do_log: bool)->Self{
        let server_idx= {
            let mut guard = MWSS_INDEX.lock().unwrap();
            let index = *guard;
            *guard += 1;
            index
        };
        Self{
            do_log,
            server_idx
        }
    }

    fn log(&self, msg: &str){
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
        let captured_request = requests.remove(0).expect_masq_msg();
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

        let requests = stop_handle.retrieve_recorded_requests(None).await;

        assert_eq!(
            requests
                .into_iter()
                .map(|x| x.expect_masq_msg())
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
        let conn_join_handle = tokio::spawn(UiConnection::new(port, NODE_UI_PROTOCOL));
        let mut conn = conn_join_handle.await.unwrap().unwrap();
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
    async fn panic_on_connection_stops_server() {
        let test_name = "panic_on_connection_stops_server".to_string();
        let port = find_free_port();
        let mut server = MockWebSocketsServer::new(port);
        let mutex_to_sense_panic = Arc::new(Mutex::new(()));
        server.test_panicking_conn_opt = Some(PanickingConn {
            mutex_to_sense_panic: mutex_to_sense_panic.clone(),
        });

        let stop_handle = server.start().await;

        let _ = tokio::task::spawn(UiConnection::new(port, NODE_UI_PROTOCOL));
        while !mutex_to_sense_panic.is_poisoned() {
            tokio::time::sleep(Duration::from_millis(5)).await
        }
        let _ = stop_handle
            .server_background_thread_join_handle
            .await
            .unwrap();
    }
}
