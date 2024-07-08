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
use std::time::{Duration, Instant, SystemTime};
use tokio::{select, task};
use std::str::FromStr;
use clap::ArgAction;
use tokio::runtime::Runtime;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use tokio::task::{JoinHandle, spawn_blocking};
use workflow_websocket::server::error::Error as WebsocketServerError;
use workflow_websocket::server::{Error, Message, WebSocketConfig, WebSocketHandler, WebSocketReceiver, WebSocketSender, WebSocketServer, WebSocketServerTrait, WebSocketSink};
use crate::test_utils::utils::make_rt;

lazy_static! {
    static ref MWSS_INDEX: Mutex<u64> = Mutex::new(0);
}

struct NodeUiProtocolWebSocketHandler {
    requests_arc: Arc<Mutex<Vec<MockWSServerRecordedRequest>>>,
    responses_arc: Arc<Mutex<Vec<Message>>>,
    termination_style_rx: Receiver<TerminationStyle>,
    websocket_sink_tx: Sender<WebSocketSink>,
    websocket_sink_rx: Receiver<WebSocketSink>,
    connections_status: Arc<tokio::sync::Mutex<ConnectionStatus>>,
    opening_broadcasts_signal_rx_opt: Mutex<Option<tokio::sync::oneshot::Receiver<()>>>,
    do_log: bool,
    index: u64,
}

impl Drop for NodeUiProtocolWebSocketHandler {
    fn drop(&mut self) {
        let termination_style = self.termination_style_rx.try_recv();
        let kill_flag = match termination_style {
            Ok(TerminationStyle::Kill) => true,
            _ => false,
        };
        let latest_connection_status = self.connections_status.clone();
        let do_log = self.do_log;
        let index = self.index;

        tokio::task::spawn( async move {
            if kill_flag {
                log(
                    do_log,
                    index,
                    "Setting the connection status that server is killed from an outer directive",
                );
                MockWebSocketsServer::announce_killed_status(latest_connection_status).await
            } else if matches!(*latest_connection_status.lock().await, ConnectionStatus::Connected(..)) {
                log(
                    do_log,
                    index,
                    "Server's disconnect function hasn't been called, fixing status during drop",
                );
                MockWebSocketsServer::switch_connection_status(&latest_connection_status).await;
            }
        });

        if !kill_flag {
            if let Ok(websocket_sink) = self.websocket_sink_rx.try_recv() {
                let _ = websocket_sink.send(Message::Close(None));
            } else {
                eprintln!(
                    "No WebSocket connection has been initialized in the server's session, \
                    Close cannot be, and what more, does't need to be signalized."
                )
            }
        }
    }
}

#[async_trait]
impl WebSocketHandler for NodeUiProtocolWebSocketHandler {
    type Context = ();

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
            format!("Accepted TCP connection from {}", peer).as_str(),
        );
        self.websocket_sink_tx.send(sink.clone()).unwrap();

        // TODO Real handshake stuff, if any, goes here

        log(
            self.do_log,
            self.index,
            "Checking for initial fire-and-forget messages",
        );
        self.handle_opening_broadcasts(sink);
        MockWebSocketsServer::switch_connection_status(&self.connections_status).await;
        eprintln!("After change: {:?}", self.connections_status.lock().await);
        Ok(())
    }

    async fn disconnect(self: &Arc<Self>, _ctx: Self::Context, _result: workflow_websocket::server::Result<()>) {
        MockWebSocketsServer::switch_connection_status(&self.connections_status).await;
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

        let cash_for_panic_opt = self.record_incomming_msg(
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
                    meaningless garbage to the server: {:?}",
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

    fn record_incomming_msg(
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
        let (termination_style_tx, termination_style_rx) = unbounded();
        let (server_shutdown_tx, mut server_shutdown_rx) = unbounded_channel();
        let (websocket_sink_tx, websocket_sink_rx) = unbounded();
        let connection_status = Arc::new(tokio::sync::Mutex::new(ConnectionStatus::Disconnected(0)));

        let handler = NodeUiProtocolWebSocketHandler {
            requests_arc: requests_arc.clone(),
            responses_arc: Arc::new(Mutex::new(self.responses)),
            termination_style_rx,
            websocket_sink_tx,
            websocket_sink_rx,
            connections_status: connection_status.clone(),
            opening_broadcasts_signal_rx_opt: Mutex::new(self.opening_broadcast_signal_rx_opt),
            do_log: self.do_log,
            index,
        };

        let ws_server = WebSocketServer::new(Arc::new(handler), None);
        let socket_addr = SocketAddr::new(localhost(), self.port);
        log(
            self.do_log,
            index,
            format!("Listening on: {}", socket_addr).as_str(),
        );
        let static_socket_addr_str: &'static str = Box::leak(socket_addr.to_string().into_boxed_str());
        let server_task = ws_server.listen(static_socket_addr_str, None);
        let join_handle = task::spawn(async move {
                select! {
                    res = server_task => {
                        log(
                            self.do_log,
                            index,
                            "Server's task completed unexpectedly",
                        );
                        res
                    },
                    _ = server_shutdown_rx.recv() => {
                        log(
                            self.do_log,
                            index,
                            "Received a shutdown order. Dumping the server's task",
                        );
                        Ok(())
                    }
                }
            }
        );

        MockWebSocketsServerStopHandle {
            index,
            log: self.do_log,
            requests_arc,
            connection_status,
            termination_style_tx,
            server_shutdown_tx,
            // join_handle_opt: Some(join_handle),
        }
    }

    // async fn process_connection(
    //     stream: TcpStream,
    //     peer_addr: SocketAddr,
    //     requests_arc: Arc<Mutex<Vec<Result<MessageBody, String>>>>,
    //     responses_arc: Arc<Mutex<Vec<Message>>>,
    //     looping_tx: Sender<()>,
    //     stop_rx: Receiver<bool>,
    //     first_f_f_msg_sent_tx_opt: Option<Sender<()>>,
    //     do_log: bool,
    //     index: u64,
    // ) {
    //     let ws_connection = tokio_tungstenite::accept_hdr_async(
    //         stream,
    //         AcceptHdrCallback::new(/* TODO Put something here */)
    //     ).await.unwrap();
    //     log(do_log, index, format!("New WebSocket connection from: {}", peer_addr).as_str());
    //     let (ws_transmitter_sink, mut ws_receiver) = ws_connection.split();
    //     let ws_transmitter = ws_transmitter_sink.with(|item| async { Ok(item) });
    //     pin!(ws_transmitter);
    //     log(do_log, index, "Entering background loop");
    //     match looping_tx.send(()) {
    //         Ok(_) => (),
    //         Err(e) => {
    //             log(do_log, index, &format!("MockWebSocketsServerStopHandle died before loop could start: {:?}", e));
    //             return;
    //         }
    //     }
    //     loop {
    //         log(do_log, index, "Checking for fire-and-forget messages");
    //         Self::handle_all_f_f_messages_introducing_the_queue(
    //             first_f_f_msg_sent_tx_opt.clone(),
    //             &mut ws_transmitter,
    //             &responses_arc.clone(),
    //             index,
    //             do_log,
    //         ).await;
    //         log(do_log, index, "Checking for message from client");
    //         if let Some(incoming) =
    //             Self::handle_incoming_msg_raw(ws_receiver.next().await, do_log, index)
    //         {
    //             log(
    //                 do_log,
    //                 index,
    //                 &format!("Recording incoming message: {:?}", incoming),
    //             );
    //             {
    //                 requests_arc.lock().unwrap().push(incoming.clone());
    //             }
    //             if let Ok(message_body) = incoming {
    //                 match message_body.path {
    //                     MessagePath::Conversation(_) => {
    //                         if Self::handle_conversational_incoming_message(
    //                             &mut ws_transmitter,
    //                             &responses_arc.clone(),
    //                             index,
    //                             do_log,
    //                         ).await.not() {
    //                             break; //"disconnect" received
    //                         }
    //                     }
    //
    //                     MessagePath::FireAndForget => {
    //                         log(
    //                             do_log,
    //                             index,
    //                             "Responding to FireAndForget message by forgetting",
    //                         );
    //                     }
    //                 }
    //             } else {
    //                 log(
    //                     do_log,
    //                     index,
    //                     "Going to panic: Unrecognizable form of a text message",
    //                 );
    //                 panic!("Unrecognizable incoming message received; you should refrain from sending some meaningless garbage to the server: {:?}", incoming)
    //             }
    //         }
    //         log(do_log, index, "Checking for termination directive");
    //         if let Ok(kill) = stop_rx.try_recv() {
    //             log(
    //                 do_log,
    //                 index,
    //                 &format!("Received termination directive with kill = {}", kill),
    //             );
    //             if !kill {
    //                 ws_transmitter.send(Message::Close(None)).await.unwrap();
    //             }
    //             break;
    //         }
    //         log(
    //             do_log,
    //             index,
    //             "No termination directive. Sleeping for 50ms before the next iteration",
    //         );
    //         thread::sleep(Duration::from_millis(50))
    //     }
    //     log(do_log, index, "Connection-handling future completed");
    // }

    // async fn handle_all_f_f_messages_introducing_the_queue<S>(
    //     first_f_f_msg_sent_tx_opt: Option<Sender<()>>,
    //     ws_transmitter: &mut S,
    //     inner_responses_arc: &Arc<Mutex<Vec<Message>>>,
    //     index: u64,
    //     do_log: bool,
    // ) where S: SinkExt<Message, Error=Error> + Unpin
    // {
    //     let mut counter = 0usize;
    //     let mut inner_responses_vec = inner_responses_arc.lock().unwrap();
    //     loop {
    //         let should_signal_first_f_f_msg = first_f_f_msg_sent_tx_opt.is_some() && counter == 1;
    //         if inner_responses_vec.is_empty() {
    //             break;
    //         }
    //         let temporarily_owned_possible_f_f = inner_responses_vec.remove(0);
    //         if match &temporarily_owned_possible_f_f {
    //             Message::Text(text) =>
    //                 match UiTrafficConverter::new_unmarshal_to_ui(text, MessageTarget::AllClients)
    //                 {
    //                     Ok(msg) => match msg.body.path {
    //                         MessagePath::FireAndForget => {
    //                             if should_signal_first_f_f_msg {
    //                                 log(do_log,index,"Sending a signal between the first two fire-and-forget messages");
    //                                 first_f_f_msg_sent_tx_opt.as_ref().unwrap().send(()).unwrap()
    //                             }
    //                             let f_f_message = temporarily_owned_possible_f_f.clone();
    //                             ws_transmitter.send(f_f_message).await;
    //                             log(do_log, index, "Sending a fire-and-forget message to the UI");
    //                             true
    //                         }
    //                         _ => false
    //                     }
    //                     _ => false
    //                 }
    //             _ => false
    //         }.not() {
    //             inner_responses_vec.insert(0, temporarily_owned_possible_f_f);
    //             log(do_log, index, "No fire-and-forget message found; heading over to conversational messages");
    //             break
    //         }
    //         thread::sleep(Duration::from_millis(1));
    //         counter += 1;
    //         //for true, we keep looping
    //     }
    // }

    //     async fn handle_conversational_incoming_message<S>(
    //         ws_transmitter: &mut S,
    //         inner_responses_arc: &Arc<Mutex<Vec<Message>>>,
    //         index: u64,
    //         do_log: bool,
    //     ) -> bool where S: SinkExt<Message, Error=Error> + Unpin
    //     {
    //         let mut temporary_access_to_inner_responses_arc = inner_responses_arc.lock().unwrap();
    //         if temporary_access_to_inner_responses_arc.len() != 0 {
    //             match temporary_access_to_inner_responses_arc.remove(0) {
    //                 Message::Text(outgoing) => {
    //                     if outgoing == "disconnect" {
    //                         log(do_log, index, "Executing 'disconnect' directive");
    //                         return false;
    //                     }
    //                     if outgoing == "close" {
    //                         log(do_log, index, "Sending Close message");
    //                         ws_transmitter.send(Message::Close(None)).await.unwrap();
    //                     } else {
    //                         log(
    //                             do_log,
    //                             index,
    //                             &format!("Responding with preset message: '{}'", &outgoing),
    //                         );
    //                         ws_transmitter.send(Message::Text(outgoing)).await.unwrap();
    //                     }
    //                 }
    //                 om => {
    //                     log(
    //                         do_log,
    //                         index,
    //                         &format!("Responding with preset Message: {:?}", om),
    //                     );
    //                     ws_transmitter.send(om).await.unwrap()
    //                 }
    //             }
    //         } else {
    //             log(do_log, index, "Sending Close message");
    //             ws_transmitter
    //                 .send(Message::Binary(b"EMPTY QUEUE".to_vec()))
    //                 .await
    //                 .unwrap()
    //         };
    //         true
    //     }
    async fn switch_connection_status(storage: &Arc<tokio::sync::Mutex<ConnectionStatus>>){
        let mut current = storage.lock().await;
        let new = current.switched();
        let _ = mem::replace(current.deref_mut(), new);
    }

    async fn announce_killed_status(local_storage_to_drop_after: Arc<tokio::sync::Mutex<ConnectionStatus>>){
        let mut current = local_storage_to_drop_after.lock().await;
        let _ = mem::replace(current.deref_mut(), ConnectionStatus::ServerKilledFromOuterDirective);
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
    termination_style_tx: Sender<TerminationStyle>,
    server_shutdown_tx: UnboundedSender<()>,
    connection_status: Arc<tokio::sync::Mutex<ConnectionStatus>>,
    // join_handle_opt: Option<JoinHandle<Result<(), workflow_websocket::server::Error>>>,
}

impl MockWebSocketsServerStopHandle {
    pub async fn stop(self, time_granted_for_conn_establishment_opt: Option<Duration>, min_count_of_awaited_requests_opt: Option<usize>) -> Vec<MockWSServerRecordedRequest> {
        self.send_terminate_order(false, time_granted_for_conn_establishment_opt, min_count_of_awaited_requests_opt.unwrap_or(0)).await
    }

    pub async fn kill(self, min_count_of_awaited_requests_opt: Option<usize>) -> Vec<MockWSServerRecordedRequest> {
        let result = self.send_terminate_order(true, None, min_count_of_awaited_requests_opt.unwrap_or(0)).await;
        result
    }

    async fn send_terminate_order(
        mut self,
        kill: bool,
        time_granted_for_conn_establishment_opt: Option<Duration>,
        awaited_count_of_handled_msgs: usize
    ) -> Vec<MockWSServerRecordedRequest> {
        // Unfortunately, the used library and the tokio frimewark don't allow much about controlling
        // the spawned server to such a level that we could politely shut down the server and still
        // not to close the connection with waving a farwell to the distant client, and ideally to
        // join the finished task. If We want to be able to kill it from here, this is a problem.
        // (The future with the server refused to complite immediately even when we tried calling
        // 'abort()' on its handle. The 'stop_and_join()' method belonging to the server disappointed
        // by its effectiveness constrained only to running a server with all connections already
        // disconnected - an active one would keep it from reaching the directive)
        let start = Instant::now();
        let hard_limit = time_granted_for_conn_establishment_opt.unwrap_or(Duration::from_millis(0));
        let requests = loop {
            let connection_status = {
                *self.connection_status.lock().await
            };
            match connection_status {
                ConnectionStatus::Connected(..) => {
                    log(
                        self.log,
                        self.index,
                        &format!(
                            "Sending terminate order with kill = {} to running background thread",
                            kill
                        ),
                    );
                    let terminataion_msg = if kill {
                        TerminationStyle::Kill
                    } else {
                        TerminationStyle::Stop
                    };
                    self.termination_style_tx
                        .send(terminataion_msg)
                        .unwrap();
                    log(self.log, self.index, "Joining background thread");

                    break self.await_all_msgs_to_be_handled(awaited_count_of_handled_msgs).await
                },
                ConnectionStatus::Disconnected(..) => {
                    if start.elapsed() < hard_limit {
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    } else {
                        log(
                            self.log,
                            self.index,
                            "Processing termination order, but Websockects already \
                            disconnected. Proceeding to shut down the server wholly",
                        );
                        self.server_shutdown_tx.send(()).expect("Failed to send a shutdown order to the server");
                        break vec![]
                    }
                }
                ConnectionStatus::ServerKilledFromOuterDirective => {
                    log(
                        self.log,
                        self.index,
                        "Server already killed, no need to kick the horse's dead body",
                    );
                }
            }
        };

        self.await_disconnection().await;

        requests
    }

    async fn await_all_msgs_to_be_handled(&mut self, awaited_msg_count: usize)-> Vec<MockWSServerRecordedRequest>{
        let obtain_guard = ||match self.requests_arc.lock() {
            Ok(guard) => guard,
            Err(poison_error) => poison_error.into_inner(),
        };

        log(
            self.log,
            self.index,
            "Waiting for expected number of received requests",
        );
        let recorded_requests_waiting_start = SystemTime::now();
        let recorded_requests_waiting_hard_limit = Duration::from_millis(2500);
        while obtain_guard().len() < awaited_msg_count {
            if recorded_requests_waiting_start.elapsed().expect("travelling in time") >= recorded_requests_waiting_hard_limit {
                panic!("We waited for all expected requests but they weren't receieved even after {} ms", recorded_requests_waiting_hard_limit.as_millis())
            }
            tokio::time::sleep(Duration::from_millis(50)).await
        }
        let waiting_for_joining_the_server_task_hard_limit = Duration::from_millis(2500);
        self.server_shutdown_tx.send(()).expect("sending server shutdown order failed");
        // self.join_handle_opt.take().expect("join handle should be present").await;
        // tokio::time::timeout(waiting_for_joining_the_server_task_hard_limit, self.join_handle).await
        //     .unwrap_or_else(|_|panic!("Timed out after {} waiting for joining the stopped server", waiting_for_joining_the_server_task_hard_limit.as_millis()));
            log(
                self.log,
                self.index,
                "Background thread joined; retrieving recording",
            );

        (*obtain_guard()).clone()
    }

    pub async fn await_conn_established(&self){
        self.await_loop(|read_conn_status|matches!(read_conn_status, ConnectionStatus::Connected(..))).await
    }

    pub async fn await_disconnection(&self){
        self.await_loop(|read_conn_status|matches!(read_conn_status, ConnectionStatus::Disconnected(..))).await
    }

    async fn await_loop<F>(&self, test_desired_condition: F) where F: Fn(ConnectionStatus)->bool{
        let status_clone = self.connection_status.clone();
        let fut = async {
            loop {
                let status = *status_clone.lock().await;
                eprintln!("trying again: {:?}", status);
                tokio::time::sleep(Duration::from_millis(100)).await
            }
        };
        tokio::time::timeout(Duration::from_millis(5_000), fut).await.expect("Timed out waiting for server connection's status change")
    }

    // pub fn is_terminated(&self) -> bool {
    //     self.join_handle_opt.is_finished()
    // }

    async fn connection_status(&self)->ConnectionStatus{
        let status = *self.connection_status.lock().await;
        eprintln!("status: {:?}", status);
        status
    }
}

// TODO: This should really be an object, not a function, and the object should hold do_log and index.
fn log(do_log: bool, index: u64, msg: &str) {
    if do_log {
        eprintln!("MockWebSocketsServer {}: {}", index, msg);
    }
}

enum TerminationStyle {
    Stop,
    Kill,
}

#[derive(Copy, Clone, Debug)]
pub enum ConnectionStatus{
    // The additional number always signifies the number of prior connections that have been
    // established
    Disconnected(usize),
    Connected(usize),
    ServerKilledFromOuterDirective
}

impl ConnectionStatus{
    fn switched(&self)->Self{
        match self {
            ConnectionStatus::Disconnected(connections_already_established) => {
                ConnectionStatus::Connected(*connections_already_established + 1)
            },
            ConnectionStatus::Connected(connections_already_established) => {
                ConnectionStatus::Disconnected(*connections_already_established)
            },
            x => panic!("Switched doesn't suite {:?}", x)
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

        let requests = stop_handle.stop();
        let actual_message_gotten_by_the_server =
            UiCheckPasswordRequest::fmb(requests[0].clone().unwrap())
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

        let requests = stop_handle.stop();

        assert_eq!(
            requests
                .into_iter()
                .flat_map(|x| x)
                .collect::<Vec<MessageBody>>(),
            vec![
                conversation_number_one_request.tmb(1),
                conversation_number_two_request.tmb(2),
                conversation_number_three_request.tmb(3)
            ]
        )
    }

    #[tokio::test]
    async fn attempt_to_get_a_message_from_an_empty_queue_causes_a_panic() {
        let port = find_free_port();
        let server = MockWebSocketsServer::new(port);
        let stop_handle = server.start().await;
        let mut connection = UiConnection::new(port, NODE_UI_PROTOCOL).await.unwrap();
        let conversation_request = UiChangePasswordRequest {
            old_password_opt: None,
            new_password: "password".to_string(),
        };

        //catch_unwind so that we have a chance to shut down the server manually, not letting its thread leak away
        let encapsulated_panic = std::panic::AssertUnwindSafe(async {
            connection
                .transact::<UiChangePasswordRequest, UiChangePasswordResponse>(conversation_request)
                .await
                .unwrap();
        })
        .catch_unwind()
        .await;

        stop_handle.stop();
        let panic_err = encapsulated_panic.unwrap_err();
        let panic_message = panic_err.downcast_ref::<&str>().unwrap();
        assert_eq!(*panic_message, "The queue is empty; all messages are gone.")
    }

    #[test]
    fn switch_status_works(){
        let first = ConnectionStatus::Connected(3);
        let storage_handle = Arc::new(Mutex::new(first));

        MockWebSocketsServer::switch_connection_status(&storage_handle);
        let second = *storage_handle.lock().unwrap();
        MockWebSocketsServer::switch_connection_status(&second);
        let third = *storage_handle.lock().unwrap();

        assert_eq!(second, ConnectionStatus::Disconnected(3));
        assert_eq!(third, ConnectionStatus::Connected(4))
    }
}
