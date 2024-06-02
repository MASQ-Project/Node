// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::messages::NODE_UI_PROTOCOL;
use crate::ui_gateway::{MessageBody, MessagePath, MessageTarget};
use crate::ui_traffic_converter::UiTrafficConverter;
use crate::utils::localhost;
use crossbeam_channel::{unbounded, Receiver, Sender};
use futures_util::SinkExt;
use lazy_static::lazy_static;
use std::net::SocketAddr;
use std::ops::Not;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use tokio::task;
use workflow_websocket::server::{
    Error, Message, WebSocketHandler, WebSocketReceiver, WebSocketSender, WebSocketServer,
    WebSocketSink,
};
use async_trait::async_trait;
use futures::future::FutureExt;
use tokio::task::{JoinError, JoinHandle};

lazy_static! {
    static ref MWSS_INDEX: Mutex<u64> = Mutex::new(0);
}

struct NodeUiProtocolWebSocketHandler {
    requests_arc: Arc<Mutex<Vec<Result<MessageBody, String>>>>,
    responses_arc: Arc<Mutex<Vec<Message>>>,
    looping_tx: Sender<()>,
    termination_style_rx: Receiver<TerminationStyle>,
    websocket_sink_tx: Sender<WebSocketSink>,
    websocket_sink_rx: Receiver<WebSocketSink>,
    first_f_f_msg_sent_tx_opt: Option<Sender<()>>,
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
        if !kill_flag {
            if let Ok(websocket_sink) = self.websocket_sink_rx.try_recv() {
                websocket_sink.send(Message::Close(None)).unwrap();
            }
            else {
                panic!("Tried to gracefully close the WebSocket connection, but no WebsocketSink was available over which to send the Close")
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
        match self.looping_tx.send(()) {
            Ok(_) => (),
            Err(e) => {
                let msg = format!("MockWebSocketsServerStopHandle died before loop could start: {:?}", e);
                log(self.do_log, self.index, &msg);
                return Err(Error::Other(msg));
            }
        }
        self.handle_all_f_f_messages_introducing_the_queue(sink);
        Ok(())
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
        self.handle_all_f_f_messages_introducing_the_queue(sink);
        log(self.do_log, self.index, "Checking for message from client");
        if let Some(incoming) = self.handle_incoming_msg_raw(msg) {
            log(
                self.do_log,
                self.index,
                &format!("Recording incoming message: {:?}", incoming),
            );
            {
                self.requests_arc.lock().unwrap().push(incoming.clone());
            }
            if let Ok(message_body) = incoming {
                match message_body.path {
                    MessagePath::Conversation(_) => {
                        if self.handle_conversational_incoming_message(sink).not() {
                            return Err(Error::ServerClose); // "disconnect" received
                        }
                    }

                    MessagePath::FireAndForget => {
                        log(
                            self.do_log,
                            self.index,
                            "Responding to FireAndForget message by forgetting",
                        );
                    }
                }
            } else {
                log(
                    self.do_log,
                    self.index,
                    "Going to panic: Unrecognizable form of a text message",
                );
                panic!("Unrecognizable incoming message received; you should refrain from sending some meaningless garbage to the server: {:?}", incoming)
            }
        }
        return Ok(())
    }
}

impl NodeUiProtocolWebSocketHandler {
    fn handle_all_f_f_messages_introducing_the_queue(&self, sink: &WebSocketSink) {
        let mut counter = 0usize;
        loop {
            let should_signal_first_f_f_msg =
                self.first_f_f_msg_sent_tx_opt.is_some() && counter == 1;
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
                                if should_signal_first_f_f_msg {
                                    log(self.do_log, self.index,"Sending a signal between the first two fire-and-forget messages");
                                    self.first_f_f_msg_sent_tx_opt.as_ref().unwrap().send(()).unwrap()
                                }
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

    fn handle_incoming_msg_raw(&self, incoming: Message) -> Option<Result<MessageBody, String>> {
        match incoming {
            Message::Text(json) => {
                log(self.do_log, self.index, &format!("Received '{}'", json));
                Some(match UiTrafficConverter::new_unmarshal_from_ui(&json, 0) {
                    Ok(msg) => Ok(msg.body),
                    Err(_) => Err(json),
                })
            }
            x => {
                log(
                    self.do_log,
                    self.index,
                    &format!("Received unexpected message {:?} - discarding", x),
                );
                Some(Err(format!("{:?}", x)))
            }
        }
    }

    fn handle_conversational_incoming_message(&self, sink: &WebSocketSink) -> bool {
        let mut temporary_access_to_responses = self.responses_arc.lock().unwrap();
        if temporary_access_to_responses.len() != 0 {
            match temporary_access_to_responses.remove(0) {
                Message::Text(outgoing) => {
                    if outgoing == "disconnect" {
                        log(self.do_log, self.index, "Executing 'disconnect' directive");
                        return false;
                    }
                    if outgoing == "close" {
                        log(self.do_log, self.index, "Sending Close message");
                        sink.send(Message::Close(None)).unwrap();
                    } else {
                        log(
                            self.do_log,
                            self.index,
                            &format!("Responding with preset message: '{}'", &outgoing),
                        );
                        sink.send(Message::Text(outgoing)).unwrap();
                    }
                }
                om => {
                    log(
                        self.do_log,
                        self.index,
                        &format!("Responding with preset Message: {:?}", om),
                    );
                    sink.send(om).unwrap()
                }
            }
        } else {
            log(self.do_log, self.index, "Sending Close message");
            sink.send(Message::Binary(b"EMPTY QUEUE".to_vec())).unwrap()
        };
        true
    }

    async fn message(
        self: &Arc<Self>,
        ctx: &(),
        msg: Message,
        sink: &WebSocketSink,
    ) -> workflow_websocket::server::Result<()> {
        todo!()
    }
}

pub struct MockWebSocketsServer {
    do_log: bool,
    port: u16,
    protocol: String,
    responses: Vec<Message>,
    first_f_f_msg_sent_tx_opt: Option<Sender<()>>,
}

impl MockWebSocketsServer {
    pub fn new(port: u16) -> Self {
        Self {
            do_log: false,
            port,
            protocol: NODE_UI_PROTOCOL.to_string(),
            responses: vec![],
            first_f_f_msg_sent_tx_opt: None,
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

    pub fn inject_signal_sender(mut self, sender: Sender<()>) -> Self {
        self.first_f_f_msg_sent_tx_opt = Some(sender);
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
        let requests_arc_inner = requests_arc.clone();
        let (looping_tx, looping_rx) = unbounded();
        let (termination_style_tx, termination_style_rx) = unbounded();
        let (websocket_sink_tx, websocket_sink_rx) = unbounded();

        let handler = NodeUiProtocolWebSocketHandler {
            requests_arc: requests_arc.clone(),
            responses_arc: Arc::new(Mutex::new(self.responses)),
            looping_tx,
            termination_style_rx,
            websocket_sink_tx,
            websocket_sink_rx,
            first_f_f_msg_sent_tx_opt: None, // TODO Probably shouldn't be None. Bert?
            do_log: self.do_log,
            index,
        };
        let server = WebSocketServer::new(Arc::new(handler), None);
        let socket_addr = SocketAddr::new(localhost(), self.port);
        log(
            self.do_log,
            index,
            format!("Listening on: {}", socket_addr).as_str(),
        );
        let static_socket_addr_str: &'static str =
            Box::leak(socket_addr.to_string().into_boxed_str());
        let future = server.listen(static_socket_addr_str, None);
        let join_handle = task::spawn(future);

        MockWebSocketsServerStopHandle {
            index,
            log: self.do_log,
            requests_arc,
            looping_rx,
            termination_style_tx,
            join_handle,
        }
        // let future = async move {
        //     let socket_addr = SocketAddr::new(localhost(), self.port);
        //     let listener = TcpListener::bind(socket_addr).await
        //         .expect(format!("MockWebsocketsServer could not bind to {:?}", socket_addr).as_str());
        //     log(self.do_log, index, format!("Listening on: {}", socket_addr).as_str());
        //     let (stream, peer_addr) = listener.accept().await.unwrap();
        //     log(self.do_log, index, format!("Accepted TCP connection from {}", peer_addr).as_str());
        //
        //     Self::process_connection(
        //         stream,
        //         peer_addr,
        //         requests_arc_inner,
        //         self.responses_arc.clone(),
        //         looping_tx,
        //         stop_rx,
        //         self.first_f_f_msg_sent_tx_opt.clone(),
        //         self.do_log,
        //         index
        //     ).await
        // };
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
}

pub struct MockWebSocketsServerStopHandle {
    index: u64,
    log: bool,
    requests_arc: Arc<Mutex<Vec<Result<MessageBody, String>>>>,
    looping_rx: Receiver<()>,
    termination_style_tx: Sender<TerminationStyle>,
    join_handle: JoinHandle<Result<(), workflow_websocket::server::Error>>,
}

impl MockWebSocketsServerStopHandle {
    pub fn stop(self) -> Vec<Result<MessageBody, String>> {
        self.send_terminate_order(false)
    }

    pub fn kill(self) -> Vec<Result<MessageBody, String>> {
        let result = self.send_terminate_order(true);
        thread::sleep(Duration::from_millis(150));
        result
    }

    fn send_terminate_order(self, kill: bool) -> Vec<Result<MessageBody, String>> {
        match self.looping_rx.try_recv() {
            Ok(_) => {
                log(
                    self.log,
                    self.index,
                    &format!(
                        "Sending terminate order with kill = {} to running background thread",
                        kill
                    ),
                );
                self.termination_style_tx.send(if kill {
                    TerminationStyle::Kill
                } else {
                    TerminationStyle::Stop
                }).unwrap();
                log(self.log, self.index, "Joining background thread");
                self.join_handle.abort();
                log(
                    self.log,
                    self.index,
                    "Background thread joined; retrieving recording",
                );
                let guard = match self.requests_arc.lock() {
                    Ok(guard) => guard,
                    Err(poison_error) => poison_error.into_inner(),
                };
                (*guard).clone()
            }
            Err(_) => {
                log(
                    self.log,
                    self.index,
                    "Background thread is stuck and can't be terminated; leaking it",
                );
                vec![]
            }
        }
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
    Kill
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
        let server = MockWebSocketsServer::new(port)
            .queue_response(conversation_number_one_response.clone().tmb(1))
            .queue_response(conversation_number_two_response.clone().tmb(2))
            .queue_response(broadcast_number_one)
            .queue_response(broadcast_number_two)
            .queue_response(conversation_number_three_response)
            .queue_response(broadcast_number_three);
        let stop_handle = server.start().await;
        let mut connection = UiConnection::new(port, NODE_UI_PROTOCOL).await.unwrap();

        let received_message_number_one: UiCheckPasswordResponse = connection
            .transact_with_context_id(conversation_number_one_request.clone(), 1)
            .await
            .unwrap();
        assert_eq!(
            received_message_number_one.matches,
            conversation_number_one_response.matches
        );

        let received_message_number_two: UiCheckPasswordResponse = connection
            .transact_with_context_id(conversation_number_two_request.clone(), 2)
            .await
            .unwrap();
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
        let encapsulated_panic =
            std::panic::AssertUnwindSafe(async {
                connection
                    .transact::<UiChangePasswordRequest, UiChangePasswordResponse>(conversation_request)
                    .await
                    .unwrap();
            }).catch_unwind().await;

        stop_handle.stop();
        let panic_err = encapsulated_panic
            .unwrap_err();
        let panic_message = panic_err.downcast_ref::<&str>()
            .unwrap();
        assert_eq!(*panic_message, "The queue is empty; all messages are gone.")
    }
}
