// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::messages::NODE_UI_PROTOCOL;
use crate::ui_gateway::{MessageBody, MessagePath, MessageTarget};
use crate::ui_traffic_converter::UiTrafficConverter;
use crate::utils::localhost;
use crossbeam_channel::{unbounded, Receiver, Sender};
use lazy_static::lazy_static;
use std::cell::RefCell;
use std::net::SocketAddr;
use std::net::TcpStream;
use std::ops::Not;
use std::sync::{Arc, Mutex};
use std::thread;
use std::thread::JoinHandle;
use std::time::Duration;
use websocket::result::WebSocketError;
use websocket::sync::{Client, Server};
use websocket::{OwnedMessage, WebSocketResult};

lazy_static! {
    static ref MWSS_INDEX: Mutex<u64> = Mutex::new(0);
}

pub struct MockWebSocketsServer {
    log: bool,
    port: u16,
    pub protocol: String,
    responses_arc: Arc<Mutex<Vec<OwnedMessage>>>,
    signal_sender: RefCell<Option<Sender<()>>>,
}

pub struct MockWebSocketsServerStopHandle {
    index: u64,
    log: bool,
    requests_arc: Arc<Mutex<Vec<Result<MessageBody, String>>>>,
    looping_rx: Receiver<()>,
    stop_tx: Sender<bool>,
    join_handle: JoinHandle<()>,
}

impl MockWebSocketsServer {
    pub fn new(port: u16) -> Self {
        Self {
            log: false,
            port,
            protocol: NODE_UI_PROTOCOL.to_string(),
            responses_arc: Arc::new(Mutex::new(vec![])),
            signal_sender: RefCell::new(None),
        }
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn queue_response(self, message: MessageBody) -> Self {
        self.queue_string(&UiTrafficConverter::new_marshal(message))
    }

    pub fn queue_string(self, string: &str) -> Self {
        self.queue_owned_message(OwnedMessage::Text(string.to_string()))
    }

    pub fn queue_owned_message(self, msg: OwnedMessage) -> Self {
        self.responses_arc.lock().unwrap().push(msg);
        self
    }

    pub fn inject_signal_sender(self, sender: Sender<()>) -> Self {
        self.signal_sender.replace(Some(sender));
        self
    }

    pub fn write_logs(mut self) -> Self {
        self.log = true;
        self
    }

    pub fn start(self) -> MockWebSocketsServerStopHandle {
        let index = {
            let mut guard = MWSS_INDEX.lock().unwrap();
            let index = *guard;
            *guard += 1;
            index
        };
        let server_arc = Arc::new(Mutex::new(
            Server::bind(SocketAddr::new(localhost(), self.port)).unwrap(),
        ));
        let requests_arc = Arc::new(Mutex::new(vec![]));
        let inner_requests_arc = requests_arc.clone();
        let inner_responses_arc = self.responses_arc.clone();
        let stop_pair: (Sender<bool>, Receiver<bool>) = unbounded();
        let (stop_tx, stop_rx) = stop_pair;
        let (ready_tx, ready_rx) = unbounded();
        let (looping_tx, looping_rx) = unbounded();
        let do_log = self.log;
        log(do_log, index, "Starting background thread");
        let join_handle = thread::spawn(move || {
            let mut server = server_arc.lock().unwrap();
            let mut requests = inner_requests_arc.lock().unwrap();
            ready_tx.send(()).unwrap();
            log(do_log, index, "Waiting for upgrade");
            let upgrade = server.accept().unwrap();
            if upgrade.protocols().iter().all(|p| *p != self.protocol) {
                panic!("Unrecognized protocol(s): {:?}", upgrade.protocols())
            }
            log(do_log, index, "Waiting for handshake");
            let mut client = upgrade.accept().unwrap();
            client.set_nonblocking(true).unwrap();
            match looping_tx.send(()) {
                Ok(_) => (),
                Err(e) => {
                    log(
                        do_log,
                        index,
                        &format!(
                            "MockWebSocketsServerStopHandle died before loop could start: {:?}",
                            e
                        ),
                    );
                    return;
                }
            }
            log(do_log, index, "Entering background loop");
            loop {
                log(do_log, index, "Checking for fire-and-forget messages");
                self.handle_all_f_f_messages_introducing_the_queue(
                    &mut client,
                    &inner_responses_arc,
                    index,
                    do_log,
                );
                log(do_log, index, "Checking for message from client");
                if let Some(incoming) =
                    Self::handle_incoming_msg_raw(client.recv_message(), do_log, index)
                {
                    log(
                        do_log,
                        index,
                        &format!("Recording incoming message: {:?}", incoming),
                    );
                    requests.push(incoming.clone());
                    if let Ok(message_body) = incoming {
                        match message_body.path {
                            MessagePath::Conversation(_) => {
                                if Self::handle_conversational_incoming_message(
                                    &mut client,
                                    &inner_responses_arc,
                                    index,
                                    do_log,
                                )
                                .not()
                                {
                                    break; //"disconnect" received
                                }
                            }

                            MessagePath::FireAndForget => {
                                log(
                                    do_log,
                                    index,
                                    "Responding to FireAndForget message by forgetting",
                                );
                            }
                        }
                    } else {
                        log(
                            do_log,
                            index,
                            "Going to panic: Unrecognizable form of a text message",
                        );
                        panic!("Unrecognizable incoming message received; you should refrain from sending some meaningless garbage to the server: {:?}", incoming)
                    }
                }
                log(do_log, index, "Checking for termination directive");
                if let Ok(kill) = stop_rx.try_recv() {
                    log(
                        do_log,
                        index,
                        &format!("Received termination directive with kill = {}", kill),
                    );
                    if !kill {
                        client.send_message(&OwnedMessage::Close(None)).unwrap();
                    }
                    break;
                }
                log(
                    do_log,
                    index,
                    "No termination directive. Sleeping for 50ms before the next iteration",
                );
                thread::sleep(Duration::from_millis(50))
            }
            log(do_log, index, "Background thread terminated");
        });
        ready_rx.recv().unwrap();
        thread::sleep(Duration::from_millis(250));
        MockWebSocketsServerStopHandle {
            index,
            log: do_log,
            requests_arc,
            looping_rx,
            stop_tx,
            join_handle,
        }
    }

    fn handle_incoming_msg_raw(
        incoming: WebSocketResult<OwnedMessage>,
        do_log: bool,
        index: u64,
    ) -> Option<Result<MessageBody, String>> {
        match incoming {
            Err(WebSocketError::NoDataAvailable) => {
                log(do_log, index, "No data available");
                None
            }
            Err(WebSocketError::IoError(e)) if e.kind() == std::io::ErrorKind::WouldBlock => {
                log(do_log, index, "No message waiting");
                None
            }
            Err(e) => Some(Err(format!("Error serving WebSocket: {:?}", e))),
            Ok(OwnedMessage::Text(json)) => {
                log(do_log, index, &format!("Received '{}'", json));
                Some(match UiTrafficConverter::new_unmarshal_from_ui(&json, 0) {
                    Ok(msg) => Ok(msg.body),
                    Err(_) => Err(json),
                })
            }
            Ok(x) => {
                log(do_log, index, &format!("Received {:?}", x));
                Some(Err(format!("{:?}", x)))
            }
        }
    }

    fn handle_all_f_f_messages_introducing_the_queue(
        &self,
        client: &mut Client<TcpStream>,
        inner_responses_arc: &Arc<Mutex<Vec<OwnedMessage>>>,
        index: u64,
        do_log: bool,
    ) {
        let mut counter = 0usize;
        let sender_opt = self.signal_sender.clone().take();
        loop {
            let signalization_required = sender_opt.is_some() && counter == 1;
            let mut inner_responses_vec = inner_responses_arc.lock().unwrap();
            if inner_responses_vec.is_empty() {
                break;
            }
            let temporarily_owned = inner_responses_vec.remove(0);
            if match &temporarily_owned {
                OwnedMessage::Text(text) =>
                    match UiTrafficConverter::new_unmarshal_to_ui(text, MessageTarget::AllClients)
                    {
                        Ok(msg) => match msg.body.path {
                            MessagePath::FireAndForget => {
                                if signalization_required {
                                    log(do_log,index,"Sending a signal between the first two fire-and-forget messages");
                                    sender_opt.as_ref().unwrap().send(()).unwrap()
                                }
                                client.send_message(&temporarily_owned).unwrap();
                                log(do_log, index, "Sending a fire-and-forget message to the UI");
                                true
                            }
                            _ => false
                        }
                        _ => false
                    }
                _ => false
            }.not() {
                inner_responses_vec.insert(0, temporarily_owned);
                log(do_log, index, "No fire-and-forget message found; heading over to conversational messages");
                break
            }
            thread::sleep(Duration::from_millis(1));
            counter += 1;
            //for true, we keep looping
        }
    }

    fn handle_conversational_incoming_message(
        client: &mut Client<TcpStream>,
        inner_responses_arc: &Arc<Mutex<Vec<OwnedMessage>>>,
        index: u64,
        do_log: bool,
    ) -> bool {
        let mut temporary_access_to_inner_responses_arc = inner_responses_arc.lock().unwrap();
        if temporary_access_to_inner_responses_arc.len() != 0 {
            match temporary_access_to_inner_responses_arc.remove(0) {
                OwnedMessage::Text(outgoing) => {
                    if outgoing == "disconnect" {
                        log(do_log, index, "Executing 'disconnect' directive");
                        return false;
                    }
                    if outgoing == "close" {
                        log(do_log, index, "Sending Close message");
                        client.send_message(&OwnedMessage::Close(None)).unwrap();
                    } else {
                        log(
                            do_log,
                            index,
                            &format!("Responding with preset message: '{}'", &outgoing),
                        );
                        client.send_message(&OwnedMessage::Text(outgoing)).unwrap()
                    }
                }
                om => {
                    log(
                        do_log,
                        index,
                        &format!("Responding with preset OwnedMessage: {:?}", om),
                    );
                    client.send_message(&om).unwrap()
                }
            }
        } else {
            log(do_log, index, "Sending Close message");
            client
                .send_message(&OwnedMessage::Binary(b"EMPTY QUEUE".to_vec()))
                .unwrap()
        };
        true
    }
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
                let _ = self.stop_tx.send(kill);
                log(self.log, self.index, "Joining background thread");
                let _ = self.join_handle.join();
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

fn log(log: bool, index: u64, msg: &str) {
    if log {
        eprintln!("MockWebSocketsServer {}: {}", index, msg);
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
    use std::panic::{catch_unwind, AssertUnwindSafe};

    #[test]
    fn conversational_communication_happy_path_with_full_assertion() {
        let port = find_free_port();
        let expected_response = UiCheckPasswordResponse { matches: false };
        let stop_handle = MockWebSocketsServer::new(port)
            .queue_response(expected_response.clone().tmb(123))
            .start();
        let mut connection = UiConnection::new(port, NODE_UI_PROTOCOL);
        let request = UiCheckPasswordRequest {
            db_password_opt: None,
        };

        let actual_response: UiCheckPasswordResponse = connection
            .transact_with_context_id(request.clone(), 123)
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

    #[test]
    fn conversational_and_broadcast_messages_work_together() {
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
        let stop_handle = server.start();
        let mut connection = UiConnection::new(port, NODE_UI_PROTOCOL);

        let received_message_number_one: UiCheckPasswordResponse = connection
            .transact_with_context_id(conversation_number_one_request.clone(), 1)
            .unwrap();
        assert_eq!(
            received_message_number_one.matches,
            conversation_number_one_response.matches
        );

        let received_message_number_two: UiCheckPasswordResponse = connection
            .transact_with_context_id(conversation_number_two_request.clone(), 2)
            .unwrap();
        assert_eq!(
            received_message_number_two.matches,
            conversation_number_two_response.matches
        );

        let _received_message_number_three: UiConfigurationChangedBroadcast =
            connection.skip_until_received().unwrap();

        let _received_message_number_four: UiNodeCrashedBroadcast =
            connection.skip_until_received().unwrap();

        let received_message_number_five: UiDescriptorResponse = connection
            .transact_with_context_id(conversation_number_three_request.clone(), 3)
            .unwrap();
        assert_eq!(
            received_message_number_five.node_descriptor_opt,
            Some("ae15fe6".to_string())
        );

        let _received_message_number_six: UiNewPasswordBroadcast =
            connection.skip_until_received().unwrap();

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

    #[test]
    fn attempt_to_get_a_message_from_an_empty_queue_causes_a_panic() {
        let port = find_free_port();
        let server = MockWebSocketsServer::new(port);
        let stop_handle = server.start();
        let mut connection = UiConnection::new(port, NODE_UI_PROTOCOL);
        let conversation_request = UiChangePasswordRequest {
            old_password_opt: None,
            new_password: "password".to_string(),
        };

        //catch_unwind so that we have a chance to shut down the server manually, not letting its thread leak away
        let encapsulated_panic: Result<
            Result<UiChangePasswordResponse, (u64, std::string::String)>,
            Box<dyn std::any::Any + Send>,
        > = catch_unwind(AssertUnwindSafe(|| {
            connection.transact(conversation_request)
        }));

        stop_handle.stop();
        let panic_message = *encapsulated_panic
            .unwrap_err()
            .downcast_ref::<&str>()
            .unwrap();
        assert_eq!(panic_message, "The queue is empty; all messages are gone.")
    }
}
