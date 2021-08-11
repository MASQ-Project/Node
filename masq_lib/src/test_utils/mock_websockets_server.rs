// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
use crate::messages::{FromMessageBody, UiBroadcastTrigger, NODE_UI_PROTOCOL};
use crate::ui_gateway::{MessageBody, MessagePath};
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
                log(do_log, index, "Checking for message from client");
                if let Some(incoming) =
                    Self::handle_incoming_raw(client.recv_message(), do_log, index)
                {
                    log(
                        do_log,
                        index,
                        &format!("Recording incoming message: {:?}", incoming),
                    );
                    requests.push(incoming.clone());
                    if let Ok(message_body) = incoming {
                        match message_body.path {
                            MessagePath::Conversation(context_id) => {
                                if Self::handle_conversational_incoming_message(
                                    &mut client,
                                    message_body,
                                    &inner_responses_arc,
                                    context_id,
                                    do_log,
                                    index,
                                )
                                .not()
                                {
                                    break; //"disconnect" received
                                }
                            }

                            MessagePath::FireAndForget
                                if message_body.opcode == "broadcastTrigger" =>
                            {
                                self.handle_broadcast_trigger(
                                    &mut client,
                                    message_body,
                                    &inner_responses_arc,
                                    do_log,
                                    index,
                                )
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
                        panic!("Unrecognizable incoming message received; you should refrain from sending some meaningless garbage to the server: {:?}",incoming)
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

    fn handle_incoming_raw(
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

    fn handle_conversational_incoming_message(
        client: &mut Client<TcpStream>,
        message_body: MessageBody,
        inner_responses_arc: &Arc<Mutex<Vec<OwnedMessage>>>,
        context_id: u64,
        do_log: bool,
        index: u64,
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
                            &format!("Responding with preset message: '{}'", outgoing),
                        );
                        //asserting on that we've truly been given a conversational message from the queue
                        let response_to_the_client = if outgoing.contains("\"contextId\"") {
                            outgoing
                        }
                        //all messages not being conversational but still recognisable from our point of view
                        else if outgoing.starts_with("{\"opcode\":") {
                            //giving the pulled message back into the queue on its former position
                            temporary_access_to_inner_responses_arc
                                .insert(0, OwnedMessage::Text(outgoing));
                            format!(
                                r#"{{"opcode": "{}", "contextId": {}, "error": {{"code": 0, "message": "You tried to call up a fire-and-forget message from the queue by sending a conversational request; try to adjust the queue or similar"}}}}"#,
                                message_body.opcode, context_id
                            )
                        } else {
                            //this branch is for processing messages from the queue dissimilar to our UI-Node protocol...simply garbage
                            outgoing
                        };
                        client
                            .send_message(&OwnedMessage::Text(response_to_the_client))
                            .unwrap()
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
                //a response that's going to be interpreted as an empty queue
                .send_message(&OwnedMessage::Binary(b"EMPTY QUEUE".to_vec()))
                .unwrap()
        };
        true
    }

    fn handle_broadcast_trigger(
        &self,
        client: &mut Client<TcpStream>,
        message_body: MessageBody,
        inner_responses_arc: &Arc<Mutex<Vec<OwnedMessage>>>,
        do_log: bool,
        index: u64,
    ) {
        log(do_log, index, "Responding to a BroadcastTrigger");
        let queued_messages = &mut *inner_responses_arc.lock().unwrap();
        let (signal_params, batch_size_of_broadcasts_to_be_released_at_once) =
            match (UiBroadcastTrigger::fmb(message_body),self.signal_sender.clone().take()) {
            (Ok((trigger_message, _)), Some(sender)) => match (trigger_message.position_to_send_the_signal_opt, trigger_message.number_of_broadcasts_in_one_batch){
                (Some(position),Some(demanded_batch_size)) => (Some((position, sender)), demanded_batch_size),
                (Some(position),None) => (Some((position, sender)), queued_messages.len()),
                (None,_) => panic!("You provided a Sender<()> but forgot to provide the positional number of the broadcast where it should be sent; settable within the trigger message"),
            }

            (Ok((trigger_message, _)), None) => match (trigger_message.position_to_send_the_signal_opt,trigger_message.number_of_broadcasts_in_one_batch){
                (Some(_),_) => panic!("You require to send a signal but haven't provided Sender<()> by inject_signal_sender()"),
                (None,Some(demanded_batch_size)) => (None,demanded_batch_size),
                (None,None) =>  (None, queued_messages.len())
            },
            (_,_) => panic!("BroadcastTrigger received but somehow malformed")
        };

        //////////////////////////////////////////////////////////////////////////////////////////////
        //here the proper algorithm carrying out messaging starts
        let mut already_sent = 0_usize;
        let starting_length = queued_messages.len();
        for i in 0..starting_length {
            //sending signal if wanted ///////////////////////////////
            if let Some((position, signal_sender)) = signal_params.as_ref() {
                if *position == i {
                    log(
                        do_log,
                        index,
                        "Sending a generic signal required by a BroadcastTrigger",
                    );
                    signal_sender.send(()).unwrap()
                }
            }
            //generally: watching that we don't grab any conversational message from the queue accidentally
            //first line: consider the minus after 'i' as a factor of positional reduction inside the queue
            //caused by how I remove each message after I send it
            if let OwnedMessage::Text(json) = &queued_messages[i - already_sent] {
                if let Ok(msg) = UiTrafficConverter::new_unmarshal_from_ui(json, 0) {
                    if msg.body.path == MessagePath::FireAndForget {
                        //////////////////////////////////////////////////////////////////////
                        client.send_message(&queued_messages.remove(0)).unwrap();
                        already_sent += 1;
                        if already_sent == batch_size_of_broadcasts_to_be_released_at_once {
                            break;
                        }
                        //////////////////////////////////////////////////////////////////////////////////////////
                    } else {
                        //let's end it; we ran into a conversational message in the queue
                        break;
                    }
                }
            }
        }
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
    use crate::messages::UiSetupResponseValueStatus::Set;
    use crate::messages::{
        CrashReason, FromMessageBody, ToMessageBody, UiBroadcastTrigger, UiCheckPasswordRequest,
        UiCheckPasswordResponse, UiConfigurationChangedBroadcast, UiDescriptorRequest,
        UiDescriptorResponse, UiNewPasswordBroadcast, UiNodeCrashedBroadcast, UiSetupRequest,
        UiSetupRequestValue, UiSetupResponse, UiSetupResponseValue, NODE_UI_PROTOCOL,
    };
    use crate::test_utils::ui_connection::UiConnection;
    use crate::utils::find_free_port;

    #[test]
    fn conversational_communication_happy_path_with_full_assertion() {
        let port = find_free_port();
        let expected_response = UiSetupResponse {
            running: true,
            values: vec![UiSetupResponseValue {
                name: "direction".to_string(),
                value: "to UI".to_string(),
                status: Set,
            }],
            errors: vec![
                ("param1".to_string(), "reason1".to_string()),
                ("param2".to_string(), "reason2".to_string()),
            ],
        };
        let stop_handle = MockWebSocketsServer::new(port)
            .queue_response(expected_response.clone().tmb(123))
            .start();
        let mut connection = UiConnection::new(port, NODE_UI_PROTOCOL);

        let request = UiSetupRequest {
            values: vec![UiSetupRequestValue {
                name: "direction".to_string(),
                value: Some("to UI".to_string()),
            }],
        };

        let actual_response: UiSetupResponse = connection
            .transact_with_context_id(request.clone(), 123)
            .unwrap();

        let requests = stop_handle.stop();
        let actual_body_gotten_by_the_server =
            UiSetupRequest::fmb(requests[0].clone().unwrap()).unwrap().0;
        assert_eq!(actual_body_gotten_by_the_server, request);
        assert_eq!(
            (actual_response, 123),
            UiSetupResponse::fmb(expected_response.tmb(123)).unwrap()
        );
    }

    #[test]
    fn conversational_and_broadcast_messages_can_work_together_testing_corner_cases() {
        //The test follows these presumptions:
        // Queue:
        // Conversation 1
        // Conversation 2
        // Broadcast 1
        // Broadcast 2
        // Broadcast 3
        // Broadcast 4
        // Conversation 3
        // Conversation 4
        // Broadcast 5
        //
        // Code:
        // connection.transact(stimulus) -> Conversation 1
        // connection.transact(stimulus) -> Conversation 2
        // connection.send(BroadcastTrigger {limit: Some(2)});
        // connection.receive() -> Broadcast 1
        // connection.receive() -> Broadcast 2
        // connection.receive() -> error: Limit of two Broadcasts specified in trigger
        // connection.transact(stimulus) -> error: next queued message is a Broadcast, not a Conversation
        // connection.send(BroadcastTrigger {limit: None});
        // connection.receive() -> Broadcast 3
        // connection.receive() -> Broadcast 4
        // connection.receive() -> error: No more Broadcasts available before a Conversation
        // connection.transact(stimulus) -> Conversation 3
        // connection.transact(stimulus) -> Conversation 4
        // connection.send(BroadcastTrigger {limit: None});
        // connection.receive() -> Broadcast 5
        // connection.receive() -> error: No more Broadcasts available

        //Content of those messages is practically irrelevant because it's not under the scope of this test.
        //Also, a lot of lines could be highlighted with text like this "TESTED BY COMPLETING THE TASK - NO ADDITIONAL ASSERTION NEEDED",
        //but it may have made the test (even) harder to read.

        //Lists of messages used in this test

        //A) All messages "sent from UI to D/N" (in an exact order)
        ////////////////////////////////////////////////////////////////////////////////////////////
        let conversation_number_one_request = UiCheckPasswordRequest {
            db_password_opt: None,
        };
        let conversation_number_two_request = UiCheckPasswordRequest {
            db_password_opt: Some("Titanic".to_string()),
        };
        //nonconversational stimulus
        let broadcast_trigger_one_with_limit_on_two = UiBroadcastTrigger {
            number_of_broadcasts_in_one_batch: Some(2),
            position_to_send_the_signal_opt: None,
        };
        //the following message is expected not to get answered
        let conversation_number_three_request = UiDescriptorRequest {};
        //nonconversational stimulus
        let broadcast_trigger_two_with_no_limit = UiBroadcastTrigger::default();
        let conversation_number_four_request = UiDescriptorRequest {};
        //nonconversational stimulus
        let broadcast_trigger_three_with_no_limit = UiBroadcastTrigger::default();

        //B) All messages "responding the opposite way" (in an exact order)
        ////////////////////////////////////////////////////////////////////////////////////////////
        let conversation_number_one_response = UiCheckPasswordResponse { matches: false }.tmb(1);
        let conversation_number_two_response = UiCheckPasswordResponse { matches: true }.tmb(2);
        let broadcast_number_one = UiConfigurationChangedBroadcast {}.tmb(0);
        let broadcast_number_two = UiNodeCrashedBroadcast {
            process_id: 0,
            crash_reason: CrashReason::NoInformation,
        }
        .tmb(0);
        let broadcast_number_three = UiNewPasswordBroadcast {}.tmb(0);
        let broadcast_number_four = broadcast_number_three.clone();
        let broadcast_number_five = broadcast_number_three.clone();
        let conversation_number_three_response = UiDescriptorResponse {
            node_descriptor: "ae15fe6".to_string(),
        }
        .tmb(4);
        let broadcast_number_six = broadcast_number_two.clone();
        ////////////////////////////////////////////////////////////////////////////////////////////
        let port = find_free_port();
        //preparing the server and filling the queue
        let server = MockWebSocketsServer::new(port)
            .queue_response(conversation_number_one_response)
            .queue_response(conversation_number_two_response)
            .queue_response(broadcast_number_one)
            .queue_response(broadcast_number_two)
            .queue_response(broadcast_number_three)
            .queue_response(broadcast_number_four)
            .queue_response(broadcast_number_five)
            .queue_response(conversation_number_three_response)
            .queue_response(broadcast_number_six);
        let stop_handle = server.start();
        let waiting_for_message_time_out = if cfg!(target_os = "macos") { 250 } else { 150 };
        let mut connection = UiConnection::new(port, NODE_UI_PROTOCOL);

        let _received_message_number_one: UiCheckPasswordResponse = connection
            .transact_with_context_id(conversation_number_one_request, 1)
            .unwrap();

        let _received_message_number_two: UiCheckPasswordResponse = connection
            .transact_with_context_id(conversation_number_two_request, 2)
            .unwrap();

        //sending the first demand to send broadcasts; just two should come
        connection.send(broadcast_trigger_one_with_limit_on_two);

        //checking what is arriving
        let _received_message_number_three: UiConfigurationChangedBroadcast =
            connection.receive().unwrap();

        let _received_message_number_four: UiNodeCrashedBroadcast = connection.receive().unwrap();

        //because we've demanded to "trigger" just two broadcasts; there should be no other broadcast waiting for us
        let naive_attempt_number_one_to_receive_the_third_broadcast: Result<
            UiNewPasswordBroadcast,
            (u64, String),
        > = connection.receive_custom(waiting_for_message_time_out);

        connection.send_with_context_id(conversation_number_three_request, 3);
        let naive_attempt_number_two_now_to_receive_a_conversational_message: Result<
            UiDescriptorResponse,
            (u64, String),
        > = connection.receive_custom(waiting_for_message_time_out);

        //sending another broadcast trigger (unlimited) to get the fifth, sixth and seventh message
        connection.send(broadcast_trigger_two_with_no_limit);
        //finally, when using the trigger again, we can get three other messages

        let _ = (0..3)
            .map(|_| connection.receive().unwrap())
            .collect::<Vec<UiNewPasswordBroadcast>>();

        //here we shouldn't be able to jump over to some other broadcast in the queue though there is one!;
        //instead we should see an error because next we meet a conversational message
        let naive_attempt_number_three_to_receive_another_broadcast_from_the_queue: Result<
            UiNodeCrashedBroadcast,
            (u64, String),
        > = connection.receive_custom(waiting_for_message_time_out);

        let _received_message_number_eight: UiDescriptorResponse = connection
            .transact_with_context_id(conversation_number_four_request, 4)
            .unwrap();
        //we want to get to the last broadcast
        connection.send(broadcast_trigger_three_with_no_limit);

        let _received_message_number_ninth: UiNodeCrashedBroadcast = connection.receive().unwrap();
        //the queue should be empty now

        let naive_attempt_number_four: Result<UiNodeCrashedBroadcast, (u64, String)> =
            connection.receive_custom(waiting_for_message_time_out);
        //the previous attempt eliminated the possibility of another broadcast
        //but what happens when new conversation tried

        connection.send_with_context_id(UiDescriptorRequest {}, 5);
        let naive_attempt_number_five: Result<UiDescriptorResponse, (u64, String)> =
            connection.receive_custom(waiting_for_message_time_out);

        let _ = stop_handle.stop();
        ////////////////////////////////////////////////////////////////////////////////////////////
        //assertions for deliberately caused errors
        let expected_time_out_message = &format!("Expected a response. Probably none is to come, waiting was too long (with time limit: {} ms)",waiting_for_message_time_out);

        let error_message_number_one = naive_attempt_number_one_to_receive_the_third_broadcast
            .unwrap_err()
            .1;
        assert!(
            error_message_number_one.contains(expected_time_out_message),
            "this text was unexpected: {}",
            error_message_number_one
        );
        let error_message_number_two =
            naive_attempt_number_two_now_to_receive_a_conversational_message
                .unwrap_err()
                .1;
        assert!(error_message_number_two.contains("You tried to call up a fire-and-forget message from the queue by sending a conversational request; \
        try to adjust the queue or similar"),"this text was unexpected: {}",error_message_number_two);
        let error_message_number_three =
            naive_attempt_number_three_to_receive_another_broadcast_from_the_queue
                .unwrap_err()
                .1;
        assert!(
            error_message_number_three.contains(expected_time_out_message),
            "this text was unexpected: {}",
            error_message_number_three
        );
        let error_message_number_four = naive_attempt_number_four.unwrap_err().1;
        assert!(
            error_message_number_four.contains(expected_time_out_message),
            "this text was unexpected: {}",
            error_message_number_four
        );

        let error_message_number_five = naive_attempt_number_five.unwrap_err().1;
        assert!(
            error_message_number_five.contains("The queue is empty"),
            "this text was unexpected: {}",
            error_message_number_five
        )
    }
}
