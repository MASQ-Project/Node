// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
use crate::messages::{
    FromMessageBody, ToMessageBody, UiBroadcastTrigger, UiUnmarshalError, NODE_UI_PROTOCOL,
};
use crate::ui_gateway::{MessageBody, MessagePath};
use crate::ui_traffic_converter::UiTrafficConverter;
use crate::utils::localhost;
use crossbeam_channel::{unbounded, Receiver, Sender};
use lazy_static::lazy_static;
use std::cell::Cell;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::thread;
use std::thread::JoinHandle;
use std::time::Duration;
use websocket::result::WebSocketError;
use websocket::sync::Server;
use websocket::OwnedMessage;

lazy_static! {
    static ref MWSS_INDEX: Mutex<u64> = Mutex::new(0);
}

pub struct MockWebSocketsServer {
    log: bool,
    port: u16,
    pub protocol: String,
    responses_arc: Arc<Mutex<Vec<OwnedMessage>>>,
    signal_sender: Cell<Option<Sender<()>>>,
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
            signal_sender: Cell::new(None),
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
        self.signal_sender.set(Some(sender));
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
            if upgrade
                .protocols()
                .iter()
                .find(|p| *p == &self.protocol)
                .is_none()
            {
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
                let incoming_opt = match client.recv_message() {
                    Err(WebSocketError::NoDataAvailable) => {
                        log(do_log, index, "No data available");
                        None
                    }
                    Err(WebSocketError::IoError(e))
                        if e.kind() == std::io::ErrorKind::WouldBlock =>
                    {
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
                };
                if let Some(incoming) = incoming_opt {
                    log(
                        do_log,
                        index,
                        &format!("Recording incoming message: {:?}", incoming),
                    );
                    requests.push(incoming.clone());
                    if let Ok(message_body) = incoming {
                        match message_body.path {
                            MessagePath::Conversation(_) => match inner_responses_arc
                                .lock()
                                .unwrap()
                                .remove(0)
                            {
                                OwnedMessage::Text(outgoing) => {
                                    if outgoing == "disconnect" {
                                        log(do_log, index, "Executing 'disconnect' directive");
                                        break;
                                    }
                                    if outgoing == "close" {
                                        log(do_log, index, "Sending Close message");
                                        client.send_message(&OwnedMessage::Close(None)).unwrap();
                                    } else {
                                        log(
                                            do_log,
                                            index,
                                            &format!(
                                                "Responding with preset message: '{}'",
                                                outgoing
                                            ),
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
                            },
                            MessagePath::FireAndForget
                                if message_body.opcode == "broadcastTrigger" =>
                            {
                                log(
                                    do_log,
                                    index,
                                    "Responding to a request for FireAndForget message in direction to UI",
                                );
                                let (trigger, _) = UiBroadcastTrigger::fmb(message_body).unwrap();
                                let positional_number_of_the_signal_sent_opt =
                                    trigger.position_to_send_the_signal_opt;
                                let signal_sender_opt: Option<Sender<()>> =
                                    if positional_number_of_the_signal_sent_opt.is_some() {
                                        if let Some(signal_sender) = self.signal_sender.take() {
                                            Some(signal_sender)
                                        } else {
                                            panic!("You require to send a signal but haven't provided Sender<()> by inject_signal_sender()")
                                        }
                                    } else {
                                        None
                                    };
                                {
                                    let queued_messages = &mut *inner_responses_arc.lock().unwrap();
                                    let mut factor_of_position_reduction = 0_usize;
                                    (0..queued_messages.len()).for_each(|i| {
                                        if let Some(position) =
                                            positional_number_of_the_signal_sent_opt
                                        {
                                            if position == i {
                                                signal_sender_opt
                                                    .as_ref()
                                                    .unwrap()
                                                    .send(())
                                                    .unwrap()
                                            }
                                        }
                                        if let OwnedMessage::Text(json) =
                                            &queued_messages[i - factor_of_position_reduction]
                                        {
                                            if let Ok(msg) =
                                                UiTrafficConverter::new_unmarshal_from_ui(&json, 0)
                                            {
                                                if msg.body.path == MessagePath::FireAndForget {
                                                    client
                                                        .send_message(
                                                            &queued_messages
                                                                [i - factor_of_position_reduction],
                                                        )
                                                        .unwrap();
                                                    queued_messages
                                                        .remove(i - factor_of_position_reduction);
                                                    factor_of_position_reduction += 1;
                                                    thread::sleep(Duration::from_millis(1))
                                                }
                                            }
                                        }
                                    })
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
                            "Responding to unrecognizable OwnedMessage::Text",
                        );
                        let bad_message = incoming.unwrap_err();
                        let marshal_error = UiTrafficConverter::new_unmarshal_from_ui(
                            &bad_message,
                            0, //irrelevant?
                        )
                        .unwrap_err();
                        let to_ui_response = UiUnmarshalError {
                            message: bad_message,
                            bad_data: marshal_error.to_string(),
                        }
                        .tmb(0);
                        let marshaled_response = UiTrafficConverter::new_marshal(to_ui_response);
                        client
                            .send_message(&OwnedMessage::Text(marshaled_response))
                            .unwrap()
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
        FromMessageBody, ToMessageBody, UiBroadcastTrigger, UiChangePasswordRequest,
        UiChangePasswordResponse, UiNewPasswordBroadcast, UiNodeCrashedBroadcast, UiSetupBroadcast,
        UiSetupRequest, UiSetupResponse, UiSetupResponseValue, UiUnmarshalError, NODE_UI_PROTOCOL,
    };
    use crate::test_utils::ui_connection::UiConnection;
    use crate::utils::find_free_port;
    use crossbeam_channel::bounded;

    #[test]
    fn two_in_two_out() {
        let port = find_free_port();
        let first_expected_response = UiSetupResponse {
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
        }
        .tmb(1);
        let second_expected_response = UiUnmarshalError {
            message: "}: Bad request :{".to_string(),
            bad_data: "Critical error unmarshalling unidentified message: \
            Couldn't parse text as JSON: Error(\"expected value\", line: 1, column: 1)"
                .to_string(),
        }
        .tmb(0);
        let stop_handle = MockWebSocketsServer::new(port)
            .queue_response(first_expected_response.clone())
            .queue_response(second_expected_response.clone())
            .start();
        let mut connection = UiConnection::new(port, NODE_UI_PROTOCOL);

        let first_actual_response: UiSetupResponse = connection
            .transact_with_context_id(
                UiSetupResponse {
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
                },
                1234,
            )
            .unwrap();

        connection.send_string("}: Bad request :{".to_string());

        let second_actual_response: UiUnmarshalError = connection.receive().unwrap();

        let requests = stop_handle.stop();
        let actual_body: UiSetupResponse = UiSetupResponse::fmb(requests[0].clone().unwrap())
            .unwrap()
            .0;
        assert_eq!(
            actual_body,
            UiSetupResponse {
                running: true,
                values: vec![UiSetupResponseValue {
                    name: "direction".to_string(),
                    value: "to UI".to_string(),
                    status: Set,
                }],
                errors: vec![
                    ("param1".to_string(), "reason1".to_string()),
                    ("param2".to_string(), "reason2".to_string()),
                ]
            }
        );
        assert_eq!(
            (first_actual_response, 1),
            UiSetupResponse::fmb(first_expected_response).unwrap()
        );
        assert_eq!(requests[1], Err("}: Bad request :{".to_string()));
        assert_eq!(
            (second_actual_response, 0),
            UiUnmarshalError::fmb(second_expected_response).unwrap()
        );
    }

    #[test]
    fn broadcast_trigger_can_work_together_with_conversational_messages() {
        let port = find_free_port();
        let (tx, rx) = bounded(1);
        let expected_ui_setup_broadcast = UiSetupBroadcast {
            running: false,
            values: vec![UiSetupResponseValue {
                name: "direction".to_string(),
                value: "to UI".to_string(),
                status: Set,
            }],
            errors: vec![],
        };
        let server = MockWebSocketsServer::new(port)
            .queue_response(
                UiSetupResponse {
                    running: false,
                    values: vec![],
                    errors: vec![],
                }
                .tmb(10),
            )
            .queue_response(expected_ui_setup_broadcast.clone().tmb(0))
            .queue_response(UiChangePasswordResponse {}.tmb(11))
            .queue_response(UiNewPasswordBroadcast {}.tmb(0))
            .inject_signal_sender(tx);
        let stop_handle = server.start();
        let ui_setup_request = UiSetupRequest { values: vec![] };
        let ui_change_password_request = UiChangePasswordRequest {
            old_password_opt: None,
            new_password: "abraka".to_string(),
        };
        let broadcast_trigger = UiBroadcastTrigger {
            position_to_send_the_signal_opt: None,
        };
        let mut connection = UiConnection::new(port, NODE_UI_PROTOCOL);

        connection.send(broadcast_trigger);
        let first_received_message: UiSetupBroadcast = connection.receive().unwrap();
        let second_received_message: UiNewPasswordBroadcast = connection.receive().unwrap();
        //let ui_setup_response: UiSetupResponse = connection.transact_with_context_id(ui_setup_request,10).unwrap();

        let requests = stop_handle.stop();
        assert_eq!(first_received_message, expected_ui_setup_broadcast);
        assert_eq!(second_received_message, UiNewPasswordBroadcast {})
    }
}
