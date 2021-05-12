// Copyright (c) 2019-2021, MASQ (https://masq.ai). All rights reserved.

use crate::messages::{FromMessageBody, ToMessageBody, UiMessageError};
use crate::ui_gateway::MessagePath::Conversation;
use crate::ui_gateway::MessageTarget::ClientId;
use crate::ui_traffic_converter::UiTrafficConverter;
use crate::utils::localhost;
use std::io::{ErrorKind, Write};
use std::net::TcpStream;
use std::thread;
use std::time::{Duration, Instant};
use websocket::sync::Client;
use websocket::{ClientBuilder, OwnedMessage, WebSocketError, WebSocketResult};

const NORMAL_WAITING_PERIOD: u64 = 1000;

pub struct UiConnection {
    context_id: u64,
    client: Client<TcpStream>,
}

impl UiConnection {
    pub fn make(port: u16, protocol: &str) -> Result<UiConnection, String> {
        let client_builder =
            match ClientBuilder::new(format!("ws://{}:{}", localhost(), port).as_str()) {
                Ok(cb) => cb,
                Err(e) => return Err(format!("{:?}", e)),
            };
        let client = match client_builder.add_protocol(protocol).connect_insecure() {
            Ok(c) => c,
            Err(e) => return Err(format!("{:?}", e)),
        };
        match client.set_nonblocking(true) {
            Ok(_) => (),
            Err(e) => return Err(format!("{:?}", e)),
        }
        Ok(UiConnection {
            client,
            context_id: 0,
        })
    }

    pub fn new(port: u16, protocol: &str) -> UiConnection {
        Self::make(port, protocol).unwrap()
    }

    pub fn send<T: ToMessageBody>(&mut self, payload: T) {
        let context_id = self.context_id;
        self.context_id += 1;
        self.send_with_context_id(payload, context_id)
    }

    pub fn send_with_context_id<T: ToMessageBody>(&mut self, payload: T, context_id: u64) {
        let outgoing_msg = payload.tmb(context_id);
        let outgoing_msg_json = UiTrafficConverter::new_marshal(outgoing_msg);
        self.send_string(outgoing_msg_json);
    }

    pub fn send_string(&mut self, string: String) {
        self.send_message(&OwnedMessage::Text(string))
    }

    pub fn send_message(&mut self, message: &OwnedMessage) {
        self.client.send_message(message).unwrap();
    }

    pub fn writer(&mut self) -> &mut dyn Write {
        self.client.writer_mut()
    }

    fn receive_raw<T: FromMessageBody>(
        &mut self,
        context_id: Option<u64>,
        waiting_limit: u64,
    ) -> Result<T, (u64, String)> {
        let mut failure_state_holder: Option<WebSocketResult<OwnedMessage>> = None;
        let start_instant = Instant::now();

        let incoming_msg_json = loop {
            if start_instant.elapsed() > Duration::from_millis(waiting_limit) {
                //a way to inform that the attempt failed, without blocking
                return
                    Err((0,
                format!("Expected a response. Probably none is to come, waiting was too long (with time limit: {} ms){}", waiting_limit,
                        if let Some(error) = failure_state_holder{format!(" or the cause is the following error: {:?}",error)}else{"".to_string()}
                ))
                );
            }
            match self.client.recv_message() {
                Ok(OwnedMessage::Binary(bytes))
                    if std::str::from_utf8(&bytes).unwrap() == "EMPTY QUEUE" =>
                {
                    return Err((0, "The queue is empty; all messages are gone.".to_string()))
                }
                Ok(OwnedMessage::Text(json)) => break json,
                Err(WebSocketError::IoError(io_e))
                    if io_e.kind() == ErrorKind::WouldBlock
                        || io_e.kind() == ErrorKind::TimedOut =>
                {
                    failure_state_holder = None
                }
                x => failure_state_holder = Some(x),
            }
            thread::sleep(Duration::from_millis(20))
        };

        let incoming_msg = UiTrafficConverter::new_unmarshal_to_ui(&incoming_msg_json, ClientId(0))
            .unwrap_or_else(|_| panic!("Deserialization problem with: {}: ", &incoming_msg_json));
        let opcode = incoming_msg.body.opcode.clone();

        if let Some(testing_id) = context_id {
            match incoming_msg.body.path {
                Conversation(id) if id == testing_id => (),
                Conversation(id) if id != testing_id => panic!(
                    "Context ID of the request and the response don't match; message: \
         {:?}, request id: {}, response id: {}",
                    incoming_msg, testing_id, id
                ),
                _ => (),
            }
        }

        let result: Result<(T, u64), UiMessageError> = T::fmb(incoming_msg.body);
        match result {
            Ok((payload, _)) => Ok(payload),
            Err(UiMessageError::PayloadError(code, message)) => Err((code, message)),
            Err(e) => panic!("Deserialization problem for {}: {:?}", opcode, e),
        }
    }

    pub fn receive<T: FromMessageBody>(&mut self) -> Result<T, (u64, String)> {
        self.receive_raw::<T>(None, NORMAL_WAITING_PERIOD)
    }

    pub fn receive_custom<T: FromMessageBody>(
        &mut self,
        waiting_period: u64,
    ) -> Result<T, (u64, String)> {
        self.receive_raw::<T>(None, waiting_period)
    }

    pub fn transact<S: ToMessageBody, R: FromMessageBody>(
        &mut self,
        payload: S,
    ) -> Result<R, (u64, String)> {
        self.send(payload);
        self.receive_raw::<R>(None, NORMAL_WAITING_PERIOD)
    }

    pub fn transact_with_context_id<S: ToMessageBody, R: FromMessageBody>(
        &mut self,
        payload: S,
        context_id: u64,
    ) -> Result<R, (u64, String)> {
        self.send_with_context_id(payload, context_id);
        self.receive_raw::<R>(Some(context_id), NORMAL_WAITING_PERIOD)
    }

    pub fn shutdown(self) {
        self.client.shutdown().unwrap()
    }
}
