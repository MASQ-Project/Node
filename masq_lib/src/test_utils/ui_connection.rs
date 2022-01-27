// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::messages::{FromMessageBody, ToMessageBody, UiMessageError};
use crate::ui_gateway::MessagePath::Conversation;
use crate::ui_gateway::MessageTarget::ClientId;
use crate::ui_traffic_converter::UiTrafficConverter;
use crate::utils::localhost;
use std::io::Write;
use std::net::TcpStream;
use websocket::sync::Client;
use websocket::{ClientBuilder, OwnedMessage};

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
    ) -> Result<T, (u64, String)> {
        let incoming_msg_json = match self.client.recv_message() {
            Ok(OwnedMessage::Binary(bytes)) if bytes == b"EMPTY QUEUE" => {
                panic!("The queue is empty; all messages are gone.")
            }
            Ok(OwnedMessage::Text(json)) => json,
            x => panic!(
                "We received an unexpected message from the MockWebSocketServer: {:?}",
                x
            ),
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
            Err(UiMessageError::PayloadError(message_body)) => {
                let payload_error = message_body
                    .payload
                    .err()
                    .expect("PayloadError message body contained no payload error");
                Err(payload_error)
            }
            Err(e) => panic!("Deserialization problem for {}: {:?}", opcode, e),
        }
    }

    pub fn receive<T: FromMessageBody>(&mut self) -> Result<T, (u64, String)> {
        self.receive_raw::<T>(None)
    }

    pub fn transact<S: ToMessageBody, R: FromMessageBody>(
        &mut self,
        payload: S,
    ) -> Result<R, (u64, String)> {
        self.send(payload);
        self.receive_raw::<R>(None)
    }

    pub fn transact_with_context_id<S: ToMessageBody, R: FromMessageBody>(
        &mut self,
        payload: S,
        context_id: u64,
    ) -> Result<R, (u64, String)> {
        self.send_with_context_id(payload, context_id);
        self.receive_raw::<R>(Some(context_id))
    }

    pub fn shutdown(self) {
        self.client.shutdown().unwrap()
    }
}
