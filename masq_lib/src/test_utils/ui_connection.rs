// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::messages::{FromMessageBody, ToMessageBody, UiMessageError};
use crate::test_utils::ui_connection::ReceiveResult::{
    Correct, MBMarshalError, MarshalError, TransactionError,
};
use crate::ui_gateway::MessageBody;
use crate::ui_gateway::MessagePath::Conversation;
use crate::ui_gateway::{MessagePath, MessageTarget, NodeToUiMessage};
use crate::ui_traffic_converter::UiTrafficConverter;
use crate::utils::localhost;
use crate::websockets_types::{WSReceiver, WSSender};
use futures_util::io::{BufReader, BufWriter};
use rustc_hex::ToHex;
use soketto::data::ByteSlice125;
use soketto::handshake::ServerResponse;
use soketto::{handshake, Data as SokettoDataType};
use std::fmt::{Debug, Formatter};
use std::net::SocketAddr;
use std::time::Duration;
use std::{fmt, io};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_util::compat::TokioAsyncReadCompatExt;

pub struct UiConnection {
    context_id: u64,
    local_addr: SocketAddr,
    accepted_protocol_opt: Option<String>,
    sender: WSSender,
    receiver: WSReceiver,
}

impl Debug for UiConnection {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("UiConnection")
            .field("context_id", &self.context_id)
            .field("local_addr", &self.local_addr)
            .field("sender", &"--unprintable--".to_string())
            .field("receiver", &"--unprintable--".to_string())
            .finish()
    }
}

impl UiConnection {
    pub async fn new(port: u16, protocol: &'static str) -> Result<UiConnection, String> {
        let (sender, receiver, accepted_protocol_opt) =
            Self::establish_ws_conn_with_protocols(port, vec![protocol.to_string()])
                .await
                .unwrap();
        Ok(UiConnection {
            context_id: 0,
            local_addr: SocketAddr::new(localhost(), port),
            accepted_protocol_opt,
            sender,
            receiver,
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub async fn send<T: ToMessageBody>(&mut self, payload: T) {
        let context_id = self.context_id;
        self.context_id += 1;
        self.send_with_context_id(payload, context_id).await
    }

    pub async fn send_with_context_id<T: ToMessageBody>(&mut self, payload: T, context_id: u64) {
        let outgoing_msg = payload.tmb(context_id);
        let outgoing_msg_json = UiTrafficConverter::new_marshal(outgoing_msg);
        self.send_string(outgoing_msg_json).await;
    }

    pub async fn send_close(&mut self) {
        self.sender
            .close()
            .await
            .expect("Failed to close connection");
    }

    pub async fn send_data(&mut self, data: Vec<u8>) {
        self.sender
            .send_binary(data)
            .await
            .expect("Failed to send data");
        self.sender.flush().await.expect("Failed to flush data");
    }

    pub async fn send_string(&mut self, string: String) {
        self.sender
            .send_text_owned(string)
            .await
            .expect("Failed to send message");
        self.sender.flush().await.expect("Failed to flush message");
    }

    pub async fn send_ping(&mut self, data: Vec<u8>) {
        self.sender
            .send_ping(ByteSlice125::try_from(data.as_slice()).unwrap())
            .await
            .expect("Failed to send ping");
        self.sender.flush().await.expect("Failed to flush ping");
    }

    pub async fn send_pong(&mut self, data: Vec<u8>) {
        self.sender
            .send_pong(ByteSlice125::try_from(data.as_slice()).unwrap())
            .await
            .expect("Failed to send pong");
        self.sender.flush().await.expect("Failed to flush pong");
    }

    pub async fn receive(
        &mut self,
    ) -> Result<(SokettoDataType, Vec<u8>), soketto::connection::Error> {
        let mut message = Vec::new();
        let data_type = self.receiver.receive_data(&mut message).await?;
        match data_type {
            SokettoDataType::Binary(_) => {
                if message.as_slice() == b"EMPTY_QUEUE" {
                    panic!("The queue is empty; all messages are gone.")
                }
            }
            _ => (),
        }
        Ok((data_type, message))
    }

    pub async fn receive_data(&mut self) -> Vec<u8> {
        let (data_type, message) = self.receive().await.unwrap();
        if let SokettoDataType::Binary(_) = data_type {
            message
        } else {
            panic!("Expected a binary message, but received a text message")
        }
    }

    pub async fn receive_string(&mut self) -> String {
        let (data_type, message) = self.receive().await.unwrap();
        if let SokettoDataType::Text(_) = data_type {
            String::from_utf8(message).expect("Failed to convert message to string")
        } else {
            panic!("Expected a text message, but received a binary message")
        }
    }

    pub async fn receive_node_to_ui(&mut self, target: MessageTarget) -> NodeToUiMessage {
        let incoming_msg_json = self.receive_string().await;
        UiTrafficConverter::new_unmarshal_to_ui(&incoming_msg_json, target)
            .unwrap_or_else(|_| panic!("Deserialization problem with: {}: ", &incoming_msg_json))
    }

    pub async fn receive_message<T: FromMessageBody>(
        &mut self,
        context_id: Option<u64>,
    ) -> ReceiveResult<T> {
        let incoming_msg_json = self.receive_string().await;
        let message_body = UiTrafficConverter::new_unmarshal(&incoming_msg_json)
            .unwrap_or_else(|_| panic!("Deserialization problem with: {}: ", &incoming_msg_json));
        if let Some(testing_id) = context_id {
            match message_body.path {
                Conversation(id) if id == testing_id => (),
                Conversation(id) if id != testing_id => panic!(
                    "Context ID of the request and the response don't match; message: {:?}, request id: {}, response id: {}",
                    message_body, testing_id, id
                ),
                _ => (),
            }
        }

        let result: Result<(T, u64), UiMessageError> = T::fmb(message_body.clone());
        match result {
            Ok((payload, _)) => Correct(message_body.path, payload),
            Err(UiMessageError::PayloadError(message_body)) => {
                let payload_error = message_body
                    .payload
                    .expect_err("PayloadError message body contained no payload error");
                TransactionError(payload_error.0, payload_error.1)
            }
            Err(e) => MBMarshalError(message_body, e),
        }
    }

    pub async fn assert_nothing_waiting(&mut self, milliseconds: u64) {
        let mut message: Vec<u8> = Vec::new();
        let future = self.receiver.receive_data(&mut message);
        match timeout(Duration::from_millis(milliseconds), future).await {
            Ok(Ok(data_type)) => panic!(
                "Expected nothing; found {:?} message: {}",
                data_type,
                message.to_hex::<String>()
            ),
            Ok(Err(e)) => panic!("Error verifying no waiting message: {}", e),
            Err(_) => return,
        }
    }

    pub async fn skip_until_received<T: FromMessageBody>(
        &mut self,
    ) -> Result<(MessagePath, T), (u64, String)> {
        match Self::await_message(self).await {
            Ok((path, msg, _)) => Ok((path, msg)),
            Err((code, msg)) => Err((code, msg)),
        }
    }

    async fn establish_ws_conn_with_protocols(
        port: u16,
        protocols: Vec<String>,
    ) -> Result<(WSSender, WSReceiver, Option<String>), String> {
        let socket_addr = SocketAddr::new(localhost(), port);
        let stream = TcpStream::connect(socket_addr).await.map_err(|e| {
            format!(
                "Connecting a TCP stream to the websocket server failed: {}",
                e
            )
        })?;
        let host = socket_addr.to_string();
        let mut client = handshake::Client::new(
            BufReader::new(BufWriter::new(stream.compat())),
            host.as_str(),
            "/",
        );
        protocols.iter().for_each(|protocol| {
            client.add_protocol(protocol.as_str());
        });
        let handshake_response = client
            .handshake()
            .await
            .map_err(|e| format!("Handshake with the websocket server failed: {}", e))?;
        let accepted_protocol_opt = match handshake_response {
            ServerResponse::Accepted {
                protocol: protocol_opt,
            } => protocol_opt,
            _ => {
                return Err(format!(
                    "Websocket server did not accept any of these subprotocols: {:?}: {:?}",
                    protocols, handshake_response
                ));
            }
        };
        let (sender, receiver) = client.into_builder().finish();
        Ok((sender, receiver, accepted_protocol_opt))
    }

    async fn await_message<T: FromMessageBody>(
        &mut self,
    ) -> Result<(MessagePath, T, Vec<ReceiveResult<T>>), (u64, String)> {
        let mut errors = Vec::new();
        // Keep looping until we get the specific message we're looking for; throw away all others
        loop {
            match self.receive_message::<T>(None).await {
                Correct(path, msg) => break Ok((path, msg, errors)),
                TransactionError(code, msg) => break Err((code, msg)),
                e => {
                    errors.push(e);
                    continue;
                }
            }
        }
    }

    pub async fn transact<S: ToMessageBody, R: FromMessageBody>(
        &mut self,
        payload: S,
    ) -> Result<(MessagePath, R), (u64, String)> {
        self.send(payload).await;
        let receive_result = self.receive_message::<R>(None).await;
        Self::standard_result_resolution(receive_result)
    }

    pub async fn transact_with_context_id<S: ToMessageBody, R: FromMessageBody>(
        &mut self,
        payload: S,
        context_id: u64,
    ) -> Result<(MessagePath, R), (u64, String)> {
        self.send_with_context_id(payload, context_id).await;
        Self::standard_result_resolution(self.receive_message::<R>(Some(context_id)).await)
    }

    pub async fn shutdown(&self) -> io::Result<()> {
        todo!("Drive this in, if necessary");
    }

    pub fn accepted_protocol(&self) -> Option<&str> {
        self.accepted_protocol_opt.as_ref().map(|p| p.as_str())
    }

    fn standard_result_resolution<T>(
        extended_result: ReceiveResult<T>,
    ) -> Result<(MessagePath, T), (u64, String)> {
        match extended_result {
            Correct(path, msg) => Ok((path, msg)),
            TransactionError(code, msg) => Err((code, msg)),
            MBMarshalError(msg, e) => {
                panic!("Deserialization of {:?} ended up with err: {:?}", msg, e)
            }
            MarshalError(msg, e) => {
                panic!("Deserialization of {:?} ended up with err: {:?}", msg, e)
            }
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum ReceiveResult<T> {
    Correct(MessagePath, T),
    TransactionError(u64, String),
    MBMarshalError(MessageBody, UiMessageError),
    MarshalError(NodeToUiMessage, UiMessageError),
}

impl<T> ReceiveResult<T> {
    pub fn correct(self) -> Result<T, String> {
        match self {
            Correct(_path, msg) => Ok(msg),
            TransactionError(code, msg) => Err(format!("Transaction error: {}: {}", code, msg)),
            MBMarshalError(msg, e) => Err(format!("Body marshal error: {:?}: {:?}", msg, e)),
            MarshalError(msg, e) => Err(format!("Marshal error: {:?}: {:?}", msg, e)),
        }
    }
}
