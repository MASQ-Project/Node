// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::messages::{FromMessageBody, ToMessageBody, UiMessageError};
use crate::test_utils::ui_connection::ReceiveResult::{Correct, MarshalError, TransactionError};
use crate::ui_gateway::MessagePath::Conversation;
use crate::ui_gateway::MessageTarget::ClientId;
use crate::ui_gateway::{MessagePath, NodeToUiMessage};
use crate::ui_traffic_converter::UiTrafficConverter;
use crate::utils::localhost;
use crate::websockets_types::{WSSender, WSReceiver};
use std::net::SocketAddr;
use std::{fmt, io};
use workflow_websocket::client::{Error, Message, WebSocket};
use std::fmt::{Debug, Formatter};
use futures_util::io::{BufReader, BufWriter};
use soketto::{handshake, Data as SokettoDataType};
use soketto::data::ByteSlice125;
use soketto::handshake::ServerResponse;
use tokio::net::TcpStream;
use tokio_util::compat::TokioAsyncReadCompatExt;

pub struct UiConnection {
    context_id: u64,
    local_addr: SocketAddr,
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
        let (sender, receiver) = Self::establish_ws_conn_with_protocols(port,
   vec![protocol.to_string()]).await.unwrap();
        Ok(UiConnection {
            context_id: 0,
            local_addr: SocketAddr::new(localhost(), port),
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
        self.sender.close().await.expect("Failed to close connection");
    }

    pub async fn send_data(&mut self, data: Vec<u8>) {
        self.sender.send_binary(data).await.expect("Failed to send data");
        self.sender.flush().await.expect("Failed to flush data");
    }

    pub async fn send_string(&mut self, string: String) {
        self.sender.send_text_owned(string).await.expect("Failed to send message");
        self.sender.flush().await.expect("Failed to flush message");
    }

    pub async fn send_ping(&mut self, data: Vec<u8>) {
        self.sender.send_ping(ByteSlice125::try_from(data.as_slice()).unwrap()).await.expect("Failed to send ping");
        self.sender.flush().await.expect("Failed to flush ping");
    }

    pub async fn send_pong(&mut self, data: Vec<u8>) {
        self.sender.send_pong(ByteSlice125::try_from(data.as_slice()).unwrap()).await.expect("Failed to send pong");
        self.sender.flush().await.expect("Failed to flush pong");
    }

    async fn receive(&mut self) -> (SokettoDataType, Vec<u8>) {
        let mut message = Vec::new();
        let data_type = self.receiver.receive_data(&mut message).await.expect("Failed to receive message");
        match data_type {
            SokettoDataType::Binary(_) => if message.as_slice() == b"EMPTY_QUEUE" {
                panic!("The queue is empty; all messages are gone.")
            },
            _ => ()
        }
        (data_type, message)
    }

    pub async fn receive_data(&mut self) -> Vec<u8> {
        let (data_type, message) = self.receive().await;
        if let SokettoDataType::Binary(_) = data_type {
            message
        }
        else {
            panic!("Expected a binary message, but received a text message")
        }
    }

    pub async fn receive_string(&mut self) -> String {
        let (data_type, message) = self.receive().await;
        if let SokettoDataType::Text(_) = data_type {
            String::from_utf8(message).expect("Failed to convert message to string")
        }
        else {
            panic!("Expected a text message, but received a binary message")
        }
    }

    pub async fn receive_message<T: FromMessageBody>(
        &mut self,
        context_id: Option<u64>,
    ) -> ReceiveResult<T> {
        let incoming_msg_json = self.receive_string().await;
        let incoming_msg = UiTrafficConverter::new_unmarshal_to_ui(&incoming_msg_json, ClientId(0))
            .unwrap_or_else(|_| panic!("Deserialization problem with: {}: ", &incoming_msg_json));
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

        let result: Result<(T, u64), UiMessageError> = T::fmb(incoming_msg.body.clone());
        match result {
            Ok((payload, _)) => Correct(incoming_msg.body.path, payload),
            Err(UiMessageError::PayloadError(message_body)) => {
                let payload_error = message_body
                    .payload
                    .expect_err("PayloadError message body contained no payload error");
                TransactionError(payload_error.0, payload_error.1)
            }
            Err(e) => MarshalError(incoming_msg, e),
        }
    }

    pub async fn skip_until_received<T: FromMessageBody>(&mut self) -> Result<(MessagePath, T), (u64, String)> {
        Self::await_message(self).await
    }

    async fn establish_ws_conn_with_protocols(
        port: u16,
        protocols: Vec<String>,
    ) -> Result<(WSSender, WSReceiver), String> {
        let socket_addr = SocketAddr::new(localhost(), port);
        let stream = TcpStream::connect(socket_addr)
            .await
            .map_err(|e| format!("Connecting a TCP stream to the websocket server failed: {}", e))?;
        let host = socket_addr.to_string();
        let mut client = handshake::Client::new(
            BufReader::new(BufWriter::new(stream.compat())),
            host.as_str(),
            "/"
        );
        protocols.iter().for_each (|protocol| {client.add_protocol(protocol.as_str());});
        let handshake_response = client
            .handshake()
            .await
            .map_err(|e| format!("Handshake with the websocket server failed: {}", e))?;
        match handshake_response {
            ServerResponse::Accepted { protocol: protocol_opt } => {
                // TODO: Record protocol_opt somehow so that it can be asserted
            }
            _ => {
                return Err(format!("Websocket server did not accept any of these subprotocols: {:?}: {:?}",
                                   protocols, handshake_response));
            }
        }
        let (sender, receiver) = client.into_builder().finish();
        Ok((sender, receiver))
    }

    async fn await_message<T: FromMessageBody>(&mut self) -> Result<(MessagePath, T), (u64, String)> {
        loop {
            match self.receive_message::<T>(None).await {
                Correct(path, msg) => break Ok((path, msg)),
                TransactionError(code, msg) => break Err((code, msg)),
                MarshalError(_, _) => continue,
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

    fn standard_result_resolution<T>(
        extended_result: ReceiveResult<T>,
    ) -> Result<(MessagePath, T), (u64, String)> {
        match extended_result {
            Correct(path, msg) => Ok((path, msg)),
            TransactionError(code, msg) => Err((code, msg)),
            MarshalError(msg, e) => {
                // TODO: This msg is something that came in from outside; the rules say it's not
                // allowed to panic us. We should probably log it and return an error.
                panic!("Deserialization of {:?} ended up with err: {:?}", msg, e)
            }
        }
    }
}

pub enum ReceiveResult<T> {
    Correct(MessagePath, T),
    TransactionError(u64, String),
    MarshalError(NodeToUiMessage, UiMessageError),
}
