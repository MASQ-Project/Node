// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::messages::{FromMessageBody, ToMessageBody, UiMessageError};
use crate::test_utils::ui_connection::ReceiveResult::{Correct, MarshalError, TransactionError};
use crate::test_utils::websockets_utils::establish_ws_conn_with_arbitrary_protocol;
use crate::ui_gateway::MessagePath::Conversation;
use crate::ui_gateway::MessageTarget::ClientId;
use crate::ui_gateway::NodeToUiMessage;
use crate::ui_traffic_converter::UiTrafficConverter;
use crate::utils::localhost;
use std::net::SocketAddr;
use std::{fmt, io};
use workflow_websocket::client::{Error, Message, WebSocket};
use std::fmt::{Debug, Formatter};
use crate::websockets_handshake::{WSSender, WSReceiver};
use soketto::Data as SokettoDataType;

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
        let (sender, receiver) = establish_ws_conn_with_arbitrary_protocol(port, protocol).await?;
        Ok(UiConnection {
            context_id: 0,
            local_addr: SocketAddr::new(localhost(), port),
            sender,
            receiver,
        })
    }
    //
    // fn make_initial_http_request(port: u16, protocol: &str) -> Request<()> {
    //     let url = format!("ws://{}:{}", localhost(), port);
    //     let websocket_key = (0..16)
    //         .into_iter()
    //         .map (|_| ((random::<u8>() % 95) + 32) as char)
    //         .collect::<String>();
    //     let mut websocket_key_encoded = String::new();
    //     BASE64_STANDARD.encode_string(websocket_key, &mut websocket_key_encoded);
    //     Builder::new()
    //         .method(Method::GET)
    //         .uri(url)
    //         .version(Version::HTTP_11)
    //         .header("Connection", "Upgrade")
    //         .header("Upgrade", "websocket")
    //         .header("Sec-Websocket-Key", websocket_key_encoded)
    //         .header("Sec-Websocket-Protocol", protocol)
    //         .header("Sec-Websocket-Version", "13")
    //         .body(())
    //         .unwrap()
    // }

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

    pub async fn send_string(&mut self, string: String) {
        self.sender.send_text_owned(string).await.expect("Failed to send message");
    }

    async fn receive_main<T: FromMessageBody>(
        &mut self,
        context_id: Option<u64>,
    ) -> ReceiveResult<T> {
        let mut message = Vec::new();
        let incoming_msg_json = loop {
            message.clear();
            match self.receiver.receive_data(&mut message).await {
                Ok(SokettoDataType::Binary(n)) if message.as_slice() == b"EMPTY QUEUE" => {
                    panic!("The queue is empty; all messages are gone.")
                }
                Ok(SokettoDataType::Text(n)) => {
                    break String::from_utf8(message).expect("Failed to convert message to string");
                }
                Err(e) => panic!("Reception error: {}", e),
                x => panic!(
                    "We received an unexpected message from the MockWebSocketServer: {:?}",
                    x
                ),
            }
        };

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
            Ok((payload, _)) => Correct(payload),
            Err(UiMessageError::PayloadError(message_body)) => {
                let payload_error = message_body
                    .payload
                    .expect_err("PayloadError message body contained no payload error");
                TransactionError(payload_error)
            }
            Err(e) => MarshalError((incoming_msg, e)),
        }
    }

    pub async fn skip_until_received<T: FromMessageBody>(&mut self) -> Result<T, (u64, String)> {
        Self::await_message(self).await
    }

    async fn await_message<T: FromMessageBody>(&mut self) -> Result<T, (u64, String)> {
        loop {
            match self.receive_main::<T>(None).await {
                Correct(msg) => break Ok(msg),
                TransactionError(e) => break Err(e),
                MarshalError(_) => continue,
            }
        }
    }

    pub async fn transact<S: ToMessageBody, R: FromMessageBody>(
        &mut self,
        payload: S,
    ) -> Result<R, (u64, String)> {
        self.send(payload).await;
        Self::standard_result_resolution(self.receive_main::<R>(None).await)
    }

    pub async fn transact_with_context_id<S: ToMessageBody, R: FromMessageBody>(
        &mut self,
        payload: S,
        context_id: u64,
    ) -> Result<R, (u64, String)> {
        self.send_with_context_id(payload, context_id).await;
        Self::standard_result_resolution(self.receive_main::<R>(Some(context_id)).await)
    }

    pub async fn shutdown(&self) -> io::Result<()> {
        todo!("Drive this in, if necessary");
    }

    fn standard_result_resolution<T>(
        extended_result: ReceiveResult<T>,
    ) -> Result<T, (u64, String)> {
        match extended_result {
            Correct(msg) => Ok(msg),
            TransactionError(e) => Err(e),
            MarshalError((msg, e)) => {
                panic!("Deserialization of {:?} ended up with err: {:?}", msg, e)
            }
        }
    }
}

pub enum ReceiveResult<T> {
    Correct(T),
    TransactionError((u64, String)),
    MarshalError((NodeToUiMessage, UiMessageError)),
}
