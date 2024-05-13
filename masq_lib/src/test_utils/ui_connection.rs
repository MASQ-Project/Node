// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::messages::{FromMessageBody, ToMessageBody, UiMessageError};
use crate::test_utils::ui_connection::ReceiveResult::{Correct, MarshalError, TransactionError};
use crate::ui_gateway::NodeToUiMessage;
use crate::ui_traffic_converter::UiTrafficConverter;
use crate::utils::localhost;
use std::net::{SocketAddr};
use workflow_websocket::client::{WebSocket, ConnectOptions};
use workflow_websocket::server::{Message};
use crate::test_utils::utils::make_rt;

pub struct UiConnection {
    context_id: u64,
    local_addr: SocketAddr,
    websocket: WebSocket,
}

impl UiConnection {
    pub async fn make(port: u16, protocol: &str) -> Result<UiConnection, String> {
        let ws = match WebSocket::new(Some(format!("ws://localhost:{}", port).as_str()), None) {
            Err(e) => return Err(format!("{:?}", e)),
            Ok(ws) => ws,
        };
        match ws.connect(ConnectOptions::default()).await {
            Err(e) => Err(format!("{:?}", e)),
            Ok(_) => Ok(UiConnection {
                context_id: 0,
                local_addr: SocketAddr::new(localhost(), port),
                websocket: ws,
            }),
        }
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

    pub fn new(port: u16, protocol: &str) -> UiConnection {
        let future = Self::make(port, protocol);
        make_rt().block_on(future).unwrap()
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
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
        self.send_message(&Message::Text(string))
    }

    pub fn send_message(&mut self, message: Message) {
        self.websocket.send(message.into());
    }

    fn receive_main<T: FromMessageBody>(&mut self, context_id: Option<u64>) -> ReceiveResult<T> {
        todo!()
        // let incoming_msg_json = match self.stream.next().unwrap() {
        //     Ok(Message::Binary(bytes)) if bytes == b"EMPTY QUEUE" => {
        //         panic!("The queue is empty; all messages are gone.")
        //     }
        //     Ok(Message::Text(json)) => json,
        //     x => panic!(
        //         "We received an unexpected message from the MockWebSocketServer: {:?}",
        //         x
        //     ),
        // };
        //
        // let incoming_msg = UiTrafficConverter::new_unmarshal_to_ui(&incoming_msg_json, ClientId(0))
        //     .unwrap_or_else(|_| panic!("Deserialization problem with: {}: ", &incoming_msg_json));
        // if let Some(testing_id) = context_id {
        //     match incoming_msg.body.path {
        //         Conversation(id) if id == testing_id => (),
        //         Conversation(id) if id != testing_id => panic!(
        //             "Context ID of the request and the response don't match; message: \
        //  {:?}, request id: {}, response id: {}",
        //             incoming_msg, testing_id, id
        //         ),
        //         _ => (),
        //     }
        // }
        //
        // let result: Result<(T, u64), UiMessageError> = T::fmb(incoming_msg.body.clone());
        // match result {
        //     Ok((payload, _)) => Correct(payload),
        //     Err(UiMessageError::PayloadError(message_body)) => {
        //         let payload_error = message_body
        //             .payload
        //             .expect_err("PayloadError message body contained no payload error");
        //         TransactionError(payload_error)
        //     }
        //     Err(e) => MarshalError((incoming_msg, e)),
        // }
    }

    pub fn skip_until_received<T: FromMessageBody>(&mut self) -> Result<T, (u64, String)> {
        Self::await_message(self)
    }

    fn await_message<T: FromMessageBody>(&mut self) -> Result<T, (u64, String)> {
        loop {
            match self.receive_main::<T>(None) {
                Correct(msg) => break Ok(msg),
                TransactionError(e) => break Err(e),
                MarshalError(_) => continue,
            }
        }
    }

    pub fn transact<S: ToMessageBody, R: FromMessageBody>(
        &mut self,
        payload: S,
    ) -> Result<R, (u64, String)> {
        self.send(payload);
        Self::standard_result_resolution(self.receive_main::<R>(None))
    }

    pub fn transact_with_context_id<S: ToMessageBody, R: FromMessageBody>(
        &mut self,
        payload: S,
        context_id: u64,
    ) -> Result<R, (u64, String)> {
        self.send_with_context_id(payload, context_id);
        Self::standard_result_resolution(self.receive_main::<R>(Some(context_id)))
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
