// Copyright (c) 2024, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
use std::net::SocketAddr;
use futures_util::io::{BufReader, BufWriter};
use soketto::handshake;
// use crate::messages::NODE_UI_PROTOCOL;
// use async_channel::{Receiver, Sender};
// use futures_util::TryFutureExt;
// use std::sync::{Arc, Mutex};
// use std::time::Duration;
// use tokio::sync::mpsc::unbounded_channel;
// use workflow_websocket::client::{Ack, Message, WebSocket};
// use workflow_websocket::client::{ConnectOptions, Handshake, WebSocketConfig};
use soketto::handshake::{Client, ServerResponse};
use tokio::net::TcpStream;
use tokio_util::compat::TokioAsyncReadCompatExt;
use crate::utils::localhost;
use crate::websockets_handshake::{WSReceiver, WSSender};
//
// pub async fn establish_ws_conn_with_handshake(port: u16) -> WebSocket {
//     establish_ws_conn_with_arbitrary_protocol(port, NODE_UI_PROTOCOL)
//         .await
//         .unwrap()
// }

pub async fn establish_ws_conn_with_arbitrary_protocol(
    port: u16,
    protocol: &'static str,
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
    let handshake_response = client
        .add_protocol(protocol)
        .handshake()
        .await
        .map_err(|e| format!("Handshake with the websocket server failed: {}", e))?;
    if ! matches!(&handshake_response, ServerResponse::Accepted { protocol: Some(protocol) }) {
        return Err(format!("Websocket server did not accept protocol {}: {:?}", protocol, handshake_response));
    }
    let (sender, receiver) = client.into_builder().finish();
    Ok((sender, receiver))
}
//
// pub async fn websocket_utils_with_masq_handshake(
//     port: u16,
// ) -> (WebSocket, Sender<(Message, Ack)>, Receiver<Message>) {
//     let ws = establish_ws_conn_with_handshake(port).await;
//     arrange_utils(ws)
// }
//
// pub async fn websocket_utils_without_handshake(
//     port: u16,
// ) -> (WebSocket, Sender<(Message, Ack)>, Receiver<Message>) {
//     let url = ws_url(port);
//     let config = WebSocketConfig::default();
//     let ws = WebSocket::new(Some(&url), Some(config)).unwrap();
//     let connect_options = ConnectOptions::default();
//     ws.connect(connect_options).await.unwrap();
//     arrange_utils(ws)
// }
//
// fn arrange_utils(ws: WebSocket) -> (WebSocket, Sender<(Message, Ack)>, Receiver<Message>) {
//     let talker_half = ws.sender_tx().clone();
//     let listener_half = ws.receiver_rx().clone();
//     (ws, talker_half, listener_half)
// }
//
// #[derive(Default)]
// pub struct WSHandshakeHandlerFactoryMock {
//     make_params: Arc<Mutex<Vec<HandshakeResultTx>>>,
//     make_results: Arc<Mutex<Vec<WSHandshakeHandlerFactoryResult>>>,
// }
//
// impl WSHandshakeHandlerFactory for WSHandshakeHandlerFactoryMock {
//     fn make(&self, confirmation_rx: HandshakeResultTx) -> Arc<dyn Handshake> {
//         self.make_params
//             .lock()
//             .unwrap()
//             .push(confirmation_rx.clone());
//         match self.make_results.lock().unwrap().remove(0) {
//             WSHandshakeHandlerFactoryResult::Complete(handler) => handler,
//             WSHandshakeHandlerFactoryResult::ToBeConstructed(handler_constructor) => {
//                 handler_constructor(confirmation_rx)
//             }
//         }
//     }
// }
//
// impl WSHandshakeHandlerFactoryMock {
//     pub fn make_params(mut self, params: Arc<Mutex<Vec<HandshakeResultTx>>>) -> Self {
//         self.make_params = params.clone();
//         self
//     }
//
//     pub fn make_plain_result(self, result: Arc<dyn Handshake>) -> Self {
//         self.make_results
//             .lock()
//             .unwrap()
//             .push(WSHandshakeHandlerFactoryResult::Complete(result));
//         self
//     }
//
//     pub fn make_result_constructor(
//         self,
//         constructor: Box<dyn FnOnce(HandshakeResultTx) -> Arc<dyn Handshake> + Send>,
//     ) -> Self {
//         self.make_results
//             .lock()
//             .unwrap()
//             .push(WSHandshakeHandlerFactoryResult::ToBeConstructed(
//                 constructor,
//             ));
//         self
//     }
// }
//
// enum WSHandshakeHandlerFactoryResult {
//     Complete(Arc<dyn Handshake>),
//     ToBeConstructed(Box<dyn FnOnce(HandshakeResultTx) -> Arc<dyn Handshake> + Send>),
// }
