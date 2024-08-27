// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
//
// use async_channel::{Receiver, Sender};
// use std::time::Duration;
// use workflow_websocket::client::{Ack, ConnectOptions, ConnectStrategy, Message, WebSocket};
// use crate::test_utils::mocks::make_websocket;
//
// pub struct WSTestClient {
//     pub websocket: WebSocket,
// }
//
// impl WSTestClient {
//     pub fn new(port: u16) -> Self {
//         let websocket = make_websocket(port);
//         Self { websocket }
//     }
//
//     pub async fn connect(&self){
//         let mut connect_options = ConnectOptions::default();
//         connect_options.block_async_connect = true;
//         connect_options.connect_timeout = Some(Duration::from_millis(1000));
//         connect_options.strategy = ConnectStrategy::Fallback;
//         self.websocket.connect(connect_options).await.expect("Connecting to the websocket server failed");
//     }
//
//     pub fn split(&self) -> (Receiver<Message>, Sender<(Message, Ack)>) {
//         if !self.websocket.is_open() {
//             panic!("WSTestClient: No open connection found. Make sure to call the 'connect' method.")
//         }
//         let rx = self.websocket.receiver_rx().clone();
//         let tx = self.websocket.sender_tx().clone();
//         (rx, tx)
//     }
// }
