// Copyright (c) 2024, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use std::sync::Arc;
use std::time::Duration;
use async_channel::{Receiver, Sender};
use crate::utils::localhost;
use crate::websockets::WSClientHandshakeHandler;
use workflow_websocket::client::{Ack, Message, WebSocket};
use workflow_websocket::client::WebSocketConfig;
use workflow_websocket::client::ConnectOptions;
use workflow_websocket::client::ConnectStrategy;
use crate::messages::NODE_UI_PROTOCOL;

pub async fn establish_ws_conn_with_handshake(port: u16) -> WebSocket {
    let websocket = establish_bare_ws_conn(port).await;
    websocket.send(Message::Text(NODE_UI_PROTOCOL.to_string())).await.expect("couldn't send a handshake protocol");
    websocket
}

pub async fn establish_bare_ws_conn(port: u16)->WebSocket{
    let url = format!("ws://{}:{}", localhost(), port);
    let mut config = WebSocketConfig::default();
    config.handshake = Some(Arc::new(WSClientHandshakeHandler::default()));
    let websocket = WebSocket::new(Some(&url), Some(config))
        .expect("Couldn't initialize websocket for the client");
    connect(&websocket).await;
    websocket
}

async fn connect(websocket: &WebSocket) {
    let mut connect_options = ConnectOptions::default();
    connect_options.block_async_connect = true;
    connect_options.connect_timeout = Some(Duration::from_millis(40000));
    connect_options.strategy = ConnectStrategy::Fallback;
    websocket
        .connect(connect_options)
        .await
        .expect("Connecting to the websocket server failed");
}

pub async fn websocket_utils(port: u16) -> (WebSocket, Sender<(Message, Ack)>, Receiver<Message>) {
    let websocket = establish_ws_conn_with_handshake(port).await;
    let talker_half = websocket.sender_tx().clone();
    let listener_half = websocket.receiver_rx().clone();
    (websocket, talker_half, listener_half)
}