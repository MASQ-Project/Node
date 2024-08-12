// Copyright (c) 2024, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use std::sync::Arc;
use std::time::Duration;
use async_channel::{Receiver, Sender};
use futures_util::TryFutureExt;
use crate::utils::localhost;
use crate::websockets_handshake::{client_connect_with_timeout, WSClientHandshakeHandler};
use workflow_websocket::client::{Ack, Message, WebSocket};
use workflow_websocket::client::WebSocketConfig;
use workflow_websocket::client::ConnectOptions;
use workflow_websocket::client::ConnectStrategy;
use crate::messages::NODE_UI_PROTOCOL;

pub async fn establish_ws_conn_with_handshake(port: u16) -> WebSocket {
    establish_ws_conn_with_arbitrary_handshake(port, NODE_UI_PROTOCOL).await.unwrap()
}

pub async fn establish_ws_conn_with_arbitrary_handshake(port: u16, protocol: &str)-> Result<WebSocket, String>{
    let ws = establish_bare_ws_conn(port).await?;
    while !ws.is_open(){
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    ws.send(Message::Text(protocol.to_string())).await.expect("Couldn't send the protocol for a handshake");
    Ok(ws)
}

pub async fn establish_bare_ws_conn(port: u16)->Result<WebSocket, String>{
    let url = format!("ws://{}:{}", localhost(), port);
    let mut config = WebSocketConfig::default();
    config.handshake = Some(Arc::new(WSClientHandshakeHandler::default()));
    let ws = WebSocket::new(Some(&url), Some(config)).map_err(|e|format!("Failed to establish websocket for {}", url))?;
    connect(ws).await
}

async fn connect(ws: WebSocket) -> Result<WebSocket, String>{
    client_connect_with_timeout(ws, Duration::from_millis(2000)).await.map_err(|e|format!("Connecting to the websocket server failed: {}", e))
}

pub async fn websocket_utils(port: u16) -> (WebSocket, Sender<(Message, Ack)>, Receiver<Message>) {
    let ws = establish_ws_conn_with_handshake(port).await;
    let talker_half = ws.sender_tx().clone();
    let listener_half = ws.receiver_rx().clone();
    (ws, talker_half, listener_half)
}