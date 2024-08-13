// Copyright (c) 2024, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::messages::NODE_UI_PROTOCOL;
use crate::utils::localhost;
use crate::websockets_handshake::{client_connect_with_timeout, WSClientHandshakeHandler};
use async_channel::{Receiver, Sender};
use futures_util::TryFutureExt;
use std::sync::Arc;
use std::time::Duration;
use workflow_websocket::client::ConnectOptions;
use workflow_websocket::client::ConnectStrategy;
use workflow_websocket::client::WebSocketConfig;
use workflow_websocket::client::{Ack, Message, WebSocket};

pub async fn establish_ws_conn_with_handshake(port: u16) -> WebSocket {
    establish_ws_conn_with_arbitrary_handshake(port, NODE_UI_PROTOCOL)
        .await
        .unwrap()
}

pub async fn establish_ws_conn_with_arbitrary_handshake(
    port: u16,
    protocol: &str,
) -> Result<WebSocket, String> {
    let url = format!("ws://{}:{}", localhost(), port);
    let mut config = WebSocketConfig::default();
    let (tx, rx) = tokio::sync::oneshot::channel();
    config.handshake = Some(Arc::new(WSClientHandshakeHandler::new(
        Duration::from_millis(500),
        protocol,
        tx,
    )));
    let ws = WebSocket::new(Some(&url), Some(config))
        .map_err(|e| format!("Failed to establish websocket for {}", url))?;
    connect(ws, rx).await
}

async fn connect(
    ws: WebSocket,
    successful_handshake_rx: tokio::sync::oneshot::Receiver<()>,
) -> Result<WebSocket, String> {
    client_connect_with_timeout(ws, Duration::from_millis(5_000), successful_handshake_rx)
        .await
        .map_err(|e| format!("Connecting to the websocket server failed: {}", e))
}

pub async fn websocket_utils(port: u16) -> (WebSocket, Sender<(Message, Ack)>, Receiver<Message>) {
    let ws = establish_ws_conn_with_handshake(port).await;
    let talker_half = ws.sender_tx().clone();
    let listener_half = ws.receiver_rx().clone();
    (ws, talker_half, listener_half)
}
