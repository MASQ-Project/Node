// Copyright (c) 2024, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::messages::NODE_UI_PROTOCOL;
use crate::utils::localhost;
use crate::websockets_handshake::{ws_url, HandshakeResultTx, MASQWSClientHandshakeHandler, WSClientConnectionInitiator, WS_CLIENT_CONNECT_TIMEOUT_MS};
use async_channel::{Receiver, Sender};
use futures_util::TryFutureExt;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use workflow_websocket::client::{Ack, Message, WebSocket};
use workflow_websocket::client::{ConnectOptions, Handshake, WebSocketConfig};

pub async fn establish_ws_conn_with_handshake(port: u16) -> WebSocket {
    establish_ws_conn_with_arbitrary_protocol(port, NODE_UI_PROTOCOL)
        .await
        .unwrap()
}

pub async fn establish_ws_conn_with_arbitrary_protocol(
    port: u16,
    protocol: &'static str,
) -> Result<WebSocket, String> {
    let prepare_handshake_handler =
        Box::new(|tx: HandshakeResultTx| -> Arc<dyn Handshake> {
            Arc::new(MASQWSClientHandshakeHandler::new(
                Duration::from_millis(500),
                protocol,
                tx,
            ))
        });
    let set_global_timeout = Duration::from_millis(4_000);
    let connect_timeout = Duration::from_millis(WS_CLIENT_CONNECT_TIMEOUT_MS);
    let mut connector = WSClientConnectionInitiator::new_with_full_setup(port, prepare_handshake_handler, set_global_timeout, connect_timeout);
    connector
        .connect_with_timeout()
        .await
        .map_err(|e| format!("Connecting to the websocket server failed: {}", e))
}

pub async fn websocket_utils(port: u16) -> (WebSocket, Sender<(Message, Ack)>, Receiver<Message>) {
    let ws = establish_ws_conn_with_handshake(port).await;
    arrange_utils(ws)
}

pub async fn websocket_utils_without_handshake(
    port: u16,
) -> (WebSocket, Sender<(Message, Ack)>, Receiver<Message>) {
    let url = ws_url(port);
    let config = WebSocketConfig::default();
    let ws = WebSocket::new(Some(&url), Some(config)).unwrap();
    let connect_options = ConnectOptions::default();
    ws.connect(connect_options).await.unwrap();
    arrange_utils(ws)
}

fn arrange_utils(ws: WebSocket) -> (WebSocket, Sender<(Message, Ack)>, Receiver<Message>) {
    let talker_half = ws.sender_tx().clone();
    let listener_half = ws.receiver_rx().clone();
    (ws, talker_half, listener_half)
}
