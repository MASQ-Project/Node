// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::communications::connection_manager::WSClientHandshakeHandler;
use async_channel::{Receiver, Sender};
use masq_lib::utils::localhost;
use std::sync::Arc;
use workflow_websocket::client::{Ack, Handshake, Message, WebSocket, WebSocketConfig};

pub struct WSTestClient {
    websocket: WebSocket,
}

impl WSTestClient {
    pub fn new(port: u16) -> Self {
        let url = format!("ws://{}:{}", localhost(), port);
        let mut config = WebSocketConfig::default();
        config.handshake = Some(Arc::new(WSClientHandshakeHandler::default()));
        let websocket = WebSocket::new(Some(&url), Some(config))
            .expect("Couldn't initialize websocket for client");
        Self { websocket }
    }

    pub fn split(self) -> (Receiver<Message>, Sender<(Message, Ack)>) {
        let rx = self.websocket.receiver_rx().clone();
        let tx = self.websocket.sender_tx().clone();
        (rx, tx)
    }
}
