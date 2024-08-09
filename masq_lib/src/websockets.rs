// Copyright (c) 2024, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use std::time::Duration;
use async_trait::async_trait;
use tokio::select;
use workflow_websocket::client::Handshake;
use workflow_websocket::client::Message;
use crate::messages::NODE_UI_PROTOCOL;

#[derive(Default)]
pub struct WSClientHandshakeHandler { timeout: Duration}

#[async_trait]
impl Handshake for WSClientHandshakeHandler {
    async fn handshake(
        &self,
        sender: &async_channel::Sender<Message>,
        receiver: &async_channel::Receiver<Message>,
    ) -> workflow_websocket::client::Result<()> {
        match sender.send(Message::Text(NODE_UI_PROTOCOL.to_string())).await{
           Err(e) => todo!(),
            Ok(_) => ()
        }

        let fut = async {
            let server_response = match receiver.recv().await {
              Ok(res) => todo!(),
                Err(e) => todo!()
            };
        };

        //Err(NegotiationFailure)

        tokio::time::timeout(self.timeout, fut).await.map_err(|e|todo!())
    }
}