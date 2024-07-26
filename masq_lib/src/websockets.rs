// Copyright (c) 2024, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use async_trait::async_trait;
use time::Duration;
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
        sender.send(Message::Text(NODE_UI_PROTOCOL.to_string())).await.map_err(|e| todo!())
        // let delay = tokio::time::sleep(self.timeout);
        // select! {
        //     rcv_res = receiver.recv() => {
        //         todo!()
        //     },
        //     _ = delay => {
        //         todo!()
        //     }
        // }
        //
        // incoming_msg = receiver.recv().await;
        // match incoming_msg {
        //     Message::Text(text) if text.contains(NODE_UI_PROTOCOL) => {
        //         todo!()
        //         //sender.send(Message::Open).await.unwrap();
        //         //Ok(())
        //     }
        //     _ => {
        //         todo!()
        //         //sender.send(Message::Close).await.unwrap();
        //         //Err(NegotiationFailure)
        //     }
        // }
    }
}