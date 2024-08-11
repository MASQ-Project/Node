// Copyright (c) 2024, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use std::time::Duration;
use async_trait::async_trait;
use tokio::select;
use workflow_websocket::client::Handshake;
use workflow_websocket::client::Message;
use workflow_websocket::client::result::Result as ClientResult;
use workflow_websocket::client::Error as ClientError;
use workflow_websocket::server::result::Result as ServerResult;
use workflow_websocket::server::Error as ServerError;
use crate::messages::NODE_UI_PROTOCOL;

pub const WS_CLIENT_CONNECT_TIMEOUT_MS: u64 = 2000;

#[derive(Default)]
pub struct WSClientHandshakeHandler { timeout: Duration}

impl WSClientHandshakeHandler{
    pub fn new(timeout: Duration)->Self{
        Self{
            timeout
        }
    }
}

#[async_trait]
impl Handshake for WSClientHandshakeHandler {
    async fn handshake(
        &self,
        sender: &async_channel::Sender<Message>,
        receiver: &async_channel::Receiver<Message>,
    ) -> ClientResult<()> {
        match sender.send(Message::Text(NODE_UI_PROTOCOL.to_string())).await{
           Err(e) => return Err(ClientError::ChannelSend),
            Ok(_) => ()
        }

        let fut = async {
            match receiver.recv().await {
              Ok(Message::Open) => Ok(()),
                Ok(Message::Close) => Err(ClientError::NegotiationFailure),
                Ok(x) => Err(ClientError::Custom(format!("Unexpected response on handshake from server: {:?}", x))),
                Err(_) => Err(ClientError::ReceiveChannel)
            }
        };

        match tokio::time::timeout(self.timeout, fut).await{
            Ok(Ok(())) => Ok(()),
            Ok(e) => e,
            Err(elapsed) => Err(ClientError::ConnectionTimeout)
        }
    }
}

pub fn verify_masq_ws_subprotocol(msg: &str)-> ServerResult<()>{
    if msg == NODE_UI_PROTOCOL{
        Ok(())
    } else {
        Err(ServerError::MalformedHandshake)
    }
}

#[cfg(test)]
mod tests {
    use clap::builder::TypedValueParser;
    use futures_util::future::join_all;
    use super::*;
    use tokio::task::JoinHandle;
    use crate::messages::NODE_UI_PROTOCOL;
    use crate::websockets_handshake::WS_CLIENT_CONNECT_TIMEOUT_MS;
    use crate::websockets_handshake::{verify_masq_ws_subprotocol, WSClientHandshakeHandler};

    #[test]
    fn constants_are_correct(){
        assert_eq!(WS_CLIENT_CONNECT_TIMEOUT_MS,2000)
    }

    #[tokio::test]
    async fn client_handshake_handler_happy_path(){
        let (subject, to_server_tx, from_server_rx, server_join_handle) = setup_for_full_client_server_msg_exchange(Message::Open);

        let result = subject.handshake(&to_server_tx, &from_server_rx).await;

        match result {
            Ok(()) => (),
            Err(e) => panic!("We expected Ok(()) but received {:?}", e)
        }
        let sent_msg = server_join_handle.await.unwrap();
        assert_eq!(sent_msg, Message::Text(NODE_UI_PROTOCOL.to_string()))
    }

    #[tokio::test]
    async fn client_handshake_handler_timeout_error(){
        let subject = WSClientHandshakeHandler::new(Duration::from_millis(5));
        let (to_server_tx, _to_server_rx) = async_channel::unbounded();
        let (_from_server_tx, from_server_rx) = async_channel::unbounded();

        let result = subject.handshake(&to_server_tx, &from_server_rx).await;

        match result {
            Err(ClientError::ConnectionTimeout) => (),
            x => panic!("Expected ConnectionTimeout error but got {:?}", x)
        }
    }

    #[tokio::test]
    async fn client_handshake_handler_sender_error(){
        let subject = WSClientHandshakeHandler::new(Duration::from_millis(WS_CLIENT_CONNECT_TIMEOUT_MS));
        let (to_server_tx, _) = async_channel::unbounded();
        let (_from_server_tx, from_server_rx) = async_channel::unbounded();

        let result = subject.handshake(&to_server_tx, &from_server_rx).await;

        match result {
            Err(ClientError::ChannelSend) => (),
            x => panic!("Expected ChannelSend error but got {:?}", x)
        }
    }

    #[tokio::test]
    async fn client_handshake_handler_receiver_error(){
        let subject = WSClientHandshakeHandler::new(Duration::from_millis(WS_CLIENT_CONNECT_TIMEOUT_MS));
        let (to_server_tx, _to_server_rx) = async_channel::unbounded();
        let (_, from_server_rx) = async_channel::unbounded();

        let result = subject.handshake(&to_server_tx, &from_server_rx).await;

        match result {
            Err(ClientError::ReceiveChannel) => (),
            x => panic!("Expected ReceiveChannel error but got {:?}", x)
        }
    }

    #[tokio::test]
    async fn client_handshake_server_negotioation_failure(){
        let (subject, to_server_tx, from_server_rx, server_join_handle) = setup_for_full_client_server_msg_exchange(Message::Close);

        let result = subject.handshake(&to_server_tx, &from_server_rx).await;

        match result {
            Err(ClientError::NegotiationFailure) => (),
            x => panic!("Expected NegotiationFailure error but got {:?}", x)
        }
        let sent_msg = server_join_handle.await.unwrap();
        assert_eq!(sent_msg, Message::Text(NODE_UI_PROTOCOL.to_string()))
    }

    #[tokio::test]
    async fn client_handshake_unexpected_msg_from_server(){
        let input_and_expected = vec![
            (Message::Binary(b"Binary crap".to_vec()), "Unexpected response on handshake from server: Binary([66, 105, 110, 97, 114, 121, 32, 99, 114, 97, 112])"),
            (Message::Text("Literal crap".to_string()), "Unexpected response on handshake from server: Text(\"Literal crap\")")
        ];

        join_all(input_and_expected.into_iter().enumerate().map(|(idx, (server_response, expected_err_msg))| async move {
            let (subject, to_server_tx, from_server_rx, server_join_handle) = setup_for_full_client_server_msg_exchange(server_response);

            let result = subject.handshake(&to_server_tx, &from_server_rx).await;

            match result {
                Err(ClientError::Custom(msg)) if msg == expected_err_msg => (),
                x => panic!("Item {}: Expected Custom error with message {} but got {:?}", idx + 1, expected_err_msg, x)
            };
            let sent_msg = server_join_handle.await.unwrap();
            assert_eq!(sent_msg, Message::Text(NODE_UI_PROTOCOL.to_string()))
        })).await;
    }

    fn setup_for_full_client_server_msg_exchange(server_response: Message) ->(WSClientHandshakeHandler, async_channel::Sender<Message>, async_channel::Receiver<Message>, JoinHandle<Message>){
        let subject = WSClientHandshakeHandler::new(Duration::from_millis(WS_CLIENT_CONNECT_TIMEOUT_MS));
        let (to_server_tx, to_server_rx) = async_channel::unbounded();
        let (from_server_tx, from_server_rx) = async_channel::unbounded();
        let mocked_server = async move {
            let receive_res =   tokio::time::timeout(Duration::from_millis(2000),to_server_rx.recv()).await.unwrap();
            let msg_from_client: Message = receive_res.unwrap();
            from_server_tx.send(server_response).await.unwrap();
            msg_from_client
        };
        let server_join_handle = tokio::task::spawn(mocked_server);
        (subject, to_server_tx, from_server_rx, server_join_handle)
    }

    #[test]
    fn subprotocol_verified_correct(){
        let protocol = NODE_UI_PROTOCOL;

        assert_eq!(verify_masq_ws_subprotocol(protocol).is_ok(), true);
    }

    #[test]
    fn subprotocol_verified_wrong(){
        let protocols = vec![
            format!("a{}", NODE_UI_PROTOCOL),
            format!("{}1", NODE_UI_PROTOCOL),
            {
                let prt = NODE_UI_PROTOCOL;
                prt.chars().rev().collect::<String>()
            }];

        protocols.into_iter().enumerate().for_each(|(idx, protocol)| {
            let result = verify_masq_ws_subprotocol(&protocol);
            match result {
                Err(ServerError::MalformedHandshake) => (),
                x => panic!("Item {}: We expected MalformedHandshake err but got {:?}", idx + 1, x)
            }
        })
    }
}