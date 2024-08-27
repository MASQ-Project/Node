// Copyright (c) 2024, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::messages::NODE_UI_PROTOCOL;
use async_trait::async_trait;
use clap::builder::TypedValueParser;
use futures_util::{FutureExt, SinkExt, StreamExt};
use std::future::Future;
use std::net::SocketAddr;
use std::time::Duration;
use workflow_websocket::client::result::Result as ClientResult;
use workflow_websocket::client::ConnectStrategy::{Fallback, Retry};
use workflow_websocket::client::Error as ClientError;
use workflow_websocket::client::Message as ClientMessage;
use workflow_websocket::client::{ConnectOptions, ConnectResult, Handshake, WebSocket};
use workflow_websocket::server::result::Result as ServerResult;
use workflow_websocket::server::Message as ServerMessage;
use workflow_websocket::server::{Error as ServerError, WebSocketReceiver, WebSocketSender};

pub const WS_CLIENT_CONNECT_TIMEOUT_MS: u64 = 2000;

pub struct WSClientHandshakeHandler {
    timeout: Duration,
    protocol: String,
    successful_handshake_tx: tokio::sync::oneshot::Sender<()>,
}

impl WSClientHandshakeHandler {
    pub fn new(
        timeout: Duration,
        protocol: &str,
        successful_handshake_tx: tokio::sync::oneshot::Sender<()>,
    ) -> Self {
        let protocol = protocol.to_string();
        Self {
            timeout,
            protocol,
            successful_handshake_tx,
        }
    }
}

#[async_trait]
impl Handshake for WSClientHandshakeHandler {
    async fn handshake(
        &self,
        sender: &async_channel::Sender<ClientMessage>,
        receiver: &async_channel::Receiver<ClientMessage>,
    ) -> ClientResult<()> {
        match sender
            .send(ClientMessage::Text(NODE_UI_PROTOCOL.to_string()))
            .await
        {
            Err(e) => return Err(ClientError::ChannelSend),
            Ok(_) => (),
        }

        let fut = async {
            match receiver.recv().await {
                Ok(ClientMessage::Open) => Ok(()),
                Ok(ClientMessage::Close) => Err(ClientError::NegotiationFailure),
                Ok(x) => Err(ClientError::Custom(format!(
                    "Unexpected response on handshake from server: {:?}",
                    x
                ))),
                Err(_) => Err(ClientError::ReceiveChannel),
            }
        };

        match tokio::time::timeout(self.timeout, fut).await {
            Ok(Ok(())) => Ok(()),
            Ok(e) => e,
            Err(elapsed) => Err(ClientError::ConnectionTimeout),
        }
    }
}

pub async fn node_greeting<'ws>(
    timeout_duration: Duration,
    peer_addr: SocketAddr,
    sender: &'ws mut WebSocketSender,
    receiver: &'ws mut WebSocketReceiver,
) -> ServerResult<()> {
    let fut = async {
        let msg = receiver.next().fuse().await;

        if let Some(Ok(ServerMessage::Text(text))) = msg {
            if text == NODE_UI_PROTOCOL {
                //sender.send(ServerMessage::Text("Node: Conn to client {:?} established", peer_addr))
                return todo!("ws protocol mismatch");
            } else {
                todo!()
            }
        } else {
            todo!()
        }
    };

    match tokio::time::timeout(timeout_duration, fut).await {
        Ok(_) => todo!(),
        Err(e) => todo!(),
    }
}

pub fn verify_masq_ws_subprotocol(msg: &str) -> ServerResult<()> {
    if msg == NODE_UI_PROTOCOL {
        Ok(())
    } else {
        Err(ServerError::MalformedHandshake)
    }
}

// Found possibly a spot of wrong design in the connect procedure: despite the library provides
// configuration with connect timeout, it may not follow up if the connection is initiated but fails
// on the handshake due to which it falls into infinite retries if the server always accept the TCP
// connections but return an error or even panics before the handshake is completed. This is to
// ensure it would always fall back when the time lapses even if it's encountered a blocking issue.
pub async fn client_connect_with_timeout(
    ws: WebSocket,
    timeout: Duration,
    successful_handshake_rx: tokio::sync::oneshot::Receiver<()>,
) -> ClientResult<WebSocket> {
    let mut connect_options = ConnectOptions::default();
    connect_options.block_async_connect = true;
    connect_options.strategy = Fallback;

    let mut delay = tokio::time::sleep(timeout);

    tokio::select! {
        biased;

        res = asserted_connect(&ws, connect_options, successful_handshake_rx) => {
            todo!("returning")
        }

        _ = delay => {
            disconnect(ws).await;
            Err(ClientError::ConnectionTimeout)
        }
    }
}

async fn disconnect(ws: WebSocket) {
    //todo!("disconnect")
    //drop(ws);
    ws.trigger_abort().unwrap();
   //  let _ = ws.disconnect().await;
    // if not achieved politely, dropping ws will do the job too
}

async fn asserted_connect(
    ws: &WebSocket,
    connect_options: ConnectOptions,
    successful_handshake_rx: tokio::sync::oneshot::Receiver<()>,
) -> ConnectResult<ClientError> {
    let res = ws.connect(connect_options).await;

    match res {
        // None is expected because we use 'true' for block_async_connect
        Ok(None) => (),
        //   tokio::time::sleep(Duration::from_millis(150)).await; ,
        Ok(Some(_)) => todo!("unreachable"),
        Err(e) => todo!("Error in connect: {}", e),
    }

    match successful_handshake_rx.await {
        Ok(()) => todo!(),
        Err(e) => todo!(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messages::NODE_UI_PROTOCOL;
    use crate::test_utils::utils::{make_multi_thread_rt, make_rt};
    use crate::utils::{find_free_port, localhost};
    use crate::websockets_handshake::WS_CLIENT_CONNECT_TIMEOUT_MS;
    use crate::websockets_handshake::{verify_masq_ws_subprotocol, WSClientHandshakeHandler};
    use futures_util::future::join_all;
    use std::io::ErrorKind;
    use std::io::Read;
    use std::net::TcpListener;
    use std::sync::Arc;
    use std::thread;
    use tokio::io::{AsyncReadExt, Interest};
    use tokio::sync::oneshot;
    use tokio::task;
    use tokio::task::JoinHandle;
    use tokio::time::timeout;
    use workflow_websocket::client::WebSocketConfig;

    #[test]
    fn constants_are_correct() {
        assert_eq!(WS_CLIENT_CONNECT_TIMEOUT_MS, 2000)
    }

    #[tokio::test]
    async fn client_handshake_handler_happy_path() {
        let (subject, to_server_tx, from_server_rx, handshake_verification_rx, server_join_handle) =
            setup_for_full_client_server_msg_exchange(ClientMessage::Open);

        let result = subject.handshake(&to_server_tx, &from_server_rx).await;

        match result {
            Ok(()) => (),
            Err(e) => panic!("We expected Ok(()) but received {:?}", e),
        }
        let sent_msg = server_join_handle.await.unwrap();
        assert_eq!(sent_msg, ClientMessage::Text(NODE_UI_PROTOCOL.to_string()))
    }

    #[tokio::test]
    async fn client_handshake_handler_timeout_error() {
        let (tx, _rx) = tokio::sync::oneshot::channel();
        let subject = WSClientHandshakeHandler::new(Duration::from_millis(5), NODE_UI_PROTOCOL, tx);
        let (to_server_tx, _to_server_rx) = async_channel::unbounded();
        let (_from_server_tx, from_server_rx) = async_channel::unbounded();

        let result = subject.handshake(&to_server_tx, &from_server_rx).await;

        match result {
            Err(ClientError::ConnectionTimeout) => (),
            x => panic!("Expected ConnectionTimeout error but got {:?}", x),
        }
    }

    #[tokio::test]
    async fn client_handshake_handler_sender_error() {
        let (tx, _rx) = tokio::sync::oneshot::channel();
        let subject = WSClientHandshakeHandler::new(
            Duration::from_millis(WS_CLIENT_CONNECT_TIMEOUT_MS),
            NODE_UI_PROTOCOL,
            tx,
        );
        let (to_server_tx, _) = async_channel::unbounded();
        let (_from_server_tx, from_server_rx) = async_channel::unbounded();

        let result = subject.handshake(&to_server_tx, &from_server_rx).await;

        match result {
            Err(ClientError::ChannelSend) => (),
            x => panic!("Expected ChannelSend error but got {:?}", x),
        }
    }

    #[tokio::test]
    async fn client_handshake_handler_receiver_error() {
        let (tx, _rx) = tokio::sync::oneshot::channel();
        let subject = WSClientHandshakeHandler::new(
            Duration::from_millis(WS_CLIENT_CONNECT_TIMEOUT_MS),
            NODE_UI_PROTOCOL,
            tx,
        );
        let (to_server_tx, _to_server_rx) = async_channel::unbounded();
        let (_, from_server_rx) = async_channel::unbounded();

        let result = subject.handshake(&to_server_tx, &from_server_rx).await;

        match result {
            Err(ClientError::ReceiveChannel) => (),
            x => panic!("Expected ReceiveChannel error but got {:?}", x),
        }
    }

    #[tokio::test]
    async fn client_handshake_server_negotioation_failure() {
        let (subject, to_server_tx, from_server_rx, handshake_verification_rx, server_join_handle) =
            setup_for_full_client_server_msg_exchange(ClientMessage::Close);

        let result = subject.handshake(&to_server_tx, &from_server_rx).await;

        match result {
            Err(ClientError::NegotiationFailure) => (),
            x => panic!("Expected NegotiationFailure error but got {:?}", x),
        }
        let sent_msg = server_join_handle.await.unwrap();
        assert_eq!(sent_msg, ClientMessage::Text(NODE_UI_PROTOCOL.to_string()))
    }

    #[tokio::test]
    async fn client_handshake_unexpected_msg_from_server() {
        let input_and_expected = vec![
            (ClientMessage::Binary(b"Binary crap".to_vec()), "Unexpected response on handshake from server: Binary([66, 105, 110, 97, 114, 121, 32, 99, 114, 97, 112])"),
            (ClientMessage::Text("Literal crap".to_string()), "Unexpected response on handshake from server: Text(\"Literal crap\")")
        ];

        join_all(input_and_expected.into_iter().enumerate().map(
            |(idx, (server_response, expected_err_msg))| async move {
                let (
                    subject,
                    to_server_tx,
                    from_server_rx,
                    handshake_verification_rx,
                    server_join_handle,
                ) = setup_for_full_client_server_msg_exchange(server_response);

                let result = subject.handshake(&to_server_tx, &from_server_rx).await;

                match result {
                    Err(ClientError::Custom(msg)) if msg == expected_err_msg => (),
                    x => panic!(
                        "Item {}: Expected Custom error with message {} but got {:?}",
                        idx + 1,
                        expected_err_msg,
                        x
                    ),
                };
                let sent_msg = server_join_handle.await.unwrap();
                assert_eq!(sent_msg, ClientMessage::Text(NODE_UI_PROTOCOL.to_string()))
            },
        ))
        .await;
    }

    fn setup_for_full_client_server_msg_exchange(
        server_response: ClientMessage,
    ) -> (
        WSClientHandshakeHandler,
        async_channel::Sender<ClientMessage>,
        async_channel::Receiver<ClientMessage>,
        oneshot::Receiver<()>,
        JoinHandle<ClientMessage>,
    ) {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let subject = WSClientHandshakeHandler::new(
            Duration::from_millis(WS_CLIENT_CONNECT_TIMEOUT_MS),
            NODE_UI_PROTOCOL,
            tx,
        );
        let (to_server_tx, to_server_rx) = async_channel::unbounded();
        let (from_server_tx, from_server_rx) = async_channel::unbounded();
        let mocked_server = async move {
            let receive_res =
                tokio::time::timeout(Duration::from_millis(2000), to_server_rx.recv())
                    .await
                    .unwrap();
            let msg_from_client: ClientMessage = receive_res.unwrap();
            from_server_tx.send(server_response).await.unwrap();
            msg_from_client
        };
        let server_join_handle = tokio::task::spawn(mocked_server);
        (
            subject,
            to_server_tx,
            from_server_rx,
            rx,
            server_join_handle,
        )
    }

    #[test]
    fn subprotocol_verified_correct() {
        let protocol = NODE_UI_PROTOCOL;

        assert_eq!(verify_masq_ws_subprotocol(protocol).is_ok(), true);
    }

    #[test]
    fn subprotocol_verified_wrong() {
        let protocols = vec![
            format!("a{}", NODE_UI_PROTOCOL),
            format!("{}1", NODE_UI_PROTOCOL),
            {
                let prt = NODE_UI_PROTOCOL;
                prt.chars().rev().collect::<String>()
            },
        ];

        protocols
            .into_iter()
            .enumerate()
            .for_each(|(idx, protocol)| {
                let result = verify_masq_ws_subprotocol(&protocol);
                match result {
                    Err(ServerError::MalformedHandshake) => (),
                    x => panic!(
                        "Item {}: We expected MalformedHandshake err but got {:?}",
                        idx + 1,
                        x
                    ),
                }
            })
    }

    #[test]
    fn connect_timeouts_without_blocking() {
        todo!("This appears to loop forever in its current incarnation");
        let port = find_free_port();
        let listening_socket = SocketAddr::new(localhost(), port);
        let rt = make_multi_thread_rt();
        let listener_join_handle = rt.spawn(async move {
            let listener = tokio::net::TcpListener::bind(listening_socket)
                .await
                .unwrap();
            let fut = listener.accept();
            let (mut tcp, _) = timeout(Duration::from_millis(3000), fut)
                .await
                .expect("Accept timed out")
                .unwrap();
            let mut buffer = Vec::new();
            loop {

                match tcp.read(&mut buffer).await {
                    Ok(0) => {
                        eprintln!("Nothing to read");
                        tokio::time::sleep(Duration::from_millis(50)).await
                    }
                    Err(e)
                        if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut =>
                    {
                        eprintln!("Would block");
                        tokio::time::sleep(Duration::from_millis(50)).await
                    }
                    Err(e) => {
                        panic!("Error reading from TCP channel {}", e);
                    }
                    Ok(data) => panic!(
                        "We read this {}, but should not be possible",
                        String::from_utf8_lossy(&buffer)
                    ),
                }
            }
        });

        // let listener_join_handle = thread::spawn( move || {
        //     let listener = TcpListener::bind(listening_socket).unwrap();
        //     let (mut tcp, _)  = listener.accept().unwrap();
        //     // let (mut tcp, _) = timeout(Duration::from_millis(3000), fut).await.expect("Accept timed out").unwrap();
        //     let mut buffer = Vec::new();
        //     loop {
        //         //let _ = tcp.readable().await;
        //         match tcp.read(&mut buffer){
        //             // Trying to keep the connection up until it breaks from the other end
        //
        //             Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {
        //                     thread::sleep(Duration::from_millis(50))
        //             }
        //             Err(e) => {
        //                 panic!("Error reading from TCP channel {}", e);
        //             },
        //             Ok(0) => {
        //                 eprintln!("Further end notified terminating this connection");
        //                 thread::sleep(Duration::from_millis(50))
        //             }
        //             Ok(data) => panic!("We read this {}, but should not be possible", String::from_utf8_lossy(&buffer))
        //         }
        //     }
        // });

        let url = format!("ws://{}:{}", localhost(), port);
        let mut config = WebSocketConfig::default();
        let (tx, rx) = tokio::sync::oneshot::channel();
        config.handshake = Some(Arc::new(WSClientHandshakeHandler::new(
            Duration::from_millis(5000),
            NODE_UI_PROTOCOL,
            tx,
        )));
        let ws = WebSocket::new(Some(&url), Some(config)).unwrap();
        let timeout = Duration::from_millis(500);

        let result = rt.block_on(client_connect_with_timeout(ws, timeout, rx));

        match result {
            Err(ClientError::ConnectionTimeout) => {
                assert!(rt.block_on(listener_join_handle).is_ok())
            }
            Err(e) => panic!("Expected connection timeout but got {:?}", e),
            Ok(_) => panic!("Expected connect timeout but got Ok()"),
        }
    }
}
