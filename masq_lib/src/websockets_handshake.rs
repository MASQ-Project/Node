// Copyright (c) 2024, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::messages::NODE_UI_PROTOCOL;
use crate::utils::localhost;
use async_trait::async_trait;
use clap::builder::TypedValueParser;
use futures_util::{FutureExt, SinkExt, StreamExt};
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use workflow_websocket::client::result::Result as ClientResult;
use workflow_websocket::client::ConnectStrategy::Fallback;
use workflow_websocket::client::Message as ClientMessage;
use workflow_websocket::client::{ConnectOptions, Handshake, WebSocket};
use workflow_websocket::client::{Error as ClientError, WebSocketConfig};
use workflow_websocket::server::result::Result as ServerResult;
use workflow_websocket::server::Message as ServerMessage;
use workflow_websocket::server::{Error as ServerError, WebSocketReceiver, WebSocketSender};

pub const WS_CLIENT_CONNECT_TIMEOUT_MS: u64 = 2_000;
pub const WS_CLIENT_HANDSHAKE_TIMEOUT_MS: u64 = 1_000;

pub struct MASQWSClientHandshakeHandler {
    handshake_procedure: Box<dyn ClientHandshakeProcedure>,
    handshake_timeout: Duration,
    protocol: String,
    handshake_result_tx: HandshakeResultTx,
}

pub type HandshakeResultTx = tokio::sync::mpsc::UnboundedSender<ClientResult<()>>;
pub type HandshakeResultRx = tokio::sync::mpsc::UnboundedReceiver<ClientResult<()>>;

impl MASQWSClientHandshakeHandler {
    pub fn new(
        handshake_timeout: Duration,
        protocol: &str,
        handshake_result_tx: HandshakeResultTx,
    ) -> Self {
        let protocol = protocol.to_string();
        let handshake_procedure = Box::new(ClientHandshakeProcedureReal::default());
        Self {
            handshake_procedure,
            handshake_timeout,
            protocol,
            handshake_result_tx,
        }
    }
}

#[async_trait]
trait ClientHandshakeProcedure: Send + Sync {
    async fn do_handshake(
        &self,
        timeout: Duration,
        protocol: &str,
        sender: &async_channel::Sender<ClientMessage>,
        receiver: &async_channel::Receiver<ClientMessage>,
    ) -> ClientResult<()>;
}

#[derive(Default)]
struct ClientHandshakeProcedureReal {}

#[async_trait]
impl ClientHandshakeProcedure for ClientHandshakeProcedureReal {
    async fn do_handshake(
        &self,
        timeout: Duration,
        protocol: &str,
        sender: &async_channel::Sender<ClientMessage>,
        receiver: &async_channel::Receiver<ClientMessage>,
    ) -> ClientResult<()> {
        match sender.send(ClientMessage::Text(protocol.to_string())).await {
            Err(e) => return Err(ClientError::ChannelSend),
            Ok(_) => (),
        }

        let fut = async {
            match receiver.recv().await {
                Ok(ClientMessage::Text(msg))
                    if msg.contains("Node: new WS conn to client 127.0.0.1:") =>
                {
                    Ok(())
                }
                Ok(ClientMessage::Close) => Err(ClientError::NegotiationFailure),
                Ok(x) => {
                    todo!("{:?}", x);
                    Err(ClientError::Custom(format!(
                        "Unexpected response on handshake from server: {:?}",
                        x
                    )))
                }
                Err(_) => Err(ClientError::ReceiveChannel),
            }
        };

        match tokio::time::timeout(timeout, fut).await {
            Ok(Ok(())) => Ok(()),
            Ok(e) => e,
            //TODO this shouldn't be ConnectionTimeout
            Err(elapsed) => Err(ClientError::ConnectionTimeout),
        }
    }
}

//TODO have an inline with logic, that returns to the channel so it's delivered back out to
// the select macro (placed before the `delay` option)...
// For ok, we check both, the returned type from connect and also Ok sent from here
#[async_trait]
impl Handshake for MASQWSClientHandshakeHandler {
    async fn handshake(
        &self,
        sender: &async_channel::Sender<ClientMessage>,
        receiver: &async_channel::Receiver<ClientMessage>,
    ) -> ClientResult<()> {
        let res = self
            .handshake_procedure
            .do_handshake(self.handshake_timeout, &self.protocol, sender, receiver)
            .await;

        // The library has the server throw this error away...
        let sentinel_res = match res {
            Ok(()) => Ok(()),
            Err(_) => todo!(),
        };

        let _ = self.handshake_result_tx.send(res);

        sentinel_res
    }
}

pub async fn node_greeting<'ws, L>(
    timeout_duration: Duration,
    peer_addr: SocketAddr,
    sender: &'ws mut WebSocketSender,
    receiver: &'ws mut WebSocketReceiver,
    log_msg: L,
) -> ServerResult<()>
where
    L: Fn(&str),
{
    let fut = async {
        let msg = receiver.next().fuse().await;
        if let Some(Ok(ServerMessage::Text(text))) = msg {
            if text == NODE_UI_PROTOCOL {
                match sender
                    .send(ServerMessage::Text(format!(
                        "Node: new WS conn to client {:?}",
                        peer_addr
                    )))
                    .await
                {
                    Ok(()) => Ok(()),
                    Err(e) => todo!(),
                }
            } else {
                todo!()
            }
        } else {
            match sender.send(ServerMessage::Close(None)).await {
                Ok(()) => (),
                Err(e) => todo!(),
            };
            Err(ServerError::MalformedHandshake)
        }
    };

    match tokio::time::timeout(timeout_duration, fut).await {
        Ok(_) => Ok(()),
        Err(e) => todo!(),
    }
}

pub type PrepareHandshakeProcedure =
    Box<dyn FnOnce(HandshakeResultTx) -> Arc<dyn Handshake> + Send>;

pub struct WSClientConnector {
    url: String,
    pub prepare_handshake_procedure: PrepareHandshakeProcedure,
    pub global_timeout: Duration,
    pub connect_timeout: Duration,
}

impl WSClientConnector {
    pub fn new(port: u16) -> WSClientConnector {
        let url = format!("ws://{}:{}", localhost(), port);
        Self {
            url,
            prepare_handshake_procedure: Box::new(move |tx| {
                Arc::new(MASQWSClientHandshakeHandler::new(
                    Duration::from_millis(WS_CLIENT_HANDSHAKE_TIMEOUT_MS),
                    NODE_UI_PROTOCOL,
                    tx,
                ))
            }),
            global_timeout: Default::default(),
            connect_timeout: Default::default(),
        }
    }

    // Found possibly a spot of wrong design in the connect procedure: despite the library provides
    // configuration with connect timeout, it may not follow up if the connection is initiated but
    // fails on the handshake due to which it falls into infinite retries if the server always
    // accept the TCP connections but return an error or even panics before the handshake is
    // completed. This is to ensure it would always fall back when the time lapses even if it's
    // encountered a blocking issue.
    pub async fn connect_with_timeout(self) -> ClientResult<WebSocket> {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();

        let mut ws_config = WebSocketConfig::default();
        ws_config.handshake = Some((self.prepare_handshake_procedure)(tx));

        let ws: WebSocket = match WebSocket::new(Some(&self.url), Some(ws_config)) {
            Ok(ws) => ws,
            Err(e) => todo!(),
        };

        let mut connect_options = ConnectOptions::default();
        connect_options.block_async_connect = true;
        connect_options.strategy = Fallback;
        //TODO remove me
        connect_options.connect_timeout = Some(self.connect_timeout);

        let mut delay = tokio::time::sleep(self.global_timeout);

        tokio::select! {
            biased;

            res = Self::asserted_connect(&ws, connect_options, rx) => {
                match res {
                    Ok(_) => Ok(ws),
                    Err(e) => todo!()
                }
            }

            _ = delay => {
                Self::disconnect(ws);
                Err(ClientError::ConnectionTimeout)
            }
        }
    }

    fn disconnect(ws: WebSocket) {
        //todo!("disconnect")
        //drop(ws);
        // let _ = ws.disconnect().await;
        // if not achieved politely, dropping ws will do the job too
    }

    async fn asserted_connect(
        ws: &WebSocket,
        connect_options: ConnectOptions,
        mut handshake_result_rx: HandshakeResultRx,
    ) -> ClientResult<()> {
        let res = ws.connect(connect_options).await;

        match res {
            // None is expected because we use 'true' for block_async_connect
            Ok(None) => (),
            //   tokio::time::sleep(Duration::from_millis(150)).await; ,
            Ok(Some(_)) => todo!("unreachable"),
            Err(e) => todo!("Error in connect: {}", e),
        }

        // We're still operating under the global timeout
        // TODO untestable?
        match handshake_result_rx.recv().await {
            Some(Ok(_)) => Ok(()),
            Some(Err(e)) => todo!(),
            None => todo!(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messages::NODE_UI_PROTOCOL;
    use crate::test_utils::mock_websockets_server::MockWebSocketsServer;
    use crate::utils::{find_free_port, localhost};
    use crate::websockets_handshake::MASQWSClientHandshakeHandler;
    use crate::websockets_handshake::WS_CLIENT_CONNECT_TIMEOUT_MS;
    use futures_util::future::join_all;
    use std::sync::{Arc, Mutex};
    use std::time::Instant;
    use tokio::net::{TcpListener, TcpStream};
    use tokio::task::JoinHandle;
    use tokio_tungstenite::tungstenite::protocol::Role;

    #[test]
    fn constants_are_correct() {
        assert_eq!(WS_CLIENT_CONNECT_TIMEOUT_MS, 2_000);
        assert_eq!(WS_CLIENT_HANDSHAKE_TIMEOUT_MS, 1_000)
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
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        let subject =
            MASQWSClientHandshakeHandler::new(Duration::from_millis(5), NODE_UI_PROTOCOL, tx);
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
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        let subject = MASQWSClientHandshakeHandler::new(
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
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        let subject = MASQWSClientHandshakeHandler::new(
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
    async fn client_handshake_server_negotiation_failure() {
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
        MASQWSClientHandshakeHandler,
        async_channel::Sender<ClientMessage>,
        async_channel::Receiver<ClientMessage>,
        HandshakeResultRx,
        JoinHandle<ClientMessage>,
    ) {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let subject = MASQWSClientHandshakeHandler::new(
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

    #[tokio::test]
    async fn server_greetings_happy_path() {
        let closure_with_client_future = |client_addr, tcp_listener: TcpListener| async move {
            let (tcp, _) = tcp_listener.accept().await.unwrap();
            let (mut sender, mut receiver) =
                tokio_tungstenite::WebSocketStream::from_raw_socket(tcp, Role::Client, None)
                    .await
                    .split();
            sender
                .send(tokio_tungstenite::tungstenite::Message::Text(
                    NODE_UI_PROTOCOL.to_string(),
                ))
                .await
                .unwrap();
            let response = receiver.next().await.unwrap().unwrap();
            let expected_response = tokio_tungstenite::tungstenite::Message::Text(format!(
                "Node: Conn to client {:?} established",
                client_addr
            ));
            assert_eq!(response, expected_response);
        };
        let expected_server_result = Ok(());

        test_server_greeting(closure_with_client_future, expected_server_result).await
    }

    #[tokio::test]
    async fn server_greetings_unexpected_msg_type_received_from_client() {
        let peer_port = find_free_port();
        let timeout = Duration::from_millis(1_500);
        let client_addr = SocketAddr::new(localhost(), peer_port);
        let closure_with_client_future = |client_addr, tcp_listener: TcpListener| async move {
            let (tcp, _) = tcp_listener.accept().await.unwrap();
            let (mut sender, mut receiver) =
                tokio_tungstenite::WebSocketStream::from_raw_socket(tcp, Role::Client, None)
                    .await
                    .split();
            sender
                .send(tokio_tungstenite::tungstenite::Message::Binary(
                    NODE_UI_PROTOCOL.as_bytes().to_vec(),
                ))
                .await
                .unwrap();
            let response = receiver.next().await.unwrap().unwrap();
            let expected_response = tokio_tungstenite::tungstenite::Message::Close(None);
            assert_eq!(response, expected_response);
        };
        let expected_server_result = Err(ServerError::MalformedHandshake);

        test_server_greeting(closure_with_client_future, expected_server_result).await
    }

    async fn test_server_greeting<C, F>(
        closure_with_client_future: C,
        expected_server_result: ServerResult<()>,
    ) where
        C: Fn(SocketAddr, TcpListener) -> F,
        F: Future<Output = ()> + Send + 'static,
    {
        let test_global_timeout = Duration::from_millis(5_000);
        let peer_port = find_free_port();
        let timeout = Duration::from_millis(1_500);
        let client_addr = SocketAddr::new(localhost(), peer_port);
        let tcp_listener = TcpListener::bind(client_addr).await.unwrap();
        let client_future: F = closure_with_client_future(client_addr, tcp_listener);
        let timed_future = tokio::time::timeout(test_global_timeout, client_future);
        let client_join_handle = tokio::task::spawn(timed_future);
        let tcp = TcpStream::connect(client_addr).await.unwrap();
        let (mut sender, mut receiver) =
            tokio_tungstenite::WebSocketStream::from_raw_socket(tcp, Role::Server, None)
                .await
                .split();

        let result = node_greeting(timeout, client_addr, &mut sender, &mut receiver, |_| {}).await;

        if matches!(result, ref expected_server_result) {
            ()
        } else {
            panic!(
                "Expected {:?} in greeting from server but got {:?}",
                expected_server_result, result
            )
        };
        while !client_join_handle.is_finished() {
            tokio::time::sleep(Duration::from_millis(10)).await
        }
        let client_finished = client_join_handle.await;
        match client_finished {
            Ok(Ok(())) => (),
            Ok(Err(_)) => panic!(
                "Test timed out after {} ms",
                test_global_timeout.as_millis()
            ),
            Err(_) => panic!("Expected Ok at the client but got {:?}", client_finished),
        }
    }

    #[tokio::test]
    async fn connect_success() {
        let port = find_free_port();
        let server = MockWebSocketsServer::new(port);
        let server_handle = server.start().await;
        let mut connector = WSClientConnector::new(port);
        connector.connect_timeout = Duration::from_millis(5_000);
        connector.global_timeout = Duration::from_millis(6_000);

        let ws = connector.connect_with_timeout().await.unwrap();

        ws.send(ClientMessage::Text("Hello MASQ world".to_string()))
            .await
            .unwrap();
        let mut requests = server_handle.retrieve_recorded_requests(Some(1)).await;
        let only_msg = requests.remove(0);
        assert_eq!(only_msg.expect_textual_msg(), "Hello MASQ world");
    }

    #[test]
    fn connect_timeouts_without_blocking() {
        // let port = find_free_port();
        // let listening_socket = SocketAddr::new(localhost(), port);
        // let rt = make_multi_thread_rt();
        // let listener_join_handle = rt.spawn(async move {
        //     let listener = tokio::net::TcpListener::bind(listening_socket)
        //         .await
        //         .unwrap();
        //     let fut = listener.accept();
        //     let (mut tcp, _) = timeout(Duration::from_millis(4000), fut)
        //         .await
        //         .expect("Accept timed out")
        //         .unwrap();
        //     let mut buffer = [0; 1024];
        //     loop {
        //         match tcp.read(&mut buffer).await {
        //             Ok(0) => {
        //                 eprintln!("Stream closed. Nothing to read");
        //                 break;
        //             }
        //             Err(e) => {
        //                 eprintln!("Receiving this error: {}", e);
        //                 break;
        //             }
        //             Ok(data_len) => {
        //                 panic!("We read only this {}", String::from_utf8_lossy(&buffer))
        //             }
        //         }
        //     }
        // });
        // // let listener_join_handle = rt.spawn_blocking(move || {
        // //     let listener = std::net::TcpListener::bind(listening_socket)
        // //         .unwrap();
        // //     let (mut tcp, _) = listener.accept().unwrap();
        // //     // let (mut tcp, _) = timeout(Duration::from_millis(3000), fut)
        // //     //     .await
        // //     //     .expect("Accept timed out")
        // //     //     .unwrap();
        // //     tcp.set_nonblocking(false).unwrap();
        // //     let mut buffer = Vec::new();
        // //     loop {
        // //
        // //         match tcp.read(&mut buffer){
        // //             Ok(0) => {
        // //                 eprintln!("Stream closed. Nothing to read");
        // //                 thread::sleep(Duration::from_millis(500));
        // //                 break;
        // //             }
        // //             Err(e) => {
        // //                 panic!("Error reading from TCP channel {}", e);
        // //             }
        // //             Ok(data) => panic!(
        // //                 "We read this {}, but should not be possible",
        // //                 String::from_utf8_lossy(&buffer)
        // //             ),
        // //         }
        // //     }
        // //});
        //
        // // let listener_join_handle = thread::spawn( move || {
        // //     let listener = TcpListener::bind(listening_socket).unwrap();
        // //     let (mut tcp, _)  = listener.accept().unwrap();
        // //     // let (mut tcp, _) = timeout(Duration::from_millis(3000), fut).await.expect("Accept timed out").unwrap();
        // //     let mut buffer = Vec::new();
        // //     loop {
        // //         //let _ = tcp.readable().await;
        // //         match tcp.read(&mut buffer){
        // //             // Trying to keep the connection up until it breaks from the other end
        // //
        // //             Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {
        // //                     thread::sleep(Duration::from_millis(50))
        // //             }
        // //             Err(e) => {
        // //                 panic!("Error reading from TCP channel {}", e);
        // //             },
        // //             Ok(0) => {
        // //                 eprintln!("Further end notified terminating this connection");
        // //                 thread::sleep(Duration::from_millis(50))
        // //             }
        // //             Ok(data) => panic!("We read this {}, but should not be possible", String::from_utf8_lossy(&buffer))
        // //         }
        // //     }
        // // });
        //
        // let url = format!("ws://{}:{}", localhost(), port);
        // let mut config = WebSocketConfig::default();
        // let (tx, rx) = tokio::sync::oneshot::channel();
        // todo!("write a handshake handler for this test that returns errors in a loop");
        // config.handshake = Some(Arc::new(MASQWSClientHandshakeHandler::new(
        //     Duration::from_millis(3000),
        //     NODE_UI_PROTOCOL,
        //     tx,
        // )));
        // let ws = WebSocket::new(Some(&url), Some(config)).unwrap();
        // let timeout = Duration::from_millis(20);
        //
        // let result = rt.block_on(client_connect_with_timeout(ws, timeout, rx));
        //
        // match result {
        //     Err(ClientError::ConnectionTimeout) => {
        //         assert!(rt.block_on(listener_join_handle).is_ok())
        //     }
        //     Err(e) => panic!("Expected connection timeout but got {:?}", e),
        //     Ok(_) => panic!("Expected connect timeout but got Ok()"),
        // }
        todo!("decide if should be kept")
    }

    #[tokio::test]
    async fn connect_handles_handshake_failures() {
        // This test has a story. I found misbehavior in the ws library, particularly,
        // when a connection is established correctly, but the following handshake doesn't work,
        // the error is natively only swallowed and the client tries to reconnect and go through
        // the same procedure again. I had to invent a notification channel letting the foreground
        // task know about the emerged error and cancel the whole efforts, returning a failure.
        let port = find_free_port();
        let server = MockWebSocketsServer::new(port);
        let server_handle = server.start().await;
        let mut connector = WSClientConnector::new(port);
        connector.prepare_handshake_procedure = Box::new(|tx| -> Arc<dyn Handshake> {
            let mut handler = MASQWSClientHandshakeHandler::new(
                Duration::from_millis(60_000),
                "CorrectProtocol",
                tx,
            );
            handler.handshake_procedure = Box::new(
                ClientHandshakeProcedureMock::default().do_handshake_result(Err(
                    ClientError::Custom("Your handshake ain't right".to_string()),
                )),
            );
            Arc::new(handler)
        });
        connector.connect_timeout = Duration::from_millis(60_000);
        connector.global_timeout = Duration::from_millis(60_000);
        let before = Instant::now();

        let result = connector.connect_with_timeout().await;

        let after = Instant::now();
        match result {
            Err(ClientError::Custom(msg)) if msg == "Your handshake ain't right" => (),
            Err(e) => panic!("Expected handshake err but got {:?}", e),
            Ok(_) => panic!("Expected handshake err but got Ok()"),
        }
        let exec_time_ms = after.checked_duration_since(before).unwrap().as_millis();
        // Hopefully 10s is enough for Actions :) Because normally it should return in a blink of
        // eye. Compared to those timeouts set above we can conclude they did not participate
        // in any of the returns. It was a signal transferred by a channel that made things resolve
        // quickly
        assert!(exec_time_ms < 10_000);
    }

    #[derive(Default)]
    struct ClientHandshakeProcedureMock {
        do_handshake_params: Arc<Mutex<Vec<(Duration, String)>>>,
        do_handshake_results: Mutex<Vec<ClientResult<()>>>,
    }

    #[async_trait]
    impl ClientHandshakeProcedure for ClientHandshakeProcedureMock {
        async fn do_handshake(
            &self,
            timeout: Duration,
            protocol: &str,
            sender: &async_channel::Sender<ClientMessage>,
            receiver: &async_channel::Receiver<ClientMessage>,
        ) -> ClientResult<()> {
            self.do_handshake_params
                .lock()
                .unwrap()
                .push((timeout, protocol.to_string()));
            self.do_handshake_results.lock().unwrap().remove(0)
        }
    }

    impl ClientHandshakeProcedureMock {
        fn do_handshake_params(mut self, params: &Arc<Mutex<Vec<(Duration, String)>>>) -> Self {
            self.do_handshake_params = params.clone();
            self
        }
        fn do_handshake_result(self, result: ClientResult<()>) -> Self {
            self.do_handshake_results.lock().unwrap().push(result);
            self
        }
    }
}
