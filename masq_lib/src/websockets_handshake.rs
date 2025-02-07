// Copyright (c) 2024, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::messages::NODE_UI_PROTOCOL;
use crate::utils::localhost;
use async_trait::async_trait;
use futures_util::{FutureExt, SinkExt, StreamExt};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::unbounded_channel;
use workflow_websocket::client::result::Result as ClientResult;
use workflow_websocket::client::ConnectStrategy::Fallback;
use workflow_websocket::client::Message as ClientMessage;
use workflow_websocket::client::{ConnectOptions, Handshake, WebSocket};
use workflow_websocket::client::{Error as ClientError, WebSocketConfig};
use workflow_websocket::server::result::Result as ServerResult;
use workflow_websocket::server::Message as ServerMessage;
use workflow_websocket::server::{Error as ServerError, WebSocketReceiver, WebSocketSender};

pub const WS_CLIENT_CONNECT_TIMEOUT_MS: u64 = 2_000;
pub const WS_CLIENT_HANDSHAKE_TIMEOUT_MS: u64 = 1_300;
pub const WS_CLIENT_GLOBAL_TIMEOUT_MS: u64 = 3_000;

pub struct MASQClientWSHandshakeHandler {
    handshake_procedure: Box<dyn ClientHandshakeProcedure>,
    handshake_timeout: Duration,
    protocol: String,
    handshake_result_tx: HandshakeResultTx,
}

pub type HandshakeResultTx = tokio::sync::mpsc::UnboundedSender<ClientResult<()>>;
pub type HandshakeResultRx = tokio::sync::mpsc::UnboundedReceiver<ClientResult<()>>;

impl MASQClientWSHandshakeHandler {
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
impl Handshake for MASQClientWSHandshakeHandler {
    async fn handshake(
        &self,
        sender: &async_channel::Sender<ClientMessage>,
        receiver: &async_channel::Receiver<ClientMessage>,
    ) -> ClientResult<()> {
        let res = self
            .handshake_procedure
            .do_handshake(self.handshake_timeout, &self.protocol, sender, receiver)
            .await;

        // The library would've thrown this error away hadn't we stepped in by...
        let sentinel_res = match res {
            Ok(()) => Ok(()),
            Err(_) => Err(ClientError::NegotiationFailure),
        };

        // ...using this channel.
        let _ = self.handshake_result_tx.send(res);

        sentinel_res
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
            Ok(_) => (),
            Err(_) => return Err(ClientError::ChannelSend),
        }

        let fut = async {
            match receiver.recv().await {
                Ok(ClientMessage::Text(msg)) if msg.contains("Node -> client 127.0.0.1:") => Ok(()),
                Ok(ClientMessage::Close) => Err(ClientError::NegotiationFailure),
                Ok(x) => Err(ClientError::Custom(format!(
                    "Unexpected response on handshake from server: {:?}",
                    x
                ))),
                Err(_) => Err(ClientError::ReceiveChannel),
            }
        };

        match tokio::time::timeout(timeout, fut).await {
            Ok(Ok(())) => Ok(()),
            Ok(e) => e,
            Err(_) => Err(ClientError::Custom("Handshake timeout".to_string())),
        }
    }
}

pub async fn node_server_greeting<'ws>(
    timeout_duration: Duration,
    peer_addr: SocketAddr,
    sender: &'ws mut WebSocketSender,
    receiver: &'ws mut WebSocketReceiver,
) -> ServerResult<()> {
    let fut = async {
        let msg = receiver.next().fuse().await;
        let matches = if let Some(Ok(ServerMessage::Text(text))) = msg {
            if text == NODE_UI_PROTOCOL {
                true
            } else {
                false
            }
        } else {
            false
        };

        respond_to_handshake_request(matches, peer_addr, sender).await
    };

    match tokio::time::timeout(timeout_duration, fut).await {
        Ok(res) => res,
        Err(_) => Err(ServerError::Other(format!(
            "Handshake timeout after {} ms",
            timeout_duration.as_millis()
        ))),
    }
}

async fn respond_to_handshake_request(
    protocol_matches: bool,
    peer_addr: SocketAddr,
    sender: &mut WebSocketSender,
) -> ServerResult<()> {
    if protocol_matches {
        match sender
            .send(ServerMessage::Text(format!("Node -> client {}", peer_addr)))
            .await
        {
            Ok(()) => Ok(()),
            Err(e) => Err(ServerError::Other(format!(
                "SendError for confirmation to client {}: {}",
                peer_addr, e
            ))),
        }
    } else {
        match sender.send(ServerMessage::Close(None)).await {
            Ok(()) => Err(ServerError::MalformedHandshake),
            Err(e) => Err(ServerError::Other(format!(
                "SendError for refusal to client {}: {}",
                peer_addr, e
            ))),
        }
    }
}

pub trait WSHandshakeHandlerFactory: Send + Sync {
    fn make(&self, confirmation_tx: HandshakeResultTx) -> Arc<dyn Handshake>;
}

#[derive(Default)]
pub struct WSHandshakeHandlerFactoryReal {}

impl WSHandshakeHandlerFactory for WSHandshakeHandlerFactoryReal {
    fn make(&self, confirmation_tx: HandshakeResultTx) -> Arc<dyn Handshake> {
        Arc::new(MASQClientWSHandshakeHandler::new(
            Duration::from_millis(WS_CLIENT_HANDSHAKE_TIMEOUT_MS),
            NODE_UI_PROTOCOL,
            confirmation_tx,
        ))
    }
}

pub struct WSClientConnectionInitiator {
    global_timeout: Duration,
    connect_timeout: Duration,
    handshake_handler: Arc<dyn Handshake>,
    handshake_confirmation_rx: HandshakeResultRx,
    url: String,
}

impl WSClientConnectionInitiator {
    pub fn new(
        port: u16,
        global_timeout_ms: u64,
        ws_handshake_handler_factory: Arc<dyn WSHandshakeHandlerFactory>,
    ) -> WSClientConnectionInitiator {
        let (handshake_confirmation_tx, handshake_confirmation_rx) = unbounded_channel();
        let handshake_handler = ws_handshake_handler_factory.make(handshake_confirmation_tx);
        let global_timeout = Duration::from_millis(global_timeout_ms);
        let connect_timeout = Duration::from_millis(WS_CLIENT_CONNECT_TIMEOUT_MS);
        Self::new_with_full_setup(
            port,
            handshake_handler,
            handshake_confirmation_rx,
            global_timeout,
            connect_timeout,
        )
    }

    pub fn new_with_full_setup(
        port: u16,
        handshake_handler: Arc<dyn Handshake>,
        handshake_confirmation_rx: HandshakeResultRx,
        global_timeout: Duration,
        connect_timeout: Duration,
    ) -> WSClientConnectionInitiator {
        let url = ws_url(port);
        Self {
            url,
            handshake_handler,
            handshake_confirmation_rx,
            global_timeout,
            connect_timeout,
        }
    }

    // Found a possible weak design in the third party's connect procedure: despite the library
    // provides configuration with connect timeout, it may not follow up if the connection is
    // initiated but fails on the handshake due to which it falls into infinite retries. It is
    // when the server always accepts the TCP connections but returns an error or even panics
    // before the handshake completes. This function ensures it would always fall back when
    // the time lapses and wouldn't get stuck in loops or upon a blocking issue.
    pub async fn connect_with_timeout(self) -> ClientResult<WebSocket> {
        let mut ws_config = WebSocketConfig::default();
        ws_config.handshake = Some(self.handshake_handler);

        let ws = WebSocket::new(Some(&self.url), Some(ws_config))?;

        let mut connect_options = ConnectOptions::default();
        connect_options.block_async_connect = true;
        connect_options.strategy = Fallback;
        connect_options.connect_timeout = Some(self.connect_timeout);

        let delay = tokio::time::sleep(self.global_timeout);

        tokio::select! {
            biased;

            res = Self::asserted_connect(&ws, connect_options, self.handshake_confirmation_rx) => {
                match res {
                    Ok(_) => Ok(ws),
                    Err(e) => Err(e)
                }
            }

            _ = delay => {
                Self::disconnect(ws).await;
                Err(ClientError::ConnectionTimeout)
            }
        }
    }

    async fn disconnect(ws: WebSocket) {
        if ws.is_connected() {
            let _ = ws.disconnect().await;
            while ws.is_connected() {
                tokio::time::sleep(Duration::from_millis(20)).await
            }
        }
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
            Ok(Some(_)) => {
                unreachable!("block_async_connect for WS should be set but apparently wasn't")
            }
            Err(e) => return Err(e),
        }

        // We're still operating under the global timeout
        match handshake_result_rx.recv().await {
            Some(res) => res,
            None => Err(ClientError::Custom(
                "Handshake verification channel closed".to_string(),
            )),
        }
    }
}

pub fn ws_url(port: u16) -> String {
    format!("ws://{}:{}", localhost(), port)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messages::NODE_UI_PROTOCOL;
    use crate::test_utils::mock_websockets_server::MockWebSocketsServer;
    use crate::test_utils::websockets_utils::{
        establish_ws_conn_with_handshake, WSHandshakeHandlerFactoryMock,
    };
    use crate::utils::{find_free_port, localhost};
    use crate::websockets_handshake::MASQClientWSHandshakeHandler;
    use crate::websockets_handshake::WS_CLIENT_CONNECT_TIMEOUT_MS;
    use futures_util::future::join_all;
    use std::sync::{Arc, Mutex};
    use std::time::Instant;
    use tokio::io::AsyncReadExt;
    use tokio::net::{TcpListener, TcpStream};
    use tokio::task::JoinHandle;
    use tokio_tungstenite::tungstenite::protocol::Role;
    use tokio_tungstenite::WebSocketStream;

    #[test]
    fn constants_are_correct() {
        assert_eq!(WS_CLIENT_CONNECT_TIMEOUT_MS, 2_000);
        assert_eq!(WS_CLIENT_HANDSHAKE_TIMEOUT_MS, 1_300);
        assert_eq!(WS_CLIENT_GLOBAL_TIMEOUT_MS, 3_000);
    }

    #[test]
    fn timeouts_are_set_properly() {
        let global_timeout_ms = 456456;
        let ws_handshake_handler_factory = Arc::new(WSHandshakeHandlerFactoryReal::default());

        let result =
            WSClientConnectionInitiator::new(123, global_timeout_ms, ws_handshake_handler_factory);

        assert_eq!(
            result.connect_timeout.as_millis(),
            Duration::from_millis(WS_CLIENT_CONNECT_TIMEOUT_MS).as_millis()
        );
        assert_eq!(result.global_timeout.as_millis(), global_timeout_ms as u128)
    }

    #[tokio::test]
    async fn connect_success() {
        let port = find_free_port();
        let server = MockWebSocketsServer::new(port);
        let server_handle = server.start().await;
        let mut connector = WSClientConnectionInitiator::new(
            port,
            6000,
            Arc::new(WSHandshakeHandlerFactoryReal::default()),
        );
        connector.connect_timeout = Duration::from_millis(5_000);

        let ws = connector.connect_with_timeout().await.unwrap();

        ws.send(ClientMessage::Text("Hello world with MASQ".to_string()))
            .await
            .unwrap();
        let mut requests = server_handle.retrieve_recorded_requests(Some(1)).await;
        let only_msg = requests.remove(0);
        assert_eq!(only_msg.expect_textual_msg(), "Hello world with MASQ");
    }

    #[tokio::test]
    async fn connect_timeouts_without_blocking() {
        let port = find_free_port();
        let listening_socket = SocketAddr::new(localhost(), port);
        let listener_join_handle = tokio::spawn(async move {
            let listener = tokio::net::TcpListener::bind(listening_socket)
                .await
                .unwrap();
            let fut = listener.accept();
            let (mut tcp, _) = tokio::time::timeout(Duration::from_millis(3_000), fut)
                .await
                .expect("Timeout on Accept")
                .unwrap();
            let mut buffer = [0; 1024];
            loop {
                match tcp.read(&mut buffer).await {
                    Ok(0) => {
                        eprintln!("Stream closed. Nothing to read");
                        break;
                    }
                    Err(e) => {
                        panic!("Server's receiving this error: {}", e);
                    }
                    //Receiving the client hello Http request
                    Ok(data_len) if data_len < 100 => {
                        panic!("We read only this {}", String::from_utf8_lossy(&buffer))
                    }
                    _ => continue,
                }
            }
        });
        // This should work as an ultimate constraint
        let global_timeout_ms = 10;
        let mut connector = WSClientConnectionInitiator::new(
            port,
            global_timeout_ms,
            Arc::new(WSHandshakeHandlerFactoryReal::default()),
        );
        // We'd receive a different error due to this limit
        connector.connect_timeout = Duration::from_millis(4_000);
        let before = Instant::now();

        let result = connector.connect_with_timeout().await;

        let after = Instant::now();
        match result {
            Err(ClientError::ConnectionTimeout) => {}
            Err(e) => panic!(
                "Expected ClientError::Custom with connection timeout msg but got: {:?}",
                e
            ),
            Ok(_) => panic!("Expected connect timeout but got Ok()"),
        }
        let elapsed = after.checked_duration_since(before).unwrap();
        assert!(Duration::from_millis(50) > elapsed)
    }

    #[tokio::test]
    async fn connect_handles_handshake_failures() {
        // This test has a story. I found misbehavior in the ws library, particularly,
        // when a connection is established correctly, but the following handshake doesn't work,
        // the error is natively only swallowed and the client tries to reconnect and go through
        // the same procedure again. I had to invent a notification channel letting the foreground
        // task know about the emerged error and cancel the whole efforts, returning a failure.
        let make_params_arc = Arc::new(Mutex::new(vec![]));
        let port = find_free_port();
        let server = MockWebSocketsServer::new(port);
        let _server_handle = server.start().await;
        let handshake_timeout = Duration::from_millis(60_000);
        let (tx, rx) = unbounded_channel();
        let ws_handshake_handler = {
            let mut handler =
                MASQClientWSHandshakeHandler::new(handshake_timeout, "CorrectProtocol", tx);
            handler.handshake_procedure = Box::new(
                ClientHandshakeProcedureMock::default().do_handshake_result(Err(
                    ClientError::Custom("Your handshake ain't right".to_string()),
                )),
            );
            Arc::new(handler)
        };
        let ws_handshake_handler_factory = Arc::new(
            WSHandshakeHandlerFactoryMock::default()
                .make_params(make_params_arc)
                .make_plain_result(ws_handshake_handler),
        );
        let global_timeout = 60_000;
        let mut connector =
            WSClientConnectionInitiator::new(port, global_timeout, ws_handshake_handler_factory);
        connector.handshake_confirmation_rx = rx;
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

    #[tokio::test]
    async fn connect_with_timeout_cannot_establish_local_ws_object() {
        let mut connector = WSClientConnectionInitiator::new(
            12345,
            6000,
            Arc::new(WSHandshakeHandlerFactoryReal::default()),
        );
        let bad_url = "X-files://new-protocols.com";
        connector.url = bad_url.to_string();

        let result = connector.connect_with_timeout().await;

        match result {
            Err(ClientError::AddressSchema(msg)) if msg == bad_url => (),
            Err(e) => panic!("Expected AddressSchema err but got {:?}", e),
            Ok(_) => panic!("Expected AddressSchema err but got Ok()"),
        }
    }

    #[tokio::test]
    #[should_panic(
        expected = "internal error: entered unreachable code: block_async_connect for WS should be set but apparently wasn't"
    )]
    async fn asserted_connect_is_not_meant_for_none_blocking_mode() {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let url = ws_url(12345);
        let ws = WebSocket::new(Some(&url), None).unwrap();
        let mut connect_options = ConnectOptions::default();
        connect_options.block_async_connect = false;

        let _ = WSClientConnectionInitiator::asserted_connect(&ws, connect_options, rx).await;
    }

    #[tokio::test]
    async fn asserted_connect_with_handshake_result_rx_returning_err() {
        let port = find_free_port();
        let server = MockWebSocketsServer::new(port);
        let _server_handle = server.start().await;
        let (_, rx) = tokio::sync::mpsc::unbounded_channel();
        let url = ws_url(port);
        let ws = WebSocket::new(Some(&url), None).unwrap();
        let mut connect_options = ConnectOptions::default();
        connect_options.block_async_connect = true;

        let result = WSClientConnectionInitiator::asserted_connect(&ws, connect_options, rx).await;

        match result {
            Err(ClientError::Custom(msg)) if msg == "Handshake verification channel closed" => (),
            Err(e) => panic!(
                "Expected Custom(Handshake verification channel closed) but got {:?}",
                e
            ),
            Ok(_) => panic!("Expected Custom(Handshake verification channel closed) but got Ok"),
        };
    }

    #[tokio::test]
    async fn disconnects_can_disconnect() {
        let port = find_free_port();
        let server = MockWebSocketsServer::new(port);
        let server_handle = server.start().await;
        let ws = establish_ws_conn_with_handshake(port).await;
        server_handle.await_conn_established(None).await;

        WSClientConnectionInitiator::disconnect(ws).await;

        server_handle.await_conn_disconnected(None).await
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

    macro_rules! check_expected_result {
        ($tested_result: expr, $expected: pat, $additional_pass_condition: expr) => {{
            let passed = if let $expected = $tested_result {
                $additional_pass_condition
            } else {
                false
            };
            if !passed {
                panic!(
                    "Expected {:?} (with additional conn {:?}) but got {:?}",
                    stringify!($expected),
                    stringify!($additional_pass_condition),
                    $tested_result
                )
            }
        }};
    }

    fn assert_negotiation_failure(sentinel_res: ClientResult<()>) {
        check_expected_result!(sentinel_res, Err(ClientError::NegotiationFailure), true)
    }

    #[tokio::test]
    async fn client_handshake_handler_timeout_error() {
        let (tx, mut handshake_res_rx) = tokio::sync::mpsc::unbounded_channel();
        let subject =
            MASQClientWSHandshakeHandler::new(Duration::from_millis(5), NODE_UI_PROTOCOL, tx);
        let (to_server_tx, to_server_rx) = async_channel::unbounded();
        let (_from_server_tx, from_server_rx) = async_channel::unbounded();

        let sentinel_res = subject.handshake(&to_server_tx, &from_server_rx).await;

        assert_negotiation_failure(sentinel_res);
        let actual_res = handshake_res_rx.recv().await.unwrap();
        check_expected_result!(
            actual_res,
            Err(ClientError::Custom(ref msg)),
            msg.contains("Handshake timeout")
        );
    }

    #[tokio::test]
    async fn client_handshake_handler_sender_error() {
        let (tx, mut handshake_res_rx) = tokio::sync::mpsc::unbounded_channel();
        let subject = MASQClientWSHandshakeHandler::new(
            Duration::from_millis(WS_CLIENT_CONNECT_TIMEOUT_MS),
            NODE_UI_PROTOCOL,
            tx,
        );
        let (to_server_tx, _) = async_channel::unbounded();
        let (_from_server_tx, from_server_rx) = async_channel::unbounded();

        let sentinel_res = subject.handshake(&to_server_tx, &from_server_rx).await;

        assert_negotiation_failure(sentinel_res);
        let actual_res = handshake_res_rx.recv().await.unwrap();
        check_expected_result!(actual_res, Err(ClientError::ChannelSend), true);
    }

    #[tokio::test]
    async fn client_handshake_handler_receiver_error() {
        let (tx, mut handshake_res_rx) = tokio::sync::mpsc::unbounded_channel();
        let subject = MASQClientWSHandshakeHandler::new(
            Duration::from_millis(WS_CLIENT_CONNECT_TIMEOUT_MS),
            NODE_UI_PROTOCOL,
            tx,
        );
        let (to_server_tx, _to_server_rx) = async_channel::unbounded();
        let (_, from_server_rx) = async_channel::unbounded();

        let sentinel_res = subject.handshake(&to_server_tx, &from_server_rx).await;

        assert_negotiation_failure(sentinel_res);
        let actual_res = handshake_res_rx.recv().await.unwrap();
        check_expected_result!(actual_res, Err(ClientError::ReceiveChannel), true);
    }

    #[tokio::test]
    async fn client_handshake_server_negotiation_failure() {
        let (subject, to_server_tx, from_server_rx, mut handshake_res_rx, server_join_handle) =
            setup_for_full_client_server_msg_exchange(ClientMessage::Close);

        let sentinel_res = subject.handshake(&to_server_tx, &from_server_rx).await;

        assert_negotiation_failure(sentinel_res);
        let actual_res = handshake_res_rx.recv().await.unwrap();
        check_expected_result!(actual_res, Err(ClientError::NegotiationFailure), true);
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
                    mut handshake_res_rx,
                    server_join_handle,
                ) = setup_for_full_client_server_msg_exchange(server_response);

                let sentinel_res = subject.handshake(&to_server_tx, &from_server_rx).await;

                assert_negotiation_failure(sentinel_res);
                let actual_res = handshake_res_rx.recv().await.unwrap();
                match actual_res {
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
        MASQClientWSHandshakeHandler,
        async_channel::Sender<ClientMessage>,
        async_channel::Receiver<ClientMessage>,
        HandshakeResultRx,
        JoinHandle<ClientMessage>,
    ) {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let subject = MASQClientWSHandshakeHandler::new(
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
    async fn server_greeting_happy_path() {
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
                "Node -> client {:?}",
                client_addr
            ));
            assert_eq!(response, expected_response);
        };
        let assert_expected_server_result = |result| check_expected_result!(result, Ok(()), true);

        test_server_greeting(
            None,
            closure_with_client_future,
            assert_expected_server_result,
        )
        .await
    }

    #[tokio::test]
    async fn server_greeting_unexpected_msg_type_received_from_client() {
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
        let assert_expected_server_result =
            |result| check_expected_result!(result, Err(ServerError::MalformedHandshake), true);

        test_server_greeting(
            None,
            closure_with_client_future,
            assert_expected_server_result,
        )
        .await
    }

    #[tokio::test]
    async fn server_greeting_protocol_mismatch() {
        let closure_with_client_future = |client_addr, tcp_listener: TcpListener| async move {
            let (tcp, _) = tcp_listener.accept().await.unwrap();
            let (mut sender, mut receiver) =
                tokio_tungstenite::WebSocketStream::from_raw_socket(tcp, Role::Client, None)
                    .await
                    .split();
            sender
                .send(tokio_tungstenite::tungstenite::Message::Text(format!(
                    "abc{}123",
                    NODE_UI_PROTOCOL
                )))
                .await
                .unwrap();
            let response = receiver.next().await.unwrap().unwrap();
            let expected_response = tokio_tungstenite::tungstenite::Message::Close(None);
            assert_eq!(response, expected_response);
        };
        let assert_expected_server_result =
            |result| check_expected_result!(result, Err(ServerError::MalformedHandshake), true);

        test_server_greeting(
            None,
            closure_with_client_future,
            assert_expected_server_result,
        )
        .await
    }

    #[tokio::test]
    async fn server_greeting_timeout() {
        let peer_port = find_free_port();
        let timeout = Duration::from_millis(20);
        let client_addr = SocketAddr::new(localhost(), peer_port);
        let closure_with_client_future = |client_addr, tcp_listener: TcpListener| async move {
            let (tcp, _) = tcp_listener.accept().await.unwrap();
            let (_sender, _receiver) =
                tokio_tungstenite::WebSocketStream::from_raw_socket(tcp, Role::Client, None)
                    .await
                    .split();
            tokio::time::sleep(Duration::from_millis(25)).await;
        };
        let assert_expected_server_result = |result| {
            check_expected_result!(
                result,
                Err(ServerError::Other(ref msg)),
                msg.contains("Handshake timeout after 20 ms")
            )
        };
        let before = Instant::now();

        test_server_greeting(
            Some(timeout),
            closure_with_client_future,
            assert_expected_server_result,
        )
        .await;

        let after = Instant::now();
        let elapsed = after.checked_duration_since(before).unwrap();
        assert!(elapsed < Duration::from_millis(100))
    }

    #[tokio::test]
    async fn server_cannot_send_positive_response() {
        let port = find_free_port();
        let expected_err_msg = format!("SendError for confirmation to client 127.0.0.1:{}: WebSocket protocol error: Sending after closing is not allowed", port);
        let protocol_matches = true;
        test_server_fails_sending_response(protocol_matches, port, &expected_err_msg).await
    }

    #[tokio::test]
    async fn server_cannot_send_negative_response() {
        let port = find_free_port();
        let expected_err_msg = format!("SendError for refusal to client 127.0.0.1:{}: WebSocket protocol error: Sending after closing is not allowed", port);
        let protocol_matches = false;
        test_server_fails_sending_response(protocol_matches, port, &expected_err_msg).await
    }

    async fn test_server_fails_sending_response(
        protocol_matches: bool,
        port: u16,
        expected_err_msg: &str,
    ) {
        let peer_addr = SocketAddr::new(localhost(), port);
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let listener_join_handle = tokio::task::spawn(async move {
            let listener = TcpListener::bind(peer_addr).await.unwrap();
            tx.send(()).unwrap();
            let (tcp, _) = listener.accept().await.unwrap();
        });
        rx.recv().await;
        let tcp = TcpStream::connect(peer_addr).await.unwrap();
        let (mut sender, _) = WebSocketStream::from_raw_socket(tcp, Role::Client, None)
            .await
            .split();
        sender.close().await.unwrap();

        let result = respond_to_handshake_request(protocol_matches, peer_addr, &mut sender).await;

        check_expected_result!(
            result,
            Err(ServerError::Other(ref msg)),
            msg.contains(expected_err_msg)
        );
        listener_join_handle.await.unwrap()
    }

    async fn test_server_greeting<C1, C2, F>(
        timeout_opt: Option<Duration>,
        closure_with_client_future: C1,
        assert_expected_server_result: C2,
    ) where
        C1: Fn(SocketAddr, TcpListener) -> F,
        C2: Fn(ServerResult<()>),
        F: Future<Output = ()> + Send + 'static,
    {
        let test_global_timeout = Duration::from_millis(5_000);
        let peer_port = find_free_port();
        let timeout = timeout_opt.unwrap_or(Duration::from_millis(3_000));
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

        let result = node_server_greeting(timeout, client_addr, &mut sender, &mut receiver).await;

        assert_expected_server_result(result);
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
}
