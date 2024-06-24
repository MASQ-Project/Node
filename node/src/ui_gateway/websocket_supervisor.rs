// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
use actix::Recipient;
use futures_util::{Sink, SinkExt, StreamExt, TryStreamExt};
use masq_lib::constants::UNMARSHAL_ERROR;
use masq_lib::logger::Logger;
use masq_lib::messages::{ToMessageBody, UiUnmarshalError, NODE_UI_PROTOCOL};
use masq_lib::ui_gateway::MessagePath::Conversation;
use masq_lib::ui_gateway::MessageTarget::{AllClients, AllExcept, ClientId};
use masq_lib::ui_gateway::{MessageBody, MessageTarget, NodeFromUiMessage, NodeToUiMessage};
use masq_lib::ui_traffic_converter::UiTrafficConverter;
use masq_lib::ui_traffic_converter::UnmarshalError::{Critical, NonCritical};
use masq_lib::utils::{localhost, ExpectValue};
use std::any::Any;
use std::borrow::Cow;
use std::collections::HashMap;
use std::fmt::Debug;
use std::future::Future;
use std::io;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;
use tokio::net::{TcpStream};
use tokio::task;
use tungstenite::protocol::frame::coding::CloseCode;
use tungstenite::protocol::CloseFrame;
use workflow_websocket::server::handshake::greeting;
use workflow_websocket::server::result::Result as WWResult;
use workflow_websocket::server::Error::{Done};
use workflow_websocket::server::{
    Error, Message, WebSocketHandler, WebSocketReceiver, WebSocketSender, WebSocketServer,
    WebSocketSink,
};

pub trait WebSocketSupervisor {
    fn send_msg(&self, msg: NodeToUiMessage);
}

pub struct WebSocketSupervisorReal {
    #[allow(dead_code)]
    inner_arc: Arc<Mutex<WebSocketSupervisorInner>>,
}

type MessageWriter = dyn SinkExt<Message, Error = io::Error> + Unpin;

struct WebSocketSupervisorInner {
    port: u16,
    next_client_id: u64,
    from_ui_message_sub: Recipient<NodeFromUiMessage>,
    client_id_by_socket_addr: HashMap<SocketAddr, u64>,
    socket_addr_by_client_id: HashMap<u64, SocketAddr>,
    client_by_id: HashMap<u64, WebSocketSink>,
}

impl WebSocketSupervisor for WebSocketSupervisorReal {
    fn send_msg(&self, msg: NodeToUiMessage) {
        Self::send_msg(
            self.inner_arc
                .lock()
                .expect("WebSocketSupervisor clients are dying"),
            msg,
        );
    }
}

impl WebSocketSupervisorReal {
    pub fn new(
        port: u16,
        from_ui_message_sub: Recipient<NodeFromUiMessage>,
        connections_to_accept: usize,
    ) -> WebSocketSupervisorReal {
        let inner_arc = Arc::new(Mutex::new(WebSocketSupervisorInner {
            port,
            next_client_id: 0,
            from_ui_message_sub: from_ui_message_sub.clone(),
            client_id_by_socket_addr: HashMap::new(),
            socket_addr_by_client_id: HashMap::new(),
            client_by_id: HashMap::new(),
        }));
        task::spawn(Self::listen_for_connections_on(
            SocketAddr::new(localhost(), port),
            from_ui_message_sub,
            connections_to_accept,
        ));
        WebSocketSupervisorReal {
            inner_arc: inner_arc,
        }
    }

    async fn listen_for_connections_on(
        socket_addr: SocketAddr,
        from_ui_message_sub: Recipient<NodeFromUiMessage>,
        mut connections_to_accept: usize, // TODO: Figure a way to bring this back into service
    ) -> WWResult<()> {
        let handler = MasqNodeUiv2Handler::new(socket_addr.port(), from_ui_message_sub);
        let server = WebSocketServer::new(Arc::new(handler), None);
        let future = server.listen(socket_addr.to_string().as_str(), None);
        return future;
    }

    fn filter_clients<'a, P>(
        locked_inner: &'a mut MutexGuard<WebSocketSupervisorInner>,
        predicate: P,
    ) -> Vec<(u64, &mut MessageWriter)>
    where
        P: FnMut(&(&u64, &mut MessageWriter)) -> bool,
    {
        locked_inner
            .client_by_id
            .iter_mut()
            .filter(predicate)
            .map(|(id, item)| (*id, item.as_mut()))
            .collect()
    }

    async fn send_msg(
        mut locked_inner: MutexGuard<WebSocketSupervisorInner>,
        msg: NodeToUiMessage,
    ) {
        let clients = match msg.target {
            ClientId(n) => {
                let clients = Self::filter_clients(&mut locked_inner, |(id, _)| **id == n);
                if !clients.is_empty() {
                    clients
                } else {
                    Self::log_absent_client(n);
                    return;
                }
            }
            AllExcept(n) => Self::filter_clients(&mut locked_inner, |(id, _)| **id != n),
            AllClients => Self::filter_clients(&mut locked_inner, |_| true),
        };
        let json = UiTrafficConverter::new_marshal(msg.body);
        if let Some(errors) = Self::send_to_clients(clients, json).await {
            drop(locked_inner);
            Self::handle_sink_errs(errors, &locked_inner)
        }
    }

    fn handle_sink_errs(
        errors: Vec<SendToClientWebsocketError>,
        locked_inner: &MutexGuard<WebSocketSupervisorInner>,
    ) {
        errors.into_iter().for_each(|e| match e {
            SendToClientWebsocketError::FlushError((client_id, e)) => {
                Self::handle_flush_error(e, locked_inner, client_id)
            }
            SendToClientWebsocketError::SendError((client_id, e)) => {
                Self::handle_send_error(e, locked_inner, client_id)
            }
        })
    }

    async fn send_to_clients(
        clients: Vec<(u64, &mut MessageWriter)>,
        json: String,
    ) -> Option<Vec<SendToClientWebsocketError>> {
        let errors: Vec<SendToClientWebsocketError> = clients
            .into_iter()
            .flat_map(async move |(client_id, client)| {
                match client.send(Message::Text(json.clone())).await {
                    Ok(_) => None,
                    Err(e) => Some(SendToClientWebsocketError::SendError((client_id, e))),
                }
                .await
            })
            .collect();
        if errors.is_empty() {
            None
        } else {
            Some(errors)
        }
    }

    fn handle_flush_error(
        e: io::Error,
        locked_inner: &MutexGuard<WebSocketSupervisorInner>,
        client_id: u64,
    ) {
        if e.kind() == ErrorKind::BrokenPipe || e.kind() == ErrorKind::ConnectionReset {
            Self::emergency_client_removal(client_id, locked_inner);
            warning!(
                Logger::new("WebSocketSupervisor"),
                "Client {} hit a fatal flush error: {:?}, dropping the client",
                client_id,
                e.kind()
            )
        }
    }

    fn handle_send_error(
        error: io::Error,
        locked_inner: &MutexGuard<WebSocketSupervisorInner>,
        client_id: u64,
    ) {
        Self::emergency_client_removal(client_id, locked_inner);
        error!(
            Logger::new("WebSocketSupervisor"),
            "Error sending to client {}: {:?}, dropping the client", client_id, error
        );
    }

    fn emergency_client_removal(
        client_id: u64,
        locked_inner: &MutexGuard<WebSocketSupervisorInner>,
    ) {
        locked_inner
            .client_by_id
            .remove(&client_id)
            .expectv("client");
        let socket_addr = locked_inner
            .socket_addr_by_client_id
            .remove(&client_id)
            .expectv("socket address");
        locked_inner
            .client_id_by_socket_addr
            .remove(&socket_addr)
            .expectv("client id");
    }

    fn close_connection(
        locked_inner: &mut MutexGuard<WebSocketSupervisorInner>,
        client_id: u64,
        socket_addr: SocketAddr,
        logger: &Logger,
    ) {
        let _ = locked_inner.socket_addr_by_client_id.remove(&client_id);
        let mut client = match locked_inner.client_by_id.remove(&client_id) {
            Some(client) => client,
            None => panic!("WebSocketSupervisor got a disconnect from a client that has disappeared from the stable!"),
        };
        let future = async {
            let close_message = Message::Close(Some(CloseFrame {
                code: CloseCode::Normal,
                reason: Cow::Owned("Client initiated closure"),
            }));
            match client.send(close_message).await {
                Err(e) => warning!(
                    logger,
                    "Error acknowledging connection closure from UI at {}: {:?}",
                    socket_addr,
                    e
                ),
                Ok(_) => {
                    client.flush().await.unwrap_or_else(|_| {
                        warning!(
                            logger,
                            "Couldn't flush closure acknowledgement to UI at {}, client removed anyway",
                            socket_addr
                        )
                    });
                }
            }
        };
        task::spawn(future);
    }

    fn log_absent_client(client_id: u64) {
        warning!(
            Logger::new("WebsocketSupervisor"),
            "WebsocketSupervisor: WARN: Tried to send to an absent client {}",
            client_id
        )
    }
}

enum SendToClientWebsocketError {
    SendError((u64, io::Error)),
    FlushError((u64, io::Error)),
}

pub trait WebSocketSupervisorFactory: Send {
    fn make(
        &self,
        port: u16,
        recipient: Recipient<NodeFromUiMessage>,
    ) -> std::io::Result<Box<dyn WebSocketSupervisor>>;
}

pub struct WebsocketSupervisorFactoryReal;

impl WebSocketSupervisorFactory for WebsocketSupervisorFactoryReal {
    fn make(
        &self,
        port: u16,
        recipient: Recipient<NodeFromUiMessage>,
    ) -> io::Result<Box<dyn WebSocketSupervisor>> {
        WebSocketSupervisorReal::new(port, recipient, usize::MAX)
            .map(|positive| positive as Box<dyn WebSocketSupervisor>)
    }
}

struct MasqNodeUiv2Handler {
    logger: Logger,
    inner_mutex: Mutex<WebSocketSupervisorInner>,
}

impl WebSocketHandler for MasqNodeUiv2Handler {
    type Context = u64;

    async fn handshake(
        self: &Arc<Self>,
        peer_addr: &SocketAddr,
        sender: &mut WebSocketSender,
        receiver: &mut WebSocketReceiver,
        sink: &WebSocketSink,
    ) -> WWResult<Self::Context> {
        info!(self.logger, "New WebSocket connection from: {}", peer_addr);
        greeting(
            Duration::from_millis(5000),
            sender,
            receiver,
            Box::pin(Self::verify_subprotocol),
        )
        .await?;
        let client_id = {
            let mut inner = self
                .inner_mutex
                .lock()
                .expect("Client futures are panicking");
            let client_id = inner.next_client_id;
            inner.next_client_id += 1;
            inner.client_id_by_socket_addr.insert(*peer_addr, client_id);
            inner.socket_addr_by_client_id.insert(client_id, *peer_addr);
            inner.client_by_id.insert(client_id, sink.clone());
            client_id
        };
        Ok(client_id)
        /*
        while match read.next().await {
            None => todo!("Test-drive me"),
            Some(msg_result) => match msg_result {
                Err(e) => todo!("Test-drive me!"),
                Ok(msg) => match msg {
                    Message::Text(message) => Self::handle_text_message(
                        inner_arc.lock().expect("Client futures are panicking"),
                        &logger,
                        peer_addr,
                        message.as_str()
                    ).await,
                    Message::Close(_) => Self::handle_close_message(
                        inner_arc.lock().expect("Client futures are panicking"),
                        &logger,
                        peer_addr
                    ),
                    Message::Binary(_) => Self::handle_other_message(&logger, peer_addr, "binary"),
                    Message::Ping(_) => Self::handle_other_message(&logger, peer_addr, "ping"),
                    Message::Pong(_) => Self::handle_other_message(&logger, peer_addr, "pong"),
                    Message::Frame(_) => panic!("Should never happen"),
                }
            }
        } {}
        let mut inner = inner_arc.lock().expect("Client futures are panicking");
        inner.client_id_by_socket_addr.remove(&peer_addr).expect("Client ID disappeared");
        inner.socket_addr_by_client_id.remove(&client_id).expect("Peer address disappeared");
        // TODO Hopefully, dropping the write half will close everything
        inner.client_by_id.remove(&client_id).expect("Write half disappeared");
         */
    }

    async fn message(
        self: &Arc<Self>,
        client_id: &u64,
        msg: Message,
        _sink: &WebSocketSink,
    ) -> WWResult<()> {
        match msg {
            Message::Text(message) => self.handle_text_message(*client_id, message.as_str()).await,
            Message::Close(_) => self.handle_close_message(*client_id).await,
            Message::Binary(_) => self.handle_other_message(*client_id, "binary").await,
            Message::Ping(payload) => self.handle_ping_message(*client_id, payload).await,
            Message::Pong(_) => self.handle_other_message(*client_id, "pong").await,
            Message::Frame(_) => panic!("Should never happen"),
        }
    }
}

impl MasqNodeUiv2Handler {
    fn new(port: u16, from_ui_message_sub: Recipient<NodeFromUiMessage>) -> Self {
        Self {
            logger: Logger::new("WebSocketSupervisor"),
            inner_mutex: Mutex::new(WebSocketSupervisorInner {
                port,
                next_client_id: 1,
                from_ui_message_sub,
                client_id_by_socket_addr: Default::default(),
                socket_addr_by_client_id: Default::default(),
                client_by_id: Default::default(),
            }),
        }
    }

    fn verify_subprotocol(msg: &str) -> WWResult<()> {
        todo!("Try to verify subprotocol in this message: '{}'", msg)
    }

    async fn handle_text_message(self: &Arc<Self>, client_id: u64, message: &str) -> WWResult<()> {
        let mut locked_inner = self
            .inner_mutex
            .lock()
            .expect("Client futures are panicking");
        match UiTrafficConverter::new_unmarshal_from_ui(message, client_id) {
            Ok(from_ui_message) => {
                locked_inner
                    .from_ui_message_sub
                    .try_send(from_ui_message)
                    .expect("UiGateway is dead");
                return Ok(());
            }
            Err(Critical(e)) => {
                error!(
                    &self.logger,
                    "Bad message from client {} at {}: {:?}:\n{}\n",
                    client_id,
                    Self::peer_addr_str(client_id, &locked_inner),
                    Critical(e.clone()),
                    message
                );
                Self::send_msg(
                    locked_inner,
                    NodeToUiMessage {
                        target: ClientId(client_id),
                        body: UiUnmarshalError {
                            message: e.to_string(),
                            bad_data: message.to_string(),
                        }
                        .tmb(0),
                    },
                )
                .await;
                return Ok(());
            }
            Err(NonCritical(opcode, context_id_opt, e)) => {
                error!(
                    &self.logger,
                    "Bad message from client {} at {}: {:?}:\n{}\n",
                    client_id,
                    Self::peer_addr_str(client_id, &locked_inner),
                    NonCritical(opcode.clone(), context_id_opt, e.clone()),
                    message
                );
                match context_id_opt {
                    None => {
                        Self::send_msg(
                            locked_inner,
                            NodeToUiMessage {
                                target: ClientId(client_id),
                                body: UiUnmarshalError {
                                    message: e.to_string(),
                                    bad_data: message.to_string(),
                                }
                                .tmb(0),
                            },
                        )
                        .await
                    }
                    Some(context_id) => {
                        Self::send_msg(
                            locked_inner,
                            NodeToUiMessage {
                                target: ClientId(client_id),
                                body: MessageBody {
                                    opcode,
                                    path: Conversation(context_id),
                                    payload: Err((UNMARSHAL_ERROR, e.to_string())),
                                },
                            },
                        )
                        .await
                    }
                };
                return Ok(());
            }
        }
    }

    async fn handle_close_message(self: &Arc<Self>, client_id: u64) -> WWResult<()> {
        let mut locked_inner = self
            .inner_mutex
            .lock()
            .expect("Client futures are panicking");
        let socket_addr_opt = locked_inner.socket_addr_by_client_id.get(&client_id);
        info!(
            &self.logger,
            "UI client {} at {} disconnected from port {}",
            client_id,
            Self::peer_addr_str(client_id, &locked_inner),
            locked_inner.port
        );
        Self::close_connection(
            &mut locked_inner,
            client_id,
            &self.logger,
            Done("Client close".to_string()),
        )
    }

    async fn handle_ping_message(
        self: &Arc<Self>,
        client_id: u64,
        payload: Vec<u8>,
    ) -> WWResult<()> {
        todo!()
    }

    async fn handle_other_message(
        self: &Arc<Self>,
        client_id: u64,
        message_type_name: &str,
    ) -> WWResult<()> {
        info!(
            &self.logger,
            "UI at {} sent unexpected {} message; ignoring",
            Self::peer_addr_str(
                client_id,
                &self
                    .inner_mutex
                    .lock()
                    .expect("Client futures are panicking")
            ),
            message_type_name
        );
        Ok(())
    }

    async fn close_connection(
        locked_inner: &mut MutexGuard<WebSocketSupervisorInner>,
        client_id: u64,
        logger: &Logger,
        reason: Error,
    ) -> WWResult<()> {
        let _ = locked_inner.socket_addr_by_client_id.remove(&client_id);
        let mut client = match locked_inner.client_by_id.remove(&client_id) {
            Some(client) => client,
            None => panic!("WebSocketSupervisor got a disconnect from a client that has disappeared from the stable!"),
        };
        let socket_addr_opt = locked_inner.socket_addr_by_client_id.remove(&client_id);
        if let Some(socket_addr) = socket_addr_opt {
            locked_inner.client_id_by_socket_addr.remove(&socket_addr);
        }
        let close_message = Message::Close(Some(CloseFrame {
            code: CloseCode::Normal,
            reason: Cow::Owned("Client initiated closure"),
        }));
        match client.send(close_message).await {
            Err(e) => warning!(
                logger,
                "Error acknowledging connection closure from UI client {} at {}: {:?}",
                client_id,
                Self::peer_addr_str(client_id, locked_inner),
                e
            ),
            Ok(_) => {
                client.flush().await.unwrap_or_else(|_| {
                    warning!(
                        logger,
                        "Couldn't flush closure acknowledgement to UI client {} at {}, client removed anyway",
                        client_id,
                        if let Some(socket_addr) = socket_addr_opt {socket_addr.to_string().as_str()} else {"an unknown address"},
                    )
                })
            }
        }
        Err(reason)
    }

    fn peer_addr_str<'a>(
        client_id: u64,
        locked_inner: &'a MutexGuard<WebSocketSupervisorInner>,
    ) -> &'a str {
        let socket_addr_opt = locked_inner.socket_addr_by_client_id.remove(&client_id);
        if let Some(socket_addr) = socket_addr_opt {
            socket_addr.to_string().as_str()
        } else {
            "an unknown address"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::recorder::{make_recorder, Recorder};
    use crate::test_utils::{assert_contains, await_value, wait_for};
    use actix::System;
    use actix::{Actor, Addr};
    use crossbeam_channel::bounded;
    use masq_lib::constants::UNMARSHAL_ERROR;
    use masq_lib::messages::{
        FromMessageBody, UiCheckPasswordRequest, UiDescriptorResponse, UiShutdownRequest,
        UiStartOrder, UiUnmarshalError, NODE_UI_PROTOCOL,
    };
    use masq_lib::test_utils::logging::init_test_logging;
    use masq_lib::test_utils::logging::TestLogHandler;
    use masq_lib::test_utils::ui_connection::UiConnection;
    use masq_lib::test_utils::utils::make_rt;
    use masq_lib::ui_gateway::MessagePath::FireAndForget;
    use masq_lib::ui_gateway::NodeFromUiMessage;
    use masq_lib::ui_traffic_converter::UiTrafficConverter;
    use masq_lib::utils::{find_free_port, localhost};
    use std::net::{IpAddr, Ipv4Addr, Shutdown};
    use std::str::FromStr;
    use std::thread;
    use std::time::Duration;
    use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver};
    use workflow_websocket::client::{ConnectOptions, WebSocket};

    impl WebSocketSupervisorReal {
        fn inject_client(&self, web_socket_sink: WebSocketSink) -> u64 {
            let mut locked_inner = self.inner_arc.lock().unwrap();
            let client_id = locked_inner.next_client_id;
            locked_inner.next_client_id += 1;
            locked_inner.client_by_id.insert(client_id, web_socket_sink);
            client_id
        }
    }

    fn make_websocket_sink_pair() -> (WebSocketSink, UnboundedReceiver<Message>) {
        unbounded_channel::<Message>()
    }

    /*
    let ws = WebSocket::new(Some("ws://localhost:9090"), None)?;
        ws.connect(ConnectOptions::default()).await?;

        let ws_ = ws.clone();
        workflow_core::task::spawn(async move {
            let mut seq = 0;
            loop {
                log_info!("▷ sending message {seq}");
                let msg = format!("message {seq}");
                // let result = ws_.post(Message::Text(msg)).await;;
                let result = ws_.send(Message::Text(msg)).await;
                match result {
                    Ok(_) => {}
                    Err(err) => {
                        log_error!("Error sending message: {}", err);
                    }
                }

                workflow_core::task::sleep(message_delay).await;

                seq += 1;
            }
        });

        let ws_ = ws.clone();
        loop {
            let message = ws_.recv().await.unwrap();
            log_info!("◁ receiving message: {:?}", message);
        }     */

    async fn make_client(port: u16, protocol: &str) -> WWResult<WebSocket> {
        let url = format!("ws://{}:{}", localhost(), port);
        let ws = WebSocket::new(Some(url.as_str()), None).unwrap();
        ws.connect(ConnectOptions::default()).await.unwrap();
        // TODO: Needs subprotocol name
        Ok(ws)
    }

    fn wait_for_client(port: u16, protocol: &str) -> WebSocket {
        let mut one_client_opt: Option<WebSocket> = None;
        wait_for(None, None, || match make_client(port, protocol) {
            Ok(client) => {
                one_client_opt = Some(client);
                true
            }
            Err(e) => {
                println!("Couldn't make client yet: {}", e);
                false
            }
        });
        one_client_opt.unwrap()
    }

    fn wait_for_server(port: u16) {
        wait_for(None, None, || {
            match TcpStream::connect(SocketAddr::new(localhost(), port)) {
                Ok(stream) => {
                    stream.shutdown(Shutdown::Both).unwrap();
                    true
                }
                Err(_) => false,
            }
        });
    }

    fn subs(ui_gateway: Recorder) -> Recipient<NodeFromUiMessage> {
        let addr: Addr<Recorder> = ui_gateway.start();
        addr.recipient::<NodeFromUiMessage>()
    }

    #[test]
    fn logs_pre_upgrade_connection_errors() {
        init_test_logging();
        let port = find_free_port();
        let (ui_gateway, _, _) = make_recorder();
        let ui_message_sub = subs(ui_gateway);
        let _subject = WebSocketSupervisorReal::new(port, ui_message_sub, 1);

        wait_for_server(port);

        let tlh = TestLogHandler::new();
        // TODO: Include severity in the assertion
        tlh.await_log_containing("Unsuccessful connection to UI port detected", 1000);
    }

    #[test]
    fn data_for_a_newly_connected_client_is_set_properly() {
        init_test_logging();
        let port = find_free_port();
        let (ui_gateway, _, ui_gateway_recording_arc) = make_recorder();
        let system = System::new();
        let recipient = ui_gateway.start().recipient();
        let subject = WebSocketSupervisorReal::new(port, recipient, 1);
        wait_for_server(port);

        let mut ui_connection: UiConnection = UiConnection::make(port, NODE_UI_PROTOCOL).unwrap();

        {
            let inner = subject.inner_arc.lock().unwrap();
            assert_eq!(inner.next_client_id, 2);
            assert_eq!(
                inner.socket_addr_by_client_id.get(&1).unwrap(),
                &ui_connection.local_addr()
            );
            assert_eq!(
                inner
                    .client_id_by_socket_addr
                    .get(&ui_connection.local_addr())
                    .unwrap(),
                &1
            );
        }
        ui_connection.send(UiCheckPasswordRequest {
            db_password_opt: Some("booga".to_string()),
        });
        System::current().stop();
        system.run();
        let recording = ui_gateway_recording_arc.lock().unwrap();
        let message = recording.get_record::<UiCheckPasswordRequest>(0);
        assert_eq!(
            message,
            UiCheckPasswordRequest {
                db_password_opt: Some("booga".to_string())
            }
        );
        todo!("Check for proper connection-progress logs")
    }

    #[test]
    fn rejects_connection_attempt_with_improper_protocol_name() {
        init_test_logging();
        let port = find_free_port();
        let (ui_gateway, _, ui_gateway_recording_arc) = make_recorder();
        let system = System::new();
        let recipient = ui_gateway.start().recipient();
        let subject = WebSocketSupervisorReal::new(port, recipient, 1);
        wait_for_server(port);

        let result: Result<UiConnection, String> = UiConnection::make(port, "MASQNode-UI");

        assert_eq!(
            result,
            Err("UI attempted connection without protocol MASQNode-UIv2: [\"MASQNode-UI\"]")
        );
        {
            let inner = subject.inner_arc.lock().unwrap();
            assert_eq!(inner.next_client_id, 1);
            assert_eq!(inner.socket_addr_by_client_id.is_empty(), true);
            assert_eq!(inner.client_id_by_socket_addr.is_empty(), true);
        }
        let tlh = TestLogHandler::new();
        tlh.exists_log_containing(
            "UI attempted connection without protocol MASQNode-UIv2: [\"MASQNode-UI\"]",
        );
    }

    #[test]
    fn logs_unexpected_binary_ping_pong_websocket_messages() {
        init_test_logging();
        let port = find_free_port();
        let (ui_gateway, _, ui_gateway_recording_arc) = make_recorder();
        let system = System::new();
        let recipient = ui_gateway.start().recipient();
        let subject = WebSocketSupervisorReal::new(port, recipient, 1);
        wait_for_server(port);

        {
            let mut ui_connection: UiConnection =
                UiConnection::make(port, NODE_UI_PROTOCOL).unwrap();
            ui_connection.send_message(&Message::Binary(vec![1u8, 2u8, 3u8, 4u8]));
            ui_connection.send_message(&Message::Ping(vec![1u8, 2u8, 3u8, 4u8]));
            ui_connection.send_message(&Message::Pong(vec![1u8, 2u8, 3u8, 4u8]));
        }

        let tlh = TestLogHandler::new();
        tlh.await_log_matching(
            "UI at 127\\.0\\.0\\.1:\\d+ sent unexpected binary message; ignoring",
            1000,
        );
        tlh.await_log_matching(
            "UI at 127\\.0\\.0\\.1:\\d+ sent unexpected ping message; ignoring",
            1000,
        );
        tlh.await_log_matching(
            "UI at 127\\.0\\.0\\.1:\\d+ sent unexpected pong message; ignoring",
            1000,
        );
    }

    #[test]
    fn can_connect_two_clients_and_receive_messages_from_them() {
        let port = find_free_port();
        let (ui_gateway, ui_gateway_awaiter, ui_gateway_recording_arc) = make_recorder();

        let ui_message_sub = subs(ui_gateway);
        let subject = WebSocketSupervisorReal::new(port, ui_message_sub, 2);
        let mut one_client = wait_for_client(port, NODE_UI_PROTOCOL);
        let mut another_client = wait_for_client(port, NODE_UI_PROTOCOL);
        one_client
            .send_message(&Message::text(r#"{"opcode": "one", "payload": {}}"#))
            .unwrap();
        another_client
            .send_message(&Message::text(r#"{"opcode": "another", "payload": {}}"#))
            .unwrap();
        one_client
            .send_message(&Message::text(r#"{"opcode": "athird", "payload": {}}"#))
            .unwrap();

        one_client.send_message(&Message::Close(None)).unwrap();
        let one_close_msg = one_client.recv_message().unwrap();
        another_client.send_message(&Message::Close(None)).unwrap();
        let another_close_msg = another_client.recv_message().unwrap();

        ui_gateway_awaiter.await_message_count(3);
        let ui_gateway_recording = ui_gateway_recording_arc.lock().unwrap();
        let messages = (0..=2)
            .map(|i| {
                ui_gateway_recording
                    .get_record::<NodeFromUiMessage>(i)
                    .clone()
            })
            .collect::<Vec<NodeFromUiMessage>>();
        assert_contains(
            &messages,
            &NodeFromUiMessage {
                client_id: 0,
                body: MessageBody {
                    opcode: "one".to_string(),
                    path: FireAndForget,
                    payload: Ok("{}".to_string()),
                },
            },
        );
        assert_contains(
            &messages,
            &NodeFromUiMessage {
                client_id: 1,
                body: MessageBody {
                    opcode: "another".to_string(),
                    path: FireAndForget,
                    payload: Ok("{}".to_string()),
                },
            },
        );
        assert_contains(
            &messages,
            &NodeFromUiMessage {
                client_id: 0,
                body: MessageBody {
                    opcode: "athird".to_string(),
                    path: FireAndForget,
                    payload: Ok("{}".to_string()),
                },
            },
        );
        assert_eq!(one_close_msg, Message::Close(None));
        assert_eq!(another_close_msg, Message::Close(None));
    }

    #[test]
    fn logs_badly_formatted_json_and_returns_unmarshal_error() {
        init_test_logging();
        let subject_inner = make_ordinary_inner();
        let subject = WebSocketSupervisorReal {
            inner_arc: Arc::new(Mutex::new(subject_inner)),
        };
        let socket_addr = SocketAddr::from_str("1.2.3.4:1234").unwrap();
        let (client, mut client_rx) = make_websocket_sink_pair();
        let client_id = subject.inject_client(client);
        let mut inner = subject.inner_arc.lock().unwrap();
        inner
            .client_id_by_socket_addr
            .insert(socket_addr, client_id);
        let bad_json = "}: I am badly-formatted JSON :{";

        let future = WebSocketSupervisorReal::handle_text_message(
            inner,
            &Logger::new("test"),
            socket_addr,
            bad_json,
        );

        make_rt().block_on(future).unwrap();
        let expected_traffic_conversion_message =
            format!("Couldn't parse text as JSON: Error(\"expected value\", line: 1, column: 1)");
        let expected_unmarshal_message = format!(
            "Critical error unmarshalling unidentified message: {}",
            expected_traffic_conversion_message
        );
        TestLogHandler::new().exists_log_containing(
            format!(
                "ERROR: test: Bad message from client 0 at 1.2.3.4:1234: {}",
                expected_unmarshal_message
            )
            .as_str(),
        );
        let actual_json = match client_rx.recv().unwrap() {
            Message::Text(s) => s,
            x => panic!("Expected OwnedMessage::Text, got {:?}", x),
        };
        let actual_struct =
            UiTrafficConverter::new_unmarshal_to_ui(&actual_json, ClientId(0)).unwrap();
        assert_eq!(actual_struct.target, ClientId(0));
        assert_eq!(
            UiUnmarshalError::fmb(actual_struct.body).unwrap().0,
            UiUnmarshalError {
                message: expected_traffic_conversion_message,
                bad_data: bad_json.to_string(),
            }
        )
    }

    fn make_ordinary_inner() -> WebSocketSupervisorInner {
        let (ui_message_sub, _, _) = make_recorder();
        WebSocketSupervisorInner {
            port: 1234,
            next_client_id: 0,
            from_ui_message_sub: ui_message_sub.start().recipient::<NodeFromUiMessage>(),
            client_id_by_socket_addr: Default::default(),
            socket_addr_by_client_id: Default::default(),
            client_by_id: Default::default(),
        }
    }

    #[test]
    fn bad_one_way_message_is_logged_and_returns_error() {
        init_test_logging();
        let subject_inner = make_ordinary_inner();
        let subject = WebSocketSupervisorReal {
            inner_arc: Arc::new(Mutex::new(subject_inner)),
        };
        let socket_addr = SocketAddr::from_str("1.2.3.4:1234").unwrap();
        let (client, mut client_rx) = make_websocket_sink_pair();
        let client_id = subject.inject_client(client);
        {
            let mut inner = subject.inner_arc.lock().unwrap();
            inner
                .client_id_by_socket_addr
                .insert(socket_addr, client_id);
        }
        let bad_message_json = r#"{"opcode":"shutdown"}"#;

        let future = WebSocketSupervisorReal::handle_text_message(
            subject.inner_arc.lock().unwrap(),
            &Logger::new("test"),
            socket_addr,
            bad_message_json,
        );

        make_rt().block_on(future).unwrap();
        let expected_traffic_conversion_message =
            format!("Required field was missing: payload, error");
        let expected_unmarshal_message = format!(
            "Error unmarshalling 'shutdown' message: {}",
            expected_traffic_conversion_message
        );
        TestLogHandler::new().exists_log_containing(
            format!(
                "ERROR: test: Bad message from client 0 at 1.2.3.4:1234: {}",
                expected_unmarshal_message
            )
            .as_str(),
        );
        let actual_json = match client_rx.recv().unwrap() {
            Message::Text(s) => s,
            x => panic!("Expected OwnedMessage::Text, got {:?}", x),
        };
        let actual_struct =
            UiTrafficConverter::new_unmarshal_to_ui(&actual_json, ClientId(0)).unwrap();
        assert_eq!(actual_struct.target, ClientId(0));
        assert_eq!(
            UiUnmarshalError::fmb(actual_struct.body).unwrap().0,
            UiUnmarshalError {
                message: expected_traffic_conversion_message,
                bad_data: bad_message_json.to_string(),
            }
        )
    }

    #[test]
    fn bad_two_way_message_is_logged_and_returns_error() {
        init_test_logging();
        let subject_inner = make_ordinary_inner();
        let subject = WebSocketSupervisorReal {
            inner_arc: Arc::new(Mutex::new(subject_inner)),
        };
        let socket_addr = SocketAddr::from_str("1.2.3.4:1234").unwrap();
        let (client, mut client_rx) = make_websocket_sink_pair();
        let client_id = subject.inject_client(client);
        {
            let mut inner = subject.inner_arc.lock().unwrap();
            inner
                .client_id_by_socket_addr
                .insert(socket_addr, client_id);
        }
        let bad_message_json = r#"{"opcode":"setup", "contextId":3333}"#;

        let future = WebSocketSupervisorReal::handle_text_message(
            subject.inner_arc.lock().unwrap(),
            &Logger::new("test"),
            socket_addr,
            bad_message_json,
        );

        make_rt().block_on(future).unwrap();
        let expected_traffic_conversion_message =
            format!("Required field was missing: payload, error");
        let expected_unmarshal_message = format!(
            "Error unmarshalling 'setup' message: {}",
            expected_traffic_conversion_message
        );
        TestLogHandler::new().exists_log_containing(
            format!(
                "ERROR: test: Bad message from client 0 at 1.2.3.4:1234: {}",
                expected_unmarshal_message
            )
            .as_str(),
        );
        let actual_json = match client_rx.recv().unwrap() {
            Message::Text(s) => s,
            x => panic!("Expected OwnedMessage::Text, got {:?}", x),
        };
        let actual_struct =
            UiTrafficConverter::new_unmarshal_to_ui(&actual_json, ClientId(0)).unwrap();
        assert_eq!(
            actual_struct,
            NodeToUiMessage {
                target: ClientId(0),
                body: MessageBody {
                    opcode: "setup".to_string(),
                    path: Conversation(3333),
                    payload: Err((UNMARSHAL_ERROR, expected_traffic_conversion_message))
                }
            }
        );
    }

    fn transmit_failure_assertion() {
        let client = {
            let (client, _client_rx) = make_websocket_sink_pair();
            client
        };
        sink_failure_test_body(client, false)
    }

    fn sink_failure_test_body(client_mock: WebSocketSink, client_is_retained_after_error: bool) {
        let (ui_gateway, _, _) = make_recorder();
        let from_ui_message_sub = subs(ui_gateway);
        let socket_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::from([1, 2, 4, 5])), 4455);
        let mut client_by_id: HashMap<u64, WebSocketSink> = HashMap::new();
        client_by_id.insert(123, client_mock);
        let mut client_id_by_socket_addr: HashMap<SocketAddr, u64> = HashMap::new();
        client_id_by_socket_addr.insert(socket_addr, 123);
        let mut socket_addr_by_client_id: HashMap<u64, SocketAddr> = HashMap::new();
        socket_addr_by_client_id.insert(123, socket_addr);
        let inner_arc = Arc::new(Mutex::new(WebSocketSupervisorInner {
            port: 0,
            next_client_id: 0,
            from_ui_message_sub,
            client_id_by_socket_addr,
            socket_addr_by_client_id,
            client_by_id,
        }));
        let msg = NodeToUiMessage {
            target: ClientId(123),
            body: UiDescriptorResponse {
                node_descriptor_opt: None,
            }
            .tmb(111),
        };
        let inner = inner_arc.lock().expect("WebSocketSupervisor is dead");

        WebSocketSupervisorReal::send_msg(inner, msg);

        let (client_id_by_socket_addr_expected, socket_addr_by_client_id_expected) =
            if client_is_retained_after_error {
                (Some(&123), Some(&socket_addr))
            } else {
                (None, None)
            };
        assert_eq!(
            inner.client_id_by_socket_addr.get(&socket_addr),
            client_id_by_socket_addr_expected
        );
        assert_eq!(
            inner.client_by_id.get(&123).is_some(),
            client_is_retained_after_error
        );
        assert_eq!(
            inner.socket_addr_by_client_id.get(&123),
            socket_addr_by_client_id_expected
        )
    }

    #[test]
    fn can_handle_transmit_failure() {
        init_test_logging();
        transmit_failure_assertion();
        TestLogHandler::new().exists_log_containing(
            "WARN: WebSocketSupervisor: Client 123 hit a fatal flush error: BrokenPipe, dropping the client",
        );
    }

    #[test]
    fn once_a_client_sends_a_close_no_more_data_is_accepted() {
        let port = find_free_port();
        let (ui_gateway, ui_gateway_awaiter, ui_gateway_recording_arc) = make_recorder();
        let (tx, rx) = bounded(1);
        let ui_message_sub = subs(ui_gateway);

        let _subject = WebSocketSupervisorReal::new(port, ui_message_sub, 1);

        let mut client = await_value(None, || UiConnection::make(port, NODE_UI_PROTOCOL)).unwrap();
        client.send(UiShutdownRequest {});
        client.send_message(&Message::Close(None));
        client.send(UiStartOrder {});
        client.shutdown();
        ui_gateway_awaiter.await_message_count(1);
        thread::sleep(Duration::from_millis(500)); // make sure there's not another message sent
        let ui_gateway_recording = ui_gateway_recording_arc.lock().unwrap();
        assert_eq!(
            ui_gateway_recording.get_record::<NodeFromUiMessage>(0),
            &NodeFromUiMessage {
                client_id: 0,
                body: UiShutdownRequest {}.tmb(0),
            }
        );
        assert_eq!(ui_gateway_recording.len(), 1);
        let mail = rx.try_recv().unwrap();
        let inner_clone = mail.lock().unwrap();
        assert!(inner_clone.client_by_id.is_empty());
        assert!(inner_clone.client_id_by_socket_addr.is_empty());
        assert!(inner_clone.socket_addr_by_client_id.is_empty())
    }

    #[test]
    fn a_client_that_violates_the_protocol_is_terminated() {
        let port = find_free_port();
        let (ui_gateway, ui_gateway_awaiter, ui_gateway_recording_arc) = make_recorder();
        let ui_message_sub = subs(ui_gateway);

        let _subject = WebSocketSupervisorReal::new(port, ui_message_sub, 1);

        let mut client = await_value(None, || UiConnection::make(port, "MASQNode-UIv2")).unwrap();
        client.send(UiShutdownRequest {});
        {
            let writer = client.writer();
            writer.write(b"Booga!").unwrap();
        }
        client.send(UiStartOrder {});
        ui_gateway_awaiter.await_message_count(1);
        thread::sleep(Duration::from_millis(500)); // make sure there's not another message sent
        let ui_gateway_recording = ui_gateway_recording_arc.lock().unwrap();
        assert_eq!(
            ui_gateway_recording.get_record::<NodeFromUiMessage>(0),
            &NodeFromUiMessage {
                client_id: 0,
                body: UiShutdownRequest {}.tmb(0)
            }
        );
        assert_eq!(ui_gateway_recording.len(), 1);
    }

    fn msg_received_assertion(
        mut client_rx: UnboundedReceiver<Message>,
        expected_target: MessageTarget,
    ) -> NodeToUiMessage {
        match client_rx.recv() {
            Some(Message::Text(json)) =>
                UiTrafficConverter::new_unmarshal_to_ui(json.as_str(), expected_target).unwrap(),
            Some(x) => panic! ("send should have been called with OwnedMessage::Text, but was called with {:?} instead", x),
            None => panic! ("send should have been called, but wasn't"),
        }
    }

    #[test]
    fn send_msg_with_a_client_id_sends_a_message_to_the_client() {
        let port = find_free_port();
        let (ui_gateway, _, _) = make_recorder();
        let ui_message_sub = subs(ui_gateway);
        let subject = WebSocketSupervisorReal::new(port, ui_message_sub, 1);
        let (one_mock_client, mut one_mock_client_rx) = make_websocket_sink_pair();
        let (another_mock_client, mut another_mock_client_rx) = make_websocket_sink_pair();
        let one_client_id = subject.inject_client(one_mock_client);
        let another_client_id = subject.inject_client(another_mock_client);
        let msg = NodeToUiMessage {
            target: ClientId(one_client_id),
            body: MessageBody {
                opcode: "booga".to_string(),
                path: FireAndForget,
                payload: Ok("{}".to_string()),
            },
        };

        subject.send_msg(msg.clone());

        let actual_message = msg_received_assertion(one_mock_client_rx, ClientId(one_client_id));
        assert_eq!(actual_message, msg);
        assert_eq!(another_mock_client_rx.recv(), None);
    }

    #[test]
    fn send_msg_with_all_except_sends_a_message_to_all_except() {
        let port = find_free_port();
        let (ui_gateway, _, _) = make_recorder();
        let ui_message_sub = subs(ui_gateway);
        let subject = WebSocketSupervisorReal::new(port, ui_message_sub, 2);
        let (one_mock_client, mut one_mock_client_rx) = make_websocket_sink_pair();
        let (another_mock_client, mut another_mock_client_rx) = make_websocket_sink_pair();
        let one_client_id = subject.inject_client(one_mock_client);
        let another_client_id = subject.inject_client(another_mock_client);
        let msg = NodeToUiMessage {
            target: AllExcept(another_client_id),
            body: MessageBody {
                opcode: "booga".to_string(),
                path: FireAndForget,
                payload: Ok("{}".to_string()),
            },
        };

        subject.send_msg(msg.clone());

        let actual_message =
            msg_received_assertion(one_mock_client_rx, AllExcept(another_client_id));
        assert_eq!(actual_message, msg);
        assert_eq!(another_mock_client_rx.recv(), None);
    }

    #[test]
    fn send_msg_with_all_clients_sends_a_message_to_all_clients() {
        let port = find_free_port();
        let (ui_gateway, _, _) = make_recorder();
        let ui_message_sub = subs(ui_gateway);
        let subject = WebSocketSupervisorReal::new(port, ui_message_sub, 2);
        let (one_mock_client, mut one_mock_client_rx) = make_websocket_sink_pair();
        let (another_mock_client, mut another_mock_client_rx) = make_websocket_sink_pair();
        let one_client_id = subject.inject_client(one_mock_client);
        let another_client_id = subject.inject_client(another_mock_client);
        let msg = NodeToUiMessage {
            target: MessageTarget::AllClients,
            body: MessageBody {
                opcode: "booga".to_string(),
                path: FireAndForget,
                payload: Ok("{}".to_string()),
            },
        };

        subject.send_msg(msg.clone());

        let one_mock_client_ref = subject.get_mock_client(one_client_id);
        let actual_message = msg_received_assertion(one_mock_client_rx, AllClients);
        assert_eq!(actual_message, msg);
        let actual_message = msg_received_assertion(another_mock_client_rx, AllClients);
        assert_eq!(actual_message, msg);
    }

    #[test]
    fn send_msg_fails_on_send_and_so_logs_and_removes_the_client() {
        init_test_logging();

        transmit_failure_assertion();

        TestLogHandler::new().exists_log_containing(
            "ERROR: WebSocketSupervisor: Error sending to client 123: BrokenPipe, dropping the client",
        );
    }

    #[test]
    fn send_msg_fails_to_look_up_client_to_send_to() {
        init_test_logging();
        let port = find_free_port();
        let (ui_gateway, _, _) = make_recorder();
        let ui_message_sub = subs(ui_gateway);
        let subject = WebSocketSupervisorReal::new(port, ui_message_sub, 0);
        let msg = NodeToUiMessage {
            target: MessageTarget::ClientId(7),
            body: MessageBody {
                opcode: "booga".to_string(),
                path: FireAndForget,
                payload: Ok("{}".to_string()),
            },
        };

        subject.send_msg(msg);

        TestLogHandler::new().await_log_containing(
            "WebsocketSupervisor: WARN: Tried to send to an absent client 7",
            1000,
        );
    }
}
