// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
use actix::Recipient;
use futures_util::{SinkExt, StreamExt};
use masq_lib::constants::UNMARSHAL_ERROR;
use masq_lib::logger::Logger;
use masq_lib::messages::{ToMessageBody, UiUnmarshalError};
use masq_lib::ui_gateway::MessagePath::Conversation;
use masq_lib::ui_gateway::MessageTarget::{AllClients, AllExcept, ClientId};
use masq_lib::ui_gateway::{MessageBody, NodeFromUiMessage, NodeToUiMessage};
use masq_lib::ui_traffic_converter::UiTrafficConverter;
use masq_lib::ui_traffic_converter::UnmarshalError::{Critical, NonCritical};
use masq_lib::utils::{localhost, ExpectValue};
use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;
use itertools::Itertools;
use tokio::task;
use tokio::sync::mpsc::unbounded_channel;
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

// TODO: Needs a better name. Used by both WebSocketSupervisorReal and MasqNodeUiv2Handler.
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
        let locked_inner = self.inner_arc
            .lock()
            .expect("WebSocketSupervisor clients are dying");
        Self::send_msg(locked_inner, msg);
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
            inner_arc,
        }
    }

    async fn listen_for_connections_on(
        socket_addr: SocketAddr,
        from_ui_message_sub: Recipient<NodeFromUiMessage>,
        connections_to_accept: usize, // TODO: Figure a way to bring this back into service
    ) -> WWResult<()> {
        todo!("Make sure this is covered by tests");
        // let handler = MasqNodeUiv2Handler::new(socket_addr.port(), from_ui_message_sub);
        // let server = WebSocketServer::new(Arc::new(handler), None);
        // let future = server.listen(socket_addr.to_string().as_str(), None);
        // future
    }

    fn filter_clients<'a, P>(
        locked_inner: &'a MutexGuard<WebSocketSupervisorInner>,
        predicate: P,
    ) -> Vec<(u64, &'a WebSocketSink)>
    where
        P: FnOnce(&(&u64, &WebSocketSink)) -> bool,
    {
        locked_inner
            .client_by_id
            .iter()
            .filter(predicate)
            .map(|(id, item)| (*id, item.as_ref()))
            .collect()
    }

    // TODO: This is called both by WebSocketSupervisor and MasqNodeUiv2Handler. It should be
    // moved outside of the WebSocketSupervisorReal impl block. Perhaps it should be made a method
    // of WebSocketSupervisorInner.
    fn send_msg(
        mut locked_inner: MutexGuard<'_, WebSocketSupervisorInner>,
        msg: NodeToUiMessage,
    ) {
        let clients = match msg.target {
            ClientId(n) => {
                let clients = Self::filter_clients(&locked_inner, |(id, _)| **id == n);
                if !clients.is_empty() {
                    clients
                } else {
                    Self::log_absent_client(n);
                    return;
                }
            }
            AllExcept(n) => Self::filter_clients(&locked_inner, |(id, _)| **id != n),
            AllClients => Self::filter_clients(&locked_inner, |_| true),
        };
        let json = UiTrafficConverter::new_marshal(msg.body);
        if let Some(dead_client_ids) = Self::send_to_clients(clients, json) {
            Self::handle_sink_errs(dead_client_ids, &mut locked_inner)
        }
    }

    fn handle_sink_errs(
        dead_client_ids: Vec<u64>,
        locked_inner: &mut MutexGuard<WebSocketSupervisorInner>,
    ) {
        dead_client_ids.into_iter().for_each(|client_id| {
            Self::emergency_client_removal(client_id, locked_inner);
            warning!(
                Logger::new("WebSocketSupervisor"),
                "Error sending to client {}; dropping the client",
                client_id
            )
        })
    }

    fn send_to_clients(
        clients: Vec<(u64, &WebSocketSink)>,
        json: String,
    ) -> Option<Vec<u64>> { // list of clients that died and could not receive the message
        let dead_client_ids = clients.into_iter()
            .map(move |(client_id, client)| {
                let result = client.send(Message::Text(json.clone()));
                (client_id, result)
            }
        )
            .flat_map(|(client_id, result)| {
            match result {
                Ok(_) => None,
                Err(_error_with_message) => Some(client_id ),
            }
        })
        .collect_vec();
        if dead_client_ids.is_empty() {
            None
        } else {
            Some(dead_client_ids)
        }
    }

    fn emergency_client_removal(
        client_id: u64,
        locked_inner: &mut MutexGuard<WebSocketSupervisorInner>,
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
            let close_message = Message::Close(None);
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
    ) -> io::Result<Box<dyn WebSocketSupervisor>>;
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
    fn new(
        port: u16,
        from_ui_message_sub: Recipient<NodeFromUiMessage>,
    ) -> Self {
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
                Ok(())
            }
            Err(Critical(e)) => {
                error!(
                    &self.logger,
                    "Bad message from client {} at {}: {:?}:\n{}\n",
                    client_id,
                    Self::peer_addr_string(client_id, &locked_inner),
                    Critical(e.clone()),
                    message
                );
                WebSocketSupervisorReal::send_msg(
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
                Ok(())
            }
            Err(NonCritical(opcode, context_id_opt, e)) => {
                error!(
                    &self.logger,
                    "Bad message from client {} at {}: {:?}:\n{}\n",
                    client_id,
                    Self::peer_addr_string(client_id, &locked_inner),
                    NonCritical(opcode.clone(), context_id_opt, e.clone()),
                    message
                );
                match context_id_opt {
                    None => {
                        WebSocketSupervisorReal::send_msg(
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
                        WebSocketSupervisorReal::send_msg(
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
                Ok(())
            }
        }
    }

    async fn handle_close_message(self: &Arc<Self>, client_id: u64) -> WWResult<()> {
        let mut locked_inner = self
            .inner_mutex
            .lock()
            .expect("Client futures are panicking");
        info!(
            &self.logger,
            "UI client {} at {} disconnected from port {}",
            client_id,
            Self::peer_addr_string(client_id, &locked_inner),
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
            Self::peer_addr_string(
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
        locked_inner: &mut MutexGuard<'_, WebSocketSupervisorInner>,
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
        let close_message = Message::Close(None);
        match client.send(close_message).await {
            Err(e) => warning!(
                logger,
                "Error acknowledging connection closure from UI client {} at {}: {:?}",
                client_id,
                Self::peer_addr_string(client_id, locked_inner),
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

    fn peer_addr_string(
        client_id: u64,
        locked_inner: &MutexGuard<WebSocketSupervisorInner>,
    ) -> String {
        let socket_addr_opt = locked_inner.socket_addr_by_client_id.get(&client_id);
        if let Some(socket_addr) = socket_addr_opt {
            socket_addr.to_string()
        } else {
            "an unknown address".to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
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
    use masq_lib::ui_gateway::{MessageTarget, NodeFromUiMessage};
    use masq_lib::ui_traffic_converter::UiTrafficConverter;
    use masq_lib::utils::{find_free_port, localhost};
    use std::net::{IpAddr, Ipv4Addr, Shutdown, TcpStream};
    use std::time::Duration;
    use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
    use workflow_websocket::client::{ConnectOptions, WebSocket};
    use workflow_websocket::client::message::Message;

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
        let (sender, receiver) = unbounded_channel::<Message>();
        (sender.into(), receiver)
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

    async fn wait_for_client(port: u16, protocol: &str) -> WebSocket {
        wait_for(100, 1000, || {
            match make_client(port, protocol) {
                Ok(client) => Some(client),
                Err(e) => {
                    println!("Couldn't make client yet: {}", e);
                    None
                },
            }
        }).await
    }

    async fn wait_for_server(port: u16) {
        wait_for(100, 1000, || {
            match TcpStream::connect(SocketAddr::new(localhost(), port)) {
                Ok(_) => Some(()),
                Err(_) => None,
            }
        }).await
    }

    async fn wait_for<F, T>(interval_ms: u64, remaining_ms: u64, mut f: F) -> T
    where
        F: FnMut() -> Option<T>,
    {
        if remaining_ms <= 0 {
            panic!("Timeout waiting for condition");
        }
        match f() {
            Some(result) => result,
            None => {
                tokio::time::sleep(Duration::from_millis(interval_ms)).await;
                Box::pin(wait_for(interval_ms, remaining_ms - interval_ms, f)).await
            }
        }
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

    #[tokio::test]
    async fn data_for_a_newly_connected_client_is_set_properly() {
        init_test_logging();
        let port = find_free_port();
        let (ui_gateway, _, ui_gateway_recording_arc) = make_recorder();
        let system = System::new();
        let recipient = ui_gateway.start().recipient();
        let subject = WebSocketSupervisorReal::new(port, recipient, 1);
        wait_for_server(port);

        let mut ui_connection: UiConnection = UiConnection::new(port, NODE_UI_PROTOCOL).await.unwrap();

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
        }).await;
        System::current().stop();
        system.run().unwrap();
        let recording = ui_gateway_recording_arc.lock().unwrap();
        let message = recording.get_record::<UiCheckPasswordRequest>(0);
        assert_eq!(
            message,
            &UiCheckPasswordRequest {
                db_password_opt: Some("booga".to_string())
            }
        );
        todo!("Check for proper connection-progress logs")
    }

    #[tokio::test]
    async fn rejects_connection_attempt_with_improper_protocol_name() {
        init_test_logging();
        let port = find_free_port();
        let (ui_gateway, _, ui_gateway_recording_arc) = make_recorder();
        let system = System::new();
        let recipient = ui_gateway.start().recipient();
        let subject = WebSocketSupervisorReal::new(port, recipient, 1);
        wait_for_server(port);

        let result: Result<UiConnection, String> = UiConnection::new(port, "MASQNode-UI").await;

        assert_eq!(
            result.err().unwrap(),
            "UI attempted connection without protocol MASQNode-UIv2: [\"MASQNode-UI\"]".to_string()
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

    #[tokio::test]
    async fn logs_unexpected_binary_ping_pong_websocket_messages() {
        init_test_logging();
        let port = find_free_port();
        let (ui_gateway, _, ui_gateway_recording_arc) = make_recorder();
        let system = System::new();
        let recipient = ui_gateway.start().recipient();
        let subject = WebSocketSupervisorReal::new(port, recipient, 1);
        wait_for_server(port);

        {
            let mut ui_connection: UiConnection =
                UiConnection::new(port, NODE_UI_PROTOCOL).await.unwrap();
            ui_connection.send_message(Message::Binary(vec![1u8, 2u8, 3u8, 4u8])).await;
            // Low-level messages inaccessible to the client but not to the server.
            // We'll need to find some way to make a lower-level element (probably
            // Tungstenite) send these messages.
            // ui_connection.send_message(Message::Ping(vec![1u8, 2u8, 3u8, 4u8]));
            // ui_connection.send_message(Message::Pong(vec![1u8, 2u8, 3u8, 4u8]));
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

    #[tokio::test]
    async fn can_connect_two_clients_and_receive_messages_from_them() {
        let port = find_free_port();
        let (ui_gateway, ui_gateway_awaiter, ui_gateway_recording_arc) = make_recorder();

        let ui_message_sub = subs(ui_gateway);
        let subject = WebSocketSupervisorReal::new(port, ui_message_sub, 2);
        let mut one_client = wait_for_client(port, NODE_UI_PROTOCOL).await;
        let mut another_client = wait_for_client(port, NODE_UI_PROTOCOL).await;
        one_client
            .send(Message::Text(r#"{"opcode": "one", "payload": {}}"#.to_string()))
            .await
            .unwrap();
        another_client
            .send(Message::Text(r#"{"opcode": "another", "payload": {}}"#.to_string()))
            .await
            .unwrap();
        one_client
            .send(Message::Text(r#"{"opcode": "athird", "payload": {}}"#.to_string()))
            .await
            .unwrap();

        one_client.send(Message::Close).await.unwrap();
        let one_close_msg = one_client.recv().await.unwrap();
        another_client.send(Message::Close).await.unwrap();
        let another_close_msg = another_client.recv().await.unwrap();

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
        assert_eq!(one_close_msg, Message::Close);
        assert_eq!(another_close_msg, Message::Close);
    }

    #[tokio::test]
    async fn logs_badly_formatted_json_and_returns_unmarshal_error() {
        init_test_logging();
        let (recorder, _, recording_arc) = make_recorder();
        let mut subject = MasqNodeUiv2Handler::new(1234, recorder.start().recipient());
        let test_name = "logs_badly_formatted_json_and_returns_unmarshal_error";
        let logger = Logger::new(test_name);
        subject.logger = logger;
        let subject_arc = Arc::new(subject);
        let bad_json = "}: I am badly-formatted JSON :{";
        let client_id = 4321u64;
        let (websocket_sink, mut client_rx) = make_websocket_sink_pair();

        subject_arc.message(&client_id, Message::Text(bad_json.to_string()).into(), &websocket_sink).await.unwrap();

        let expected_traffic_conversion_message =
            "Couldn't parse text as JSON: Error(\"expected value\", line: 1, column: 1)".to_string();
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
        let actual_json = match client_rx.recv().await.unwrap() {
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

    #[tokio::test]
    async fn bad_one_way_message_is_logged_and_returns_error() {
        init_test_logging();
        let (recorder, _, recording_arc) = make_recorder();
        let mut subject = MasqNodeUiv2Handler::new(1234, recorder.start().recipient());
        let test_name = "bad_one_way_message_is_logged_and_returns_error";
        let logger = Logger::new(test_name);
        subject.logger = logger;
        let subject_arc = Arc::new(subject);
        let bad_message_json = r#"{"opcode":"shutdown"}"#;
        let client_id = 4321u64;
        let (websocket_sink, mut client_rx) = make_websocket_sink_pair();

        subject_arc.message(&client_id, Message::Text(bad_message_json.to_string()).into(), &websocket_sink).await.unwrap();

        let expected_traffic_conversion_message =
            "Required field was missing: payload, error".to_string();
        let expected_unmarshal_message = format!(
            "Error unmarshalling 'shutdown' message: {}",
            expected_traffic_conversion_message
        );
        TestLogHandler::new().exists_log_containing(
            format!(
                "ERROR: {}: Bad message from client 4321 at localhost:1234: {}",
                test_name,
                expected_unmarshal_message
            )
                .as_str(),
        );
        let actual_json = match client_rx.recv().await.unwrap() {
            Message::Text(s) => s,
            x => panic!("Expected OwnedMessage::Text, got {:?}", x),
        };
        let actual_struct =
            UiTrafficConverter::new_unmarshal_to_ui(&actual_json, ClientId(0)).unwrap();
        assert_eq!(actual_struct.target, ClientId(4321));
        assert_eq!(
            UiUnmarshalError::fmb(actual_struct.body).unwrap().0,
            UiUnmarshalError {
                message: expected_traffic_conversion_message,
                bad_data: bad_message_json.to_string(),
            }
        )
    }

    #[tokio::test]
    async fn bad_two_way_message_is_logged_and_returns_error() {
        init_test_logging();
        let (recorder, _, recording_arc) = make_recorder();
        let mut subject = MasqNodeUiv2Handler::new(1234, recorder.start().recipient());
        let test_name = "bad_two_way_message_is_logged_and_returns_error";
        let logger = Logger::new(test_name);
        subject.logger = logger;
        let subject_arc = Arc::new(subject);
        let bad_message_json = r#"{"opcode":"setup", "contextId":3333}"#;
        let client_id = 4321u64;
        let (websocket_sink, mut client_rx) = make_websocket_sink_pair();

        subject_arc.message(&client_id, Message::Text(bad_message_json.to_string()).into(), &websocket_sink).await.unwrap();

        let expected_traffic_conversion_message =
            "Required field was missing: payload, error".to_string();
        let expected_unmarshal_message = format!(
            "Error unmarshalling 'setup' message: {}",
            expected_traffic_conversion_message
        );
        TestLogHandler::new().exists_log_containing(
            format!(
                "ERROR: {}: Bad message from client 4321 at localhost:1234: {}",
                test_name,
                expected_unmarshal_message
            )
            .as_str(),
        );

        let actual_json = match client_rx.recv().await.unwrap() {
            Message::Text(s) => s,
            x => panic!("Expected OwnedMessage::Text, got {:?}", x),
        };
        let actual_struct =
            UiTrafficConverter::new_unmarshal_to_ui(&actual_json, ClientId(0)).unwrap();
        assert_eq!(
            actual_struct,
            NodeToUiMessage {
                target: ClientId(4321),
                body: MessageBody {
                    opcode: "setup".to_string(),
                    path: Conversation(3333),
                    payload: Err((UNMARSHAL_ERROR, expected_traffic_conversion_message))
                }
            }
        );
    }

    async fn transmit_failure_assertion() {
        let client_mock = {
            let (client, _client_rx) = make_websocket_sink_pair();
            client
        };
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
        let assertable_inner_arc = inner_arc.clone();
        let inner = inner_arc.lock().unwrap();

        WebSocketSupervisorReal::send_msg(inner, msg).await;

        let assertable_inner = assertable_inner_arc.lock().unwrap();
        assert_eq!(assertable_inner.client_id_by_socket_addr.get(&socket_addr), None);
        assert_eq!(assertable_inner.client_by_id.get(&123).is_none(), true);
        assert_eq!(assertable_inner.socket_addr_by_client_id.get(&123), None)
    }

    #[tokio::test]
    async fn can_handle_transmit_failure() {
        init_test_logging();

        transmit_failure_assertion().await;

        TestLogHandler::new().exists_log_containing(
            "WARN: WebSocketSupervisor: Client 123 hit a fatal flush error: BrokenPipe, dropping the client",
        );
    }

    #[tokio::test]
    async fn once_a_client_sends_a_close_no_more_data_is_accepted() {
        let port = find_free_port();
        let (ui_gateway, ui_gateway_awaiter, ui_gateway_recording_arc) = make_recorder();
        let (tx, rx) = bounded(1);
        let ui_message_sub = subs(ui_gateway);

        let _subject = WebSocketSupervisorReal::new(port, ui_message_sub, 1);

        let mut client = await_value(None, || {
            make_rt().block_on(UiConnection::new(port, NODE_UI_PROTOCOL))
        }).unwrap();
        client.send(UiShutdownRequest {}).await;
        client.send_message(Message::Close).await;
        client.send(UiStartOrder {}).await;
        client.shutdown().await.unwrap();
        ui_gateway_awaiter.await_message_count(1);
        tokio::time::sleep(Duration::from_millis(500)).await; // make sure there's not another message sent
        let ui_gateway_recording = ui_gateway_recording_arc.lock().unwrap();
        assert_eq!(
            ui_gateway_recording.get_record::<NodeFromUiMessage>(0),
            &NodeFromUiMessage {
                client_id: 0,
                body: UiShutdownRequest {}.tmb(0),
            }
        );
        assert_eq!(ui_gateway_recording.len(), 1);
        let mail: Arc<Mutex<WebSocketSupervisorInner>> = rx.try_recv().unwrap();
        let inner_clone = mail.lock().unwrap();
        assert!(inner_clone.client_by_id.is_empty());
        assert!(inner_clone.client_id_by_socket_addr.is_empty());
        assert!(inner_clone.socket_addr_by_client_id.is_empty())
    }

    #[tokio::test]
    async fn a_client_that_violates_the_protocol_is_terminated() {
        let port = find_free_port();
        let (ui_gateway, ui_gateway_awaiter, ui_gateway_recording_arc) = make_recorder();
        let ui_message_sub = subs(ui_gateway);

        let _subject = WebSocketSupervisorReal::new(port, ui_message_sub, 1);

        let mut client = TcpStream::connect(SocketAddr::new(localhost(), port)).unwrap();
        client.write(b"GET / HTTP/1.1\r\nHost: 127.0.01\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n").unwrap();
        let mut buf = [0u8; 1024];
        let _ = client.read(&mut buf).unwrap();
        client.write(b"Booga!").unwrap();
        ui_gateway_awaiter.await_message_count(1);
        tokio::time::sleep(Duration::from_millis(500)).await; // make sure there's not another message sent
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

    async fn msg_received_assertion(
        mut client_rx: UnboundedReceiver<Message>,
        expected_target: MessageTarget,
    ) -> NodeToUiMessage {
        match client_rx.recv().await {
            Some(Message::Text(json)) =>
                UiTrafficConverter::new_unmarshal_to_ui(json.as_str(), expected_target).unwrap(),
            Some(x) => panic! ("send should have been called with OwnedMessage::Text, but was called with {:?} instead", x),
            None => panic! ("send should have been called, but wasn't"),
        }
    }

    #[tokio::test]
    async fn send_msg_with_a_client_id_sends_a_message_to_the_client() {
        let port = find_free_port();
        let (ui_gateway, _, _) = make_recorder();
        let ui_message_sub = subs(ui_gateway);
        let subject = WebSocketSupervisorReal::new(port, ui_message_sub, 1);
        let (one_mock_client, one_mock_client_rx) = make_websocket_sink_pair();
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

        let actual_message = msg_received_assertion(one_mock_client_rx, ClientId(one_client_id)).await;
        assert_eq!(actual_message, msg);
        assert_eq!(another_mock_client_rx.recv().await, None);
    }

    #[tokio::test]
    async fn send_msg_with_all_except_sends_a_message_to_all_except() {
        let port = find_free_port();
        let (ui_gateway, _, _) = make_recorder();
        let ui_message_sub = subs(ui_gateway);
        let subject = WebSocketSupervisorReal::new(port, ui_message_sub, 2);
        let (one_mock_client, one_mock_client_rx) = make_websocket_sink_pair();
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
            msg_received_assertion(one_mock_client_rx, AllExcept(another_client_id)).await;
        assert_eq!(actual_message, msg);
        assert_eq!(another_mock_client_rx.recv().await, None);
    }

    #[tokio::test]
    async fn send_msg_with_all_clients_sends_a_message_to_all_clients() {
        let port = find_free_port();
        let (ui_gateway, _, _) = make_recorder();
        let ui_message_sub = subs(ui_gateway);
        let subject = WebSocketSupervisorReal::new(port, ui_message_sub, 2);
        let (one_mock_client, one_mock_client_rx) = make_websocket_sink_pair();
        let (another_mock_client, another_mock_client_rx) = make_websocket_sink_pair();
        let one_client_id = subject.inject_client(one_mock_client);
        let another_client_id = subject.inject_client(another_mock_client);
        let msg = NodeToUiMessage {
            target: AllClients,
            body: MessageBody {
                opcode: "booga".to_string(),
                path: FireAndForget,
                payload: Ok("{}".to_string()),
            },
        };

        subject.send_msg(msg.clone());

        let actual_message = msg_received_assertion(one_mock_client_rx, AllClients).await;
        assert_eq!(actual_message, msg);
        let actual_message = msg_received_assertion(another_mock_client_rx, AllClients).await;
        assert_eq!(actual_message, msg);
    }

    #[tokio::test]
    async fn send_msg_fails_on_send_and_so_logs_and_removes_the_client() {
        init_test_logging();

        transmit_failure_assertion().await;

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
            target: ClientId(7),
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
