// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
use actix::Recipient;
use futures_util::future::join_all;
use futures_util::io::{BufReader, BufWriter};
use itertools::Itertools;
use masq_lib::constants::UNMARSHAL_ERROR;
use masq_lib::logger::Logger;
use masq_lib::messages::{ToMessageBody, UiUnmarshalError, NODE_UI_PROTOCOL};
use masq_lib::ui_gateway::MessagePath::Conversation;
use masq_lib::ui_gateway::MessageTarget::{AllClients, AllExcept, ClientId};
use masq_lib::ui_gateway::{MessageBody, NodeFromUiMessage, NodeToUiMessage};
use masq_lib::ui_traffic_converter::UiTrafficConverter;
use masq_lib::ui_traffic_converter::UnmarshalError::{Critical, NonCritical};
use masq_lib::utils::{localhost, ExpectValue};
use masq_lib::websockets_types::{WSReceiver, WSSender};
use rustc_hex::ToHex;
use soketto::handshake::server::Response;
use soketto::handshake::Server;
use soketto::Incoming;
use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::{Mutex, MutexGuard};
use async_trait::async_trait;
use tokio::net::TcpStream;
use tokio_util::compat::{Compat, TokioAsyncReadCompatExt};

#[async_trait]
pub trait WebSocketSupervisor: Send + Sync {
    async fn send_msg(&self, msg: NodeToUiMessage);
}

#[async_trait]
trait ClientWrapper: Send {
    async fn send_text(&mut self, text: String) -> Result<(), soketto::connection::Error>;
    async fn flush(&mut self) -> Result<(), soketto::connection::Error>;
    async fn close(&mut self) -> Result<(), soketto::connection::Error>;
}

struct ClientWrapperReal {
    delegate: WSSender,
}

impl ClientWrapperReal {
    fn new(delegate: WSSender) -> Self {
        Self { delegate }
    }
}

#[async_trait]
impl ClientWrapper for ClientWrapperReal {
    async fn send_text(&mut self, text: String) -> Result<(), soketto::connection::Error> {
        self.delegate.send_text(text).await
    }

    async fn flush(&mut self) -> Result<(), soketto::connection::Error> {
        self.delegate.flush().await
    }

    async fn close(&mut self) -> Result<(), soketto::connection::Error> {
        self.delegate.close().await
    }
}

// TODO: Needs a better name. Used by both WebSocketSupervisorReal and MasqNodeUiv2Handler.
pub struct WebSocketSupervisorInner {
    port: u16,
    next_client_id: u64,
    from_ui_message_sub: Recipient<NodeFromUiMessage>,
    client_id_by_socket_addr: HashMap<SocketAddr, u64>,
    socket_addr_by_client_id: HashMap<u64, SocketAddr>,
    client_by_id: HashMap<u64, Box<dyn ClientWrapper>>,
    logger: Logger,
}

pub struct WebSocketSupervisorReal {
    inner_arc: Arc<Mutex<WebSocketSupervisorInner>>,
}

#[async_trait]
impl WebSocketSupervisor for WebSocketSupervisorReal {
    async fn send_msg(&self, msg: NodeToUiMessage) {
        Self::send_msg_inner(self.inner_arc.clone(), msg).await;
    }
}

impl WebSocketSupervisorReal {
    pub fn new(
        port: u16,
        from_ui_message_sub: Recipient<NodeFromUiMessage>,
        connections_to_accept: usize,
    ) -> WebSocketSupervisorReal {
        let logger = Logger::new("WebSocketSupervisor");
        let inner_arc = Arc::new(Mutex::new(WebSocketSupervisorInner {
            port,
            next_client_id: 1,
            from_ui_message_sub: from_ui_message_sub.clone(),
            client_id_by_socket_addr: HashMap::new(),
            socket_addr_by_client_id: HashMap::new(),
            client_by_id: HashMap::new(),
            logger,
        }));
        let inner_arc_clone = inner_arc.clone();
        tokio::spawn(Self::listen_for_connections_on(
            SocketAddr::new(localhost(), port),
            inner_arc_clone,
            connections_to_accept,
        ));
        WebSocketSupervisorReal { inner_arc }
    }

    async fn listen_for_connections_on(
        socket_addr: SocketAddr,
        inner_arc: Arc<Mutex<WebSocketSupervisorInner>>,
        mut connections_to_accept: usize,
    ) -> Result<(), ()> {
        let logger = {
            let inner = inner_arc.lock().await;
            inner.logger.clone()
        };
        let tcp_listener = tokio::net::TcpListener::bind(socket_addr)
            .await
            .unwrap_or_else(|e| panic!("Could not create listener for {}: {:?}", socket_addr, e));
        loop {
            if connections_to_accept == 0 {
                break Ok(());
            }
            info!( logger, "Listening for new WebSocket client connections on {}", socket_addr);
            let (stream, peer_addr) = tcp_listener
                .accept()
                .await
                // TODO: This is not cool. We can't be letting things coming in from the outside
                // panic the Node.
                .expect("Error accepting incoming connection to MockWebsocketsServer");
            info!(logger, "Accepted new WebSocket client connection from {}", peer_addr);
            let mut server = Server::new(BufReader::new(BufWriter::new(stream.compat())));
            server.add_protocol(NODE_UI_PROTOCOL);
            let inner_arc_clone = inner_arc.clone();
            tokio::spawn(Self::handle_client(peer_addr, server, inner_arc_clone));
            connections_to_accept -= 1;
        }
    }

    async fn handle_client<'a>(
        peer_addr: SocketAddr,
        mut server: Server<'a, BufReader<BufWriter<Compat<TcpStream>>>>,
        inner_arc: Arc<Mutex<WebSocketSupervisorInner>>,
    ) {
        let logger = {
            let inner = inner_arc.lock().await;
            inner.logger.clone()
        };
        info!(logger, "Handshaking with new WebSocket client at {}", peer_addr);
        let websocket_key_opt = {
            let req = server
                .receive_request()
                .await
                // TODO: This is not cool. We can't be letting things coming in from the outside
                // panic the Node.
                .expect("Error receiving request from client");
            if !req.protocols().contains(&NODE_UI_PROTOCOL) {
                None
            }
            else {
                Some(req.key())
            }
        };
        if websocket_key_opt.is_none() {
            warning!(logger, "New WebSocket client at {} does not support required WebSocket protocol; rejecting connection", peer_addr);
            let reject = Response::Reject {
                status_code: 400,
            };
            server
                .send_response(&reject)
                .await
                .expect("Error sending handshake acceptance to client");
            return;
        }
        let accept = Response::Accept {
            key: websocket_key_opt.expect("Option::is_none() suddenly stopped working"),
            protocol: Some(NODE_UI_PROTOCOL),
        };
        server
            .send_response(&accept)
            .await
            .expect("Error sending handshake acceptance to client");
        info!(logger, "Handshake with new WebSocket client at {} complete", peer_addr);
        let (sender, receiver) = server.into_builder().finish();
        let (client_id, from_ui_message_sub, logger) = {
            let mut locked_inner = inner_arc.lock().await;
            let client_id = locked_inner.next_client_id;
            locked_inner.next_client_id += 1;
            locked_inner
                .client_id_by_socket_addr
                .insert(peer_addr, client_id);
            locked_inner
                .socket_addr_by_client_id
                .insert(client_id, peer_addr);
            locked_inner
                .client_by_id
                .insert(client_id, Box::new(ClientWrapperReal::new(sender)));
            (
                client_id,
                locked_inner.from_ui_message_sub.clone(),
                locked_inner.logger.clone(),
            )
        };
        info!(logger, "New WebSocket client at {} designated with id {}", peer_addr, client_id);
        let _ = Self::conduct_conversation(
            peer_addr,
            client_id,
            receiver,
            inner_arc,
            from_ui_message_sub,
            logger,
        )
        .await;
    }

    async fn conduct_conversation(
        peer_addr: SocketAddr,
        client_id: u64,
        mut receiver: WSReceiver,
        inner_arc: Arc<Mutex<WebSocketSupervisorInner>>,
        from_ui_message_sub: Recipient<NodeFromUiMessage>,
        logger: Logger,
    ) -> Result<(), ()> {
        loop {
            let mut message: Vec<u8> = vec![];
            let message_type = match receiver.receive(&mut message).await {
                Ok(message_type) => message_type,
                Err(e) => {
                    warning!(
                        logger,
                        "Error receiving message from client at {}: {:?}",
                        peer_addr,
                        e
                    );
                    return Err(());
                }
            };
            match message_type {
                Incoming::Data(data_type) => match data_type {
                    soketto::Data::Text(_) => {
                        let text = match String::from_utf8(message.clone()) {
                            Ok(text) => text,
                            Err(e) => {
                                error!(&logger, "WebSocket text message is not UTF-8: {:?}", e);
                                return Err(());
                            }
                        };
                        match UiTrafficConverter::new_unmarshal_from_ui(text.as_str(), client_id) {
                            Ok(from_ui_message) => {
                                from_ui_message_sub
                                    .try_send(from_ui_message)
                                    .expect("UiGateway is dead");
                            }
                            Err(Critical(e)) => {
                                error!(
                                    &logger,
                                    "Bad message from client {} at {}: {:?}:\n{}\n",
                                    client_id,
                                    peer_addr,
                                    Critical(e.clone()),
                                    text
                                );
                                Self::send_unmarshal_error_to_client_without_context(
                                    inner_arc.clone(),
                                    client_id,
                                    message.as_slice(),
                                    e.to_string(),
                                )
                                .await;
                                return Err(());
                            }
                            Err(NonCritical(opcode, context_id_opt, e)) => {
                                error!(
                                    &logger,
                                    "Bad message from client {} at {}: {:?}:\n{}\n",
                                    client_id,
                                    peer_addr,
                                    NonCritical(opcode.clone(), context_id_opt, e.clone()),
                                    text
                                );
                                match context_id_opt {
                                    None => {
                                        Self::send_unmarshal_error_to_client_without_context(
                                            inner_arc.clone(),
                                            client_id,
                                            message.as_slice(),
                                            e.to_string(),
                                        )
                                        .await;
                                    }
                                    Some(context_id) => {
                                        Self::send_unmarshal_error_to_client_with_context(
                                            inner_arc.clone(),
                                            client_id,
                                            opcode,
                                            context_id,
                                            e.to_string(),
                                        )
                                        .await;
                                    }
                                }
                            }
                        }
                    }
                    soketto::Data::Binary(_) => {
                        error!(
                            &logger,
                            "Client {} at {} sent unexpected binary message; ignoring",
                            client_id,
                            peer_addr
                        );
                        return Err(());
                    }
                },
                Incoming::Closed(reason) => {
                    info!(
                        &logger,
                        "UI client {} at {} disconnected: {:?}",
                        client_id,
                        peer_addr,
                        reason
                    );
                    Self::close_connection(inner_arc.clone(), client_id, peer_addr, &logger).await;
                    return Ok(());
                }
                Incoming::Pong(_) => {
                    // We can't write a unit test for this, because Soketto swallows Pongs.
                    error!(
                        &logger,
                        "Pong message from client {} at {} should have been handled by Soketto",
                        client_id,
                        peer_addr
                    );
                }
            }
        }
    }

    fn filter_clients<'a, P>(
        locked_inner: &'a mut MutexGuard<WebSocketSupervisorInner>,
        predicate: P,
    ) -> Vec<(u64, &'a mut (dyn ClientWrapper + 'a))>
    where
        P: Fn(u64) -> bool,
    {
        locked_inner
            .client_by_id
            .iter_mut()
            .filter(|(id_ref_ref, _)| {
                let id = **id_ref_ref;
                predicate(id)
            })
            .map(|(id, item)| {
                let item_ref: &'a mut (dyn ClientWrapper + 'a) = item.as_mut();
                (*id, item_ref)
            })
            .collect()
    }

    async fn send_msg_inner(
        inner_arc: Arc<Mutex<WebSocketSupervisorInner>>,
        msg: NodeToUiMessage,
    ) {
        let mut locked_inner = inner_arc.lock().await;
        let dead_client_ids_opt = {
            let clients = match msg.target {
                ClientId(n) => {
                    let clients = Self::filter_clients(&mut locked_inner, |id| id == n);
                    if !clients.is_empty() {
                        clients
                    } else {
                        Self::log_absent_client(n);
                        return;
                    }
                }
                AllExcept(n) => Self::filter_clients(&mut locked_inner, |id| id != n),
                AllClients => Self::filter_clients(&mut locked_inner, |_| true),
            };
            let json = UiTrafficConverter::new_marshal(msg.body);
            Self::send_to_clients(clients, json).await
        };
        drop(locked_inner);
        if let Some(dead_client_ids) = dead_client_ids_opt {
            Self::handle_sink_errs(dead_client_ids, inner_arc).await;
        }
    }

    async fn handle_sink_errs(
        sink_errors: Vec<SendToClientWebsocketError>,
        inner_arc: Arc<Mutex<WebSocketSupervisorInner>>,
    ) {
        let mut locked_inner = inner_arc.lock().await;
        sink_errors.into_iter().for_each(|sink_error| {
            let (client_id, operation, error) = match sink_error {
                SendToClientWebsocketError::SendError { client_id, error } => {
                    (client_id, "sending", error)
                }
                SendToClientWebsocketError::FlushError { client_id, error } => {
                    (client_id, "flushing", error)
                }
            };
            Self::emergency_client_removal(client_id, &mut locked_inner);
            match operation {
                "sending" => error!(
                    Logger::new("WebSocketSupervisor"),
                    "Error sending to client {}: {:?}, dropping the client",
                    client_id,
                    error
                ),
                _ => error!(
                    Logger::new("WebSocketSupervisor"),
                    "Client {} hit a fatal flush error: {:?}, dropping the client",
                    client_id,
                    error
                ),
            }
        })
    }

    async fn send_to_clients(
        mut clients: Vec<(u64, &mut (dyn ClientWrapper + '_))>,
        json: String,
    ) -> Option<Vec<SendToClientWebsocketError>> {
        // list of clients that died and could not receive the message
        let sink_errors = join_all(clients.iter_mut()
            .map(|(client_id, ref mut client)| async {
                let send_result = client.send_text(json.clone()).await;
                if let Err(error) = send_result {
                    return Some(SendToClientWebsocketError::SendError {
                        client_id: *client_id,
                        error,
                    });
                }
                match client.flush().await {
                    Ok(_) => None,
                    Err(error) => Some(SendToClientWebsocketError::FlushError {
                        client_id: *client_id,
                        error,
                    }),
                }
            },
        ))
        .await;
        let sink_errors = sink_errors
            .into_iter()
            .flatten()
            .collect_vec();
        if sink_errors.is_empty() {
            None
        } else {
            Some(sink_errors)
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

    async fn close_connection(
        inner_arc: Arc<Mutex<WebSocketSupervisorInner>>,
        client_id: u64,
        socket_addr: SocketAddr,
        logger: &Logger,
    ) {
        let mut locked_inner = inner_arc.lock().await;
        let _ = locked_inner.socket_addr_by_client_id.remove(&client_id);
        let mut client = match locked_inner.client_by_id.remove(&client_id) {
            Some(client) => client,
            // TODO: This should be a logged error, not a panic. This is something that came in from outside.
            None => panic!("WebSocketSupervisor got a disconnect from a client that has disappeared from the stable!"),
        };
        match client.close().await {
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
    }

    async fn send_unmarshal_error_to_client_without_context(
        inner_arc: Arc<Mutex<WebSocketSupervisorInner>>,
        client_id: u64,
        bad_data: &[u8],
        error_message: String,
    ) {
        Self::send_msg_inner(
            inner_arc,
            NodeToUiMessage {
                target: ClientId(client_id),
                body: UiUnmarshalError {
                    message: error_message,
                    bad_data: bad_data.to_hex(),
                }
                .tmb(0),
            },
        )
        .await;
    }

    async fn send_unmarshal_error_to_client_with_context(
        inner_arc: Arc<Mutex<WebSocketSupervisorInner>>,
        client_id: u64,
        opcode: String,
        context_id: u64,
        error_message: String,
    ) {
        Self::send_msg_inner(
            inner_arc,
            NodeToUiMessage {
                target: ClientId(client_id),
                body: MessageBody {
                    opcode,
                    path: Conversation(context_id),
                    payload: Err((UNMARSHAL_ERROR, error_message)),
                },
            },
        )
        .await;
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
    SendError {
        client_id: u64,
        error: soketto::connection::Error,
    },
    FlushError {
        client_id: u64,
        error: soketto::connection::Error,
    },
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
    ) -> io::Result<Box<dyn WebSocketSupervisor>> { // TODO This shouldn't be a Result, since there's no way to fail.
        let wss = WebSocketSupervisorReal::new(port, recipient, usize::MAX);
        Ok(Box::new(wss))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use crate::test_utils::assert_contains;
    use crate::test_utils::poll_until_with_attempts;
    use crate::test_utils::recorder::{make_recorder, Recorder};
    use actix::{Actor, Addr};
    use masq_lib::constants::UNMARSHAL_ERROR;
    use masq_lib::messages::{
        FromMessageBody, UiCheckPasswordRequest, UiConfigurationChangedBroadcast,
        UiDescriptorResponse,UiShutdownRequest, UiStartOrder, UiUnmarshalError, NODE_UI_PROTOCOL,
    };
    use masq_lib::test_utils::logging::init_test_logging;
    use masq_lib::test_utils::logging::TestLogHandler;
    use masq_lib::test_utils::ui_connection::{UiConnection};
    use masq_lib::ui_gateway::MessagePath::FireAndForget;
    use masq_lib::ui_gateway::{MessageTarget, NodeFromUiMessage};
    use masq_lib::ui_traffic_converter::UiTrafficConverter;
    use masq_lib::utils::{find_free_port, localhost};
    use std::cell::RefCell;
    use std::io::ErrorKind;
    use std::net::{TcpStream};
    use std::sync::{Arc as StdArc, Mutex as StdMutex};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::sync::mpsc::{UnboundedReceiver};
    use workflow_websocket::client::message::Message;

    struct ClientWrapperMock {
        send_text_params: StdArc<StdMutex<Vec<String>>>,
        flush_params: StdArc<StdMutex<Vec<()>>>,
        send_text_results: RefCell<Vec<Result<(), soketto::connection::Error>>>,
        flush_results: RefCell<Vec<Result<(), soketto::connection::Error>>>,
        close_results: RefCell<Vec<Result<(), soketto::connection::Error>>>,
    }

    impl ClientWrapperMock {
        fn new() -> Self {
            Self {
                send_text_params: StdArc::new(StdMutex::new(vec![])),
                flush_params: StdArc::new(StdMutex::new(vec![])),
                send_text_results: RefCell::new(vec![]),
                flush_results: RefCell::new(vec![]),
                close_results: RefCell::new(vec![]),
            }
        }

        fn send_text_params(mut self, params: &StdArc<StdMutex<Vec<String>>>) -> Self {
            self.send_text_params = params.clone();
            self
        }

        fn flush_params(mut self, params: &StdArc<StdMutex<Vec<()>>>) -> Self {
            self.flush_params = params.clone();
            self
        }

        fn send_text_result(self, result: Result<(), soketto::connection::Error>) -> Self {
            self.send_text_results.borrow_mut().push(result);
            self
        }

        fn flush_result(self, result: Result<(), soketto::connection::Error>) -> Self {
            self.flush_results.borrow_mut().push(result);
            self
        }

        fn close_result(self, result: Result<(), soketto::connection::Error>) -> Self {
            self.close_results.borrow_mut().push(result);
            self
        }
    }

    #[async_trait]
    impl ClientWrapper for ClientWrapperMock {
        async fn send_text(&mut self, text: String) -> Result<(), soketto::connection::Error> {
            self.send_text_params.lock().unwrap().push(text);
            self.send_text_results.borrow_mut().remove(0)
        }

        async fn flush(&mut self) -> Result<(), soketto::connection::Error> {
            self.flush_params.lock().unwrap().push(());
            self.flush_results.borrow_mut().remove(0)
        }

        async fn close(&mut self) -> Result<(), soketto::connection::Error> {
            self.close_results.borrow_mut().remove(0)
        }
    }

    impl WebSocketSupervisorReal {

        async fn inject_logger(&self, logger: Logger) {
            let mut locked_inner = self.inner_arc.lock().await;
            locked_inner.logger = logger;
        }
    }

    async fn wait_for_server(port: u16) {
        let socket_addr = SocketAddr::new(localhost(), port);
        if poll_until_with_attempts(10, Duration::from_millis(100), || {
            TcpListener::bind(socket_addr).is_err()
        })
        .await
        {
            return;
        }
        panic!("Timeout waiting for websocket server on {}", socket_addr);
    }

    // async fn wait_for<F, T>(interval_ms: u64, remaining_ms: u64, mut f: F) -> T
    // where
    //     F: FnMut() -> Option<T>,
    // {
    //     if remaining_ms <= 0 {
    //         panic!("Timeout waiting for condition");
    //     }
    //     match f() {
    //         Some(result) => result,
    //         None => {
    //             tokio::time::sleep(Duration::from_millis(interval_ms)).await;
    //             Box::pin(wait_for(interval_ms, remaining_ms - interval_ms, f)).await
    //         }
    //     }
    // }

    fn subs(ui_gateway: Recorder) -> Recipient<NodeFromUiMessage> {
        let addr: Addr<Recorder> = ui_gateway.start();
        addr.recipient::<NodeFromUiMessage>()
    }

    #[actix::test]
    async fn logs_pre_upgrade_connection_errors() {
        let port = find_free_port();
        let (ui_gateway, _, _) = make_recorder();
        let ui_message_sub = subs(ui_gateway);
        let _subject = WebSocketSupervisorReal::new(port, ui_message_sub, 2);

        wait_for_server(port).await;

        // Simulate a client that drops before sending an upgrade request.
        let _ = TcpStream::connect(SocketAddr::new(localhost(), port)).unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;

        let _valid_client = UiConnection::new(port, NODE_UI_PROTOCOL).await.unwrap();
    }

    #[actix::test]
    async fn data_for_a_newly_connected_client_is_set_properly() {
        init_test_logging();
        let port = find_free_port();
        let (ui_gateway, ui_gateway_awaiter, ui_gateway_recording_arc) = make_recorder();
        let recipient = ui_gateway.start().recipient();
        let subject = WebSocketSupervisorReal::new(port, recipient, 2);
        wait_for_server(port).await;

        let mut ui_connection: UiConnection =
            UiConnection::new(port, NODE_UI_PROTOCOL).await.unwrap();
        let server_high_port = {
            subject.inner_arc.lock().await.socket_addr_by_client_id.get(&1).unwrap().port()
        };

        {
            let inner = subject.inner_arc.lock().await;
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
        ui_connection
            .send(UiCheckPasswordRequest {
                db_password_opt: Some("booga".to_string()),
            })
            .await;
        ui_gateway_awaiter.await_message_count_async(1).await;
        let recording = ui_gateway_recording_arc.lock().unwrap();
        let ui_message = recording.get_record::<NodeFromUiMessage>(0).clone();
        let (message, ctx_id) = UiCheckPasswordRequest::fmb(ui_message.body).unwrap();
        assert_eq!(
            message,
            UiCheckPasswordRequest {
                db_password_opt: Some("booga".to_string())
            }
        );
        eprintln!("port: {}, server_high_port: {}", port, server_high_port);
        let tlh = TestLogHandler::new();
        tlh.assert_logs_contain_in_order(vec![
            format!("INFO: WebSocketSupervisor: Listening for new WebSocket client connections on 127.0.0.1:{}", port).as_str(),
            format!("INFO: WebSocketSupervisor: Accepted new WebSocket client connection from 127.0.0.1:{}", server_high_port).as_str(),
            format!("INFO: WebSocketSupervisor: Listening for new WebSocket client connections on 127.0.0.1:{}", port).as_str(),
            format!("INFO: WebSocketSupervisor: Handshaking with new WebSocket client at 127.0.0.1:{}", server_high_port).as_str(),
            format!("INFO: WebSocketSupervisor: Handshake with new WebSocket client at 127.0.0.1:{} complete", server_high_port).as_str(),
            format!("INFO: WebSocketSupervisor: New WebSocket client at 127.0.0.1:{} designated with id 1", server_high_port).as_str(),
        ]);
    }

    #[actix::test]
    async fn rejects_connection_attempt_with_improper_protocol_name() {
        init_test_logging();
        let port = find_free_port();
        let (ui_gateway, _, _) = make_recorder();
        let recipient = ui_gateway.start().recipient();
        let subject = WebSocketSupervisorReal::new(port, recipient, 2);
        wait_for_server(port).await;

        let result: Result<UiConnection, String> = UiConnection::new(port, "MASQNode-UI").await;

        assert_eq!(
            result.err().unwrap(),
            "Websocket server did not accept any of these subprotocols: [\"MASQNode-UI\"]: Rejected { status_code: 400 }"
                .to_string()
        );
        {
            let inner = subject.inner_arc.lock().await;
            assert_eq!(inner.next_client_id, 1);
            assert_eq!(inner.socket_addr_by_client_id.is_empty(), true);
            assert_eq!(inner.client_id_by_socket_addr.is_empty(), true);
        }
        let tlh = TestLogHandler::new();
        tlh.await_log_matching(
            r"WARN: WebSocketSupervisor: New WebSocket client at 127\.0\.0\.1:\d+ does not support required WebSocket protocol; rejecting connection",
            1000,
        );
    }

    #[actix::test]
    async fn logs_unexpected_binary_websocket_messages() {
        init_test_logging();
        let port = find_free_port();
        let (ui_gateway, _, _) = make_recorder();
        let recipient = ui_gateway.start().recipient();
        let _subject = WebSocketSupervisorReal::new(port, recipient, 2);
        wait_for_server(port).await;

        {
            let mut ui_connection: UiConnection =
                UiConnection::new(port, NODE_UI_PROTOCOL).await.unwrap();
            ui_connection.send_data(vec![1u8, 2u8, 3u8, 4u8]).await;
        }

        tokio::time::sleep(Duration::from_millis(50)).await;
        let tlh = TestLogHandler::new();
        tlh.await_log_matching(
            "Client 1 at 127\\.0\\.0\\.1:\\d+ sent unexpected binary message; ignoring",
            1000,
        );
    }

    #[actix::test]
    async fn can_connect_two_clients_and_receive_messages_from_them() {
        let port = find_free_port();
        let (ui_gateway, ui_gateway_awaiter, ui_gateway_recording_arc) = make_recorder();
        let recipient = ui_gateway.start().recipient();
        let _subject = WebSocketSupervisorReal::new(port, recipient, 2);
        wait_for_server(port).await;
        let mut one_client = UiConnection::new(port, NODE_UI_PROTOCOL).await.unwrap();
        let mut another_client = UiConnection::new(port, NODE_UI_PROTOCOL).await.unwrap();
        one_client.send(UiShutdownRequest {}).await;
        another_client.send(UiStartOrder {}).await;
        one_client.send(UiShutdownRequest {}).await;

        one_client.send_close().await;
        another_client.send_close().await;

        ui_gateway_awaiter.await_message_count_async(3).await;
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
                client_id: 1,
                body: UiShutdownRequest {}.tmb(0),
            },
        );
        assert_contains(
            &messages,
            &NodeFromUiMessage {
                client_id: 2,
                body: UiStartOrder {}.tmb(0),
            },
        );
        assert_contains(
            &messages,
            &NodeFromUiMessage {
                client_id: 1,
                body: UiShutdownRequest {}.tmb(1),
            },
        );
    }

    #[actix::test]
    async fn logs_badly_formatted_json_and_returns_unmarshal_error() {
        init_test_logging();
        let advertised_port = find_free_port();
        let (recorder, _, _) = make_recorder();
        let subject = WebSocketSupervisorReal::new(advertised_port, recorder.start().recipient(), 1);
        let test_name = "logs_badly_formatted_json_and_returns_unmarshal_error";
        let logger = Logger::new(test_name);
        subject.inject_logger(logger).await;
        wait_for_server(advertised_port).await;
        let bad_json = "}: I am badly-formatted JSON :{";
        let mut client = UiConnection::new(advertised_port, NODE_UI_PROTOCOL).await.unwrap();
        let server_high_port = {
            subject.inner_arc.lock().await.socket_addr_by_client_id.get(&1).unwrap().port()
        };

        client.send_string(bad_json.to_string()).await;

        tokio::time::sleep(Duration::from_millis(50)).await; // make sure there's not another message sent
        let expected_traffic_conversion_message =
            "Couldn't parse text as JSON: Error(\"expected value\", line: 1, column: 1)"
                .to_string();
        let expected_unmarshal_message = "Critical(JsonSyntaxError(\"Error(\\\"expected value\\\", line: 1, column: 1)\")):";
        TestLogHandler::new().exists_log_containing(
            format!(
                "ERROR: {}: Bad message from client 1 at 127.0.0.1:{}: {}",
                test_name, server_high_port, expected_unmarshal_message
            )
            .as_str(),
        );
        let actual_json = tokio::time::timeout(
            Duration::from_secs(3),
            client.receive_string()
        ).await.unwrap();
        let actual_struct =
            UiTrafficConverter::new_unmarshal_to_ui(&actual_json, ClientId(1)).unwrap();
        assert_eq!(actual_struct.target, ClientId(1));
        assert_eq!(
            UiUnmarshalError::fmb(actual_struct.body).unwrap().0,
            UiUnmarshalError {
                message: expected_traffic_conversion_message,
                bad_data: bad_json.as_bytes().to_hex(),
            }
        )
    }

    fn make_ordinary_inner(port: u16, test_name: &str) -> WebSocketSupervisorInner {
        let (ui_message_sub, _, _) = make_recorder();
        WebSocketSupervisorInner {
            port,
            next_client_id: 0,
            from_ui_message_sub: ui_message_sub.start().recipient::<NodeFromUiMessage>(),
            client_id_by_socket_addr: Default::default(),
            socket_addr_by_client_id: Default::default(),
            client_by_id: Default::default(),
            logger: Logger::new(test_name),
        }
    }

    #[actix::test]
    async fn bad_one_way_message_is_logged_and_returns_error() {
        init_test_logging();
        let port = find_free_port();
        let (recorder, _, _) = make_recorder();
        let subject = WebSocketSupervisorReal::new(port, recorder.start().recipient(), 1);
        let test_name = "bad_one_way_message_is_logged_and_returns_error";
        subject.inject_logger(Logger::new(test_name)).await;
        wait_for_server(port).await;
        let bad_message_json = r#"{"opcode":"shutdown"}"#;
        let mut client = UiConnection::new(port, NODE_UI_PROTOCOL).await.unwrap();

        client.send_string(bad_message_json.to_string()).await;

        let expected_traffic_conversion_message =
            "Required field was missing: payload, error".to_string();
        let actual_json = tokio::time::timeout(
            Duration::from_secs(3),
            client.receive_string()
        ).await.unwrap();
        let actual_struct =
            UiTrafficConverter::new_unmarshal_to_ui(&actual_json, ClientId(1)).unwrap();
        assert_eq!(actual_struct.target, ClientId(1));
        assert_eq!(
            UiUnmarshalError::fmb(actual_struct.body).unwrap().0,
            UiUnmarshalError {
                message: expected_traffic_conversion_message,
                bad_data: "7b226f70636f6465223a2273687574646f776e227d".to_string(),
            }
        )
    }

    #[actix::test]
    async fn bad_two_way_message_is_logged_and_returns_error() {
        init_test_logging();
        let port = find_free_port();
        let (recorder, _, _) = make_recorder();
        let subject = WebSocketSupervisorReal::new(port, recorder.start().recipient(), 1);
        let test_name = "bad_two_way_message_is_logged_and_returns_error";
        subject.inject_logger(Logger::new(test_name)).await;
        wait_for_server(port).await;
        let bad_message_json = r#"{"opcode":"setup", "contextId":3333}"#;
        let mut client = UiConnection::new(port, NODE_UI_PROTOCOL).await.unwrap();

        client.send_string(bad_message_json.to_string()).await;

        let expected_traffic_conversion_message =
            "Required field was missing: payload, error".to_string();
        let expected_unmarshal_message = format!(
            "Error unmarshalling 'setup' message: {}",
            expected_traffic_conversion_message
        );
        let actual_json = tokio::time::timeout(
            Duration::from_secs(3),
            client.receive_string()
        ).await.unwrap();
        let actual_struct =
            UiTrafficConverter::new_unmarshal_to_ui(&actual_json, ClientId(1)).unwrap();
        assert_eq!(
            actual_struct,
            NodeToUiMessage {
                target: ClientId(1),
                body: MessageBody {
                    opcode: "setup".to_string(),
                    path: Conversation(3333),
                    payload: Err((UNMARSHAL_ERROR, expected_traffic_conversion_message))
                }
            }
        );
    }

    async fn sink_failure_assertion(client: ClientWrapperMock) {
        let socket_addr = SocketAddr::new(localhost(), find_free_port());
        let mut inner = make_ordinary_inner(0, "sink_failure_assertion");
        inner.client_id_by_socket_addr.insert(socket_addr, 123);
        inner.socket_addr_by_client_id.insert(123, socket_addr);
        inner.client_by_id.insert(123, Box::new(client));
        let inner_arc = Arc::new(Mutex::new(inner));
        let msg = NodeToUiMessage {
            target: ClientId(123),
            body: UiDescriptorResponse {
                node_descriptor_opt: None,
            }
            .tmb(111),
        };
        let assertable_inner_arc = inner_arc.clone();
        let inner_arc_clone = inner_arc.clone();

        WebSocketSupervisorReal::send_msg_inner(inner_arc_clone, msg).await;

        let assertable_inner = assertable_inner_arc.lock().await;
        assert_eq!(
            assertable_inner.client_id_by_socket_addr.get(&socket_addr),
            None
        );
        assert_eq!(assertable_inner.client_by_id.get(&123).is_none(), true);
        assert_eq!(assertable_inner.socket_addr_by_client_id.get(&123), None)
    }

    #[actix::test]
    async fn send_msg_fails_on_send_and_so_logs_and_removes_the_client() {
        init_test_logging();
        let send_text_params = StdArc::new(StdMutex::new(vec![]));
        let flush_params = StdArc::new(StdMutex::new(vec![]));
        let client = ClientWrapperMock::new()
            .send_text_params(&send_text_params)
            .flush_params(&flush_params)
            .send_text_result(Err(soketto::connection::Error::Io(io::Error::from(
                ErrorKind::BrokenPipe,
            ))));

        sink_failure_assertion(client).await;

        assert_eq!(send_text_params.lock().unwrap().len(), 1);
        assert!(flush_params.lock().unwrap().is_empty());

        TestLogHandler::new().exists_log_containing(
            "ERROR: WebSocketSupervisor: Error sending to client 123: Io(Kind(BrokenPipe)), dropping the client",
        );
    }

    #[actix::test]
    async fn send_msg_fails_on_flush_and_so_logs_and_removes_the_client() {
        init_test_logging();
        let send_text_params = StdArc::new(StdMutex::new(vec![]));
        let flush_params = StdArc::new(StdMutex::new(vec![]));
        let client = ClientWrapperMock::new()
            .send_text_params(&send_text_params)
            .flush_params(&flush_params)
            .send_text_result(Ok(()))
            .flush_result(Err(soketto::connection::Error::Io(io::Error::from(
                ErrorKind::BrokenPipe,
            ))));

        sink_failure_assertion(client).await;

        assert_eq!(send_text_params.lock().unwrap().len(), 1);
        assert_eq!(flush_params.lock().unwrap().len(), 1);

        TestLogHandler::new().exists_log_containing(
            "ERROR: WebSocketSupervisor: Client 123 hit a fatal flush error: Io(Kind(BrokenPipe)), dropping the client",
        );
    }

    #[actix::test]
    #[should_panic(expected = "Failed to flush message: Closed")]
    async fn once_a_client_sends_a_close_no_more_data_is_accepted() {
        let port = find_free_port();
        let (ui_gateway, ui_gateway_awaiter, ui_gateway_recording_arc) = make_recorder();
        let ui_message_sub = subs(ui_gateway);

        let subject = WebSocketSupervisorReal::new(port, ui_message_sub, 1);
        wait_for_server(port).await;

        let mut client = UiConnection::new(port, NODE_UI_PROTOCOL).await.unwrap();
        client.send(UiShutdownRequest {}).await;
        client.send_close().await;
        client.send(UiStartOrder {}).await;
    }

    #[actix::test]
    async fn a_client_that_violates_the_protocol_is_terminated() {
        let port = find_free_port();
        let (ui_gateway, _, ui_gateway_recording_arc) = make_recorder();
        let ui_message_sub = subs(ui_gateway);

        let _subject = WebSocketSupervisorReal::new(port, ui_message_sub, 1);
        wait_for_server(port).await;

        let mut client = tokio::net::TcpStream::connect(SocketAddr::new(localhost(), port))
            .await
            .unwrap();
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: 127.0.01\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: MASQNode-UIv2\r\n\r\n")
            .await
            .unwrap();
        let mut buf = [0u8; 1024];
        let _ = client.read(&mut buf).await.unwrap();
        client.write_all(b"Booga!").await.unwrap();

        tokio::time::sleep(Duration::from_millis(500)).await; // make sure there's not another message sent
        let ui_gateway_recording = ui_gateway_recording_arc.lock().unwrap();
        assert_eq!(ui_gateway_recording.len(), 0);
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

    #[actix::test]
    async fn send_msg_with_a_client_id_sends_a_message_to_the_client() {
        let port = find_free_port();
        let (ui_gateway, _, _) = make_recorder();
        let ui_message_sub = subs(ui_gateway);
        let subject = WebSocketSupervisorReal::new(port, ui_message_sub, 2);
        wait_for_server(port).await;
        let mut one_client = UiConnection::new(port, NODE_UI_PROTOCOL).await.unwrap();
        let mut another_client = UiConnection::new(port, NODE_UI_PROTOCOL).await.unwrap();
        let msg = NodeToUiMessage {
            target: ClientId(1), // first client gets client ID 1
            body: MessageBody {
                opcode: "configurationChanged".to_string(),
                path: FireAndForget,
                payload: Ok("{}".to_string()),
            },
        };

        subject.send_msg(msg.clone()).await;

        let _ = one_client
            .receive_message::<UiConfigurationChangedBroadcast>(None)
            .await;
        another_client.assert_nothing_waiting(100).await;
    }

    #[actix::test]
    async fn send_msg_with_all_except_sends_a_message_to_all_except() {
        let port = find_free_port();
        let (ui_gateway, _, _) = make_recorder();
        let ui_message_sub = subs(ui_gateway);
        let subject = WebSocketSupervisorReal::new(port, ui_message_sub, 3);
        wait_for_server(port).await;
        let mut one_client = UiConnection::new(port, NODE_UI_PROTOCOL).await.unwrap();
        let mut another_client = UiConnection::new(port, NODE_UI_PROTOCOL).await.unwrap();
        let mut third_client = UiConnection::new(port, NODE_UI_PROTOCOL).await.unwrap();
        let another_client_id = 2;
        let msg = NodeToUiMessage {
            target: AllExcept(another_client_id),
            body: MessageBody {
                opcode: "configurationChanged".to_string(),
                path: FireAndForget,
                payload: Ok("{}".to_string()),
            },
        };

        subject.send_msg(msg.clone()).await;

        let _ = one_client
            .receive_message::<UiConfigurationChangedBroadcast>(None)
            .await;
        another_client.assert_nothing_waiting(100).await;
        let _ = third_client
            .receive_message::<UiConfigurationChangedBroadcast>(None)
            .await;
    }

    #[actix::test]
    async fn send_msg_with_all_clients_sends_a_message_to_all_clients() {
        let port = find_free_port();
        let (ui_gateway, _, _) = make_recorder();
        let ui_message_sub = subs(ui_gateway);
        let subject = WebSocketSupervisorReal::new(port, ui_message_sub, 3);
        wait_for_server(port).await;
        let mut one_client = UiConnection::new(port, NODE_UI_PROTOCOL).await.unwrap();
        let mut another_client = UiConnection::new(port, NODE_UI_PROTOCOL).await.unwrap();
        let mut third_client = UiConnection::new(port, NODE_UI_PROTOCOL).await.unwrap();
        let msg = NodeToUiMessage {
            target: AllClients,
            body: MessageBody {
                opcode: "configurationChanged".to_string(),
                path: FireAndForget,
                payload: Ok("{}".to_string()),
            },
        };

        subject.send_msg(msg.clone()).await;

        let _ = one_client
            .receive_message::<UiConfigurationChangedBroadcast>(None)
            .await;
        let _ = another_client
            .receive_message::<UiConfigurationChangedBroadcast>(None)
            .await;
        let _ = third_client
            .receive_message::<UiConfigurationChangedBroadcast>(None)
            .await;
    }

    #[actix::test]
    async fn send_msg_fails_to_look_up_client_to_send_to() {
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

        subject.send_msg(msg).await;

        TestLogHandler::new().await_log_containing(
            "WebsocketSupervisor: WARN: Tried to send to an absent client 7",
            1000,
        );
    }
}
