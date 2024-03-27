// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
use actix::Recipient;
use masq_lib::constants::UNMARSHAL_ERROR;
use masq_lib::logger::Logger;
use masq_lib::messages::{ToMessageBody, UiUnmarshalError, NODE_UI_PROTOCOL};
use masq_lib::ui_gateway::MessagePath::Conversation;
use masq_lib::ui_gateway::MessageTarget::ClientId;
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
use tokio::net::{TcpListener, TcpStream};
use tokio::task;
use tokio_tungstenite::tungstenite::handshake::server::{Callback, ErrorResponse, Request, Response};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;
use futures_util::{Sink, SinkExt, StreamExt, TryStreamExt};
use tokio_tungstenite::tungstenite::protocol::CloseFrame;
use tungstenite::protocol::frame::coding::CloseCode;

struct SubprotocolCallback {}

impl Unpin for SubprotocolCallback {}

impl Callback for SubprotocolCallback {
    fn on_request(self, request: &Request, response: Response) -> Result<Response, ErrorResponse> {
        // Examine request to make sure it contains a Sec-WebSocket-Protocol with MASQNode-UIv2 in its list
        todo!()
    }
}

impl SubprotocolCallback {
    fn new() -> Self {
        Self{}
    }
}

pub trait WebSocketSupervisor: Send {
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
    client_by_id: HashMap<u64, Box<MessageWriter>>,
}

impl WebSocketSupervisor for WebSocketSupervisorReal {
    fn send_msg(&self, msg: NodeToUiMessage) {
        Self::send_msg(self.inner_arc.lock().expect("WebSocketSupervisor clients are dying"), msg);
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
            from_ui_message_sub,
            client_id_by_socket_addr: HashMap::new(),
            socket_addr_by_client_id: HashMap::new(),
            client_by_id: HashMap::new(),
        }));
        task::spawn(Self::listen_for_connections_on(
            SocketAddr::new(localhost(), port),
            inner_arc.clone(),
            Logger::new("WebSocketSupervisor"),
            connections_to_accept
        ));
        WebSocketSupervisorReal { inner_arc: inner_arc }
    }

    async fn listen_for_connections_on(
        socket_addr: SocketAddr,
        inner_arc: Arc<Mutex<WebSocketSupervisorInner>>,
        logger: Logger,
        mut connections_to_accept: usize
    ) {
        let listener = TcpListener::bind(socket_addr).await
            .expect(format!("WebSocketSupervisor could not bind to {:?}", socket_addr).as_str());
        info!(logger, "Listening on: {}", socket_addr);
        loop {
            match listener.accept().await {
                Ok((stream, peer_addr)) => {
                    debug!(logger, "Accepted TCP connection from {}", peer_addr);
                    task::spawn(Self::process_connection(stream, peer_addr, inner_arc.clone(), logger.clone()))
                },
                Err(e) => {
                    error!(logger, "Error accepting connection to {}: {:?}", socket_addr, e)
                }
            }
            connections_to_accept -= 1;
            if connections_to_accept == 0 {
                break
            }
        }
    }

    async fn process_connection(stream: TcpStream, peer_addr: SocketAddr, inner_arc: Arc<Mutex<WebSocketSupervisorInner>>, logger: Logger) {
        let ws_stream: WebSocketStream<TcpStream> = match tokio_tungstenite::accept_hdr_async(stream, SubprotocolCallback::new()) {
            Err(e) => {
                error!(logger, "Handshake error for {}: {:?}", peer_addr, e);
                return
            },
            Ok(ws_stream) => {
                ws_stream
            }
        };
        info!(logger, "New WebSocket connection from: {}", peer_addr);
        let (write, mut read) = ws_stream.split();
        let client_id = {
            let mut inner = inner_arc.lock().expect("Client futures are panicking");
            let client_id = inner.next_client_id;
            inner.next_client_id += 1;
            inner.client_id_by_socket_addr.insert(peer_addr, client_id);
            inner.socket_addr_by_client_id.insert(client_id, peer_addr);
            inner.client_by_id.insert(client_id, Box::new(write));
            client_id
        };
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

    async fn send_msg(mut locked_inner: MutexGuard<WebSocketSupervisorInner>, msg: NodeToUiMessage) {
        let clients = match msg.target {
            MessageTarget::ClientId(n) => {
                let clients = Self::filter_clients(&mut locked_inner, |(id, _)| **id == n);
                if !clients.is_empty() {
                    clients
                } else {
                    Self::log_absent_client(n);
                    return;
                }
            }
            MessageTarget::AllExcept(n) => {
                Self::filter_clients(&mut locked_inner, |(id, _)| **id != n)
            }
            MessageTarget::AllClients => Self::filter_clients(&mut locked_inner, |_| true),
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

    async fn handle_text_message(
        locked_inner: MutexGuard<WebSocketSupervisorInner>,
        logger: &Logger,
        peer_addr: SocketAddr,
        message: &str,
    ) -> bool {
        let client_id = match locked_inner.client_id_by_socket_addr.get(&peer_addr) {
            Some(client_id_ref) => *client_id_ref,
            None => {
                warning!(
                    logger,
                    "WebSocketSupervisor got a message from a client that never connected!"
                );
                return false // end the stream
            }
        };
        match UiTrafficConverter::new_unmarshal_from_ui(message, client_id) {
            Ok(from_ui_message) => {
                locked_inner
                    .from_ui_message_sub
                    .try_send(from_ui_message)
                    .expect("UiGateway is dead");
                return true
            }
            Err(Critical(e)) => {
                error!(
                    logger,
                    "Bad message from client {} at {}: {:?}:\n{}\n",
                    client_id,
                    peer_addr,
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
                ).await;
                return true
            }
            Err(NonCritical(opcode, context_id_opt, e)) => {
                error!(
                    logger,
                    "Bad message from client {} at {}: {:?}:\n{}\n",
                    client_id,
                    peer_addr,
                    NonCritical(opcode.clone(), context_id_opt, e.clone()),
                    message
                );
                match context_id_opt {
                    None => Self::send_msg(
                        locked_inner,
                        NodeToUiMessage {
                            target: ClientId(client_id),
                            body: UiUnmarshalError {
                                message: e.to_string(),
                                bad_data: message.to_string(),
                            }
                            .tmb(0),
                        },
                    ).await,
                    Some(context_id) => Self::send_msg(
                        locked_inner,
                        NodeToUiMessage {
                            target: ClientId(client_id),
                            body: MessageBody {
                                opcode,
                                path: Conversation(context_id),
                                payload: Err((UNMARSHAL_ERROR, e.to_string())),
                            },
                        },
                    ).await,
                };
                return true
            }
        }
    }

    fn handle_close_message(
        mut locked_inner: MutexGuard<WebSocketSupervisorInner>,
        logger: &Logger,
        socket_addr: SocketAddr,
    ) -> bool {
        // TODO: This removal should probably happen in Self::close_connection() like all the others.
        let client_id = match locked_inner.client_id_by_socket_addr.remove(&socket_addr) {
            None => {
                error!(
                    logger,
                    "WebSocketSupervisor got a disconnect from a client that never connected!"
                );
               return false
            }
            Some(client_id) => client_id,
        };
        info!(
            logger,
            "UI at {} (client ID {}) disconnected from port {}",
            socket_addr,
            client_id,
            locked_inner.port
        );
        Self::close_connection(&mut locked_inner, client_id, socket_addr, logger);
        false
    }

    fn handle_other_message(
        logger: &Logger,
        socket_addr: SocketAddr,
        message_type: &str,
    ) -> bool {
        info!(
            logger,
            "UI at {} sent unexpected {} message; ignoring", socket_addr, message_type
        );
        true
    }

    async fn send_to_clients(
        clients: Vec<(u64, &mut MessageWriter)>,
        json: String,
    ) -> Option<Vec<SendToClientWebsocketError>> {
        let errors: Vec<SendToClientWebsocketError> = clients
            .into_iter()
            .flat_map(
                async move |(client_id, client)| match client.send(Message::Text(json.clone())).await {
                    Ok(_) => None,
                    Err(e) => Some(SendToClientWebsocketError::SendError((client_id, e))),
                }.await,
            )
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

    fn emergency_client_removal(client_id: u64, locked_inner: &MutexGuard<WebSocketSupervisorInner>) {
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
            let close_message = Message::Close(Some(CloseFrame{ code: CloseCode::Normal, reason: Cow::Owned("Client initiated closure")}));
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::recorder::{make_recorder, Recorder};
    use crate::test_utils::{assert_contains, await_value, wait_for};
    use actix::System;
    use actix::{Actor, Addr};
    use crossbeam_channel::bounded;
    use masq_lib::constants::UNMARSHAL_ERROR;
    use masq_lib::messages::{FromMessageBody, UiDescriptorResponse, UiShutdownRequest, UiStartOrder, UiUnmarshalError, NODE_UI_PROTOCOL, UiCheckPasswordRequest};
    use masq_lib::test_utils::logging::init_test_logging;
    use masq_lib::test_utils::logging::TestLogHandler;
    use masq_lib::test_utils::ui_connection::UiConnection;
    use masq_lib::ui_gateway::MessagePath::FireAndForget;
    use masq_lib::ui_gateway::NodeFromUiMessage;
    use masq_lib::ui_traffic_converter::UiTrafficConverter;
    use masq_lib::utils::{find_free_port, localhost};
    use std::cell::RefCell;
    use std::future::ready;
    use std::io::{Error, ErrorKind};
    use std::net::{IpAddr, Ipv4Addr, Shutdown};
    use std::pin::Pin;
    use std::str::FromStr;
    use std::task::{Context, Poll};
    use std::thread;
    use std::time::Duration;
    use tokio_tungstenite::MaybeTlsStream;
    use websocket::client::sync::Client;
    use websocket::stream::sync::TcpStream;
    use masq_lib::test_utils::utils::make_rt;

    impl WebSocketSupervisorReal {
        fn inject_mock_client(&self, mock_client: MessageWriterMock) -> u64 {
            let mut locked_inner = self.inner_arc.lock().unwrap();
            let client_id = locked_inner.next_client_id;
            locked_inner.next_client_id += 1;
            locked_inner
                .client_by_id
                .insert(client_id, Box::new(mock_client));
            client_id
        }

        fn get_mock_client(&self, client_id: u64) -> MessageWriterMock {
            let locked_inner = self.inner_arc.lock().unwrap();
            let mock_client_box = match locked_inner.client_by_id.get(&client_id) {
                Some(mcb) => mcb,
                None => panic!("Did not find mock client for id: {}", client_id),
            };
            let any = mock_client_box.as_any();
            let result = any
                .downcast_ref::<MessageWriterMock>()
                .expect("couldn't downcast");
            result.clone()
        }
    }

    #[derive(Clone)]
    struct MessageWriterMock {
        send_params: Arc<Mutex<Vec<Message>>>,
        send_results: RefCell<Vec<Result<(), io::Error>>>,
    }

    impl Sink<Message> for MessageWriterMock {
        type Error = io::Error;
        fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> { unimplemented!() }
        fn start_send(self: Pin<&mut Self>, item: Message) -> Result<(), Self::Error> { unimplemented!() }
        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> { unimplemented!() }
        fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> { unimplemented!() }
    }

    impl SinkExt<Message> for MessageWriterMock {
        fn send(&mut self, item: Message) -> futures_util::sink::Send<'_, Self, Message> where Self: Unpin {
            self.send_params.lock().unwrap().push(item.clone());
            todo!()
        }
    }

    impl Unpin for MessageWriterMock {}

    impl MessageWriterMock {
        fn new() -> MessageWriterMock {
            MessageWriterMock {
                send_params: Arc::new(Mutex::new(vec![])),
                send_results: RefCell::new(vec![]),
            }
        }

        fn send_params(mut self, params: &Arc<Mutex<Vec<Message>>>) -> Self {
            self.send_params = params.clone();
            self
        }

        fn send_result(self, result: Result<(), io::Error>) -> Self {
            self.send_results.borrow_mut().push(result);
            self
        }
    }
    //
    // struct ClientWrapperMock {
    //     send_params: Arc<Mutex<Vec<Message>>>,
    //     send_results: RefCell<Vec<Result<(), io::Error>>>,
    // }
    //
    // impl Clone for ClientWrapperMock {
    //     fn clone(&self) -> Self {
    //         ClientWrapperMock {
    //             send_params: self.send_params.clone(),
    //             send_results: RefCell::new(
    //                 self.send_results
    //                     .borrow()
    //                     .iter()
    //                     .map(|result| match result {
    //                         Ok(()) => Ok(()),
    //                         Err(e) => Err((*e).clone()),
    //                     })
    //                     .collect::<Vec<Result<(), io::Error>>>(),
    //             ),
    //         }
    //     }
    // }
    //
    // impl ClientWrapperMock {
    //     fn new() -> ClientWrapperMock {
    //         ClientWrapperMock {
    //             send_params: Arc::new(Mutex::new(vec![])),
    //             send_results: RefCell::new(vec![]),
    //         }
    //     }
    //
    //     fn send_params(mut self, params: &Arc<Mutex<Vec<Message>>>) -> Self {
    //         self.send_params = params.clone();
    //         self
    //     }
    //
    //     fn send_result(self, result: Result<(), io::Error>) -> Self {
    //         self.send_results.borrow_mut().push(result);
    //         self
    //     }
    // }
    //
    // impl ClientWrapper for ClientWrapperMock {
    //     fn as_any(&self) -> &dyn Any {
    //         self
    //     }
    //
    //     async fn send(&mut self, item: Message) -> Box<dyn Future<Output = Result<(), io::Error>>> {
    //         self.send_params.lock().unwrap().push(item);
    //         if self.send_results.borrow().is_empty() {
    //             panic!("ClientWrapperMock: send_results is empty")
    //         }
    //         Box::new (ready(self.send_results.borrow_mut().remove(0)))
    //     }
    // }

    type Client = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

    async fn make_client(port: u16, protocol: &str) -> Client {
        let url = format!("ws://{}:{}", localhost(), port);
        let (stream, response) =
            tokio_tungstenite::connect_async(url).await.unwrap();
        stream
    }

    fn wait_for_client(port: u16, protocol: &str) -> Client {
        let mut one_client_opt: Option<Client<TcpStream>> = None;
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
        let _subject =  WebSocketSupervisorReal::new(port, ui_message_sub, 1);

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
        ui_connection.send(UiCheckPasswordRequest{db_password_opt: Some("booga".to_string())});
        System::current().stop();
        system.run();
        let recording = ui_gateway_recording_arc.lock().unwrap();
        let message = recording.get_record::<UiCheckPasswordRequest>(0);
        assert_eq!(message, UiCheckPasswordRequest{db_password_opt: Some("booga".to_string())});
        todo! ("Check for proper connection-progress logs")
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

        assert_eq!(result, Err("UI attempted connection without protocol MASQNode-UIv2: [\"MASQNode-UI\"]"));
        {
            let inner = subject.inner_arc.lock().unwrap();
            assert_eq!(inner.next_client_id, 1);
            assert_eq!(inner.socket_addr_by_client_id.is_empty(), true);
            assert_eq!(inner.client_id_by_socket_addr.is_empty(), true);
        }
        let tlh = TestLogHandler::new();
        tlh.exists_log_containing("UI attempted connection without protocol MASQNode-UIv2: [\"MASQNode-UI\"]");
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
            let mut ui_connection: UiConnection = UiConnection::make(port, NODE_UI_PROTOCOL).unwrap();
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
        another_client
            .send_message(&Message::Close(None))
            .unwrap();
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
        let send_params_arc = Arc::new(Mutex::new(vec![]));
        let client = MessageWriterMock::new()
            .send_params(&send_params_arc)
            .send_result(Ok(()));
        let client_id = subject.inject_mock_client(client);
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
        let mut send_params = send_params_arc.lock().unwrap();
        let actual_json = match send_params.remove(0) {
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
        let send_params_arc = Arc::new(Mutex::new(vec![]));
        let client = MessageWriterMock::new()
            .send_params(&send_params_arc)
            .send_result(Ok(()));
        let client_id = subject.inject_mock_client(client);
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
        let mut send_params = send_params_arc.lock().unwrap();
        let actual_json = match send_params.remove(0) {
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
        let send_params_arc = Arc::new(Mutex::new(vec![]));
        let client = MessageWriterMock::new()
            .send_params(&send_params_arc)
            .send_result(Ok(()));
        let client_id = subject.inject_mock_client(client);
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
        let mut send_params = send_params_arc.lock().unwrap();
        let actual_json = match send_params.remove(0) {
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

    fn flush_failure_assertion(flush_error: io::Error, client_is_retained_after_error: bool) {
        let client = MessageWriterMock::new()
            .send_result(Ok(()));
        sink_failure_test_body(client, client_is_retained_after_error)
    }

    fn send_failure_assertion(send_error: io::Error) {
        let client = MessageWriterMock::new().send_result(Err(send_error));
        sink_failure_test_body(client, false)
    }

    fn sink_failure_test_body(
        client_mock: MessageWriterMock,
        client_is_retained_after_error: bool,
    ) {
        let (ui_gateway, _, _) = make_recorder();
        let from_ui_message_sub = subs(ui_gateway);
        let socket_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::from([1, 2, 4, 5])), 4455);
        let mut client_by_id: HashMap<u64, Box<MessageWriter>> = HashMap::new();
        client_by_id.insert(123, Box::new(client_mock));
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
    fn can_handle_non_fatal_flush_failure() {
        init_test_logging();
        let flush_error = io::Error::from(ErrorKind::BrokenPipe);
        flush_failure_assertion(flush_error, true);
        TestLogHandler::new().exists_log_containing(
            "WARN: WebSocketSupervisor: 'NoDataAvailable' occurred when flushing msg for Client 123",
        );
    }

    #[test]
    fn can_handle_broken_pipe_flush_failure() {
        init_test_logging();
        let flush_error = io::Error::from(ErrorKind::BrokenPipe);
        flush_failure_assertion(flush_error, false);
        TestLogHandler::new().exists_log_containing(
            "WARN: WebSocketSupervisor: Client 123 hit a fatal flush error: BrokenPipe, dropping the client",
        );
    }

    #[test]
    fn can_handle_connection_aborted_flush_failure() {
        init_test_logging();
        let flush_error = io::Error::from(ErrorKind::BrokenPipe);
        flush_failure_assertion(flush_error, false);
        TestLogHandler::new().exists_log_containing(
            "WARN: WebSocketSupervisor: Client 123 hit a fatal flush error: ConnectionReset, dropping the client",
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

    #[test]
    fn send_msg_with_a_client_id_sends_a_message_to_the_client() {
        let port = find_free_port();
        let (ui_gateway, _, _) = make_recorder();
        let ui_message_sub = subs(ui_gateway);
        let subject = WebSocketSupervisorReal::new(port, ui_message_sub, 1);
        let one_mock_client = MessageWriterMock::new()
            .send_result(Ok(()));
        let another_mock_client = MessageWriterMock::new();
        let one_client_id = subject.inject_mock_client(one_mock_client);
        let another_client_id = subject.inject_mock_client(another_mock_client);
        let msg = NodeToUiMessage {
            target: ClientId(one_client_id),
            body: MessageBody {
                opcode: "booga".to_string(),
                path: FireAndForget,
                payload: Ok("{}".to_string()),
            },
        };

        subject.send_msg(msg.clone());

        let one_mock_client_ref = subject.get_mock_client(one_client_id);
        let actual_message = match one_mock_client_ref.send_params.lock().unwrap().get(0) {
            Some(Message::Text(json)) => UiTrafficConverter::new_unmarshal_to_ui(json.as_str(), MessageTarget::ClientId(one_client_id)).unwrap(),
            Some(x) => panic! ("send should have been called with OwnedMessage::Text, but was called with {:?} instead", x),
            None => panic! ("send should have been called, but wasn't"),
        };
        assert_eq!(actual_message, msg);
        let another_mock_client_ref = subject.get_mock_client(another_client_id);
        assert_eq!(another_mock_client_ref.send_params.lock().unwrap().len(), 0);
        Ok(())
    }

    #[test]
    fn send_msg_with_all_except_sends_a_message_to_all_except() {
        let port = find_free_port();
        let (ui_gateway, _, _) = make_recorder();
        let ui_message_sub = subs(ui_gateway);
        let subject = WebSocketSupervisorReal::new(port, ui_message_sub, 2);
        let one_mock_client = MessageWriterMock::new()
            .send_result(Ok(()));
        let another_mock_client = MessageWriterMock::new()
            .send_result(Ok(()));
        let one_client_id = subject.inject_mock_client(one_mock_client);
        let another_client_id = subject.inject_mock_client(another_mock_client);
        let msg = NodeToUiMessage {
            target: MessageTarget::AllExcept(another_client_id),
            body: MessageBody {
                opcode: "booga".to_string(),
                path: FireAndForget,
                payload: Ok("{}".to_string()),
            },
        };

        subject.send_msg(msg.clone());

        let one_mock_client_ref = subject.get_mock_client(one_client_id);
        let actual_message = match one_mock_client_ref.send_params.lock().unwrap().get(0) {
            Some(Message::Text(json)) => UiTrafficConverter::new_unmarshal_to_ui(json.as_str(), MessageTarget::AllExcept(another_client_id)).unwrap(),
            Some(x) => panic! ("send should have been called with OwnedMessage::Text, but was called with {:?} instead", x),
            None => panic! ("send should have been called, but wasn't"),
        };
        assert_eq!(actual_message, msg);
        let another_mock_client_ref = subject.get_mock_client(another_client_id);
        assert_eq!(another_mock_client_ref.send_params.lock().unwrap().len(), 0);
    }

    #[test]
    fn send_msg_with_all_clients_sends_a_message_to_all_clients() {
        let port = find_free_port();
        let (ui_gateway, _, _) = make_recorder();
        let ui_message_sub = subs(ui_gateway);
        let subject = WebSocketSupervisorReal::new(port, ui_message_sub, 2);
        let one_mock_client = MessageWriterMock::new()
            .send_result(Ok(()));
        let another_mock_client = MessageWriterMock::new()
            .send_result(Ok(()));
        let one_client_id = subject.inject_mock_client(one_mock_client);
        let another_client_id = subject.inject_mock_client(another_mock_client);
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
        let msg_received_assertion = |mock_client_ref: MessageWriterMock| {
            match mock_client_ref.send_params.lock().unwrap().get(0) {
                Some(Message::Text(json)) =>
                    UiTrafficConverter::new_unmarshal_to_ui(json.as_str(), MessageTarget::AllClients).unwrap(),
                Some(x) => panic! ("send should have been called with OwnedMessage::Text, but was called with {:?} instead", x),
                None => panic! ("send should have been called, but wasn't"),
            }
        };
        let actual_message = msg_received_assertion(one_mock_client_ref);
        assert_eq!(actual_message, msg);
        let another_mock_client_ref = subject.get_mock_client(another_client_id);
        let actual_message = msg_received_assertion(another_mock_client_ref);
        assert_eq!(actual_message, msg);
    }

    #[test]
    fn send_msg_fails_on_send_and_so_logs_and_removes_the_client() {
        init_test_logging();

        send_failure_assertion(io::Error::from(ErrorKind::BrokenPipe));

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
            1000
        );
    }
}
