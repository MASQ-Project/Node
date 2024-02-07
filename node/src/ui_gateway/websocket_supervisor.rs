// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
use actix::Recipient;
use bytes::BytesMut;
use futures::future::FutureResult;
use futures::future::{err, ok};
use futures::sink::Wait;
use futures::stream::SplitSink;
use futures::Future;
use futures::Sink;
use futures::Stream;
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
use std::collections::HashMap;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard};
use tokio::reactor::Handle;
use websocket::r#async::server::Upgrade;
use websocket::client::r#async::Framed;
use websocket::r#async::MessageCodec;
use websocket::r#async::TcpStream;
use websocket::server::r#async::{Server, Incoming};
use websocket::server::upgrade::WsUpgrade;
use websocket::OwnedMessage;
use websocket::server::InvalidConnection;
use websocket::WebSocketError;

trait ClientWrapper: Send + Any {
    fn as_any(&self) -> &dyn Any;
    fn send(&mut self, item: OwnedMessage) -> Result<(), WebSocketError>;
    fn flush(&mut self) -> Result<(), WebSocketError>;
}

struct ClientWrapperReal {
    delegate: Wait<SplitSink<Framed<TcpStream, MessageCodec<OwnedMessage>>>>,
}

impl ClientWrapper for ClientWrapperReal {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn send(&mut self, item: OwnedMessage) -> Result<(), WebSocketError> {
        self.delegate.send(item)
    }

    fn flush(&mut self) -> Result<(), WebSocketError> {
        self.delegate.flush()
    }
}

pub trait WebSocketSupervisor: Send {
    fn send_msg(&self, msg: NodeToUiMessage);
}

pub struct WebSocketSupervisorReal {
    #[allow(dead_code)]
    inner: Arc<Mutex<WebSocketSupervisorInner>>,
}

struct WebSocketSupervisorInner {
    port: u16,
    next_client_id: u64,
    from_ui_message_sub: Recipient<NodeFromUiMessage>,
    client_id_by_socket_addr: HashMap<SocketAddr, u64>,
    socket_addr_by_client_id: HashMap<u64, SocketAddr>,
    client_by_id: HashMap<u64, Box<dyn ClientWrapper>>,
}

impl WebSocketSupervisor for WebSocketSupervisorReal {
    fn send_msg(&self, msg: NodeToUiMessage) {
        Self::send_msg(&self.inner, msg);
    }
}

impl WebSocketSupervisorReal {
    pub fn new(
        port: u16,
        from_ui_message_sub: Recipient<NodeFromUiMessage>,
    ) -> std::io::Result<Box<WebSocketSupervisorReal>> {
        let inner = Arc::new(Mutex::new(WebSocketSupervisorInner {
            port,
            next_client_id: 0,
            from_ui_message_sub,
            client_id_by_socket_addr: HashMap::new(),
            socket_addr_by_client_id: HashMap::new(),
            client_by_id: HashMap::new(),
        }));
        let logger = Logger::new("WebSocketSupervisor");
        let logger_1 = logger.clone();
        let server_address = SocketAddr::new(localhost(), port);
        let server = Server::bind(server_address, &Handle::default())
            .unwrap_or_else(|e| panic!("Could not start UI server at {}: {}", server_address, e));
        let upgrade_tuple_stream = Self::remove_failures(server.incoming(), &logger);
        let inner_clone = inner.clone();
        let foreach_result = upgrade_tuple_stream.for_each(move |(upgrade, socket_addr)| {
            Self::handle_upgrade_request(upgrade, socket_addr, inner_clone.clone(), &logger);
            Ok(())
        });
        tokio::spawn(foreach_result.then(move |result| match result {
            Ok(_) => {
                debug!(logger_1, "WebSocketSupervisor accepted a connection");
                Ok(())
            }
            Err(_) => {
                error!(
                    logger_1,
                    "WebSocketSupervisor experienced unprintable error accepting connection"
                );
                Err(())
            }
        }));
        Ok(Box::new(WebSocketSupervisorReal { inner }))
    }

    fn filter_clients<'a, P>(
        locked_inner: &'a mut MutexGuard<WebSocketSupervisorInner>,
        predicate: P,
    ) -> Vec<(u64, &'a mut dyn ClientWrapper)>
    where
        P: FnMut(&(&u64, &mut Box<dyn ClientWrapper>)) -> bool,
    {
        locked_inner
            .client_by_id
            .iter_mut()
            .filter(predicate)
            .map(|(id, item)| (*id, item.as_mut()))
            .collect()
    }

    fn send_msg(inner_arc: &Arc<Mutex<WebSocketSupervisorInner>>, msg: NodeToUiMessage) {
        let mut locked_inner = inner_arc.lock().expect("WebSocketSupervisor is poisoned");
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
        if let Some(errors) = Self::send_to_clients(clients, json) {
            drop(locked_inner);
            Self::handle_sink_errs(errors, inner_arc)
        }
    }

    fn handle_sink_errs(
        errors: Vec<SendToClientWebsocketError>,
        inner_arc: &Arc<Mutex<WebSocketSupervisorInner>>,
    ) {
        errors.into_iter().for_each(|e| match e {
            SendToClientWebsocketError::FlushError((client_id, e)) => {
                Self::handle_flush_error(e, inner_arc, client_id)
            }
            SendToClientWebsocketError::SendError((client_id, e)) => {
                Self::handle_send_error(e, inner_arc, client_id)
            }
        })
    }

    fn remove_failures(
        stream: Incoming<TcpStream>,
        logger: &Logger,
    ) -> impl Stream<Item = (Upgrade<TcpStream>, SocketAddr), Error = InvalidConnection<TcpStream, BytesMut>> {
        let logger_clone = logger.clone();
        stream
            .then(move |result| match result {
                Ok(x) => ok(Some(x)),
                Err(e) => {
                    // Self::handle_invalid_connection(&logger_clone, e);
                    warning!(
                        logger_clone,
                        "Unsuccessful connection to UI port detected: {:?}",
                        e
                    );
                    ok(None)
                }
            })
            .filter(|option| option.is_some())
            .map(|option| option.expect("A None magically got through the filter"))

    }

    // fn warn_of_invalid_connection<T: Debug>(logger: &Logger, debuggable: T) {
    //     warning!(
    //         logger,
    //         "Unsuccessful connection to UI port detected: {:?}",
    //         debuggable
    //     );
    // }
    //
    // #[cfg(target_os = "windows")]
    // fn handle_invalid_connection(logger: &Logger, e: InvalidConnection<TcpStream, BytesMut>) {
    //     let error_string = format!("{:?}", e);
    //     match error_string.contains("10093") || error_string.contains("10053") {
    //             true => return,
    //             false => Self::warn_of_invalid_connection(logger, e)
    //     };
    // }
    //
    // #[cfg(not(target_os = "windows"))]
    // fn handle_invalid_connection(logger: &Logger, e: InvalidConnection<TcpStream, BytesMut>) {
    //     Self::warn_of_invalid_connection(logger, e)
    // }

    fn handle_upgrade_request(
        upgrade: WsUpgrade<TcpStream, BytesMut>,
        socket_addr: SocketAddr,
        inner: Arc<Mutex<WebSocketSupervisorInner>>,
        logger: &Logger,
    ) {
        if upgrade
            .protocols()
            .contains(&String::from(NODE_UI_PROTOCOL))
        {
            Self::accept_upgrade_request(upgrade, socket_addr, inner, logger);
        } else {
            Self::reject_upgrade_request(upgrade, logger);
        }
    }

    fn accept_upgrade_request(
        upgrade: WsUpgrade<TcpStream, BytesMut>,
        socket_addr: SocketAddr,
        inner: Arc<Mutex<WebSocketSupervisorInner>>,
        logger: &Logger,
    ) {
        let logger_clone = logger.clone();
        info!(logger_clone, "UI connected at {}", socket_addr);
        let upgrade_future =
            upgrade
                .use_protocol(NODE_UI_PROTOCOL)
                .accept()
                .map(move |(client, _)| {
                    Self::handle_connection(client, &inner, &logger_clone, socket_addr);
                });
        tokio::spawn(upgrade_future.then(|result| {
            match result {
                Ok(_) => ok::<(), ()>(()),
                Err(_) => ok::<(), ()>(()), // this should never happen: compiler candy
            }
        }));
    }

    fn reject_upgrade_request(upgrade: WsUpgrade<TcpStream, BytesMut>, logger: &Logger) {
        info!(
            logger,
            "UI attempted connection without protocol {}: {:?}",
            NODE_UI_PROTOCOL,
            upgrade.protocols()
        );
        tokio::spawn(upgrade.reject().then(|_| ok::<(), ()>(())));
    }

    fn handle_connection(
        client: Framed<TcpStream, MessageCodec<OwnedMessage>>,
        inner: &Arc<Mutex<WebSocketSupervisorInner>>,
        logger: &Logger,
        socket_addr: SocketAddr,
    ) {
        let logger_1 = logger.clone();
        let logger_2 = logger.clone();
        let inner_1 = inner.clone();
        let (outgoing, incoming) = client.split();
        // "Going synchronous" here to avoid calling .send() on an async Sink, which consumes it
        let sync_outgoing: Wait<SplitSink<_>> = outgoing.wait();
        let client_wrapper = Box::new(ClientWrapperReal {
            delegate: sync_outgoing,
        });
        let mut locked_inner = inner.lock().expect("WebSocketSupervisor is poisoned");
        let client_id = locked_inner.next_client_id;
        locked_inner.next_client_id += 1;
        locked_inner
            .client_id_by_socket_addr
            .insert(socket_addr, client_id);
        locked_inner
            .socket_addr_by_client_id
            .insert(client_id, socket_addr);
        locked_inner.client_by_id.insert(client_id, client_wrapper);
        let incoming_future = incoming
            .then(move |result| Self::handle_websocket_errors(result, &logger_2, socket_addr))
            .map(move |owned_message| match owned_message {
                OwnedMessage::Text(message) => {
                    Self::handle_text_message(&inner_1, &logger_1, socket_addr, &message)
                }
                OwnedMessage::Close(_) => {
                    Self::handle_close_message(&inner_1, &logger_1, socket_addr)
                }
                OwnedMessage::Binary(_) => {
                    Self::handle_other_message(&logger_1, socket_addr, "binary")
                }
                OwnedMessage::Ping(_) => Self::handle_other_message(&logger_1, socket_addr, "ping"),
                OwnedMessage::Pong(_) => Self::handle_other_message(&logger_1, socket_addr, "pong"),
            })
            .for_each(|_| ok::<(), ()>(()));

        tokio::spawn(incoming_future);
    }

    fn send_msg_safely(
        locked_inner: MutexGuard<WebSocketSupervisorInner>,
        inner_arc: &Arc<Mutex<WebSocketSupervisorInner>>,
        msg: NodeToUiMessage,
    ) {
        drop(locked_inner);
        Self::send_msg(inner_arc, msg)
    }

    fn handle_text_message(
        inner_arc: &Arc<Mutex<WebSocketSupervisorInner>>,
        logger: &Logger,
        socket_addr: SocketAddr,
        message: &str,
    ) -> FutureResult<(), ()> {
        let locked_inner = inner_arc.lock().expect("WebSocketSupervisor is poisoned");
        let client_id = match locked_inner.client_id_by_socket_addr.get(&socket_addr) {
            Some(client_id_ref) => *client_id_ref,
            None => {
                warning!(
                    logger,
                    "WebSocketSupervisor got a message from a client that never connected!"
                );
                return err::<(), ()>(()); // end the stream
            }
        };
        match UiTrafficConverter::new_unmarshal_from_ui(message, client_id) {
            Ok(from_ui_message) => {
                locked_inner
                    .from_ui_message_sub
                    .try_send(from_ui_message)
                    .expect("UiGateway is dead");
            }
            Err(Critical(e)) => {
                error!(
                    logger,
                    "Bad message from client {} at {}: {}:\n{}\n",
                    client_id,
                    socket_addr,
                    Critical(e.clone()),
                    message
                );
                Self::send_msg_safely(
                    locked_inner,
                    inner_arc,
                    NodeToUiMessage {
                        target: ClientId(client_id),
                        body: UiUnmarshalError {
                            message: e.to_string(),
                            bad_data: message.to_string(),
                        }
                        .tmb(0),
                    },
                );
                return ok::<(), ()>(());
            }
            Err(NonCritical(opcode, context_id_opt, e)) => {
                error!(
                    logger,
                    "Bad message from client {} at {}: {}:\n{}\n",
                    client_id,
                    socket_addr,
                    NonCritical(opcode.clone(), context_id_opt, e.clone()),
                    message
                );
                match context_id_opt {
                    None => Self::send_msg_safely(
                        locked_inner,
                        inner_arc,
                        NodeToUiMessage {
                            target: ClientId(client_id),
                            body: UiUnmarshalError {
                                message: e.to_string(),
                                bad_data: message.to_string(),
                            }
                            .tmb(0),
                        },
                    ),
                    Some(context_id) => Self::send_msg_safely(
                        locked_inner,
                        inner_arc,
                        NodeToUiMessage {
                            target: ClientId(client_id),
                            body: MessageBody {
                                opcode,
                                path: Conversation(context_id),
                                payload: Err((UNMARSHAL_ERROR, e.to_string())),
                            },
                        },
                    ),
                }
                return ok::<(), ()>(());
            }
        }
        ok::<(), ()>(())
    }

    fn handle_close_message(
        inner_arc: &Arc<Mutex<WebSocketSupervisorInner>>,
        logger: &Logger,
        socket_addr: SocketAddr,
    ) -> FutureResult<(), ()> {
        let mut locked_inner = inner_arc.lock().expect("WebSocketSupervisor is poisoned");
        let client_id = match locked_inner.client_id_by_socket_addr.remove(&socket_addr) {
            None => {
                error!(
                    logger,
                    "WebSocketSupervisor got a disconnect from a client that never connected!"
                );
                return err::<(), ()>(());
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

        err::<(), ()>(()) // end the stream
    }

    fn handle_other_message(
        logger: &Logger,
        socket_addr: SocketAddr,
        message_type: &str,
    ) -> FutureResult<(), ()> {
        info!(
            logger,
            "UI at {} sent unexpected {} message; ignoring", socket_addr, message_type
        );
        ok::<(), ()>(())
    }

    fn send_to_clients(
        clients: Vec<(u64, &mut dyn ClientWrapper)>,
        json: String,
    ) -> Option<Vec<SendToClientWebsocketError>> {
        let errors: Vec<SendToClientWebsocketError> = clients
            .into_iter()
            .flat_map(
                |(client_id, client)| match client.send(OwnedMessage::Text(json.clone())) {
                    Ok(_) => match client.flush() {
                        Ok(_) => None,
                        Err(e) => Some(SendToClientWebsocketError::FlushError((client_id, e))),
                    },
                    Err(e) => Some(SendToClientWebsocketError::SendError((client_id, e))),
                },
            )
            .collect();
        if errors.is_empty() {
            None
        } else {
            Some(errors)
        }
    }

    fn handle_flush_error(
        error: WebSocketError,
        inner_arc: &Arc<Mutex<WebSocketSupervisorInner>>,
        client_id: u64,
    ) {
        match error {
            WebSocketError::IoError(e)
                if e.kind() == ErrorKind::BrokenPipe || e.kind() == ErrorKind::ConnectionReset =>
            {
                Self::emergency_client_removal(client_id, inner_arc);
                warning!(
                    Logger::new("WebSocketSupervisor"),
                    "Client {} hit a fatal flush error: {:?}, dropping the client",
                    client_id,
                    e.kind()
                )
            }
            err => warning!(
                Logger::new("WebSocketSupervisor"),
                "'{:?}' occurred when flushing msg for Client {}",
                err,
                client_id
            ),
        }
    }

    fn handle_send_error(
        error: WebSocketError,
        inner_arc: &Arc<Mutex<WebSocketSupervisorInner>>,
        client_id: u64,
    ) {
        Self::emergency_client_removal(client_id, inner_arc);
        error!(
            Logger::new("WebSocketSupervisor"),
            "Error sending to client {}: {:?}, dropping the client", client_id, error
        );
    }

    fn emergency_client_removal(client_id: u64, inner_arc: &Arc<Mutex<WebSocketSupervisorInner>>) {
        let mut locked_inner = inner_arc.lock().expect("WebSocketSupervisor is poisoned");
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

    fn handle_websocket_errors<I>(
        result: Result<I, WebSocketError>,
        logger: &Logger,
        socket_addr: SocketAddr,
    ) -> FutureResult<I, ()> {
        match result {
            Err(e) => {
                warning!(
                    logger,
                    "UI at {} violated protocol ({:?}): terminating",
                    socket_addr,
                    e
                );
                err::<I, ()>(())
            }
            Ok(msg) => ok::<I, ()>(msg),
        }
    }

    fn close_connection(
        locked_inner: &mut WebSocketSupervisorInner,
        client_id: u64,
        socket_addr: SocketAddr,
        logger: &Logger,
    ) {
        let _ = locked_inner.socket_addr_by_client_id.remove(&client_id);
        let mut client = match locked_inner.client_by_id.remove(&client_id) {
            Some(client) => client,
            None => panic!("WebSocketSupervisor got a disconnect from a client that has disappeared from the stable!"),
        };
        match client.send(OwnedMessage::Close(None)) {
            Err(e) => warning!(
                logger,
                "Error acknowledging connection closure from UI at {}: {:?}",
                socket_addr,
                e
            ),
            Ok(_) => {
                client.flush().unwrap_or_else(|_| {
                    warning!(
                        logger,
                        "Couldn't flush transmission to UI at {}, client dumped anyway",
                        socket_addr
                    )
                });
            }
        }
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
    SendError((u64, WebSocketError)),
    FlushError((u64, WebSocketError)),
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
    ) -> std::io::Result<Box<dyn WebSocketSupervisor>> {
        WebSocketSupervisorReal::new(port, recipient)
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
    use futures::lazy;
    use masq_lib::constants::UNMARSHAL_ERROR;
    use masq_lib::messages::{
        FromMessageBody, UiDescriptorResponse, UiShutdownRequest, UiStartOrder, UiUnmarshalError,
        NODE_UI_PROTOCOL,
    };
    use masq_lib::test_utils::logging::init_test_logging;
    use masq_lib::test_utils::logging::TestLogHandler;
    use masq_lib::test_utils::ui_connection::UiConnection;
    use masq_lib::ui_gateway::MessagePath::FireAndForget;
    use masq_lib::ui_gateway::NodeFromUiMessage;
    use masq_lib::ui_traffic_converter::UiTrafficConverter;
    use masq_lib::utils::{find_free_port, localhost};
    use std::cell::RefCell;
    use std::io::{Error, ErrorKind};
    use std::net::{IpAddr, Ipv4Addr, Shutdown};
    use std::str::FromStr;
    use std::thread;
    use std::time::Duration;
    use tokio::runtime::Runtime;
    use websocket::client::sync::Client;
    use websocket::r#async::TcpStream as TcpStreamAsync;
    use websocket::stream::sync::TcpStream;
    use websocket::ClientBuilder;
    use websocket::Message;

    impl WebSocketSupervisorReal {
        fn inject_mock_client(&self, mock_client: ClientWrapperMock) -> u64 {
            let mut locked_inner = self.inner.lock().unwrap();
            let client_id = locked_inner.next_client_id;
            locked_inner.next_client_id += 1;
            locked_inner
                .client_by_id
                .insert(client_id, Box::new(mock_client));
            client_id
        }

        fn get_mock_client(&self, client_id: u64) -> ClientWrapperMock {
            let locked_inner = self.inner.lock().unwrap();
            let mock_client_box = match locked_inner.client_by_id.get(&client_id) {
                Some(mcb) => mcb,
                None => panic!("Did not find mock client for id: {}", client_id),
            };
            let any = mock_client_box.as_any();
            let result = any
                .downcast_ref::<ClientWrapperMock>()
                .expect("couldn't downcast");
            result.clone()
        }
    }

    struct ClientWrapperMock {
        send_params: Arc<Mutex<Vec<OwnedMessage>>>,
        send_results: RefCell<Vec<Result<(), WebSocketError>>>,
        flush_results: RefCell<Vec<Result<(), WebSocketError>>>,
    }

    impl Clone for ClientWrapperMock {
        fn clone(&self) -> Self {
            ClientWrapperMock {
                send_params: self.send_params.clone(),
                send_results: RefCell::new(
                    self.send_results
                        .borrow()
                        .iter()
                        .map(|result| match result {
                            Ok(()) => Ok(()),
                            Err(_) => Err(WebSocketError::NoDataAvailable),
                        })
                        .collect::<Vec<Result<(), WebSocketError>>>(),
                ),
                flush_results: RefCell::new(
                    self.flush_results
                        .borrow()
                        .iter()
                        .map(|result| match result {
                            Ok(()) => Ok(()),
                            Err(_) => Err(WebSocketError::NoDataAvailable),
                        })
                        .collect::<Vec<Result<(), WebSocketError>>>(),
                ),
            }
        }
    }

    impl ClientWrapperMock {
        fn new() -> ClientWrapperMock {
            ClientWrapperMock {
                send_params: Arc::new(Mutex::new(vec![])),
                send_results: RefCell::new(vec![]),
                flush_results: RefCell::new(vec![]),
            }
        }

        fn send_params(mut self, params: &Arc<Mutex<Vec<OwnedMessage>>>) -> Self {
            self.send_params = params.clone();
            self
        }

        fn send_result(self, result: Result<(), WebSocketError>) -> Self {
            self.send_results.borrow_mut().push(result);
            self
        }

        fn flush_result(self, result: Result<(), WebSocketError>) -> Self {
            self.flush_results.borrow_mut().push(result);
            self
        }
    }

    impl ClientWrapper for ClientWrapperMock {
        fn as_any(&self) -> &dyn Any {
            self
        }

        fn send(&mut self, item: OwnedMessage) -> Result<(), WebSocketError> {
            self.send_params.lock().unwrap().push(item);
            if self.send_results.borrow().is_empty() {
                panic!("ClientWrapperMock: send_results is empty")
            }
            self.send_results.borrow_mut().remove(0)
        }

        fn flush(&mut self) -> Result<(), WebSocketError> {
            if self.flush_results.borrow().is_empty() {
                panic!("ClientWrapperMock: flush_results is empty")
            }
            self.flush_results.borrow_mut().remove(0)
        }
    }

    fn make_client(port: u16, protocol: &str) -> Result<Client<TcpStream>, WebSocketError> {
        ClientBuilder::new(format!("ws://127.0.0.1:{}", port).as_str())
            .expect("ClientBuilder could not be built")
            .add_protocol(protocol)
            .connect_insecure()
    }

    fn wait_for_client(port: u16, protocol: &str) -> Client<TcpStream> {
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

    // #[test]
    // #[cfg(not(target_os = "windows"))]
    // fn connection_error_with_10093_and_10095_handled_properly() {
    //     init_test_logging();
    //     let logger = Logger::new("connection_error_with_10093_handled_properly");
    //     let connection_error: InvalidConnection<TcpStreamAsync, BytesMut> = InvalidConnection {
    //         stream: None,
    //         parsed: None,
    //         buffer: None,
    //         error: HyperIntoWsError::Io(io::Error::from_raw_os_error(10093)).into(),
    //     };
    //     let connection_error2: InvalidConnection<TcpStreamAsync, BytesMut> = InvalidConnection {
    //         stream: None,
    //         parsed: None,
    //         buffer: None,
    //         error: HyperIntoWsError::Io(io::Error::from_raw_os_error(10053)).into(),
    //     };
    //     let connection_error3: InvalidConnection<TcpStreamAsync, BytesMut> = InvalidConnection {
    //         stream: None,
    //         parsed: None,
    //         buffer: None,
    //         error: HyperIntoWsError::Io(io::Error::from_raw_os_error(10005)).into(),
    //     };
    //
    //     WebSocketSupervisorReal::handle_invalid_connection(&logger, connection_error);
    //
    //     TestLogHandler::new().exists_log_containing("connection_error_with_10093_handled_properly");
    //
    //     let logger = Logger::new("connection_error_with_10053_handled_properly");
    //
    //     WebSocketSupervisorReal::handle_invalid_connection(&logger, connection_error2);
    //
    //     TestLogHandler::new().exists_log_containing("connection_error_with_10053_handled_properly");
    //
    //     let logger = Logger::new("connection_error_with_10005_handled_properly");
    //
    //     WebSocketSupervisorReal::handle_invalid_connection(&logger, connection_error3);
    //
    //     TestLogHandler::new().exists_log_containing("connection_error_with_10005_handled_properly");
    // }
    //
    // #[test]
    // #[cfg(target_os = "windows")]
    // fn connection_error_with_10093_and_10095_handled_properly() {
    //     init_test_logging();
    //     let logger = Logger::new("connection_error_with_10093_handled_properly");
    //     let connection_error: InvalidConnection<TcpStreamAsync, BytesMut> = InvalidConnection {
    //         stream: None,
    //         parsed: None,
    //         buffer: None,
    //         error: HyperIntoWsError::Io(io::Error::from_raw_os_error(10093)).into(),
    //     };
    //     let connection_error2: InvalidConnection<TcpStreamAsync, BytesMut> = InvalidConnection {
    //         stream: None,
    //         parsed: None,
    //         buffer: None,
    //         error: HyperIntoWsError::Io(io::Error::from_raw_os_error(10053)).into(),
    //     };
    //     let connection_error3: InvalidConnection<TcpStreamAsync, BytesMut> = InvalidConnection {
    //         stream: None,
    //         parsed: None,
    //         buffer: None,
    //         error: HyperIntoWsError::Io(io::Error::from_raw_os_error(10005)).into(),
    //     };
    //
    //     WebSocketSupervisorReal::handle_invalid_connection(&logger, connection_error);
    //
    //     TestLogHandler::new().exists_no_log_containing("connection_error_with_10093_handled_properly");
    //
    //     WebSocketSupervisorReal::handle_invalid_connection(&logger, connection_error2);
    //
    //     TestLogHandler::new().exists_no_log_containing("connection_error_with_10093_handled_properly");
    //
    //     WebSocketSupervisorReal::handle_invalid_connection(&logger, connection_error3);
    //
    //     TestLogHandler::new().exists_log_containing("connection_error_with_10093_handled_properly");
    // }

    #[test]
    fn logs_pre_upgrade_connection_errors() {
        init_test_logging();
        let port = find_free_port();
        let (ui_gateway, _, _) = make_recorder();

        thread::spawn(move || {
            let system = System::new("logs_pre_upgrade_connection_errors");
            let ui_message_sub = subs(ui_gateway);
            let subject = lazy(move || {
                let _subject = WebSocketSupervisorReal::new(port, ui_message_sub).unwrap();
                Ok(())
            });
            actix::spawn(subject);
            system.run();
        });
        wait_for_server(port);

        let tlh = TestLogHandler::new();
        tlh.await_log_containing("Unsuccessful connection to UI port detected", 1000);
    }

    #[test]
    fn data_for_a_newly_connected_client_is_set_properly() {
        fn prepare_conn(
            upgradable: WsUpgrade<TcpStreamAsync, BytesMut>,
            inner_arc: Arc<Mutex<WebSocketSupervisorInner>>,
            socket_addr: SocketAddr,
            logger: Logger,
        ) -> impl Future<Item = (), Error = WebSocketError> {
            upgradable.accept().and_then(move |(client, _)| {
                let logger = logger;
                //this is the function being under assertions in this test
                //^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
                WebSocketSupervisorReal::handle_connection(
                    client,
                    &inner_arc,
                    &logger,
                    socket_addr,
                );
                //^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
                Ok(())
            })
        }
        let port = find_free_port();
        let logger = Logger::new("test_logger");
        let ws_server = Server::bind(format!("127.0.0.1:{}", port), &Handle::default()).unwrap();
        let upgrade = WebSocketSupervisorReal::remove_failures(ws_server.incoming(), &logger);
        //thread causing an initiation of a new connection to the server
        let join_handle = thread::spawn(move || {
            ClientBuilder::new(format!("ws://127.0.0.1:{}", port).as_str())
                .unwrap()
                .connect_insecure()
        });
        let future_result = upgrade
            //converting error type of the stream to something simple
            .map_err(|_| ())
            .for_each(move |(upgrade, _)| {
                let inner_arc = Arc::new(Mutex::new(make_ordinary_inner()));
                let socket_addr = SocketAddr::from_str("1.2.3.4:1234").unwrap();
                let future = prepare_conn(upgrade, inner_arc.clone(), socket_addr, logger.clone())
                    //making sure we won't make assertions earlier than prepare_conn has completed
                    .then(|_| {
                        let inner_accessible = inner_arc.lock().unwrap();
                        assert_eq!(inner_accessible.next_client_id, 1);
                        assert_eq!(
                            inner_accessible.socket_addr_by_client_id.get(&0).unwrap(),
                            &socket_addr
                        );
                        assert_eq!(
                            inner_accessible
                                .client_id_by_socket_addr
                                .get(&socket_addr)
                                .unwrap(),
                            &0
                        );
                        assert!(inner_accessible.client_by_id.get(&0).is_some());
                        ok::<(), ()>(())
                    });
                match future.wait() {
                    //taking advantage of a halt of the stream's iteration by an error; though paradoxical,
                    //successful test ends with Err(())
                    Ok(_) => Err(()),
                    _ => unreachable!("test failed for an unexpected reason"),
                }
            });
        let mut runtime = Runtime::new().unwrap();

        runtime
            .block_on(
                future_result.then::<_, Result<(), ()>>(|result| match result {
                    Ok(_) => unreachable!("test failed for an unexpected reason"),
                    _ => Ok(()),
                }),
            )
            .unwrap();

        join_handle.join().unwrap().unwrap();
    }

    #[test]
    fn rejects_connection_attempt_with_improper_protocol_name() {
        init_test_logging();
        let port = find_free_port();
        let (ui_gateway, _, _) = make_recorder();

        thread::spawn(move || {
            let system = System::new("rejects_connection_attempt_with_improper_protocol_name");
            let ui_message_sub = subs(ui_gateway);
            let subject = lazy(move || {
                let _subject = WebSocketSupervisorReal::new(port, ui_message_sub).unwrap();
                Ok(())
            });
            actix::spawn(subject);
            system.run();
        });
        wait_for_server(port);

        make_client(port, "MASQNode-UI").err().unwrap();

        let tlh = TestLogHandler::new();
        tlh.await_log_containing(
            "UI attempted connection without protocol MASQNode-UIv2: [\"MASQNode-UI\"]",
            1000,
        );
    }

    #[test]
    fn logs_unexpected_binary_ping_pong_websocket_messages() {
        init_test_logging();
        let port = find_free_port();
        let (ui_gateway, _, _) = make_recorder();

        thread::spawn(move || {
            let system = System::new("logs_unexpected_binary_ping_pong_websocket_messages");
            let ui_message_sub = subs(ui_gateway);
            let subject = lazy(move || {
                let _subject = WebSocketSupervisorReal::new(port, ui_message_sub).unwrap();
                Ok(())
            });
            actix::spawn(subject);
            system.run();
        });
        let mut client = await_value(None, || UiConnection::make(port, NODE_UI_PROTOCOL)).unwrap();

        client.send_message(&OwnedMessage::Binary(vec![1u8, 2u8, 3u8, 4u8]));
        client.send_message(&OwnedMessage::Ping(vec![1u8, 2u8, 3u8, 4u8]));
        client.send_message(&OwnedMessage::Pong(vec![1u8, 2u8, 3u8, 4u8]));
        client.shutdown();

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

        thread::spawn(move || {
            let system = System::new("can_connect_two_clients_and_receive_messages_from_them");
            let ui_message_sub = subs(ui_gateway);
            let subject = lazy(move || {
                let _subject = WebSocketSupervisorReal::new(port, ui_message_sub).unwrap();
                Ok(())
            });
            actix::spawn(subject);
            system.run();
        });

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

        one_client.send_message(&OwnedMessage::Close(None)).unwrap();
        let one_close_msg = one_client.recv_message().unwrap();
        another_client
            .send_message(&OwnedMessage::Close(None))
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
        assert_eq!(one_close_msg, OwnedMessage::Close(None));
        assert_eq!(another_close_msg, OwnedMessage::Close(None));
    }

    #[test]
    fn logs_badly_formatted_json_and_returns_unmarshal_error() {
        init_test_logging();
        let subject_inner = make_ordinary_inner();
        let subject = WebSocketSupervisorReal {
            inner: Arc::new(Mutex::new(subject_inner)),
        };
        let socket_addr = SocketAddr::from_str("1.2.3.4:1234").unwrap();
        let send_params_arc = Arc::new(Mutex::new(vec![]));
        let client = ClientWrapperMock::new()
            .send_params(&send_params_arc)
            .send_result(Ok(()))
            .flush_result(Ok(()));
        let client_id = subject.inject_mock_client(client);
        {
            let mut inner = subject.inner.lock().unwrap();
            inner
                .client_id_by_socket_addr
                .insert(socket_addr, client_id);
        }
        let bad_json = "}: I am badly-formatted JSON :{";

        let _ = WebSocketSupervisorReal::handle_text_message(
            &subject.inner,
            &Logger::new("test"),
            socket_addr,
            bad_json,
        )
        .wait();

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
            OwnedMessage::Text(s) => s,
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
            inner: Arc::new(Mutex::new(subject_inner)),
        };
        let socket_addr = SocketAddr::from_str("1.2.3.4:1234").unwrap();
        let send_params_arc = Arc::new(Mutex::new(vec![]));
        let client = ClientWrapperMock::new()
            .send_params(&send_params_arc)
            .send_result(Ok(()))
            .flush_result(Ok(()));
        let client_id = subject.inject_mock_client(client);
        {
            let mut inner = subject.inner.lock().unwrap();
            inner
                .client_id_by_socket_addr
                .insert(socket_addr, client_id);
        }
        let bad_message_json = r#"{"opcode":"shutdown"}"#;

        let _ = WebSocketSupervisorReal::handle_text_message(
            &subject.inner,
            &Logger::new("test"),
            socket_addr,
            bad_message_json,
        )
        .wait();

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
            OwnedMessage::Text(s) => s,
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
            inner: Arc::new(Mutex::new(subject_inner)),
        };
        let socket_addr = SocketAddr::from_str("1.2.3.4:1234").unwrap();
        let send_params_arc = Arc::new(Mutex::new(vec![]));
        let client = ClientWrapperMock::new()
            .send_params(&send_params_arc)
            .send_result(Ok(()))
            .flush_result(Ok(()));
        let client_id = subject.inject_mock_client(client);
        {
            let mut inner = subject.inner.lock().unwrap();
            inner
                .client_id_by_socket_addr
                .insert(socket_addr, client_id);
        }
        let bad_message_json = r#"{"opcode":"setup", "contextId":3333}"#;

        let _ = WebSocketSupervisorReal::handle_text_message(
            &subject.inner,
            &Logger::new("test"),
            socket_addr,
            bad_message_json,
        )
        .wait();

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
            OwnedMessage::Text(s) => s,
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

    fn flush_failure_assertion(flush_error: WebSocketError, client_is_retained_after_error: bool) {
        let client = ClientWrapperMock::new()
            .send_result(Ok(()))
            .flush_result(Err(flush_error));
        sink_failure_test_body(client, client_is_retained_after_error)
    }

    fn send_failure_assertion(send_error: WebSocketError) {
        let client = ClientWrapperMock::new().send_result(Err(send_error));
        sink_failure_test_body(client, false)
    }

    fn sink_failure_test_body(
        client_mock: ClientWrapperMock,
        client_is_retained_after_error: bool,
    ) {
        let (ui_gateway, _, _) = make_recorder();
        let from_ui_message_sub = subs(ui_gateway);
        let socket_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::from([1, 2, 4, 5])), 4455);
        let mut client_by_id: HashMap<u64, Box<dyn ClientWrapper>> = HashMap::new();
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

        WebSocketSupervisorReal::send_msg(&inner_arc, msg);

        let inner = inner_arc.lock().unwrap();
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
        let flush_error = WebSocketError::NoDataAvailable;
        flush_failure_assertion(flush_error, true);
        TestLogHandler::new().exists_log_containing(
            "WARN: WebSocketSupervisor: 'NoDataAvailable' occurred when flushing msg for Client 123",
        );
    }

    #[test]
    fn can_handle_broken_pipe_flush_failure() {
        init_test_logging();
        let flush_error = WebSocketError::IoError(Error::from(ErrorKind::BrokenPipe));
        flush_failure_assertion(flush_error, false);
        TestLogHandler::new().exists_log_containing(
            "WARN: WebSocketSupervisor: Client 123 hit a fatal flush error: BrokenPipe, dropping the client",
        );
    }

    #[test]
    fn can_handle_connection_aborted_flush_failure() {
        init_test_logging();
        let flush_error = WebSocketError::IoError(Error::from(ErrorKind::ConnectionReset));
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

        thread::spawn(move || {
            let system = System::new("once_a_client_sends_a_close_no_more_data_is_accepted");
            let ui_message_sub = subs(ui_gateway);
            let subject = lazy(move || {
                let subject = WebSocketSupervisorReal::new(port, ui_message_sub).unwrap();
                tx.send(subject.inner.clone()).unwrap();
                Ok(())
            });
            actix::spawn(subject);
            system.run();
        });

        let mut client = await_value(None, || UiConnection::make(port, NODE_UI_PROTOCOL)).unwrap();

        client.send(UiShutdownRequest {});
        client.send_message(&OwnedMessage::Close(None));
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
    fn close_connection_logs_inability_to_flush_close_msg_before_the_client_is_dumped_anyway() {
        init_test_logging();
        let mut inner = make_ordinary_inner();
        let mock_client = ClientWrapperMock::new()
            .send_result(Ok(()))
            .flush_result(Err(WebSocketError::IoError(Error::from(
                ErrorKind::BrokenPipe,
            ))));
        let socket_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 44444);
        inner.client_by_id.insert(1, Box::new(mock_client));
        inner.socket_addr_by_client_id.insert(1, socket_addr);
        let inner_arc = Arc::new(Mutex::new(inner));
        let mut locked_inner = inner_arc.lock().unwrap();

        WebSocketSupervisorReal::close_connection(
            &mut locked_inner,
            1,
            socket_addr,
            &Logger::new("close_connection_test"),
        );

        TestLogHandler::new().exists_log_containing(
            "WARN: close_connection_test: Couldn't \
         flush transmission to UI at 1.2.3.4:44444, client dumped anyway",
        );
        assert!(locked_inner.socket_addr_by_client_id.is_empty());
        assert!(locked_inner.client_by_id.is_empty())
        //the third hashmap is supposed to be cleared a step before this fn call
    }

    #[test]
    fn a_client_that_violates_the_protocol_is_terminated() {
        let port = find_free_port();
        let (ui_gateway, ui_gateway_awaiter, ui_gateway_recording_arc) = make_recorder();

        thread::spawn(move || {
            let system = System::new("a_client_that_violates_the_protocol_is_terminated");
            let ui_message_sub = subs(ui_gateway);
            let subject = lazy(move || {
                let _subject = WebSocketSupervisorReal::new(port, ui_message_sub).unwrap();
                Ok(())
            });
            actix::spawn(subject);
            system.run();
        });
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
        let system = System::new("send_msg_sends_a_message_to_the_client");
        let lazy_future = lazy(move || {
            let subject = WebSocketSupervisorReal::new(port, ui_message_sub).unwrap();
            let one_mock_client = ClientWrapperMock::new()
                .send_result(Ok(()))
                .flush_result(Ok(()));
            let another_mock_client = ClientWrapperMock::new();
            let one_client_id = subject.inject_mock_client(one_mock_client);
            let another_client_id = subject.inject_mock_client(another_mock_client);
            let msg = NodeToUiMessage {
                target: MessageTarget::ClientId(one_client_id),
                body: MessageBody {
                    opcode: "booga".to_string(),
                    path: FireAndForget,
                    payload: Ok("{}".to_string()),
                },
            };

            subject.send_msg(msg.clone());

            let one_mock_client_ref = subject.get_mock_client(one_client_id);
            let actual_message = match one_mock_client_ref.send_params.lock().unwrap().get(0) {
                Some(OwnedMessage::Text(json)) => UiTrafficConverter::new_unmarshal_to_ui(json.as_str(), MessageTarget::ClientId(one_client_id)).unwrap(),
                Some(x) => panic! ("send should have been called with OwnedMessage::Text, but was called with {:?} instead", x),
                None => panic! ("send should have been called, but wasn't"),
            };
            assert_eq!(actual_message, msg);
            let another_mock_client_ref = subject.get_mock_client(another_client_id);
            assert_eq!(another_mock_client_ref.send_params.lock().unwrap().len(), 0);
            Ok(())
        });
        actix::spawn(lazy_future);
        System::current().stop();
        system.run();
    }

    #[test]
    fn send_msg_with_all_except_sends_a_message_to_all_except() {
        let port = find_free_port();
        let (ui_gateway, _, _) = make_recorder();
        let ui_message_sub = subs(ui_gateway);
        let system = System::new("send_msg_sends_a_message_to_the_client");
        let lazy_future = lazy(move || {
            let subject = WebSocketSupervisorReal::new(port, ui_message_sub).unwrap();
            let one_mock_client = ClientWrapperMock::new()
                .send_result(Ok(()))
                .flush_result(Ok(()));
            let another_mock_client = ClientWrapperMock::new()
                .send_result(Ok(()))
                .flush_result(Ok(()));
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
                Some(OwnedMessage::Text(json)) => UiTrafficConverter::new_unmarshal_to_ui(json.as_str(), MessageTarget::AllExcept(another_client_id)).unwrap(),
                Some(x) => panic! ("send should have been called with OwnedMessage::Text, but was called with {:?} instead", x),
                None => panic! ("send should have been called, but wasn't"),
            };
            assert_eq!(actual_message, msg);
            let another_mock_client_ref = subject.get_mock_client(another_client_id);
            assert_eq!(another_mock_client_ref.send_params.lock().unwrap().len(), 0);
            Ok(())
        });
        actix::spawn(lazy_future);
        System::current().stop();
        system.run();
    }

    #[test]
    fn send_msg_with_all_clients_sends_a_message_to_all_clients() {
        let port = find_free_port();
        let (ui_gateway, _, _) = make_recorder();
        let ui_message_sub = subs(ui_gateway);
        let system = System::new("send_msg_sends_a_message_to_the_client");
        let lazy_future = lazy(move || {
            let subject = WebSocketSupervisorReal::new(port, ui_message_sub).unwrap();
            let one_mock_client = ClientWrapperMock::new()
                .send_result(Ok(()))
                .flush_result(Ok(()));
            let another_mock_client = ClientWrapperMock::new()
                .send_result(Ok(()))
                .flush_result(Ok(()));
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
            let msg_received_assertion = |mock_client_ref: ClientWrapperMock| {
                match mock_client_ref.send_params.lock().unwrap().get(0) {
                    Some(OwnedMessage::Text(json)) =>
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
            Ok(())
        });
        actix::spawn(lazy_future);
        System::current().stop();
        system.run();
    }

    #[test]
    fn send_msg_fails_on_send_and_so_logs_and_removes_the_client() {
        init_test_logging();
        send_failure_assertion(WebSocketError::NoDataAvailable);
        TestLogHandler::new().exists_log_containing(
            "ERROR: WebSocketSupervisor: Error sending to client 123: NoDataAvailable, dropping the client",
        );
    }

    #[test]
    fn send_msg_fails_to_look_up_client_to_send_to() {
        init_test_logging();
        let port = find_free_port();
        let (ui_gateway, _, _) = make_recorder();
        let ui_message_sub = subs(ui_gateway);
        let system = System::new("send_msg_fails_to_look_up_client_to_send_to");
        let lazy_future = lazy(move || {
            let subject = WebSocketSupervisorReal::new(port, ui_message_sub).unwrap();
            let msg = NodeToUiMessage {
                target: MessageTarget::ClientId(7),
                body: MessageBody {
                    opcode: "booga".to_string(),
                    path: FireAndForget,
                    payload: Ok("{}".to_string()),
                },
            };
            subject.send_msg(msg);
            Ok(())
        });
        actix::spawn(lazy_future);
        System::current().stop();
        system.run();
        TestLogHandler::new().exists_log_containing(
            "WebsocketSupervisor: WARN: Tried to send to an absent client 7",
        );
    }
}
