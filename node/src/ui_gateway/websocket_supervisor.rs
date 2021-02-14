// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use crate::sub_lib::logger::Logger;
use actix::Recipient;
use bytes::BytesMut;
use futures::future::FutureResult;
use futures::future::{err, ok};
use futures::sink::Wait;
use futures::stream::SplitSink;
use futures::Future;
use futures::Sink;
use futures::Stream;
use itertools::Itertools;
use masq_lib::messages::{ToMessageBody, UiUnmarshalError, NODE_UI_PROTOCOL, UNMARSHAL_ERROR};
use masq_lib::ui_gateway::MessagePath::Conversation;
use masq_lib::ui_gateway::MessageTarget::ClientId;
use masq_lib::ui_gateway::{MessageBody, MessageTarget, NodeFromUiMessage, NodeToUiMessage};
use masq_lib::ui_traffic_converter::UiTrafficConverter;
use masq_lib::ui_traffic_converter::UnmarshalError::{Critical, NonCritical};
use masq_lib::utils::localhost;
use std::any::Any;
use std::collections::HashMap;
use std::fmt::Debug;
use std::net::SocketAddr;
use std::sync::Mutex;
use std::sync::{Arc, MutexGuard};
use tokio::reactor::Handle;
use websocket::client::r#async::Framed;
use websocket::r#async::MessageCodec;
use websocket::r#async::TcpStream;
use websocket::server::r#async::Server;
use websocket::server::upgrade::WsUpgrade;
use websocket::OwnedMessage;
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
    client_by_id: HashMap<u64, Box<dyn ClientWrapper>>,
}

impl WebSocketSupervisor for WebSocketSupervisorReal {
    fn send_msg(&self, msg: NodeToUiMessage) {
        let mut locked_inner = self.inner.lock().expect("WebSocketSupervisor is poisoned");
        Self::send_msg(&mut locked_inner, msg);
    }
}

impl WebSocketSupervisorReal {
    pub fn new(
        port: u16,
        from_ui_message_sub: Recipient<NodeFromUiMessage>,
    ) -> std::io::Result<WebSocketSupervisorReal> {
        let inner = Arc::new(Mutex::new(WebSocketSupervisorInner {
            port,
            next_client_id: 0,
            from_ui_message_sub,
            client_id_by_socket_addr: HashMap::new(),
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
        Ok(WebSocketSupervisorReal { inner })
    }

    fn send_msg(locked_inner: &mut MutexGuard<WebSocketSupervisorInner>, msg: NodeToUiMessage) {
        let client_ids = match msg.target {
            MessageTarget::ClientId(n) => vec![n],
            MessageTarget::AllExcept(n) => locked_inner
                .client_by_id
                .keys()
                .filter(|k| k != &&n)
                .copied()
                .collect_vec(),
            MessageTarget::AllClients => locked_inner.client_by_id.keys().copied().collect_vec(),
        };
        let json = UiTrafficConverter::new_marshal(msg.body);
        Self::send_to_clients(locked_inner, client_ids, json);
    }

    fn remove_failures<I, E: Debug>(
        stream: impl Stream<Item = I, Error = E>,
        logger: &Logger,
    ) -> impl Stream<Item = I, Error = E> {
        let logger_clone = logger.clone();
        stream
            .then(move |result| match result {
                Ok(x) => ok::<Option<I>, E>(Some(x)),
                Err(e) => {
                    warning!(
                        logger_clone,
                        "Unsuccessful connection to UI port detected: {:?}",
                        e
                    );
                    ok::<Option<I>, E>(None)
                }
            })
            .filter(|option| option.is_some())
            .map(|option| option.expect("A None magically got through the filter"))
    }

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
            Self::reject_upgrade_request(upgrade, &logger);
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

    fn handle_text_message(
        inner_arc: &Arc<Mutex<WebSocketSupervisorInner>>,
        logger: &Logger,
        socket_addr: SocketAddr,
        message: &str,
    ) -> FutureResult<(), ()> {
        let mut locked_inner = inner_arc.lock().expect("WebSocketSupervisor is poisoned");
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
                Self::send_msg(
                    &mut locked_inner,
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
                    None => Self::send_msg(
                        &mut locked_inner,
                        NodeToUiMessage {
                            target: ClientId(client_id),
                            body: UiUnmarshalError {
                                message: e.to_string(),
                                bad_data: message.to_string(),
                            }
                            .tmb(0),
                        },
                    ),
                    Some(context_id) => Self::send_msg(
                        &mut locked_inner,
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
        Self::close_connection(&mut locked_inner, client_id, socket_addr, &logger);

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
        locked_inner: &mut MutexGuard<WebSocketSupervisorInner>,
        client_ids: Vec<u64>,
        json: String,
    ) {
        client_ids.into_iter().for_each(|client_id| {
            let client = locked_inner
                .client_by_id
                .get_mut(&client_id)
                .unwrap_or_else(|| panic!("Tried to send to a nonexistent client {}", client_id));
            match client.send(OwnedMessage::Text(json.clone())) {
                Ok(_) => match client.flush() {
                    Ok(_) => (),
                    Err(_) => warning!(
                        Logger::new("WebSocketSupervisor"),
                        "Client {} dropped its connection before it could be flushed",
                        client_id
                    ),
                },
                Err(e) => error!(
                    Logger::new("WebSocketSupervisor"),
                    "Error sending to client {}: {:?}", client_id, e
                ),
            };
        });
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
                    panic!("Couldn't flush transmission to UI at {}", socket_addr)
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::logging::init_test_logging;
    use crate::test_utils::logging::TestLogHandler;
    use crate::test_utils::recorder::{make_recorder, Recorder};
    use crate::test_utils::wait_for;
    use crate::test_utils::{assert_contains, await_value};
    use actix::System;
    use actix::{Actor, Addr};
    use futures::future::lazy;
    use masq_lib::messages::{
        FromMessageBody, UiShutdownRequest, UiStartOrder, UiUnmarshalError, NODE_UI_PROTOCOL,
        UNMARSHAL_ERROR,
    };
    use masq_lib::test_utils::ui_connection::UiConnection;
    use masq_lib::ui_gateway::MessagePath::FireAndForget;
    use masq_lib::ui_gateway::NodeFromUiMessage;
    use masq_lib::ui_traffic_converter::UiTrafficConverter;
    use masq_lib::utils::{find_free_port, localhost};
    use std::cell::RefCell;
    use std::net::Shutdown;
    use std::str::FromStr;
    use std::thread;
    use std::time::Duration;
    use websocket::client::sync::Client;
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
        let messages = vec![0, 1, 2]
            .into_iter()
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
        let (ui_message_sub, _, _) = make_recorder();
        let subject_inner = WebSocketSupervisorInner {
            port: 4321,
            next_client_id: 0,
            from_ui_message_sub: ui_message_sub.start().recipient::<NodeFromUiMessage>(),
            client_id_by_socket_addr: Default::default(),
            client_by_id: Default::default(),
        };
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

    #[test]
    fn bad_one_way_message_is_logged_and_returns_error() {
        init_test_logging();
        let (ui_message_sub, _, _) = make_recorder();
        let subject_inner = WebSocketSupervisorInner {
            port: 1234,
            next_client_id: 0,
            from_ui_message_sub: ui_message_sub.start().recipient::<NodeFromUiMessage>(),
            client_id_by_socket_addr: Default::default(),
            client_by_id: Default::default(),
        };
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
        let (ui_message_sub, _, _) = make_recorder();
        let subject_inner = WebSocketSupervisorInner {
            port: 1234,
            next_client_id: 0,
            from_ui_message_sub: ui_message_sub.start().recipient::<NodeFromUiMessage>(),
            client_id_by_socket_addr: Default::default(),
            client_by_id: Default::default(),
        };
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

    #[test]
    fn can_handle_flush_failure_after_send() {
        init_test_logging();
        let (ui_gateway, _, _) = make_recorder();
        let from_ui_message_sub = subs(ui_gateway);
        let client = ClientWrapperMock::new()
            .send_result(Ok(()))
            .flush_result(Err(WebSocketError::NoDataAvailable));
        let mut client_by_id: HashMap<u64, Box<dyn ClientWrapper>> = HashMap::new();
        client_by_id.insert(1234, Box::new(client));
        let inner_arc = Arc::new(Mutex::new(WebSocketSupervisorInner {
            port: 0,
            next_client_id: 0,
            from_ui_message_sub,
            client_id_by_socket_addr: Default::default(),
            client_by_id,
        }));

        WebSocketSupervisorReal::send_to_clients(
            &mut inner_arc.lock().unwrap(),
            vec![1234],
            "json".to_string(),
        );

        TestLogHandler::new().exists_log_containing ("WARN: WebSocketSupervisor: Client 1234 dropped its connection before it could be flushed");
    }

    #[test]
    fn once_a_client_sends_a_close_no_more_data_is_accepted() {
        let port = find_free_port();
        let (ui_gateway, ui_gateway_awaiter, ui_gateway_recording_arc) = make_recorder();

        thread::spawn(move || {
            let system = System::new("once_a_client_sends_a_close_no_more_data_is_accepted");
            let ui_message_sub = subs(ui_gateway);
            let subject = lazy(move || {
                let _subject = WebSocketSupervisorReal::new(port, ui_message_sub).unwrap();
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
            let actual_message = match one_mock_client_ref.send_params.lock().unwrap().get(0) {
                Some(OwnedMessage::Text(json)) =>
                    UiTrafficConverter::new_unmarshal_to_ui(json.as_str(), MessageTarget::AllClients).unwrap(),
                Some(x) => panic! ("send should have been called with OwnedMessage::Text, but was called with {:?} instead", x),
                None => panic! ("send should have been called, but wasn't"),
            };
            assert_eq!(actual_message, msg);
            let another_mock_client_ref = subject.get_mock_client(another_client_id);
            let actual_message = match another_mock_client_ref.send_params.lock().unwrap().get(0) {
                Some(OwnedMessage::Text(json)) => UiTrafficConverter::new_unmarshal_to_ui(json.as_str(), MessageTarget::AllClients).unwrap(),
                Some(x) => panic! ("send should have been called with OwnedMessage::Text, but was called with {:?} instead", x),
                None => panic! ("send should have been called, but wasn't"),
            };
            assert_eq!(actual_message, msg);
            Ok(())
        });
        actix::spawn(lazy_future);
        System::current().stop();
        system.run();
    }

    #[test]
    fn send_msg_tries_to_send_message_and_logs_warning_on_flush_failure() {
        init_test_logging();
        let port = find_free_port();
        let (ui_gateway, _, _) = make_recorder();
        let ui_message_sub = subs(ui_gateway);
        let system = System::new("send_msg_tries_to_send_message_and_panics_on_flush");
        let lazy_future = lazy(move || {
            let subject = WebSocketSupervisorReal::new(port, ui_message_sub).unwrap();
            let mock_client = ClientWrapperMock::new()
                .send_result(Ok(()))
                .flush_result(Err(WebSocketError::NoDataAvailable));
            let correspondent = MessageTarget::ClientId(subject.inject_mock_client(mock_client));
            let msg = NodeToUiMessage {
                target: correspondent,
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
            "WARN: WebSocketSupervisor: Client 0 dropped its connection before it could be flushed",
        );
    }

    #[test]
    fn send_msg_tries_to_send_message_and_fails_and_logs() {
        init_test_logging();
        let port = find_free_port();
        let (ui_gateway, _, _) = make_recorder();
        let ui_message_sub = subs(ui_gateway);
        let system = System::new("send_msg_tries_to_send_message_and_panics");
        let lazy_future = lazy(move || {
            let subject = WebSocketSupervisorReal::new(port, ui_message_sub).unwrap();
            let mock_client =
                ClientWrapperMock::new().send_result(Err(WebSocketError::NoDataAvailable));
            let msg = NodeToUiMessage {
                target: MessageTarget::ClientId(subject.inject_mock_client(mock_client)),
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
            "ERROR: WebSocketSupervisor: Error sending to client 0: NoDataAvailable",
        );
    }

    #[test]
    #[should_panic(expected = "Tried to send to a nonexistent client")]
    fn send_msg_fails_to_look_up_client_to_send_to() {
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
    }
}
