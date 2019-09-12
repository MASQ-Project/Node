// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use crate::sub_lib::logger::Logger;
use crate::sub_lib::ui_gateway::FromUiMessage;
use crate::sub_lib::utils::localhost;
use actix::Recipient;
use bytes::BytesMut;
use futures::future::FutureResult;
use futures::future::{err, ok};
use futures::sink::Wait;
use futures::stream::SplitSink;
use futures::Future;
use futures::Sink;
use futures::Stream;
use std::any::Any;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::Mutex;
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
    fn send(&self, client_id: u64, message_json: &str);
}

pub struct WebSocketSupervisorReal {
    #[allow(dead_code)]
    inner: Arc<Mutex<WebSocketSupervisorInner>>,
}

struct WebSocketSupervisorInner {
    next_client_id: u64,
    from_ui_message: Recipient<FromUiMessage>,
    client_id_by_socket_addr: HashMap<SocketAddr, u64>,
    client_by_id: HashMap<u64, Box<dyn ClientWrapper>>,
}

impl WebSocketSupervisor for WebSocketSupervisorReal {
    fn send(&self, client_id: u64, message_json: &str) {
        let mut locked_inner = self.inner.lock().expect("WebSocketSupervisor is poisoned");
        match locked_inner.client_by_id.get_mut(&client_id) {
            Some(client) => match client.send(OwnedMessage::Text(message_json.to_string())) {
                Ok(_) => client.flush().expect("Flush error"),
                Err(e) => panic!("Send error: {:?}", e),
            },
            None => panic!("Tried to send to a nonexistent client"),
        };
    }
}

impl WebSocketSupervisorReal {
    pub fn new(port: u16, from_ui_message: Recipient<FromUiMessage>) -> WebSocketSupervisorReal {
        let inner = Arc::new(Mutex::new(WebSocketSupervisorInner {
            next_client_id: 0,
            from_ui_message,
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
            Ok(_) => Ok(()),
            Err(_) => {
                error!(
                    logger_1,
                    "WebSocketSupervisor experienced unprintable error accepting connection"
                );
                Err(())
            }
        }));
        WebSocketSupervisorReal { inner }
    }

    fn remove_failures<I, E>(
        stream: impl Stream<Item = I, Error = E>,
        logger: &Logger,
    ) -> impl Stream<Item = I, Error = E> {
        let logger_clone = logger.clone();
        stream
            .then(move |result| match result {
                Ok(x) => ok::<Option<I>, E>(Some(x)),
                Err(_) => {
                    info!(logger_clone, "Unsuccessful connection to UI port detected");
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
        if !upgrade
            .protocols()
            .contains(&String::from("SubstratumNode-UI"))
        {
            Self::reject_upgrade_request(upgrade, &logger);
        } else {
            Self::accept_upgrade_request(upgrade, socket_addr, inner, logger);
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
                .use_protocol("SubstratumNode-UI")
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
            "UI attempted connection without protocol SubstratumNode-UI: {:?}",
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
        let mut locked_inner = inner.lock().expect("WebSocketSupervisor is poisoned");
        let client_id = locked_inner.next_client_id;
        locked_inner.next_client_id += 1;
        locked_inner
            .client_id_by_socket_addr
            .insert(socket_addr, client_id);
        locked_inner.client_by_id.insert(
            client_id,
            Box::new(ClientWrapperReal {
                delegate: sync_outgoing,
            }),
        );
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
        let locked_inner = inner_arc.lock().expect("WebSocketSupervisor is poisoned");
        match locked_inner.client_id_by_socket_addr.get(&socket_addr) {
            None => {
                warning!(
                    logger,
                    "WebSocketSupervisor got a message from a client that never connected!"
                );
                err::<(), ()>(()) // end the stream
            }
            Some(client_id_ref) => {
                locked_inner
                    .from_ui_message
                    .try_send(FromUiMessage {
                        client_id: *client_id_ref,
                        json: String::from(message),
                    })
                    .expect("UiGateway is dead");
                ok::<(), ()>(())
            }
        }
    }

    fn handle_close_message(
        inner_arc: &Arc<Mutex<WebSocketSupervisorInner>>,
        logger: &Logger,
        socket_addr: SocketAddr,
    ) -> FutureResult<(), ()> {
        info!(logger, "UI at {} disconnected", socket_addr);
        let mut locked_inner = inner_arc.lock().expect("WebSocketSupervisor is poisoned");
        let client_id = match locked_inner.client_id_by_socket_addr.remove(&socket_addr) {
            None => {
                panic!("WebSocketSupervisor got a disconnect from a client that never connected!")
            }
            Some(client_id) => client_id,
        };
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

    fn handle_websocket_errors<I>(
        result: Result<I, WebSocketError>,
        logger: &Logger,
        socket_addr: SocketAddr,
    ) -> FutureResult<I, ()> {
        match result {
            Err(_e) => {
                warning!(
                    logger,
                    "UI at {} violated protocol: terminating",
                    socket_addr
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
        let client = match locked_inner.client_by_id.get_mut(&client_id) {
            None => panic!("WebSocketSupervisor got a disconnect from a client that has disappeared from the stable!"),
            Some(client) => client,
        };
        match client.send(OwnedMessage::Close(None)) {
            Err(e) => warning!(
                logger,
                "Error acknowledging connection closure from UI at {}: {:?}",
                socket_addr,
                e
            ),
            Ok(_) => client
                .flush()
                .unwrap_or_else(|_| panic!("Couldn't flush transmission to UI at {}", socket_addr)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sub_lib::ui_gateway::{FromUiMessage, UiMessage};
    use crate::test_utils::find_free_port;
    use crate::test_utils::logging::init_test_logging;
    use crate::test_utils::logging::TestLogHandler;
    use crate::test_utils::recorder::make_recorder;
    use crate::test_utils::recorder::Recorder;
    use crate::test_utils::wait_for;
    use crate::ui_gateway::ui_traffic_converter::{UiTrafficConverter, UiTrafficConverterReal};
    use actix::Actor;
    use actix::Addr;
    use actix::System;
    use futures::future::lazy;
    use std::collections::HashSet;
    use std::net::Shutdown;
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
            let mock_client_box = locked_inner
                .client_by_id
                .get(&client_id)
                .expect(&format!("Did not find mock client for id: {}", client_id));
            let any = mock_client_box.as_any();
            let result = any
                .downcast_ref::<ClientWrapperMock>()
                .expect("couldn't downcast");
            result.clone()
        }
    }

    struct ClientWrapperMock {
        send_params: Arc<Mutex<Vec<OwnedMessage>>>,
        send_results: Vec<Result<(), WebSocketError>>,
        flush_results: Vec<Result<(), WebSocketError>>,
    }

    impl Clone for ClientWrapperMock {
        fn clone(&self) -> Self {
            ClientWrapperMock {
                send_params: self.send_params.clone(),
                send_results: self
                    .send_results
                    .iter()
                    .map(|result| match result {
                        Ok(()) => Ok(()),
                        Err(_) => Err(WebSocketError::NoDataAvailable),
                    })
                    .collect::<Vec<Result<(), WebSocketError>>>(),
                flush_results: self
                    .flush_results
                    .iter()
                    .map(|result| match result {
                        Ok(()) => Ok(()),
                        Err(_) => Err(WebSocketError::NoDataAvailable),
                    })
                    .collect::<Vec<Result<(), WebSocketError>>>(),
            }
        }
    }

    impl ClientWrapperMock {
        fn new() -> ClientWrapperMock {
            ClientWrapperMock {
                send_params: Arc::new(Mutex::new(vec![])),
                send_results: vec![],
                flush_results: vec![],
            }
        }
    }

    impl ClientWrapper for ClientWrapperMock {
        fn as_any(&self) -> &dyn Any {
            self
        }

        fn send(&mut self, item: OwnedMessage) -> Result<(), WebSocketError> {
            self.send_params.lock().unwrap().push(item);
            if self.send_results.is_empty() {
                panic!("WaitWrapperMock: send_results is empty")
            }
            self.send_results.remove(0)
        }

        fn flush(&mut self) -> Result<(), WebSocketError> {
            if self.flush_results.is_empty() {
                panic!("WaitWrapperMock: flush_results is empty")
            }
            self.flush_results.remove(0)
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

    #[test]
    fn logs_pre_upgrade_connection_errors() {
        init_test_logging();
        let port = find_free_port();
        let (ui_gateway, _, _) = make_recorder();

        thread::spawn(move || {
            let system = System::new("logs_pre_upgrade_connection_errors");
            let from_ui_message = {
                let addr: Addr<Recorder> = ui_gateway.start();
                addr.recipient::<FromUiMessage>()
            };
            let subject = lazy(move || {
                let _subject = WebSocketSupervisorReal::new(port, from_ui_message);
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
            let from_ui_message = {
                let addr: Addr<Recorder> = ui_gateway.start();
                addr.recipient::<FromUiMessage>()
            };
            let subject = lazy(move || {
                let _subject = WebSocketSupervisorReal::new(port, from_ui_message);
                Ok(())
            });
            actix::spawn(subject);
            system.run();
        });
        wait_for_server(port);

        make_client(port, "bad-protocol").err().unwrap();

        let tlh = TestLogHandler::new();
        tlh.await_log_containing(
            "UI attempted connection without protocol SubstratumNode-UI: [\"bad-protocol\"]",
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
            let from_ui_message = {
                let addr: Addr<Recorder> = ui_gateway.start();
                addr.recipient::<FromUiMessage>()
            };
            let subject = lazy(move || {
                let _subject = WebSocketSupervisorReal::new(port, from_ui_message);
                Ok(())
            });
            actix::spawn(subject);
            system.run();
        });

        let mut client = wait_for_client(port, "SubstratumNode-UI");

        client
            .send_message(&Message::binary(vec![1u8, 2u8, 3u8, 4u8]))
            .unwrap();
        client
            .send_message(&Message::ping(vec![1u8, 2u8, 3u8, 4u8]))
            .unwrap();
        client
            .send_message(&Message::pong(vec![1u8, 2u8, 3u8, 4u8]))
            .unwrap();
        client.shutdown().unwrap();

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
            let from_ui_message = {
                let addr: Addr<Recorder> = ui_gateway.start();
                addr.recipient::<FromUiMessage>()
            };
            let subject = lazy(move || {
                let _subject = WebSocketSupervisorReal::new(port, from_ui_message);
                Ok(())
            });
            actix::spawn(subject);
            system.run();
        });

        let mut one_client = wait_for_client(port, "SubstratumNode-UI");
        let mut another_client = make_client(port, "SubstratumNode-UI").unwrap();

        one_client.send_message(&Message::text("One")).unwrap();
        another_client
            .send_message(&Message::text("Another"))
            .unwrap();
        one_client.send_message(&Message::text("A third")).unwrap();

        one_client.send_message(&OwnedMessage::Close(None)).unwrap();
        let one_close_msg = one_client.recv_message().unwrap();
        another_client
            .send_message(&OwnedMessage::Close(None))
            .unwrap();
        let another_close_msg = another_client.recv_message().unwrap();

        ui_gateway_awaiter.await_message_count(3);
        let ui_gateway_recording = ui_gateway_recording_arc.lock().unwrap();
        let jsons = vec![0, 1, 2]
            .into_iter()
            .map(|i| {
                ui_gateway_recording
                    .get_record::<FromUiMessage>(i)
                    .json
                    .clone()
            })
            .collect::<HashSet<String>>();
        assert_eq!(
            jsons,
            vec![
                String::from("One"),
                String::from("Another"),
                String::from("A third")
            ]
            .into_iter()
            .collect::<HashSet<String>>()
        );
        assert_eq!(one_close_msg, OwnedMessage::Close(None));
        assert_eq!(another_close_msg, OwnedMessage::Close(None));
    }

    #[test]
    fn client_dot_graph_request_is_forwarded_to_ui_gateway() {
        let port = find_free_port();
        let (ui_gateway, ui_gateway_awaiter, ui_gateway_recording_arc) = make_recorder();

        thread::spawn(move || {
            let system = System::new("client_dot_graph_request_is_forwarded_to_ui_gateway");
            let from_ui_message = {
                let addr: Addr<Recorder> = ui_gateway.start();
                addr.recipient::<FromUiMessage>()
            };
            let subject = lazy(move || {
                let _subject = WebSocketSupervisorReal::new(port, from_ui_message);
                Ok(())
            });
            actix::spawn(subject);
            system.run();
        });

        let mut client = wait_for_client(port, "SubstratumNode-UI");

        let neighborhood_dot_graph_request =
            serde_json::to_string(&UiMessage::NeighborhoodDotGraphRequest).unwrap();
        client
            .send_message(&Message::text(neighborhood_dot_graph_request))
            .unwrap();
        ui_gateway_awaiter.await_message_count(1);
        let ui_gateway_recording = ui_gateway_recording_arc.lock().unwrap();
        let actual_msg = ui_gateway_recording
            .get_record::<FromUiMessage>(0)
            .json
            .clone();

        assert_eq!(actual_msg, "\"NeighborhoodDotGraphRequest\"");
    }

    #[test]
    fn client_receives_dot_graph_response_from_websocket_supervisor() {
        let port = find_free_port();
        let (ui_gateway, ui_gateway_awaiter, ui_gateway_recording_arc) = make_recorder();

        thread::spawn(move || {
            let system =
                System::new("client_receives_dot_graph_response_from_websocket_supervisor");
            let from_ui_message = {
                let addr: Addr<Recorder> = ui_gateway.start();
                addr.recipient::<FromUiMessage>()
            };
            let subject = lazy(move || {
                let _subject = WebSocketSupervisorReal::new(port, from_ui_message);
                Ok(())
            });
            actix::spawn(subject);
            system.run();
        });

        let mut client = wait_for_client(port, "SubstratumNode-UI");

        let neighborhood_dot_graph_request =
            serde_json::to_string(&UiMessage::NeighborhoodDotGraphRequest).unwrap();
        client
            .send_message(&Message::text(neighborhood_dot_graph_request))
            .unwrap();
        ui_gateway_awaiter.await_message_count(1);
        let ui_gateway_recording = ui_gateway_recording_arc.lock().unwrap();
        let actual_msg = ui_gateway_recording
            .get_record::<FromUiMessage>(0)
            .json
            .clone();

        assert_eq!(actual_msg, "\"NeighborhoodDotGraphRequest\"");
    }

    #[test]
    fn send_dot_graph_response_sends_it_to_the_client() {
        let port = find_free_port();
        let (ui_gateway, _, _) = make_recorder();
        let ui_gateway_recipient = ui_gateway.start().recipient::<FromUiMessage>();
        let system = System::new("send_dot_graph_response_sends_it_to_the_client");
        let mut client_id = 0;
        let lazy_future = lazy(move || {
            let subject = WebSocketSupervisorReal::new(port, ui_gateway_recipient);
            let mut mock_client = ClientWrapperMock::new();
            mock_client.send_results.push(Ok(()));
            mock_client.flush_results.push(Ok(()));
            client_id = subject.inject_mock_client(mock_client);

            let json_string = UiTrafficConverterReal::new()
                .marshal(UiMessage::NeighborhoodDotGraphResponse(String::from(
                    "digraph db { }",
                )))
                .unwrap();

            subject.send(client_id, json_string.as_str());

            let mock_client_ref = subject.get_mock_client(client_id);
            assert_eq!(
                &OwnedMessage::Text(json_string),
                mock_client_ref
                    .send_params
                    .lock()
                    .unwrap()
                    .get(0)
                    .expect("Send was not called")
            );
            Ok(())
        });

        actix::spawn(lazy_future);
        System::current().stop();
        system.run();
    }

    #[test]
    fn once_a_client_sends_a_close_no_more_data_is_accepted() {
        let port = find_free_port();
        let (ui_gateway, ui_gateway_awaiter, ui_gateway_recording_arc) = make_recorder();

        thread::spawn(move || {
            let system = System::new("once_a_client_sends_a_close_no_more_data_is_accepted");
            let from_ui_message = {
                let addr: Addr<Recorder> = ui_gateway.start();
                addr.recipient::<FromUiMessage>()
            };
            let subject = lazy(move || {
                let _subject = WebSocketSupervisorReal::new(port, from_ui_message);
                Ok(())
            });
            actix::spawn(subject);
            system.run();
        });

        let mut client = wait_for_client(port, "SubstratumNode-UI");

        client.send_message(&Message::text("One")).unwrap();
        client.send_message(&Message::close()).unwrap();
        client.send_message(&Message::text("Two")).unwrap();

        client.shutdown().unwrap();
        thread::sleep(Duration::from_secs(1));
        ui_gateway_awaiter.await_message_count(1);
        let ui_gateway_recording = ui_gateway_recording_arc.lock().unwrap();
        assert_eq!(
            ui_gateway_recording.get_record::<FromUiMessage>(0),
            &FromUiMessage {
                client_id: 0,
                json: String::from("One")
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
            let from_ui_message = {
                let addr: Addr<Recorder> = ui_gateway.start();
                addr.recipient::<FromUiMessage>()
            };
            let subject = lazy(move || {
                let _subject = WebSocketSupervisorReal::new(port, from_ui_message);
                Ok(())
            });
            actix::spawn(subject);
            system.run();
        });
        let mut client = wait_for_client(port, "SubstratumNode-UI");
        client.send_message(&Message::text("One")).unwrap();

        {
            let writer = client.writer_mut();
            writer.write(b"Booga!").unwrap();
        }

        client.send_message(&Message::text("Two")).unwrap();
        thread::sleep(Duration::from_secs(1));
        ui_gateway_awaiter.await_message_count(1);
        let ui_gateway_recording = ui_gateway_recording_arc.lock().unwrap();
        assert_eq!(
            ui_gateway_recording.get_record::<FromUiMessage>(0),
            &FromUiMessage {
                client_id: 0,
                json: String::from("One")
            }
        );
        assert_eq!(ui_gateway_recording.len(), 1);
    }

    #[test]
    fn send_sends_a_message_to_the_client() {
        let port = find_free_port();
        let (ui_gateway, _, _) = make_recorder();
        let ui_gateway_recipient = ui_gateway.start().recipient::<FromUiMessage>();
        let system = System::new("send_sends_a_message_to_the_client");
        let mut client_id = 0;
        let lazy_future = lazy(move || {
            let subject = WebSocketSupervisorReal::new(port, ui_gateway_recipient);
            let mut mock_client = ClientWrapperMock::new();
            mock_client.send_results.push(Ok(()));
            mock_client.flush_results.push(Ok(()));
            client_id = subject.inject_mock_client(mock_client);

            let json_string = "{totally: 'valid'}";

            subject.send(client_id, json_string);

            let mock_client_ref = subject.get_mock_client(client_id);
            assert_eq!(
                &OwnedMessage::Text(String::from(json_string)),
                mock_client_ref
                    .send_params
                    .lock()
                    .unwrap()
                    .get(0)
                    .expect("Send was not called")
            );
            Ok(())
        });
        actix::spawn(lazy_future);
        System::current().stop();
        system.run();
    }

    #[test]
    #[should_panic(expected = "Flush error: NoDataAvailable")]
    fn send_tries_to_send_message_and_panics_on_flush() {
        let port = find_free_port();
        let (ui_gateway, _, _) = make_recorder();
        let ui_gateway_recipient = ui_gateway.start().recipient::<FromUiMessage>();
        let system = System::new("receive_sends_a_message_and_errors_on_flush");
        let mut client_id = 0;
        let lazy_future = lazy(move || {
            let subject = WebSocketSupervisorReal::new(port, ui_gateway_recipient);
            let mut mock_client = ClientWrapperMock::new();
            mock_client.send_results.push(Ok(()));
            mock_client
                .flush_results
                .push(Err(WebSocketError::NoDataAvailable));
            client_id = subject.inject_mock_client(mock_client);

            let json_string = "{totally: 'valid'}";

            subject.send(client_id, json_string);
            Ok(())
        });
        actix::spawn(lazy_future);
        System::current().stop();
        system.run();
    }

    #[test]
    #[should_panic(expected = "Send error: NoDataAvailable")]
    fn send_tries_to_send_message_and_panics() {
        let port = find_free_port();
        let (ui_gateway, _, _) = make_recorder();
        let ui_gateway_recipient = ui_gateway.start().recipient::<FromUiMessage>();
        let system = System::new("receive_sends_a_message_and_errors_on_send");
        let mut client_id = 0;
        let lazy_future = lazy(move || {
            let subject = WebSocketSupervisorReal::new(port, ui_gateway_recipient);
            let mut mock_client = ClientWrapperMock::new();
            mock_client
                .send_results
                .push(Err(WebSocketError::NoDataAvailable));
            client_id = subject.inject_mock_client(mock_client);

            let json_string = "{totally: 'valid'}";

            subject.send(client_id, json_string);
            Ok(())
        });
        actix::spawn(lazy_future);
        System::current().stop();
        system.run();
    }

    #[test]
    #[should_panic(expected = "Tried to send to a nonexistent client")]
    fn send_fails_to_look_up_client_to_send_to() {
        let port = find_free_port();
        let (ui_gateway, _, _) = make_recorder();
        let ui_gateway_recipient = ui_gateway.start().recipient::<FromUiMessage>();
        let system = System::new("receive_sends_a_message_and_errors_on_send");
        let lazy_future = lazy(move || {
            let subject = WebSocketSupervisorReal::new(port, ui_gateway_recipient);

            let json_string = "{totally: 'valid'}";

            subject.send(7, json_string);
            Ok(())
        });
        actix::spawn(lazy_future);
        System::current().stop();
        system.run();
    }
}
