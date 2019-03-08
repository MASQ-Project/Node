// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use crate::sub_lib::logger::Logger;
use crate::sub_lib::ui_gateway::FromUiMessage;
use actix::Recipient;
use bytes::BytesMut;
use futures::future::FutureResult;
use futures::future::{err, ok};
use futures::sink::Wait;
use futures::stream::SplitSink;
use futures::Future;
use futures::Sink;
use futures::Stream;
use std::collections::HashMap;
use std::net::IpAddr;
use std::net::Ipv4Addr;
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

pub trait WebSocketSupervisor {
    fn receive(&self, client_id: u64, message_json: &str);
}

pub struct WebSocketSupervisorReal {
    #[allow(dead_code)]
    inner: Arc<Mutex<WebSocketSupervisorInner>>,
}

impl WebSocketSupervisor for WebSocketSupervisorReal {
    fn receive(&self, _client_id: u64, _message_json: &str) {
        unimplemented!()
    }
}

struct WebSocketSupervisorInner {
    next_client_id: u64,
    from_ui_message: Recipient<FromUiMessage>,
    client_id_by_socket_addr: HashMap<SocketAddr, u64>,
    client_by_id: HashMap<u64, Wait<SplitSink<Framed<TcpStream, MessageCodec<OwnedMessage>>>>>,
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
        let server_address = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port);
        let server = Server::bind(server_address, &Handle::default())
            .expect(format!("Could not start UI server at {}", server_address).as_str());
        let upgrade_tuple_stream = Self::remove_failures(server.incoming(), &logger);
        let inner_clone = inner.clone();
        let foreach_result = upgrade_tuple_stream.for_each(move |(upgrade, socket_addr)| {
            Self::handle_upgrade_request(upgrade, socket_addr, inner_clone.clone(), &logger);
            Ok(())
        });
        tokio::spawn(foreach_result.then(move |result| match result {
            Ok(_) => Ok(()),
            Err(_) => {
                logger_1.error(
                    "WebSocketSupervisor experienced unprintable error accepting connection"
                        .to_string(),
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
                    logger_clone.info("Unsuccessful connection to UI port detected".to_string());
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
        logger_clone.info(format!("UI connected at {}", socket_addr));
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
        logger.info(format!(
            "UI attempted connection without protocol SubstratumNode-UI: {:?}",
            upgrade.protocols()
        ));
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
        locked_inner.client_by_id.insert(client_id, sync_outgoing);
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
                logger.warning(
                    "WebSocketSupervisor got a message from a client that never connected!"
                        .to_string(),
                );
                err::<(), ()>(()) // end the stream
            }
            Some(_client_id_ref) => {
                locked_inner
                    .from_ui_message
                    .try_send(FromUiMessage {
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
        logger.info(format!("UI at {} disconnected", socket_addr));
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
        logger.info(format!(
            "UI at {} sent unexpected {} message; ignoring",
            socket_addr, message_type
        ));
        ok::<(), ()>(())
    }

    fn handle_websocket_errors<I>(
        result: Result<I, WebSocketError>,
        logger: &Logger,
        socket_addr: SocketAddr,
    ) -> FutureResult<I, ()> {
        match result {
            Err(_e) => {
                logger.warning(format!(
                    "UI at {} violated protocol: terminating",
                    socket_addr
                ));
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
            Err(e) => logger.warning(format!(
                "Error acknowledging connection closure from UI at {}: {:?}",
                socket_addr, e
            )),
            Ok(_) => client
                .flush()
                .expect(format!("Couldn't flush transmission to UI at {}", socket_addr).as_str()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sub_lib::ui_gateway::FromUiMessage;
    use crate::test_utils::logging::init_test_logging;
    use crate::test_utils::logging::TestLogHandler;
    use crate::test_utils::recorder::make_recorder;
    use crate::test_utils::recorder::Recorder;
    use crate::test_utils::test_utils::find_free_port;
    use crate::test_utils::test_utils::wait_for;
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
            match TcpStream::connect(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                port,
            )) {
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
                json: String::from("One")
            }
        );
        assert_eq!(ui_gateway_recording.len(), 1);
    }
}
