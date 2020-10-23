// Copyright (c) 2019-2020, MASQ (https://masq.ai). All rights reserved.

use crossbeam_channel::{unbounded, Receiver, Sender};
use masq_lib::ui_gateway::MessageBody;
use masq_lib::ui_traffic_converter::UiTrafficConverter;
use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use std::thread;
use websocket::receiver::Reader;
use websocket::ws::receiver::Receiver as WsReceiver;
use websocket::OwnedMessage;

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum ClientListenerError {
    Closed,
    Broken,
    Timeout,
    UnexpectedPacket,
}

impl ClientListenerError {
    pub fn is_fatal(self) -> bool {
        match self {
            ClientListenerError::Closed => true,
            ClientListenerError::Broken => true,
            ClientListenerError::Timeout => true,
            ClientListenerError::UnexpectedPacket => false,
        }
    }
}

pub struct ClientListener {
    signal_opt: Arc<Mutex<Option<Receiver<()>>>>,
}

impl ClientListener {
    pub fn new() -> Self {
        Self {
            signal_opt: Arc::new(Mutex::new(None)),
        }
    }

    pub fn start(
        &self,
        listener_half: Reader<TcpStream>,
        message_body_tx: Sender<Result<MessageBody, ClientListenerError>>,
    ) {
        let thread = ClientListenerThread::new(listener_half, message_body_tx);
        self.signal_opt
            .lock()
            .expect("ClientListener thread handle poisoned")
            .replace(thread.start());
    }

    #[allow(dead_code)]
    pub fn is_running(&self) -> bool {
        let mut handle_opt_guard = self
            .signal_opt
            .lock()
            .expect("ClientListener thread handle poisoned");
        match handle_opt_guard.take() {
            Some(receiver) => match receiver.try_recv() {
                Ok(_) => false, // don't put it back; leave signal_out as None
                Err(_) => {
                    handle_opt_guard.replace(receiver);
                    true
                }
            },
            None => false,
        }
    }
}

struct ClientListenerThread {
    listener_half: Reader<TcpStream>,
    message_body_tx: Sender<Result<MessageBody, ClientListenerError>>,
}

impl ClientListenerThread {
    pub fn new(
        listener_half: Reader<TcpStream>,
        message_body_tx: Sender<Result<MessageBody, ClientListenerError>>,
    ) -> Self {
        Self {
            listener_half,
            message_body_tx,
        }
    }

    pub fn start(mut self) -> Receiver<()> {
        let (tx, rx) = unbounded();
        thread::spawn(move || {
            loop {
                match self
                    .listener_half
                    .receiver
                    .recv_message(&mut self.listener_half.stream)
                {
                    Ok(OwnedMessage::Text(string)) => {
                        match UiTrafficConverter::new_unmarshal(&string) {
                            Ok(body) => match self.message_body_tx.send(Ok(body.clone())) {
                                Ok(_) => (),
                                Err(_) => break,
                            },
                            Err(_) => match self
                                .message_body_tx
                                .send(Err(ClientListenerError::UnexpectedPacket))
                            {
                                Ok(_) => (),
                                Err(_) => break,
                            },
                        }
                    }
                    Ok(OwnedMessage::Close(_)) => {
                        let _ = self.message_body_tx.send(Err(ClientListenerError::Closed));
                        break;
                    }
                    Ok(_unexpected) => match self
                        .message_body_tx
                        .send(Err(ClientListenerError::UnexpectedPacket))
                    {
                        Ok(_) => (),
                        Err(_) => break,
                    },
                    Err(_error) => {
                        let _ = self.message_body_tx.send(Err(ClientListenerError::Broken));
                        break;
                    }
                }
            }
            let _ = tx.send(());
        });
        rx
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::client_utils::make_client;
    use crossbeam_channel::unbounded;
    use masq_lib::messages::ToMessageBody;
    use masq_lib::messages::{UiShutdownRequest, UiShutdownResponse};
    use masq_lib::test_utils::mock_websockets_server::MockWebSocketsServer;
    use masq_lib::utils::find_free_port;
    use std::time::Duration;
    use websocket::ws::sender::Sender;

    #[test]
    fn listens_and_passes_data_through() {
        let expected_message = UiShutdownResponse {};
        let port = find_free_port();
        let server =
            MockWebSocketsServer::new(port).queue_response(expected_message.clone().tmb(1));
        let stop_handle = server.start();
        let client = make_client(port);
        let (listener_half, mut talker_half) = client.split().unwrap();
        let (message_body_tx, message_body_rx) = unbounded();
        let subject = ClientListener::new();
        subject.start(listener_half, message_body_tx);
        let message =
            OwnedMessage::Text(UiTrafficConverter::new_marshal(UiShutdownRequest {}.tmb(1)));

        talker_half
            .sender
            .send_message(&mut talker_half.stream, &message)
            .unwrap();

        let message_body = message_body_rx.recv().unwrap().unwrap();
        assert_eq!(message_body, expected_message.tmb(1));
        assert_eq!(subject.is_running(), true);
        let _ = stop_handle.stop();
        wait_for_stop(&subject);
        assert_eq!(subject.is_running(), false);
    }

    #[test]
    fn processes_incoming_close_correctly() {
        let port = find_free_port();
        let server = MockWebSocketsServer::new(port)
            .queue_string("close")
            .queue_string("disconnect");
        let stop_handle = server.start();
        let client = make_client(port);
        let (listener_half, mut talker_half) = client.split().unwrap();
        let (message_body_tx, message_body_rx) = unbounded();
        let subject = ClientListener::new();
        subject.start(listener_half, message_body_tx);
        let message =
            OwnedMessage::Text(UiTrafficConverter::new_marshal(UiShutdownRequest {}.tmb(1)));

        talker_half
            .sender
            .send_message(&mut talker_half.stream, &message)
            .unwrap();

        let error = message_body_rx.recv().unwrap().err().unwrap();
        assert_eq!(error, ClientListenerError::Closed);
        wait_for_stop(&subject);
        assert_eq!(subject.is_running(), false);
        let _ = stop_handle.stop();
    }

    #[test]
    fn processes_broken_connection_correctly() {
        let port = find_free_port();
        let server = MockWebSocketsServer::new(port).queue_string("disconnect");
        let stop_handle = server.start();
        let client = make_client(port);
        let (listener_half, mut talker_half) = client.split().unwrap();
        let (message_body_tx, message_body_rx) = unbounded();
        let subject = ClientListener::new();
        subject.start(listener_half, message_body_tx);
        let message =
            OwnedMessage::Text(UiTrafficConverter::new_marshal(UiShutdownRequest {}.tmb(1)));

        talker_half
            .sender
            .send_message(&mut talker_half.stream, &message)
            .unwrap();

        let error = message_body_rx.recv().unwrap().err().unwrap();
        assert_eq!(error, ClientListenerError::Broken);
        wait_for_stop(&subject);
        assert_eq!(subject.is_running(), false);
        let _ = stop_handle.stop();
    }

    #[test]
    fn processes_bad_owned_message_correctly() {
        let port = find_free_port();
        let server =
            MockWebSocketsServer::new(port).queue_owned_message(OwnedMessage::Binary(vec![]));
        let stop_handle = server.start();
        let client = make_client(port);
        let (listener_half, mut talker_half) = client.split().unwrap();
        let (message_body_tx, message_body_rx) = unbounded();
        let subject = ClientListener::new();
        subject.start(listener_half, message_body_tx);
        let message =
            OwnedMessage::Text(UiTrafficConverter::new_marshal(UiShutdownRequest {}.tmb(1)));

        talker_half
            .sender
            .send_message(&mut talker_half.stream, &message)
            .unwrap();

        let error = message_body_rx.recv().unwrap().err().unwrap();
        assert_eq!(error, ClientListenerError::UnexpectedPacket);
        assert_eq!(subject.is_running(), true);
        let _ = stop_handle.stop();
        wait_for_stop(&subject);
        assert_eq!(subject.is_running(), false);
    }

    #[test]
    fn processes_bad_packet_correctly() {
        let port = find_free_port();
        let server = MockWebSocketsServer::new(port).queue_string("booga");
        let stop_handle = server.start();
        let client = make_client(port);
        let (listener_half, mut talker_half) = client.split().unwrap();
        let (message_body_tx, message_body_rx) = unbounded();
        let subject = ClientListener::new();
        subject.start(listener_half, message_body_tx);
        let message =
            OwnedMessage::Text(UiTrafficConverter::new_marshal(UiShutdownRequest {}.tmb(1)));

        talker_half
            .sender
            .send_message(&mut talker_half.stream, &message)
            .unwrap();

        let error = message_body_rx.recv().unwrap().err().unwrap();
        assert_eq!(error, ClientListenerError::UnexpectedPacket);
        assert_eq!(subject.is_running(), true);
        let _ = stop_handle.stop();
        wait_for_stop(&subject);
        assert_eq!(subject.is_running(), false);
    }

    #[test]
    fn client_listener_errors_know_their_own_fatality() {
        assert_eq!(ClientListenerError::Closed.is_fatal(), true);
        assert_eq!(ClientListenerError::Broken.is_fatal(), true);
        assert_eq!(ClientListenerError::Timeout.is_fatal(), true);
        assert_eq!(ClientListenerError::UnexpectedPacket.is_fatal(), false);
    }

    fn wait_for_stop(listener: &ClientListener) {
        let mut retries = 10;
        while retries > 0 {
            retries -= 1;
            if !listener.is_running() {
                return;
            }
            thread::sleep(Duration::from_millis(100));
        }
        panic!("ClientListener was supposed to stop but didn't");
    }
}
