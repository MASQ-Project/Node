// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use async_channel::Receiver as WSReceiver;
use masq_lib::ui_gateway::MessageBody;
use masq_lib::ui_traffic_converter::UiTrafficConverter;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::task::JoinHandle;
use workflow_websocket::client::Message;

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ClientListenerError {
    Closed,
    Broken(String),
    Timeout,
    UnexpectedPacket,
}

impl ClientListenerError {
    pub fn is_fatal(&self) -> bool {
        match self {
            ClientListenerError::Closed => true,
            ClientListenerError::Broken(_) => true,
            ClientListenerError::Timeout => true,
            ClientListenerError::UnexpectedPacket => false,
        }
    }
}

pub struct ClientListener {
    signal_opt: Arc<tokio::sync::Mutex<Option<JoinHandle<()>>>>,
}

impl ClientListener {
    pub fn new() -> Self {
        Self {
            signal_opt: Arc::new(tokio::sync::Mutex::new(None)),
        }
    }

    pub async fn start(
        &self,
        listener_half: WSReceiver<Message>,
        is_closing: Arc<AtomicBool>,
        message_body_tx: tokio::sync::mpsc::UnboundedSender<
            Result<MessageBody, ClientListenerError>,
        >,
    ) {
        let thread =
            ClientListenerEventLoopStarter::new(listener_half, message_body_tx, is_closing);
        self.signal_opt.lock().await.replace(thread.spawn());
    }

    //TODO is it necessary to use these hacks in tests?
    #[cfg(test)]
    pub async fn is_running(&self) -> bool {
        let mut handle_opt_guard = self.signal_opt.lock().await;
        match handle_opt_guard.take() {
            Some(join_handle) => !join_handle.is_finished(),
            None => false,
        }
    }
}

struct ClientListenerEventLoopStarter {
    listener_half: WSReceiver<Message>,
    message_body_tx: tokio::sync::mpsc::UnboundedSender<Result<MessageBody, ClientListenerError>>,
    is_closing: Arc<AtomicBool>,
}

impl ClientListenerEventLoopStarter {
    pub fn new(
        listener_half: WSReceiver<Message>,
        message_body_tx: tokio::sync::mpsc::UnboundedSender<
            Result<MessageBody, ClientListenerError>,
        >,
        is_closing: Arc<AtomicBool>,
    ) -> Self {
        Self {
            listener_half,
            message_body_tx,
            is_closing,
        }
    }

    pub fn spawn(self) -> JoinHandle<()> {
        let future = async move {
            loop {
                match (
                    self.listener_half.recv().await,
                    self.is_closing.load(Ordering::Relaxed),
                ) {
                    (_, true) => todo!(),
                    (Ok(Message::Text(string)), _) => {
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
                    (Ok(Message::Close), _) => {
                        let _ = self.message_body_tx.send(Err(ClientListenerError::Closed));
                        break;
                    }
                    (Ok(_unexpected), _) => match self
                        .message_body_tx
                        .send(Err(ClientListenerError::UnexpectedPacket))
                    {
                        Ok(_) => (),
                        Err(_) => break,
                    },
                    (Err(error), _) => {
                        let _ = self
                            .message_body_tx
                            .send(Err(ClientListenerError::Broken(format!("{:?}", error))));
                        break;
                    }
                }
            }
        };
        // TODO maybe you want to use the handle in place of the single-message channel to detect
        // that thread is dead
        tokio::spawn(future)
        // thread::spawn(move || {
        //     loop {
        //         match self
        //             .listener_half
        //             .recv_message(&mut self.listener_half.stream)
        //         {
        //             Ok(OwnedMessage::Text(string)) => {
        //                 match UiTrafficConverter::new_unmarshal(&string) {
        //                     Ok(body) => match self.message_body_tx.send(Ok(body.clone())) {
        //                         Ok(_) => (),
        //                         Err(_) => break,
        //                     },
        //                     Err(_) => match self
        //                         .message_body_tx
        //                         .send(Err(ClientListenerError::UnexpectedPacket))
        //                     {
        //                         Ok(_) => (),
        //                         Err(_) => break,
        //                     },
        //                 }
        //             }
        //             Ok(OwnedMessage::Close(_)) => {
        //                 let _ = self.message_body_tx.send(Err(ClientListenerError::Closed));
        //                 break;
        //             }
        //             Ok(_unexpected) => match self
        //                 .message_body_tx
        //                 .send(Err(ClientListenerError::UnexpectedPacket))
        //             {
        //                 Ok(_) => (),
        //                 Err(_) => break,
        //             },
        //             Err(error) => {
        //                 let _ = self
        //                     .message_body_tx
        //                     .send(Err(ClientListenerError::Broken(format!("{:?}", error))));
        //                 break;
        //             }
        //         }
        //     }
        //     let _ = tx.send(());
        // });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::client_utils::WSTestClient;
    use masq_lib::messages::ToMessageBody;
    use masq_lib::messages::{UiShutdownRequest, UiShutdownResponse};
    use masq_lib::test_utils::mock_websockets_server::MockWebSocketsServer;
    use masq_lib::test_utils::utils::make_multi_thread_rt;
    use masq_lib::utils::find_free_port;
    use std::time::Duration;
    use tokio::sync::mpsc::unbounded_channel;
    use workflow_websocket::client::Message as ClientMessage;
    use workflow_websocket::server::Message as ServerMessage;

    #[tokio::test]
    async fn listens_and_passes_data_through() {
        let expected_message = UiShutdownResponse {};
        let port = find_free_port();
        // let rt = make_multi_thread_rt();
        let server =
            MockWebSocketsServer::new(port).queue_response(expected_message.clone().tmb(1));
        let stop_handle = server.start().await;
        let client = WSTestClient::new(port);
        let (listener_half, talker_half) = client.split();
        let (message_body_tx, mut message_body_rx) = unbounded_channel();
        let subject = ClientListener::new();
        subject
            .start(
                listener_half,
                Arc::new(AtomicBool::new(false)),
                message_body_tx,
            )
            .await;
        let message =
            ClientMessage::Text(UiTrafficConverter::new_marshal(UiShutdownRequest {}.tmb(1)));

        let message_body: MessageBody = async {
            talker_half.send((message, None)).await.unwrap();
            message_body_rx.recv().await.unwrap().unwrap()
        }
        .await;

        assert_eq!(message_body, expected_message.tmb(1));
        let is_running = subject.is_running().await;
        assert_eq!(is_running, true);
        let _ = stop_handle.stop();
        wait_for_stop(&subject).await;
        let is_running = subject.is_running().await;
        assert_eq!(is_running, false);
    }

    #[tokio::test]
    async fn processes_incoming_close_correctly() {
        let port = find_free_port();
        let server = MockWebSocketsServer::new(port)
            .queue_string("close")
            .queue_string("disconnect");
        let stop_handle = server.start().await;
        let client = WSTestClient::new(port);
        let (listener_half, talker_half) = client.split();
        let (message_body_tx, mut message_body_rx) = unbounded_channel();
        let subject = ClientListener::new();
        subject
            .start(
                listener_half,
                Arc::new(AtomicBool::new(false)),
                message_body_tx,
            )
            .await;
        let message =
            ClientMessage::Text(UiTrafficConverter::new_marshal(UiShutdownRequest {}.tmb(1)));

        talker_half.send((message, None)).await.unwrap();
        let error = message_body_rx.recv().await.unwrap().err().unwrap();

        assert_eq!(error, ClientListenerError::Closed);
        wait_for_stop(&subject).await;
        let is_running = subject.is_running().await;
        assert_eq!(is_running, false);
        let _ = stop_handle.stop();
    }

    #[tokio::test]
    async fn processes_broken_connection_correctly() {
        let port = find_free_port();
        let server = MockWebSocketsServer::new(port).queue_string("disconnect");
        let stop_handle = server.start().await;
        let client = WSTestClient::new(port);
        let (listener_half, talker_half) = client.split();
        let (message_body_tx, mut message_body_rx) = unbounded_channel();
        let subject = ClientListener::new();
        subject
            .start(
                listener_half,
                Arc::new(AtomicBool::new(false)),
                message_body_tx,
            )
            .await;
        let message =
            ClientMessage::Text(UiTrafficConverter::new_marshal(UiShutdownRequest {}.tmb(1)));

        talker_half.send((message, None)).await.unwrap();
        let error = message_body_rx.recv().await.unwrap().err().unwrap();

        assert_eq!(
            error,
            ClientListenerError::Broken("NoDataAvailable".to_string())
        );
        wait_for_stop(&subject).await;
        let is_running = subject.is_running().await;
        assert_eq!(is_running, false);
        let _ = stop_handle.stop();
    }

    #[tokio::test]
    async fn processes_bad_owned_message_correctly() {
        let port = find_free_port();
        let server =
            MockWebSocketsServer::new(port).queue_owned_message(ServerMessage::Binary(vec![]));
        let stop_handle = server.start().await;
        let client = WSTestClient::new(port);
        let (listener_half, mut talker_half) = client.split();
        let (message_body_tx, mut message_body_rx) = unbounded_channel();
        let subject = ClientListener::new();
        subject
            .start(
                listener_half,
                Arc::new(AtomicBool::new(false)),
                message_body_tx,
            )
            .await;
        let message = Message::Text(UiTrafficConverter::new_marshal(UiShutdownRequest {}.tmb(1)));

        talker_half.send((message, None)).await.unwrap();
        let error = message_body_rx.recv().await.unwrap().err().unwrap();

        assert_eq!(error, ClientListenerError::UnexpectedPacket);
        let is_running = subject.is_running().await;
        assert_eq!(is_running, true);
        let _ = stop_handle.stop();
        wait_for_stop(&subject).await;
        let is_running = subject.is_running().await;
        assert_eq!(is_running, false);
    }

    #[tokio::test]
    async fn processes_bad_packet_correctly() {
        let port = find_free_port();
        let server = MockWebSocketsServer::new(port).queue_string("booga");
        let stop_handle = server.start().await;
        let client = WSTestClient::new(port);
        let (listener_half, talker_half) = client.split();
        let (message_body_tx, mut message_body_rx) = unbounded_channel();
        let subject = ClientListener::new();
        subject
            .start(
                listener_half,
                Arc::new(AtomicBool::new(false)),
                message_body_tx,
            )
            .await;

        let message = Message::Text(UiTrafficConverter::new_marshal(UiShutdownRequest {}.tmb(1)));

        talker_half.send((message, None)).await.unwrap();
        let error = message_body_rx.recv().await.unwrap().err().unwrap();

        assert_eq!(error, ClientListenerError::UnexpectedPacket);
        let is_running = subject.is_running().await;
        assert_eq!(is_running, true);
        let _ = stop_handle.stop();
        wait_for_stop(&subject).await;
        let is_running = subject.is_running().await;
        assert_eq!(is_running, false);
    }

    #[test]
    fn client_listener_errors_know_their_own_fatality() {
        assert_eq!(ClientListenerError::Closed.is_fatal(), true);
        assert_eq!(ClientListenerError::Broken("".to_string()).is_fatal(), true);
        assert_eq!(ClientListenerError::Timeout.is_fatal(), true);
        assert_eq!(ClientListenerError::UnexpectedPacket.is_fatal(), false);
    }

    async fn wait_for_stop(listener: &ClientListener) {
        let mut retries = 10;
        while retries > 0 {
            retries -= 1;
            if !listener.is_running().await {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("ClientListener was supposed to stop but didn't");
    }
}
