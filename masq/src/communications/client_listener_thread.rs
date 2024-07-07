// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use async_channel::Receiver as WSReceiver;
use masq_lib::ui_gateway::MessageBody;
use masq_lib::ui_traffic_converter::UiTrafficConverter;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::UnboundedSender;
use tokio::task::JoinHandle;
use workflow_websocket::client::{Message, WebSocket};

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
    websocket: WebSocket,
}

impl ClientListener {
    pub fn new(websocket: WebSocket) -> Self {
        Self { websocket }
    }

    pub async fn start(
        self,
        is_closing: Arc<AtomicBool>,
        message_body_tx: UnboundedSender<Result<MessageBody, ClientListenerError>>,
    ) -> WSClientHandle {
        let listener_half = self.websocket.receiver_rx().clone();
        let event_loop = ClientListenerEventLoop::new(listener_half, message_body_tx, is_closing);
        let task_handle = event_loop.spawn();
        WSClientHandle::new(self.websocket, task_handle)
    }
}

pub struct WSClientHandle {
    websocket: WebSocket,
    listening_event_loop_join_handle: JoinHandle<()>,
}

impl Drop for WSClientHandle {
    fn drop(&mut self) {
        self.dismiss_event_loop()
    }
}

impl WSClientHandle {
    pub fn new(websocket: WebSocket, event_loop_join_handle: JoinHandle<()>) -> Self {
        Self {
            websocket,
            listening_event_loop_join_handle: event_loop_join_handle,
        }
    }

    pub async fn send(&self, msg: Message) -> workflow_websocket::client::Result<&WebSocket> {
        self.websocket.post(msg).await
    }

    pub fn close_talker_half(&self) -> bool {
        self.websocket.sender_tx().close()
    }

    pub fn dismiss_event_loop(&self) {
        self.listening_event_loop_join_handle.abort()
    }
}

struct ClientListenerEventLoop {
    listener_half: WSReceiver<Message>,
    message_body_tx: UnboundedSender<Result<MessageBody, ClientListenerError>>,
    is_closing: Arc<AtomicBool>,
}

impl ClientListenerEventLoop {
    pub fn new(
        listener_half: WSReceiver<Message>,
        message_body_tx: UnboundedSender<Result<MessageBody, ClientListenerError>>,
        is_closing: Arc<AtomicBool>,
    ) -> Self {
        Self {
            listener_half,
            message_body_tx,
            is_closing,
        }
    }

    pub fn spawn(self) -> JoinHandle<()> {
        let future = async move { self.loop_guts().await };

        tokio::task::spawn(future)
    }

    async fn loop_guts(self) {
        loop {
            let received_ws_message = self.listener_half.recv().await;
            let is_closing = self.is_closing.load(Ordering::Relaxed);

            match (received_ws_message, is_closing) {
                (_, true) => break,
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
                (Ok(Message::Open), _) => {
                    // Dropping, it doesn't say anything but what we already know
                }
                (Ok(Message::Close), _) => {
                    let _ = self.message_body_tx.send(Err(ClientListenerError::Closed));
                    break;
                }
                (Ok(_unexpected), _) => {
                    match self
                        .message_body_tx
                        .send(Err(ClientListenerError::UnexpectedPacket))
                    {
                        Ok(_) => (),
                        Err(_) => break,
                    }
                }
                (Err(error), _) => {
                    let _ = self
                        .message_body_tx
                        .send(Err(ClientListenerError::Broken(format!("{:?}", error))));
                    break;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::mocks::{make_and_connect_websocket, websocket_utils};
    use async_channel::{unbounded, Sender};
    use futures::{FutureExt, TryFutureExt};
    use masq_lib::messages::{
        FromMessageBody, ToMessageBody, UiCheckPasswordResponse, UiDescriptorResponse,
    };
    use masq_lib::messages::{UiShutdownRequest, UiShutdownResponse};
    use masq_lib::test_utils::mock_websockets_server::MockWebSocketsServer;
    use masq_lib::utils::find_free_port;
    use std::time::{Duration, SystemTime};
    use tokio::sync::mpsc::error::TryRecvError;
    use tokio::sync::mpsc::unbounded_channel;
    use tokio::task::JoinError;
    use workflow_websocket::client::{Ack, Message as ClientMessage};
    use workflow_websocket::server::Message as ServerMessage;

    impl WSClientHandle {
        pub fn is_connection_open(&self) -> bool {
            self.websocket.is_open()
        }

        fn is_event_loop_spinning(&self) -> bool {
            !self.listening_event_loop_join_handle.is_finished()
        }
    }

    async fn stimulate_queued_response_from_server(client_talker_half: &Sender<(Message, Ack)>) {
        let message = Message::Text(UiTrafficConverter::new_marshal(
            UiShutdownRequest {}.tmb(345345),
        ));
        client_talker_half.send((message, None)).await.unwrap();
    }

    #[tokio::test]
    async fn listens_and_passes_data_through() {
        let expected_message = UiShutdownResponse {};
        let port = find_free_port();
        let server =
            MockWebSocketsServer::new(port).queue_response(expected_message.clone().tmb(1));
        let stop_handle = server.start().await;
        let websocket = make_and_connect_websocket(port);
        let (websocket, talker_half, _) = websocket_utils(port).await;
        let (message_body_tx, mut message_body_rx) = unbounded_channel();
        let mut subject = ClientListener::new(websocket);
        let client_listener_handle = subject
            .start(Arc::new(AtomicBool::new(false)), message_body_tx)
            .await;
        stimulate_queued_response_from_server(client_listener_handle.websocket.sender_tx()).await;

        let message_body = message_body_rx.recv().await.unwrap().unwrap();

        assert_eq!(message_body, expected_message.tmb(1));
        let is_spinning = client_listener_handle.is_event_loop_spinning();
        assert_eq!(is_spinning, true);
        let _ = stop_handle.stop(None,None).await;
        wait_for_stop(&client_listener_handle).await;
        let is_spinning = client_listener_handle.is_event_loop_spinning();
        assert_eq!(is_spinning, false);
    }

    #[tokio::test]
    async fn processes_incoming_close_correctly() {
        let port = find_free_port();
        let server = MockWebSocketsServer::new(port)
            .queue_string("close")
            .queue_string("disconnect");
        let stop_handle = server.start().await;
        let (websocket, listener_half, talker_half) = websocket_utils(port).await;
        let (message_body_tx, mut message_body_rx) = unbounded_channel();
        let mut subject = ClientListener::new(websocket);
        let client_listener_handle = subject
            .start(Arc::new(AtomicBool::new(false)), message_body_tx)
            .await;
        let message =
            ClientMessage::Text(UiTrafficConverter::new_marshal(UiShutdownRequest {}.tmb(1)));

        client_listener_handle.send(message).await.unwrap();
        let error = message_body_rx.recv().await.unwrap().err().unwrap();

        assert_eq!(error, ClientListenerError::Closed);
        wait_for_stop(&client_listener_handle).await;
        let is_spinning = client_listener_handle.is_event_loop_spinning();
        assert_eq!(is_spinning, false);
        let _ = stop_handle.stop(None, None).await;
    }

    #[tokio::test]
    async fn processes_broken_connection_correctly() {
        let port = find_free_port();
        let server = MockWebSocketsServer::new(port);
        let stop_handle = server.start().await;
        let (websocket, listener_half, talker_half) = websocket_utils(port).await;
        let listener_half_clone = listener_half.clone();
        let (message_body_tx, mut message_body_rx) = unbounded_channel();
        let mut subject = ClientListener::new(websocket);
        let client_listener_handle = subject
            .start(Arc::new(AtomicBool::new(false)), message_body_tx)
            .await;
        assert!(talker_half.close());

        let error = message_body_rx.recv().await.unwrap().unwrap_err();

        assert_eq!(error, ClientListenerError::Broken("RecvError".to_string()));
        wait_for_stop(&client_listener_handle).await;
        let is_spinning = client_listener_handle.is_event_loop_spinning();
        assert_eq!(is_spinning, false);
    }

    #[tokio::test]
    async fn processes_bad_owned_message_correctly() {
        let port = find_free_port();
        let server =
            MockWebSocketsServer::new(port).queue_owned_message(ServerMessage::Binary(vec![]));
        let stop_handle = server.start().await;
        let websocket = make_and_connect_websocket(port).await;
        let (message_body_tx, mut message_body_rx) = unbounded_channel();
        let mut subject = ClientListener::new(websocket);
        let client_listener_handle = subject
            .start(Arc::new(AtomicBool::new(false)), message_body_tx)
            .await;
        stimulate_queued_response_from_server(&client_listener_handle.websocket.sender_tx()).await;

        let error = message_body_rx.recv().await.unwrap().err().unwrap();

        assert_eq!(error, ClientListenerError::UnexpectedPacket);
        let is_spinning = client_listener_handle.is_event_loop_spinning();
        assert_eq!(is_spinning, true);
        let _ = stop_handle.stop(None,None).await;
        wait_for_stop(&client_listener_handle).await;
        let is_spinning = client_listener_handle.is_event_loop_spinning();
        assert_eq!(is_spinning, false);
    }

    #[tokio::test]
    async fn processes_bad_packet_correctly() {
        let port = find_free_port();
        let server = MockWebSocketsServer::new(port).queue_string("booga");
        let stop_handle = server.start().await;
        let websocket = make_and_connect_websocket(port).await;
        let (message_body_tx, mut message_body_rx) = unbounded_channel();
        let mut subject = ClientListener::new(websocket);
        let client_listener_handle = subject
            .start(Arc::new(AtomicBool::new(false)), message_body_tx)
            .await;
        stimulate_queued_response_from_server(client_listener_handle.websocket.sender_tx()).await;

        let error = message_body_rx.recv().await.unwrap().err().unwrap();

        assert_eq!(error, ClientListenerError::UnexpectedPacket);
        let is_running = client_listener_handle.is_event_loop_spinning();
        assert_eq!(is_running, true);
        let _ = stop_handle.stop(None, None).await;
        wait_for_stop(&client_listener_handle).await;
        let is_running = client_listener_handle.is_event_loop_spinning();
        assert_eq!(is_running, false);
    }

    #[tokio::test]
    async fn drop_implementation_works_correctly() {
        let port = find_free_port();
        let server = MockWebSocketsServer::new(port);
        let stop_handle = server.start().await;
        let (websocket, _, _) = websocket_utils(port).await;
        let ref_counting_object = Arc::new(123);
        let cloned = ref_counting_object.clone();
        let join_handle = tokio::task::spawn(async move {
            let cloned = cloned;
            loop {
                tokio::time::sleep(Duration::from_millis(1000)).await;
            }
        });
        let client_handle = WSClientHandle::new(websocket, join_handle);
        let count_before = Arc::strong_count(&ref_counting_object);

        drop(client_handle);

        assert_eq!(count_before, 2);
        while Arc::strong_count(&ref_counting_object) > 1 {
            tokio::time::sleep(Duration::from_millis(10)).await
        }
        let _ = stop_handle.stop(None, None).await;
    }

    #[tokio::test]
    async fn no_new_received_message_is_processed_at_closing_stage() {
        let port = find_free_port();
        let server = MockWebSocketsServer::new(port)
            .queue_response(
                UiDescriptorResponse {
                    node_descriptor_opt: None,
                }
                .tmb(1234),
            )
            .queue_response(UiCheckPasswordResponse { matches: false }.tmb(4321));
        let stop_handle = server.start().await;
        let (websocket, talker_half, listener_half) = websocket_utils(port).await;
        let (message_body_tx, mut message_body_rx) = unbounded_channel();
        let is_closing = Arc::new(AtomicBool::new(false));
        let is_closing_cloned = is_closing.clone();
        let subject = ClientListenerEventLoop::new(listener_half, message_body_tx, is_closing);
        let join_handle = tokio::task::spawn(async { subject.loop_guts().await });
        let count_before = Arc::strong_count(&is_closing_cloned);
        stimulate_queued_response_from_server(&talker_half).await;
        let received_msg_body = message_body_rx.recv().await.unwrap().unwrap();
        let (received_message, context_id) = UiDescriptorResponse::fmb(received_msg_body).unwrap();

        is_closing_cloned.store(true, Ordering::Relaxed);
        stimulate_queued_response_from_server(&talker_half).await;

        assert_eq!(count_before, 2);
        assert_eq!(
            received_message,
            UiDescriptorResponse {
                node_descriptor_opt: None
            }
        );
        assert_eq!(context_id, 1234);
        while Arc::strong_count(&is_closing_cloned) > 1 {
            tokio::time::sleep(Duration::from_millis(10)).await
        }
        let second_msg_attempt = message_body_rx.try_recv();
        assert_eq!(second_msg_attempt, Err(TryRecvError::Disconnected));
        join_handle
            .await
            .expect("We expected peacefully completed task");
        let _ = stop_handle.stop(None, None).await;
    }

    #[tokio::test]
    async fn close_talker_half_works() {
        let port = find_free_port();
        let server = MockWebSocketsServer::new(port);
        let stop_handle = server.start().await;
        let websocket = make_and_connect_websocket(port).await;
        let meaningless_event_loop_join_handle = tokio::task::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_millis(1000)).await;
            }
        });
        let subject = WSClientHandle::new(websocket, meaningless_event_loop_join_handle);
        let is_closed_before = subject.websocket.sender_tx().is_closed();

        let closed_successfully = subject.close_talker_half();

        let is_closed_after = subject.websocket.sender_tx().is_closed();
        assert_eq!(is_closed_before, false);
        assert_eq!(closed_successfully, true);
        assert_eq!(is_closed_after, true);
        let _ = stop_handle.stop(None, None).await;
    }

    #[test]
    fn client_listener_errors_know_their_own_fatality() {
        assert_eq!(ClientListenerError::Closed.is_fatal(), true);
        assert_eq!(ClientListenerError::Broken("".to_string()).is_fatal(), true);
        assert_eq!(ClientListenerError::Timeout.is_fatal(), true);
        assert_eq!(ClientListenerError::UnexpectedPacket.is_fatal(), false);
    }

    async fn wait_for_stop(listener_handle: &WSClientHandle) {
        listener_handle.listening_event_loop_join_handle.abort();
        let mut retries = 100;
        while retries > 0 {
            retries -= 1;
            if !listener_handle.is_event_loop_spinning() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("ClientListener was supposed to stop but didn't");
    }
}
