// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::communications::connection_manager::CloseSignalling;
use async_channel::Receiver as WSReceiver;
use async_trait::async_trait;
use masq_lib::ui_gateway::MessageBody;
use masq_lib::ui_traffic_converter::UiTrafficConverter;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::broadcast::Receiver as BroadcastReceiver;
use tokio::sync::broadcast::Sender as BroadcastSender;
use tokio::sync::mpsc::UnboundedSender;
use tokio::task::{AbortHandle, JoinHandle};
use workflow_websocket::client::{Error, Result as ClientResult};
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
        close_sig: BroadcastReceiver<()>,
        message_body_tx: UnboundedSender<Result<MessageBody, ClientListenerError>>,
    ) -> Box<dyn WSClientHandle> {
        let listener_half = self.websocket.receiver_rx().clone();
        let event_loop = ClientListenerEventLoop::new(listener_half, message_body_tx, close_sig);
        let task_handle = event_loop.spawn();
        Box::new(WSClientHandleReal::new(
            self.websocket,
            task_handle.abort_handle(),
        ))
    }
}

#[async_trait]
pub trait WSClientHandle: Send {
    async fn send(&self, msg: Message) -> std::result::Result<(), Arc<Error>>;
    async fn disconnect(&self) -> ClientResult<()>;
    fn close_talker_half(&self) -> bool;
    fn dismiss_event_loop(&self);
    #[cfg(test)]
    fn is_connection_open(&self) -> bool;
    #[cfg(test)]
    fn is_event_loop_spinning(&self) -> bool;
}

pub struct WSClientHandleReal {
    websocket: WebSocket,
    listener_event_loop_abort_handle: AbortHandle,
}

impl Drop for WSClientHandleReal {
    fn drop(&mut self) {
        self.dismiss_event_loop()
    }
}

#[async_trait]
impl WSClientHandle for WSClientHandleReal {
    async fn send(&self, msg: Message) -> std::result::Result<(), Arc<Error>> {
        self.websocket.send(msg).await.map(|_| ())
    }

    async fn disconnect(&self) -> ClientResult<()> {
        self.websocket.disconnect().await
    }

    fn close_talker_half(&self) -> bool {
        self.websocket.sender_tx().close()
    }

    fn dismiss_event_loop(&self) {
        self.listener_event_loop_abort_handle.abort()
    }

    #[cfg(test)]
    fn is_connection_open(&self) -> bool {
        self.websocket.is_connected()
    }

    #[cfg(test)]
    fn is_event_loop_spinning(&self) -> bool {
        !self.listener_event_loop_abort_handle.is_finished()
    }
}

impl WSClientHandleReal {
    pub fn new(websocket: WebSocket, listener_event_loop_abort_handle: AbortHandle) -> Self {
        Self {
            websocket,
            listener_event_loop_abort_handle,
        }
    }
}

struct ClientListenerEventLoop {
    listener_half: WSReceiver<Message>,
    message_body_tx: UnboundedSender<Result<MessageBody, ClientListenerError>>,
    close_sig: BroadcastReceiver<()>,
}

impl ClientListenerEventLoop {
    pub fn new(
        listener_half: WSReceiver<Message>,
        message_body_tx: UnboundedSender<Result<MessageBody, ClientListenerError>>,
        close_sig: BroadcastReceiver<()>,
    ) -> Self {
        Self {
            listener_half,
            message_body_tx,
            close_sig,
        }
    }

    pub fn spawn(self) -> JoinHandle<()> {
        tokio::task::spawn(self.loop_guts())
    }

    async fn loop_guts(mut self) {
        loop {
            let ws_msg_rcv = self.listener_half.recv();
            let close_sig = self.close_sig.recv();

            tokio::select! {
                biased;

                _ = close_sig => {
                    break
                }

                msg = ws_msg_rcv => {
                      match msg {
                        Ok(Message::Text(string)) => {
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
                        Ok(Message::Open) => {
                            // Dropping, it doesn't say anything but what we already know
                        }
                        Ok(Message::Close) => {
                            let _ = self.message_body_tx.send(Err(ClientListenerError::Closed));
                            break;
                        }
                        Ok(_unexpected) => {
                            match self
                                .message_body_tx
                                .send(Err(ClientListenerError::UnexpectedPacket))
                            {
                                Ok(_) => (),
                                Err(_) => break,
                            }
                        }
                        Err(error) => {
                            let _ = self
                                .message_body_tx
                                .send(Err(ClientListenerError::Broken(format!("{:?}", error))));
                            break;
                        }
                     }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_channel::{unbounded, Sender};
    use futures::{FutureExt, SinkExt, StreamExt, TryFutureExt};
    use masq_lib::messages::{
        FromMessageBody, ToMessageBody, UiCheckPasswordResponse, UiDescriptorResponse,
    };
    use masq_lib::messages::{UiShutdownRequest, UiShutdownResponse};
    use masq_lib::test_utils::mock_websockets_server::MockWebSocketsServer;
    use masq_lib::test_utils::websockets_utils::{
        establish_ws_conn_with_handshake, websocket_utils, websocket_utils_without_handshake,
    };
    use masq_lib::utils::{find_free_port, localhost};
    use std::net::SocketAddr;
    use std::time::{Duration, SystemTime};
    use tokio::net::TcpListener;
    use tokio::sync::mpsc::error::TryRecvError;
    use tokio::sync::mpsc::unbounded_channel;
    use tokio::task::JoinError;
    use tokio::time::Instant;
    use tokio_tungstenite::tungstenite::protocol::Role;
    use tokio_tungstenite::{accept_async, accept_async_with_config};
    use workflow_websocket::client::{Ack, Message as ClientMessage};
    use workflow_websocket::server::Message as ServerMessage;

    async fn stimulate_queued_response_from_server(client_talker_half: &dyn WSClientHandle) {
        let message = Message::Text(UiTrafficConverter::new_marshal(
            UiShutdownRequest {}.tmb(345678),
        ));
        client_talker_half.send(message).await.unwrap();
    }

    #[tokio::test]
    async fn listens_and_passes_data_through() {
        let expected_message = UiShutdownResponse {};
        let port = find_free_port();
        let server =
            MockWebSocketsServer::new(port).queue_response(expected_message.clone().tmb(1));
        let stop_handle = server.start().await;
        //let websocket = establish_ws_conn_with_handshake(port);
        let (websocket, talker_half, _) = websocket_utils(port).await;
        let (message_body_tx, mut message_body_rx) = unbounded_channel();
        let (_close_tx, close_sig) = CloseSignalling::make_for_test();
        let mut subject = ClientListener::new(websocket);
        let client_listener_handle = subject
            .start(close_sig.dup_receiver(), message_body_tx)
            .await;
        stimulate_queued_response_from_server(client_listener_handle.as_ref()).await;

        let message_body = message_body_rx.recv().await.unwrap().unwrap();

        assert_eq!(message_body, expected_message.tmb(1));
        let is_spinning = client_listener_handle.is_event_loop_spinning();
        assert_eq!(is_spinning, true);
    }

    #[tokio::test]
    async fn processes_incoming_close_correctly() {
        let port = find_free_port();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let server_join_handle = tokio::task::spawn(async move {
            let listener = TcpListener::bind(SocketAddr::new(localhost(), port))
                .await
                .unwrap();
            tx.send(()).unwrap();
            let (tcp, _) = listener.accept().await.unwrap();
            let (mut write, read) = accept_async(tcp).await.unwrap().split();
            write
                .send(tokio_tungstenite::tungstenite::Message::Close(None))
                .await
                .unwrap();
        });
        rx.recv().await.unwrap();
        let (websocket, listener_half, talker_half) = websocket_utils_without_handshake(port).await;
        let (message_body_tx, mut message_body_rx) = unbounded_channel();
        let (_close_tx, close_sig) = CloseSignalling::make_for_test();
        let mut subject = ClientListener::new(websocket);
        let client_listener_handle = subject
            .start(close_sig.dup_receiver(), message_body_tx)
            .await;

        let conn_closed_announcement = message_body_rx.recv().await.unwrap();
        let probe =
            ClientMessage::Text(UiTrafficConverter::new_marshal(UiShutdownRequest {}.tmb(1)));
        let send_error = client_listener_handle.send(probe).await.unwrap_err();

        assert_eq!(conn_closed_announcement, Err(ClientListenerError::Closed));
        match send_error.as_ref() {
            Error::NotConnected => (),
            x => panic!("We expected Err(NotConnected) but got {:?}", x),
        };
        let is_spinning = client_listener_handle.is_event_loop_spinning();
        assert_eq!(is_spinning, false);
        server_join_handle.await.unwrap();
    }

    #[tokio::test]
    async fn processes_broken_connection_correctly() {
        let port = find_free_port();
        let server = MockWebSocketsServer::new(port);
        let stop_handle = server.start().await;
        let (websocket, listener_half, talker_half) = websocket_utils(port).await;
        let listener_half_clone = listener_half.clone();
        let (message_body_tx, mut message_body_rx) = unbounded_channel();
        let (_close_tx, close_sig) = CloseSignalling::make_for_test();
        let mut subject = ClientListener::new(websocket);
        let client_listener_handle = subject
            .start(close_sig.dup_receiver(), message_body_tx)
            .await;
        assert!(talker_half.close());

        let error = message_body_rx.recv().await.unwrap().unwrap_err();

        assert_eq!(error, ClientListenerError::Broken("RecvError".to_string()));
        wait_for_stop(client_listener_handle.as_ref()).await;
        let is_spinning = client_listener_handle.is_event_loop_spinning();
        assert_eq!(is_spinning, false);
    }

    #[tokio::test]
    async fn processes_bad_owned_message_correctly() {
        let port = find_free_port();
        let server =
            MockWebSocketsServer::new(port).queue_owned_message(ServerMessage::Binary(vec![]));
        let stop_handle = server.start().await;
        let websocket = establish_ws_conn_with_handshake(port).await;
        let (message_body_tx, mut message_body_rx) = unbounded_channel();
        let (_close_tx, close_sig) = CloseSignalling::make_for_test();
        let mut subject = ClientListener::new(websocket);
        let client_listener_handle = subject
            .start(close_sig.dup_receiver(), message_body_tx)
            .await;
        stimulate_queued_response_from_server(client_listener_handle.as_ref()).await;

        let error = message_body_rx.recv().await.unwrap().err().unwrap();

        assert_eq!(error, ClientListenerError::UnexpectedPacket);
        let is_spinning = client_listener_handle.is_event_loop_spinning();
        assert_eq!(is_spinning, true);
    }

    #[tokio::test]
    async fn processes_bad_packet_correctly() {
        let port = find_free_port();
        let server = MockWebSocketsServer::new(port).queue_string("booga");
        let stop_handle = server.start().await;
        let websocket = establish_ws_conn_with_handshake(port).await;
        let (message_body_tx, mut message_body_rx) = unbounded_channel();
        let (_close_tx, close_sig) = CloseSignalling::make_for_test();
        let mut subject = ClientListener::new(websocket);
        let client_listener_handle = subject
            .start(close_sig.dup_receiver(), message_body_tx)
            .await;
        stimulate_queued_response_from_server(client_listener_handle.as_ref()).await;

        let error = message_body_rx.recv().await.unwrap().err().unwrap();

        assert_eq!(error, ClientListenerError::UnexpectedPacket);
        let is_running = client_listener_handle.is_event_loop_spinning();
        assert_eq!(is_running, true);
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
        let client_handle = WSClientHandleReal::new(websocket, join_handle.abort_handle());
        let count_before = Arc::strong_count(&ref_counting_object);

        drop(client_handle);

        assert_eq!(count_before, 2);
        while Arc::strong_count(&ref_counting_object) > 1 {
            tokio::time::sleep(Duration::from_millis(10)).await
        }
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
        let (close_signaler, close_sig) = CloseSignalling::make_for_test();
        let subject =
            ClientListenerEventLoop::new(listener_half, message_body_tx, close_sig.dup_receiver());
        let mut join_handle = tokio::task::spawn(async { subject.loop_guts().await });
        let client_handle = WSClientHandleReal::new(websocket, join_handle.abort_handle());
        stimulate_queued_response_from_server(&client_handle).await;
        let received_msg_body = message_body_rx.recv().await.unwrap().unwrap();
        let (received_message, context_id) = UiDescriptorResponse::fmb(received_msg_body).unwrap();

        close_signaler.signalize_close();
        stimulate_queued_response_from_server(&client_handle).await;

        let timeout = Duration::from_millis(1500);
        let start = Instant::now();
        while client_handle.is_event_loop_spinning() {
            tokio::time::sleep(Duration::from_millis(20)).await;
            if start.elapsed() >= timeout {
                panic!(
                    "Waited on the listener's task to finish within {} ms, but it didn't",
                    timeout.as_millis()
                )
            }
        }
        // Checking that spawn didn't finish by panicking
        join_handle.await.unwrap();
        assert_eq!(
            received_message,
            UiDescriptorResponse {
                node_descriptor_opt: None
            }
        );
        assert_eq!(context_id, 1234);
        let second_msg_attempt = message_body_rx.try_recv();
        assert_eq!(second_msg_attempt, Err(TryRecvError::Disconnected));
    }

    #[tokio::test]
    async fn close_talker_half_works() {
        let port = find_free_port();
        let server = MockWebSocketsServer::new(port);
        let stop_handle = server.start().await;
        let websocket = establish_ws_conn_with_handshake(port).await;
        let meaningless_event_loop_join_handle = tokio::task::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_millis(1000)).await;
            }
        });
        let subject =
            WSClientHandleReal::new(websocket, meaningless_event_loop_join_handle.abort_handle());
        let is_closed_before = subject.websocket.sender_tx().is_closed();

        let closed_successfully = subject.close_talker_half();

        let is_closed_after = subject.websocket.sender_tx().is_closed();
        assert_eq!(is_closed_before, false);
        assert_eq!(closed_successfully, true);
        assert_eq!(is_closed_after, true);
    }

    #[test]
    fn client_listener_errors_know_their_own_fatality() {
        assert_eq!(ClientListenerError::Closed.is_fatal(), true);
        assert_eq!(ClientListenerError::Broken("".to_string()).is_fatal(), true);
        assert_eq!(ClientListenerError::Timeout.is_fatal(), true);
        assert_eq!(ClientListenerError::UnexpectedPacket.is_fatal(), false);
    }

    async fn wait_for_stop(listener_handle: &dyn WSClientHandle) {
        listener_handle.dismiss_event_loop();
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
