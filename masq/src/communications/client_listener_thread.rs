// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::communications::connection_manager::ClosingStageDetector;
use async_channel::Receiver as WSReceiver;
use async_trait::async_trait;
use masq_lib::ui_gateway::MessageBody;
use masq_lib::ui_traffic_converter::UiTrafficConverter;
use std::sync::Arc;
use tokio::sync::broadcast::Receiver as BroadcastReceiver;
use tokio::sync::mpsc::UnboundedSender;
use tokio::task::{AbortHandle, JoinHandle};
use workflow_websocket::client::{Error, Result as ClientResult};
use workflow_websocket::client::{Message, WebSocket};

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ClientListenerError {
    Closed,
    Broken(String),
    Timeout { elapsed_ms: u64 },
    UnexpectedPacket,
}

impl ClientListenerError {
    pub fn is_fatal(&self) -> bool {
        match self {
            ClientListenerError::Closed => true,
            ClientListenerError::Broken(_) => true,
            ClientListenerError::Timeout { .. } => true,
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
        let ws_receiver = self.websocket.receiver_rx().clone();
        let spawner = ClientListenerEventLoopSpawner::new(ws_receiver, message_body_tx, close_sig);
        let abort_handle = spawner.spawn().abort_handle();
        let client_listener = WSClientHandleReal::new(self.websocket, abort_handle);
        Box::new(client_listener)
    }
}

#[async_trait]
pub trait WSClientHandle: Send {
    async fn send(&self, msg: Message) -> std::result::Result<(), Arc<Error>>;
    // This is unfortunate as we cannot get the library we're using to send a graceful Close msg.
    // Without us to understand, they implemented a panic to unwind upon this message's arrival (on
    // the server side - which also is built from the same library). All they provide is this
    // disconnection which, however, results in a connection reset considered an error on
    // the server's side. I'll have to leave it this way for timely reasons but a redesign should
    // take place someday.
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
    async fn send(&self, msg: Message) -> Result<(), Arc<Error>> {
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

struct ClientListenerEventLoopSpawner {
    listener_half: WSReceiver<Message>,
    message_body_tx: UnboundedSender<Result<MessageBody, ClientListenerError>>,
    close_sig: BroadcastReceiver<()>,
}

impl ClientListenerEventLoopSpawner {
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
            let close_sig_rcv = self.close_sig.recv();

            tokio::select! {
                biased;

                _ = close_sig_rcv => {
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
    use masq_lib::messages::{
        FromMessageBody, ToMessageBody, UiCheckPasswordResponse, UiDescriptorRequest,
        UiDescriptorResponse,
    };
    use masq_lib::messages::{UiShutdownRequest, UiShutdownResponse};
    use masq_lib::test_utils::mock_websockets_server::MockWebSocketsServer;
    use masq_lib::test_utils::websockets_utils::{
        establish_ws_conn_with_handshake, websocket_utils_with_masq_handshake,
    };
    use masq_lib::utils::find_free_port;
    use std::time::Duration;
    use tokio::sync::mpsc::error::TryRecvError;
    use tokio::sync::mpsc::unbounded_channel;
    use tokio::time::Instant;
    use workflow_websocket::client::Message as ClientMessage;
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
        let (websocket, talker_half, _) = websocket_utils_with_masq_handshake(port).await;
        let (message_body_tx, mut message_body_rx) = unbounded_channel();
        let (_close_tx, close_sig) = ClosingStageDetector::make_for_test();
        let subject = ClientListener::new(websocket);
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
        let server_handle = MockWebSocketsServer::new(port)
            .queue_owned_message(ServerMessage::Close(None))
            .start()
            .await;
        let (websocket, listener_half, talker_half) =
            websocket_utils_with_masq_handshake(port).await;
        let (message_body_tx, mut message_body_rx) = unbounded_channel();
        let (close_signaler, close_detector) = ClosingStageDetector::make_for_test();
        let subject = ClientListener::new(websocket);
        let client_listener_handle = subject
            .start(close_detector.dup_receiver(), message_body_tx)
            .await;

        let server_response_trigger = ClientMessage::Text(UiTrafficConverter::new_marshal(
            UiDescriptorRequest {}.tmb(1),
        ));
        client_listener_handle
            .send(server_response_trigger)
            .await
            .unwrap();
        let conn_closed_announcement = message_body_rx.recv().await.unwrap();
        let disconnection_probe =
            ClientMessage::Text(UiTrafficConverter::new_marshal(UiShutdownRequest {}.tmb(2)));
        let send_error = client_listener_handle
            .send(disconnection_probe)
            .await
            .unwrap_err();

        assert_eq!(conn_closed_announcement, Err(ClientListenerError::Closed));
        match send_error.as_ref() {
            Error::NotConnected => (),
            x => panic!("We expected Err(NotConnected) but got {:?}", x),
        };
        let is_spinning = client_listener_handle.is_event_loop_spinning();
        assert_eq!(is_spinning, false);
        // Because not ordered from our side
        assert_eq!(close_signaler.is_closing(), false)
    }

    #[tokio::test]
    async fn processes_broken_connection_correctly() {
        let port = find_free_port();
        let server = MockWebSocketsServer::new(port);
        let stop_handle = server.start().await;
        let (websocket, listener_half, talker_half) =
            websocket_utils_with_masq_handshake(port).await;
        let listener_half_clone = listener_half.clone();
        let (message_body_tx, mut message_body_rx) = unbounded_channel();
        let (_close_tx, close_sig) = ClosingStageDetector::make_for_test();
        let subject = ClientListener::new(websocket);
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
        let (_close_tx, close_sig) = ClosingStageDetector::make_for_test();
        let subject = ClientListener::new(websocket);
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
        let (_close_tx, close_sig) = ClosingStageDetector::make_for_test();
        let subject = ClientListener::new(websocket);
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
        let (websocket, _, _) = websocket_utils_with_masq_handshake(port).await;
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
        let (websocket, _talker_half, listener_half) =
            websocket_utils_with_masq_handshake(port).await;
        let (message_body_tx, mut message_body_rx) = unbounded_channel();
        let (close_signaler, close_sig) = ClosingStageDetector::make_for_test();
        let subject = ClientListenerEventLoopSpawner::new(
            listener_half,
            message_body_tx,
            close_sig.dup_receiver(),
        );
        let join_handle = tokio::task::spawn(async { subject.loop_guts().await });
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
        assert_eq!(
            ClientListenerError::Timeout { elapsed_ms: 1000 }.is_fatal(),
            true
        );
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
