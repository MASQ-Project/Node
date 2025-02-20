// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::communications::connection_manager::ClosingStageDetector;
use async_trait::async_trait;
use masq_lib::ui_gateway::MessageBody;
use masq_lib::ui_traffic_converter::UiTrafficConverter;
use std::sync::Arc;
use soketto::connection::Error;
use soketto::Data;
use tokio::sync::broadcast::Receiver as BroadcastReceiver;
use tokio::sync::mpsc::UnboundedSender;
use tokio::task::{AbortHandle, JoinHandle};
use masq_lib::websockets_types::{WSReceiver, WSSender};
use std::net::SocketAddr;
use futures::io::{BufReader, BufWriter};
use soketto::handshake::{Client, ServerResponse};
use tokio_util::compat::TokioAsyncReadCompatExt;
use masq_lib::messages::NODE_UI_PROTOCOL;
use masq_lib::utils::localhost;

// TODO assert me if preserved
pub const WS_CONNECT_TIMEOUT_MS: u64 = 1500;

#[derive(Debug)]
pub enum ConnectError{
    Error(Error),
    Timeout
}

pub async fn make_connection(port: u16, timeout_ms: u64) -> Result<(WSSender, WSReceiver), ConnectError>{
    let socket_addr = SocketAddr::new(localhost(), port);

    let tcp_stream = match tokio::net::TcpStream::connect(socket_addr).await{
        Ok(tcp) => tcp,
        Err(e) => todo!()
    };

    let mut client = Client::new(BufReader::new(BufWriter::new(tcp_stream.compat())), "/", "/");

    client.add_protocol(NODE_UI_PROTOCOL);

    let result =  client.handshake().await;

    let server_response = match result{
        Ok(res) => res,
        Err(e) => todo!()
    };

    match server_response {
        ServerResponse::Accepted {protocol} => {
            if let Some(_) = protocol {
                Ok(client.into_builder().finish())
            } else {
                todo!()
            }
        },
        ServerResponse::Rejected {status_code} => todo!(),
        ServerResponse::Redirect {status_code, location} => todo!()
    }
}

#[async_trait]
pub trait WSClientHandle: Send {
    async fn send_msg(&mut self, msg: MessageBody) -> Result<(), Error>;
    async fn close(&self) -> Result<(), Error>;
    fn dismiss_event_loop(&self);
    #[cfg(test)]
    async fn is_connection_open(&mut self) -> bool;
    #[cfg(test)]
    fn is_event_loop_spinning(&self) -> bool;
}

pub struct WSClientHandleReal {
    ws_sender: WSSender,
    listener_event_loop_abort_handle: AbortHandle,
}

impl Drop for WSClientHandleReal {
    fn drop(&mut self) {
        self.dismiss_event_loop()
    }
}

#[async_trait]
impl WSClientHandle for WSClientHandleReal {
    async fn send_msg(&mut self, msg: MessageBody) -> Result<(), Error> {
        let txt = UiTrafficConverter::new_marshal(msg);
        //TODO untested
        eprintln!("client sends: {}", txt);
        self.ws_sender.send_text_owned(txt).await;
        self.ws_sender.flush().await
    }

    async fn close(&self) -> Result<(), Error> {
        todo!()
    }

    fn dismiss_event_loop(&self) {
        self.listener_event_loop_abort_handle.abort()
    }

    #[cfg(test)]
    async fn is_connection_open(&mut self) -> bool {
        // Is this too big a hack?
        self.ws_sender.flush().await.is_ok()
    }

    #[cfg(test)]
    fn is_event_loop_spinning(&self) -> bool {
        !self.listener_event_loop_abort_handle.is_finished()
    }
}

impl WSClientHandleReal {
    pub fn new(ws_sender: WSSender, listener_event_loop_abort_handle: AbortHandle) -> Self {
        Self {
            ws_sender,
            listener_event_loop_abort_handle,
        }
    }
}

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
    ws_receiver: WSReceiver,
}

impl ClientListener {
    pub fn new(ws_receiver: WSReceiver) -> Self {
        Self { ws_receiver }
    }

    pub async fn start(
        self,
        close_sig: BroadcastReceiver<()>,
        message_body_tx: UnboundedSender<Result<MessageBody, ClientListenerError>>,
    ) -> AbortHandle {
        let spawner = ClientListenerSpawner::new(self.ws_receiver, message_body_tx, close_sig);
        spawner.spawn().abort_handle()
        // let client_handle = WSClientHandleReal::new(self.websocket, abort_handle);
        // Box::new(client_handle)
    }
}

struct ClientListenerSpawner {
    listener_half: WSReceiver,
    message_body_tx: UnboundedSender<Result<MessageBody, ClientListenerError>>,
    close_sig: BroadcastReceiver<()>,
}

impl ClientListenerSpawner {
    pub fn new(
        listener_half: WSReceiver,
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
        let mut msg = Vec::new();
        loop {
            msg.clear();

            let ws_msg_rcv = self.listener_half.receive_data(&mut msg);
            let close_sig_rcv = self.close_sig.recv();

            tokio::select! {
                biased;

                _ = close_sig_rcv => {
                    break
                }

                received = ws_msg_rcv => {
                      match received {
                        Ok(Data::Text(len)) => {
                            match UiTrafficConverter::new_unmarshal(&String::from_utf8_lossy(&msg)) {
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
                        Ok(Data::Binary(_)) => {
                            match self
                                .message_body_tx
                                .send(Err(ClientListenerError::UnexpectedPacket))
                            {
                                Ok(_) => (),
                                Err(_) => break,
                            }
                        }
                        Err(Error::Closed) => {
                            let _ = self.message_body_tx.send(Err(ClientListenerError::Closed));
                            break;
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
    use masq_lib::messages::{FromMessageBody, ToMessageBody, UiCheckPasswordRequest, UiCheckPasswordResponse, UiConnectionChangeBroadcast, UiConnectionStage, UiDescriptorRequest, UiDescriptorResponse};
    use masq_lib::messages::{UiShutdownRequest, UiShutdownResponse};
    use masq_lib::test_utils::mock_websockets_server::{MWSSMessage, MockWebSocketsServer, StopStrategy};
    use masq_lib::utils::find_free_port;
    use std::time::Duration;
    use tokio::sync::mpsc::error::TryRecvError;
    use tokio::sync::mpsc::unbounded_channel;
    use tokio::time::Instant;

    // TODO ditch me after you have Dan's server in
    // async fn stimulate_queued_response_from_server(client_talker_half: &dyn WSClientHandle) {
    //     let message = Message::Text(UiTrafficConverter::new_marshal(
    //         UiShutdownRequest {}.tmb(345678),
    //     ));
    //     client_talker_half.send_msg(message).await.unwrap();
    // }

    #[tokio::test]
    async fn listens_and_passes_data_through() {
        let expected_message = UiConnectionChangeBroadcast { stage: UiConnectionStage::RouteFound };
        let port = find_free_port();
        let server =
            MockWebSocketsServer::new(port).queue_response(expected_message.clone().tmb(1));
        let server_stop_handle = server.start().await;
        let (talker_half, listener_half) = make_connection(port, WS_CONNECT_TIMEOUT_MS).await.unwrap();
        let (message_body_tx, mut message_body_rx) = unbounded_channel();
        let (_close_tx, close_sig) = ClosingStageDetector::make_for_test();
        let subject = ClientListener::new(listener_half);
        let abort_handle = subject
            .start(close_sig.dup_receiver(), message_body_tx)
            .await;

        let message_body = message_body_rx.recv().await.unwrap().unwrap();

        assert_eq!(message_body, expected_message.tmb(1));
        let is_spinning = !abort_handle.is_finished();
        assert_eq!(is_spinning, true);
        server_stop_handle.stop(StopStrategy::Close).await;
    }

    #[tokio::test]
    async fn processes_incoming_close_correctly() {
        let port = find_free_port();
        let server_stop_handle = MockWebSocketsServer::new(port)
            .start()
            .await;
        let (mut talker_half, listener_half) =
            make_connection(port, WS_CONNECT_TIMEOUT_MS).await.unwrap();
        let (message_body_tx, mut message_body_rx) = unbounded_channel();
        let (close_signaler, close_detector) = ClosingStageDetector::make_for_test();
        let subject = ClientListener::new(listener_half);
        let abort_handle = subject
            .start(close_detector.dup_receiver(), message_body_tx)
            .await;

        server_stop_handle.stop(StopStrategy::Close).await;
        let conn_closed_announcement = message_body_rx.recv().await.unwrap();
        let disconnection_probe = UiTrafficConverter::new_marshal(UiShutdownRequest {}.tmb(2));
        let send_error = talker_half
            .send_text_owned(disconnection_probe)
            .await
            .unwrap_err();

        assert_eq!(conn_closed_announcement, Err(ClientListenerError::Closed));
        match send_error {
            Error::Closed => (),
            x => panic!("We expected Err(Closed) but got {:?}", x),
        };
        let is_spinning = !abort_handle.is_finished();
        assert_eq!(is_spinning, false);
        // Because not ordered from our side
        assert_eq!(close_signaler.is_closing(), false)
    }

    #[tokio::test]
    async fn processes_broken_connection_correctly() {
        let port = find_free_port();
        let server = MockWebSocketsServer::new(port);
        let server_stop_handle = server.start().await;
        let (talker_half, listener_half) =
            make_connection(port, WS_CONNECT_TIMEOUT_MS).await.unwrap();
        let (message_body_tx, mut message_body_rx) = unbounded_channel();
        let (_close_tx, close_sig) = ClosingStageDetector::make_for_test();
        let subject = ClientListener::new(listener_half);
        let abort_handle = subject
            .start(close_sig.dup_receiver(), message_body_tx)
            .await;
        server_stop_handle.stop(StopStrategy::Abort).await;

        let error = message_body_rx.recv().await.unwrap().unwrap_err();

        assert_eq!(error, ClientListenerError::Broken("RecvError".to_string()));
        let is_spinning = !abort_handle.is_finished();
        assert_eq!(is_spinning, false);
    }

    #[tokio::test]
    async fn processes_bad_owned_message_correctly() {
        let port = find_free_port();
        let server =
            MockWebSocketsServer::new(port)
                .queue_faf_owned_message(Data::Binary(10), b"BadMessage".to_vec());
        let stop_handle = server.start().await;
        let (talker_half, listener_half) =
            make_connection(port, WS_CONNECT_TIMEOUT_MS).await.unwrap();
        let (message_body_tx, mut message_body_rx) = unbounded_channel();
        let (_close_tx, close_sig) = ClosingStageDetector::make_for_test();
        let subject = ClientListener::new(listener_half);
        let abort_handle = subject
            .start(close_sig.dup_receiver(), message_body_tx)
            .await;

        let error = message_body_rx.recv().await.unwrap().err().unwrap();

        assert_eq!(error, ClientListenerError::UnexpectedPacket);
        let is_spinning = !abort_handle.is_finished();
        assert_eq!(is_spinning, true);
    }

    #[tokio::test]
    async fn processes_bad_packet_correctly() {
        let port = find_free_port();
        let server = MockWebSocketsServer::new(port).queue_faf_owned_message(Data::Text(5),b"booga".to_vec());
        let stop_handle = server.start().await;
        let (talker_half, listener_half) =
            make_connection(port, WS_CONNECT_TIMEOUT_MS).await.unwrap();
        let (message_body_tx, mut message_body_rx) = unbounded_channel();
        let (_close_tx, close_sig) = ClosingStageDetector::make_for_test();
        let subject = ClientListener::new(listener_half);
        let abort_handle = subject
            .start(close_sig.dup_receiver(), message_body_tx)
            .await;

        let error = message_body_rx.recv().await.unwrap().err().unwrap();

        assert_eq!(error, ClientListenerError::UnexpectedPacket);
        let is_running = !abort_handle.is_finished();
        assert_eq!(is_running, true);
    }

    #[tokio::test]
    async fn drop_implementation_works_correctly() {
        let port = find_free_port();
        let server = MockWebSocketsServer::new(port);
        let stop_handle = server.start().await;
        let (talker_half, listener_half) =
            make_connection(port, WS_CONNECT_TIMEOUT_MS).await.unwrap();
        let ref_counting_object = Arc::new(123);
        let cloned = ref_counting_object.clone();
        let join_handle = tokio::task::spawn(async move {
            let _cloned_moved_in = cloned;
            loop {
                tokio::time::sleep(Duration::from_millis(1000)).await;
            }
        });
        let client_handle = WSClientHandleReal::new(talker_half, join_handle.abort_handle());
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
        let (mut talker_half, listener_half) =
            make_connection(port, WS_CONNECT_TIMEOUT_MS).await.unwrap();
        let (message_body_tx, mut message_body_rx) = unbounded_channel();
        let (close_signaler, close_sig) = ClosingStageDetector::make_for_test();
        let subject = ClientListenerSpawner::new(
            listener_half,
            message_body_tx,
            close_sig.dup_receiver(),
        );
        let join_handle = tokio::task::spawn(async { subject.loop_guts().await });
        let mut client_handle = WSClientHandleReal::new(talker_half, join_handle.abort_handle());
        client_handle.send_msg(UiDescriptorRequest{}.tmb(1234)).await.unwrap();
        let received_msg_body = message_body_rx.recv().await.unwrap().unwrap();
        let (received_message, context_id) = UiDescriptorResponse::fmb(received_msg_body).unwrap();

        close_signaler.signalize_close();
        // Making the mock server send another msg
        client_handle.send_msg(UiCheckPasswordRequest{ db_password_opt: None }.tmb(4321)).await.unwrap();

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
    async fn close_works() {
        let port = find_free_port();
        let server = MockWebSocketsServer::new(port);
        let stop_handle = server.start().await;
        let (mut talker_half, listener_half) =
            make_connection(port, WS_CONNECT_TIMEOUT_MS).await.unwrap();
        let meaningless_event_loop_join_handle = tokio::task::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_millis(1000)).await;
            }
        });
        let subject =
            WSClientHandleReal::new(talker_half, meaningless_event_loop_join_handle.abort_handle());

        let result = subject.close().await;

        assert!(matches!(result, Ok(())));
        let requests = stop_handle.stop(StopStrategy::Abort).await;
        assert_eq!(requests.requests, vec![MWSSMessage::Close])
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
