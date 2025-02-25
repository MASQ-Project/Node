// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::communications::connection_manager::ClosingStageDetector;
use async_trait::async_trait;
use futures::io::{BufReader, BufWriter};
use masq_lib::messages::NODE_UI_PROTOCOL;
use masq_lib::ui_gateway::MessageBody;
use masq_lib::ui_traffic_converter::UiTrafficConverter;
use masq_lib::utils::localhost;
use masq_lib::websockets_types::{WSReceiver, WSSender};
use soketto::connection::Error as SokettoError;
use soketto::handshake::{Client, ServerResponse};
use soketto::Data;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::broadcast::Receiver as BroadcastReceiver;
use tokio::sync::mpsc::UnboundedSender;
use tokio::task::{AbortHandle, JoinHandle};
use tokio_util::compat::TokioAsyncReadCompatExt;

// TODO assert me if preserved
pub const WS_CONNECT_TIMEOUT_MS: u64 = 1500;

#[derive(Debug)]
pub enum ConnectError {
    Soketto(SokettoError),
    Timeout,
}

impl From<SokettoError> for ConnectError {
    fn from(e: SokettoError) -> Self {
        ConnectError::Soketto(e)
    }
}

pub async fn make_connection_with_timeout(
    port: u16,
    timeout_ms: u64,
) -> Result<(WSSender, WSReceiver), ConnectError> {
    let connect_fut = async move {
        let socket_addr = SocketAddr::new(localhost(), port);

        let tcp_stream = match tokio::net::TcpStream::connect(socket_addr).await {
            Ok(tcp) => tcp,
            Err(e) => return Err(ConnectError::Soketto(SokettoError::Io(e))),
        };

        let mut client = Client::new(
            BufReader::new(BufWriter::new(tcp_stream.compat())),
            "localhost",
            "/",
        );

        client.add_protocol(NODE_UI_PROTOCOL);

        let result = client.handshake().await;

        let server_response = match result {
            Ok(res) => res,
            Err(e) => todo!("{:?}", e),
        };

        match server_response {
            ServerResponse::Accepted { protocol } => {
                if let Some(_) = protocol {
                    Ok::<_, ConnectError>(client.into_builder().finish())
                } else {
                    todo!()
                }
            }
            ServerResponse::Rejected { status_code } => todo!(),
            ServerResponse::Redirect {
                status_code,
                location,
            } => todo!(),
        }
    };

    match tokio::time::timeout(Duration::from_millis(timeout_ms), connect_fut).await {
        Ok(res) => res,
        Err(_) => Err(ConnectError::Timeout),
    }
}

#[async_trait]
pub trait WSClientHandle: Send {
    async fn send_msg(&mut self, msg: MessageBody) -> Result<(), SokettoError>;
    async fn close(&mut self) -> Result<(), SokettoError>;
    fn dismiss_event_loop(&self);
    #[cfg(test)]
    fn is_event_loop_spinning(&self) -> bool;
}

pub struct WSClientHandleReal {
    ws_sender: Box<dyn WSSenderWrapper>,
    listener_event_loop_abort_handle: AbortHandle,
}

impl Drop for WSClientHandleReal {
    fn drop(&mut self) {
        self.dismiss_event_loop()
    }
}

#[async_trait]
pub trait WSSenderWrapper: Send {
    async fn send_text_owned(&mut self, data: String)-> Result<(), SokettoError>;
    async fn flush(&mut self) -> Result<(), SokettoError>;
    async fn close(&mut self) -> Result<(), SokettoError>;
}

pub struct WSSenderWrapperReal {
    sender: WSSender
}

#[async_trait]
impl WSSenderWrapper for WSSenderWrapperReal {
    async fn send_text_owned(&mut self, data: String) -> Result<(), SokettoError> {
        self.sender.send_text_owned(data).await
    }

    async fn flush(&mut self) -> Result<(), SokettoError> {
        self.sender.flush().await
    }

    async fn close(&mut self) -> Result<(), SokettoError> {
        self.sender.close().await
    }
}

impl WSSenderWrapperReal {
    pub fn new(sender: WSSender) -> Self {
        Self {sender}
    }
}

#[async_trait]
impl WSClientHandle for WSClientHandleReal {
    async fn send_msg(&mut self, msg: MessageBody) -> Result<(), SokettoError> {
        let txt = UiTrafficConverter::new_marshal(msg);
        self.ws_sender.send_text_owned(txt).await?;
        self.ws_sender.flush().await
    }

    async fn close(&mut self) -> Result<(), SokettoError> {
        self.ws_sender.close().await
    }

    fn dismiss_event_loop(&self) {
        self.listener_event_loop_abort_handle.abort()
    }

    #[cfg(test)]
    fn is_event_loop_spinning(&self) -> bool {
        !self.listener_event_loop_abort_handle.is_finished()
    }
}

impl WSClientHandleReal {
    pub fn new(ws_sender: Box<dyn WSSenderWrapper>, listener_event_loop_abort_handle: AbortHandle) -> Self {
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
        ClientListenerSpawner::new(self.ws_receiver, message_body_tx, close_sig)
            .spawn()
            .abort_handle()
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
                        Ok(Data::Text(_)) => {
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
                        Err(SokettoError::Closed) => {
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
    use crate::communications::websockets_client::tests::violate_tcp_conn_in_test::set_socket_to_no_linger;
    use masq_lib::messages::{
        FromMessageBody, ToMessageBody, UiCheckPasswordRequest, UiCheckPasswordResponse,
        UiConnectionChangeBroadcast, UiConnectionStage, UiDescriptorRequest, UiDescriptorResponse,
    };
    use masq_lib::test_utils::mock_websockets_server::{MWSSMessage, MockWebSocketsServer};
    use masq_lib::utils::find_free_port;
    use soketto::handshake::server::Response;
    use soketto::handshake::Server;
    use std::os::fd::AsRawFd;
    use std::time::Duration;
    use soketto::base;
    use soketto::connection::Error;
    use tokio::net::TcpListener;
    use tokio::sync::mpsc::error::TryRecvError;
    use tokio::sync::mpsc::unbounded_channel;
    use tokio::time::Instant;
    use crate::test_utils::mocks::WSSenderWrapperMock;

    #[tokio::test]
    async fn listens_and_passes_data_through() {
        let expected_message = UiConnectionChangeBroadcast {
            stage: UiConnectionStage::RouteFound,
        };
        let port = find_free_port();
        let server =
            MockWebSocketsServer::new(port).queue_response(expected_message.clone().tmb(1));
        let server_stop_handle = server.start().await;
        let (_talker_half, listener_half) =
            make_connection_with_timeout(port, WS_CONNECT_TIMEOUT_MS)
                .await
                .unwrap();
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
        server_stop_handle.stop().await;
    }

    #[tokio::test]
    async fn processes_incoming_close_correctly() {
        let port = find_free_port();
        let server_stop_handle = MockWebSocketsServer::new(port).start().await;
        let (_talker_half, listener_half) =
            make_connection_with_timeout(port, WS_CONNECT_TIMEOUT_MS)
                .await
                .unwrap();
        let (message_body_tx, mut message_body_rx) = unbounded_channel();
        let (close_signaler, close_detector) = ClosingStageDetector::make_for_test();
        let subject = ClientListener::new(listener_half);
        let abort_handle = subject
            .start(close_detector.dup_receiver(), message_body_tx)
            .await;

        server_stop_handle.stop().await;
        let conn_closed_announcement = message_body_rx.recv().await.unwrap();

        // This error would travel to the handler of the incoming messages where a close is called
        // on the talker half of the websockets connection
        assert_eq!(conn_closed_announcement, Err(ClientListenerError::Closed));
        let is_spinning = !abort_handle.is_finished();
        assert_eq!(is_spinning, false);
        // Because not ordered from our side
        assert_eq!(close_signaler.is_closing(), false)
    }

    mod violate_tcp_conn_in_test {
        use nix::libc::linger;
        use std::os::fd::RawFd;
        use std::os::raw::c_int;
        use std::os::raw::c_void;

        mod test_sys_call {
            use super::*;

            extern "C" {
                pub fn setsockopt(
                    socket: c_int,
                    level: c_int,
                    name: c_int,
                    value: *const c_void,
                    option_len: u32,
                ) -> c_int;
            }
        }

        #[cfg(unix)]
        pub fn set_socket_to_no_linger(fd: RawFd) {
            // Will cause a sending of TCP RST instead of TCP FIN on a close
            let sol_socket = c_int::from(1);
            let so_linger = c_int::from(13);
            let linger = linger {
                l_onoff: c_int::from(1),
                l_linger: c_int::from(0),
            };
            unsafe {
                test_sys_call::setsockopt(
                    fd,
                    sol_socket,
                    so_linger,
                    &linger as *const linger as *const c_void,
                    std::mem::size_of::<linger>() as u32,
                )
            };
        }

        #[cfg(windows)]
        #[repr(C)]
        pub struct Linger {
            pub l_onoff: u16,
            pub l_linger: u16,
        }

        #[cfg(windows)]
        pub fn set_socket_to_no_linger(socket: RawSocket) {
            // Will cause a sending of TCP RST instead of TCP FIN on a close
            let ws_sol_socket = c_int::from(65535);
            let ws_so_linger = c_int::from(128);
            let linger = Linger {
                l_onoff: 1,
                l_linger: 0,
            };
            unsafe {
                test_sys_call::setsockopt(
                    fd,
                    ws_sol_socket,
                    ws_so_linger,
                    &linger as *const Linger as *const c_void,
                    std::mem::size_of::<Linger>() as u32,
                )
            };
        }
    }

    #[tokio::test]
    async fn processes_broken_connection_correctly() {
        let port = find_free_port();
        let (background_task_ready_tx, background_task_ready_rx) = tokio::sync::oneshot::channel();
        let server_side_join_handle = tokio::task::spawn(async move {
            background_task_ready_tx.send(()).unwrap();
            let listener = TcpListener::bind(SocketAddr::new(localhost(), port))
                .await
                .unwrap();
            let (stream, _) = listener.accept().await.unwrap();
            #[cfg(unix)]
            let handle = stream.as_raw_fd();
            #[cfg(windows)]
            let handle = stream.as_raw_socket();
            let mut server = Server::new(BufReader::new(BufWriter::new(stream.compat())));
            server.add_protocol(NODE_UI_PROTOCOL);
            let req = server.receive_request().await.unwrap();
            let key = req.key();
            server
                .send_response(&Response::Accept {
                    key,
                    protocol: Some(NODE_UI_PROTOCOL),
                })
                .await
                .unwrap();
            set_socket_to_no_linger(handle);
            // Dropping the server which closes the stream
        });
        background_task_ready_rx.await.unwrap();
        let (_talker_half, listener_half) =
            make_connection_with_timeout(port, WS_CONNECT_TIMEOUT_MS)
                .await
                .unwrap();
        let (message_body_tx, mut message_body_rx) = unbounded_channel();
        let (_close_tx, close_sig) = ClosingStageDetector::make_for_test();
        let subject = ClientListener::new(listener_half);
        let abort_handle = subject
            .start(close_sig.dup_receiver(), message_body_tx)
            .await;

        let error = message_body_rx.recv().await.unwrap();

        match &error {
            Err(ClientListenerError::Broken(msg))
                if msg.contains("kind: ConnectionReset, message:") => {}
            _ => panic!("We expected a connection reset error but got: {:?}", error),
        };
        let is_spinning = !abort_handle.is_finished();
        assert_eq!(is_spinning, false);
        server_side_join_handle.await.unwrap();
    }

    #[tokio::test]
    async fn processes_bad_owned_message_correctly() {
        let port = find_free_port();
        let server = MockWebSocketsServer::new(port)
            .queue_faf_owned_message(Data::Binary(10), b"BadMessage".to_vec());
        let _server_stop_handle = server.start().await;
        let (_talker_half, listener_half) =
            make_connection_with_timeout(port, WS_CONNECT_TIMEOUT_MS)
                .await
                .unwrap();
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
        let server = MockWebSocketsServer::new(port)
            .queue_faf_owned_message(Data::Text(5), b"booga".to_vec());
        let _server_stop_handle = server.start().await;
        let (_talker_half, listener_half) =
            make_connection_with_timeout(port, WS_CONNECT_TIMEOUT_MS)
                .await
                .unwrap();
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
        let _stop_handle = server.start().await;
        let (talker_half, _listener_half) =
            make_connection_with_timeout(port, WS_CONNECT_TIMEOUT_MS)
                .await
                .unwrap();
        let ref_counting_object = Arc::new(123);
        let cloned = ref_counting_object.clone();
        let join_handle = tokio::task::spawn(async move {
            let _cloned_moved_in = cloned;
            loop {
                tokio::time::sleep(Duration::from_millis(1000)).await;
            }
        });
        let sender_wrapper = Box::new(WSSenderWrapperReal::new(talker_half));
        let client_handle = WSClientHandleReal::new(sender_wrapper, join_handle.abort_handle());
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
        let _server_stop_handle = server.start().await;
        let (talker_half, listener_half) =
            make_connection_with_timeout(port, WS_CONNECT_TIMEOUT_MS)
                .await
                .unwrap();
        let (message_body_tx, mut message_body_rx) = unbounded_channel();
        let (close_signaler, close_sig) = ClosingStageDetector::make_for_test();
        let subject =
            ClientListenerSpawner::new(listener_half, message_body_tx, close_sig.dup_receiver());
        let join_handle = tokio::task::spawn(async { subject.loop_guts().await });
        let sender_wrapper = Box::new(WSSenderWrapperReal::new(talker_half));
        let mut client_handle = WSClientHandleReal::new(sender_wrapper, join_handle.abort_handle());
        client_handle
            .send_msg(UiDescriptorRequest {}.tmb(1234))
            .await
            .unwrap();
        let received_msg_body = message_body_rx.recv().await.unwrap().unwrap();
        let (received_message, context_id) = UiDescriptorResponse::fmb(received_msg_body).unwrap();

        close_signaler.signalize_close();
        // Making the mock server send another msg
        client_handle
            .send_msg(
                UiCheckPasswordRequest {
                    db_password_opt: None,
                }
                .tmb(4321),
            )
            .await
            .unwrap();

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
        let server_stop_handle = server.start().await;
        let (talker_half, _listener_half) =
            make_connection_with_timeout(port, WS_CONNECT_TIMEOUT_MS)
                .await
                .unwrap();
        let meaningless_event_loop_join_handle = tokio::task::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_millis(1000)).await;
            }
        });
        let sender_wrapper = Box::new(WSSenderWrapperReal::new(talker_half));
        let mut subject = WSClientHandleReal::new(
            sender_wrapper,
            meaningless_event_loop_join_handle.abort_handle(),
        );

        let result = subject.close().await;

        assert!(matches!(result, Ok(())));
        let requests = server_stop_handle.stop().await;
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

    #[tokio::test]
    async fn send_msg_error_at_sending_is_handled(){
        let sender = WSSenderWrapperMock::default().send_text_owned_result(Err(Error::Codec(base::Error::InvalidControlFrameLen)));
        let meaningless_event_loop_join_handle = tokio::task::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_millis(1000)).await;
            }
        });
        let mut subject = WSClientHandleReal::new(
            Box::new(sender),
            meaningless_event_loop_join_handle.abort_handle(),
        );
        let msg = UiDescriptorRequest{}.tmb(1);

        let result = subject.send_msg(msg).await;

        assert!(matches!(result, Err(Error::Codec(base::Error::InvalidControlFrameLen))));
    }
}
