// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::command_context::ContextError::ConnectionRefused;
use crate::communications::broadcast_handlers::BroadcastHandle;
use crate::communications::connection_manager::{
    ConnectionManager, ConnectionManagerBootstrapper, REDIRECT_TIMEOUT_MILLIS,
};
use crate::communications::node_conversation::ClientError;
use crate::terminal::{WTermInterface, WTermInterfaceImplementingSend};
use async_trait::async_trait;
use masq_lib::constants::{TIMEOUT_ERROR, UNMARSHAL_ERROR};
use masq_lib::ui_gateway::MessageBody;
use std::fmt::{Debug, Formatter};
use std::io;
use std::io::{Read, Write};
use tokio::runtime::Runtime;
use masq_lib::arbitrary_id_stamp_in_trait;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ContextError {
    ConnectionRefused(String),
    ConnectionDropped(String),
    PayloadError(u64, String),
    RedirectFailure(String),
    Other(String),
}

impl From<ClientError> for ContextError {
    fn from(client_error: ClientError) -> Self {
        match client_error {
            ClientError::ConnectionDropped => ContextError::ConnectionDropped(String::new()),
            ClientError::Deserialization(_) => ContextError::PayloadError(
                UNMARSHAL_ERROR,
                "Node or Daemon sent corrupted packet".to_string(),
            ),
            ClientError::NoServer(port, _) => ContextError::ConnectionDropped(format!(
                "No server listening on port {} where it's supposed to be",
                port
            )),
            ClientError::FallbackFailed(e) => ContextError::ConnectionDropped(e),
            ClientError::PacketType(e) => ContextError::PayloadError(
                UNMARSHAL_ERROR,
                format!("Node or Daemon sent unrecognized '{}' packet", e),
            ),
            ClientError::Timeout(ms) => ContextError::PayloadError(
                TIMEOUT_ERROR,
                format!("No response from Node or Daemon after {}ms", ms),
            ),
        }
    }
}

#[async_trait(?Send)]
pub trait CommandContext {
    async fn active_port(&self) -> Option<u16>;
    async fn send_one_way(&self, message: MessageBody) -> Result<(), ContextError>;
    async fn transact(
        &self,
        message: MessageBody,
        timeout_millis: u64,
    ) -> Result<MessageBody, ContextError>;
    fn close(&self);
    arbitrary_id_stamp_in_trait!();
}

pub struct CommandContextReal {
    connection: ConnectionManager,
}

impl Debug for CommandContextReal {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "CommandContextReal")
    }
}

#[async_trait(?Send)]
impl CommandContext for CommandContextReal {
    async fn active_port(&self) -> Option<u16> {
        self.connection.active_ui_port().await
    }

    async fn send_one_way(&self, outgoing_message: MessageBody) -> Result<(), ContextError> {
        let mut conversation = self.connection.start_conversation().await;
        match conversation.send(outgoing_message).await {
            Ok(_) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    async fn transact(
        &self,
        outgoing_message: MessageBody,
        timeout_millis: u64,
    ) -> Result<MessageBody, ContextError> {
        let mut conversation = self.connection.start_conversation().await;
        let incoming_message_result = conversation
            .transact(outgoing_message, timeout_millis)
            .await;
        let incoming_message = match incoming_message_result {
            Err(e) => return Err(e.into()),
            Ok(message) => match message.payload {
                Err((code, msg)) => return Err(ContextError::PayloadError(code, msg)),
                Ok(_) => message,
            },
        };
        Ok(incoming_message)
    }

    fn close(&self) {
        self.connection.close();
    }
}

impl CommandContextReal {
    pub async fn new(
        daemon_ui_port: u16,
        terminal_interface_opt: Option<Box<dyn WTermInterfaceImplementingSend>>,
        bootstrapper: &ConnectionManagerBootstrapper,
    ) -> Result<Self, ContextError> {
        let result = bootstrapper
            .spawn_background_loops(
                daemon_ui_port,
                terminal_interface_opt,
                REDIRECT_TIMEOUT_MILLIS,
            )
            .await;
        let connectors = match result {
            Ok(c) => c,
            Err(e) => return Err(ConnectionRefused(format!("{:?}", e))),
        };
        let connection = ConnectionManager::new(connectors);

        Ok(Self { connection })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command_context::ContextError::{
        ConnectionDropped, ConnectionRefused, PayloadError,
    };
    use crate::communications::broadcast_handlers::BroadcastHandleInactive;
    use crate::test_utils::mocks::StandardBroadcastHandlerFactoryMock;
    use masq_lib::messages::{FromMessageBody, UiCrashRequest, UiSetupRequest};
    use masq_lib::messages::{ToMessageBody, UiShutdownRequest, UiShutdownResponse};
    use masq_lib::test_utils::fake_stream_holder::{ByteArrayReader, ByteArrayWriter};
    use masq_lib::test_utils::mock_websockets_server::MockWebSocketsServer;
    use masq_lib::test_utils::utils::make_rt;
    use masq_lib::ui_gateway::MessageBody;
    use masq_lib::ui_gateway::MessagePath::Conversation;
    use masq_lib::ui_traffic_converter::{TrafficConversionError, UnmarshalError};
    use masq_lib::utils::{find_free_port, running_test};

    #[test]
    fn error_conversion_happy_path() {
        running_test();
        let result: Vec<ContextError> = vec![
            ClientError::FallbackFailed("fallback reason".to_string()),
            ClientError::ConnectionDropped,
            ClientError::NoServer(1234, "blah".to_string()),
            ClientError::Timeout(1234),
            ClientError::Deserialization(UnmarshalError::Critical(
                TrafficConversionError::MissingFieldError("blah".to_string()),
            )),
            ClientError::PacketType("blah".to_string()),
        ]
        .into_iter()
        .map(|e| e.into())
        .collect();

        assert_eq!(
            result,
            vec![
                ContextError::ConnectionDropped("fallback reason".to_string()),
                ContextError::ConnectionDropped("".to_string()),
                ContextError::ConnectionDropped(
                    "No server listening on port 1234 where it's supposed to be".to_string()
                ),
                ContextError::PayloadError(
                    TIMEOUT_ERROR,
                    "No response from Node or Daemon after 1234ms".to_string()
                ),
                ContextError::PayloadError(
                    UNMARSHAL_ERROR,
                    "Node or Daemon sent corrupted packet".to_string()
                ),
                ContextError::PayloadError(
                    UNMARSHAL_ERROR,
                    "Node or Daemon sent unrecognized 'blah' packet".to_string()
                ),
            ]
        );
    }

    #[tokio::test]
    async fn is_created_correctly_initially() {
        running_test();
        let port = find_free_port();
        let server = MockWebSocketsServer::new(port);
        let handle = server.start().await;
        let standard_broadcast_handler_factory =
            Box::new(StandardBroadcastHandlerFactoryMock::default());
        let bootstrapper = ConnectionManagerBootstrapper::default();

        let subject = CommandContextReal::new(port, None, &bootstrapper)
            .await
            .unwrap();

        assert_eq!(subject.active_port().await, Some(port));
        assert_eq!(subject.connection.is_closing(), false)
    }

    #[test]
    fn transact_works_when_everything_is_fine() {
        todo!("should I save this test???")
        // running_test();
        // let port = find_free_port();
        // let stdout = ByteArrayWriter::new();
        // let stdout_arc = stdout.inner_arc();
        // let stderr = ByteArrayWriter::new();
        // let stderr_arc = stderr.inner_arc();
        // let server = MockWebSocketsServer::new(port).queue_response(UiShutdownResponse {}.tmb(1));
        // let rt = make_rt();
        // let stop_handle = rt.block_on(server.start());
        // let standard_broadcast_handler_factory =
        //     Box::new(StandardBroadcastHandlerFactoryMock::default());
        // let bootstrapper = ConnectionManagerBootstrapper::default();
        // let mut subject = CommandContextReal::new(port, &rt, None, &bootstrapper).unwrap();
        // let mut term_interface = NonInteractiveWTermInterface::new(Box::new(stdout), Box::new(stderr));
        //
        // let response = subject.transact(UiShutdownRequest {}.tmb(1),1000).unwrap();
        // write!(term_interface.stdout(), "This is stdout.").unwrap();
        // write!(term_interface.stderr(), "This is stderr.").unwrap();
        //
        // assert_eq!(
        //     UiShutdownResponse::fmb(response).unwrap(),
        //     (UiShutdownResponse {}, 1)
        // );
        // assert_eq!(
        //     stdout_arc.lock().unwrap().get_string(),
        //     "This is stdout.".to_string()
        // );
        // assert_eq!(
        //     stderr_arc.lock().unwrap().get_string(),
        //     "This is stderr.".to_string()
        // );
        // stop_handle.stop();
    }

    #[tokio::test]
    async fn works_when_server_isnt_present() {
        running_test();
        let port = find_free_port();
        let broadcast_handle = BroadcastHandleInactive;
        let bootstrapper = ConnectionManagerBootstrapper::default();

        let result = CommandContextReal::new(port, None, &bootstrapper).await;

        match result {
            Err(ConnectionRefused(_)) => (),
            Ok(_) => panic!("Succeeded when it should have failed"),
            Err(e) => panic!("Expected ConnectionRefused; got {:?}", e),
        }
    }

    #[tokio::test]
    async fn transact_works_when_server_sends_payload_error() {
        running_test();
        let port = find_free_port();
        let server = MockWebSocketsServer::new(port).queue_response(MessageBody {
            opcode: "setup".to_string(),
            path: Conversation(1),
            payload: Err((101, "booga".to_string())),
        });
        let stop_handle = server.start().await;
        let broadcast_handle = BroadcastHandleInactive;
        let bootstrapper = ConnectionManagerBootstrapper::default();
        let mut subject = CommandContextReal::new(port, None, &bootstrapper)
            .await
            .unwrap();

        let response = subject
            .transact(UiSetupRequest { values: vec![] }.tmb(1), 1000)
            .await;

        assert_eq!(response, Err(PayloadError(101, "booga".to_string())));
    }

    #[tokio::test]
    async fn transact_works_when_server_sends_connection_error() {
        running_test();
        let port = find_free_port();
        let server = MockWebSocketsServer::new(port).queue_string("disconnect");
        let stop_handle = server.start().await;
        let broadcast_handle = BroadcastHandleInactive;
        let bootstrapper = ConnectionManagerBootstrapper::default();
        let mut subject = CommandContextReal::new(port, None, &bootstrapper)
            .await
            .unwrap();

        let response = subject
            .transact(UiSetupRequest { values: vec![] }.tmb(1), 1000)
            .await;

        match response {
            Err(ConnectionDropped(_)) => (),
            x => panic!("Expected ConnectionDropped; got {:?} instead", x),
        }
    }

    #[test]
    fn send_works_when_everythings_fine() {
        todo!("should I preserve this test?");
        // running_test();
        // let port = find_free_port();
        // let stdin = ByteArrayReader::new(b"This is stdin.");
        // let stdout = ByteArrayWriter::new();
        // let stdout_arc = stdout.inner_arc();
        // let stderr = ByteArrayWriter::new();
        // let stderr_arc = stderr.inner_arc();
        // let server = MockWebSocketsServer::new(port);
        // let rt = make_rt();
        // let stop_handle = rt.block_on(server.start());
        // let broadcast_handle = BroadcastHandleInactive;
        // let bootstrapper = ConnectionManagerBootstrapper::default();
        // let subject_result = CommandContextReal::new(port, &rt, None, &bootstrapper);
        // let mut subject = subject_result.unwrap();
        // subject.stdin = Box::new(stdin);
        // subject.stdout = Box::new(stdout);
        // subject.stderr = Box::new(stderr);
        // let msg = UiCrashRequest {
        //     actor: "Dispatcher".to_string(),
        //     panic_message: "Message".to_string(),
        // }
        // .tmb(0);
        //
        // let result = subject.send_one_way(msg);
        //
        // assert_eq!(result, Ok(()));
        // let mut input = String::new();
        // subject.stdin().read_to_string(&mut input).unwrap();
        // write!(subject.stdout(), "This is stdout.").unwrap();
        // write!(subject.stderr(), "This is stderr.").unwrap();
        //
        // assert_eq!(input, "This is stdin.".to_string());
        // assert_eq!(
        //     stdout_arc.lock().unwrap().get_string(),
        //     "This is stdout.".to_string()
        // );
        // assert_eq!(
        //     stderr_arc.lock().unwrap().get_string(),
        //     "This is stderr.".to_string()
        // );
        // stop_handle.stop();
    }
}
