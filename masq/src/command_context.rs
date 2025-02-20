// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::command_context::ContextError::ConnectionRefused;
use crate::communications::connection_manager::{CMBootstrapper, ConnectionManager};
use crate::communications::node_conversation::ClientError;
use crate::terminal::WTermInterfaceDupAndSend;
use async_trait::async_trait;
use masq_lib::arbitrary_id_stamp_in_trait;
use masq_lib::constants::{TIMEOUT_ERROR, UNMARSHAL_ERROR};
use masq_lib::intentionally_blank;
use masq_lib::test_utils::arbitrary_id_stamp::ArbitraryIdStamp;
use masq_lib::ui_gateway::MessageBody;
use std::fmt::{Debug, Formatter};

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
            ClientError::ClosingStage => {
                ContextError::ConnectionDropped("Close being executed".to_string())
            }
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
        let conversation = self.connection.start_conversation().await;
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
        let conversation = self.connection.start_conversation().await;
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
        terminal_interface_opt: Option<Box<dyn WTermInterfaceDupAndSend>>,
        bootstrapper: CMBootstrapper,
    ) -> Result<Self, ContextError> {
        let result = bootstrapper
            .establish_connection_manager(daemon_ui_port, terminal_interface_opt)
            .await;

        let connection = match result {
            Ok(c) => c,
            Err(e) => return Err(ConnectionRefused(format!("{:?}", e))),
        };

        Ok(Self { connection })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command_context::ContextError::{
        ConnectionDropped, ConnectionRefused, PayloadError,
    };
    use masq_lib::messages::{ToMessageBody, UiShutdownRequest, UiShutdownResponse, NODE_UI_PROTOCOL};
    use masq_lib::messages::{UiCrashRequest, UiSetupRequest};
    use masq_lib::test_utils::mock_websockets_server::{MWSSMessage, MockWebSocketsServer, StopStrategy};
    use masq_lib::ui_gateway::MessageBody;
    use masq_lib::ui_gateway::MessagePath::Conversation;
    use masq_lib::ui_traffic_converter::{TrafficConversionError, UnmarshalError};
    use masq_lib::utils::{find_free_port, running_test};
    use tokio_tungstenite::tungstenite::Message;

    #[test]
    fn error_conversion_happy_path() {
        running_test();
        let result: Vec<ContextError> = vec![
            ClientError::FallbackFailed("fallback reason".to_string()),
            ClientError::ClosingStage,
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
                ContextError::ConnectionDropped("Close being executed".to_string()),
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
        let bootstrapper = CMBootstrapper::default();

        let subject = CommandContextReal::new(port, None, bootstrapper)
            .await
            .unwrap();

        assert_eq!(subject.active_port().await, Some(port));
        assert_eq!(subject.connection.is_closing(), false)
    }

    #[tokio::test]
    async fn works_when_server_isnt_present() {
        running_test();
        let port = find_free_port();
        let bootstrapper = CMBootstrapper::default();

        let result = CommandContextReal::new(port, None, bootstrapper).await;

        match result {
            Err(ConnectionRefused(_)) => (),
            Ok(_) => panic!("Succeeded when it should have failed"),
            Err(e) => panic!("Expected ConnectionRefused; got {:?}", e),
        }
    }

    #[tokio::test]
    async fn transact_works_when_everything_is_fine() {
        running_test();
        let port = find_free_port();
        let request = UiShutdownRequest {}.tmb(1);
        let expected_response = UiShutdownResponse {}.tmb(1);
        let server = MockWebSocketsServer::new(port).queue_response(expected_response.clone());
        let server_stop_handle = server.start().await;
        let bootstrapper = CMBootstrapper::default();
        let subject = CommandContextReal::new(port, None, bootstrapper)
            .await
            .unwrap();

        let result = subject.transact(request.clone(), 1000).await;

        assert_eq!(result, Ok(expected_response));
        let mut recorded = server_stop_handle.stop(StopStrategy::Close).await;
        assert_eq!(recorded.requests, vec![MWSSMessage::MessageBody(request)]);
        assert_eq!(recorded.proposed_protocols, vec![NODE_UI_PROTOCOL])
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
        let bootstrapper = CMBootstrapper::default();
        let subject = CommandContextReal::new(port, None, bootstrapper)
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
        let server = MockWebSocketsServer::new(port);
        let server_stop_handle = server.start().await;
        let bootstrapper = CMBootstrapper::default();
        let request = UiSetupRequest { values: vec![] }.tmb(1);
        let subject = CommandContextReal::new(port, None, bootstrapper)
            .await
            .unwrap();
        // TODO have the MockWebsocketServer adapted or write it alternatively without it

        let response = subject.transact(request.clone(), 1000).await;

        match response {
            Err(ConnectionDropped(_)) => (),
            x => panic!("Expected ConnectionDropped; got {:?} instead", x),
        }
        let recorded = server_stop_handle.stop(StopStrategy::Abort).await;
        assert_eq!(recorded.requests, vec![MWSSMessage::MessageBody(request)])
    }

    #[tokio::test]
    async fn send_works_when_everything_fine() {
        running_test();
        let port = find_free_port();
        let server_stop_handle = MockWebSocketsServer::new(port).start().await;
        let bootstrapper = CMBootstrapper::default();
        let subject = CommandContextReal::new(port, None, bootstrapper)
            .await
            .unwrap();
        let msg = UiCrashRequest {
            actor: "Dispatcher".to_string(),
            panic_message: "Message".to_string(),
        }
        .tmb(0);

        let result = subject.send_one_way(msg.clone()).await;

        assert_eq!(result, Ok(()));
        let recorded = server_stop_handle.stop(StopStrategy::Close).await;
        assert_eq!(recorded.requests, vec![MWSSMessage::MessageBody(msg)]);
        assert_eq!(recorded.proposed_protocols, vec![NODE_UI_PROTOCOL])
    }
}
