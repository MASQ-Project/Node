// Copyright (c) 2019-2020, MASQ (https://masq.ai). All rights reserved.

use crate::communications::client_handle::ClientHandle;
use crate::communications::node_connection::ClientError;
use crate::communications::node_connection::ClientError::MessageType;
use masq_lib::ui_gateway::MessageBody;
use masq_lib::ui_gateway::MessagePath::{Conversation, FireAndForget};
use std::sync::{Arc, Mutex};

pub struct NodeConversation {
    context_id: u64,
    client_handle_arc: Arc<Mutex<ClientHandle>>,
}

impl Drop for NodeConversation {
    fn drop(&mut self) {
        // TODO: When the client goes asynchronous, this will have to delete the conversation from the connection's map.
    }
}

impl NodeConversation {
    pub fn new(context_id: u64, client_handle_arc: &Arc<Mutex<ClientHandle>>) -> Self {
        Self {
            context_id,
            client_handle_arc: client_handle_arc.clone(),
        }
    }

    pub fn context_id(&self) -> u64 {
        self.context_id
    }

    #[allow(dead_code)]
    pub fn establish_receiver<F>(/*mut*/ self, _receiver: F) -> Result<(), ClientError>
    where
        F: Fn() -> MessageBody,
    {
        unimplemented!();
    }

    // Warning: the context_id is completely ignored by this method.
    pub fn transact(&self, mut outgoing_msg: MessageBody) -> Result<MessageBody, ClientError> {
        if outgoing_msg.path == FireAndForget {
            return Err(MessageType(outgoing_msg.opcode, outgoing_msg.path));
        } else {
            outgoing_msg.path = Conversation(self.context_id());
        }
        let mut client_handle = self.client_handle_arc.lock().expect("Connection poisoned");
        if let Err(e) = client_handle.send(outgoing_msg) {
            return Err(e); // Don't know how to drive this line
        }
        client_handle.receive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(not(target_os = "windows"))]
    use crate::communications::node_connection::ClientError::PacketType;
    use crate::communications::node_connection::ClientError::{ConnectionDropped, Deserialization};
    use crate::communications::node_connection::NodeConnection;
    use crate::test_utils::mock_websockets_server::MockWebSocketsServer;
    use masq_lib::messages::ToMessageBody;
    use masq_lib::messages::UiSetupResponseValueStatus::Set;
    use masq_lib::messages::{FromMessageBody, UiShutdownRequest};
    use masq_lib::messages::{UiSetupRequest, UiSetupResponse, UiUnmarshalError};
    use masq_lib::messages::{UiSetupRequestValue, UiSetupResponseValue};
    use masq_lib::ui_gateway::MessagePath;
    use masq_lib::ui_gateway::MessagePath::Conversation;
    use masq_lib::ui_traffic_converter::TrafficConversionError::JsonSyntaxError;
    use masq_lib::ui_traffic_converter::UnmarshalError::Critical;
    use masq_lib::utils::find_free_port;

    #[test]
    fn cant_transact_with_a_one_way_message() {
        let port = find_free_port();
        let server = MockWebSocketsServer::new(port);
        let stop_handle = server.start();
        let mut connection = NodeConnection::new(0, port).unwrap();
        let subject = connection.start_conversation();

        let result = subject.transact(
            UiUnmarshalError {
                message: "".to_string(),
                bad_data: "".to_string(),
            }
            .tmb(1),
        );

        assert_eq!(
            result,
            Err(MessageType("unmarshalError".to_string(), FireAndForget))
        );
        stop_handle.stop();
    }

    #[test]
    fn handles_connection_dropped_by_node_before_receive_when_daemon_is_still_alive() {
        let node_port = find_free_port();
        let node_server = MockWebSocketsServer::new(node_port).queue_string("disconnect"); // magic value that causes disconnection
        let node_handle = node_server.start();
        let daemon_port = find_free_port();
        let daemon_server = MockWebSocketsServer::new(daemon_port);
        let daemon_handle = daemon_server.start();
        let mut connection = NodeConnection::new(daemon_port, node_port).unwrap();
        let subject = connection.start_conversation();

        let result = subject.transact(UiShutdownRequest {}.tmb(1));

        match result {
            Err(ConnectionDropped(_)) => (),
            x => panic!("Expected ConnectionDropped, got {:?}", x),
        }
        assert_eq!(daemon_handle.kill().len(), 0);
        node_handle.kill();
    }

    #[test]
    fn handles_connection_dropped_by_node_before_receive_when_daemon_is_dead() {
        let node_port = find_free_port();
        let node_server = MockWebSocketsServer::new(node_port).queue_string("disconnect"); // magic value that causes disconnection
        let node_handle = node_server.start();
        let daemon_port = find_free_port();
        let mut connection = NodeConnection::new(daemon_port, node_port).unwrap();
        let subject = connection.start_conversation();

        let error = subject.transact(UiShutdownRequest {}.tmb(1)).err().unwrap();

        match error {
            ClientError::FallbackFailed(_) => (),
            x => panic!("Expected FallbackFailed; got {:?}", x),
        }
        node_handle.kill();
    }

    #[test]
    fn handles_connection_dropped_by_node_before_transmit_when_daemon_is_still_alive() {
        let node_port = find_free_port();
        let node_server = MockWebSocketsServer::new(node_port);
        let node_stop_handle = node_server.start();
        let daemon_port = find_free_port();
        let daemon_server = MockWebSocketsServer::new(daemon_port);
        let daemon_stop_handle = daemon_server.start();
        let mut connection = NodeConnection::new(daemon_port, node_port).unwrap();
        node_stop_handle.kill();
        let subject = connection.start_conversation();

        let result = subject.transact(UiShutdownRequest {}.tmb(1));

        match result {
            Err(ConnectionDropped(_)) => (),
            x => panic!("Expected ConnectionDropped, got {:?}", x),
        }
        assert_eq!(daemon_stop_handle.kill().len(), 0);
    }

    #[test]
    fn handles_connection_dropped_by_node_before_transmit_when_daemon_is_dead() {
        let node_port = find_free_port();
        let node_server = MockWebSocketsServer::new(node_port);
        let node_stop_handle = node_server.start();
        let daemon_port = find_free_port();
        let mut connection = NodeConnection::new(daemon_port, node_port).unwrap();
        node_stop_handle.kill();
        let subject = connection.start_conversation();

        let error = subject.transact(UiShutdownRequest {}.tmb(1)).err().unwrap();

        match error {
            ClientError::FallbackFailed(msg) => assert_eq!(
                msg.starts_with("Both Node and Daemon have terminated:"),
                true
            ),
            x => panic!("Expected ConnectionDropped; got {:?}", x),
        }
    }

    #[test]
    fn handles_being_sent_something_other_than_text() {
        let port = find_free_port();
        let server = MockWebSocketsServer::new(port).queue_string("disconnect"); // magic value that causes disconnection
        let stop_handle = server.start();
        let mut connection = NodeConnection::new(port, port).unwrap();
        let subject = connection.start_conversation();
        stop_handle.stop();

        let error = subject.transact(UiShutdownRequest {}.tmb(1)).err().unwrap();

        #[cfg(not(target_os = "windows"))]
        {
            assert_eq!(error, PacketType("Close(None)".to_string()));
        }

        #[cfg(target_os = "windows")]
        {
            match error {
                // ...wondering whether this is right or not...
                ClientError::FallbackFailed(s) => {
                    assert_eq!(s.contains("Daemon has terminated:"), true)
                }
                x => panic!("Expected ClientError::FallbackFailed; got {:?}", x),
            }
        }
    }

    #[test]
    fn handles_being_sent_bad_syntax() {
        let port = find_free_port();
        let server = MockWebSocketsServer::new(port).queue_string("} -- bad syntax -- {");
        let stop_handle = server.start();
        let mut connection = NodeConnection::new(0, port).unwrap();
        let subject = connection.start_conversation();

        let result = subject.transact(UiSetupRequest { values: vec![] }.tmb(1));

        stop_handle.stop();
        assert_eq!(
            result,
            Err(Deserialization(Critical(JsonSyntaxError(
                "Error(\"expected value\", line: 1, column: 1)".to_string()
            ))))
        );
    }

    #[test]
    fn handles_being_sent_a_payload_error() {
        let port = find_free_port();
        let server = MockWebSocketsServer::new(port).queue_response(MessageBody {
            opcode: "setup".to_string(),
            path: MessagePath::Conversation(101),
            payload: Err((101, "booga".to_string())),
        });
        let stop_handle = server.start();
        let mut connection = NodeConnection::new(0, port).unwrap();
        let subject = connection.start_conversation();

        let result = subject
            .transact(UiSetupRequest { values: vec![] }.tmb(1))
            .unwrap();

        stop_handle.stop();
        assert_eq!(result.payload, Err((101, "booga".to_string())));
    }

    #[test]
    fn single_cycle_conversation_works_as_expected() {
        let port = find_free_port();
        let server = MockWebSocketsServer::new(port).queue_response(
            UiSetupResponse {
                running: true,
                values: vec![UiSetupResponseValue::new("type", "response", Set)],
                errors: vec![("parameter".to_string(), "reason".to_string())],
            }
            .tmb(1),
        );
        let stop_handle = server.start();
        let mut connection = NodeConnection::new(0, port).unwrap();
        let subject = connection.start_conversation();

        let response_body = subject
            .transact(
                UiSetupRequest {
                    values: vec![UiSetupRequestValue::new("type", "request")],
                }
                .tmb(1),
            )
            .unwrap();

        let response = UiSetupResponse::fmb(response_body).unwrap();
        let requests = stop_handle.stop();
        assert_eq!(
            requests,
            vec![Ok(UiSetupRequest {
                values: vec![UiSetupRequestValue::new("type", "request")]
            }
            .tmb(1))]
        );
        assert_eq!(
            response,
            (
                UiSetupResponse {
                    running: true,
                    values: vec![UiSetupResponseValue::new("type", "response", Set)],
                    errors: vec![("parameter".to_string(), "reason".to_string())],
                },
                1
            )
        );
    }

    #[test]
    #[ignore]
    fn overlapping_conversations_work_as_expected() {
        let port = find_free_port();
        let server = MockWebSocketsServer::new(port)
            .queue_response(
                UiSetupResponse {
                    running: false,
                    values: vec![UiSetupResponseValue::new(
                        "type",
                        "conversation 2 response",
                        Set,
                    )],
                    errors: vec![],
                }
                .tmb(2),
            )
            .queue_response(
                UiSetupResponse {
                    running: true,
                    values: vec![UiSetupResponseValue::new(
                        "type",
                        "conversation 1 response",
                        Set,
                    )],
                    errors: vec![],
                }
                .tmb(1),
            );
        let stop_handle = server.start();
        let mut connection = NodeConnection::new(0, port).unwrap();
        let subject1 = connection.start_conversation();
        let subject2 = connection.start_conversation();

        let response1_body = subject1
            .transact(
                UiSetupRequest {
                    values: vec![UiSetupRequestValue::new("type", "conversation 1 request")],
                }
                .tmb(1),
            )
            .unwrap();
        let response2_body = subject2
            .transact(
                UiSetupRequest {
                    values: vec![UiSetupRequestValue::new("type", "conversation 2 request")],
                }
                .tmb(2),
            )
            .unwrap();

        assert_eq!(subject1.context_id(), 1);
        assert_eq!(subject2.context_id(), 2);
        let requests = stop_handle.stop();
        assert_eq!(
            requests,
            vec![
                Ok(UiSetupRequest {
                    values: vec![UiSetupRequestValue::new("type", "conversation 1 request")]
                }
                .tmb(1)),
                Ok(UiSetupRequest {
                    values: vec![UiSetupRequestValue::new("type", "conversation 2 request")]
                }
                .tmb(2)),
            ]
        );
        assert_eq!(response1_body.path, Conversation(1));
        assert_eq!(
            UiSetupResponse::fmb(response1_body).unwrap().0,
            UiSetupResponse {
                running: false,
                values: vec![UiSetupResponseValue::new(
                    "type",
                    "conversation 1 response",
                    Set
                )],
                errors: vec![],
            }
        );
        assert_eq!(response2_body.path, Conversation(2));
        assert_eq!(
            UiSetupResponse::fmb(response2_body).unwrap().0,
            UiSetupResponse {
                running: true,
                values: vec![UiSetupResponseValue::new(
                    "type",
                    "conversation 2 response",
                    Set
                )],
                errors: vec![],
            }
        );
    }
}
