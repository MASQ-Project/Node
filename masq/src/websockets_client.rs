// Copyright (c) 2019-2020, MASQ (https://masq.ai). All rights reserved.

use crate::websockets_client::ClientError::{
    ConnectionDropped, Deserialization, MessageType, NoServer, PacketType,
};
use masq_lib::messages::{ToMessageBody, NODE_UI_PROTOCOL};
use masq_lib::ui_gateway::MessagePath::{OneWay, TwoWay};
use masq_lib::ui_gateway::MessageTarget::ClientId;
use masq_lib::ui_gateway::{MessagePath, NodeFromUiMessage, NodeToUiMessage};
use masq_lib::ui_traffic_converter::{UiTrafficConverter, UnmarshalError};
use masq_lib::utils::localhost;
use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use websocket::sync::Client;
use websocket::{ClientBuilder, OwnedMessage};

pub const BROADCAST_CONTEXT_ID: u64 = 0;

#[derive(Clone, Debug, PartialEq)]
pub enum ClientError {
    NoServer(u16, String),
    ConnectionDropped(String),
    PacketType(String),
    Deserialization(UnmarshalError),
    MessageType(String, MessagePath),
}

pub struct NodeConnectionInner {
    next_context_id: u64,
    client: Client<TcpStream>,
}

pub struct NodeConnection {
    inner_arc: Arc<Mutex<NodeConnectionInner>>,
}

impl Drop for NodeConnection {
    fn drop(&mut self) {
        if let Ok(mut guard) = self.inner_arc.lock() {
            let _ = guard.client.send_message(&OwnedMessage::Close(None));
        }
    }
}

impl NodeConnection {
    pub fn new(port: u16) -> Result<NodeConnection, ClientError> {
        let builder =
            ClientBuilder::new(format!("ws://{}:{}", localhost(), port).as_str()).expect("Bad URL");
        let client = match builder.add_protocol(NODE_UI_PROTOCOL).connect_insecure() {
            Err(e) => return Err(NoServer(port, format!("{:?}", e))),
            Ok(c) => c,
        };
        let inner_arc = Arc::new(Mutex::new(NodeConnectionInner {
            client,
            next_context_id: BROADCAST_CONTEXT_ID + 1,
        }));
        Ok(NodeConnection { inner_arc })
    }

    pub fn start_conversation(&self) -> NodeConversation {
        let inner_arc = self.inner_arc.clone();
        let context_id = {
            let mut inner = inner_arc.lock().expect("NodeConnection is poisoned");
            let context_id = inner.next_context_id;
            inner.next_context_id += 1;
            context_id
        };
        NodeConversation {
            context_id,
            inner_arc,
        }
    }

    #[allow(dead_code)]
    pub fn establish_broadcast_receiver<F>(&self, _receiver: F) -> Result<(), String>
    where
        F: Fn() -> NodeToUiMessage,
    {
        unimplemented!();
    }
}

pub struct NodeConversation {
    context_id: u64,
    inner_arc: Arc<Mutex<NodeConnectionInner>>,
}

impl Drop for NodeConversation {
    fn drop(&mut self) {
        // TODO: When the client goes asynchronous, this will have to delete the conversation from the connection's map.
    }
}

impl NodeConversation {
    pub fn context_id(&self) -> u64 {
        self.context_id
    }

    #[allow(dead_code)]
    pub fn establish_receiver<F>(/*mut*/ self, _receiver: F) -> Result<(), ClientError>
    where
        F: Fn() -> NodeToUiMessage,
    {
        unimplemented!();
    }

    // Warning: both the client_id and the context_id are completely ignored by this method.
    pub fn transact(
        &mut self,
        mut outgoing_msg: NodeFromUiMessage,
    ) -> Result<NodeToUiMessage, ClientError> {
        if outgoing_msg.body.path == OneWay {
            return Err(MessageType(
                outgoing_msg.body.opcode,
                outgoing_msg.body.path,
            ));
        } else {
            outgoing_msg.body.path = TwoWay(self.context_id());
        }
        if let Err(e) = self.send(outgoing_msg) {
            return Err(e); // Don't know how to drive this line
        }
        self.receive()
    }

    pub fn close(&mut self) {
        // Nothing yet
    }

    fn send(&mut self, outgoing_msg: NodeFromUiMessage) -> Result<(), ClientError> {
        let outgoing_msg_json = UiTrafficConverter::new_marshal_from_ui(outgoing_msg);
        self.send_string(outgoing_msg_json)
    }

    fn send_string(&mut self, string: String) -> Result<(), ClientError> {
        let client = &mut self.inner_arc.lock().expect("Connection poisoned").client;
        if let Err(e) = client.send_message(&OwnedMessage::Text(string)) {
            Err(ConnectionDropped(format!("{:?}", e)))
        } else {
            Ok(())
        }
    }

    fn receive(&mut self) -> Result<NodeToUiMessage, ClientError> {
        let client = &mut self.inner_arc.lock().expect("Connection poisoned").client;
        let incoming_msg = client.recv_message();
        let incoming_msg_json = match incoming_msg {
            Ok(OwnedMessage::Text(json)) => json,
            Ok(x) => return Err(PacketType(format!("{:?}", x))),
            Err(e) => return Err(ConnectionDropped(format!("{:?}", e))),
        };
        match UiTrafficConverter::new_unmarshal_to_ui(&incoming_msg_json, ClientId(0)) {
            Ok(m) => Ok(m),
            Err(e) => Err(Deserialization(e)),
        }
    }
}

// Warning: this function does not properly set the context_id field.
#[allow(dead_code)]
pub fn nfum<T: ToMessageBody>(tmb: T) -> NodeFromUiMessage {
    NodeFromUiMessage {
        client_id: 0,
        body: tmb.tmb(0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::mock_websockets_server::MockWebSocketsServer;
    use crate::websockets_client::ClientError::{ConnectionDropped, NoServer};
    use masq_lib::messages::{FromMessageBody, UiUnmarshalError};
    use masq_lib::messages::{UiSetup, UiSetupValue};
    use masq_lib::ui_gateway::MessageBody;
    use masq_lib::ui_gateway::MessagePath::TwoWay;
    use masq_lib::ui_traffic_converter::TrafficConversionError::JsonSyntaxError;
    use masq_lib::ui_traffic_converter::UnmarshalError::Critical;
    use masq_lib::utils::find_free_port;

    #[allow(dead_code)]
    pub fn nftm1<T: ToMessageBody>(tmb: T) -> NodeToUiMessage {
        assert_eq!(tmb.is_two_way(), false);
        NodeToUiMessage {
            target: ClientId(0),
            body: tmb.tmb(0),
        }
    }

    pub fn nftm2<T: ToMessageBody>(context_id: u64, tmb: T) -> NodeToUiMessage {
        assert_eq!(tmb.is_two_way(), true);
        NodeToUiMessage {
            target: ClientId(0),
            body: tmb.tmb(context_id),
        }
    }

    #[allow(dead_code)]
    pub fn nftme1(opcode: &str, code: u64, msg: &str) -> NodeToUiMessage {
        NodeToUiMessage {
            target: ClientId(0),
            body: MessageBody {
                opcode: opcode.to_string(),
                path: OneWay,
                payload: Err((code, msg.to_string())),
            },
        }
    }

    pub fn nftme2(opcode: &str, context_id: u64, code: u64, msg: &str) -> NodeToUiMessage {
        NodeToUiMessage {
            target: ClientId(0),
            body: MessageBody {
                opcode: opcode.to_string(),
                path: TwoWay(context_id),
                payload: Err((code, msg.to_string())),
            },
        }
    }

    #[test]
    fn connection_works_when_no_server_exists() {
        let port = find_free_port();

        let error = NodeConnection::new(port).err().unwrap();

        match error {
            NoServer(p, _) if p == port => (),
            x => panic!("Expected NoServer; got {:?} instead", x),
        }
    }

    #[test]
    fn connection_works_when_protocol_doesnt_match() {
        let port = find_free_port();
        let mut server = MockWebSocketsServer::new(port);
        server.protocol = "Booga".to_string();
        server.start();

        let error = NodeConnection::new(port).err().unwrap();

        match error {
            NoServer(p, _) if p == port => (),
            x => panic!("Expected NoServer; got {:?} instead", x),
        }
    }

    #[test]
    fn dropping_connection_sends_a_close() {
        let port = find_free_port();
        let server = MockWebSocketsServer::new(port);
        let stop_handle = server.start();

        {
            let _ = NodeConnection::new(port).unwrap();
        }

        let results = stop_handle.stop();
        assert_eq!(results, vec![Err("Close(None)".to_string())])
    }

    #[test]
    fn cant_transact_with_a_one_way_message() {
        let port = find_free_port();
        let server = MockWebSocketsServer::new(port);
        let stop_handle = server.start();
        let connection = NodeConnection::new(port).unwrap();
        let mut subject = connection.start_conversation();

        let result = subject.transact(nfum(UiUnmarshalError {
            message: "".to_string(),
            bad_data: "".to_string(),
        }));

        assert_eq!(
            result,
            Err(MessageType("unmarshalError".to_string(), OneWay))
        );
        stop_handle.stop();
    }

    #[test]
    fn handles_connection_dropped_by_server_before_receive() {
        let port = find_free_port();
        let server = MockWebSocketsServer::new(port).queue_string("disconnect"); // magic value that causes disconnection
        let _ = server.start();
        let connection = NodeConnection::new(port).unwrap();
        let mut subject = connection.start_conversation();

        let result = subject.transact(nfum(UiSetup { values: vec![] }));

        match result {
            Err(ConnectionDropped(_)) => (),
            x => panic!("Expected ConnectionDropped; got {:?} instead", x),
        }
    }

    #[test]
    fn handles_being_sent_something_other_than_text() {
        let port = find_free_port();
        let server = MockWebSocketsServer::new(port).queue_string("disconnect"); // magic value that causes disconnection
        let stop_handle = server.start();
        let connection = NodeConnection::new(port).unwrap();
        let mut subject = connection.start_conversation();
        stop_handle.stop();

        let result = subject.receive();

        if let Err(error) = result {
            assert_eq!(error, PacketType("Close(None)".to_string()));
        } else {
            assert!(false, "Expected Close(None); got {:?}", result);
        }
    }

    #[test]
    fn handles_being_sent_bad_syntax() {
        let port = find_free_port();
        let server = MockWebSocketsServer::new(port).queue_string("} -- bad syntax -- {");
        let stop_handle = server.start();
        let connection = NodeConnection::new(port).unwrap();
        let mut subject = connection.start_conversation();

        let result = subject.transact(nfum(UiSetup { values: vec![] }));

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
        let server =
            MockWebSocketsServer::new(port).queue_response(nftme2("setup", 1, 101, "booga"));
        let stop_handle = server.start();
        let connection = NodeConnection::new(port).unwrap();
        let mut subject = connection.start_conversation();

        let result = subject.transact(nfum(UiSetup { values: vec![] })).unwrap();

        stop_handle.stop();
        assert_eq!(result.body.payload, Err((101, "booga".to_string())));
    }

    #[test]
    fn single_cycle_conversation_works_as_expected() {
        let port = find_free_port();
        let server = MockWebSocketsServer::new(port).queue_response(nftm2(
            1,
            UiSetup {
                values: vec![UiSetupValue::new("type", "response")],
            },
        ));
        let stop_handle = server.start();
        let connection = NodeConnection::new(port).unwrap();
        let mut subject = connection.start_conversation();

        let response_body = subject
            .transact(nfum(UiSetup {
                values: vec![UiSetupValue::new("type", "request")],
            }))
            .unwrap()
            .body;

        let response = UiSetup::fmb(response_body).unwrap();
        let requests = stop_handle.stop();
        assert_eq!(
            requests,
            vec![Ok(NodeFromUiMessage {
                client_id: 0,
                body: UiSetup {
                    values: vec![UiSetupValue::new("type", "request")]
                }
                .tmb(1)
            })]
        );
        assert_eq!(
            response,
            (
                UiSetup {
                    values: vec![UiSetupValue::new("type", "response")]
                },
                1
            )
        );
    }

    #[test]
    #[ignore] // Unignore this when it's time to go multithreaded
    fn overlapping_conversations_work_as_expected() {
        let port = find_free_port();
        let server = MockWebSocketsServer::new(port)
            .queue_response(NodeToUiMessage {
                target: ClientId(0),
                body: UiSetup {
                    values: vec![UiSetupValue::new("type", "conversation 2 response")],
                }
                .tmb(2),
            })
            .queue_response(NodeToUiMessage {
                target: ClientId(0),
                body: UiSetup {
                    values: vec![UiSetupValue::new("type", "conversation 1 response")],
                }
                .tmb(1),
            });
        let stop_handle = server.start();
        let connection = NodeConnection::new(port).unwrap();
        let mut subject1 = connection.start_conversation();
        let mut subject2 = connection.start_conversation();

        let response1_body = subject1
            .transact(nfum(UiSetup {
                values: vec![UiSetupValue::new("type", "conversation 1 request")],
            }))
            .unwrap()
            .body;
        let response2_body = subject2
            .transact(nfum(UiSetup {
                values: vec![UiSetupValue::new("type", "conversation 2 request")],
            }))
            .unwrap()
            .body;

        assert_eq!(subject1.context_id(), 1);
        assert_eq!(subject2.context_id(), 2);
        let requests = stop_handle.stop();
        assert_eq!(
            requests,
            vec![
                Ok(NodeFromUiMessage {
                    client_id: 0,
                    body: UiSetup {
                        values: vec![UiSetupValue::new("type", "conversation 1 request")]
                    }
                    .tmb(1)
                }),
                Ok(NodeFromUiMessage {
                    client_id: 0,
                    body: UiSetup {
                        values: vec![UiSetupValue::new("type", "conversation 2 request")]
                    }
                    .tmb(2)
                }),
            ]
        );
        assert_eq!(response1_body.path, TwoWay(1));
        assert_eq!(
            UiSetup::fmb(response1_body).unwrap().0,
            UiSetup {
                values: vec![UiSetupValue::new("type", "conversation 1 response")]
            }
        );
        assert_eq!(response2_body.path, TwoWay(2));
        assert_eq!(
            UiSetup::fmb(response2_body).unwrap().0,
            UiSetup {
                values: vec![UiSetupValue::new("type", "conversation 2 response")]
            }
        );
    }
}
