// Copyright (c) 2019-2020, MASQ (https://masq.ai). All rights reserved.

use crate::communications::client_handle::ClientHandle;
use crate::communications::node_conversation::NodeConversation;
use masq_lib::ui_gateway::{MessageBody, MessagePath};
use masq_lib::ui_traffic_converter::UnmarshalError;
use std::sync::{Arc, Mutex};

pub const BROADCAST_CONTEXT_ID: u64 = 0;

#[derive(Clone, Debug, PartialEq)]
pub enum ClientError {
    NoServer(u16, String),
    ConnectionDropped(String),
    FallbackFailed(String),
    PacketType(String),
    Deserialization(UnmarshalError),
    MessageType(String, MessagePath),
}

pub struct NodeConnection {
    active_ui_port: u16,
    next_context_id: u64,
    client_handle_arc: Arc<Mutex<ClientHandle>>,
}

impl Drop for NodeConnection {
    fn drop(&mut self) {
        if let Ok(mut guard) = self.client_handle_arc.lock() {
            guard.close();
        }
    }
}

impl NodeConnection {
    pub fn new(daemon_ui_port: u16, active_ui_port: u16) -> Result<NodeConnection, ClientError> {
        let client_handle = ClientHandle::try_new(daemon_ui_port, active_ui_port)?;
        let client_handle_arc = Arc::new(Mutex::new(client_handle));
        Ok(NodeConnection {
            active_ui_port,
            next_context_id: BROADCAST_CONTEXT_ID + 1,
            client_handle_arc,
        })
    }

    pub fn daemon_ui_port(&self) -> u16 {
        self.client_handle_arc
            .lock()
            .expect("NodeConnection is poisoned")
            .daemon_ui_port()
    }

    pub fn active_ui_port(&self) -> u16 {
        self.active_ui_port
    }

    pub fn start_conversation(&mut self) -> NodeConversation {
        let context_id = {
            let context_id = self.next_context_id;
            self.next_context_id += 1;
            context_id
        };
        NodeConversation::new(context_id, &self.client_handle_arc)
    }

    #[allow(dead_code)]
    pub fn establish_broadcast_receiver<F>(&self, _receiver: F) -> Result<(), String>
    where
        F: Fn() -> MessageBody,
    {
        unimplemented!();
    }

    pub fn close(&self) {
        let mut inner = self.client_handle_arc.lock().expect("Connection poisoned");
        inner.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::communications::node_connection::ClientError::NoServer;
    use crate::test_utils::mock_websockets_server::MockWebSocketsServer;
    use masq_lib::utils::find_free_port;

    #[test]
    fn connection_works_when_no_server_exists() {
        let port = find_free_port();

        let error = NodeConnection::new(0, port).err().unwrap();

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

        let error = NodeConnection::new(0, port).err().unwrap();

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
            let _ = NodeConnection::new(0, port).unwrap();
        }

        let results = stop_handle.stop();
        assert_eq!(results, vec![Err("Close(None)".to_string())])
    }
}
