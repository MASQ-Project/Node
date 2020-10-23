// Copyright (c) 2019-2020, MASQ (https://masq.ai). All rights reserved.
#![cfg(test)]

use crate::ui_gateway::websocket_supervisor::WebSocketSupervisor;
use masq_lib::ui_gateway::NodeToUiMessage;
use std::sync::{Arc, Mutex};

#[derive(Default)]
pub struct WebSocketSupervisorMock {
    send_msg_parameters: Arc<Mutex<Vec<NodeToUiMessage>>>,
}

impl WebSocketSupervisor for WebSocketSupervisorMock {
    fn send_msg(&self, msg: NodeToUiMessage) {
        self.send_msg_parameters.lock().unwrap().push(msg);
    }
}

impl WebSocketSupervisorMock {
    pub fn new() -> WebSocketSupervisorMock {
        WebSocketSupervisorMock {
            send_msg_parameters: Arc::new(Mutex::new(vec![])),
        }
    }

    pub fn send_msg_parameters(
        mut self,
        parameters: &Arc<Mutex<Vec<NodeToUiMessage>>>,
    ) -> WebSocketSupervisorMock {
        self.send_msg_parameters = parameters.clone();
        self
    }
}
