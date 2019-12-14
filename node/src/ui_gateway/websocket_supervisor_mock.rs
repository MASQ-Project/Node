// Copyright (c) 2019, MASQ (https://masq.ai). All rights reserved.
#![cfg(test)]

use std::sync::{Arc, Mutex};
use crate::sub_lib::ui_gateway::NewToUiMessage;
use crate::ui_gateway::websocket_supervisor::WebSocketSupervisor;

#[derive(Default)]
pub struct WebSocketSupervisorMock {
    send_parameters: Arc<Mutex<Vec<(u64, String)>>>,
    send_msg_parameters: Arc<Mutex<Vec<NewToUiMessage>>>,
}

impl WebSocketSupervisor for WebSocketSupervisorMock {
    fn send(&self, client_id: u64, message_json: &str) {
        self.send_parameters
            .lock()
            .unwrap()
            .push((client_id, String::from(message_json)));
    }

    fn send_msg(&self, msg: NewToUiMessage) {
        self.send_msg_parameters.lock().unwrap().push(msg);
    }
}

impl WebSocketSupervisorMock {
    pub fn new() -> WebSocketSupervisorMock {
        WebSocketSupervisorMock {
            send_parameters: Arc::new(Mutex::new(vec![])),
            send_msg_parameters: Arc::new(Mutex::new(vec![])),
        }
    }

    pub fn send_parameters(
        mut self,
        parameters: &Arc<Mutex<Vec<(u64, String)>>>,
    ) -> WebSocketSupervisorMock {
        self.send_parameters = parameters.clone();
        self
    }

    pub fn send_msg_parameters(
        mut self,
        parameters: &Arc<Mutex<Vec<NewToUiMessage>>>,
    ) -> WebSocketSupervisorMock {
        self.send_msg_parameters = parameters.clone();
        self
    }
}
