// Copyright (c) 2019-2021, MASQ (https://masq.ai). All rights reserved.
#![cfg(test)]

use crate::ui_gateway::websocket_supervisor::{WebSocketSupervisor, WebSocketSupervisorFactory};
use actix::Recipient;
use masq_lib::ui_gateway::{NodeFromUiMessage, NodeToUiMessage};
use std::cell::RefCell;
use std::sync::{Arc, Mutex};
use async_trait::async_trait;

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

    pub fn send_msg_params(
        mut self,
        parameters: &Arc<Mutex<Vec<NodeToUiMessage>>>,
    ) -> WebSocketSupervisorMock {
        self.send_msg_parameters = parameters.clone();
        self
    }
}

#[derive(Default)]
pub struct WebsocketSupervisorFactoryMock {
    make_results: RefCell<Vec<std::io::Result<WebSocketSupervisorMock>>>,
}

impl WebsocketSupervisorFactoryMock {
    pub fn make_result(self, result: std::io::Result<WebSocketSupervisorMock>) -> Self {
        self.make_results.borrow_mut().push(result);
        self
    }
}

impl WebSocketSupervisorFactory for WebsocketSupervisorFactoryMock {
    fn make(
        &self,
        _port: u16,
        _recipient: Recipient<NodeFromUiMessage>,
    ) -> std::io::Result<Box<dyn WebSocketSupervisor>> {
        let result = self.make_results.borrow_mut().remove(0);
        match result {
            Ok(ws_mock) => Ok(Box::new(ws_mock) as Box<dyn WebSocketSupervisor>),
            Err(err) => Err(err),
        }
    }
}
