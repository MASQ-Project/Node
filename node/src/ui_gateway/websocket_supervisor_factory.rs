// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::ui_gateway::websocket_supervisor::{WebSocketSupervisor, WebSocketSupervisorReal};
use actix::Recipient;
use masq_lib::ui_gateway::NodeFromUiMessage;

pub trait WebsocketSupervisorFactory: Send {
    fn make(
        &self,
        port: u16,
        recipient: Recipient<NodeFromUiMessage>,
    ) -> std::io::Result<Box<dyn WebSocketSupervisor>>;
}

pub struct WebsocketSupervisorFactoryReal;

impl WebsocketSupervisorFactory for WebsocketSupervisorFactoryReal {
    fn make(
        &self,
        port: u16,
        recipient: Recipient<NodeFromUiMessage>,
    ) -> std::io::Result<Box<dyn WebSocketSupervisor>> {
        WebSocketSupervisorReal::new(port, recipient)
            .map(|positive| positive as Box<dyn WebSocketSupervisor>)
    }
}

#[cfg(test)]
pub mod mock {
    use crate::ui_gateway::websocket_supervisor::WebSocketSupervisor;
    use crate::ui_gateway::websocket_supervisor_factory::WebsocketSupervisorFactory;
    use actix::Recipient;
    use masq_lib::ui_gateway::NodeFromUiMessage;
    use std::cell::RefCell;

    #[derive(Default)]
    pub struct WebsocketSupervisorFactoryMock {
        make_results: RefCell<Vec<std::io::Result<Box<dyn WebSocketSupervisor>>>>,
    }

    impl WebsocketSupervisorFactoryMock {
        pub fn make_result(self, result: std::io::Result<Box<dyn WebSocketSupervisor>>) -> Self {
            self.make_results.borrow_mut().push(result);
            self
        }
    }

    impl WebsocketSupervisorFactory for WebsocketSupervisorFactoryMock {
        fn make(
            &self,
            _port: u16,
            _recipient: Recipient<NodeFromUiMessage>,
        ) -> std::io::Result<Box<dyn WebSocketSupervisor>> {
            self.make_results.borrow_mut().remove(0)
        }
    }
}
