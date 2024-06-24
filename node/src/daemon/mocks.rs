// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

#![cfg(test)]

use crate::daemon::launch_verifier::{
    ClientBuilderWrapper, ClientWrapper, LaunchVerification, LaunchVerifier, VerifierTools,
};
use std::cell::RefCell;
use std::sync::{Arc, Mutex};

pub struct LaunchVerifierMock {
    verify_launch_params: Arc<Mutex<Vec<(u32, u16)>>>,
    verify_launch_results: RefCell<Vec<LaunchVerification>>,
}

impl LaunchVerifier for LaunchVerifierMock {
    fn verify_launch(&self, process_id: u32, ui_port: u16) -> LaunchVerification {
        self.verify_launch_params
            .lock()
            .unwrap()
            .push((process_id, ui_port));
        self.verify_launch_results.borrow_mut().remove(0)
    }
}

impl LaunchVerifierMock {
    pub fn new() -> Self {
        LaunchVerifierMock {
            verify_launch_params: Arc::new(Mutex::new(vec![])),
            verify_launch_results: RefCell::new(vec![]),
        }
    }

    pub fn verify_launch_params(mut self, params: &Arc<Mutex<Vec<(u32, u16)>>>) -> Self {
        self.verify_launch_params = params.clone();
        self
    }

    pub fn verify_launch_result(self, result: LaunchVerification) -> Self {
        self.verify_launch_results.borrow_mut().push(result);
        self
    }
}

pub struct VerifierToolsMock {
    can_connect_to_ui_gateway_params: Arc<Mutex<Vec<u16>>>,
    can_connect_to_ui_gateway_results: RefCell<Vec<bool>>,
    process_is_running_params: Arc<Mutex<Vec<u32>>>,
    process_is_running_results: RefCell<Vec<bool>>,
    kill_process_params: Arc<Mutex<Vec<u32>>>,
    delay_params: Arc<Mutex<Vec<u64>>>,
}

impl VerifierTools for VerifierToolsMock {
    fn can_connect_to_ui_gateway(&self, ui_port: u16) -> bool {
        self.can_connect_to_ui_gateway_params
            .lock()
            .unwrap()
            .push(ui_port);
        self.can_connect_to_ui_gateway_results
            .borrow_mut()
            .remove(0)
    }

    fn process_is_running(&self, process_id: u32) -> bool {
        self.process_is_running_params
            .lock()
            .unwrap()
            .push(process_id);
        self.process_is_running_results.borrow_mut().remove(0)
    }

    fn kill_process(&self, process_id: u32) {
        self.kill_process_params.lock().unwrap().push(process_id);
    }

    fn delay(&self, milliseconds: u64) {
        self.delay_params.lock().unwrap().push(milliseconds);
    }
}

impl VerifierToolsMock {
    pub fn new() -> Self {
        VerifierToolsMock {
            can_connect_to_ui_gateway_params: Arc::new(Mutex::new(vec![])),
            can_connect_to_ui_gateway_results: RefCell::new(vec![]),
            process_is_running_params: Arc::new(Mutex::new(vec![])),
            process_is_running_results: RefCell::new(vec![]),
            kill_process_params: Arc::new(Mutex::new(vec![])),
            delay_params: Arc::new(Mutex::new(vec![])),
        }
    }

    pub fn can_connect_to_ui_gateway_params(mut self, params: &Arc<Mutex<Vec<u16>>>) -> Self {
        self.can_connect_to_ui_gateway_params = params.clone();
        self
    }

    pub fn can_connect_to_ui_gateway_result(self, result: bool) -> Self {
        self.can_connect_to_ui_gateway_results
            .borrow_mut()
            .push(result);
        self
    }

    pub fn process_is_running_params(mut self, params: &Arc<Mutex<Vec<u32>>>) -> Self {
        self.process_is_running_params = params.clone();
        self
    }

    pub fn process_is_running_result(self, result: bool) -> Self {
        self.process_is_running_results.borrow_mut().push(result);
        self
    }

    pub fn kill_process_params(mut self, params: &Arc<Mutex<Vec<u32>>>) -> Self {
        self.kill_process_params = params.clone();
        self
    }

    pub fn delay_params(mut self, params: &Arc<Mutex<Vec<u64>>>) -> Self {
        self.delay_params = params.clone();
        self
    }
}

#[derive(Default)]
pub struct ClientWrapperMock {
    send_message_params: Arc<Mutex<Vec<OwnedMessage>>>,
    send_message_result: RefCell<Vec<Result<(), WebSocketError>>>,
}

impl ClientWrapper for ClientWrapperMock {
    fn send_message(&mut self, message: OwnedMessage) -> WebSocketResult<()> {
        self.send_message_params.lock().unwrap().push(message);
        self.send_message_result.borrow_mut().remove(0)
    }
}

impl ClientWrapperMock {
    pub fn send_message_params(mut self, params: &Arc<Mutex<Vec<OwnedMessage>>>) -> Self {
        self.send_message_params = params.clone();
        self
    }

    pub fn send_message_result(self, result: Result<(), WebSocketError>) -> Self {
        self.send_message_result.borrow_mut().push(result);
        self
    }
}

#[derive(Default)]
pub struct ClientBuilderWrapperMock {
    initiate_client_builder_params: Arc<Mutex<Vec<String>>>,
    initiate_client_builder_result: RefCell<Vec<Result<(), ParseError>>>,
    add_protocol_params: Arc<Mutex<Vec<String>>>,
    connect_insecure_result: RefCell<Vec<Result<Box<dyn ClientWrapper>, WebSocketError>>>,
}

impl ClientBuilderWrapper for ClientBuilderWrapperMock {
    fn initiate_client_builder(&mut self, address: &str) -> Result<(), ParseError> {
        self.initiate_client_builder_params
            .lock()
            .unwrap()
            .push(address.to_string());
        self.initiate_client_builder_result.borrow_mut().remove(0)
    }

    fn add_protocol(&self, protocol: &str) {
        self.add_protocol_params
            .lock()
            .unwrap()
            .push(protocol.to_string())
    }

    fn connect_insecure(&mut self) -> WebSocketResult<Box<dyn ClientWrapper>> {
        self.connect_insecure_result.borrow_mut().remove(0)
    }
}

impl ClientBuilderWrapperMock {
    pub fn initiate_client_builder_params(mut self, params: &Arc<Mutex<Vec<String>>>) -> Self {
        self.initiate_client_builder_params = params.clone();
        self
    }
    pub fn initiate_client_builder_result(self, result: Result<(), ParseError>) -> Self {
        self.initiate_client_builder_result
            .borrow_mut()
            .push(result);
        self
    }

    pub fn add_protocol_params(mut self, params: &Arc<Mutex<Vec<String>>>) -> Self {
        self.add_protocol_params = params.clone();
        self
    }

    pub fn connect_insecure_result(
        self,
        result: Result<Box<dyn ClientWrapper>, WebSocketError>,
    ) -> Self {
        self.connect_insecure_result.borrow_mut().push(result);
        self
    }
}
