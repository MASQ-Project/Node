// Copyright (c) 2019-2021, MASQ (https://masq.ai). All rights reserved.

use crate::daemon::launch_verifier::{LaunchVerification, LaunchVerifier, VerifierTools};
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
