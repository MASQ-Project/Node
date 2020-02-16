// Copyright (c) 2019-2020, MASQ (https://masq.ai). All rights reserved.
#![cfg(test)]

use crate::daemon::launch_verifier::{LaunchVerification, LaunchVerifier};
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
