// Copyright (c) 2019, MASQ (https://masq.ai). All rights reserved.

const DELAY_FOR_RESPONSE_MS: u64 = 1000;
const DELAY_FOR_DEATH_MS: u64 = 1000;

trait VerifierTools {
    fn can_connect_to_ui_gateway (&self, ui_port: u16) -> bool;
    fn process_is_running (&self, process_id: u32) -> bool;
    fn kill_process (&self, process_id: u32);
}

struct VerifierToolsReal {}

impl VerifierTools for VerifierToolsReal {
    fn can_connect_to_ui_gateway(&self, ui_port: u16) -> bool {
        unimplemented!()
    }

    fn process_is_running(&self, process_id: u32) -> bool {
        unimplemented!()
    }

    fn kill_process(&self, process_id: u32) {
        unimplemented!()
    }
}

impl VerifierToolsReal {
    fn new () -> Self {Self{}}
}

pub enum LaunchVerification {
    Launched, // Responded to contact via UiGateway
    CleanFailure, // No response from UiGateway, no process at process_id
    DirtyFailure, // No response from UiGateway, process at process_id, killed, disappeared
    InterventionRequired, // No response from UiGateway, process at process_id, killed, still there
}

pub trait LaunchVerifier {
    fn verify_launch (&self, process_id: u32, ui_port: u16) -> LaunchVerification;
}

pub struct LaunchVerifierReal {}

impl LaunchVerifier for LaunchVerifierReal {
    fn verify_launch(&self, process_id: u32, ui_port: u16) -> LaunchVerification {
        unimplemented!()
    }
}

impl LaunchVerifierReal {
    pub fn new () -> Self {Self{}}
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, Arc};
    use std::cell::RefCell;

    struct VerifierToolsMock {
        can_connect_to_ui_gateway_params: Arc<Mutex<Vec<u16>>>,
        can_connect_to_ui_gateway_results: RefCell<Vec<bool>>,
        process_is_running_params: Arc<Mutex<Vec<u32>>>,
        process_is_running_results: RefCell<Vec<bool>>,
        kill_process_params: Arc<Mutex<Vec<u32>>>,
    }

    impl VerifierTools for VerifierToolsMock {
        fn can_connect_to_ui_gateway(&self, ui_port: u16) -> bool {
            self.can_connect_to_ui_gateway_params.lock().unwrap().push(ui_port);
            self.can_connect_to_ui_gateway_results.borrow_mut().remove(0)
        }

        fn process_is_running(&self, process_id: u32) -> bool {
            self.process_is_running_params.lock().unwrap().push(process_id);
            self.process_is_running_results.borrow_mut().remove(0)
        }

        fn kill_process(&self, process_id: u32) {
            self.kill_process_params.lock().unwrap().push(process_id);
        }
    }

    impl VerifierToolsMock {
        fn new () -> Self {
            VerifierToolsMock {
                can_connect_to_ui_gateway_params: Arc::new(Mutex::new(vec![])),
                can_connect_to_ui_gateway_results: RefCell::new(vec![]),
                process_is_running_params: Arc::new(Mutex::new(vec![])),
                process_is_running_results: RefCell::new(vec![]),
                kill_process_params: Arc::new(Mutex::new(vec![]))
            }
        }

        fn can_connect_to_ui_gateway_params(mut self, params: &Arc<Mutex<Vec<u16>>>) -> Self {
            self.can_connect_to_ui_gateway_params = params.clone();
            self
        }

        fn can_connect_to_ui_gateway_result(self, result: bool) -> Self {
            self.can_connect_to_ui_gateway_results.borrow_mut().push (result);
            self
        }

        fn process_is_running_params(mut self, params: &Arc<Mutex<Vec<u32>>>) -> Self {
            self.process_is_running_params = params.clone();
            self
        }

        fn process_is_running_result(self, result: bool) -> Self {
            self.process_is_running_results.borrow_mut().push (result);
            self
        }

        fn kill_process_params(mut self, params: &Arc<Mutex<Vec<u32>>>) -> Self {
            self.kill_process_params = params.clone();
            self
        }
    }

    #[test]
    fn detects_immediately_successful_launch() {
        unimplemented!()
    }

    #[test]
    fn detects_successful_launch_after_two_attempts() {
        unimplemented!()
    }

    #[test]
    fn detects_clean_failure() {
        unimplemented!()
    }

    #[test]
    fn detects_dirty_failure() {
        unimplemented!()
    }

    #[test]
    fn detects_intervention_required() {
        unimplemented!()
    }
}