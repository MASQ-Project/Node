// Copyright (c) 2019, MASQ (https://masq.ai). All rights reserved.

use crate::daemon::launch_verifier::LaunchVerification::{Launched, CleanFailure, DirtyFailure, InterventionRequired};

// Note: if the INTERVALs are half the DELAYs or greater, the tests below will need to change,
// because they depend on being able to fail twice and still succeed.
const DELAY_FOR_RESPONSE_MS: u64 = 1000;
const RESPONSE_CHECK_INTERVAL_MS: u64 = 250;
const DELAY_FOR_DEATH_MS: u64 = 1000;
const DEATH_CHECK_INTERVAL_MS: u64 = 250;

trait VerifierTools {
    fn can_connect_to_ui_gateway (&self, ui_port: u16) -> bool;
    fn process_is_running (&self, process_id: u32) -> bool;
    fn kill_process (&self, process_id: u32);
    fn delay (&self, milliseconds: u64);
}

struct VerifierToolsReal {}

impl VerifierTools for VerifierToolsReal {
    fn can_connect_to_ui_gateway(&self, _ui_port: u16) -> bool {
        unimplemented!()
    }

    fn process_is_running(&self, _process_id: u32) -> bool {
        unimplemented!()
    }

    fn kill_process(&self, _process_id: u32) {
        unimplemented!()
    }

    fn delay(&self, _milliseconds: u64) {
        unimplemented!()
    }
}

impl VerifierToolsReal {
    fn new () -> Self {Self{}}
}

#[derive (Debug, PartialEq)]
pub enum LaunchVerification {
    Launched, // Responded to contact via UiGateway
    CleanFailure, // No response from UiGateway, no process at process_id
    DirtyFailure, // No response from UiGateway, process at process_id, killed, disappeared
    InterventionRequired, // No response from UiGateway, process at process_id, killed, still there
}

pub trait LaunchVerifier {
    fn verify_launch (&self, process_id: u32, ui_port: u16) -> LaunchVerification;
}

pub struct LaunchVerifierReal {
    verifier_tools: Box<dyn VerifierTools>,
}

impl LaunchVerifier for LaunchVerifierReal {
    fn verify_launch(&self, process_id: u32, ui_port: u16) -> LaunchVerification {
        match self.await_ui_connection (ui_port) {
            true => Launched,
            false => match self.verifier_tools.process_is_running(process_id) {
                true => {
                    self.verifier_tools.kill_process(process_id);
                    match self.await_process_death(process_id) {
                        true => DirtyFailure,
                        false => InterventionRequired,
                    }
                },
                false => CleanFailure
            }
        }
    }
}

impl LaunchVerifierReal {
    pub fn new () -> Self {
        LaunchVerifierReal{
            verifier_tools: Box::new (VerifierToolsReal::new())
        }
    }

    fn await_ui_connection(&self, ui_port: u16) -> bool {
        let mut accumulated_delay = 0;
        loop {
            if self.verifier_tools.can_connect_to_ui_gateway(ui_port) {
                return true
            }
            if accumulated_delay > DELAY_FOR_RESPONSE_MS {
                return false
            }
            self.verifier_tools.delay (RESPONSE_CHECK_INTERVAL_MS);
            accumulated_delay += RESPONSE_CHECK_INTERVAL_MS;
        }
    }

    fn await_process_death(&self, pid: u32) -> bool {
        let mut accumulated_delay = 0;
        loop {
            self.verifier_tools.delay (DEATH_CHECK_INTERVAL_MS);
            accumulated_delay += DEATH_CHECK_INTERVAL_MS;
            if accumulated_delay > DELAY_FOR_DEATH_MS {
                return false
            }
            if !self.verifier_tools.process_is_running(pid) {
                return true
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, Arc};
    use std::cell::RefCell;
    use crate::daemon::launch_verifier::LaunchVerification::{Launched, CleanFailure, InterventionRequired};

    struct VerifierToolsMock {
        can_connect_to_ui_gateway_params: Arc<Mutex<Vec<u16>>>,
        can_connect_to_ui_gateway_results: RefCell<Vec<bool>>,
        process_is_running_params: Arc<Mutex<Vec<u32>>>,
        process_is_running_results: RefCell<Vec<bool>>,
        kill_process_params: Arc<Mutex<Vec<u32>>>,
        delay_params: Arc<Mutex<Vec<u64>>>,
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

        fn delay(&self, milliseconds: u64) {
            self.delay_params.lock().unwrap().push(milliseconds);
        }
    }

    impl VerifierToolsMock {
        fn new () -> Self {
            VerifierToolsMock {
                can_connect_to_ui_gateway_params: Arc::new(Mutex::new(vec![])),
                can_connect_to_ui_gateway_results: RefCell::new(vec![]),
                process_is_running_params: Arc::new(Mutex::new(vec![])),
                process_is_running_results: RefCell::new(vec![]),
                kill_process_params: Arc::new(Mutex::new(vec![])),
                delay_params: Arc::new(Mutex::new(vec![])),
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

        fn delay_params(mut self, params: &Arc<Mutex<Vec<u64>>>) -> Self {
            self.delay_params = params.clone();
            self
        }
    }

    #[test]
    fn detects_successful_launch_after_two_attempts() {
        let can_connect_to_ui_gateway_params_arc = Arc::new(Mutex::new(vec![]));
        let delay_parms_arc = Arc::new(Mutex::new(vec![]));
        let tools = VerifierToolsMock::new()
            .can_connect_to_ui_gateway_params(&can_connect_to_ui_gateway_params_arc)
            .delay_params(&delay_parms_arc)
            .can_connect_to_ui_gateway_result(false)
            .can_connect_to_ui_gateway_result(false)
            .can_connect_to_ui_gateway_result(true);
        let mut subject = LaunchVerifierReal::new();
        subject.verifier_tools = Box::new (tools);

        let result = subject.verify_launch (1234, 4321);

        assert_eq! (result, Launched);
        let can_connect_to_ui_gateway_parms = can_connect_to_ui_gateway_params_arc.lock().unwrap();
        assert_eq! (*can_connect_to_ui_gateway_parms, vec![4321, 4321, 4321]);
        let delay_params = delay_parms_arc.lock().unwrap();
        assert_eq! (*delay_params, vec![
            RESPONSE_CHECK_INTERVAL_MS,
            RESPONSE_CHECK_INTERVAL_MS,
        ]);
    }

    #[test]
    fn detects_clean_failure() {
        let connect_failure_count = (DELAY_FOR_RESPONSE_MS / RESPONSE_CHECK_INTERVAL_MS) + 1;
        let delay_params_arc = Arc::new(Mutex::new(vec![]));
        let process_is_running_params_arc = Arc::new(Mutex::new(vec![]));
        let mut tools = VerifierToolsMock::new()
            .delay_params (&delay_params_arc)
            .process_is_running_params (&process_is_running_params_arc)
            .can_connect_to_ui_gateway_result(false);
        for _ in 0..connect_failure_count {
            tools = tools
                .can_connect_to_ui_gateway_result(false);
        }
        tools = tools
            .process_is_running_result(false);
        let mut subject = LaunchVerifierReal::new();
        subject.verifier_tools = Box::new (tools);

        let result = subject.verify_launch (1234, 4321);

        assert_eq! (result, CleanFailure);
        let delay_params = delay_params_arc.lock().unwrap();
        assert_eq! (delay_params.len() as u64, connect_failure_count);
        delay_params.iter ().for_each (|delay| assert_eq! (delay, &RESPONSE_CHECK_INTERVAL_MS));
        let process_is_running_params = process_is_running_params_arc.lock().unwrap();
        assert_eq! (*process_is_running_params, vec![1234]);
    }

    #[test]
    fn detects_dirty_failure_after_two_attempts() {
        let connect_failure_count = (DELAY_FOR_RESPONSE_MS / RESPONSE_CHECK_INTERVAL_MS) + 1;
        let delay_params_arc = Arc::new(Mutex::new(vec![]));
        let kill_process_params_arc = Arc::new(Mutex::new(vec![]));
        let process_is_running_params_arc = Arc::new(Mutex::new(vec![]));
        let mut tools = VerifierToolsMock::new()
            .delay_params (&delay_params_arc)
            .process_is_running_params (&process_is_running_params_arc)
            .kill_process_params (&kill_process_params_arc)
            .can_connect_to_ui_gateway_result(false);
        for _ in 0..connect_failure_count {
            tools = tools
                .can_connect_to_ui_gateway_result(false);
        }
        tools = tools
            .process_is_running_result(true)
            .process_is_running_result(true)
            .process_is_running_result(false);
        let mut subject = LaunchVerifierReal::new();
        subject.verifier_tools = Box::new (tools);

        let result = subject.verify_launch (1234, 4321);

        assert_eq! (result, DirtyFailure);
        let delay_params = delay_params_arc.lock().unwrap();
        assert_eq! (delay_params.len() as u64, connect_failure_count + 2);
        delay_params.iter ().for_each (|delay| assert_eq! (delay, &RESPONSE_CHECK_INTERVAL_MS));
        let kill_process_params = kill_process_params_arc.lock().unwrap();
        assert_eq! (*kill_process_params, vec![1234]);
        let process_is_running_params = process_is_running_params_arc.lock().unwrap();
        assert_eq! (*process_is_running_params, vec![1234, 1234, 1234]);
    }

    #[test]
    fn detects_intervention_required_after_two_attempts() {
        let connect_failure_count = (DELAY_FOR_RESPONSE_MS / RESPONSE_CHECK_INTERVAL_MS) + 1;
        let death_check_count = (DELAY_FOR_DEATH_MS / DEATH_CHECK_INTERVAL_MS) + 1;
        let delay_params_arc = Arc::new(Mutex::new(vec![]));
        let kill_process_params_arc = Arc::new(Mutex::new(vec![]));
        let process_is_running_params_arc = Arc::new(Mutex::new(vec![]));
        let mut tools = VerifierToolsMock::new()
            .delay_params (&delay_params_arc)
            .process_is_running_params (&process_is_running_params_arc)
            .kill_process_params (&kill_process_params_arc)
            .can_connect_to_ui_gateway_result(false);
        for _ in 0..connect_failure_count {
            tools = tools
                .can_connect_to_ui_gateway_result(false);
        }
        for _ in 0..death_check_count {
            tools = tools
                .process_is_running_result(true);
        }
        let mut subject = LaunchVerifierReal::new();
        subject.verifier_tools = Box::new (tools);

        let result = subject.verify_launch (1234, 4321);

        assert_eq! (result, InterventionRequired);
        let delay_params = delay_params_arc.lock().unwrap();
        assert_eq! (delay_params.len() as u64, connect_failure_count + death_check_count);
        delay_params.iter ().for_each (|delay| assert_eq! (delay, &RESPONSE_CHECK_INTERVAL_MS));
        let kill_process_params = kill_process_params_arc.lock().unwrap();
        assert_eq! (*kill_process_params, vec![1234]);
        let process_is_running_params = process_is_running_params_arc.lock().unwrap();
        assert_eq! (process_is_running_params.len() as u64, death_check_count);
        process_is_running_params.iter ().for_each (|pid| assert_eq! (pid, &1234));
    }
}
