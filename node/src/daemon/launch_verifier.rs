// Copyright (c) 2019-2020, MASQ (https://masq.ai). All rights reserved.

use crate::daemon::launch_verifier::LaunchVerification::{
    CleanFailure, DirtyFailure, InterventionRequired, Launched,
};
use crate::sub_lib::logger::Logger;
use masq_lib::messages::NODE_UI_PROTOCOL;
use std::thread;
use std::time::Duration;
use sysinfo::{ProcessExt, ProcessStatus, Signal, SystemExt};
use websocket::ClientBuilder;

// Note: if the INTERVALs are half the DELAYs or greater, the tests below will need to change,
// because they depend on being able to fail twice and still succeed.
const DELAY_FOR_RESPONSE_MS: u64 = 1000;
const RESPONSE_CHECK_INTERVAL_MS: u64 = 250;
const DELAY_FOR_DEATH_MS: u64 = 1000;
const DEATH_CHECK_INTERVAL_MS: u64 = 250;

pub trait VerifierTools {
    fn can_connect_to_ui_gateway(&self, ui_port: u16) -> bool;
    fn process_is_running(&self, process_id: u32) -> bool;
    fn kill_process(&self, process_id: u32);
    fn delay(&self, milliseconds: u64);
}

pub struct VerifierToolsReal {
    logger: Logger,
}

impl VerifierTools for VerifierToolsReal {
    fn can_connect_to_ui_gateway(&self, ui_port: u16) -> bool {
        let mut builder = match ClientBuilder::new(format!("ws://127.0.0.1:{}", ui_port).as_str()) {
            Ok(builder) => builder.add_protocol(NODE_UI_PROTOCOL),
            Err(e) => panic!(format!("{:?}", e)),
        };
        builder.connect_insecure().is_ok()
    }

    fn process_is_running(&self, process_id: u32) -> bool {
        let system = Self::system();
        let process_info_opt = system.get_process(Self::convert_pid(process_id));
        match process_info_opt {
            None => false,
            Some(process) => {
                let status = process.status();
                Self::is_alive(status)
            }
        }
    }

    fn kill_process(&self, process_id: u32) {
        if let Some(process) = Self::system().get_process(Self::convert_pid(process_id)) {
            if !process.kill(Signal::Term) && !process.kill(Signal::Kill) {
                error!(
                    self.logger,
                    "Process {} could be neither terminated nor killed", process_id
                );
            }
        }
    }

    fn delay(&self, milliseconds: u64) {
        thread::sleep(Duration::from_millis(milliseconds));
    }
}

impl Default for VerifierToolsReal {
    fn default() -> Self {
        Self::new()
    }
}

impl VerifierToolsReal {
    pub fn new() -> Self {
        Self {
            logger: Logger::new("VerifierTools"),
        }
    }

    fn system() -> sysinfo::System {
        let mut system: sysinfo::System = sysinfo::System::new_all();
        system.refresh_processes();
        system
    }

    #[cfg(not(target_os = "windows"))]
    fn convert_pid(process_id: u32) -> i32 {
        process_id as i32
    }

    #[cfg(target_os = "windows")]
    fn convert_pid(process_id: u32) -> usize {
        process_id as usize
    }

    #[cfg(target_os = "linux")]
    fn is_alive(process_status: ProcessStatus) -> bool {
        match process_status {
            ProcessStatus::Dead => false,
            ProcessStatus::Zombie => false,
            _ => true,
        }
    }

    #[cfg(target_os = "macos")]
    fn is_alive(process_status: ProcessStatus) -> bool {
        match process_status {
            ProcessStatus::Zombie => false,
            ProcessStatus::Unknown(0) => false, // This value was observed in practice; its meaning is unclear.
            _ => true,
        }
    }

    #[cfg(target_os = "windows")]
    fn is_alive(process_status: ProcessStatus) -> bool {
        match process_status {
            ProcessStatus::Run => true,
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum LaunchVerification {
    Launched,             // Responded to contact via UiGateway
    CleanFailure,         // No response from UiGateway, no process at process_id
    DirtyFailure,         // No response from UiGateway, process at process_id, killed, disappeared
    InterventionRequired, // No response from UiGateway, process at process_id, killed, still there
}

pub trait LaunchVerifier {
    fn verify_launch(&self, process_id: u32, ui_port: u16) -> LaunchVerification;
}

pub struct LaunchVerifierReal {
    verifier_tools: Box<dyn VerifierTools>,
}

impl Default for LaunchVerifierReal {
    fn default() -> Self {
        LaunchVerifierReal {
            verifier_tools: Box::new(VerifierToolsReal::new()),
        }
    }
}

impl LaunchVerifier for LaunchVerifierReal {
    fn verify_launch(&self, process_id: u32, ui_port: u16) -> LaunchVerification {
        if self.await_ui_connection(ui_port) {
            Launched
        } else if self.verifier_tools.process_is_running(process_id) {
            self.verifier_tools.kill_process(process_id);
            if self.await_process_death(process_id) {
                DirtyFailure
            } else {
                InterventionRequired
            }
        } else {
            CleanFailure
        }
    }
}

impl LaunchVerifierReal {
    pub fn new() -> Self {
        Self::default()
    }

    fn await_ui_connection(&self, ui_port: u16) -> bool {
        let mut accumulated_delay = 0;
        loop {
            if self.verifier_tools.can_connect_to_ui_gateway(ui_port) {
                return true;
            }
            if accumulated_delay > DELAY_FOR_RESPONSE_MS {
                return false;
            }
            self.verifier_tools.delay(RESPONSE_CHECK_INTERVAL_MS);
            accumulated_delay += RESPONSE_CHECK_INTERVAL_MS;
        }
    }

    fn await_process_death(&self, pid: u32) -> bool {
        let mut accumulated_delay = 0;
        loop {
            self.verifier_tools.delay(DEATH_CHECK_INTERVAL_MS);
            accumulated_delay += DEATH_CHECK_INTERVAL_MS;
            if accumulated_delay > DELAY_FOR_DEATH_MS {
                return false;
            }
            if !self.verifier_tools.process_is_running(pid) {
                return true;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::launch_verifier::LaunchVerification::{
        CleanFailure, InterventionRequired, Launched,
    };
    use crate::daemon::mocks::VerifierToolsMock;
    use masq_lib::utils::{find_free_port, localhost};
    use std::net::SocketAddr;
    use std::process::{Child, Command};
    use std::sync::{Arc, Mutex};
    use std::time::Instant;
    use websocket::server::sync::Server;

    #[test]
    fn detects_successful_launch_after_two_attempts() {
        let can_connect_to_ui_gateway_params_arc = Arc::new(Mutex::new(vec![]));
        let delay_params_arc = Arc::new(Mutex::new(vec![]));
        let tools = VerifierToolsMock::new()
            .can_connect_to_ui_gateway_params(&can_connect_to_ui_gateway_params_arc)
            .delay_params(&delay_params_arc)
            .can_connect_to_ui_gateway_result(false)
            .can_connect_to_ui_gateway_result(false)
            .can_connect_to_ui_gateway_result(true);
        let mut subject = LaunchVerifierReal::new();
        subject.verifier_tools = Box::new(tools);

        let result = subject.verify_launch(1234, 4321);

        assert_eq!(result, Launched);
        let can_connect_to_ui_gateway_parms = can_connect_to_ui_gateway_params_arc.lock().unwrap();
        assert_eq!(*can_connect_to_ui_gateway_parms, vec![4321, 4321, 4321]);
        let delay_params = delay_params_arc.lock().unwrap();
        assert_eq!(
            *delay_params,
            vec![RESPONSE_CHECK_INTERVAL_MS, RESPONSE_CHECK_INTERVAL_MS,]
        );
    }

    #[test]
    fn detects_clean_failure() {
        let connect_failure_count = (DELAY_FOR_RESPONSE_MS / RESPONSE_CHECK_INTERVAL_MS) + 1;
        let delay_params_arc = Arc::new(Mutex::new(vec![]));
        let process_is_running_params_arc = Arc::new(Mutex::new(vec![]));
        let mut tools = VerifierToolsMock::new()
            .delay_params(&delay_params_arc)
            .process_is_running_params(&process_is_running_params_arc)
            .can_connect_to_ui_gateway_result(false);
        for _ in 0..connect_failure_count {
            tools = tools.can_connect_to_ui_gateway_result(false);
        }
        tools = tools.process_is_running_result(false);
        let mut subject = LaunchVerifierReal::new();
        subject.verifier_tools = Box::new(tools);

        let result = subject.verify_launch(1234, 4321);

        assert_eq!(result, CleanFailure);
        let delay_params = delay_params_arc.lock().unwrap();
        assert_eq!(delay_params.len() as u64, connect_failure_count);
        delay_params
            .iter()
            .for_each(|delay| assert_eq!(delay, &RESPONSE_CHECK_INTERVAL_MS));
        let process_is_running_params = process_is_running_params_arc.lock().unwrap();
        assert_eq!(*process_is_running_params, vec![1234]);
    }

    #[test]
    fn detects_dirty_failure_after_two_attempts() {
        let connect_failure_count = (DELAY_FOR_RESPONSE_MS / RESPONSE_CHECK_INTERVAL_MS) + 1;
        let delay_params_arc = Arc::new(Mutex::new(vec![]));
        let kill_process_params_arc = Arc::new(Mutex::new(vec![]));
        let process_is_running_params_arc = Arc::new(Mutex::new(vec![]));
        let mut tools = VerifierToolsMock::new()
            .delay_params(&delay_params_arc)
            .process_is_running_params(&process_is_running_params_arc)
            .kill_process_params(&kill_process_params_arc)
            .can_connect_to_ui_gateway_result(false);
        for _ in 0..connect_failure_count {
            tools = tools.can_connect_to_ui_gateway_result(false);
        }
        tools = tools
            .process_is_running_result(true)
            .process_is_running_result(true)
            .process_is_running_result(false);
        let mut subject = LaunchVerifierReal::new();
        subject.verifier_tools = Box::new(tools);

        let result = subject.verify_launch(1234, 4321);

        assert_eq!(result, DirtyFailure);
        let delay_params = delay_params_arc.lock().unwrap();
        assert_eq!(delay_params.len() as u64, connect_failure_count + 2);
        delay_params
            .iter()
            .for_each(|delay| assert_eq!(delay, &RESPONSE_CHECK_INTERVAL_MS));
        let kill_process_params = kill_process_params_arc.lock().unwrap();
        assert_eq!(*kill_process_params, vec![1234]);
        let process_is_running_params = process_is_running_params_arc.lock().unwrap();
        assert_eq!(*process_is_running_params, vec![1234, 1234, 1234]);
    }

    #[test]
    fn detects_intervention_required_after_two_attempts() {
        let connect_failure_count = (DELAY_FOR_RESPONSE_MS / RESPONSE_CHECK_INTERVAL_MS) + 1;
        let death_check_count = (DELAY_FOR_DEATH_MS / DEATH_CHECK_INTERVAL_MS) + 1;
        let delay_params_arc = Arc::new(Mutex::new(vec![]));
        let kill_process_params_arc = Arc::new(Mutex::new(vec![]));
        let process_is_running_params_arc = Arc::new(Mutex::new(vec![]));
        let mut tools = VerifierToolsMock::new()
            .delay_params(&delay_params_arc)
            .process_is_running_params(&process_is_running_params_arc)
            .kill_process_params(&kill_process_params_arc)
            .can_connect_to_ui_gateway_result(false);
        for _ in 0..connect_failure_count {
            tools = tools.can_connect_to_ui_gateway_result(false);
        }
        for _ in 0..death_check_count {
            tools = tools.process_is_running_result(true);
        }
        let mut subject = LaunchVerifierReal::new();
        subject.verifier_tools = Box::new(tools);

        let result = subject.verify_launch(1234, 4321);

        assert_eq!(result, InterventionRequired);
        let delay_params = delay_params_arc.lock().unwrap();
        assert_eq!(
            delay_params.len() as u64,
            connect_failure_count + death_check_count
        );
        delay_params
            .iter()
            .for_each(|delay| assert_eq!(delay, &RESPONSE_CHECK_INTERVAL_MS));
        let kill_process_params = kill_process_params_arc.lock().unwrap();
        assert_eq!(*kill_process_params, vec![1234]);
        let process_is_running_params = process_is_running_params_arc.lock().unwrap();
        assert_eq!(process_is_running_params.len() as u64, death_check_count);
        process_is_running_params
            .iter()
            .for_each(|pid| assert_eq!(pid, &1234));
    }

    #[test]
    fn can_connect_to_ui_gateway_handles_success() {
        let port = find_free_port();
        let (tx, rx) = std::sync::mpsc::channel();
        thread::spawn(move || {
            let mut server = Server::bind(SocketAddr::new(localhost(), port)).unwrap();
            tx.send(()).unwrap();
            let upgrade = server.accept().expect("Couldn't accept connection");
            let _ = upgrade.accept().unwrap();
        });
        let subject = VerifierToolsReal::new();
        rx.recv().unwrap();

        let result = subject.can_connect_to_ui_gateway(port);

        assert_eq!(result, true);
    }

    #[test]
    fn can_connect_to_ui_gateway_handles_failure() {
        let port = find_free_port();
        let subject = VerifierToolsReal::new();

        let result = subject.can_connect_to_ui_gateway(port);

        assert_eq!(result, false);
    }

    fn make_long_running_child() -> Child {
        #[cfg(not(target_os = "windows"))]
        let child = Command::new("tail")
            .args(vec!["-f", "/dev/null"])
            .spawn()
            .unwrap();
        #[cfg(target_os = "windows")]
        let child = Command::new("cmd")
            .args(vec!["/c", "ping", "127.0.0.1"])
            .spawn()
            .unwrap();
        child
    }

    #[test]
    fn kill_process_and_process_is_running_work() {
        let subject = VerifierToolsReal::new();
        let child = make_long_running_child();
        thread::sleep(Duration::from_millis(500));

        let before = subject.process_is_running(child.id());

        subject.kill_process(child.id());

        let after = subject.process_is_running(child.id());

        assert_eq!((before, after), (true, false));
    }

    #[test]
    fn delay_works() {
        let subject = VerifierToolsReal::new();
        let begin = Instant::now();

        subject.delay(25);

        let end = Instant::now();
        let interval = end.duration_since(begin).as_millis();
        assert!(
            interval >= 25,
            "Interval should have been 25 or greater, but was {}",
            interval
        );
        assert!(
            interval < 500,
            "Interval should have been less than 500, but was {}",
            interval
        );
    }

    #[test]
    fn is_alive_works() {
        #[cfg(target_os = "linux")]
        {
            assert_eq!(VerifierToolsReal::is_alive(ProcessStatus::Idle), true);
            assert_eq!(VerifierToolsReal::is_alive(ProcessStatus::Run), true);
            assert_eq!(VerifierToolsReal::is_alive(ProcessStatus::Sleep), true);
            assert_eq!(VerifierToolsReal::is_alive(ProcessStatus::Stop), true);
            assert_eq!(VerifierToolsReal::is_alive(ProcessStatus::Zombie), false);
            assert_eq!(VerifierToolsReal::is_alive(ProcessStatus::Tracing), true);
            assert_eq!(VerifierToolsReal::is_alive(ProcessStatus::Dead), false);
            assert_eq!(VerifierToolsReal::is_alive(ProcessStatus::Wakekill), true);
            assert_eq!(VerifierToolsReal::is_alive(ProcessStatus::Waking), true);
            assert_eq!(VerifierToolsReal::is_alive(ProcessStatus::Parked), true);
            assert_eq!(VerifierToolsReal::is_alive(ProcessStatus::Unknown(0)), true);
            assert_eq!(VerifierToolsReal::is_alive(ProcessStatus::Unknown(1)), true);
        }
        #[cfg(target_os = "macos")]
        {
            assert_eq!(VerifierToolsReal::is_alive(ProcessStatus::Idle), true);
            assert_eq!(VerifierToolsReal::is_alive(ProcessStatus::Run), true);
            assert_eq!(VerifierToolsReal::is_alive(ProcessStatus::Sleep), true);
            assert_eq!(VerifierToolsReal::is_alive(ProcessStatus::Stop), true);
            assert_eq!(VerifierToolsReal::is_alive(ProcessStatus::Zombie), false);
            assert_eq!(
                VerifierToolsReal::is_alive(ProcessStatus::Unknown(0)),
                false
            );
            assert_eq!(VerifierToolsReal::is_alive(ProcessStatus::Unknown(1)), true);
        }
        #[cfg(target_os = "windows")]
        {
            assert_eq!(VerifierToolsReal::is_alive(ProcessStatus::Run), true);
        }
    }
}
