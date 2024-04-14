// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::daemon::launch_verifier::LaunchVerification::{
    CleanFailure, DirtyFailure, InterventionRequired, Launched,
};
use masq_lib::logger::Logger;
use masq_lib::messages::NODE_UI_PROTOCOL;
use masq_lib::utils::ExpectValue;
use std::cell::RefCell;
use std::net::TcpStream;
use std::thread;
use std::time::Duration;
use sysinfo::{ProcessExt, ProcessStatus, Signal, SystemExt};
use websocket::client::ParseError;
use websocket::sync::Client;
use websocket::{ClientBuilder, OwnedMessage, WebSocketResult};

// Note: if the INTERVALs are half the DELAYs or greater, the non_unit_tests below will need to change,
// because they depend on being able to fail twice and still succeed.
const DELAY_FOR_RESPONSE_MS: u64 = 10000;
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
    client_builder: RefCell<Box<dyn ClientBuilderWrapper>>,
    logger: Logger,
}

impl VerifierTools for VerifierToolsReal {
    fn can_connect_to_ui_gateway(&self, ui_port: u16) -> bool {
        let mut client_builder_ref = self.client_builder.borrow_mut();
        let url_address = format!("ws://127.0.0.1:{}", ui_port);
        if let Err(e) = client_builder_ref.initiate_client_builder(&url_address) {
            panic!("client builder: {:?}", e)
        }
        client_builder_ref.add_protocol(NODE_UI_PROTOCOL);
        match client_builder_ref.connect_insecure() {
            Ok(mut client) => client.send_message(OwnedMessage::Close(None)).is_ok(),
            Err(_) => false,
        }
    }

    fn process_is_running(&self, process_id: u32) -> bool {
        let system = Self::system();
        let process_info_opt = system.process(Self::convert_pid(process_id));
        match process_info_opt {
            None => false,
            Some(process) => {
                let status = process.status();
                Self::is_alive(status)
            }
        }
    }

    fn kill_process(&self, process_id: u32) {
        if let Some(process) = Self::system().process(Self::convert_pid(process_id)) {
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
            client_builder: RefCell::new(Box::new(ClientBuilderWrapperReal::default())),
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
        !matches!(process_status, ProcessStatus::Dead | ProcessStatus::Zombie)
    }

    #[cfg(target_os = "macos")]
    fn is_alive(process_status: ProcessStatus) -> bool {
        !matches!(
            process_status,
            ProcessStatus::Zombie | ProcessStatus::Unknown(0)
        )
    }

    #[cfg(target_os = "windows")]
    fn is_alive(process_status: ProcessStatus) -> bool {
        !matches!(process_status, ProcessStatus::Dead | ProcessStatus::Zombie)
    }
}

#[derive(Debug, PartialEq, Eq)]
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

pub trait ClientWrapper {
    fn send_message(&mut self, message: OwnedMessage) -> WebSocketResult<()>;
}

struct ClientWrapperReal {
    client: Client<TcpStream>,
}

impl ClientWrapper for ClientWrapperReal {
    fn send_message(&mut self, message: OwnedMessage) -> WebSocketResult<()> {
        self.client.send_message(&message)
    }
}

pub trait ClientBuilderWrapper {
    fn initiate_client_builder(&mut self, address: &str) -> Result<(), ParseError>;
    fn add_protocol(&self, protocol: &str);
    fn connect_insecure(&mut self) -> WebSocketResult<Box<dyn ClientWrapper>>;
}

#[derive(Default)]
struct ClientBuilderWrapperReal<'a> {
    builder_opt: RefCell<Option<ClientBuilder<'a>>>,
}

impl ClientBuilderWrapper for ClientBuilderWrapperReal<'_> {
    fn initiate_client_builder(&mut self, address: &str) -> Result<(), ParseError> {
        self.builder_opt.replace(Some(ClientBuilder::new(address)?));
        Ok(())
    }

    fn add_protocol(&self, protocol: &str) {
        let updated_builder = self
            .builder_opt
            .borrow_mut()
            .take()
            .expectv("client builder")
            .add_protocol(protocol);
        self.builder_opt.replace(Some(updated_builder));
    }

    fn connect_insecure(&mut self) -> WebSocketResult<Box<dyn ClientWrapper>> {
        self.builder_opt
            .borrow_mut()
            .as_mut()
            .expectv("client builder")
            .connect_insecure()
            .map(|client| Box::new(ClientWrapperReal { client }) as Box<dyn ClientWrapper>)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::launch_verifier::LaunchVerification::{
        CleanFailure, InterventionRequired, Launched,
    };
    use crate::daemon::mocks::{ClientBuilderWrapperMock, ClientWrapperMock, VerifierToolsMock};
    use masq_lib::utils::find_free_port;
    use std::process::{Child, Command};
    use std::sync::{Arc, Mutex};
    use std::time::Instant;
    use websocket::url::ParseError::RelativeUrlWithoutBase;
    use websocket::{OwnedMessage, WebSocketError};

    #[test]
    fn constants_have_correct_values() {
        assert_eq!(DELAY_FOR_RESPONSE_MS, 10000);
        assert_eq!(RESPONSE_CHECK_INTERVAL_MS, 250);
        assert_eq!(DELAY_FOR_DEATH_MS, 1000);
        assert_eq!(DEATH_CHECK_INTERVAL_MS, 250);
    }

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
        let port = 45554;
        let initiate_client_params_arc = Arc::new(Mutex::new(vec![]));
        let add_protocol_params_arc = Arc::new(Mutex::new(vec![]));
        let send_message_params_arc = Arc::new(Mutex::new(vec![]));
        let subject = VerifierToolsReal::new();
        let client = ClientWrapperMock::default()
            .send_message_params(&send_message_params_arc)
            .send_message_result(Ok(()));
        let client_builder = ClientBuilderWrapperMock::default()
            .initiate_client_builder_params(&initiate_client_params_arc)
            .initiate_client_builder_result(Ok(()))
            .add_protocol_params(&add_protocol_params_arc)
            .connect_insecure_result(Ok(Box::new(client)));
        subject.client_builder.replace(Box::new(client_builder));

        let result = subject.can_connect_to_ui_gateway(port);

        assert_eq!(result, true);
        let initial_client_params = initiate_client_params_arc.lock().unwrap();
        assert_eq!(
            *initial_client_params,
            vec!["ws://127.0.0.1:45554".to_string()]
        );
        let add_protocol_params = add_protocol_params_arc.lock().unwrap();
        assert_eq!(*add_protocol_params, vec![NODE_UI_PROTOCOL.to_string()]);
        let send_message_params = send_message_params_arc.lock().unwrap();
        assert_eq!(*send_message_params, vec![OwnedMessage::Close(None)])
    }

    #[test]
    fn can_connect_to_ui_gateway_handles_connection_failure() {
        let port = find_free_port();
        let subject = VerifierToolsReal::new();

        let result = subject.can_connect_to_ui_gateway(port);

        assert_eq!(result, false);
    }

    #[test]
    #[should_panic(expected = "client builder: InvalidDomainCharacter")]
    fn can_connect_to_ui_gateway_panics_on_initiate_client_builder() {
        let port = 7889;
        let subject = VerifierToolsReal::new();
        let client_builder = ClientBuilderWrapperMock::default()
            .initiate_client_builder_result(Err(ParseError::InvalidDomainCharacter));
        subject.client_builder.replace(Box::new(client_builder));

        subject.can_connect_to_ui_gateway(port);
    }

    #[test]
    fn can_connect_to_ui_gateway_handles_close_message_send_failure() {
        let port = 6578;
        let subject = VerifierToolsReal::new();
        let client = ClientWrapperMock::default()
            .send_message_result(Err(WebSocketError::ProtocolError("Oh, my bad")));
        let client_builder = ClientBuilderWrapperMock::default()
            .initiate_client_builder_result(Ok(()))
            .connect_insecure_result(Ok(Box::new(client)));
        subject.client_builder.replace(Box::new(client_builder));

        let result = subject.can_connect_to_ui_gateway(port);

        assert_eq!(result, false);
    }

    #[test]
    fn client_builder_handles_initialization_error() {
        let url_address = "foolish";
        let mut subject = ClientBuilderWrapperReal::default();

        let result = subject.initiate_client_builder(url_address);

        assert_eq!(result, Err(RelativeUrlWithoutBase))
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
        thread::sleep(Duration::from_millis(250));

        let before = subject.process_is_running(child.id());

        subject.kill_process(child.id());
        thread::sleep(Duration::from_millis(250));

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
