// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::daemon::crash_notification::CrashNotification;
use crate::daemon::launch_verifier::LaunchVerification::{
    CleanFailure, DirtyFailure, InterventionRequired, Launched,
};
use crate::daemon::launch_verifier::{LaunchVerifier, LaunchVerifierReal};
use crate::daemon::{LaunchSuccess, Launcher};
use actix::Recipient;
use crossbeam_channel::Sender;
use itertools::Itertools;
use masq_lib::logger::Logger;
use masq_lib::utils::find_free_port;
use std::collections::HashMap;
use std::path::PathBuf;
use std::process::{Child, Command, Output};
use std::thread;

trait ChildWrapper: Send {
    fn id(&self) -> u32;
    fn wait_with_output(&mut self) -> std::io::Result<Output>;
}

struct ChildWrapperReal {
    child_opt: Option<Child>,
}

impl ChildWrapper for ChildWrapperReal {
    fn id(&self) -> u32 {
        self.child_opt
            .as_ref()
            .expect("ChildWrapper has already been waited on")
            .id()
    }

    fn wait_with_output(&mut self) -> std::io::Result<Output> {
        self.child_opt
            .take()
            .expect("ChildWrapper has already been waited on")
            .wait_with_output()
    }
}

impl ChildWrapperReal {
    pub fn new(child: Child) -> Self {
        Self {
            child_opt: Some(child),
        }
    }
}

trait SpawnWrapper: Send {
    fn spawn(
        &self,
        exe_path: PathBuf,
        params: Vec<String>,
    ) -> std::io::Result<Box<dyn ChildWrapper>>;
}

struct SpawnWrapperReal {}

impl SpawnWrapper for SpawnWrapperReal {
    fn spawn(
        &self,
        exe_path: PathBuf,
        params: Vec<String>,
    ) -> std::io::Result<Box<dyn ChildWrapper>> {
        match Command::new(exe_path).args(params).spawn() {
            Ok(child) => Ok(Box::new(ChildWrapperReal::new(child))),
            Err(e) => Err(e),
        }
    }
}

pub trait Execer {
    fn exec(
        &self,
        params: Vec<String>,
        crashed_recipient: Recipient<CrashNotification>,
    ) -> Result<u32, String>;
}

pub struct ExecerReal {
    logger: Logger,
    spawn_wrapper: Box<dyn SpawnWrapper>,
}

impl Execer for ExecerReal {
    fn exec(
        &self,
        params: Vec<String>,
        crashed_recipient: Recipient<CrashNotification>,
    ) -> Result<u32, String> {
        let exe_path = match std::env::current_exe() {
            Ok(path) => path,
            Err(e) => return Err(format!("Cannot find executable: {:?}", e)),
        };
        info!(
            self.logger,
            "Starting Node with command: {} {}",
            exe_path.to_string_lossy().to_string(),
            params.join(" "),
        );
        match self.spawn_wrapper.spawn(exe_path, params) {
            Ok(mut child) => {
                let process_id = child.id();
                thread::spawn(move || match child.wait_with_output() {
                    Ok(output) => {
                        let stderr = match output.stderr.len() {
                            0 => None,
                            _ => {
                                let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                                Some(stderr)
                            }
                        };
                        crashed_recipient
                            .try_send(CrashNotification {
                                process_id,
                                exit_code: output.status.code(),
                                stderr,
                            })
                            .expect("Daemon is dead");
                    }
                    Err(e) => {
                        crashed_recipient
                            .try_send(CrashNotification {
                                process_id,
                                exit_code: None,
                                stderr: Some(format!("Child wait failure: {}", e)),
                            })
                            .expect("Daemon is dead");
                    }
                });
                Ok(process_id)
            }
            Err(e) => Err(format!("Cannot execute command: {:?}", e)),
        }
    }
}

impl ExecerReal {
    pub fn new() -> Self {
        Self {
            logger: Logger::new("Execer"),
            spawn_wrapper: Box::new(SpawnWrapperReal {}),
        }
    }
}

pub struct LauncherReal {
    execer: Box<dyn Execer>,
    verifier: Box<dyn LaunchVerifier>,
}

impl Launcher for LauncherReal {
    fn launch(
        &self,
        mut params: HashMap<String, String>,
        crashed_recipient: Recipient<CrashNotification>,
    ) -> Result<Option<LaunchSuccess>, String> {
        let redirect_ui_port = find_free_port();
        params.insert("ui-port".to_string(), format!("{}", redirect_ui_port));
        let params_vec = params
            .into_iter()
            .sorted_by_key(|(n, _)| n.clone())
            .flat_map(|(n, v)| vec![format!("--{}", n), v])
            .collect_vec();
        match self.execer.exec(params_vec, crashed_recipient) {
            Ok(new_process_id) => {
                match self.verifier.verify_launch(new_process_id, redirect_ui_port) {
                    Launched => Ok(Some(LaunchSuccess { new_process_id, redirect_ui_port })),
                    CleanFailure => Err(format! ("Node started in process {}, but died immediately.", new_process_id)),
                    DirtyFailure => Err(format! ("Node started in process {}, but was unresponsive and was successfully killed.", new_process_id)),
                    InterventionRequired => Err(format! ("Node started in process {}, but was unresponsive and could not be killed. Manual intervention is required.", new_process_id)),
                }
            }
            Err(s) => Err(s),
        }
    }
}

impl LauncherReal {
    // _sender is needed for the not-Windows side; it's not used here
    pub fn new(_sender: Sender<HashMap<String, String>>) -> Self {
        Self {
            execer: Box::new(ExecerReal::new()),
            verifier: Box::new(LaunchVerifierReal::new()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::launch_verifier::LaunchVerification::Launched;
    use crate::daemon::mocks::LaunchVerifierMock;
    use crate::test_utils::recorder::make_recorder;
    use actix::Actor;
    use actix::System;
    use crossbeam_channel::unbounded;
    use masq_lib::constants::DEFAULT_UI_PORT;
    use masq_lib::test_utils::logging::{init_test_logging, TestLogHandler};
    use std::cell::RefCell;
    use std::io::ErrorKind;
    use std::iter::FromIterator;
    #[cfg(not(target_os = "windows"))]
    use std::os::unix::process::ExitStatusExt;
    #[cfg(target_os = "windows")]
    use std::os::windows::process::ExitStatusExt;
    use std::process::ExitStatus;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::Duration;

    struct ChildWrapperMock {
        wait_latency_ms: u64,
        id_results: RefCell<Vec<u32>>,
        wait_with_output_results: RefCell<Vec<std::io::Result<Output>>>,
    }

    impl ChildWrapper for ChildWrapperMock {
        fn id(&self) -> u32 {
            self.id_results.borrow_mut().remove(0)
        }

        fn wait_with_output(&mut self) -> std::io::Result<Output> {
            thread::sleep(Duration::from_millis(self.wait_latency_ms));
            self.wait_with_output_results.borrow_mut().remove(0)
        }
    }

    impl ChildWrapperMock {
        pub fn new(wait_latency_ms: u64) -> Self {
            Self {
                wait_latency_ms,
                id_results: RefCell::new(vec![]),
                wait_with_output_results: RefCell::new(vec![]),
            }
        }

        pub fn id_result(self, result: u32) -> Self {
            self.id_results.borrow_mut().push(result);
            self
        }

        pub fn wait_with_output_result(self, result: std::io::Result<Output>) -> Self {
            self.wait_with_output_results.borrow_mut().push(result);
            self
        }
    }

    struct SpawnWrapperMock {
        spawn_params: Arc<Mutex<Vec<(PathBuf, Vec<String>)>>>,
        spawn_results: RefCell<Vec<std::io::Result<Box<dyn ChildWrapper>>>>,
    }

    impl SpawnWrapper for SpawnWrapperMock {
        fn spawn(
            &self,
            exe_path: PathBuf,
            params: Vec<String>,
        ) -> std::io::Result<Box<dyn ChildWrapper>> {
            self.spawn_params.lock().unwrap().push((exe_path, params));
            self.spawn_results.borrow_mut().remove(0)
        }
    }

    impl SpawnWrapperMock {
        pub fn new() -> Self {
            Self {
                spawn_params: Arc::new(Mutex::new(vec![])),
                spawn_results: RefCell::new(vec![]),
            }
        }

        pub fn spawn_params(mut self, params: &Arc<Mutex<Vec<(PathBuf, Vec<String>)>>>) -> Self {
            self.spawn_params = params.clone();
            self
        }

        pub fn spawn_result(self, result: std::io::Result<Box<dyn ChildWrapper>>) -> Self {
            self.spawn_results.borrow_mut().push(result);
            self
        }
    }

    struct ExecerMock {
        exec_params: Arc<Mutex<Vec<(Vec<String>, Recipient<CrashNotification>)>>>,
        exec_results: RefCell<Vec<Result<u32, String>>>,
    }

    impl Execer for ExecerMock {
        fn exec(
            &self,
            params: Vec<String>,
            crashed_recipient: Recipient<CrashNotification>,
        ) -> Result<u32, String> {
            self.exec_params
                .lock()
                .unwrap()
                .push((params, crashed_recipient));
            self.exec_results.borrow_mut().remove(0)
        }
    }

    impl ExecerMock {
        fn new() -> Self {
            ExecerMock {
                exec_params: Arc::new(Mutex::new(vec![])),
                exec_results: RefCell::new(vec![]),
            }
        }

        fn exec_params(
            mut self,
            params: &Arc<Mutex<Vec<(Vec<String>, Recipient<CrashNotification>)>>>,
        ) -> Self {
            self.exec_params = params.clone();
            self
        }

        fn exec_result(self, result: Result<u32, String>) -> Self {
            self.exec_results.borrow_mut().push(result);
            self
        }
    }

    #[test]
    fn execer_happy_path() {
        init_test_logging();
        let (daemon, daemon_awaiter, daemon_recording_arc) = make_recorder();
        let child_wrapper = ChildWrapperMock::new(100)
            .id_result(1234)
            .wait_with_output_result(Ok(Output {
                status: ExitStatus::from_raw(1),
                stdout: b"Standard out".to_vec(),
                stderr: b"Standard error".to_vec(),
            }));
        let spawn_wrapper_params_arc = Arc::new(Mutex::new(vec![]));
        let spawn_wrapper = SpawnWrapperMock::new()
            .spawn_params(&spawn_wrapper_params_arc)
            .spawn_result(Ok(Box::new(child_wrapper)));
        let exe_path = std::env::current_exe().unwrap();
        let params = vec!["paramOne".to_string(), "paramTwo".to_string()];
        let inner_params = params.clone();
        let mut subject = ExecerReal::new();
        subject.spawn_wrapper = Box::new(spawn_wrapper);
        let (result_tx, result_rx) = unbounded_channel();
        thread::spawn(move || {
            let system = System::new();
            let crashed_recipient = daemon.start().recipient();

            result_tx
                .send(subject.exec(inner_params, crashed_recipient))
                .unwrap();

            system.run();
        });
        let result = result_rx.recv().unwrap();
        assert_eq!(result, Ok(1234));
        daemon_awaiter.await_message_count(1);
        let daemon_recording = daemon_recording_arc.lock().unwrap();
        let msg = daemon_recording.get_record::<CrashNotification>(0);
        #[cfg(not(target_os = "windows"))]
        assert_eq!(
            msg,
            &CrashNotification {
                process_id: 1234,
                exit_code: None,
                stderr: Some("Standard error".to_string()),
            }
        );
        #[cfg(target_os = "windows")]
        assert_eq!(
            msg,
            &CrashNotification {
                process_id: 1234,
                exit_code: Some(1),
                stderr: Some("Standard error".to_string()),
            }
        );
        let spawn_wrapper_params = spawn_wrapper_params_arc.lock().unwrap();
        assert_eq!(*spawn_wrapper_params, vec![(exe_path, params)]);
        let exe_path = std::env::current_exe()
            .unwrap()
            .to_string_lossy()
            .to_string();
        TestLogHandler::new().exists_log_containing(&format!(
            "INFO: Execer: Starting Node with command: {} paramOne paramTwo",
            exe_path
        ));
    }

    #[test]
    fn execer_fails_to_wait_successfully() {
        let (daemon, daemon_awaiter, daemon_recording_arc) = make_recorder();
        let child_wrapper = ChildWrapperMock::new(100)
            .id_result(1234)
            .wait_with_output_result(Err(std::io::Error::from(ErrorKind::TimedOut)));
        let spawn_wrapper = SpawnWrapperMock::new().spawn_result(Ok(Box::new(child_wrapper)));
        let params = vec!["paramOne".to_string(), "paramTwo".to_string()];
        let inner_params = params.clone();
        let mut subject = ExecerReal::new();
        subject.spawn_wrapper = Box::new(spawn_wrapper);
        let (result_tx, result_rx) = unbounded_channel();
        thread::spawn(move || {
            let system = System::new();
            let crashed_recipient = daemon.start().recipient();

            result_tx
                .send(subject.exec(inner_params, crashed_recipient))
                .unwrap();

            system.run();
        });
        let result = result_rx.recv().unwrap();
        assert_eq!(result, Ok(1234));
        daemon_awaiter.await_message_count(1);
        let daemon_recording = daemon_recording_arc.lock().unwrap();
        let msg = daemon_recording.get_record::<CrashNotification>(0);
        let err = std::io::Error::from(ErrorKind::TimedOut);
        assert_eq!(
            msg,
            &CrashNotification {
                process_id: 1234,
                exit_code: None,
                stderr: Some(format!("Child wait failure: {}", err)),
            }
        );
    }

    #[test]
    fn launch_calls_execer_and_verifier_and_returns_success() {
        let (ui_gateway, _, ui_gateway_recording_arc) = make_recorder();
        let system = System::new();
        let crashed_recipient = ui_gateway.start().recipient();
        let exec_params_arc = Arc::new(Mutex::new(vec![]));
        let execer = ExecerMock::new()
            .exec_params(&exec_params_arc)
            .exec_result(Ok(1234));
        let verify_launch_params_arc = Arc::new(Mutex::new(vec![]));
        let verifier = LaunchVerifierMock::new()
            .verify_launch_params(&verify_launch_params_arc)
            .verify_launch_result(Launched);
        let mut subject = LauncherReal::new(unbounded().0);
        subject.execer = Box::new(execer);
        subject.verifier = Box::new(verifier);
        let params = HashMap::from_iter(
            vec![
                ("name".to_string(), "value".to_string()),
                ("ui-port".to_string(), format!("{}", DEFAULT_UI_PORT)),
            ]
            .into_iter(),
        );

        let result = subject
            .launch(params.clone(), crashed_recipient)
            .unwrap()
            .unwrap();

        assert_eq!(result.new_process_id, 1234);
        assert!(result.redirect_ui_port > 1024);
        let exec_params = exec_params_arc.lock().unwrap();
        assert_eq!(
            (*exec_params)
                .iter()
                .map(|x| &x.0)
                .collect::<Vec<&Vec<String>>>(),
            vec![&vec![
                "--name".to_string(),
                "value".to_string(),
                "--ui-port".to_string(),
                format!("{}", result.redirect_ui_port),
            ]]
        );
        let verify_launch_params = verify_launch_params_arc.lock().unwrap();
        assert_eq!(*verify_launch_params, vec![(1234, result.redirect_ui_port)]);
        let msg = CrashNotification {
            process_id: 12345,
            exit_code: Some(4),
            stderr: Some("".to_string()),
        };
        (*exec_params)[0].1.try_send(msg.clone()).unwrap();
        System::current().stop();
        system.run();
        let ui_gateway_recording = ui_gateway_recording_arc.lock().unwrap();
        assert_eq!(
            *ui_gateway_recording.get_record::<CrashNotification>(0),
            msg
        );
    }

    #[test]
    fn launch_calls_execer_and_returns_failure() {
        let (ui_gateway, _, _) = make_recorder();
        let crashed_recipient = ui_gateway.start().recipient();
        let exec_params_arc = Arc::new(Mutex::new(vec![]));
        let execer = ExecerMock::new()
            .exec_params(&exec_params_arc)
            .exec_result(Err("Booga!".to_string()));
        let verifier = LaunchVerifierMock::new();
        let mut subject = LauncherReal::new(unbounded().0);
        subject.execer = Box::new(execer);
        subject.verifier = Box::new(verifier);
        let params = HashMap::from_iter(
            vec![
                ("name".to_string(), "value".to_string()),
                ("ui-port".to_string(), format!("{}", DEFAULT_UI_PORT)),
            ]
            .into_iter(),
        );

        let result = subject
            .launch(params.clone(), crashed_recipient)
            .err()
            .unwrap();

        assert_eq!(result, "Booga!".to_string());
    }

    #[test]
    fn launch_calls_execer_and_verifier_and_returns_clean_failure() {
        let (ui_gateway, _, _) = make_recorder();
        let crashed_recipient = ui_gateway.start().recipient();
        let execer = ExecerMock::new().exec_result(Ok(1234));
        let verifier = LaunchVerifierMock::new().verify_launch_result(CleanFailure);
        let mut subject = LauncherReal::new(unbounded().0);
        subject.execer = Box::new(execer);
        subject.verifier = Box::new(verifier);

        let result = subject
            .launch(HashMap::new(), crashed_recipient)
            .err()
            .unwrap();

        assert_eq!(
            result,
            format!("Node started in process 1234, but died immediately.")
        )
    }

    #[test]
    fn launch_calls_execer_and_verifier_and_returns_dirty_failure() {
        let (ui_gateway, _, _) = make_recorder();
        let crashed_recipient = ui_gateway.start().recipient();
        let execer = ExecerMock::new().exec_result(Ok(1234));
        let verifier = LaunchVerifierMock::new().verify_launch_result(DirtyFailure);
        let mut subject = LauncherReal::new(unbounded().0);
        subject.execer = Box::new(execer);
        subject.verifier = Box::new(verifier);

        let result = subject
            .launch(HashMap::new(), crashed_recipient)
            .err()
            .unwrap();

        assert_eq!(
            result,
            format!(
                "Node started in process 1234, but was unresponsive and was successfully killed."
            )
        )
    }

    #[test]
    fn launch_calls_execer_and_verifier_and_returns_intervention_required() {
        let (ui_gateway, _, _) = make_recorder();
        let crashed_recipient = ui_gateway.start().recipient();
        let execer = ExecerMock::new().exec_result(Ok(1234));
        let verifier = LaunchVerifierMock::new().verify_launch_result(InterventionRequired);
        let mut subject = LauncherReal::new(unbounded().0);
        subject.execer = Box::new(execer);
        subject.verifier = Box::new(verifier);

        let result = subject
            .launch(HashMap::new(), crashed_recipient)
            .err()
            .unwrap();

        assert_eq! (result, format! ("Node started in process 1234, but was unresponsive and could not be killed. Manual intervention is required."))
    }
}
