// Copyright (c) 2019-2020, MASQ (https://masq.ai). All rights reserved.

use crate::daemon::launch_verifier::LaunchVerification::{
    CleanFailure, DirtyFailure, InterventionRequired, Launched,
};
use crate::daemon::launch_verifier::{LaunchVerifier, LaunchVerifierReal};
use crate::daemon::{LaunchSuccess, Launcher};
use itertools::Itertools;
use masq_lib::utils::find_free_port;
use std::collections::HashMap;
use std::process::Command;
use std::sync::mpsc::Sender;

pub trait Execer {
    fn exec(&self, params: Vec<String>) -> Result<u32, String>;
}

pub struct ExecerReal {}

impl Execer for ExecerReal {
    fn exec(&self, params: Vec<String>) -> Result<u32, String> {
        let exe_path = match std::env::current_exe() {
            Ok(path) => path,
            Err(e) => return Err(format!("Cannot find executable: {:?}", e)),
        };
        eprintln!("Executing {:?} with params {:?}", exe_path, params);
        match Command::new(exe_path).args(params).spawn() {
            Ok(child) => Ok(child.id()),
            Err(e) => Err(format!("Cannot execute command: {:?}", e)),
        }
    }
}

impl ExecerReal {
    pub fn new() -> Self {
        Self {}
    }
}

pub struct LauncherReal {
    execer: Box<dyn Execer>,
    verifier: Box<dyn LaunchVerifier>,
}

impl Launcher for LauncherReal {
    fn launch(&self, mut params: HashMap<String, String>) -> Result<Option<LaunchSuccess>, String> {
        let redirect_ui_port = find_free_port();
        params.insert("ui-port".to_string(), format!("{}", redirect_ui_port));
        let params_vec = params
            .into_iter()
            .sorted_by_key(|(n, _)| n.clone())
            .flat_map(|(n, v)| vec![format!("--{}", n), v])
            .collect_vec();
        match self.execer.exec(params_vec) {
            Ok(new_process_id) => {
                match self.verifier.verify_launch(new_process_id, redirect_ui_port) {
                    Launched => Ok(Some(LaunchSuccess {
                        new_process_id,
                        redirect_ui_port
                    })),
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
    use crate::daemon::launch_verifier_mock::LaunchVerifierMock;
    use masq_lib::ui_gateway::DEFAULT_UI_PORT;
    use std::cell::RefCell;
    use std::iter::FromIterator;
    use std::sync::{Arc, Mutex};

    struct ExecerMock {
        exec_params: Arc<Mutex<Vec<Vec<String>>>>,
        exec_results: RefCell<Vec<Result<u32, String>>>,
    }

    impl Execer for ExecerMock {
        fn exec(&self, params: Vec<String>) -> Result<u32, String> {
            self.exec_params.lock().unwrap().push(params);
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

        fn exec_params(mut self, params: &Arc<Mutex<Vec<Vec<String>>>>) -> Self {
            self.exec_params = params.clone();
            self
        }

        fn exec_result(self, result: Result<u32, String>) -> Self {
            self.exec_results.borrow_mut().push(result);
            self
        }
    }

    #[test]
    fn launch_calls_execer_and_verifier_and_returns_success() {
        let exec_params_arc = Arc::new(Mutex::new(vec![]));
        let execer = ExecerMock::new()
            .exec_params(&exec_params_arc)
            .exec_result(Ok(1234));
        let verify_launch_params_arc = Arc::new(Mutex::new(vec![]));
        let verifier = LaunchVerifierMock::new()
            .verify_launch_params(&verify_launch_params_arc)
            .verify_launch_result(Launched);
        let mut subject = LauncherReal::new(std::sync::mpsc::channel().0);
        subject.execer = Box::new(execer);
        subject.verifier = Box::new(verifier);
        let params = HashMap::from_iter(
            vec![
                ("name".to_string(), "value".to_string()),
                ("ui-port".to_string(), format!("{}", DEFAULT_UI_PORT)),
            ]
            .into_iter(),
        );

        let result = subject.launch(params.clone()).unwrap().unwrap();

        assert_eq!(result.new_process_id, 1234);
        assert!(result.redirect_ui_port > 1024);
        let exec_params = exec_params_arc.lock().unwrap();
        assert_eq!(
            *exec_params,
            vec![vec![
                "--name".to_string(),
                "value".to_string(),
                "--ui-port".to_string(),
                format!("{}", result.redirect_ui_port),
            ]]
        );
        let verify_launch_params = verify_launch_params_arc.lock().unwrap();
        assert_eq!(*verify_launch_params, vec![(1234, result.redirect_ui_port)])
    }

    #[test]
    fn launch_calls_execer_and_returns_failure() {
        let exec_params_arc = Arc::new(Mutex::new(vec![]));
        let execer = ExecerMock::new()
            .exec_params(&exec_params_arc)
            .exec_result(Err("Booga!".to_string()));
        let verifier = LaunchVerifierMock::new();
        let mut subject = LauncherReal::new(std::sync::mpsc::channel().0);
        subject.execer = Box::new(execer);
        subject.verifier = Box::new(verifier);
        let params = HashMap::from_iter(
            vec![
                ("name".to_string(), "value".to_string()),
                ("ui-port".to_string(), format!("{}", DEFAULT_UI_PORT)),
            ]
            .into_iter(),
        );

        let result = subject.launch(params.clone()).err().unwrap();

        assert_eq!(result, "Booga!".to_string());
    }

    #[test]
    fn launch_calls_execer_and_verifier_and_returns_clean_failure() {
        let execer = ExecerMock::new().exec_result(Ok(1234));
        let verifier = LaunchVerifierMock::new().verify_launch_result(CleanFailure);
        let mut subject = LauncherReal::new(std::sync::mpsc::channel().0);
        subject.execer = Box::new(execer);
        subject.verifier = Box::new(verifier);

        let result = subject.launch(HashMap::new()).err().unwrap();

        assert_eq!(
            result,
            format!("Node started in process 1234, but died immediately.")
        )
    }

    #[test]
    fn launch_calls_execer_and_verifier_and_returns_dirty_failure() {
        let execer = ExecerMock::new().exec_result(Ok(1234));
        let verifier = LaunchVerifierMock::new().verify_launch_result(DirtyFailure);
        let mut subject = LauncherReal::new(std::sync::mpsc::channel().0);
        subject.execer = Box::new(execer);
        subject.verifier = Box::new(verifier);

        let result = subject.launch(HashMap::new()).err().unwrap();

        assert_eq!(
            result,
            format!(
                "Node started in process 1234, but was unresponsive and was successfully killed."
            )
        )
    }

    #[test]
    fn launch_calls_execer_and_verifier_and_returns_intervention_required() {
        let execer = ExecerMock::new().exec_result(Ok(1234));
        let verifier = LaunchVerifierMock::new().verify_launch_result(InterventionRequired);
        let mut subject = LauncherReal::new(std::sync::mpsc::channel().0);
        subject.execer = Box::new(execer);
        subject.verifier = Box::new(verifier);

        let result = subject.launch(HashMap::new()).err().unwrap();

        assert_eq! (result, format! ("Node started in process 1234, but was unresponsive and could not be killed. Manual intervention is required."))
    }
}
