// Copyright (c) 2019, MASQ (https://masq.ai). All rights reserved.
#![cfg(not(target_os = "windows"))]

use crate::daemon::launch_verifier::LaunchVerification::{
    CleanFailure, DirtyFailure, InterventionRequired, Launched,
};
use crate::daemon::launch_verifier::{LaunchVerifier, LaunchVerifierReal};
use crate::daemon::{LaunchSuccess, Launcher};
use crate::test_utils::find_free_port;
use actix::System;
use nix::unistd::{fork, ForkResult};
use std::collections::HashMap;
use std::iter::FromIterator;
use std::sync::mpsc::Sender;

pub trait Forker {
    fn fork(&self) -> nix::Result<ForkResult>;
}

pub struct ForkerReal {}

impl Forker for ForkerReal {
    fn fork(&self) -> nix::Result<ForkResult> {
        fork()
    }
}

impl ForkerReal {
    pub fn new() -> Self {
        Self {}
    }
}

pub struct LauncherReal {
    forker: Box<dyn Forker>,
    sender: Sender<HashMap<String, String>>,
    verifier: Box<dyn LaunchVerifier>,
}

impl Launcher for LauncherReal {
    fn launch(&self, params: HashMap<String, String>) -> Result<Option<LaunchSuccess>, String> {
        let redirect_ui_port = find_free_port();
        match self.forker.fork() {
            Ok(ForkResult::Parent { child }) => {
                let child_pid = child.as_raw() as u32;
                match self.verifier.verify_launch(child_pid, redirect_ui_port) {
                    Launched => Ok(Some(LaunchSuccess {
                        new_process_id: child.as_raw() as u32,
                        redirect_ui_port,
                    })),
                    CleanFailure => Err (format! ("Node started in process {}, but died immediately.", child_pid)),
                    DirtyFailure => Err (format! ("Node started in process {}, but was unresponsive and was successfully killed.", child_pid)),
                    InterventionRequired => Err (format! ("Node started in process {}, but was unresponsive and could not be killed. Manual intervention is required.", child_pid)),
                }
            }
            Ok(ForkResult::Child) => {
                let mut actual_params: HashMap<String, String> =
                    HashMap::from_iter(params.clone().into_iter());
                actual_params.insert("ui-port".to_string(), format!("{}", redirect_ui_port));
                self.sender
                    .send(actual_params)
                    .expect("DaemonInitializer is dead");
                System::current().stop();
                // This is useless information
                Ok(None)
            }
            Err(e) => Err(format!("{}", e)),
        }
    }
}

impl LauncherReal {
    pub fn new(sender: Sender<HashMap<String, String>>) -> Self {
        Self {
            forker: Box::new(ForkerReal::new()),
            sender,
            verifier: Box::new(LaunchVerifierReal::new()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::launch_verifier::LaunchVerification::{
        CleanFailure, DirtyFailure, InterventionRequired, Launched,
    };
    use crate::daemon::launch_verifier_mock::LaunchVerifierMock;
    use actix::System;
    use nix::unistd::Pid;
    use std::cell::RefCell;
    use std::sync::mpsc::TryRecvError;
    use std::sync::{Arc, Mutex};

    struct ForkerMock {
        fork_results: RefCell<Vec<nix::Result<ForkResult>>>,
    }

    impl Forker for ForkerMock {
        fn fork(&self) -> nix::Result<ForkResult> {
            self.fork_results.borrow_mut().remove(0)
        }
    }

    impl ForkerMock {
        fn new() -> Self {
            ForkerMock {
                fork_results: RefCell::new(vec![]),
            }
        }

        fn fork_result(self, result: nix::Result<ForkResult>) -> Self {
            self.fork_results.borrow_mut().push(result);
            self
        }
    }

    #[test]
    fn launch_as_parent_calls_forker_and_verifier_and_returns_without_sending_parameters_or_killing_system_on_success(
    ) {
        let forker = ForkerMock::new().fork_result(Ok(ForkResult::Parent {
            child: Pid::from_raw(1234),
        }));
        let (sender, receiver) = std::sync::mpsc::channel();
        let verify_launch_params_arc = Arc::new(Mutex::new(vec![]));
        let verifier = LaunchVerifierMock::new()
            .verify_launch_params(&verify_launch_params_arc)
            .verify_launch_result(Launched);
        let mut subject = LauncherReal::new(sender);
        subject.forker = Box::new(forker);
        subject.verifier = Box::new(verifier);
        let params = HashMap::from_iter(
            vec![
                ("bname".to_string(), "bvalue".to_string()),
                ("aname".to_string(), "avalue".to_string()),
            ]
            .into_iter(),
        );

        let result = subject.launch(params).unwrap().unwrap();

        assert_eq!(result.new_process_id, 1234);
        assert!(result.redirect_ui_port > 1024); // dunno what exactly will be picked
        let sent_params = receiver.try_recv();
        assert_eq!(sent_params, Err(TryRecvError::Empty));
        let verify_launch_params = verify_launch_params_arc.lock().unwrap();
        assert_eq!(*verify_launch_params, vec![(1234, result.redirect_ui_port)])
        // Since no actor system is running, if the subject did a System::current().stop(), this test would die.
    }

    #[test]
    fn launch_as_child_calls_forker_and_sends_parameters_and_kills_system_on_success() {
        let forker = ForkerMock::new().fork_result(Ok(ForkResult::Child));
        let (sender, receiver) = std::sync::mpsc::channel();
        let verifier = LaunchVerifierMock::new();
        let mut subject = LauncherReal::new(sender);
        subject.forker = Box::new(forker);
        subject.verifier = Box::new(verifier);
        let params = HashMap::from_iter(
            vec![
                ("bname".to_string(), "bvalue".to_string()),
                ("aname".to_string(), "avalue".to_string()),
            ]
            .into_iter(),
        );
        let system = System::new("test");

        let result = subject.launch(params.clone()).unwrap();

        system.run(); // this should return immediately, because launch() already sent the stop message.
        assert_eq!(result, None);
        let sent_params = receiver.recv().unwrap();
        assert_eq!(sent_params.get("aname").unwrap(), "avalue");
        assert_eq!(sent_params.get("bname").unwrap(), "bvalue");
        let ui_port = sent_params.get("ui-port").unwrap().parse::<u16>().unwrap();
        assert!(ui_port > 1024); // dunno what exactly will be picked
    }

    #[test]
    fn launch_calls_forker_and_returns_failure() {
        let forker = ForkerMock::new().fork_result(Err(nix::Error::UnsupportedOperation));
        let (sender, _) = std::sync::mpsc::channel();
        let mut subject = LauncherReal::new(sender);
        subject.forker = Box::new(forker);
        let params = HashMap::from_iter(
            vec![
                ("bname".to_string(), "bvalue".to_string()),
                ("aname".to_string(), "avalue".to_string()),
            ]
            .into_iter(),
        );

        let result = subject.launch(params).err().unwrap();

        assert_eq!(result, "Unsupported Operation".to_string());
    }

    #[test]
    fn launch_as_parent_calls_forker_and_verifier_and_returns_clean_failure() {
        let forker = ForkerMock::new().fork_result(Ok(ForkResult::Parent {
            child: Pid::from_raw(1234),
        }));
        let verifier = LaunchVerifierMock::new().verify_launch_result(CleanFailure);
        let mut subject = LauncherReal::new(std::sync::mpsc::channel().0);
        subject.forker = Box::new(forker);
        subject.verifier = Box::new(verifier);

        let result = subject.launch(HashMap::new()).err().unwrap();

        assert_eq!(
            result,
            format!("Node started in process 1234, but died immediately.")
        );
    }

    #[test]
    fn launch_as_parent_calls_forker_and_verifier_and_returns_dirty_failure() {
        let forker = ForkerMock::new().fork_result(Ok(ForkResult::Parent {
            child: Pid::from_raw(1234),
        }));
        let verifier = LaunchVerifierMock::new().verify_launch_result(DirtyFailure);
        let mut subject = LauncherReal::new(std::sync::mpsc::channel().0);
        subject.forker = Box::new(forker);
        subject.verifier = Box::new(verifier);

        let result = subject.launch(HashMap::new()).err().unwrap();

        assert_eq!(
            result,
            format!(
                "Node started in process 1234, but was unresponsive and was successfully killed.",
            )
        );
    }

    #[test]
    fn launch_as_parent_calls_forker_and_verifier_and_returns_intervention_required() {
        let forker = ForkerMock::new().fork_result(Ok(ForkResult::Parent {
            child: Pid::from_raw(1234),
        }));
        let verifier = LaunchVerifierMock::new().verify_launch_result(InterventionRequired);
        let mut subject = LauncherReal::new(std::sync::mpsc::channel().0);
        subject.forker = Box::new(forker);
        subject.verifier = Box::new(verifier);

        let result = subject.launch(HashMap::new()).err().unwrap();

        assert_eq! (result, format!("Node started in process 1234, but was unresponsive and could not be killed. Manual intervention is required."));
    }
}
