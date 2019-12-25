// Copyright (c) 2019, MASQ (https://masq.ai). All rights reserved.
#![cfg(not(target_os = "windows"))]

use std::collections::HashMap;
use std::sync::mpsc::Sender;
use crate::test_utils::find_free_port;
use std::iter::FromIterator;
use nix::unistd::{ForkResult, fork};
use crate::daemon::{LaunchSuccess, Launcher};
use actix::System;

pub enum LocalForkResult {
    Parent (i32),
    Child,
}

pub trait Forker {
    fn fork (&self) -> Result<LocalForkResult, String>;
}

pub struct ForkerReal {}

impl Forker for ForkerReal {
    fn fork(&self) -> Result<LocalForkResult, String> {
        match fork() {
            Ok (ForkResult::Parent{child}) => Ok (LocalForkResult::Parent (child.as_raw())),
            Ok (ForkResult::Child) => Ok (LocalForkResult::Child),
            Err (e) => Err (format! ("{:?}", e)),
        }
    }
}

impl ForkerReal {
    pub fn new () -> Self {
        Self{}
    }
}

pub struct LauncherReal {
    forker: Box<dyn Forker>,
    sender: Sender<HashMap<String, String>>,
}

impl Launcher for LauncherReal {
    fn launch(&self, params: HashMap<String, String>) -> Result<LaunchSuccess, String> {
        let redirect_ui_port = find_free_port();
        match self.forker.fork() {
            Ok(LocalForkResult::Parent (new_process_id)) => Ok(LaunchSuccess {
                new_process_id,
                redirect_ui_port,
            }),
            Ok(LocalForkResult::Child) => {
                let mut actual_params: HashMap<String, String> =
                    HashMap::from_iter(params.clone().into_iter());
                actual_params.insert("ui-port".to_string(), format!("{}", redirect_ui_port));
                self.sender.send (actual_params).expect ("DaemonInitializer is dead");
                System::current().stop();
                // This is useless information
                Ok(LaunchSuccess {new_process_id: 0, redirect_ui_port: 0})
            }
            Err(e) => Err(format!("{}", e)),
        }
    }
}

impl LauncherReal {
    pub fn new(sender: Sender<HashMap<String, String>>) -> Self {
        Self {
            forker: Box::new (ForkerReal::new()),
            sender
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::sync::mpsc::TryRecvError;
    use actix::System;

    struct ForkerMock {
        fork_results: RefCell<Vec<Result<LocalForkResult, String>>>
    }

    impl Forker for ForkerMock {
        fn fork(&self) -> Result<LocalForkResult, String> {
            self.fork_results.borrow_mut().remove(0)
        }
    }

    impl ForkerMock {
        fn new () -> Self {
            ForkerMock {
                fork_results: RefCell::new (vec![]),
            }
        }

        fn fork_result (self, result: Result<LocalForkResult, String>) -> Self {
            self.fork_results.borrow_mut().push (result);
            self
        }
    }

    #[test]
    fn launch_as_parent_calls_forker_and_returns_without_sending_parameters_or_killing_system_on_success () {
        let forker = ForkerMock::new()
            .fork_result(Ok(LocalForkResult::Parent (1234)));
        let (sender, receiver) = std::sync::mpsc::channel();
        let mut subject = LauncherReal::new (sender);
        subject.forker = Box::new (forker);
        let params = HashMap::from_iter(vec![
            ("bname".to_string(), "bvalue".to_string()),
            ("aname".to_string(), "avalue".to_string())
        ].into_iter());

        let result = subject.launch (params).unwrap();

        assert_eq! (result.new_process_id, 1234);
        assert! (result.redirect_ui_port > 1024); // dunno what exactly will be picked
        let sent_params = receiver.try_recv();
        assert_eq! (sent_params, Err(TryRecvError::Empty));
        // Since no actor system is running, if the subject did a System::current().stop(), this test would die.
    }

    #[test]
    fn launch_as_child_calls_forker_and_sends_parameters_and_kills_system_on_success () {
        let forker = ForkerMock::new()
            .fork_result(Ok(LocalForkResult::Child));
        let (sender, receiver) = std::sync::mpsc::channel();
        let mut subject = LauncherReal::new (sender);
        subject.forker = Box::new (forker);
        let params = HashMap::from_iter(vec![
            ("bname".to_string(), "bvalue".to_string()),
            ("aname".to_string(), "avalue".to_string())
        ].into_iter());
        let system = System::new("test");

        let result = subject.launch (params.clone()).unwrap();

        system.run(); // this should return immediately, because launch() already sent the stop message.
        assert_eq! (result.new_process_id, 0); // irrelevant
        assert_eq! (result.redirect_ui_port, 0); // irrelevant
        let sent_params = receiver.recv().unwrap();
        assert_eq! (sent_params.get ("aname").unwrap(), "avalue");
        assert_eq! (sent_params.get ("bname").unwrap(), "bvalue");
        let ui_port = sent_params.get ("ui-port").unwrap().parse::<u16>().unwrap();
        assert! (ui_port > 1024); // dunno what exactly will be picked
    }

    #[test]
    fn launch_as_calls_forker_and_returns_failure () {
        let forker = ForkerMock::new()
            .fork_result(Err("Booga!".to_string()));
        let (sender, _) = std::sync::mpsc::channel();
        let mut subject = LauncherReal::new (sender);
        subject.forker = Box::new (forker);
        let params = HashMap::from_iter(vec![
            ("bname".to_string(), "bvalue".to_string()),
            ("aname".to_string(), "avalue".to_string())
        ].into_iter());

        let result = subject.launch (params).err().unwrap();

        assert_eq! (result, "Booga!".to_string());
    }
}
