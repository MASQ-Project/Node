// Copyright (c) 2019, MASQ (https://masq.ai). All rights reserved.
#![cfg(target_os = "windows")]

use std::collections::HashMap;
use std::sync::mpsc::Sender;
use crate::daemon::{LaunchSuccess};

pub trait Execer {
    fn exec (&self, params: Vec<String>) -> Result<i32, String>;
}

pub struct ExecerReal {}

impl Execer for ExecerReal {
    fn exec(&self, params: Vec<String>) -> Result<i32, String> {
        unimplemented!()
    }
}

impl ExecerReal {
    pub fn new () -> Self {
        Self {}
    }
}

pub trait Launcher {
    fn launch(&self, params: HashMap<String, String>) -> Result<LaunchSuccess, String>;
}

pub struct LauncherReal {
    execer: Box<dyn Execer>
}

impl Launcher for LauncherReal {
    fn launch(&self, _params: HashMap<String, String>) -> Result<LaunchSuccess, String> {
        unimplemented!()
    }
}

impl LauncherReal {
    // _sender is needed for the not-Windows side; it's not used here
    pub fn new(_sender: Sender<HashMap<String, String>>) -> Self {
        Self {
            execer: Box::new (ExecerReal::new()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::iter::FromIterator;
    use std::sync::{Mutex, Arc};
    use std::cell::RefCell;

    struct ExecerMock {
        exec_params: Arc<Mutex<Vec<Vec<String>>>>,
        exec_results: RefCell<Vec<Result<i32, String>>>
    }

    impl Execer for ExecerMock {
        fn exec(&self, params: Vec<String>) -> Result<i32, String> {
            self.exec_params.lock().unwrap().push (params);
            self.exec_results.borrow_mut().remove(0)
        }
    }

    impl ExecerMock {
        fn new () -> Self {
            ExecerMock {
                exec_params: Arc::new (Mutex::new (vec![])),
                exec_results: RefCell::new (vec![]),
            }
        }

        fn exec_params (mut self, params: &Arc<Mutex<Vec<Vec<String>>>>) -> Self {
            self.exec_params = params.clone();
            self
        }

        fn exec_result(self, result: Result<i32, String>) -> Self {
            self.exec_results.borrow_mut().push (result);
            self
        }
    }

    #[test]
    fn launch_calls_execer_and_returns_success () {
        let exec_params_arc = Arc::new (Mutex::new (vec![]));
        let execer = ExecerMock::new()
            .exec_params(&exec_params_arc)
            .exec_result(Ok(1234));
        let mut subject = LauncherReal::new (std::sync::mpsc::channel().0);
        subject.execer = Box::new (execer);
        let params = HashMap::from_iter(vec![
            ("name".to_string(), "value".to_string()),
            ("ui-port".to_string(), "5333".to_string()),
        ].into_iter());

        let result = subject.launch (params.clone()).unwrap();

        assert_eq! (result.new_process_id, 1234);
        assert! (result.redirect_ui_port > 1024);
        let exec_params = exec_params_arc.lock().unwrap();
        assert_eq! (*exec_params, vec![vec![
            "--name".to_string(), "value".to_string(),
            "--ui-port".to_string(), format!("{}", result.redirect_ui_port),
        ]]);
    }

    #[test]
    fn launch_calls_execer_and_returns_failure () {
        let exec_params_arc = Arc::new (Mutex::new (vec![]));
        let execer = ExecerMock::new()
            .exec_params(&exec_params_arc)
            .exec_result(Err("Booga!".to_string()));
        let mut subject = LauncherReal::new (std::sync::mpsc::channel().0);
        subject.execer = Box::new (execer);
        let params = HashMap::from_iter(vec![
            ("name".to_string(), "value".to_string()),
            ("ui-port".to_string(), "5333".to_string()),
        ].into_iter());

        let result = subject.launch (params.clone()).err().unwrap();

        assert_eq! (result, "Booga!".to_string());
    }
}