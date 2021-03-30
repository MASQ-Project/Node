// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

use crate::netsh::NetshError::IOError;
use std::{io, process};

pub trait Netsh {
    fn set_nameserver(&self, interface: &str, value: &str) -> Result<(), NetshError>;
}

#[derive(Default)]
pub struct NetshCommand {}

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug)]
pub enum NetshError {
    NonZeroExit(i32),
    NoCodeExit,
    IOError(io::Error),
}

impl NetshCommand {
    fn command() -> process::Command {
        process::Command::new("netsh")
    }
}

fn make_set_args(interface_name: &str, address: &str) -> [String; 7] {
    [
        "interface".to_string(),
        "ip".to_string(),
        "set".to_string(),
        "dns".to_string(),
        format!(r#"name="{}""#, interface_name),
        "source=static".to_string(),
        format!("addr={}", address),
    ]
}

impl Netsh for NetshCommand {
    fn set_nameserver(&self, interface: &str, address: &str) -> Result<(), NetshError> {
        let mut netsh = Self::command();
        let command = netsh.args(&make_set_args(interface, address));
        match command.status() {
            Ok(status) if status.success() => Ok(()),
            Ok(status) => match status.code() {
                Some(code) => Err(NetshError::NonZeroExit(code)),
                None => Err(NetshError::NoCodeExit),
            },
            Err(e) => Err(IOError(e)),
        }
    }
}

#[cfg(test)]
pub mod tests_utils {
    use super::*;
    use std::cell::RefCell;
    use std::sync::{Arc, Mutex};

    #[derive(Default)]
    pub(crate) struct NetshMock {
        pub set_nameserver_parameters: Arc<Mutex<Vec<(String, String)>>>,
        set_nameserver_results: RefCell<Vec<Result<(), NetshError>>>,
    }

    impl Netsh for NetshMock {
        fn set_nameserver(&self, interface: &str, value: &str) -> Result<(), NetshError> {
            self.set_nameserver_parameters
                .lock()
                .expect("set_nameserver couldn't take params")
                .push((interface.to_string(), value.to_string()));
            self.set_nameserver_results
                .borrow_mut()
                .pop()
                .unwrap_or_else(|| panic!("set_nameserver called without a stub"))
        }
    }

    impl NetshMock {
        pub fn new() -> Self {
            Self::default()
        }

        pub fn set_nameserver_result(self, result: Result<(), NetshError>) -> Self {
            self.set_nameserver_results.borrow_mut().insert(0, result);
            self
        }
    }
}
