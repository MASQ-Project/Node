// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
// Because we have conditional compilation going on in this file:
#![allow(unreachable_code)]
#![allow(dead_code)]

#[cfg(unix)]
extern "C" {
    pub fn getuid() -> i32;
    pub fn getgid() -> i32;
    pub fn setuid(uid: i32) -> i32;
    pub fn setgid(gid: i32) -> i32;
}

use std::env::var;
use std::path::PathBuf;

pub trait IdWrapper: Send {
    fn getuid(&self) -> i32;
    fn getgid(&self) -> i32;
    fn setuid(&self, uid: i32) -> i32;
    fn setgid(&self, gid: i32) -> i32;
}

pub struct IdWrapperReal;

pub trait EnvironmentWrapper: Send {
    fn var(&self, key: &str) -> Option<String>;
}

pub struct EnvironmentWrapperReal;

impl EnvironmentWrapper for EnvironmentWrapperReal {
    fn var(&self, key: &str) -> Option<String> {
        match var(key) {
            Ok(s) => Some(s),
            Err(_) => None,
        }
    }
}

#[cfg(unix)]
impl IdWrapper for IdWrapperReal {
    fn getuid(&self) -> i32 {
        unsafe { getuid() }
    }
    fn getgid(&self) -> i32 {
        unsafe { getgid() }
    }
    fn setuid(&self, uid: i32) -> i32 {
        unsafe { setuid(uid) }
    }
    fn setgid(&self, gid: i32) -> i32 {
        unsafe { setgid(gid) }
    }
}

#[cfg(windows)]
impl IdWrapper for IdWrapperReal {
    // crashpoint - can this be removed?
    fn getuid(&self) -> i32 {
        !unimplemented!()
    }
    // crashpoint
    fn getgid(&self) -> i32 {
        !unimplemented!()
    }
    // crashpoint
    fn setuid(&self, _uid: i32) -> i32 {
        !unimplemented!()
    }
    // crashpoint
    fn setgid(&self, _gid: i32) -> i32 {
        !unimplemented!()
    }
}

pub trait PrivilegeDropper: Send {
    fn drop_privileges(&self);
    fn chown(&self, file: &PathBuf);
}

pub struct PrivilegeDropperReal {
    id_wrapper: Box<dyn IdWrapper>,
    environment_wrapper: Box<dyn EnvironmentWrapper>,
}

impl PrivilegeDropper for PrivilegeDropperReal {
    fn drop_privileges(&self) {
        #[cfg(unix)]
        {
            let sudo_gid = self.id_from_env("SUDO_GID");
            let sudo_uid = self.id_from_env("SUDO_UID");
            let gid = sudo_gid.unwrap_or_else(|| self.id_wrapper.getgid());
            let gid_result = self.id_wrapper.setgid(gid);
            if gid_result != 0 {
                panic!("Error code {} resetting group id", gid_result)
            }
            if self.id_wrapper.getgid() == 0 {
                panic!("Attempt to drop group privileges failed: still root")
            }

            let uid = sudo_uid.unwrap_or_else(|| self.id_wrapper.getuid());
            let uid_result = self.id_wrapper.setuid(uid);
            if uid_result != 0 {
                panic!("Error code {} resetting user id", uid_result)
            }
            if self.id_wrapper.getuid() == 0 {
                panic!("Attempt to drop user privileges failed: still root")
            }
        }
    }

    #[cfg(unix)]
    fn chown(&self, file: &PathBuf) {
        let sudo_uid = self.id_from_env("SUDO_UID");
        let uid = sudo_uid.unwrap_or_else(|| self.id_wrapper.getuid());
        let sudo_gid = self.id_from_env("SUDO_GID");
        let gid = sudo_gid.unwrap_or_else(|| self.id_wrapper.getgid());
        let mut command = std::process::Command::new("chown");
        command.args(vec![
            format!("{}:{}", uid, gid),
            format!("{}", file.display()),
        ]);
        let exit_status = command
            .status()
            .expect("Could not retrieve status from chown command");
        if !exit_status.success() {
            if self.id_wrapper.getuid() == 0 {
                panic!("Couldn't chown as root");
            } else {
                // kind of expected this. Probably we're running tests or something.
            }
        }
    }

    #[cfg(windows)]
    fn chown(&self, _file: &PathBuf) {
        // Windows doesn't need chown: it runs as administrator the whole way
    }
}

impl PrivilegeDropperReal {
    pub fn new() -> PrivilegeDropperReal {
        PrivilegeDropperReal {
            // TODO: Bring these two lines under test
            id_wrapper: Box::new(IdWrapperReal {}),
            environment_wrapper: Box::new(EnvironmentWrapperReal {}),
        }
    }

    fn id_from_env(&self, name: &str) -> Option<i32> {
        match self.environment_wrapper.var(name) {
            Some(s) => match s.parse::<i32>() {
                Ok(n) => Some(n),
                Err(_) => None,
            },
            None => None,
        }
    }
}

impl Default for PrivilegeDropperReal {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::sync::{Arc, Mutex};

    #[derive(Default)]
    struct IdWrapperMock {
        getuid_results: RefCell<Vec<i32>>,
        setuid_params: Arc<Mutex<Vec<i32>>>,
        setuid_results: RefCell<Vec<i32>>,
        getgid_results: RefCell<Vec<i32>>,
        setgid_params: Arc<Mutex<Vec<i32>>>,
        setgid_results: RefCell<Vec<i32>>,
    }

    impl IdWrapper for IdWrapperMock {
        fn getuid(&self) -> i32 {
            self.getuid_results.borrow_mut().pop().unwrap()
        }
        fn getgid(&self) -> i32 {
            self.getgid_results.borrow_mut().pop().unwrap()
        }
        fn setuid(&self, uid: i32) -> i32 {
            self.setuid_params.lock().unwrap().push(uid);
            self.setuid_results.borrow_mut().pop().unwrap()
        }
        fn setgid(&self, gid: i32) -> i32 {
            self.setgid_params.lock().unwrap().push(gid);
            self.setgid_results.borrow_mut().pop().unwrap()
        }
    }

    impl IdWrapperMock {
        fn new() -> Self {
            Default::default()
        }

        fn getuid_result(self, uid: i32) -> Self {
            self.getuid_results.borrow_mut().push(uid);
            self
        }

        fn setuid_params(mut self, params: &Arc<Mutex<Vec<i32>>>) -> Self {
            self.setuid_params = params.clone();
            self
        }

        fn setuid_result(self, uid_result: i32) -> Self {
            self.setuid_results.borrow_mut().push(uid_result);
            self
        }

        fn getgid_result(self, gid: i32) -> Self {
            self.getgid_results.borrow_mut().push(gid);
            self
        }

        fn setgid_params(mut self, params: &Arc<Mutex<Vec<i32>>>) -> Self {
            self.setgid_params = params.clone();
            self
        }

        fn setgid_result(self, gid_result: i32) -> Self {
            self.setgid_results.borrow_mut().push(gid_result);
            self
        }
    }

    struct EnvironmentWrapperMock {
        sudo_uid: Option<String>,
        sudo_gid: Option<String>,
    }

    impl EnvironmentWrapper for EnvironmentWrapperMock {
        fn var(&self, key: &str) -> Option<String> {
            match key {
                "SUDO_UID" => self.sudo_uid.clone(),
                "SUDO_GID" => self.sudo_gid.clone(),
                _ => None,
            }
        }
    }

    impl EnvironmentWrapperMock {
        fn new(sudo_uid: Option<&str>, sudo_gid: Option<&str>) -> EnvironmentWrapperMock {
            EnvironmentWrapperMock {
                sudo_uid: match sudo_uid {
                    Some(x) => Some(String::from(x)),
                    None => None,
                },
                sudo_gid: match sudo_gid {
                    Some(x) => Some(String::from(x)),
                    None => None,
                },
            }
        }
    }

    #[cfg(unix)]
    #[test]
    #[should_panic(expected = "Error code 47 resetting group id")]
    fn gid_error_code_causes_panic() {
        let id_wrapper = IdWrapperMock::new().setgid_result(47);
        let environment_wrapper = EnvironmentWrapperMock::new(Some("1000"), Some("1000"));
        let subject = PrivilegeDropperReal {
            id_wrapper: Box::new(id_wrapper),
            environment_wrapper: Box::new(environment_wrapper),
        };

        subject.drop_privileges();
    }

    #[cfg(unix)]
    #[test]
    #[should_panic(expected = "Error code 47 resetting user id")]
    fn uid_error_code_causes_panic() {
        let id_wrapper = IdWrapperMock::new()
            .setgid_result(0)
            .getgid_result(1000)
            .setuid_result(47);
        let environment_wrapper = EnvironmentWrapperMock::new(Some("1000"), Some("1000"));
        let subject = PrivilegeDropperReal {
            id_wrapper: Box::new(id_wrapper),
            environment_wrapper: Box::new(environment_wrapper),
        };

        subject.drop_privileges();
    }

    #[cfg(unix)]
    #[test]
    #[should_panic(expected = "Attempt to drop group privileges failed: still root")]
    fn final_gid_of_0_causes_panic() {
        let id_wrapper = IdWrapperMock::new().setgid_result(0).getgid_result(0);
        let environment_wrapper = EnvironmentWrapperMock::new(Some("1000"), Some("1000"));
        let subject = PrivilegeDropperReal {
            id_wrapper: Box::new(id_wrapper),
            environment_wrapper: Box::new(environment_wrapper),
        };

        subject.drop_privileges();
    }

    #[cfg(unix)]
    #[test]
    #[should_panic(expected = "Attempt to drop user privileges failed: still root")]
    fn final_uid_of_0_causes_panic() {
        let id_wrapper = IdWrapperMock::new()
            .setgid_result(0)
            .getgid_result(1000)
            .setuid_result(0)
            .getuid_result(0);
        let environment_wrapper = EnvironmentWrapperMock::new(Some("1000"), Some("1000"));
        let subject = PrivilegeDropperReal {
            id_wrapper: Box::new(id_wrapper),
            environment_wrapper: Box::new(environment_wrapper),
        };

        subject.drop_privileges();
    }

    #[cfg(unix)]
    #[test]
    fn works_okay_as_root_with_environment_variables() {
        let setuid_params_arc = Arc::new(Mutex::new(vec![]));
        let setgid_params_arc = Arc::new(Mutex::new(vec![]));
        let id_wrapper = IdWrapperMock::new()
            .getuid_result(0)
            .getgid_result(0)
            .setuid_params(&setuid_params_arc)
            .setgid_params(&setgid_params_arc)
            .setuid_result(0)
            .setgid_result(0)
            .getuid_result(1000)
            .getgid_result(1000);
        let environment_wrapper = EnvironmentWrapperMock::new(Some("1000"), Some("1000"));
        let subject = PrivilegeDropperReal {
            id_wrapper: Box::new(id_wrapper),
            environment_wrapper: Box::new(environment_wrapper),
        };

        subject.drop_privileges();

        let setuid_params = setuid_params_arc.lock().unwrap();
        assert_eq!(*setuid_params, vec![1000]);
        let setgid_params = setgid_params_arc.lock().unwrap();
        assert_eq!(*setgid_params, vec![1000]);
    }
}
