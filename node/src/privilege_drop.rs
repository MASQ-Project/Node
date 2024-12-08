// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
// Because we have conditional compilation going on in this file:
#![allow(unreachable_code)]
#![allow(dead_code)]
#![allow(unused_imports)]

#[cfg(not(target_os = "windows"))]
extern "C" {
    pub fn getuid() -> i32;
    pub fn getgid() -> i32;
    pub fn setuid(uid: i32) -> i32;
    pub fn setgid(gid: i32) -> i32;
}

use crate::bootstrapper::RealUser;
#[cfg(not(target_os = "windows"))]
use nix::NixPath;
use std::path::{Path, PathBuf};
use std::process::Command;

pub trait IdWrapper: Send {
    fn getuid(&self) -> i32;
    fn getgid(&self) -> i32;
    fn setuid(&self, uid: i32) -> i32;
    fn setgid(&self, gid: i32) -> i32;
}

pub struct IdWrapperReal;

#[cfg(not(target_os = "windows"))]
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

#[cfg(target_os = "windows")]
impl IdWrapper for IdWrapperReal {
    fn getuid(&self) -> i32 {
        -1
    }
    fn getgid(&self) -> i32 {
        -1
    }
    fn setuid(&self, _uid: i32) -> i32 {
        -1
    }
    fn setgid(&self, _gid: i32) -> i32 {
        -1
    }
}

pub trait PrivilegeDropper: Send {
    fn drop_privileges(&self, real_user: &RealUser);
    fn chown(&self, file: &Path, real_user: &RealUser);
    fn expect_privilege(&self, privilege_expected: bool) -> bool;
}

pub struct PrivilegeDropperReal {
    id_wrapper: Box<dyn IdWrapper>,
}

impl PrivilegeDropper for PrivilegeDropperReal {
    #[cfg(not(target_os = "windows"))]
    fn drop_privileges(&self, real_user: &RealUser) {
        if self.id_wrapper.getgid() == 0 {
            let gid_result = self
                .id_wrapper
                .setgid(real_user.gid_opt.expect("Group-ID logic not working"));
            if gid_result != 0 {
                panic!("Error code {} resetting group id", gid_result)
            }
            if self.id_wrapper.getgid() == 0 {
                panic!("Attempt to drop group privileges failed: still root")
            }
        }

        if self.id_wrapper.getuid() == 0 {
            let uid_result = self
                .id_wrapper
                .setuid(real_user.uid_opt.expect("User-ID logic not working"));
            if uid_result != 0 {
                panic!("Error code {} resetting user id", uid_result)
            }
            if self.id_wrapper.getuid() == 0 {
                panic!("Attempt to drop user privileges failed: still root")
            }
        }
    }

    #[cfg(target_os = "windows")]
    fn drop_privileges(&self, _real_user: &RealUser) {
        // Windows doesn't need drop_privileges: it runs as administrator the whole way
    }

    #[cfg(not(target_os = "windows"))]
    fn chown(&self, file: &Path, real_user: &RealUser) {
        // Don't bother trying if the file is blank
        if file.is_empty() {
            return;
        }
        // Don't bother trying to chown if we're not root
        if (self.id_wrapper.getgid() == 0) && (self.id_wrapper.getuid() == 0) {
            let mut command = std::process::Command::new("chown");
            let args = vec![
                format!(
                    "{}:{}",
                    real_user.uid_opt.expect("User-ID logic not working"),
                    real_user.gid_opt.expect("Group-ID logic not working")
                ),
                format!("{}", file.display()),
            ];
            command.args(args.clone());
            let exit_status = command
                .status()
                .expect("Could not retrieve status from chown command");
            if !exit_status.success() {
                panic!(
                    "As root, couldn't chown {:?} to {:?}: exit code {:?}",
                    file, args, exit_status
                );
            }
        }
    }

    #[cfg(target_os = "windows")]
    fn chown(&self, _file: &Path, _real_user: &RealUser) {
        // Windows doesn't need chown: it runs as administrator the whole way
    }

    #[cfg(target_os = "windows")]
    fn expect_privilege(&self, privilege_expected: bool) -> bool {
        let mut command = Command::new("net");
        let command = command.args(vec!["session"]);
        let output = command
            .output()
            .expect("net session command didn't produce output");
        privilege_expected == output.status.success()
    }

    #[cfg(not(target_os = "windows"))]
    fn expect_privilege(&self, privilege_expected: bool) -> bool {
        (self.id_wrapper.getuid() == 0) == privilege_expected
    }
}

impl PrivilegeDropperReal {
    pub fn new() -> PrivilegeDropperReal {
        PrivilegeDropperReal {
            id_wrapper: Box::new(IdWrapperReal {}),
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
    #![allow(unreachable_code)]
    #![allow(dead_code)]
    #![allow(unused_imports)]
    use super::*;
    use crate::node_configurator::DirsWrapperReal;
    use crate::node_test_utils::IdWrapperMock;
    use std::sync::{Arc, Mutex};

    #[cfg(not(target_os = "windows"))]
    #[test]
    #[should_panic(expected = "Error code 47 resetting group id")]
    fn gid_error_code_causes_panic() {
        let id_wrapper = IdWrapperMock::new()
            .getuid_result(0)
            .getgid_result(0)
            .getuid_result(0)
            .getgid_result(0)
            .setgid_result(47);
        let mut subject = PrivilegeDropperReal::new();
        subject.id_wrapper = Box::new(id_wrapper);

        subject.drop_privileges(
            &RealUser::new(None, None, None).populate(&DirsWrapperReal::default()),
        );
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    #[should_panic(expected = "Error code 47 resetting user id")]
    fn uid_error_code_causes_panic() {
        let id_wrapper = IdWrapperMock::new()
            .getuid_result(0)
            .getgid_result(0)
            .setgid_result(0)
            .getgid_result(202)
            .setuid_result(47);
        let mut subject = PrivilegeDropperReal::new();
        subject.id_wrapper = Box::new(id_wrapper);

        subject.drop_privileges(&RealUser::new(Some(111), Some(222), None));
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    #[should_panic(expected = "Attempt to drop group privileges failed: still root")]
    fn final_gid_of_0_causes_panic() {
        let id_wrapper = IdWrapperMock::new()
            .getuid_result(0)
            .getgid_result(0)
            .setgid_result(0)
            .getgid_result(0);
        let mut subject = PrivilegeDropperReal::new();
        subject.id_wrapper = Box::new(id_wrapper);

        subject.drop_privileges(&RealUser::new(Some(111), Some(222), None));
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    #[should_panic(expected = "Attempt to drop user privileges failed: still root")]
    fn final_uid_of_0_causes_panic() {
        let id_wrapper = IdWrapperMock::new()
            .getuid_result(0)
            .getgid_result(0)
            .setgid_result(0)
            .getgid_result(202)
            .setuid_result(0)
            .getuid_result(0);
        let mut subject = PrivilegeDropperReal::new();
        subject.id_wrapper = Box::new(id_wrapper);

        subject.drop_privileges(&RealUser::new(Some(111), Some(222), None));
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn works_okay_with_real_user() {
        let setuid_params_arc = Arc::new(Mutex::new(vec![]));
        let setgid_params_arc = Arc::new(Mutex::new(vec![]));
        let id_wrapper = IdWrapperMock::new()
            .getuid_result(0)
            .getgid_result(0)
            .setuid_params(&setuid_params_arc)
            .setgid_params(&setgid_params_arc)
            .setuid_result(0)
            .setgid_result(0)
            .getuid_result(101)
            .getgid_result(202);
        let mut subject = PrivilegeDropperReal::new();
        subject.id_wrapper = Box::new(id_wrapper);

        subject.drop_privileges(&RealUser::new(
            Some(101),
            Some(202),
            Some("/home/user".into()),
        ));

        let setuid_params = setuid_params_arc.lock().unwrap();
        assert_eq!(*setuid_params, vec![101]);
        let setgid_params = setgid_params_arc.lock().unwrap();
        assert_eq!(*setgid_params, vec![202]);
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn works_okay_as_not_root() {
        let setuid_params_arc = Arc::new(Mutex::new(vec![]));
        let setgid_params_arc = Arc::new(Mutex::new(vec![]));
        let id_wrapper = IdWrapperMock::new()
            .getuid_result(101)
            .getgid_result(202)
            .setuid_params(&setuid_params_arc)
            .setgid_params(&setgid_params_arc);
        let mut subject = PrivilegeDropperReal::new();
        subject.id_wrapper = Box::new(id_wrapper);

        subject.drop_privileges(
            &RealUser::new(None, None, None).populate(&DirsWrapperReal::default()),
        );

        let setuid_params = setuid_params_arc.lock().unwrap();
        assert!(setuid_params.is_empty());
        let setgid_params = setgid_params_arc.lock().unwrap();
        assert!(setgid_params.is_empty());
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn expect_privilege_works_outside_windows() {
        let subject = PrivilegeDropperReal::new();

        assert_eq!(subject.expect_privilege(true), false);
        assert_eq!(subject.expect_privilege(false), true);
    }
}
