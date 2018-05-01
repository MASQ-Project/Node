// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
#[cfg(unix)]
extern {
    pub fn getuid () -> i32;
    pub fn getgid () -> i32;
    pub fn setuid (uid: i32) -> i32;
    pub fn setgid (gid: i32) -> i32;
}

use std::env::var;

pub trait IdWrapper {
    fn getuid (&self) -> i32;
    fn getgid (&self) -> i32;
    fn setuid (&self, uid: i32) -> i32;
    fn setgid (&self, gid: i32) -> i32;
}

pub struct IdWrapperReal;

pub trait EnvironmentWrapper {
    fn var (&self, key: &str) -> Option<String>;
}

pub struct EnvironmentWrapperReal;

impl EnvironmentWrapper for EnvironmentWrapperReal {
    fn var (&self, key: &str) -> Option<String> {
        match var (key) {
            Ok (s) => Some (s),
            Err (_) => None
        }
    }
}

#[cfg(unix)]
impl IdWrapper for IdWrapperReal {
    fn getuid (&self) -> i32 {unsafe { getuid ()}}
    fn getgid (&self) -> i32  {unsafe {getgid ()}}
    fn setuid (&self, uid: i32) -> i32 {unsafe {setuid (uid)}}
    fn setgid (&self, gid: i32) -> i32  {unsafe {setgid (gid)}}
}

#[cfg(windows)]
impl IdWrapper for IdWrapperReal {
    // crashpoint - can this be removed?
    fn getuid (&self) -> i32 { !unimplemented!() }
    // crashpoint
    fn getgid (&self) -> i32  { !unimplemented!() }
    // crashpoint
    fn setuid (&self, uid: i32) -> i32 { !unimplemented!() }
    // crashpoint
    fn setgid (&self, gid: i32) -> i32  { !unimplemented!() }
}

pub trait PrivilegeDropper {
    fn drop_privileges (&self);
}

pub struct PrivilegeDropperReal {
    id_wrapper: Box<IdWrapper>,
    environment_wrapper: Box<EnvironmentWrapper>
}

impl PrivilegeDropper for PrivilegeDropperReal {

    fn drop_privileges (&self) {
        #[cfg(unix)]
        {
            let sudo_gid = self.id_from_env("SUDO_GID");
            let sudo_uid = self.id_from_env("SUDO_UID");
            let gid = sudo_gid.unwrap_or(self.id_wrapper.getgid());
            let gid_result = self.id_wrapper.setgid(gid);
            if gid_result != 0 { panic!("Error code {} resetting group id", gid_result) }
            if self.id_wrapper.getgid() == 0 { panic!("Attempt to drop group privileges failed: still root") }

            let uid = sudo_uid.unwrap_or(self.id_wrapper.getuid());
            let uid_result = self.id_wrapper.setuid(uid);
            if uid_result != 0 { panic!("Error code {} resetting user id", uid_result) }
            if self.id_wrapper.getuid() == 0 { panic!("Attempt to drop user privileges failed: still root") }
        }
    }
}

impl PrivilegeDropperReal {

    pub fn new () -> PrivilegeDropperReal {
        PrivilegeDropperReal {
            // TODO: Bring these two lines under test
            id_wrapper: Box::new (IdWrapperReal {}),
            environment_wrapper: Box::new (EnvironmentWrapperReal {})
        }
    }

    fn id_from_env (&self, name: &str) -> Option<i32> {
        match self.environment_wrapper.var (name) {
            Some (s) => match s.parse::<i32> () {Ok(n) => Some (n), Err(_) => None},
            None => None
        }
    }
}

#[cfg (test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    struct IdWrapperMock {
        pub uids: RefCell<Vec<i32>>,
        pub uid_results: RefCell<Vec<i32>>,
        pub gids: RefCell<Vec<i32>>,
        pub gid_results: RefCell<Vec<i32>>,
        pub log: RefCell<Vec<String>>
    }

    impl IdWrapper for IdWrapperMock {
        fn getuid (&self) -> i32 {
            self.uids.borrow_mut ().pop ().unwrap ()
        }
        fn getgid (&self) -> i32  {
            self.gids.borrow_mut ().pop ().unwrap ()
        }
        fn setuid (&self, uid: i32) -> i32 {
            self.log.borrow_mut ().push (format! ("setuid ({})", uid));
            self.uid_results.borrow_mut ().pop ().unwrap ()
        }
        fn setgid (&self, gid: i32) -> i32  {
            self.log.borrow_mut ().push (format! ("setgid ({})", gid));
            self.gid_results.borrow_mut ().pop ().unwrap ()
        }
    }

    impl IdWrapperMock {
        fn new (uid_initial: i32, uid_result: i32, uid_final: i32, gid_initial: i32, gid_result: i32, gid_final: i32) -> IdWrapperMock {
            IdWrapperMock {
                uids: RefCell::new (vec![uid_final, uid_initial]),
                uid_results: RefCell::new (vec![uid_result]),
                gids: RefCell::new (vec![gid_final, gid_initial]),
                gid_results: RefCell::new (vec![gid_result]),
                log: RefCell::new (vec![])
            }
        }
    }

    struct EnvironmentWrapperMock {
        sudo_uid: Option<String>,
        sudo_gid: Option<String>
    }

    impl EnvironmentWrapper for EnvironmentWrapperMock {
        fn var(&self, key: &str) -> Option<String> {
            match key {
                "SUDO_UID" => self.sudo_uid.clone (),
                "SUDO_GID" => self.sudo_gid.clone (),
                _ => None
            }
        }
    }

    impl EnvironmentWrapperMock {
        fn new (sudo_uid: Option<&str>, sudo_gid: Option<&str>) -> EnvironmentWrapperMock {
            EnvironmentWrapperMock {
                sudo_uid: match sudo_uid {Some (x) => Some (String::from (x)), None => None},
                sudo_gid: match sudo_gid {Some (x) => Some (String::from (x)), None => None}
            }
        }
    }

    #[cfg(unix)]
    #[test]
    #[should_panic (expected = "Error code 47 resetting group id")]
    fn gid_error_code_causes_panic () {
        let id_wrapper = IdWrapperMock::new (0, 0, 1000, 0, 47, 0);
        let environment_wrapper = EnvironmentWrapperMock::new (Some ("1000"), Some ("1000"));
        let subject = PrivilegeDropperReal {id_wrapper: Box::new (id_wrapper), environment_wrapper: Box::new (environment_wrapper)};

        subject.drop_privileges ();
    }

    #[cfg(unix)]
    #[test]
    #[should_panic (expected = "Error code 47 resetting user id")]
    fn uid_error_code_causes_panic () {
        let id_wrapper = IdWrapperMock::new (0, 47, 0, 0, 0, 1000);
        let environment_wrapper = EnvironmentWrapperMock::new (Some ("1000"), Some ("1000"));
        let subject = PrivilegeDropperReal {id_wrapper: Box::new (id_wrapper), environment_wrapper: Box::new (environment_wrapper)};

        subject.drop_privileges ();
    }

    #[cfg(unix)]
    #[test]
    #[should_panic (expected = "Attempt to drop group privileges failed: still root")]
    fn final_gid_of_0_causes_panic () {
        let id_wrapper = IdWrapperMock::new (0, 0, 1000, 0, 0, 0);
        let environment_wrapper = EnvironmentWrapperMock::new (Some ("1000"), Some ("1000"));
        let subject = PrivilegeDropperReal {id_wrapper: Box::new (id_wrapper), environment_wrapper: Box::new (environment_wrapper)};

        subject.drop_privileges ();
    }

    #[cfg(unix)]
    #[test]
    #[should_panic (expected = "Attempt to drop user privileges failed: still root")]
    fn final_uid_of_0_causes_panic () {
        let id_wrapper = IdWrapperMock::new (0, 0, 0, 0, 0, 1000);
        let environment_wrapper = EnvironmentWrapperMock::new (Some ("1000"), Some ("1000"));
        let subject = PrivilegeDropperReal {id_wrapper: Box::new (id_wrapper), environment_wrapper: Box::new (environment_wrapper)};

        subject.drop_privileges ();
    }

    // TODO: Figure out how to make this test compile
//    #[test]
//    fn works_okay_as_root_with_environment_variables () {
//        let mut id_wrapper = IdWrapperMock::new (0, 0, 1000, 0, 0, 1000);
//        let environment_wrapper = EnvironmentWrapperMock::new (Some ("1000"), Some ("1000"));
//        let subject = PrivilegeDropper {
//            id_wrapper: Box::new (id_wrapper),
//            environment_wrapper: Box::new (environment_wrapper)
//        };
//
//        subject.drop_privileges ();
//
//        let log = id_wrapper.log.get_mut ();
//        assert_eq! (log, &vec![
//            String::from ("setgid (1000)"),
//            String::from ("setuid (1000)")
//        ])
//    }
}