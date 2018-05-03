// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use sub_lib::main_tools::Command;
use sub_lib::main_tools::StdStreams;
use dns_modifier_factory::DnsModifierFactory;
use dns_modifier_factory::DnsModifierFactoryReal;
use dns_modifier::DnsModifier;

pub struct DnsUtility {
    factory: Box<DnsModifierFactory>
}

enum Action {
    Subvert,
    Revert
}

impl Command for DnsUtility {
    fn go<'a>(&mut self, streams: &mut StdStreams, args: &Vec<String>) -> u8 {
        let action = match args {
            a if a.len () < 2 => return DnsUtility::usage (streams),
            a if a[1] == String::from ("subvert") => Action::Subvert,
            a if a[1] == String::from ("revert") => Action::Revert,
            _ => return DnsUtility::usage (streams),
        };
        self.perform_action (action, streams)
    }
}

impl DnsUtility {
    pub fn new () -> DnsUtility {
        DnsUtility {
            factory: Box::new (DnsModifierFactoryReal::new ())
        }
    }

    fn perform_action (&self, action: Action, streams: &mut StdStreams) -> u8 {
        let modifier = match self.factory.make () {
            None => {
                writeln! (streams.stderr, "Don't know how to modify DNS settings on this system").expect ("Could not writeln");
                return 1
            },
            Some (m) => m
        };
        let (result, name) = match action {
            Action::Subvert => (modifier.subvert (), "subvert"),
            Action::Revert => (modifier.revert (), "revert")
        };
        match result {
            Ok (_) => 0,
            Err (msg) => {
                writeln! (streams.stderr, "Cannot {} DNS: {}", name, msg).expect ("Could not writeln");
                1
            }
        }
    }

    fn usage (streams: &mut StdStreams) -> u8 {
        writeln!(streams.stderr, "Usage: dns_utility [ subvert | revert ]").expect("Internal error");
        1
    }
}

#[cfg (test)]
mod tests {
    use super::*;
    use test_utils::test_utils::FakeStreamHolder;
    use std::cell::RefCell;

    pub struct DnsModifierMock {
        subvert_results: RefCell<Vec<Result<(), String>>>,
        revert_results: RefCell<Vec<Result<(), String>>>
    }

    impl DnsModifier for DnsModifierMock {
        fn type_name (&self) -> &'static str {
            "DnsModifierMock"
        }

        fn subvert(&self) -> Result<(), String> {
            self.subvert_results.borrow_mut ().remove (0)
        }

        fn revert(&self) -> Result<(), String> {
            self.revert_results.borrow_mut ().remove (0)
        }
    }

    impl DnsModifierMock {
        pub fn new () -> DnsModifierMock {
            DnsModifierMock {
                subvert_results: RefCell::new (vec! ()),
                revert_results: RefCell::new (vec! ())
            }
        }

        pub fn subvert_result (self, result: Result<(), String>) -> DnsModifierMock {
            self.subvert_results.borrow_mut ().push (result);
            self
        }

        pub fn revert_result (self, result: Result<(), String>) -> DnsModifierMock {
            self.revert_results.borrow_mut ().push (result);
            self
        }
    }

    pub struct DnsModifierFactoryMock {
        make_results: RefCell<Vec<Option<Box<DnsModifier>>>>
    }

    impl DnsModifierFactory for DnsModifierFactoryMock {
        fn make(&self) -> Option<Box<DnsModifier>> {
            self.make_results.borrow_mut ().remove (0)
        }
    }

    impl DnsModifierFactoryMock {
        pub fn new () -> DnsModifierFactoryMock {
            DnsModifierFactoryMock {
                make_results: RefCell::new (vec! ())
            }
        }

        pub fn make_result (self, result: Option<Box<DnsModifier>>) -> DnsModifierFactoryMock {
            self.make_results.borrow_mut ().push (result);
            self
        }
    }

    #[test]
    fn go_with_no_parameters_prints_usage_to_stderr_and_exits_with_error () {
        let mut holder = FakeStreamHolder::new ();
        let mut subject = DnsUtility::new ();

        let result = subject.go (&mut holder.streams (), &vec! (String::new ()));

        assert_eq! (result, 1);
        assert_eq! (holder.stderr.get_string (), String::from (
            "Usage: dns_utility [ subvert | revert ]\n"
        ));
    }

    #[test]
    fn go_with_unknown_parameter_prints_usage_to_stderr_and_exits_with_error () {
        let mut holder = FakeStreamHolder::new ();
        let mut subject = DnsUtility::new ();

        let result = subject.go (&mut holder.streams (), &vec! (String::new (), String::from("blooga")));

        assert_eq! (result, 1);
        assert_eq! (holder.stderr.get_string (), String::from (
            "Usage: dns_utility [ subvert | revert ]\n"
        ));
    }

    #[test]
    fn go_with_unrecognized_environment_handles_failure () {
        let mut holder = FakeStreamHolder::new ();
        let factory = DnsModifierFactoryMock::new()
            .make_result (None);
        let mut subject = DnsUtility::new ();
        subject.factory = Box::new (factory);

        let result = subject.go (&mut holder.streams (), &vec! (String::new (), String::from ("subvert")));

        assert_eq! (result, 1);
        assert_eq! (holder.stderr.get_string (), String::from (
            "Don't know how to modify DNS settings on this system\n"
        ));
    }

    #[test]
    fn go_with_subvert_parameter_makes_dns_modifier_calls_subvert_and_handles_failure () {
        let mut holder = FakeStreamHolder::new ();
        let dns_modifier = DnsModifierMock::new ()
            .subvert_result (Err (String::from ("blooga blooga")));
        let factory = DnsModifierFactoryMock::new()
            .make_result (Some (Box::new (dns_modifier)));
        let mut subject = DnsUtility::new ();
        subject.factory = Box::new (factory);

        let result = subject.go (&mut holder.streams (), &vec! (String::new (), String::from ("subvert")));

        assert_eq! (result, 1);
        assert_eq! (holder.stderr.get_string (), String::from (
            "Cannot subvert DNS: blooga blooga\n"
        ));
    }

    #[test]
    fn go_with_subvert_parameter_makes_dns_modifier_calls_subvert_and_handles_success () {
        let mut holder = FakeStreamHolder::new ();
        let dns_modifier = DnsModifierMock::new ()
            .subvert_result (Ok (()));
        let factory = DnsModifierFactoryMock::new()
            .make_result (Some (Box::new (dns_modifier)));
        let mut subject = DnsUtility::new ();
        subject.factory = Box::new (factory);

        let result = subject.go (&mut holder.streams (), &vec! (String::new (), String::from ("subvert")));

        assert_eq! (result, 0);
        assert_eq! (holder.stderr.get_string (), String::new ());
    }

    #[test]
    fn go_with_revert_parameter_makes_dns_modifier_calls_revert_and_handles_failure () {
        let mut holder = FakeStreamHolder::new ();
        let dns_modifier = DnsModifierMock::new ()
            .revert_result (Err (String::from ("blooga blooga")));
        let factory = DnsModifierFactoryMock::new()
            .make_result (Some (Box::new (dns_modifier)));
        let mut subject = DnsUtility::new ();
        subject.factory = Box::new (factory);

        let result = subject.go (&mut holder.streams (), &vec! (String::new (), String::from ("revert")));

        assert_eq! (result, 1);
        assert_eq! (holder.stderr.get_string (), String::from (
            "Cannot revert DNS: blooga blooga\n"
        ));
    }

    #[test]
    fn go_with_revert_parameter_makes_dns_modifier_calls_revert_and_handles_success () {
        let mut holder = FakeStreamHolder::new ();
        let dns_modifier = DnsModifierMock::new ()
            .revert_result (Ok (()));
        let factory = DnsModifierFactoryMock::new()
            .make_result (Some (Box::new (dns_modifier)));
        let mut subject = DnsUtility::new ();
        subject.factory = Box::new (factory);

        let result = subject.go (&mut holder.streams (), &vec! (String::new (), String::from ("revert")));

        assert_eq! (result, 0);
        assert_eq! (holder.stderr.get_string (), String::new ());
    }
}
