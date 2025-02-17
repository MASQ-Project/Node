// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
use crate::dns_modifier::DnsModifier;
use crate::dns_modifier_factory::DnsModifierFactory;
use crate::dns_modifier_factory::DnsModifierFactoryReal;
use masq_lib::command::{Command, StdStreams};
use masq_lib::short_writeln;
use std::io::Write;

enum Action {
    Subvert,
    Revert,
    Inspect,
    Status,
}

pub struct DnsUtility {
    factory: Box<dyn DnsModifierFactory>,
}

impl Default for DnsUtility {
    fn default() -> Self {
        DnsUtility {
            factory: Box::new(DnsModifierFactoryReal::new()),
        }
    }
}

impl Command<u8> for DnsUtility {
    fn go(&mut self, streams: &mut StdStreams<'_>, args: &[String]) -> u8 {
        let action = match args {
            a if a.len() < 2 => return DnsUtility::usage(streams),
            a if a[1] == "subvert" => Action::Subvert,
            a if a[1] == "revert" => Action::Revert,
            a if a[1] == "inspect" => Action::Inspect,
            a if a[1] == "status" => Action::Status,
            _ => return DnsUtility::usage(streams),
        };
        self.perform_action(action, streams)
    }
}

impl DnsUtility {
    pub fn new() -> Self {
        Default::default()
    }

    fn perform_action(&self, action: Action, streams: &mut StdStreams<'_>) -> u8 {
        let modifier = match self.factory.make() {
            None => {
                writeln!(
                    streams.stderr,
                    "Don't know how to modify DNS settings on this system"
                ).expect("writeln failed");
                return 1;
            }
            Some(m) => m,
        };
        let (result, name) = match action {
            Action::Subvert => (modifier.subvert(), "subvert DNS"),
            Action::Revert => (modifier.revert(), "revert DNS"),
            Action::Inspect => (modifier.inspect(streams.stdout), "inspect DNS"),
            Action::Status => (
                self.retrieve_status(modifier, streams.stdout),
                "display DNS status",
            ),
        };
        match result {
            Ok(_) => 0,
            Err(msg) => {
                writeln!(streams.stderr, "Cannot {}: {}", name, msg)
                    .expect("writeln failed");
                1
            }
        }
    }

    fn retrieve_status(
        &self,
        modifier: Box<dyn DnsModifier>,
        stdout: &mut (dyn Write + Send),
    ) -> Result<(), String> {
        let mut stream_buf: Vec<u8> = vec![];
        modifier.inspect(&mut stream_buf)?;
        let status = match String::from_utf8(stream_buf) {
            Ok(s) => self.status_from_inspect(s),
            Err(e) => panic!(
                "Internal error: UTF-8 String suddenly became non-UTF-8: {}",
                e
            ),
        };
        writeln!(stdout, "{}", status)
            .expect("writeln failed");
        Ok(())
    }

    fn status_from_inspect(&self, dns_server_list: String) -> String {
        match dns_server_list {
            ref s if s == &String::from("127.0.0.1\n") => String::from("subverted"),
            _ => String::from("reverted"),
        }
    }

    fn usage(streams: &mut StdStreams<'_>) -> u8 {
        writeln!(
            streams.stderr,
            "Usage: dns_utility [ subvert | revert | inspect | status ]"
        ).expect("writeln failed");
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns_modifier::DnsModifier;
    use masq_lib::test_utils::fake_stream_holder::FakeStreamHolder;
    use std::cell::RefCell;
    use std::io;

    pub struct DnsModifierMock {
        subvert_results: RefCell<Vec<Result<(), String>>>,
        revert_results: RefCell<Vec<Result<(), String>>>,
        inspect_to_stdout: RefCell<Vec<String>>,
        inspect_results: RefCell<Vec<Result<(), String>>>,
    }

    impl DnsModifier for DnsModifierMock {
        fn type_name(&self) -> &'static str {
            "DnsModifierMock"
        }

        fn subvert(&self) -> Result<(), String> {
            self.subvert_results.borrow_mut().remove(0)
        }

        fn revert(&self) -> Result<(), String> {
            self.revert_results.borrow_mut().remove(0)
        }

        fn inspect(&self, stdout: &mut (dyn io::Write + Send)) -> Result<(), String> {
            write!(stdout, "{}", self.inspect_to_stdout.borrow_mut().remove(0)).unwrap();
            self.inspect_results.borrow_mut().remove(0)
        }
    }

    impl DnsModifierMock {
        pub fn new() -> DnsModifierMock {
            DnsModifierMock {
                subvert_results: RefCell::new(vec![]),
                revert_results: RefCell::new(vec![]),
                inspect_to_stdout: RefCell::new(vec![]),
                inspect_results: RefCell::new(vec![]),
            }
        }

        pub fn subvert_result(self, result: Result<(), String>) -> DnsModifierMock {
            self.subvert_results.borrow_mut().push(result);
            self
        }

        pub fn revert_result(self, result: Result<(), String>) -> DnsModifierMock {
            self.revert_results.borrow_mut().push(result);
            self
        }

        pub fn inspect_result(
            self,
            to_stdout: String,
            result: Result<(), String>,
        ) -> DnsModifierMock {
            self.inspect_to_stdout.borrow_mut().push(to_stdout);
            self.inspect_results.borrow_mut().push(result);
            self
        }
    }

    #[derive(Default)]
    pub struct DnsModifierFactoryMock {
        make_results: RefCell<Vec<Option<Box<dyn DnsModifier>>>>,
    }

    impl DnsModifierFactory for DnsModifierFactoryMock {
        fn make(&self) -> Option<Box<dyn DnsModifier>> {
            self.make_results.borrow_mut().remove(0)
        }
    }

    impl DnsModifierFactoryMock {
        pub fn new() -> DnsModifierFactoryMock {
            DnsModifierFactoryMock {
                make_results: RefCell::new(vec![]),
            }
        }

        pub fn make_result(self, result: Option<Box<dyn DnsModifier>>) -> DnsModifierFactoryMock {
            self.make_results.borrow_mut().push(result);
            self
        }
    }

    #[test]
    fn go_with_no_parameters_prints_usage_to_stderr_and_exits_with_error() {
        let mut holder = FakeStreamHolder::new();
        let mut subject = DnsUtility::new();

        let result = subject.go(&mut holder.streams(), &[String::new()]);

        assert_eq!(result, 1);
        assert_eq!(
            holder.stderr.get_string(),
            String::from("Usage: dns_utility [ subvert | revert | inspect | status ]\n")
        );
    }

    #[test]
    fn go_with_unknown_parameter_prints_usage_to_stderr_and_exits_with_error() {
        let mut holder = FakeStreamHolder::new();
        let mut subject = DnsUtility::new();

        let result = subject.go(
            &mut holder.streams(),
            &[String::new(), String::from("blooga")],
        );

        assert_eq!(result, 1);
        assert_eq!(
            holder.stderr.get_string(),
            String::from("Usage: dns_utility [ subvert | revert | inspect | status ]\n")
        );
    }

    #[test]
    fn go_with_unrecognized_environment_handles_failure() {
        let mut holder = FakeStreamHolder::new();
        let factory = DnsModifierFactoryMock::new().make_result(None);
        let mut subject = DnsUtility::new();
        subject.factory = Box::new(factory);

        let result = subject.go(
            &mut holder.streams(),
            &[String::new(), String::from("subvert")],
        );

        assert_eq!(result, 1);
        assert_eq!(
            holder.stderr.get_string(),
            String::from("Don't know how to modify DNS settings on this system\n")
        );
    }

    #[test]
    fn go_with_subvert_parameter_makes_dns_modifier_calls_subvert_and_handles_failure() {
        let mut holder = FakeStreamHolder::new();
        let dns_modifier =
            DnsModifierMock::new().subvert_result(Err(String::from("blooga blooga")));
        let factory = DnsModifierFactoryMock::new().make_result(Some(Box::new(dns_modifier)));
        let mut subject = DnsUtility::new();
        subject.factory = Box::new(factory);

        let result = subject.go(
            &mut holder.streams(),
            &[String::new(), String::from("subvert")],
        );

        assert_eq!(result, 1);
        assert_eq!(
            holder.stderr.get_string(),
            String::from("Cannot subvert DNS: blooga blooga\n")
        );
    }

    #[test]
    fn go_with_subvert_parameter_makes_dns_modifier_calls_subvert_and_handles_success() {
        let mut holder = FakeStreamHolder::new();
        let dns_modifier = DnsModifierMock::new().subvert_result(Ok(()));
        let factory = DnsModifierFactoryMock::new().make_result(Some(Box::new(dns_modifier)));
        let mut subject = DnsUtility::new();
        subject.factory = Box::new(factory);

        let result = subject.go(
            &mut holder.streams(),
            &[String::new(), String::from("subvert")],
        );

        assert_eq!(result, 0);
        assert_eq!(holder.stderr.get_string(), String::new());
    }

    #[test]
    fn go_with_revert_parameter_makes_dns_modifier_calls_revert_and_handles_failure() {
        let mut holder = FakeStreamHolder::new();
        let dns_modifier = DnsModifierMock::new().revert_result(Err(String::from("blooga blooga")));
        let factory = DnsModifierFactoryMock::new().make_result(Some(Box::new(dns_modifier)));
        let mut subject = DnsUtility::new();
        subject.factory = Box::new(factory);

        let result = subject.go(
            &mut holder.streams(),
            &[String::new(), String::from("revert")],
        );

        assert_eq!(result, 1);
        assert_eq!(
            holder.stderr.get_string(),
            String::from("Cannot revert DNS: blooga blooga\n")
        );
    }

    #[test]
    fn go_with_revert_parameter_makes_dns_modifier_calls_revert_and_handles_success() {
        let mut holder = FakeStreamHolder::new();
        let dns_modifier = DnsModifierMock::new().revert_result(Ok(()));
        let factory = DnsModifierFactoryMock::new().make_result(Some(Box::new(dns_modifier)));
        let mut subject = DnsUtility::new();
        subject.factory = Box::new(factory);

        let result = subject.go(
            &mut holder.streams(),
            &[String::new(), String::from("revert")],
        );

        assert_eq!(result, 0);
        assert_eq!(holder.stderr.get_string(), String::new());
    }

    #[test]
    fn go_with_inspect_parameter_makes_dns_modifier_calls_inspect_and_handles_failure() {
        let mut holder = FakeStreamHolder::new();
        let dns_modifier = DnsModifierMock::new()
            .inspect_result(String::new(), Err(String::from("blooga blooga")));
        let factory = DnsModifierFactoryMock::new().make_result(Some(Box::new(dns_modifier)));
        let mut subject = DnsUtility::new();
        subject.factory = Box::new(factory);

        let result = subject.go(
            &mut holder.streams(),
            &[String::new(), String::from("inspect")],
        );

        assert_eq!(result, 1);
        assert_eq!(
            holder.stderr.get_string(),
            String::from("Cannot inspect DNS: blooga blooga\n")
        );
    }

    #[test]
    fn go_with_inspect_parameter_makes_dns_modifier_calls_inspect_and_handles_success() {
        let mut holder = FakeStreamHolder::new();
        let dns_modifier = DnsModifierMock::new().inspect_result("Booga!".to_string(), Ok(()));
        let factory = DnsModifierFactoryMock::new().make_result(Some(Box::new(dns_modifier)));
        let mut subject = DnsUtility::new();
        subject.factory = Box::new(factory);

        let result = subject.go(
            &mut holder.streams(),
            &[String::new(), String::from("inspect")],
        );

        assert_eq!(result, 0);
        assert_eq!(holder.stderr.get_string(), String::new());
        assert_eq!(holder.stdout.get_string(), String::from("Booga!"));
    }

    #[test]
    fn go_with_status_parameter_makes_dns_modifier_calls_inspect_and_handles_failure() {
        let mut holder = FakeStreamHolder::new();
        let dns_modifier = DnsModifierMock::new()
            .inspect_result(String::new(), Err(String::from("blooga blooga")));
        let factory = DnsModifierFactoryMock::new().make_result(Some(Box::new(dns_modifier)));
        let mut subject = DnsUtility::new();
        subject.factory = Box::new(factory);

        let result = subject.go(
            &mut holder.streams(),
            &[String::new(), String::from("status")],
        );

        assert_eq!(result, 1);
        assert_eq!(
            holder.stderr.get_string(),
            String::from("Cannot display DNS status: blooga blooga\n")
        );
    }

    #[test]
    fn go_with_status_parameter_makes_dns_modifier_calls_inspect_and_handles_empty_response() {
        let mut holder = FakeStreamHolder::new();
        let dns_modifier = DnsModifierMock::new().inspect_result(String::new(), Ok(()));
        let factory = DnsModifierFactoryMock::new().make_result(Some(Box::new(dns_modifier)));
        let mut subject = DnsUtility::new();
        subject.factory = Box::new(factory);

        let result = subject.go(
            &mut holder.streams(),
            &[String::new(), String::from("status")],
        );

        assert_eq!(result, 0);
        assert_eq!(holder.stderr.get_string(), String::new());
        assert_eq!(holder.stdout.get_string(), String::from("reverted\n"));
    }

    #[test]
    fn go_with_status_parameter_makes_dns_modifier_calls_inspect_and_handles_subverted_dns() {
        let mut holder = FakeStreamHolder::new();
        let dns_modifier = DnsModifierMock::new().inspect_result("127.0.0.1\n".to_string(), Ok(()));
        let factory = DnsModifierFactoryMock::new().make_result(Some(Box::new(dns_modifier)));
        let mut subject = DnsUtility::new();
        subject.factory = Box::new(factory);

        let result = subject.go(
            &mut holder.streams(),
            &[String::new(), String::from("status")],
        );

        assert_eq!(result, 0);
        assert_eq!(holder.stderr.get_string(), String::new());
        assert_eq!(holder.stdout.get_string(), String::from("subverted\n"));
    }

    #[test]
    fn go_with_status_parameter_makes_dns_modifier_calls_inspect_and_handles_unsubverted_dns() {
        let mut holder = FakeStreamHolder::new();
        let dns_modifier =
            DnsModifierMock::new().inspect_result("192.168.0.1\n192.168.0.2\n".to_string(), Ok(()));
        let factory = DnsModifierFactoryMock::new().make_result(Some(Box::new(dns_modifier)));
        let mut subject = DnsUtility::new();
        subject.factory = Box::new(factory);

        let result = subject.go(
            &mut holder.streams(),
            &[String::new(), String::from("status")],
        );

        assert_eq!(result, 0);
        assert_eq!(holder.stderr.get_string(), String::new());
        assert_eq!(holder.stdout.get_string(), String::from("reverted\n"));
    }
}
