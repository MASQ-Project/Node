// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use super::bootstrapper::Bootstrapper;
use super::privilege_drop::PrivilegeDropper;
use super::privilege_drop::PrivilegeDropperReal;
use crate::entry_dns::dns_socket_server::DnsSocketServer;
use crate::sub_lib;
use crate::sub_lib::main_tools::Command;
use crate::sub_lib::main_tools::StdStreams;
use crate::sub_lib::socket_server::SocketServer;
use backtrace::Backtrace;
use chrono::{DateTime, Local};
use flexi_logger::LevelFilter;
use flexi_logger::LogSpecification;
use flexi_logger::Logger;
use flexi_logger::{DeferredNow, Duplicate, Record};
use futures::try_ready;
use std::any::Any;
use std::panic::{Location, PanicInfo};
use std::path::PathBuf;
use std::{io, thread};
use tokio::prelude::Async;
use tokio::prelude::Future;

pub struct ServerInitializer<P>
where
    P: PrivilegeDropper,
{
    dns_socket_server: Box<dyn SocketServer<Item = (), Error = ()>>,
    bootstrapper: Box<dyn SocketServer<Item = (), Error = ()>>,
    privilege_dropper: P,
}

impl<P> Command for ServerInitializer<P>
where
    P: PrivilegeDropper,
{
    fn go(&mut self, streams: &mut StdStreams<'_>, args: &Vec<String>) -> u8 {
        if args.contains(&"--help".to_string()) || args.contains(&"--version".to_string()) {
            self.privilege_dropper.drop_privileges();
            self.bootstrapper
                .as_mut()
                .initialize_as_unprivileged(args, streams);
            0
        } else {
            self.dns_socket_server
                .as_mut()
                .initialize_as_privileged(args, streams);
            self.bootstrapper
                .as_mut()
                .initialize_as_privileged(args, streams);

            self.privilege_dropper.drop_privileges();

            self.dns_socket_server
                .as_mut()
                .initialize_as_unprivileged(args, streams);
            self.bootstrapper
                .as_mut()
                .initialize_as_unprivileged(args, streams);
            1
        }
    }
}

impl<P> Future for ServerInitializer<P>
where
    P: PrivilegeDropper,
{
    type Item = ();
    type Error = ();

    fn poll(&mut self) -> Result<Async<<Self as Future>::Item>, <Self as Future>::Error> {
        try_ready!(self
            .dns_socket_server
            .as_mut()
            .join(self.bootstrapper.as_mut())
            .poll());
        Ok(Async::Ready(()))
    }
}

impl ServerInitializer<PrivilegeDropperReal> {
    pub fn new() -> ServerInitializer<PrivilegeDropperReal> {
        ServerInitializer {
            dns_socket_server: Box::new(DnsSocketServer::new()),
            bootstrapper: Box::new(Bootstrapper::new(Box::new(LoggerInitializerWrapperReal {}))),
            privilege_dropper: PrivilegeDropperReal::new(),
        }
    }
}

impl Default for ServerInitializer<PrivilegeDropperReal> {
    fn default() -> Self {
        Self::new()
    }
}

pub trait LoggerInitializerWrapper: Send {
    fn init(&mut self, file_path: PathBuf, log_level: LevelFilter);
}

pub struct LoggerInitializerWrapperReal {}

impl LoggerInitializerWrapper for LoggerInitializerWrapperReal {
    fn init(&mut self, file_path: PathBuf, log_level: LevelFilter) {
        Logger::with(LogSpecification::default(log_level).finalize())
            .log_to_file()
            .directory(&file_path.to_str().expect("Bad temporary filename")[..])
            .print_message()
            .duplicate_to_stderr(Duplicate::Info)
            .suppress_timestamp()
            .format(format_function)
            .start()
            .expect("Logging subsystem failed to start");
        let logfile_name = file_path.join("SubstratumNode.log");
        let privilege_dropper = PrivilegeDropperReal::new();
        privilege_dropper.chown(&logfile_name);
        std::panic::set_hook(Box::new(|panic_info| {
            panic_hook(AltPanicInfo::from(panic_info))
        }));
    }
}

struct AltLocation {
    file: String,
    line: u32,
    col: u32,
}

// Location can't be constructed in a test; therefore this implementation is untestable
impl<'a> From<&'a Location<'a>> for AltLocation {
    fn from(location: &Location) -> Self {
        AltLocation {
            file: location.file().to_string(),
            line: location.line(),
            col: location.column(),
        }
    }
}

struct AltPanicInfo<'a> {
    payload: &'a (dyn Any + Send),
    location: Option<AltLocation>,
}

// PanicInfo can't be constructed in a test; therefore this implementation is untestable
impl<'a> From<&'a PanicInfo<'a>> for AltPanicInfo<'a> {
    fn from(panic_info: &'a PanicInfo) -> Self {
        AltPanicInfo {
            payload: panic_info.payload(),
            location: match panic_info.location() {
                None => None,
                Some(location) => Some(AltLocation::from(location)),
            },
        }
    }
}

fn panic_hook(panic_info: AltPanicInfo) {
    let logger = sub_lib::logger::Logger::new("PanicHandler");
    let location = match panic_info.location {
        None => "<unknown location>".to_string(),
        Some(location) => format!("{}:{}:{}", location.file, location.line, location.col),
    };
    let message = if let Some(s) = panic_info.payload.downcast_ref::<&str>() {
        s.to_string()
    } else if let Some(s) = panic_info.payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "<message indecipherable>".to_string()
    };
    error!(logger, format!("{} - {}", location, message));
    let backtrace = Backtrace::new();
    error!(logger, format!("{:?}", backtrace));
}

// DeferredNow can't be constructed in a test; therefore this function is untestable...
fn format_function(
    write: &mut io::Write,
    now: &mut DeferredNow,
    record: &Record,
) -> Result<(), io::Error> {
    real_format_function(write, now.now(), record)
}

// ...but this one isn't.
pub fn real_format_function(
    write: &mut io::Write,
    timestamp: &DateTime<Local>,
    record: &Record,
) -> Result<(), io::Error> {
    let timestamp = timestamp.naive_local().format("%Y-%m-%dT%H:%M:%S%.3f");
    let thread_id_str = format!("{:?}", thread::current().id());
    let thread_id = &thread_id_str[9..(thread_id_str.len() - 1)];
    let level = record.level();
    let name = record.module_path().unwrap_or("<unnamed>");
    write.write_fmt(format_args!(
        "{} Thd{}: {}: {}: ",
        timestamp, thread_id, level, name
    ))?;
    write.write_fmt(*record.args())
}

#[cfg(test)]
pub mod test_utils {
    use crate::privilege_drop::PrivilegeDropper;
    use crate::server_initializer::LoggerInitializerWrapper;
    use crate::test_utils::logging::init_test_logging;
    use log::LevelFilter;
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};

    pub struct PrivilegeDropperMock {
        pub call_count: Arc<Mutex<usize>>,
    }

    impl PrivilegeDropperMock {
        pub fn new() -> PrivilegeDropperMock {
            PrivilegeDropperMock {
                call_count: Arc::new(Mutex::new(0)),
            }
        }
    }

    impl PrivilegeDropper for PrivilegeDropperMock {
        fn drop_privileges(&self) {
            let mut calls = self.call_count.lock().unwrap();
            *calls += 1;
        }

        fn chown(&self, _file: &PathBuf) {
            unimplemented!()
        }
    }

    pub struct LoggerInitializerWrapperMock {
        init_parameters: Arc<Mutex<Vec<(PathBuf, LevelFilter)>>>,
    }

    impl LoggerInitializerWrapper for LoggerInitializerWrapperMock {
        fn init(&mut self, file_path: PathBuf, log_level: LevelFilter) {
            self.init_parameters
                .lock()
                .unwrap()
                .push((file_path, log_level));
            assert!(init_test_logging());
        }
    }

    impl LoggerInitializerWrapperMock {
        pub fn new() -> LoggerInitializerWrapperMock {
            LoggerInitializerWrapperMock {
                init_parameters: Arc::new(Mutex::new(vec![])),
            }
        }

        pub fn init_parameters(
            mut self,
            parameters: &Arc<Mutex<Vec<(PathBuf, LevelFilter)>>>,
        ) -> Self {
            self.init_parameters = parameters.clone();
            self
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::crash_test_dummy::CrashTestDummy;
    use crate::server_initializer::test_utils::PrivilegeDropperMock;
    use crate::sub_lib::crash_point::CrashPoint;
    use crate::test_utils::logging::{init_test_logging, TestLogHandler};
    use crate::test_utils::ByteArrayWriter;
    use crate::test_utils::{ByteArrayReader, FakeStreamHolder};
    use std::sync::Arc;
    use std::sync::Mutex;

    impl SocketServer for CrashTestDummy {
        fn name(&self) -> String {
            String::from("crash test SocketServer")
        }

        fn initialize_as_privileged(&mut self, _args: &Vec<String>, _streams: &mut StdStreams<'_>) {
        }

        fn initialize_as_unprivileged(
            &mut self,
            _args: &Vec<String>,
            _streams: &mut StdStreams<'_>,
        ) {
        }
    }

    struct SocketServerMock {
        initialize_as_privileged_params: Arc<Mutex<Vec<Vec<String>>>>,
        initialize_as_unprivileged_params: Arc<Mutex<Vec<Vec<String>>>>,
    }

    impl Future for SocketServerMock {
        type Item = ();
        type Error = ();

        fn poll(&mut self) -> Result<Async<Self::Item>, Self::Error> {
            unimplemented!()
        }
    }

    impl SocketServer for SocketServerMock {
        fn name(&self) -> String {
            return "mock".to_string();
        }

        fn initialize_as_privileged(&mut self, args: &Vec<String>, _streams: &mut StdStreams) {
            self.initialize_as_privileged_params
                .lock()
                .unwrap()
                .push(args.clone());
        }

        fn initialize_as_unprivileged(&mut self, args: &Vec<String>, _streams: &mut StdStreams) {
            self.initialize_as_unprivileged_params
                .lock()
                .unwrap()
                .push(args.clone());
        }
    }

    impl SocketServerMock {
        pub fn new() -> SocketServerMock {
            SocketServerMock {
                initialize_as_privileged_params: Arc::new(Mutex::new(vec![])),
                initialize_as_unprivileged_params: Arc::new(Mutex::new(vec![])),
            }
        }

        pub fn initialize_as_privileged_params(
            mut self,
            params: &Arc<Mutex<Vec<Vec<String>>>>,
        ) -> Self {
            self.initialize_as_privileged_params = params.clone();
            self
        }

        pub fn initialize_as_unprivileged_params(
            mut self,
            params: &Arc<Mutex<Vec<Vec<String>>>>,
        ) -> Self {
            self.initialize_as_unprivileged_params = params.clone();
            self
        }
    }

    #[test]
    fn panic_hook_handles_missing_location_and_unprintable_payload() {
        init_test_logging();
        let panic_info = AltPanicInfo {
            payload: &SocketServerMock::new(), // not a String or a &str
            location: None,
        };

        panic_hook(panic_info);

        let tlh = TestLogHandler::new();
        tlh.exists_log_containing(
            "ERROR: PanicHandler: <unknown location> - <message indecipherable>",
        );
        tlh.exists_log_containing("panic_hook_handles_missing_location_and_unprintable_payload");
    }

    #[test]
    fn panic_hook_handles_existing_location_and_string_payload() {
        init_test_logging();
        let panic_info = AltPanicInfo {
            payload: &"I am a full-fledged String".to_string(),
            location: Some(AltLocation {
                file: "file.txt".to_string(),
                line: 24,
                col: 42,
            }),
        };

        panic_hook(panic_info);

        let tlh = TestLogHandler::new();
        tlh.exists_log_containing(
            "ERROR: PanicHandler: file.txt:24:42 - I am a full-fledged String",
        );
        tlh.exists_log_containing("panic_hook_handles_existing_location_and_string_payload");
    }

    #[test]
    fn panic_hook_handles_existing_location_and_string_slice_payload() {
        init_test_logging();
        let panic_info = AltPanicInfo {
            payload: &"I'm just a string slice",
            location: Some(AltLocation {
                file: "file.txt".to_string(),
                line: 24,
                col: 42,
            }),
        };

        panic_hook(panic_info);

        let tlh = TestLogHandler::new();
        tlh.exists_log_containing("ERROR: PanicHandler: file.txt:24:42 - I'm just a string slice");
    }

    #[test]
    fn exits_after_all_socket_servers_exit() {
        let dns_socket_server = CrashTestDummy::new(CrashPoint::Error);
        let bootstrapper = CrashTestDummy::new(CrashPoint::Error);

        let privilege_dropper = PrivilegeDropperMock::new();

        let mut subject = ServerInitializer {
            dns_socket_server: Box::new(dns_socket_server),
            bootstrapper: Box::new(bootstrapper),
            privilege_dropper,
        };

        let stdin = &mut ByteArrayReader::new(&[0; 0]);
        let stdout = &mut ByteArrayWriter::new();
        let stderr = &mut ByteArrayWriter::new();
        let streams = &mut StdStreams {
            stdin,
            stdout,
            stderr,
        };

        subject.go(streams, &vec![]);
        let res = subject.wait();

        assert!(res.is_err());
    }

    #[test]
    fn server_initializer_as_a_future() {
        let dns_socket_server = CrashTestDummy::new(CrashPoint::None);
        let bootstrapper = CrashTestDummy::new(CrashPoint::None);
        let privilege_dropper = PrivilegeDropperMock::new();

        let mut subject = ServerInitializer {
            dns_socket_server: Box::new(dns_socket_server),
            bootstrapper: Box::new(bootstrapper),
            privilege_dropper,
        };

        let result = subject.poll();
        assert_eq!(result, Ok(Async::Ready(())))
    }

    #[test]
    #[should_panic(expected = "EntryDnsServerMock was instructed to panic")]
    fn server_initializer_dns_socket_server_panics() {
        let bootstrapper = CrashTestDummy::new(CrashPoint::None);
        let privilege_dropper = PrivilegeDropperMock::new();

        let mut subject = ServerInitializer {
            dns_socket_server: Box::new(CrashTestDummy::panic(
                "EntryDnsServerMock was instructed to panic".to_string(),
            )),
            bootstrapper: Box::new(bootstrapper),
            privilege_dropper,
        };

        let _ = subject.poll();
    }

    #[test]
    #[should_panic(expected = "BootstrapperMock was instructed to panic")]
    fn server_initializer_bootstrapper_panics() {
        let dns_socket_server = CrashTestDummy::new(CrashPoint::None);
        let privilege_dropper = PrivilegeDropperMock::new();
        let mut subject = ServerInitializer {
            dns_socket_server: Box::new(dns_socket_server),
            bootstrapper: Box::new(CrashTestDummy::panic(
                "BootstrapperMock was instructed to panic".to_string(),
            )),
            privilege_dropper,
        };

        let _ = subject.poll();
    }

    #[test]
    fn go_should_drop_privileges() {
        let bootstrapper = CrashTestDummy::new(CrashPoint::None);
        let privilege_dropper = PrivilegeDropperMock::new();

        let call_count = Arc::clone(&privilege_dropper.call_count);

        let stdin = &mut ByteArrayReader::new(&[0; 0]);
        let stdout = &mut ByteArrayWriter::new();
        let stderr = &mut ByteArrayWriter::new();
        let streams = &mut StdStreams {
            stdin,
            stdout,
            stderr,
        };
        let mut subject = ServerInitializer {
            dns_socket_server: Box::new(CrashTestDummy::new(CrashPoint::None)),
            bootstrapper: Box::new(bootstrapper),
            privilege_dropper,
        };

        subject.go(streams, &vec![]);

        assert_eq!(*call_count.lock().unwrap(), 1);
    }

    #[test]
    fn go_with_help_should_drop_privileges_and_call_initialize_as_unprivileged() {
        go_with_something_should_drop_privileges_and_call_initialize_as_unprivileged("--help");
    }

    #[test]
    fn go_with_version_should_drop_privileges_and_call_initialize_as_unprivileged() {
        go_with_something_should_drop_privileges_and_call_initialize_as_unprivileged("--version");
    }

    fn go_with_something_should_drop_privileges_and_call_initialize_as_unprivileged(
        something: &str,
    ) {
        let dns_initialize_as_privileged_params_arc = Arc::new(Mutex::new(vec![]));
        let dns_initialize_as_unprivileged_params_arc = Arc::new(Mutex::new(vec![]));
        let dns_socket_server = SocketServerMock::new()
            .initialize_as_privileged_params(&dns_initialize_as_privileged_params_arc)
            .initialize_as_unprivileged_params(&dns_initialize_as_unprivileged_params_arc);
        let boot_initialize_as_privileged_params_arc = Arc::new(Mutex::new(vec![]));
        let boot_initialize_as_unprivileged_params_arc = Arc::new(Mutex::new(vec![]));
        let bootstrapper = SocketServerMock::new()
            .initialize_as_privileged_params(&boot_initialize_as_privileged_params_arc)
            .initialize_as_unprivileged_params(&boot_initialize_as_unprivileged_params_arc);
        let privilege_dropper = PrivilegeDropperMock::new();
        let call_count_arc = Arc::clone(&privilege_dropper.call_count);
        let mut subject = ServerInitializer {
            dns_socket_server: Box::new(dns_socket_server),
            bootstrapper: Box::new(bootstrapper),
            privilege_dropper,
        };
        let args = vec!["SubstratumNode".to_string(), something.to_string()];

        subject.go(&mut FakeStreamHolder::new().streams(), &args);

        let call_count = call_count_arc.lock().unwrap();
        assert_eq!(*call_count, 1);
        let empty_string_vec: Vec<Vec<String>> = vec![];
        let dns_initialize_as_privileged_params =
            dns_initialize_as_privileged_params_arc.lock().unwrap();
        assert_eq!(
            *dns_initialize_as_privileged_params,
            empty_string_vec.clone()
        );
        let dns_initialize_as_unprivileged_params =
            dns_initialize_as_unprivileged_params_arc.lock().unwrap();
        assert_eq!(
            *dns_initialize_as_unprivileged_params,
            empty_string_vec.clone()
        );
        let boot_initialize_as_privileged_params =
            boot_initialize_as_privileged_params_arc.lock().unwrap();
        assert_eq!(*boot_initialize_as_privileged_params, empty_string_vec);
        let boot_initialize_as_unprivileged_params =
            boot_initialize_as_unprivileged_params_arc.lock().unwrap();
        assert_eq!(*boot_initialize_as_unprivileged_params, vec![args]);
    }
}
