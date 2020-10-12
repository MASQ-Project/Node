// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use super::bootstrapper::Bootstrapper;
use super::privilege_drop::PrivilegeDropper;
use super::privilege_drop::PrivilegeDropperReal;
use crate::bootstrapper::{BootstrapperConfig, RealUser};
use crate::entry_dns::dns_socket_server::DnsSocketServer;
use crate::node_configurator::node_configurator_standard::NodeConfiguratorStandardPrivileged;
use crate::node_configurator::NodeConfigurator;
use crate::node_configurator::RealDirsWrapper;
use crate::sub_lib;
use crate::sub_lib::socket_server::SocketServer;
use backtrace::Backtrace;
use chrono::{DateTime, Local};
use flexi_logger::LogSpecBuilder;
use flexi_logger::Logger;
use flexi_logger::{Cleanup, Criterion, LevelFilter, Naming};
use flexi_logger::{DeferredNow, Duplicate, Record};
use futures::try_ready;
use lazy_static::lazy_static;
use masq_lib::command::Command;
use masq_lib::command::StdStreams;
use masq_lib::shared_schema::ConfiguratorError;
use std::any::Any;
use std::fmt::Debug;
use std::panic::{Location, PanicInfo};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};
use std::{io, thread};
use tokio::prelude::Async;
use tokio::prelude::Future;

pub struct ServerInitializer {
    dns_socket_server: Box<dyn SocketServer<(), Item = (), Error = ()>>,
    bootstrapper: Box<dyn SocketServer<BootstrapperConfig, Item = (), Error = ()>>,
    privilege_dropper: Box<dyn PrivilegeDropper>,
}

impl Command for ServerInitializer {
    fn go(&mut self, streams: &mut StdStreams<'_>, args: &[String]) -> u8 {
        let mut result: Result<(), ConfiguratorError> = Ok(());
        let exit_code =
            if args.contains(&"--help".to_string()) || args.contains(&"--version".to_string()) {
                self.privilege_dropper
                    .drop_privileges(&RealUser::null().populate(&RealDirsWrapper {}));
                result = Self::combine_results(
                    result,
                    NodeConfiguratorStandardPrivileged::new().configure(&args.to_vec(), streams),
                );
                0
            } else {
                result = Self::combine_results(
                    result,
                    self.dns_socket_server
                        .as_mut()
                        .initialize_as_privileged(args, streams),
                );
                result = Self::combine_results(
                    result,
                    self.bootstrapper
                        .as_mut()
                        .initialize_as_privileged(args, streams),
                );

                let config = self.bootstrapper.get_configuration();
                let real_user = config.real_user.populate(&RealDirsWrapper {});
                self.privilege_dropper
                    .chown(&config.data_directory, &real_user);
                self.privilege_dropper.drop_privileges(&real_user);

                result = Self::combine_results(
                    result,
                    self.dns_socket_server
                        .as_mut()
                        .initialize_as_unprivileged(args, streams),
                );
                result = Self::combine_results(
                    result,
                    self.bootstrapper
                        .as_mut()
                        .initialize_as_unprivileged(args, streams),
                );
                1
            };
        if let Some(err) = result.err() {
            err.param_errors.into_iter().for_each(|param_error| {
                writeln!(
                    streams.stderr,
                    "Problem with parameter {}: {}",
                    param_error.parameter, param_error.reason
                )
                .expect("writeln! failed")
            });
            1
        } else {
            exit_code
        }
    }
}

impl Future for ServerInitializer {
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

impl ServerInitializer {
    pub fn new() -> ServerInitializer {
        ServerInitializer {
            dns_socket_server: Box::new(DnsSocketServer::new()),
            bootstrapper: Box::new(Bootstrapper::new(Box::new(LoggerInitializerWrapperReal {}))),
            privilege_dropper: Box::new(PrivilegeDropperReal::new()),
        }
    }

    fn combine_results<A: Debug, B: Debug>(
        initial: Result<A, ConfiguratorError>,
        additional: Result<B, ConfiguratorError>,
    ) -> Result<(), ConfiguratorError> {
        match (initial, additional) {
            (Ok(_), Ok(_)) => Ok(()),
            (Ok(_), Err(e)) => Err(e),
            (Err(e), Ok(_)) => Err(e),
            (Err(e1), Err(e2)) => Err(ConfiguratorError::new(
                e1.param_errors
                    .into_iter()
                    .chain(e2.param_errors.into_iter())
                    .collect(),
            )),
        }
    }
}

impl Default for ServerInitializer {
    fn default() -> Self {
        Self::new()
    }
}

lazy_static! {
    pub static ref LOGFILE_NAME: Mutex<PathBuf> = Mutex::new(PathBuf::from("uninitialized"));
}

pub trait LoggerInitializerWrapper: Send {
    fn init(
        &mut self,
        file_path: PathBuf,
        real_user: &RealUser,
        log_level: LevelFilter,
        discriminant_opt: Option<&str>,
    );
}

pub struct LoggerInitializerWrapperReal {}

impl LoggerInitializerWrapper for LoggerInitializerWrapperReal {
    fn init(
        &mut self,
        file_path: PathBuf,
        real_user: &RealUser,
        log_level: LevelFilter,
        discriminant_opt: Option<&str>,
    ) {
        let mut logger = Logger::with(
            LogSpecBuilder::new()
                .default(log_level)
                .module("tokio", LevelFilter::Off)
                .module("mio", LevelFilter::Off)
                .build(),
        )
        .log_to_file()
        .directory(file_path.clone())
        .print_message()
        .duplicate_to_stderr(Duplicate::Info)
        .suppress_timestamp()
        .format(format_function)
        .rotate(
            Criterion::Size(100_000_000),
            Naming::Numbers,
            Cleanup::KeepZipFiles(50),
        );
        if let Some(discriminant) = discriminant_opt {
            logger = logger.discriminant(discriminant);
        }
        logger.start().expect("Logging subsystem failed to start");
        let privilege_dropper = PrivilegeDropperReal::new();
        let logfile_name = file_path.join(format!(
            "MASQNode_{}rCURRENT.log",
            match discriminant_opt {
                Some(discriminant) => format!("{}_", discriminant),
                None => "".to_string(),
            }
        ));
        privilege_dropper.chown(&logfile_name, real_user);
        *(Self::logfile_name_guard()) = logfile_name;
        std::panic::set_hook(Box::new(|panic_info| {
            panic_hook(AltPanicInfo::from(panic_info))
        }));
    }
}

impl LoggerInitializerWrapperReal {
    pub fn get_logfile_name() -> PathBuf {
        let path: &Path = &(*(Self::logfile_name_guard()).clone());
        path.to_path_buf()
    }

    #[cfg(test)]
    pub fn set_logfile_name(logfile_name: PathBuf) {
        *(Self::logfile_name_guard()) = logfile_name;
    }

    fn logfile_name_guard<'a>() -> MutexGuard<'a, PathBuf> {
        match LOGFILE_NAME.lock() {
            Ok(guard) => guard,
            Err(poison_err) => poison_err.into_inner(),
        }
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
    let location = match panic_info.location {
        None => "<unknown location>".to_string(),
        Some(location) => format!("{}:{}:{}", location.file, location.line, location.col),
    };
    let message = if let Some(s) = panic_info.payload.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = panic_info.payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "<message indecipherable>".to_string()
    };
    let logger = sub_lib::logger::Logger::new("PanicHandler");
    error!(logger, "{} - {}", location, message);
    let backtrace = Backtrace::new();
    error!(logger, "{:?}", backtrace);
}

// DeferredNow can't be constructed in a test; therefore this function is untestable...
fn format_function(
    write: &mut dyn io::Write,
    now: &mut DeferredNow,
    record: &Record,
) -> Result<(), io::Error> {
    real_format_function(write, now.now(), record)
}

// ...but this one isn't.
pub fn real_format_function(
    write: &mut dyn io::Write,
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
    use crate::bootstrapper::RealUser;
    use crate::privilege_drop::PrivilegeDropper;
    use crate::server_initializer::LoggerInitializerWrapper;
    #[cfg(not(target_os = "windows"))]
    use crate::test_utils::logging::init_test_logging;
    use log::LevelFilter;
    use std::cell::RefCell;
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};

    pub struct PrivilegeDropperMock {
        drop_privileges_params: Arc<Mutex<Vec<RealUser>>>,
        chown_params: Arc<Mutex<Vec<(PathBuf, RealUser)>>>,
        expect_privilege_params: Arc<Mutex<Vec<bool>>>,
        expect_privilege_results: RefCell<Vec<bool>>,
    }

    impl PrivilegeDropper for PrivilegeDropperMock {
        fn drop_privileges(&self, real_user: &RealUser) {
            self.drop_privileges_params
                .lock()
                .unwrap()
                .push(real_user.clone());
        }

        fn chown(&self, file: &PathBuf, real_user: &RealUser) {
            self.chown_params
                .lock()
                .unwrap()
                .push((file.clone(), real_user.clone()));
        }

        fn expect_privilege(&self, privilege_expected: bool) -> bool {
            self.expect_privilege_params
                .lock()
                .unwrap()
                .push(privilege_expected);
            self.expect_privilege_results.borrow_mut().remove(0)
        }
    }

    impl PrivilegeDropperMock {
        pub fn new() -> Self {
            Self {
                drop_privileges_params: Arc::new(Mutex::new(vec![])),
                chown_params: Arc::new(Mutex::new(vec![])),
                expect_privilege_params: Arc::new(Mutex::new(vec![])),
                expect_privilege_results: RefCell::new(vec![]),
            }
        }

        pub fn drop_privileges_params(mut self, params: &Arc<Mutex<Vec<RealUser>>>) -> Self {
            self.drop_privileges_params = params.clone();
            self
        }

        pub fn chown_params(mut self, params: &Arc<Mutex<Vec<(PathBuf, RealUser)>>>) -> Self {
            self.chown_params = params.clone();
            self
        }

        pub fn expect_privilege_params(mut self, params: &Arc<Mutex<Vec<bool>>>) -> Self {
            self.expect_privilege_params = params.clone();
            self
        }

        pub fn expect_privilege_result(self, result: bool) -> Self {
            self.expect_privilege_results.borrow_mut().push(result);
            self
        }
    }

    pub struct LoggerInitializerWrapperMock {
        init_parameters: Arc<Mutex<Vec<(PathBuf, RealUser, LevelFilter, Option<String>)>>>,
    }

    impl LoggerInitializerWrapper for LoggerInitializerWrapperMock {
        fn init(
            &mut self,
            file_path: PathBuf,
            real_user: &RealUser,
            log_level: LevelFilter,
            name_segment: Option<&str>,
        ) {
            self.init_parameters.lock().unwrap().push((
                file_path,
                real_user.clone(),
                log_level,
                match name_segment {
                    Some(s) => Some(s.to_string()),
                    None => None,
                },
            ));
            #[cfg(not(target_os = "windows"))]
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
            parameters: &Arc<Mutex<Vec<(PathBuf, RealUser, LevelFilter, Option<String>)>>>,
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
    use crate::test_utils::logfile_name_guard::LogfileNameGuard;
    use crate::test_utils::logging::{init_test_logging, TestLogHandler};
    use masq_lib::crash_point::CrashPoint;
    use masq_lib::shared_schema::{ConfiguratorError, ParamError};
    use masq_lib::test_utils::fake_stream_holder::{
        ByteArrayReader, ByteArrayWriter, FakeStreamHolder,
    };
    use std::cell::RefCell;
    use std::sync::Arc;
    use std::sync::Mutex;

    impl<C> SocketServer<C> for CrashTestDummy<C>
    where
        C: Send,
    {
        fn get_configuration(&self) -> &C {
            &self.configuration
        }

        fn initialize_as_privileged(
            &mut self,
            _args: &[String],
            _streams: &mut StdStreams<'_>,
        ) -> Result<(), ConfiguratorError> {
            Ok(())
        }

        fn initialize_as_unprivileged(
            &mut self,
            _args: &[String],
            _streams: &mut StdStreams<'_>,
        ) -> Result<(), ConfiguratorError> {
            Ok(())
        }
    }

    struct SocketServerMock<C> {
        get_configuration_result: C,
        initialize_as_privileged_params: Arc<Mutex<Vec<Vec<String>>>>,
        initialize_as_privileged_results: RefCell<Vec<Result<(), ConfiguratorError>>>,
        initialize_as_unprivileged_params: Arc<Mutex<Vec<Vec<String>>>>,
        initialize_as_unprivileged_results: RefCell<Vec<Result<(), ConfiguratorError>>>,
    }

    impl<C> Future for SocketServerMock<C> {
        type Item = ();
        type Error = ();

        fn poll(&mut self) -> Result<Async<Self::Item>, Self::Error> {
            unimplemented!()
        }
    }

    impl<C> SocketServer<C> for SocketServerMock<C>
    where
        C: Send,
    {
        fn get_configuration(&self) -> &C {
            &self.get_configuration_result
        }

        fn initialize_as_privileged(
            &mut self,
            args: &[String],
            _streams: &mut StdStreams,
        ) -> Result<(), ConfiguratorError> {
            self.initialize_as_privileged_params
                .lock()
                .unwrap()
                .push(args.to_vec());
            self.initialize_as_privileged_results.borrow_mut().remove(0)
        }

        fn initialize_as_unprivileged(
            &mut self,
            args: &[String],
            _streams: &mut StdStreams,
        ) -> Result<(), ConfiguratorError> {
            self.initialize_as_unprivileged_params
                .lock()
                .unwrap()
                .push(args.to_vec());
            self.initialize_as_unprivileged_results
                .borrow_mut()
                .remove(0)
        }
    }

    impl<C> SocketServerMock<C> {
        pub fn new(get_configuration_result: C) -> SocketServerMock<C> {
            Self {
                get_configuration_result,
                initialize_as_privileged_params: Arc::new(Mutex::new(vec![])),
                initialize_as_privileged_results: RefCell::new(vec![]),
                initialize_as_unprivileged_params: Arc::new(Mutex::new(vec![])),
                initialize_as_unprivileged_results: RefCell::new(vec![]),
            }
        }

        #[allow(dead_code)]
        pub fn initialize_as_privileged_params(
            mut self,
            params: &Arc<Mutex<Vec<Vec<String>>>>,
        ) -> Self {
            self.initialize_as_privileged_params = params.clone();
            self
        }

        #[allow(dead_code)]
        pub fn initialize_as_privileged_result(
            self,
            result: Result<(), ConfiguratorError>,
        ) -> Self {
            self.initialize_as_privileged_results
                .borrow_mut()
                .push(result);
            self
        }

        #[allow(dead_code)]
        pub fn initialize_as_unprivileged_params(
            mut self,
            params: &Arc<Mutex<Vec<Vec<String>>>>,
        ) -> Self {
            self.initialize_as_unprivileged_params = params.clone();
            self
        }

        #[allow(dead_code)]
        pub fn initialize_as_unprivileged_result(
            self,
            result: Result<(), ConfiguratorError>,
        ) -> Self {
            self.initialize_as_unprivileged_results
                .borrow_mut()
                .push(result);
            self
        }
    }

    #[test]
    fn combine_results_combines_success_and_success() {
        let initial_success = Ok("booga");
        let additional_success = Ok(42);

        let result = ServerInitializer::combine_results(initial_success, additional_success);

        assert_eq!(result, Ok(()))
    }

    #[test]
    fn combine_results_combines_success_and_failure() {
        let initial_success = Ok("success");
        let additional_failure: Result<usize, ConfiguratorError> =
            Err(ConfiguratorError::new(vec![
                ParamError::new("param-one", "Reason One"),
                ParamError::new("param-two", "Reason Two"),
            ]));

        let result = ServerInitializer::combine_results(initial_success, additional_failure);

        assert_eq!(
            result,
            Err(ConfiguratorError::new(vec![
                ParamError::new("param-one", "Reason One"),
                ParamError::new("param-two", "Reason Two"),
            ]))
        );
    }

    #[test]
    fn combine_results_combines_failure_and_success() {
        let initial_failure: Result<String, ConfiguratorError> = Err(ConfiguratorError::new(vec![
            ParamError::new("param-one", "Reason One"),
            ParamError::new("param-two", "Reason Two"),
        ]));
        let additional_success = Ok(42);

        let result = ServerInitializer::combine_results(initial_failure, additional_success);

        assert_eq!(
            result,
            Err(ConfiguratorError::new(vec![
                ParamError::new("param-one", "Reason One"),
                ParamError::new("param-two", "Reason Two"),
            ]))
        );
    }

    #[test]
    fn combine_results_combines_failure_and_failure() {
        let initial_failure: Result<String, ConfiguratorError> = Err(ConfiguratorError::new(vec![
            ParamError::new("param-one", "Reason One"),
            ParamError::new("param-two", "Reason Two"),
        ]));
        let additional_failure: Result<usize, ConfiguratorError> =
            Err(ConfiguratorError::new(vec![
                ParamError::new("param-two", "Reason Three"),
                ParamError::new("param-three", "Reason Four"),
            ]));

        let result = ServerInitializer::combine_results(initial_failure, additional_failure);

        assert_eq!(
            result,
            Err(ConfiguratorError::new(vec![
                ParamError::new("param-one", "Reason One"),
                ParamError::new("param-two", "Reason Two"),
                ParamError::new("param-two", "Reason Three"),
                ParamError::new("param-three", "Reason Four"),
            ]))
        );
    }

    #[test]
    fn panic_hook_handles_missing_location_and_unprintable_payload() {
        init_test_logging();
        let panic_info = AltPanicInfo {
            payload: &SocketServerMock::new(()), // not a String or a &str
            location: None,
        };

        panic_hook(panic_info);

        let tlh = TestLogHandler::new();
        tlh.exists_log_containing(
            "ERROR: PanicHandler: <unknown location> - <message indecipherable>",
        );
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
        // TODO: Make this assertion work. Suggestion: isolate it in a test file so that it only sees its own logs.
        //tlh.exists_log_containing("panic_hook_handles_existing_location_and_string_payload");
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
        let _ = LogfileNameGuard::new(&PathBuf::from("uninitialized"));
        let dns_socket_server = CrashTestDummy::new(CrashPoint::Error, ());
        let bootstrapper = CrashTestDummy::new(CrashPoint::Error, BootstrapperConfig::new());

        let privilege_dropper = PrivilegeDropperMock::new();

        let mut subject = ServerInitializer {
            dns_socket_server: Box::new(dns_socket_server),
            bootstrapper: Box::new(bootstrapper),
            privilege_dropper: Box::new(privilege_dropper),
        };

        let stdin = &mut ByteArrayReader::new(&[0; 0]);
        let stdout = &mut ByteArrayWriter::new();
        let stderr = &mut ByteArrayWriter::new();
        let streams = &mut StdStreams {
            stdin,
            stdout,
            stderr,
        };

        subject.go(streams, &[]);
        let res = subject.wait();

        assert!(res.is_err());
    }

    #[test]
    fn server_initializer_as_a_future() {
        let dns_socket_server = CrashTestDummy::new(CrashPoint::None, ());
        let bootstrapper = CrashTestDummy::new(CrashPoint::None, BootstrapperConfig::new());
        let privilege_dropper = PrivilegeDropperMock::new();

        let mut subject = ServerInitializer {
            dns_socket_server: Box::new(dns_socket_server),
            bootstrapper: Box::new(bootstrapper),
            privilege_dropper: Box::new(privilege_dropper),
        };

        let result = subject.poll();
        assert_eq!(result, Ok(Async::Ready(())))
    }

    #[test]
    #[should_panic(expected = "EntryDnsServerMock was instructed to panic")]
    fn server_initializer_dns_socket_server_panics() {
        let bootstrapper = CrashTestDummy::new(CrashPoint::None, BootstrapperConfig::new());
        let privilege_dropper = PrivilegeDropperMock::new();

        let mut subject = ServerInitializer {
            dns_socket_server: Box::new(CrashTestDummy::panic(
                "EntryDnsServerMock was instructed to panic".to_string(),
                (),
            )),
            bootstrapper: Box::new(bootstrapper),
            privilege_dropper: Box::new(privilege_dropper),
        };

        let _ = subject.poll();
    }

    #[test]
    #[should_panic(expected = "BootstrapperMock was instructed to panic")]
    fn server_initializer_bootstrapper_panics() {
        let dns_socket_server = CrashTestDummy::new(CrashPoint::None, ());
        let privilege_dropper = PrivilegeDropperMock::new();
        let mut subject = ServerInitializer {
            dns_socket_server: Box::new(dns_socket_server),
            bootstrapper: Box::new(CrashTestDummy::panic(
                "BootstrapperMock was instructed to panic".to_string(),
                BootstrapperConfig::new(),
            )),
            privilege_dropper: Box::new(privilege_dropper),
        };

        let _ = subject.poll();
    }

    #[test]
    fn go_should_drop_privileges() {
        let _ = LogfileNameGuard::new(&PathBuf::from("uninitialized"));
        let real_user = RealUser::new(Some(123), Some(456), Some("booga".into()));
        let mut bootstrapper_config = BootstrapperConfig::new();
        bootstrapper_config.real_user = real_user.clone();
        let bootstrapper = CrashTestDummy::new(CrashPoint::None, bootstrapper_config);
        let drop_privileges_params_arc = Arc::new(Mutex::new(vec![]));
        let privilege_dropper =
            PrivilegeDropperMock::new().drop_privileges_params(&drop_privileges_params_arc);
        let stdin = &mut ByteArrayReader::new(&[0; 0]);
        let stdout = &mut ByteArrayWriter::new();
        let stderr = &mut ByteArrayWriter::new();
        let streams = &mut StdStreams {
            stdin,
            stdout,
            stderr,
        };
        let mut subject = ServerInitializer {
            dns_socket_server: Box::new(CrashTestDummy::new(CrashPoint::None, ())),
            bootstrapper: Box::new(bootstrapper),
            privilege_dropper: Box::new(privilege_dropper),
        };

        subject.go(streams, &[]);

        let drop_privileges_params = drop_privileges_params_arc.lock().unwrap();
        assert_eq!(*drop_privileges_params, vec![real_user]);
    }

    #[test]
    #[should_panic(expected = "0: ")]
    fn go_with_help_should_print_help_and_artificially_panic() {
        go_with_something_should_print_something_and_artificially_panic("--help");
    }

    #[test]
    #[should_panic(expected = "0: ")]
    fn go_with_version_should_print_version_and_artificially_panic() {
        go_with_something_should_print_something_and_artificially_panic("--version");
    }

    fn go_with_something_should_print_something_and_artificially_panic(parameter: &str) {
        let _ = LogfileNameGuard::new(&PathBuf::from("uninitialized"));
        let dns_socket_server = SocketServerMock::new(());
        let bootstrapper = SocketServerMock::new(BootstrapperConfig::new());
        let privilege_dropper = PrivilegeDropperMock::new();
        let mut subject = ServerInitializer {
            dns_socket_server: Box::new(dns_socket_server),
            bootstrapper: Box::new(bootstrapper),
            privilege_dropper: Box::new(privilege_dropper),
        };
        let args = vec!["MASQ Node".to_string(), parameter.to_string()];

        subject.go(&mut FakeStreamHolder::new().streams(), &args);
    }

    #[test]
    fn go_should_combine_errors() {
        let _ = LogfileNameGuard::new(&PathBuf::from("uninitialized"));
        let dns_socket_server = SocketServerMock::new(())
            .initialize_as_privileged_result(Err(ConfiguratorError::required(
                "dns-iap",
                "dns-iap-reason",
            )))
            .initialize_as_unprivileged_result(Err(ConfiguratorError::required(
                "dns-iau",
                "dns-iau-reason",
            )));
        let bootstrapper = SocketServerMock::new(BootstrapperConfig::new())
            .initialize_as_privileged_result(Err(ConfiguratorError::required(
                "boot-iap",
                "boot-iap-reason",
            )))
            .initialize_as_unprivileged_result(Err(ConfiguratorError::required(
                "boot-iau",
                "boot-iau-reason",
            )));
        let privilege_dropper = PrivilegeDropperMock::new();
        let mut subject = ServerInitializer {
            dns_socket_server: Box::new(dns_socket_server),
            bootstrapper: Box::new(bootstrapper),
            privilege_dropper: Box::new(privilege_dropper),
        };
        let args = vec!["MASQ Node".to_string()];
        let stderr = ByteArrayWriter::new();
        let mut holder = FakeStreamHolder::new();
        holder.stderr = stderr;

        let result = subject.go(&mut holder.streams(), &args);

        assert_eq!(result, 1);
        assert_eq!(
            holder.stderr.get_string(),
            "Problem with parameter dns-iap: dns-iap-reason\n\
Problem with parameter boot-iap: boot-iap-reason\n\
Problem with parameter dns-iau: dns-iau-reason\n\
Problem with parameter boot-iau: boot-iau-reason\n"
        );
    }
}
