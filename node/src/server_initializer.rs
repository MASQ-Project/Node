// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use super::bootstrapper::Bootstrapper;
use super::privilege_drop::PrivilegeDropper;
use super::privilege_drop::PrivilegeDropperReal;
use crate::bootstrapper::RealUser;
use crate::entry_dns::dns_socket_server::DnsSocketServer;
use crate::node_configurator::node_configurator_standard::app;
use crate::node_configurator::node_configurator_standard::standard::service_mode_aggregated_user_params;
use crate::node_configurator::DirsWrapper;
use crate::node_configurator::DirsWrapperReal;
use crate::sub_lib;
use crate::sub_lib::socket_server::ConfiguredByPrivilege;
use backtrace::Backtrace;
use chrono::{DateTime, Local};
use clap::Error;
use flexi_logger::LogSpecBuilder;
use flexi_logger::Logger;
use flexi_logger::{Cleanup, Criterion, LevelFilter, Naming};
use flexi_logger::{DeferredNow, Duplicate, Record};
use futures::try_ready;
use lazy_static::lazy_static;
use masq_lib::command::{Command, StdStreams};
use masq_lib::multi_config::MultiConfig;
use masq_lib::shared_schema::ConfiguratorError;
use masq_lib::utils::exit_process;
use std::any::Any;
use std::fmt::Debug;
use std::panic::{Location, PanicInfo};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};
use std::{io, thread};
use tokio::prelude::Async;
use tokio::prelude::Future;

pub struct ServerInitializer {
    dns_socket_server: Box<dyn ConfiguredByPrivilege<Item = (), Error = ()>>,
    bootstrapper: Box<dyn ConfiguredByPrivilege<Item = (), Error = ()>>,
    privilege_dropper: Box<dyn PrivilegeDropper>,
    data_dir_wrapper: Box<dyn DirsWrapper>,
}

impl Command<ConfiguratorError> for ServerInitializer {
    fn go(
        &mut self,
        streams: &mut StdStreams<'_>,
        args: &[String],
    ) -> Result<(), ConfiguratorError> {
        if Self::is_help_or_version(args) {
            // self.privilege_dropper
            //     .drop_privileges(&RealUser::new(None,None,None).populate(&RealDirsWrapper));
            Self::clap_help_version_brief_process(args, streams)?
        }

        let (multi_config, data_directory, real_user) =
            service_mode_aggregated_user_params(self.data_dir_wrapper.as_ref(), args, streams)?;

        let mut result: Result<(), ConfiguratorError> = Ok(());
        result = Self::combine_results(
            result,
            self.dns_socket_server
                .as_mut()
                .initialize_as_privileged(&multi_config),
        );

        result = Self::combine_results(
            result,
            self.bootstrapper
                .as_mut()
                .initialize_as_privileged(&multi_config),
        );

        self.privilege_dropper.chown(&data_directory, &real_user);
        self.privilege_dropper.drop_privileges(&real_user);

        result = Self::combine_results(
            result,
            self.dns_socket_server
                .as_mut()
                .initialize_as_unprivileged(&multi_config, streams),
        );
        result = Self::combine_results(
            result,
            self.bootstrapper
                .as_mut()
                .initialize_as_unprivileged(&multi_config, streams),
        );
        result
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
            data_dir_wrapper: Box::new(DirsWrapperReal),
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

    fn is_help_or_version(args: &[String]) -> bool {
        args.contains(&"--help".to_string()) || args.contains(&"--version".to_string())
    }

    fn write_h_or_v_msg_and_exit(
        streams: &mut StdStreams<'_>,
        version_or_help_message: String,
    ) -> ! {
        short_writeln!(streams.stdout, "{}", version_or_help_message);
        exit_process(0, "")
    }

    fn clap_help_version_brief_process(
        args: &[String],
        streams: &mut StdStreams<'_>,
    ) -> Result<(), ConfiguratorError> {
        match Self::get_an_authorized_err_msg_from_clap(args) {
            err if err.kind == clap::ErrorKind::HelpDisplayed
                || err.kind == clap::ErrorKind::VersionDisplayed =>
            {
                Self::write_h_or_v_msg_and_exit(streams, err.message)
            }
            err => Err(MultiConfig::make_configurator_error(err)),
        }
    }

    fn get_an_authorized_err_msg_from_clap(args: &[String]) -> Error {
        match app().get_matches_from_safe(args) {
            Err(e) => e,
            _ => unreachable!("if statement in 'go' doesn't work"),
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
            location: panic_info.location().map(AltLocation::from),
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
    use std::path::{Path, PathBuf};
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

        fn chown(&self, file: &Path, real_user: &RealUser) {
            self.chown_params
                .lock()
                .unwrap()
                .push((file.to_path_buf(), real_user.clone()));
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
    use crate::bootstrapper::BootstrapperConfig;
    use crate::crash_test_dummy::CrashTestDummy;
    use crate::node_test_utils::DirsWrapperMock;
    use crate::server_initializer::test_utils::PrivilegeDropperMock;
    use crate::test_utils::logfile_name_guard::LogfileNameGuard;
    use crate::test_utils::logging::{init_test_logging, TestLogHandler};
    use masq_lib::crash_point::CrashPoint;
    use masq_lib::multi_config::{MultiConfig, MultiConfigValuesExtracted};
    use masq_lib::shared_schema::{ConfiguratorError, ParamError};
    use masq_lib::test_utils::fake_stream_holder::{
        ByteArrayReader, ByteArrayWriter, FakeStreamHolder,
    };
    use masq_lib::utils::running_test;
    use std::cell::RefCell;
    use std::ops::Not;
    use std::sync::Arc;
    use std::sync::Mutex;

    impl<C: Send + 'static> ConfiguredByPrivilege for CrashTestDummy<C> {
        fn initialize_as_privileged(
            &mut self,
            _multi_config: &MultiConfig,
        ) -> Result<(), ConfiguratorError> {
            Ok(())
        }

        fn initialize_as_unprivileged(
            &mut self,
            _multi_config: &MultiConfig,
            _streams: &mut StdStreams<'_>,
        ) -> Result<(), ConfiguratorError> {
            Ok(())
        }
    }

    struct ConfiguredByPrivilegeMock {
        demanded_values_from_multi_config: Vec<String>,
        initialize_as_privileged_params: Arc<Mutex<Vec<MultiConfigValuesExtracted>>>,
        initialize_as_privileged_results: RefCell<Vec<Result<(), ConfiguratorError>>>,
        initialize_as_unprivileged_params: Arc<Mutex<Vec<MultiConfigValuesExtracted>>>,
        initialize_as_unprivileged_results: RefCell<Vec<Result<(), ConfiguratorError>>>,
    }

    impl Future for ConfiguredByPrivilegeMock {
        type Item = ();
        type Error = ();

        fn poll(&mut self) -> Result<Async<Self::Item>, Self::Error> {
            unimplemented!()
        }
    }

    impl<'a> ConfiguredByPrivilege for ConfiguredByPrivilegeMock {
        fn initialize_as_privileged(
            &mut self,
            multi_config: &MultiConfig,
        ) -> Result<(), ConfiguratorError> {
            if self.demanded_values_from_multi_config.is_empty().not() {
                self.initialize_as_privileged_params.lock().unwrap().push(
                    MultiConfigValuesExtracted::default().extract_entries_on_demand(
                        &self.demanded_values_from_multi_config,
                        multi_config,
                    ),
                )
            };
            self.initialize_as_privileged_results.borrow_mut().remove(0)
        }

        fn initialize_as_unprivileged(
            &mut self,
            multi_config: &MultiConfig,
            _streams: &mut StdStreams,
        ) -> Result<(), ConfiguratorError> {
            if self.demanded_values_from_multi_config.is_empty().not() {
                self.initialize_as_unprivileged_params.lock().unwrap().push(
                    MultiConfigValuesExtracted::default().extract_entries_on_demand(
                        &self.demanded_values_from_multi_config,
                        multi_config,
                    ),
                );
            }
            self.initialize_as_unprivileged_results
                .borrow_mut()
                .remove(0)
        }
    }

    impl ConfiguredByPrivilegeMock {
        pub fn new() -> ConfiguredByPrivilegeMock {
            Self {
                demanded_values_from_multi_config: vec![],
                initialize_as_privileged_params: Arc::new(Mutex::new(vec![])),
                initialize_as_privileged_results: RefCell::new(vec![]),
                initialize_as_unprivileged_params: Arc::new(Mutex::new(vec![])),
                initialize_as_unprivileged_results: RefCell::new(vec![]),
            }
        }

        #[allow(dead_code)]
        pub fn initialize_as_privileged_params(
            mut self,
            params: &Arc<Mutex<Vec<MultiConfigValuesExtracted>>>,
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
            params: &Arc<Mutex<Vec<MultiConfigValuesExtracted>>>,
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
            payload: &ConfiguredByPrivilegeMock::new(), // not a String or a &str
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

    pub fn make_pre_populated_mock_directory_wrapper() -> DirsWrapperMock {
        DirsWrapperMock::new()
            .home_dir_result(Some(PathBuf::from("/home/alice")))
            .data_dir_result(Some(PathBuf::from("/home/alice/documents")))
    }

    #[test]
    fn exits_after_all_socket_servers_exit() {
        let _ = LogfileNameGuard::new(&PathBuf::from("uninitialized"));
        let dns_socket_server = CrashTestDummy::new(CrashPoint::Error, ());
        let bootstrapper = CrashTestDummy::new(CrashPoint::Error, BootstrapperConfig::new());
        let dirs_wrapper = make_pre_populated_mock_directory_wrapper();
        let privilege_dropper = PrivilegeDropperMock::new();
        let mut subject = ServerInitializer {
            dns_socket_server: Box::new(dns_socket_server),
            bootstrapper: Box::new(bootstrapper),
            privilege_dropper: Box::new(privilege_dropper),
            data_dir_wrapper: Box::new(dirs_wrapper),
        };
        let stdin = &mut ByteArrayReader::new(&[0; 0]);
        let stdout = &mut ByteArrayWriter::new();
        let stderr = &mut ByteArrayWriter::new();
        let streams = &mut StdStreams {
            stdin,
            stdout,
            stderr,
        };
        subject
            .go(
                streams,
                &convert_str_vec_slice_into_vec_slice_of_strings(&[
                    "MASQNode",
                    "--real-user",
                    "123:456:/home/alice",
                ]),
            )
            .unwrap();

        let res = subject.wait();

        assert!(res.is_err());
    }

    #[test]
    fn server_initializer_as_a_future() {
        let dns_socket_server = CrashTestDummy::new(CrashPoint::None, ());
        let bootstrapper = CrashTestDummy::new(CrashPoint::None, BootstrapperConfig::new());
        let privilege_dropper = PrivilegeDropperMock::new();
        let dirs_wrapper = DirsWrapperMock::new();

        let mut subject = ServerInitializer {
            dns_socket_server: Box::new(dns_socket_server),
            bootstrapper: Box::new(bootstrapper),
            privilege_dropper: Box::new(privilege_dropper),
            data_dir_wrapper: Box::new(dirs_wrapper),
        };

        let result = subject.poll();
        assert_eq!(result, Ok(Async::Ready(())))
    }

    #[test]
    #[should_panic(expected = "EntryDnsServerMock was instructed to panic")]
    fn server_initializer_dns_socket_server_panics() {
        let bootstrapper = CrashTestDummy::new(CrashPoint::None, BootstrapperConfig::new());
        let privilege_dropper = PrivilegeDropperMock::new();
        let dirs_wrapper = DirsWrapperMock::new();

        let mut subject = ServerInitializer {
            dns_socket_server: Box::new(CrashTestDummy::panic(
                "EntryDnsServerMock was instructed to panic".to_string(),
                (),
            )),
            bootstrapper: Box::new(bootstrapper),
            privilege_dropper: Box::new(privilege_dropper),
            data_dir_wrapper: Box::new(dirs_wrapper),
        };

        let _ = subject.poll();
    }

    #[test]
    #[should_panic(expected = "BootstrapperMock was instructed to panic")]
    fn server_initializer_bootstrapper_panics() {
        let dns_socket_server = CrashTestDummy::new(CrashPoint::None, ());
        let privilege_dropper = PrivilegeDropperMock::new();
        let dirs_wrapper = DirsWrapperMock::new();
        let mut subject = ServerInitializer {
            dns_socket_server: Box::new(dns_socket_server),
            bootstrapper: Box::new(CrashTestDummy::panic(
                "BootstrapperMock was instructed to panic".to_string(),
                BootstrapperConfig::new(),
            )),
            privilege_dropper: Box::new(privilege_dropper),
            data_dir_wrapper: Box::new(dirs_wrapper),
        };

        let _ = subject.poll();
    }

    #[test]
    fn go_should_drop_privileges() {
        let _ = LogfileNameGuard::new(&PathBuf::from("uninitialized"));
        let real_user = RealUser::new(Some(123), Some(456), Some("/home/alice".into()));
        let mut bootstrapper_config = BootstrapperConfig::new();
        bootstrapper_config.real_user = real_user.clone();
        let bootstrapper = CrashTestDummy::new(CrashPoint::None, bootstrapper_config);
        let dirs_wrapper = make_pre_populated_mock_directory_wrapper();
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
            data_dir_wrapper: Box::new(dirs_wrapper),
        };

        let result = subject.go(
            streams,
            &convert_str_vec_slice_into_vec_slice_of_strings(&[
                "MASQNode",
                "--real-user",
                "123:456:/home/alice",
            ]),
        );

        assert!(result.is_ok());
        let drop_privileges_params = drop_privileges_params_arc.lock().unwrap();
        assert_eq!(*drop_privileges_params, vec![real_user]);
    }

    #[test]
    fn get_an_authorized_msg_from_clap_provides_help_information_inside_its_error() {
        let args = &["MASQNode".to_string(), "--help".to_string()];

        let result = ServerInitializer::get_an_authorized_err_msg_from_clap(args);

        assert!(result
            .message
            .contains("MASQ\nMASQ Node is the foundation of  MASQ Network"));
        assert!(result.message.contains(
            "MASQNode [OPTIONS]\n\nFLAGS:\n    -h, --help       Prints help information\n "
        ))
    }

    #[test]
    #[should_panic(expected = "if statement in 'go' doesn't work")]
    fn get_an_authorized_msg_from_clap_panics_if_argument_parsing_ends_happily() {
        let args =
            &convert_str_vec_slice_into_vec_slice_of_strings(&["MASQNode", "--ip", "1.2.3.4"]);

        let _ = ServerInitializer::get_an_authorized_err_msg_from_clap(args);
    }

    #[test]
    fn go_returns_a_syntax_error_within_help_invocation() {
        let args = convert_str_vec_slice_into_vec_slice_of_strings(&[
            "MASQNode", "param", "--help", "arg1",
        ]);
        let mut stream_holder = FakeStreamHolder::default();
        let mut streams = stream_holder.streams();
        let mut subject = ServerInitializer {
            dns_socket_server: Box::new(ConfiguredByPrivilegeMock::new()),
            bootstrapper: Box::new(ConfiguredByPrivilegeMock::new()),
            privilege_dropper: Box::new(PrivilegeDropperMock::new()),
            data_dir_wrapper: Box::new(DirsWrapperMock::new()),
        };

        let result = subject.go(&mut streams, &args);

        let param_error = result.unwrap_err().param_errors.remove(0);
        assert_eq!(param_error.parameter, "<unknown>".to_string());
        assert!(param_error
            .reason
            .contains("Unfamiliar message: error: Found argument \'param\' which wasn\'t expected"))
    }

    pub fn convert_str_vec_slice_into_vec_slice_of_strings(slice: &[&str]) -> Vec<String> {
        slice
            .into_iter()
            .map(|item| item.to_string())
            .collect::<Vec<String>>()
    }

    #[test]
    #[should_panic(expected = "0: ")]
    fn go_with_help_should_print_help_and_artificially_panic() {
        running_test();
        go_with_something_should_print_something_and_artificially_panic("--help");
    }

    #[test]
    #[should_panic(expected = "0: ")]
    fn go_with_version_should_print_version_and_artificially_panic() {
        running_test();
        go_with_something_should_print_something_and_artificially_panic("--version");
    }

    fn go_with_something_should_print_something_and_artificially_panic(parameter: &str) {
        let _ = LogfileNameGuard::new(&PathBuf::from("uninitialized"));
        let dns_socket_server = ConfiguredByPrivilegeMock::new();
        let bootstrapper = ConfiguredByPrivilegeMock::new();
        let dirs_wrapper = make_pre_populated_mock_directory_wrapper();
        let privilege_dropper = PrivilegeDropperMock::new();
        let mut subject = ServerInitializer {
            dns_socket_server: Box::new(dns_socket_server),
            bootstrapper: Box::new(bootstrapper),
            privilege_dropper: Box::new(privilege_dropper),
            data_dir_wrapper: Box::new(dirs_wrapper),
        };
        let args = convert_str_vec_slice_into_vec_slice_of_strings(&["MASQNode", parameter]);

        subject
            .go(&mut FakeStreamHolder::new().streams(), &args)
            .unwrap();
    }

    #[test]
    fn go_should_combine_errors() {
        let _ = LogfileNameGuard::new(&PathBuf::from("uninitialized"));
        let dns_socket_server = ConfiguredByPrivilegeMock::new()
            .initialize_as_privileged_result(Err(ConfiguratorError::required(
                "dns-iap",
                "dns-iap-reason",
            )))
            .initialize_as_unprivileged_result(Err(ConfiguratorError::required(
                "dns-iau",
                "dns-iau-reason",
            )));
        let bootstrapper = ConfiguredByPrivilegeMock::new()
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
            data_dir_wrapper: Box::new(make_pre_populated_mock_directory_wrapper()),
        };
        let args = convert_str_vec_slice_into_vec_slice_of_strings(&[
            "MASQNode",
            "--real-user",
            "123:123:/home/alice",
        ]);
        let stderr = ByteArrayWriter::new();
        let mut holder = FakeStreamHolder::new();
        holder.stderr = stderr;

        let result = subject.go(&mut holder.streams(), &args);

        assert_eq!(
            result,
            Err(ConfiguratorError::new(vec![
                ParamError::new("dns-iap", "dns-iap-reason"),
                ParamError::new("boot-iap", "boot-iap-reason"),
                ParamError::new("dns-iau", "dns-iau-reason"),
                ParamError::new("boot-iau", "boot-iau-reason")
            ]))
        );
    }
}
