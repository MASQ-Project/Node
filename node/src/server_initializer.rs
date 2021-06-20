// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use super::bootstrapper::Bootstrapper;
use super::privilege_drop::{PrivilegeDropper, PrivilegeDropperReal};
use crate::bootstrapper::RealUser;
use crate::entry_dns::dns_socket_server::DnsSocketServer;
use crate::node_configurator::node_configurator_standard::standard::collected_input_params_for_service_mode;
use crate::node_configurator::{DirsWrapper, DirsWrapperReal};
use crate::run_modes_factories::{RunModeResult, ServerInitializer};
use crate::sub_lib;
use crate::sub_lib::socket_server::ConfiguredByPrivilege;
use backtrace::Backtrace;
use chrono::{DateTime, Local};
use flexi_logger::{
    Cleanup, Criterion, DeferredNow, Duplicate, LevelFilter, LogSpecBuilder, Logger, Naming, Record,
};
use futures::try_ready;
use lazy_static::lazy_static;
use masq_lib::command::{Command, StdStreams};
use masq_lib::shared_schema::ConfiguratorError;
use std::any::Any;
use std::fmt::Debug;
use std::panic::{Location, PanicInfo};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};
use std::{io, thread};
use tokio::prelude::{Async, Future};

pub struct ServerInitializerReal {
    dns_socket_server: Box<dyn ConfiguredByPrivilege<Item = (), Error = ()>>,
    bootstrapper: Box<dyn ConfiguredByPrivilege<Item = (), Error = ()>>,
    privilege_dropper: Box<dyn PrivilegeDropper>,
    dir_wrapper: Box<dyn DirsWrapper>,
}

impl Command<RunModeResult> for ServerInitializerReal {
    fn go(
        &mut self,
        streams: &mut StdStreams<'_>,
        args: &[String],
    ) -> Result<(), ConfiguratorError> {
        let (multi_config, data_directory, real_user) =
            collected_input_params_for_service_mode(self.dir_wrapper.as_ref(), args)?;

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

impl ServerInitializer for ServerInitializerReal {
    #[cfg(test)]
    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl Future for ServerInitializerReal {
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

impl ServerInitializerReal {
    pub fn new() -> ServerInitializerReal {
        ServerInitializerReal {
            dns_socket_server: Box::new(DnsSocketServer::new()),
            bootstrapper: Box::new(Bootstrapper::new(Box::new(LoggerInitializerWrapperReal {}))),
            privilege_dropper: Box::new(PrivilegeDropperReal::new()),
            dir_wrapper: Box::new(DirsWrapperReal),
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

impl Default for ServerInitializerReal {
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

pub struct LoggerInitializerWrapperReal;

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
    use crate::run_modes_factories::{RunModeResult, ServerInitializer};
    use crate::server_initializer::LoggerInitializerWrapper;
    #[cfg(not(target_os = "windows"))]
    use crate::test_utils::logging::init_test_logging;
    use futures::Async;
    use log::LevelFilter;
    use masq_lib::command::{Command, StdStreams};
    use masq_lib::shared_schema::ConfiguratorError;
    use std::cell::RefCell;
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Mutex};
    use tokio::prelude::Future;

    #[derive(Default)]
    pub struct ServerInitializerMock {
        go_result: RefCell<Vec<Result<(), ConfiguratorError>>>,
        go_params: RefCell<Arc<Mutex<Vec<Vec<String>>>>>,
        poll_result: RefCell<Vec<Result<Async<<Self as Future>::Item>, <Self as Future>::Error>>>,
    }

    impl ServerInitializerMock {
        pub fn go_result(self, result: Result<(), ConfiguratorError>) -> Self {
            self.go_result.borrow_mut().push(result);
            self
        }

        pub fn go_params(self, params: &Arc<Mutex<Vec<Vec<String>>>>) -> Self {
            self.go_params.replace(params.clone());
            self
        }

        pub fn poll_result(
            self,
            result: Result<Async<<Self as Future>::Item>, <Self as Future>::Error>,
        ) -> Self {
            self.poll_result.borrow_mut().push(result);
            self
        }
    }

    impl ServerInitializer for ServerInitializerMock {}

    impl Command<RunModeResult> for ServerInitializerMock {
        fn go(
            &mut self,
            _streams: &mut StdStreams<'_>,
            args: &[String],
        ) -> Result<(), ConfiguratorError> {
            self.go_params.borrow().lock().unwrap().push(args.to_vec());
            self.go_result.borrow_mut().remove(0)
        }
    }

    impl Future for ServerInitializerMock {
        type Item = ();
        type Error = ();

        fn poll(&mut self) -> Result<Async<<Self as Future>::Item>, <Self as Future>::Error> {
            self.poll_result.borrow_mut().remove(0)
        }
    }

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
    use masq_lib::multi_config::MultiConfig;
    use masq_lib::shared_schema::{ConfiguratorError, ParamError};
    use masq_lib::test_utils::fake_stream_holder::{
        ByteArrayReader, ByteArrayWriter, FakeStreamHolder,
    };
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

    #[derive(Default)]
    struct ConfiguredByPrivilegeMock {
        demanded_values_from_multi_config: RefCell<Vec<String>>,
        initialize_as_privileged_params: Arc<Mutex<Vec<MultiConfigExtractedValues>>>,
        initialize_as_privileged_results: RefCell<Vec<Result<(), ConfiguratorError>>>,
        initialize_as_unprivileged_params: Arc<Mutex<Vec<MultiConfigExtractedValues>>>,
        initialize_as_unprivileged_results: RefCell<Vec<Result<(), ConfiguratorError>>>,
    }

    impl Future for ConfiguredByPrivilegeMock {
        type Item = ();
        type Error = ();

        fn poll(&mut self) -> Result<Async<Self::Item>, Self::Error> {
            intentionally_blank!()
        }
    }

    pub fn extract_values_from_multi_config(
        requested_params: &RefCell<Vec<String>>,
        resulting_values: &Arc<Mutex<Vec<MultiConfigExtractedValues>>>,
        multi_config: &MultiConfig,
    ) {
        if requested_params.borrow().is_empty().not() {
            resulting_values.lock().unwrap().push(
                MultiConfigExtractedValues::default()
                    .extract_entries_on_demand(&requested_params.borrow(), multi_config),
            )
        };
    }

    impl<'a> ConfiguredByPrivilege for ConfiguredByPrivilegeMock {
        fn initialize_as_privileged(
            &mut self,
            multi_config: &MultiConfig,
        ) -> Result<(), ConfiguratorError> {
            extract_values_from_multi_config(
                &self.demanded_values_from_multi_config,
                &self.initialize_as_privileged_params,
                multi_config,
            );
            self.initialize_as_privileged_results.borrow_mut().remove(0)
        }

        fn initialize_as_unprivileged(
            &mut self,
            multi_config: &MultiConfig,
            _streams: &mut StdStreams,
        ) -> Result<(), ConfiguratorError> {
            extract_values_from_multi_config(
                &self.demanded_values_from_multi_config,
                &self.initialize_as_unprivileged_params,
                multi_config,
            );
            self.initialize_as_unprivileged_results
                .borrow_mut()
                .remove(0)
        }
    }

    impl ConfiguredByPrivilegeMock {
        pub fn set_demanded_values_from_multi_config(self, mut values: Vec<String>) -> Self {
            self.demanded_values_from_multi_config
                .borrow_mut()
                .append(&mut values);
            self
        }

        pub fn initialize_as_privileged_params(
            mut self,
            params: &Arc<Mutex<Vec<MultiConfigExtractedValues>>>,
        ) -> Self {
            self.initialize_as_privileged_params = params.clone();
            self
        }

        pub fn initialize_as_privileged_result(
            self,
            result: Result<(), ConfiguratorError>,
        ) -> Self {
            self.initialize_as_privileged_results
                .borrow_mut()
                .push(result);
            self
        }

        pub fn initialize_as_unprivileged_params(
            mut self,
            params: &Arc<Mutex<Vec<MultiConfigExtractedValues>>>,
        ) -> Self {
            self.initialize_as_unprivileged_params = params.clone();
            self
        }

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

    //TODO consider if this tool is valuable or needless
    #[derive(Default)]
    pub struct MultiConfigExtractedValues {
        pub arg_matches_requested_entries: Vec<String>,
    }

    impl MultiConfigExtractedValues {
        pub fn extract_entries_on_demand(
            mut self,
            required: &[String],
            multi_config: &MultiConfig,
        ) -> Self {
            self.arg_matches_requested_entries = required
                .iter()
                .map(|key| multi_config.arg_matches.value_of(key).unwrap().to_string())
                .collect();
            self
        }
    }

    #[test]
    fn combine_results_combines_success_and_success() {
        let initial_success = Ok("booga");
        let additional_success = Ok(42);

        let result = ServerInitializerReal::combine_results(initial_success, additional_success);

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

        let result = ServerInitializerReal::combine_results(initial_success, additional_failure);

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

        let result = ServerInitializerReal::combine_results(initial_failure, additional_success);

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

        let result = ServerInitializerReal::combine_results(initial_failure, additional_failure);

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
            payload: &ConfiguredByPrivilegeMock::default(), // not a String or a &str
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
            .data_dir_result(Some(PathBuf::from("/home/alice/Documents")))
    }

    #[test]
    fn exits_after_all_socket_servers_exit() {
        let _ = LogfileNameGuard::new(&PathBuf::from("uninitialized"));
        let dns_socket_server = CrashTestDummy::new(CrashPoint::Error, ());
        let bootstrapper = CrashTestDummy::new(CrashPoint::Error, BootstrapperConfig::new());
        let dirs_wrapper = make_pre_populated_mock_directory_wrapper();
        let privilege_dropper = PrivilegeDropperMock::new();
        let mut subject = ServerInitializerReal {
            dns_socket_server: Box::new(dns_socket_server),
            bootstrapper: Box::new(bootstrapper),
            privilege_dropper: Box::new(privilege_dropper),
            dir_wrapper: Box::new(dirs_wrapper),
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
                &convert_str_vec_slice_into_vec_of_strings(&[
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

        let mut subject = ServerInitializerReal {
            dns_socket_server: Box::new(dns_socket_server),
            bootstrapper: Box::new(bootstrapper),
            privilege_dropper: Box::new(privilege_dropper),
            dir_wrapper: Box::new(dirs_wrapper),
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

        let mut subject = ServerInitializerReal {
            dns_socket_server: Box::new(CrashTestDummy::panic(
                "EntryDnsServerMock was instructed to panic".to_string(),
                (),
            )),
            bootstrapper: Box::new(bootstrapper),
            privilege_dropper: Box::new(privilege_dropper),
            dir_wrapper: Box::new(dirs_wrapper),
        };

        let _ = subject.poll();
    }

    #[test]
    #[should_panic(expected = "BootstrapperMock was instructed to panic")]
    fn server_initializer_bootstrapper_panics() {
        let dns_socket_server = CrashTestDummy::new(CrashPoint::None, ());
        let privilege_dropper = PrivilegeDropperMock::new();
        let dirs_wrapper = DirsWrapperMock::new();
        let mut subject = ServerInitializerReal {
            dns_socket_server: Box::new(dns_socket_server),
            bootstrapper: Box::new(CrashTestDummy::panic(
                "BootstrapperMock was instructed to panic".to_string(),
                BootstrapperConfig::new(),
            )),
            privilege_dropper: Box::new(privilege_dropper),
            dir_wrapper: Box::new(dirs_wrapper),
        };

        let _ = subject.poll();
    }

    #[test]
    fn go_should_drop_privileges() {
        let _ = LogfileNameGuard::new(&PathBuf::from("uninitialized"));
        let bootstrapper_init_privileged_params_arc = Arc::new(Mutex::new(vec![]));
        let bootstrapper_init_unprivileged_params_arc = Arc::new(Mutex::new(vec![]));
        let dns_socket_server_privileged_params_arc = Arc::new(Mutex::new(vec![]));
        let dns_socket_server_unprivileged_params_arc = Arc::new(Mutex::new(vec![]));
        let bootstrapper = ConfiguredByPrivilegeMock::default()
            .initialize_as_privileged_result(Ok(()))
            .initialize_as_unprivileged_result(Ok(()))
            .initialize_as_privileged_params(&bootstrapper_init_privileged_params_arc)
            .initialize_as_unprivileged_params(&bootstrapper_init_unprivileged_params_arc)
            .set_demanded_values_from_multi_config(vec![
                "dns-servers".to_string(),
                "real-user".to_string(),
            ]);
        let dns_socket_server = ConfiguredByPrivilegeMock::default()
            .initialize_as_privileged_result(Ok(()))
            .initialize_as_unprivileged_result(Ok(()))
            .initialize_as_privileged_params(&dns_socket_server_privileged_params_arc)
            .initialize_as_unprivileged_params(&dns_socket_server_unprivileged_params_arc)
            .set_demanded_values_from_multi_config(vec![
                "dns-servers".to_string(),
                "real-user".to_string(),
            ]);
        let dirs_wrapper = make_pre_populated_mock_directory_wrapper();
        let drop_privileges_params_arc = Arc::new(Mutex::new(vec![]));
        let chown_params_arc = Arc::new(Mutex::new(vec![]));
        let privilege_dropper = PrivilegeDropperMock::new()
            .drop_privileges_params(&drop_privileges_params_arc)
            .chown_params(&chown_params_arc);
        let stdin = &mut ByteArrayReader::new(&[0; 0]);
        let stdout = &mut ByteArrayWriter::new();
        let stderr = &mut ByteArrayWriter::new();
        let streams = &mut StdStreams {
            stdin,
            stdout,
            stderr,
        };
        let mut subject = ServerInitializerReal {
            dns_socket_server: Box::new(dns_socket_server),
            bootstrapper: Box::new(bootstrapper),
            privilege_dropper: Box::new(privilege_dropper),
            dir_wrapper: Box::new(dirs_wrapper),
        };

        let result = subject.go(
            streams,
            &convert_str_vec_slice_into_vec_of_strings(&[
                "MASQNode",
                "--real-user",
                "123:456:/home/alice",
                "--dns-servers",
                "5.5.6.6",
            ]),
        );

        assert!(result.is_ok());
        let real_user = RealUser::new(Some(123), Some(456), Some("/home/alice".into()));
        let chown_params = chown_params_arc.lock().unwrap();
        assert_eq!(
            *chown_params,
            vec![(
                PathBuf::from("/home/alice/Documents/MASQ/mainnet"),
                real_user.clone()
            )]
        );
        let drop_privileges_params = drop_privileges_params_arc.lock().unwrap();
        assert_eq!(*drop_privileges_params, vec![real_user]);
        let params_for_assertion_on_multi_config = &vec!["5.5.6.6", "123:456:/home/alice"];
        [
            bootstrapper_init_privileged_params_arc,
            bootstrapper_init_unprivileged_params_arc,
            dns_socket_server_privileged_params_arc,
            dns_socket_server_unprivileged_params_arc,
        ]
        .iter()
        .for_each(|arc_params| {
            let param_vec = arc_params.lock().unwrap();
            assert_eq!(
                &param_vec[0].arg_matches_requested_entries,
                params_for_assertion_on_multi_config
            )
        })
    }

    pub fn convert_str_vec_slice_into_vec_of_strings(slice: &[&str]) -> Vec<String> {
        slice
            .iter()
            .map(|item| item.to_string())
            .collect::<Vec<String>>()
    }

    #[test]
    fn go_should_combine_errors() {
        let _ = LogfileNameGuard::new(&PathBuf::from("uninitialized"));
        let dns_socket_server = ConfiguredByPrivilegeMock::default()
            .initialize_as_privileged_result(Err(ConfiguratorError::required(
                "dns-iap",
                "dns-iap-reason",
            )))
            .initialize_as_unprivileged_result(Err(ConfiguratorError::required(
                "dns-iau",
                "dns-iau-reason",
            )));
        let bootstrapper = ConfiguredByPrivilegeMock::default()
            .initialize_as_privileged_result(Err(ConfiguratorError::required(
                "boot-iap",
                "boot-iap-reason",
            )))
            .initialize_as_unprivileged_result(Err(ConfiguratorError::required(
                "boot-iau",
                "boot-iau-reason",
            )));
        let privilege_dropper = PrivilegeDropperMock::new();
        let mut subject = ServerInitializerReal {
            dns_socket_server: Box::new(dns_socket_server),
            bootstrapper: Box::new(bootstrapper),
            privilege_dropper: Box::new(privilege_dropper),
            dir_wrapper: Box::new(make_pre_populated_mock_directory_wrapper()),
        };
        let args = convert_str_vec_slice_into_vec_of_strings(&[
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
