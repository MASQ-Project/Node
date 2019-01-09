// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use bootstrapper::Bootstrapper;
use entry_dns_lib::dns_socket_server::new_dns_socket_server;
use flexi_logger::Duplicate;
use flexi_logger::LevelFilter;
use flexi_logger::LogSpecification;
use flexi_logger::Logger;
use privilege_drop::PrivilegeDropper;
use privilege_drop::PrivilegeDropperReal;
use std::env::temp_dir;
use std::str::FromStr;
use sub_lib::main_tools::Command;
use sub_lib::main_tools::StdStreams;
use sub_lib::parameter_finder::ParameterFinder;
use sub_lib::socket_server::SocketServer;
use tokio::prelude::Async;
use tokio::prelude::Future;

pub struct ServerInitializer<P>
where
    P: PrivilegeDropper,
{
    dns_socket_server: Box<SocketServer<Item = (), Error = ()>>,
    bootstrapper: Box<SocketServer<Item = (), Error = ()>>,
    privilege_dropper: P,
    logger_initializer_wrapper: Box<LoggerInitializerWrapper>,
}

impl<P> Command for ServerInitializer<P>
where
    P: PrivilegeDropper,
{
    fn go(&mut self, streams: &mut StdStreams, args: &Vec<String>) -> u8 {
        self.logger_initializer_wrapper.init(args);

        self.dns_socket_server
            .as_mut()
            .initialize_as_privileged(args, streams);
        self.bootstrapper
            .as_mut()
            .initialize_as_privileged(args, streams);

        self.privilege_dropper.drop_privileges();

        self.dns_socket_server.as_mut().initialize_as_unprivileged();
        self.bootstrapper.as_mut().initialize_as_unprivileged();

        1
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
            dns_socket_server: Box::new(new_dns_socket_server()),
            bootstrapper: Box::new(Bootstrapper::new()),
            privilege_dropper: PrivilegeDropperReal::new(),
            logger_initializer_wrapper: Box::new(LoggerInitializerWrapperReal {}),
        }
    }
}

trait LoggerInitializerWrapper: Send {
    fn init(&mut self, args: &Vec<String>) -> bool;
}

struct LoggerInitializerWrapperReal {}

impl LoggerInitializerWrapper for LoggerInitializerWrapperReal {
    fn init(&mut self, args: &Vec<String>) -> bool {
        match Logger::with(
            LogSpecification::default(LoggerInitializerWrapperReal::get_log_level(args)).finalize(),
        )
        .log_to_file()
        .directory(&temp_dir().to_str().expect("Bad temporary filename")[..])
        .print_message()
        .duplicate_to_stderr(Duplicate::Info)
        .suppress_timestamp()
        .start()
        {
            Ok(_) => true,
            Err(_) => false,
        }
    }
}

impl LoggerInitializerWrapperReal {
    fn get_log_level(args: &Vec<String>) -> LevelFilter {
        let parameter_tag = "--log_level";
        let usage = "should be one of <trace|debug|info|warn|error|off> (default = warn)";

        match ParameterFinder::new(args.clone()).find_value_for(parameter_tag, usage) {
            Some(value) => match LevelFilter::from_str(value.as_str()) {
                Ok(lf) => lf,
                Err(_) => panic!("Bad value '{}' for {}: {}", value, parameter_tag, usage),
            },
            None => LevelFilter::Warn,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crash_test_dummy::CrashTestDummy;
    use std::sync::Arc;
    use std::sync::Mutex;
    use sub_lib::crash_point::CrashPoint;
    use test_utils::logging::init_test_logging;
    use test_utils::test_utils::ByteArrayReader;
    use test_utils::test_utils::ByteArrayWriter;

    impl SocketServer for CrashTestDummy {
        fn name(&self) -> String {
            String::from("crash test SocketServer")
        }

        fn initialize_as_privileged(&mut self, _args: &Vec<String>, _streams: &mut StdStreams) {}

        fn initialize_as_unprivileged(&mut self) {}
    }

    struct PrivilegeDropperMock {
        call_count: Arc<Mutex<usize>>,
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
    }

    struct LoggerInitializerWrapperMock {
        init_parameters: Arc<Mutex<Vec<Vec<String>>>>,
    }

    impl LoggerInitializerWrapper for LoggerInitializerWrapperMock {
        fn init(&mut self, args: &Vec<String>) -> bool {
            self.init_parameters.lock().unwrap().push(args.clone());
            init_test_logging()
        }
    }

    impl LoggerInitializerWrapperMock {
        pub fn new() -> LoggerInitializerWrapperMock {
            LoggerInitializerWrapperMock {
                init_parameters: Arc::new(Mutex::new(vec![])),
            }
        }

        pub fn init_parameters(&mut self, parameters: &Arc<Mutex<Vec<Vec<String>>>>) {
            self.init_parameters = parameters.clone();
        }
    }

    #[test]
    fn exits_after_all_socket_servers_exit() {
        let dns_socket_server = CrashTestDummy::new(CrashPoint::Error);
        let bootstrapper = CrashTestDummy::new(CrashPoint::Error);

        let privilege_dropper = PrivilegeDropperMock::new();
        let mut logger_initializer_wrapper_mock = LoggerInitializerWrapperMock::new();
        let logger_init_parameters: Arc<Mutex<Vec<Vec<String>>>> = Arc::new(Mutex::new(vec![]));
        logger_initializer_wrapper_mock.init_parameters(&logger_init_parameters);

        let mut subject = ServerInitializer {
            dns_socket_server: Box::new(dns_socket_server),
            bootstrapper: Box::new(bootstrapper),
            privilege_dropper,
            logger_initializer_wrapper: Box::new(logger_initializer_wrapper_mock),
        };

        let stdin = &mut ByteArrayReader::new(&[0; 0]);
        let stdout = &mut ByteArrayWriter::new();
        let stderr = &mut ByteArrayWriter::new();
        let streams = &mut StdStreams {
            stdin,
            stdout,
            stderr,
        };

        let args = vec![String::from("glorp")];

        subject.go(streams, &args);
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
            logger_initializer_wrapper: Box::new(LoggerInitializerWrapperMock::new()),
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
            logger_initializer_wrapper: Box::new(LoggerInitializerWrapperMock::new()),
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
            logger_initializer_wrapper: Box::new(LoggerInitializerWrapperMock::new()),
        };

        let _ = subject.poll();
    }

    #[test]
    fn get_log_level_returns_warn_by_default() {
        let args: Vec<String> = vec![];
        assert_eq!(
            LoggerInitializerWrapperReal::get_log_level(&args),
            LevelFilter::Warn
        );
    }

    #[test]
    fn get_log_level_returns_log_level_from_args() {
        let args = vec![String::from("--log_level"), String::from("trace")];
        assert_eq!(
            LoggerInitializerWrapperReal::get_log_level(&args),
            LevelFilter::Trace
        );

        let args = vec![String::from("--log_level"), String::from("WaRn")];
        assert_eq!(
            LoggerInitializerWrapperReal::get_log_level(&args),
            LevelFilter::Warn
        );

        let args = vec![String::from("--log_level"), String::from("DebuG")];
        assert_eq!(
            LoggerInitializerWrapperReal::get_log_level(&args),
            LevelFilter::Debug
        );

        let args = vec![String::from("--log_level"), String::from("INFO")];
        assert_eq!(
            LoggerInitializerWrapperReal::get_log_level(&args),
            LevelFilter::Info
        );

        let args = vec![String::from("--log_level"), String::from("Error")];
        assert_eq!(
            LoggerInitializerWrapperReal::get_log_level(&args),
            LevelFilter::Error
        );

        let args = vec![String::from("--log_level"), String::from("off")];
        assert_eq!(
            LoggerInitializerWrapperReal::get_log_level(&args),
            LevelFilter::Off
        );
    }

    #[test]
    #[should_panic(
        expected = "Bad value 'blooga' for --log_level: should be one of <trace|debug|info|warn|error|off> (default = warn)"
    )]
    fn get_log_level_panics_if_arg_makes_no_sense() {
        let args = vec![
            String::from("--dns_servers"),
            String::from("1.2.3.4"),
            String::from("--log_level"),
            String::from("blooga"),
        ];

        LoggerInitializerWrapperReal::get_log_level(&args);
    }

    #[test]
    #[should_panic(
        expected = "Missing value for --log_level: should be one of <trace|debug|info|warn|error|off> (default = warn)"
    )]
    fn get_log_level_panics_if_flag_is_last_with_no_value() {
        let args = vec![String::from("--log_level")];

        LoggerInitializerWrapperReal::get_log_level(&args);
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
            logger_initializer_wrapper: Box::new(LoggerInitializerWrapperMock::new()),
        };

        subject.go(streams, &vec![]);

        assert_eq!(*call_count.lock().unwrap(), 1);
    }
}
