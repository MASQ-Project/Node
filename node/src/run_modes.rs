// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::apps::{app_config_dumper, app_daemon, app_node};
use crate::privilege_drop::{PrivilegeDropper, PrivilegeDropperReal};
use crate::run_modes::Leaving::{ExitCode, Not};
use crate::run_modes_factories::{
    DaemonInitializerFactory, DaemonInitializerFactoryReal, DumpConfigRunnerFactory,
    DumpConfigRunnerFactoryReal, ServerInitializerFactory, ServerInitializerFactoryReal,
};
use actix::System;
use clap::Error;
use masq_lib::command::StdStreams;
use masq_lib::logger::Logger;
use masq_lib::multi_config::MultiConfig;
use masq_lib::shared_schema::{ConfiguratorError, ParamError};
use masq_lib::test_utils::utils::make_rt;
use tokio::task;
use tokio::task::JoinHandle;
use ProgramEntering::{Enter, Leave};

#[derive(Debug, PartialEq, Eq)]
enum Mode {
    DumpConfig,
    Initialization,
    Service,
}

pub struct RunModes {
    privilege_dropper: Box<dyn PrivilegeDropper>,
    runner: Box<dyn Runner>,
}

impl Default for RunModes {
    fn default() -> Self {
        Self::new()
    }
}

impl RunModes {
    pub fn new() -> Self {
        Self {
            privilege_dropper: Box::new(PrivilegeDropperReal::new()),
            runner: Box::new(RunnerReal::new()),
        }
    }

    pub fn go(&self, args: &[String], streams: &mut StdStreams<'_>) -> i32 {
        let mode = match self.meet_bouncers_at_the_door(args, streams) {
            Enter(mode) => mode,
            Leave(exit_code) => return exit_code,
        };

        let run_result = match mode {
            Mode::DumpConfig => self.runner.dump_config(args, streams),
            Mode::Initialization => self.runner.run_daemon(args, streams),
            Mode::Service => self.runner.run_node(args, streams),
        };

        match run_result {
            Ok(_) => 0,
            Err(RunnerError::Numeric(e_num)) => e_num,
            Err(RunnerError::Configurator(conf_e)) => {
                Self::process_gathered_errors(conf_e, streams);
                1
            }
        }
    }

    fn meet_bouncers_at_the_door(
        &self,
        args: &[String],
        streams: &mut StdStreams,
    ) -> ProgramEntering {
        let (mode, privilege_required) = self.determine_mode_and_priv_req(args);
        if let ExitCode(exit_code) = Self::ensure_help_or_version(args, &mode, streams) {
            return Leave(exit_code);
        };
        if let ExitCode(1) = self.verify_privilege_level(privilege_required, &mode, streams) {
            return Leave(1);
        };
        Enter(mode)
    }

    fn process_gathered_errors(error: ConfiguratorError, streams: &mut StdStreams) {
        writeln!(streams.stderr, "Configuration error").expect("writeln failed");
        Self::produce_unified_err_msgs(streams, error.param_errors)
    }

    fn ensure_help_or_version(
        args: &[String],
        mode: &Mode,
        streams: &mut StdStreams<'_>,
    ) -> Leaving {
        let is_help_or_version = match Self::is_help_or_version(args) {
            false => return Not,
            true => mode,
        };
        let command = match is_help_or_version {
            Mode::DumpConfig => app_config_dumper(),
            Mode::Initialization => app_daemon(),
            Mode::Service => app_node(),
        };
        match command.try_get_matches_from(args) {
            Err(e) => Self::clap_error_to_likely_contain_help_or_version(e, streams),
            x => unreachable!("sieve for 'help' or 'version' has flaws: {:?}", x),
        }
    }

    fn clap_error_to_likely_contain_help_or_version(
        clap_error: Error,
        streams: &mut StdStreams<'_>,
    ) -> Leaving {
        match clap_error {
            err if err.kind() == clap::error::ErrorKind::DisplayHelp
                || err.kind() == clap::error::ErrorKind::DisplayVersion =>
            {
                writeln!(streams.stdout, "{:?}", err).expect("writeln failed");
                ExitCode(0)
            }
            err => {
                Self::produce_unified_err_msgs(
                    streams,
                    MultiConfig::make_configurator_error(err).param_errors,
                );
                ExitCode(1)
            }
        }
    }

    fn verify_privilege_level(
        &self,
        privilege_required: bool,
        mode: &Mode,
        streams: &mut StdStreams,
    ) -> Leaving {
        match (
            self.privilege_dropper.expect_privilege(privilege_required),
            privilege_required,
        ) {
            (true, _) => Not,
            (false, fatal) => {
                Self::produce_privilege_mismatch_message(mode, privilege_required, streams);
                if fatal {
                    ExitCode(1)
                } else {
                    ExitCode(0)
                }
            }
        }
    }

    fn produce_privilege_mismatch_message(
        mode: &Mode,
        privilege_required: bool,
        streams: &mut StdStreams,
    ) {
        writeln!(
            streams.stderr,
            "{}",
            Self::privilege_mismatch_message(mode, privilege_required)
        )
        .expect("writeln failed")
    }

    fn is_help_or_version(args: &[String]) -> bool {
        ["--help", "--version", "-h", "-V"]
            .iter()
            .any(|searched| args.contains(&searched.to_string()))
    }

    fn produce_unified_err_msgs(streams: &mut StdStreams, error: Vec<ParamError>) {
        error.into_iter().for_each(|err_case| {
            writeln!(
                streams.stderr,
                "{} - {}",
                err_case.parameter, err_case.reason
            )
            .expect("writeln failed")
        })
    }

    #[cfg(not(target_os = "windows"))]
    fn privilege_mismatch_message(mode: &Mode, need_but_dont_have: bool) -> String {
        let (requirement, recommendation) = if need_but_dont_have {
            ("must run with", "sudo")
        } else {
            ("does not require", "without sudo next time")
        };
        format!(
            "MASQNode in {:?} mode {} root privilege; try {}",
            mode, requirement, recommendation
        )
    }

    #[cfg(target_os = "windows")]
    fn privilege_mismatch_message(mode: &Mode, need_but_dont_have: bool) -> String {
        let suffix = if need_but_dont_have {
            "must run as Administrator."
        } else {
            "does not require Administrator privilege."
        };
        format!("MASQNode.exe in {:?} mode {}", mode, suffix)
    }

    fn determine_mode_and_priv_req(&self, args: &[String]) -> (Mode, bool) {
        if args.contains(&"--dump-config".to_string()) {
            (Mode::DumpConfig, false)
        } else if args.contains(&"--initialization".to_string()) {
            (Mode::Initialization, true)
        } else {
            (Mode::Service, true)
        }
    }
}

pub enum ProgramEntering {
    Enter(Mode),
    Leave(i32),
}

enum Leaving {
    Not,
    ExitCode(i32),
}

#[derive(Debug, PartialEq, Eq)]
pub enum RunnerError {
    Configurator(ConfiguratorError),
    Numeric(i32),
}

trait Runner {
    fn run_node(&self, args: &[String], streams: &mut StdStreams<'_>) -> Result<(), RunnerError>;
    fn dump_config(&self, args: &[String], streams: &mut StdStreams<'_>)
        -> Result<(), RunnerError>;
    fn run_daemon(&self, args: &[String], streams: &mut StdStreams<'_>) -> Result<(), RunnerError>;
}

struct RunnerReal {
    dump_config_runner_factory: Box<dyn DumpConfigRunnerFactory>,
    server_initializer_factory: Box<dyn ServerInitializerFactory>,
    daemon_initializer_factory: Box<dyn DaemonInitializerFactory>,
}

impl Runner for RunnerReal {
    fn run_node(&self, args: &[String], streams: &mut StdStreams<'_>) -> Result<(), RunnerError> {
        let system = System::new();
        let mut server_initializer = self.server_initializer_factory.make();
        let args_inner = args.to_vec();
        // TODO Bert thinks the task::spawn() is overkill; wants system.block_on() instead
        let join_handle: JoinHandle<Result<(), String>> = task::spawn(async move {
            match server_initializer.go(streams, &args_inner).await {
                Ok(_) => (),
                Err(e) => {
                    System::current().stop_with_code(1);
                    return Err(format!("{:?}", e));
                }
            }
            let result = server_initializer.spawn_long_lived_services().await;
            match result {
                Ok(x) => panic!(
                    "DNS server was never supposed to stop, but terminated with {:?}",
                    x
                ),
                Err(e) => {
                    System::current().stop_with_code(1);
                    return Err(format!("{:?}", e));
                }
            }
        });
        match system.run() {
            Ok(()) => Ok(()),
            Err(e) => {
                let result = make_rt().block_on(join_handle);
                let logger = Logger::new("RunnerReal");
                /// TODO SPIKE
                match result {
                    Ok(Ok(_)) => error!(logger, "Node terminated with error: {:?}", e),
                    Ok(Err(e)) => error!(logger, "Node terminated with error, but we couldn't get the error message: {:?}", e),
                    Err(e) => error!(logger, "Node terminated with error, but we couldn't look for the error message: {:?}", e),
                }
                /// TODO SPIKE
                Err(RunnerError::Numeric(1))
            }
        }
    }

    fn dump_config(
        &self,
        args: &[String],
        streams: &mut StdStreams<'_>,
    ) -> Result<(), RunnerError> {
        self.dump_config_runner_factory
            .make()
            .go(streams, args)
            .map_err(RunnerError::Configurator)
    }

    fn run_daemon(&self, args: &[String], streams: &mut StdStreams<'_>) -> Result<(), RunnerError> {
        let mut initializer = self.daemon_initializer_factory.make(args)?;
        initializer.go(streams, args)?;
        Ok(()) //there might presently be no way to make this fn terminate politely, it blocks at the previous line until somebody kills the process
    }
}

impl RunnerReal {
    pub fn new() -> Self {
        Self {
            dump_config_runner_factory: Box::new(DumpConfigRunnerFactoryReal),
            server_initializer_factory: Box::new(ServerInitializerFactoryReal),
            daemon_initializer_factory: Box::new(DaemonInitializerFactoryReal::default()),
        }
    }
}

impl From<ConfiguratorError> for RunnerError {
    fn from(error: ConfiguratorError) -> Self {
        RunnerError::Configurator(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::run_modes_factories::mocks::{
        DaemonInitializerFactoryMock, DaemonInitializerMock, DumpConfigRunnerFactoryMock,
        DumpConfigRunnerMock, ServerInitializerFactoryMock, ServerInitializerMock,
    };
    use crate::server_initializer::test_utils::PrivilegeDropperMock;
    use masq_lib::test_utils::fake_stream_holder::FakeStreamHolder;
    use masq_lib::utils::slice_of_strs_to_vec_of_strings;
    use regex::Regex;
    use std::cell::RefCell;
    use std::io;
    use std::io::ErrorKind;
    use std::ops::{Deref, Not};
    use std::sync::{Arc, Mutex};
    use time::OffsetDateTime;
    use tokio::spawn;
    use tokio::task::JoinSet;

    pub struct RunnerMock {
        run_node_params: Arc<Mutex<Vec<Vec<String>>>>,
        run_node_results: RefCell<Vec<Result<(), RunnerError>>>,
        dump_config_params: Arc<Mutex<Vec<Vec<String>>>>,
        dump_config_results: RefCell<Vec<Result<(), RunnerError>>>,
        run_daemon_params: Arc<Mutex<Vec<Vec<String>>>>,
        run_daemon_results: RefCell<Vec<Result<(), RunnerError>>>,
    }

    impl Runner for RunnerMock {
        fn run_node(
            &self,
            args: &[String],
            _streams: &mut StdStreams<'_>,
        ) -> Result<(), RunnerError> {
            self.run_node_params.lock().unwrap().push(args.to_vec());
            self.run_node_results.borrow_mut().remove(0)
        }

        fn dump_config(
            &self,
            args: &[String],
            _streams: &mut StdStreams<'_>,
        ) -> Result<(), RunnerError> {
            self.dump_config_params.lock().unwrap().push(args.to_vec());
            self.dump_config_results.borrow_mut().remove(0)
        }

        fn run_daemon(
            &self,
            args: &[String],
            _streams: &mut StdStreams<'_>,
        ) -> Result<(), RunnerError> {
            self.run_daemon_params.lock().unwrap().push(args.to_vec());
            self.run_daemon_results.borrow_mut().remove(0)
        }
    }

    #[allow(dead_code)]
    impl RunnerMock {
        pub fn new() -> Self {
            Self {
                run_node_params: Arc::new(Mutex::new(vec![])),
                run_node_results: RefCell::new(vec![]),
                dump_config_params: Arc::new(Mutex::new(vec![])),
                dump_config_results: RefCell::new(vec![]),
                run_daemon_params: Arc::new(Mutex::new(vec![])),
                run_daemon_results: RefCell::new(vec![]),
            }
        }

        pub fn run_node_params(mut self, params: &Arc<Mutex<Vec<Vec<String>>>>) -> Self {
            self.run_node_params = params.clone();
            self
        }

        pub fn run_node_result(self, result: Result<(), RunnerError>) -> Self {
            self.run_node_results.borrow_mut().push(result);
            self
        }

        pub fn dump_config_params(mut self, params: &Arc<Mutex<Vec<Vec<String>>>>) -> Self {
            self.dump_config_params = params.clone();
            self
        }

        pub fn dump_config_result(self, result: Result<(), RunnerError>) -> Self {
            self.dump_config_results.borrow_mut().push(result);
            self
        }

        pub fn run_daemon_params(mut self, params: &Arc<Mutex<Vec<Vec<String>>>>) -> Self {
            self.run_daemon_params = params.clone();
            self
        }

        pub fn run_daemon_result(self, result: Result<(), RunnerError>) -> Self {
            self.run_daemon_results.borrow_mut().push(result);
            self
        }
    }

    #[test]
    fn dump_config() {
        let arg = vec!["--dump-config".to_string()];
        check_mode(arg, Mode::DumpConfig, false);
    }

    #[test]
    fn initialization() {
        let arg = vec!["--initialization".to_string()];
        check_mode(arg, Mode::Initialization, true);
    }

    #[test]
    fn everything_beats_initialization() {
        check_mode(
            slice_of_strs_to_vec_of_strings(&["--initialization", "--dump-config"]),
            Mode::DumpConfig,
            false,
        );
        check_mode(
            slice_of_strs_to_vec_of_strings(&["--dump-config", "--initialization"]),
            Mode::DumpConfig,
            false,
        );
    }

    #[test]
    fn dump_config_rules_all() {
        let args = slice_of_strs_to_vec_of_strings(&[
            "--booga",
            "--goober",
            "--initialization",
            "--dump-config",
        ]);
        check_mode(args, Mode::DumpConfig, false);
    }

    #[test]
    fn run_servers() {
        check_mode(vec![], Mode::Service, true)
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn privilege_mismatch_messages() {
        let service_yes = RunModes::privilege_mismatch_message(&Mode::Service, true);
        let dump_config_no = RunModes::privilege_mismatch_message(&Mode::DumpConfig, false);
        let initialization_yes = RunModes::privilege_mismatch_message(&Mode::Initialization, true);

        assert_eq!(
            service_yes,
            "MASQNode in Service mode must run with root privilege; try sudo"
        );
        assert_eq!(dump_config_no, "MASQNode in DumpConfig mode does not require root privilege; try without sudo next time");
        assert_eq!(
            initialization_yes,
            "MASQNode in Initialization mode must run with root privilege; try sudo"
        )
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn privilege_mismatch_messages() {
        let node_yes = RunModes::privilege_mismatch_message(&Mode::Service, true);
        let dump_config_no = RunModes::privilege_mismatch_message(&Mode::DumpConfig, false);
        let initialization_yes = RunModes::privilege_mismatch_message(&Mode::Initialization, true);

        assert_eq!(
            node_yes,
            "MASQNode.exe in Service mode must run as Administrator."
        );
        assert_eq!(
            dump_config_no,
            "MASQNode.exe in DumpConfig mode does not require Administrator privilege."
        );
        assert_eq!(
            initialization_yes,
            "MASQNode.exe in Initialization mode must run as Administrator."
        );
    }

    #[test]
    fn go_accepts_requireds_errors_and_renders_them() {
        let mut subject = RunModes::new();
        subject.runner = Box::new(RunnerMock::new().dump_config_result(Err(
            RunnerError::Configurator(
                ConfiguratorError::required("parm1", "msg1").another_required("parm2", "msg2"),
            ),
        )));
        subject.privilege_dropper =
            Box::new(PrivilegeDropperMock::new().expect_privilege_result(true));
        let mut holder = FakeStreamHolder::new();

        let result = subject.go(&["--dump-config".to_string()], &mut holder.streams());

        assert_eq!(result, 1);
        assert_eq!(
            &holder.stderr.get_string(),
            "Configuration error\n\
parm1 - msg1\n\
parm2 - msg2\n"
        )
    }

    #[test]
    fn run_node_hands_in_an_error_from_go() {
        let go_params_arc = Arc::new(Mutex::new(vec![]));
        let mut subject = RunModes::new();
        let mut runner = RunnerReal::new();
        runner.server_initializer_factory = Box::new(
            ServerInitializerFactoryMock::default().make_result(Box::new(
                ServerInitializerMock::default()
                    .go_result(Err(ConfiguratorError::required(
                        "some-parameter",
                        "too-low-value",
                    )))
                    .go_params(&go_params_arc),
            )),
        );
        subject.runner = Box::new(runner);
        let mut holder = FakeStreamHolder::new();
        let args = &slice_of_strs_to_vec_of_strings(&["program", "param", "--arg"]);

        let result = subject.runner.run_node(&args, &mut holder.streams());

        let configurator_error = if let RunnerError::Configurator(c_e) = result.unwrap_err() {
            c_e
        } else {
            panic!("expected ConfiguratorError")
        };
        assert_eq!(
            configurator_error.param_errors[0],
            ParamError {
                parameter: "some-parameter".to_string(),
                reason: "too-low-value".to_string()
            }
        );
        assert_eq!(&holder.stdout.get_string(), "");
        assert_eq!(&holder.stderr.get_string(), "");
        let go_params = go_params_arc.lock().unwrap();
        assert_eq!(go_params.deref().len(), 1);
        assert_eq!(&go_params[0], args)
    }

    #[test]
    fn run_node_hands_in_an_error_from_polling_on_its_future() {
        let go_params_arc = Arc::new(Mutex::new(vec![]));
        let mut subject = RunModes::new();
        let mut runner = RunnerReal::new();
        let join_handle = spawn(async { Err(io::Error::from(ErrorKind::BrokenPipe)) });
        runner.server_initializer_factory = Box::new(
            ServerInitializerFactoryMock::default().make_result(Box::new(
                ServerInitializerMock::default()
                    .go_result(Ok(()))
                    .go_params(&go_params_arc)
                    .spawn_long_lived_services_result(join_handle),
            )),
        );
        subject.runner = Box::new(runner);
        let mut holder = FakeStreamHolder::new();
        let args = slice_of_strs_to_vec_of_strings(&["program", "param", "param", "--arg"]);

        let result = subject
            .runner
            .run_node(args.as_slice(), &mut holder.streams());

        assert_eq!(result, Err(RunnerError::Numeric(1)));
        assert_eq!(&holder.stdout.get_string(), "");
        assert_eq!(&holder.stderr.get_string(), "");
        let go_params = go_params_arc.lock().unwrap();
        assert_eq!(go_params.deref().len(), 1);
        assert_eq!(go_params[0], args)
    }

    #[test]
    fn run_daemon_hands_in_an_error_from_creating_the_multi_config() {
        let make_params_arc = Arc::new(Mutex::new(vec![]));
        let mut subject = RunModes::new();
        let mut runner = RunnerReal::new();
        runner.daemon_initializer_factory = Box::new(
            DaemonInitializerFactoryMock::default()
                .make_params(&make_params_arc)
                .make_result(Err(ConfiguratorError::required(
                    "<unknown>",
                    "Unfamiliar message: error: Found argument \'--halabala\'",
                ))),
        );
        subject.runner = Box::new(runner);
        let mut holder = FakeStreamHolder::new();
        let args = slice_of_strs_to_vec_of_strings(&["program", "--initialization", "--halabala"]);

        let result = subject.runner.run_daemon(&args, &mut holder.streams());

        assert_eq!(&holder.stdout.get_string(), "");
        assert_eq!(&holder.stderr.get_string(), "");
        let mut make_params = make_params_arc.lock().unwrap();
        assert_eq!(make_params.remove(0), *args);
        assert_eq!(
            result,
            Err(RunnerError::Configurator(ConfiguratorError::new(vec![
                ParamError {
                    parameter: "<unknown>".to_string(),
                    reason: "Unfamiliar message: error: Found argument \'--halabala\'".to_string()
                }
            ])))
        )
    }

    #[test]
    fn run_daemon_hands_in_an_error_from_go() {
        let go_params_arc = Arc::new(Mutex::new(vec![]));
        let mut subject = RunModes::new();
        let mut runner = RunnerReal::new();
        runner.daemon_initializer_factory = Box::new(
            DaemonInitializerFactoryMock::default().make_result(Ok(Box::new(
                DaemonInitializerMock::default()
                    .go_params(&go_params_arc)
                    .go_results(Err(ConfiguratorError::required("parameter", "too-bad"))),
            ))),
        );
        subject.runner = Box::new(runner);
        let mut holder = FakeStreamHolder::new();
        let args =
            slice_of_strs_to_vec_of_strings(&["program", "--initialization", "--ui-port", "52452"]);

        let result = subject.runner.run_daemon(&args, &mut holder.streams());

        assert_eq!(&holder.stdout.get_string(), "");
        assert_eq!(&holder.stderr.get_string(), "");
        let mut go_params = go_params_arc.lock().unwrap();
        assert_eq!(go_params.remove(0), *args);
        assert_eq!(
            result,
            Err(RunnerError::Configurator(ConfiguratorError::new(vec![
                ParamError {
                    parameter: "parameter".to_string(),
                    reason: "too-bad".to_string()
                }
            ])))
        )
    }

    #[test]
    fn dump_config_hands_in_an_error_from_dump_config() {
        let dump_config_params_arc = Arc::new(Mutex::new(vec![]));
        let mut subject = RunModes::new();
        let mut runner = RunnerReal::new();
        runner.dump_config_runner_factory = Box::new(
            DumpConfigRunnerFactoryMock::default().make_result(Box::new(
                DumpConfigRunnerMock::default()
                    .dump_config_result(Err(ConfiguratorError::required(
                        "parameter",
                        "deep-reason",
                    )))
                    .dump_config_params(&dump_config_params_arc),
            )),
        );
        subject.runner = Box::new(runner);
        let mut holder = FakeStreamHolder::new();
        let args = slice_of_strs_to_vec_of_strings(&["program", "param", "--arg"]);

        let result = subject.runner.dump_config(&args, &mut holder.streams());

        let configurator_error = if let RunnerError::Configurator(c_e) = result.unwrap_err() {
            c_e
        } else {
            panic!("expected ConfiguratorError")
        };
        assert_eq!(
            configurator_error.param_errors[0],
            ParamError {
                parameter: "parameter".to_string(),
                reason: "deep-reason".to_string()
            }
        );
        assert_eq!(&holder.stdout.get_string(), "");
        assert_eq!(&holder.stderr.get_string(), "");
        let dump_config_params = dump_config_params_arc.lock().unwrap();
        assert_eq!(dump_config_params.deref().len(), 1);
        assert_eq!(*dump_config_params[0], args)
    }

    #[test]
    fn daemon_and_node_modes_complain_without_privilege() {
        let mut subject = RunModes::new();
        subject.runner = Box::new(RunnerMock::new()); // No prepared results: any calls to this will cause panics
        let params_arc = Arc::new(Mutex::new(vec![]));
        let privilege_dropper = PrivilegeDropperMock::new()
            .expect_privilege_params(&params_arc)
            .expect_privilege_result(false)
            .expect_privilege_result(false);
        subject.privilege_dropper = Box::new(privilege_dropper);
        let mut daemon_stream_holder = FakeStreamHolder::new();
        let mut node_stream_holder = FakeStreamHolder::new();

        let initialization_exit_code = subject.go(
            &["--initialization".to_string()],
            &mut daemon_stream_holder.streams(),
        );
        let service_mode_exit_code = subject.go(&[], &mut node_stream_holder.streams());

        assert_eq!(initialization_exit_code, 1);
        assert_eq!(daemon_stream_holder.stdout.get_string(), "");
        let mut p_m_msg_daemon = RunModes::privilege_mismatch_message(&Mode::Initialization, true);
        p_m_msg_daemon.push_str("\n");
        assert_eq!(daemon_stream_holder.stderr.get_string(), p_m_msg_daemon);
        assert_eq!(service_mode_exit_code, 1);
        assert_eq!(node_stream_holder.stdout.get_string(), "");
        let mut p_m_msg_node = RunModes::privilege_mismatch_message(&Mode::Service, true);
        p_m_msg_node.push_str("\n");
        assert_eq!(node_stream_holder.stderr.get_string(), p_m_msg_node);
        let params = params_arc.lock().unwrap();
        assert_eq!(*params, vec![true, true])
    }

    #[test]
    fn is_help_or_version_works() {
        vec![
            slice_of_strs_to_vec_of_strings(&["whatever", "--help", "something"]),
            slice_of_strs_to_vec_of_strings(&["whatever", "--version", "something"]),
            slice_of_strs_to_vec_of_strings(&["whatever", "-V", "something"]),
            slice_of_strs_to_vec_of_strings(&["whatever", "-h", "something"]),
        ]
        .into_iter()
        .for_each(|args| assert!(RunModes::is_help_or_version(&args)))
    }

    #[test]
    fn is_help_or_version_lets_you_in_if_no_specific_arguments() {
        vec![
            slice_of_strs_to_vec_of_strings(&["whatever", "something"]).as_slice(),
            &["drowned--help".to_string()],
            &["drowned--version".to_string()],
            &["drowned-Vin a juice".to_string()],
            &["drowned-hin a coke".to_string()],
        ]
        .into_iter()
        .for_each(|args| assert!(RunModes::is_help_or_version(args).not()))
    }

    #[test]
    fn daemon_and_node_modes_help_call() {
        let subject = RunModes::new();
        let mut daemon_h_holder = FakeStreamHolder::new();
        let mut node_h_holder = FakeStreamHolder::new();

        let daemon_h_exit_code = subject.go(
            &slice_of_strs_to_vec_of_strings(&["program", "--initialization", "--help"]),
            &mut daemon_h_holder.streams(),
        );

        let node_h_exit_code = subject.go(
            &["program".to_string(), "--help".to_string()],
            &mut node_h_holder.streams(),
        );

        assert_eq!(daemon_h_exit_code, 0);
        let daemon_stdout_message = daemon_h_holder.stdout.get_string();
        assert!(daemon_stdout_message.contains("MASQ\nMASQ Node is the foundation of MASQ Network, an open-source network that allows anyone to"));
        assert!(daemon_stdout_message.contains("--initialization    Directs"));
        assert_eq!(daemon_h_holder.stderr.get_string(), "");
        assert_eq!(node_h_exit_code, 0);
        let node_stdout_message = node_h_holder.stdout.get_string();
        assert!(node_stdout_message
            .contains("to allocate spare computing\nresources to make the internet a free"));
        assert!(node_stdout_message.contains("--clandestine-port <CLANDESTINE-PORT>\n"));
        assert_eq!(node_h_holder.stderr.get_string(), "");
    }

    //TODO fix the functionality by upgrading Clap;
    // it should be the card GH-460
    // or eventually transform this into an integration test
    // TODO: Don't forget to investigate this
    #[ignore]
    #[test]
    fn daemon_and_node_modes_version_call() {
        use time::macros::datetime;
        //this line here makes us aware that this issue is still unresolved; you may want to set this date more forward if we still cannot answer this
        if OffsetDateTime::now_utc().date() >= datetime!(2022-03-31 0:00 UTC).date() {
            let subject = RunModes::new();
            let mut daemon_v_holder = FakeStreamHolder::new();
            let mut node_v_holder = FakeStreamHolder::new();

            let daemon_v_exit_code = subject.go(
                &[
                    "program".to_string(),
                    "--initialization".to_string(),
                    "--version".to_string(),
                ],
                &mut daemon_v_holder.streams(),
            );

            let node_v_exit_code = subject.go(
                &["program".to_string(), "--version".to_string()],
                &mut node_v_holder.streams(),
            );

            assert_eq!(daemon_v_exit_code, 0);
            let regex = Regex::new(r"MASQ Node \d+\.\d+\.\d+\n").unwrap();
            let daemon_stdout_message = daemon_v_holder.stdout.get_string();
            assert!(
                regex.is_match(&daemon_stdout_message),
                "Should see the version of the Daemon printed to stdout, but got this: {}",
                daemon_stdout_message
            );
            assert_eq!(daemon_v_holder.stderr.get_string(), "");

            assert_eq!(node_v_exit_code, 0);
            let node_stdout_message = node_v_holder.stdout.get_string();
            assert!(
                regex.is_match(&node_stdout_message),
                "Should see the version of the Node printed to stdout, but got this: {}",
                node_stdout_message
            );
            assert_eq!(node_v_holder.stderr.get_string(), "");
        }
    }

    #[test]
    fn a_help_call_together_with_false_and_badly_written_parameters_simply_results_in_terminating_of_the_app(
    ) {
        let subject = RunModes::new();
        let mut stream_holder = FakeStreamHolder::new();

        let daemon_exit_code = subject.go(
            &slice_of_strs_to_vec_of_strings(&["program", "--initiabababa", "--help"]),
            &mut stream_holder.streams(),
        );

        assert_eq!(daemon_exit_code, 1);
        assert!(stream_holder
            .stderr
            .get_string()
            .contains("Unfamiliar message: error: Found argument '--initiabababa'"))
    }

    #[test]
    fn modes_other_than_daemon_and_node_mention_privilege_but_do_not_abort() {
        let mut subject = RunModes::new();
        let runner_params_arc = Arc::new(Mutex::new(vec![]));
        let runner = RunnerMock::new()
            .dump_config_params(&runner_params_arc)
            .dump_config_result(Ok(()));
        subject.runner = Box::new(runner);
        let dropper_params_arc = Arc::new(Mutex::new(vec![]));
        let privilege_dropper = PrivilegeDropperMock::new()
            .expect_privilege_params(&dropper_params_arc)
            .expect_privilege_result(false);
        subject.privilege_dropper = Box::new(privilege_dropper);
        let mut dump_config_holder = FakeStreamHolder::new();

        let dump_config_exit_code = subject.go(
            &["--dump-config".to_string()],
            &mut dump_config_holder.streams(),
        );

        assert_eq!(dump_config_exit_code, 0);
        assert_eq!(dump_config_holder.stdout.get_string(), "");
        let mut p_m_message = RunModes::privilege_mismatch_message(&Mode::DumpConfig, false);
        p_m_message.push_str("\n");
        assert_eq!(dump_config_holder.stderr.get_string(), p_m_message);
        let params = dropper_params_arc.lock().unwrap();
        assert_eq!(*params, vec![false]);
        let params = runner_params_arc.lock().unwrap();
        assert_eq!(*params, vec![vec!["--dump-config"]])
    }

    fn check_mode(args: Vec<String>, expected_mode: Mode, privilege_required: bool) {
        let mut augmented_args = vec!["--unrelated".to_string()];
        augmented_args.extend(args);
        augmented_args.push("--unrelated".to_string());
        let subject = RunModes::new();

        let (actual_mode, actual_privilege_required) =
            subject.determine_mode_and_priv_req(&augmented_args);

        assert_eq!(actual_mode, expected_mode, "args: {:?}", augmented_args);
        assert_eq!(
            actual_privilege_required, privilege_required,
            "args: {:?}",
            augmented_args
        );
    }
}
