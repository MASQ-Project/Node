// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

use crate::apps::{app_config_dumper, app_daemon, app_node};
use crate::privilege_drop::{PrivilegeDropper, PrivilegeDropperReal};
use crate::run_modes_factories::{
    DaemonInitializerFactory, DaemonInitializerFactoryReal, DumpConfigRunnerFactory,
    DumpConfigRunnerFactoryReal, ServerInitializerFactory, ServerInitializerFactoryReal,
};
use actix::System;
use clap::Error;
use futures::future::Future;
use masq_lib::command::StdStreams;
use masq_lib::multi_config::MultiConfig;
use masq_lib::shared_schema::{ConfiguratorError, ParamError};
use EnterProgram::{Enter, LeaveRight, LeaveWrong};

#[derive(Debug, PartialEq)]
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
        let (mode, privilege_required) = self.determine_mode_and_priv_req(args);
        match Self::ensure_help_or_version(args, &mode, streams) {
            Enter => (),
            LeaveRight => return 0,
            LeaveWrong => return 1,
        };

        if let LeaveWrong = self.verify_privilege_level(privilege_required, &mode, streams) {
            return 1;
        }

        match match mode {
            Mode::DumpConfig => self.runner.dump_config(args, streams),
            Mode::Initialization => self.runner.run_daemon(args, streams),
            Mode::Service => self.runner.run_node(args, streams),
        } {
            Ok(_) => 0,
            Err(RunnerError::Numeric(e_num)) => e_num,
            Err(RunnerError::Configurator(conf_e)) => {
                Self::configurator_err_final_processing(conf_e, streams);
                1
            }
        }
    }

    fn configurator_err_final_processing(error: ConfiguratorError, streams: &mut StdStreams) {
        short_writeln!(streams.stderr, "Configuration error");
        Self::write_unified_err_msgs(streams, error.param_errors)
    }

    fn ensure_help_or_version(
        args: &[String],
        mode: &Mode,
        streams: &mut StdStreams<'_>,
    ) -> EnterProgram {
        match match match Self::is_help_or_version(args) {
            false => return Enter,
            true => mode,
        } {
            Mode::DumpConfig => app_config_dumper(),
            Mode::Initialization => app_daemon(),
            Mode::Service => app_node(),
        }
        .get_matches_from_safe(args)
        {
            Err(e) => Self::process_clap_error_that_may_contain_help_or_version(e, streams),
            x => unreachable!("the sieve for 'help' or 'version' failed {:?}", x),
        }
    }

    fn process_clap_error_that_may_contain_help_or_version(
        clap_error: Error,
        streams: &mut StdStreams<'_>,
    ) -> EnterProgram {
        match clap_error {
            err if err.kind == clap::ErrorKind::HelpDisplayed
                || err.kind == clap::ErrorKind::VersionDisplayed =>
            {
                short_writeln!(streams.stdout, "{}", err.message);
                LeaveRight
            }
            err => {
                Self::write_unified_err_msgs(
                    streams,
                    MultiConfig::make_configurator_error(err).param_errors,
                );
                LeaveWrong
            }
        }
    }

    fn verify_privilege_level(
        &self,
        privilege_required: bool,
        mode: &Mode,
        streams: &mut StdStreams,
    ) -> EnterProgram {
        match (
            self.privilege_dropper.expect_privilege(privilege_required),
            privilege_required,
        ) {
            (true, _) => Enter,
            (false, fatal) => {
                Self::write_msg_about_privilege_mismatch(mode, privilege_required, streams);
                if fatal {
                    LeaveWrong
                } else {
                    Enter
                }
            }
        }
    }

    fn write_msg_about_privilege_mismatch(
        mode: &Mode,
        privilege_required: bool,
        streams: &mut StdStreams,
    ) {
        short_writeln!(
            streams.stderr,
            "{}",
            Self::privilege_mismatch_message(mode, privilege_required)
        )
    }

    fn is_help_or_version(args: &[String]) -> bool {
        ["--help", "--version", "-h", "-V"]
            .iter()
            .any(|searched| args.contains(&searched.to_string()))
    }

    fn write_unified_err_msgs(streams: &mut StdStreams, error: Vec<ParamError>) {
        error.into_iter().for_each(|err_case| {
            short_writeln!(
                streams.stderr,
                "{} - {}",
                err_case.parameter,
                err_case.reason
            )
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

enum EnterProgram {
    Enter,
    LeaveRight,
    LeaveWrong,
}

#[derive(Debug, PartialEq)]
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
        let system = System::new("main");
        let mut server_initializer = self.server_initializer_factory.make();
        server_initializer.go(streams, args)?;
        actix::spawn(server_initializer.map_err(|_| {
            System::current().stop_with_code(1);
        }));
        match system.run() {
            0 => Ok(()),
            num_e => Err(RunnerError::Numeric(num_e)),
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
        Ok(()) //there might presently be no way to make this fn terminate politely
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
    use masq_lib::utils::SliceToVec;
    use regex::Regex;
    use std::cell::RefCell;
    use std::ops::{Deref, Not};
    use std::sync::{Arc, Mutex};

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
            ["--initialization", "--dump-config"].array_of_borrows_to_vec(),
            Mode::DumpConfig,
            false,
        );
        check_mode(
            ["--dump-config", "--initialization"].array_of_borrows_to_vec(),
            Mode::DumpConfig,
            false,
        );
    }

    #[test]
    fn dump_config_rules_all() {
        let args =
            ["--booga", "--goober", "--initialization", "--dump-config"].array_of_borrows_to_vec();
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
        let args = (&["program", "param", "--arg"]).array_of_borrows_to_vec();

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
        assert_eq!(go_params[0], args)
    }

    #[test]
    fn run_node_hands_in_an_error_from_polling_on_its_future() {
        let go_params_arc = Arc::new(Mutex::new(vec![]));
        let mut subject = RunModes::new();
        let mut runner = RunnerReal::new();
        runner.server_initializer_factory = Box::new(
            ServerInitializerFactoryMock::default().make_result(Box::new(
                ServerInitializerMock::default()
                    .go_result(Ok(()))
                    .go_params(&go_params_arc)
                    .poll_result(Err(())),
            )),
        );
        subject.runner = Box::new(runner);
        let mut holder = FakeStreamHolder::new();
        let args = ["program", "param", "param", "--arg"].array_of_borrows_to_vec();

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
        let args = ["program", "--initialization", "--halabala"].array_of_borrows_to_vec();

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
        let args = ["program", "--initialization", "--ui-port", "52452"].array_of_borrows_to_vec();

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
        let args = ["program", "param", "--arg"].array_of_borrows_to_vec();

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
            ["whatever", "--help", "something"].array_of_borrows_to_vec(),
            ["whatever", "--version", "something"].array_of_borrows_to_vec(),
            ["whatever", "-V", "something"].array_of_borrows_to_vec(),
            ["whatever", "-h", "something"].array_of_borrows_to_vec(),
        ]
        .into_iter()
        .for_each(|args| assert!(RunModes::is_help_or_version(&args)))
    }

    #[test]
    fn is_help_or_version_lets_you_in_if_no_specific_arguments() {
        vec![
            ["whatever", "something"]
                .array_of_borrows_to_vec()
                .as_slice(),
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
            &["program", "--initialization", "--help"].array_of_borrows_to_vec(),
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
    #[test]
    fn daemon_and_node_modes_version_call() {
        use chrono::offset::Utc;
        use chrono::NaiveDate;
        //this line here makes us aware that this issue is still unresolved; you may want to set this date more forward if we still cannot answer this
        if Utc::today().and_hms(0, 0, 0).naive_utc().date() >= NaiveDate::from_ymd(2021, 10, 30) {
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
            &["program", "--initiabababa", "--help"].array_of_borrows_to_vec(),
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
