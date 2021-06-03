// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

use crate::daemon::daemon_initializer::{DaemonInitializer, RecipientsFactoryReal, RerunnerReal};
use crate::daemon::ChannelFactoryReal;
use crate::database::config_dumper;
use crate::node_configurator::node_configurator_initialization::NodeConfiguratorInitialization;
use crate::node_configurator::{NodeConfigurator, RealDirsWrapper};
use crate::privilege_drop::{PrivilegeDropper, PrivilegeDropperReal};
use crate::server_initializer::{LoggerInitializerWrapperReal, ServerInitializer};
use actix::System;
use futures::future::Future;
use masq_lib::command::{CommandConfigError, StdStreams};
use masq_lib::shared_schema::ConfiguratorError;

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
        let privilege_as_expected = self.privilege_dropper.expect_privilege(privilege_required);
        let help_or_version = Self::args_contain_help_or_version(args);
        if !help_or_version && !privilege_as_expected {
            write!(
                streams.stderr,
                "{}",
                Self::privilege_mismatch_message(&mode, privilege_required)
            )
            .expect("write! failed");
            if privilege_required && !help_or_version {
                return 1;
            }
        }
        match match mode {
            Mode::DumpConfig => self.runner.dump_config(args, streams),
            Mode::Initialization => self.runner.run_daemon(args, streams),
            Mode::Service => self.runner.run_node(args, streams),
        } {
            Ok(exit_code) => exit_code,
            Err(e) => {
                short_writeln!(streams.stderr, "Configuration error");
                e.param_errors.into_iter().for_each(|required| {
                    short_writeln!(
                        streams.stderr,
                        "{} - {}",
                        required.parameter,
                        required.reason
                    )
                });
                1
            }
        }
    }

    fn args_contain_help_or_version(args: &[String]) -> bool {
        args.contains(&"--help".to_string())
            || args.contains(&"-h".to_string())
            || args.contains(&"--version".to_string())
            || args.contains(&"-V".to_string())
    }

    #[cfg(not(target_os = "windows"))]
    fn privilege_mismatch_message(mode: &Mode, need_but_dont_have: bool) -> String {
        let (requirement, recommendation) = if need_but_dont_have {
            ("must run with", "sudo")
        } else {
            ("does not require", "without sudo next time")
        };
        format!(
            "MASQNode in {:?} mode {} root privilege; try {}\n",
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
        format!("MASQNode.exe in {:?} mode {}\n", mode, suffix)
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

trait Runner {
    fn run_node(
        &self,
        args: &[String],
        streams: &mut StdStreams<'_>,
    ) -> Result<i32, ConfiguratorError>;
    fn dump_config(
        &self,
        args: &[String],
        streams: &mut StdStreams<'_>,
    ) -> Result<i32, ConfiguratorError>;
    fn run_daemon(
        &self,
        args: &[String],
        streams: &mut StdStreams<'_>,
    ) -> Result<i32, ConfiguratorError>;
}

struct RunnerReal {}

impl Runner for RunnerReal {
    fn run_node(
        &self,
        args: &[String],
        streams: &mut StdStreams<'_>,
    ) -> Result<i32, ConfiguratorError> {
        let system = System::new("main");

        let mut server_initializer = ServerInitializer::new();
        server_initializer.go(streams, args)?;

        actix::spawn(server_initializer.map_err(|_| {
            System::current().stop_with_code(1);
        }));

        Ok(system.run())
    }

    fn dump_config(
        &self,
        args: &[String],
        streams: &mut StdStreams<'_>,
    ) -> Result<i32, ConfiguratorError> {
        config_dumper::dump_config(args, streams)
    }

    fn run_daemon(
        &self,
        args: &[String],
        streams: &mut StdStreams<'_>,
    ) -> Result<i32, ConfiguratorError> {
        let configurator = NodeConfiguratorInitialization {};
        let config = configurator.configure(args, streams)?;
        let mut initializer = DaemonInitializer::new(
            &RealDirsWrapper {},
            Box::new(LoggerInitializerWrapperReal {}),
            config,
            Box::new(ChannelFactoryReal::new()),
            Box::new(RecipientsFactoryReal::new()),
            Box::new(RerunnerReal::new()),
        );
        initializer.go(streams, args)?;
        Ok(1)
    }
}

impl RunnerReal {
    pub fn new() -> Self {
        Self {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server_initializer::test_utils::PrivilegeDropperMock;
    use masq_lib::test_utils::fake_stream_holder::FakeStreamHolder;
    use std::cell::RefCell;
    use std::sync::{Arc, Mutex};

    pub struct RunnerMock {
        run_node_params: Arc<Mutex<Vec<Vec<String>>>>,
        run_node_results: RefCell<Vec<Result<i32, ConfiguratorError>>>,
        dump_config_params: Arc<Mutex<Vec<Vec<String>>>>,
        dump_config_results: RefCell<Vec<Result<i32, ConfiguratorError>>>,
        run_daemon_params: Arc<Mutex<Vec<Vec<String>>>>,
        run_daemon_results: RefCell<Vec<Result<i32, ConfiguratorError>>>,
    }

    impl Runner for RunnerMock {
        fn run_node(
            &self,
            args: &[String],
            _streams: &mut StdStreams<'_>,
        ) -> Result<i32, ConfiguratorError> {
            self.run_node_params.lock().unwrap().push(args.to_vec());
            self.run_node_results.borrow_mut().remove(0)
        }

        fn dump_config(
            &self,
            args: &[String],
            _streams: &mut StdStreams<'_>,
        ) -> Result<i32, ConfiguratorError> {
            self.dump_config_params.lock().unwrap().push(args.to_vec());
            self.dump_config_results.borrow_mut().remove(0)
        }

        fn run_daemon(
            &self,
            args: &[String],
            _streams: &mut StdStreams<'_>,
        ) -> Result<i32, ConfiguratorError> {
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

        pub fn run_node_result(self, result: Result<i32, ConfiguratorError>) -> Self {
            self.run_node_results.borrow_mut().push(result);
            self
        }

        pub fn dump_config_params(mut self, params: &Arc<Mutex<Vec<Vec<String>>>>) -> Self {
            self.dump_config_params = params.clone();
            self
        }

        pub fn dump_config_result(self, result: Result<i32, ConfiguratorError>) -> Self {
            self.dump_config_results.borrow_mut().push(result);
            self
        }

        pub fn run_daemon_params(mut self, params: &Arc<Mutex<Vec<Vec<String>>>>) -> Self {
            self.run_daemon_params = params.clone();
            self
        }

        pub fn run_daemon_result(self, result: Result<i32, ConfiguratorError>) -> Self {
            self.run_daemon_results.borrow_mut().push(result);
            self
        }
    }

    #[test]
    fn dump_config() {
        [["--dump-config"]]
            .iter()
            .for_each(|args| check_mode(args, Mode::DumpConfig, false));
    }

    #[test]
    fn initialization() {
        [["--initialization"]]
            .iter()
            .for_each(|args| check_mode(args, Mode::Initialization, true));
    }

    #[test]
    fn everything_beats_initialization() {
        check_mode(
            &["--initialization", "--dump-config"],
            Mode::DumpConfig,
            false,
        );
        check_mode(
            &["--dump-config", "--initialization"],
            Mode::DumpConfig,
            false,
        );
    }

    #[test]
    fn dump_config_rules_all() {
        [["--booga", "--goober", "--initialization", "--dump-config"]]
            .iter()
            .for_each(|args| check_mode(args, Mode::DumpConfig, false));
    }

    #[test]
    fn run_servers() {
        check_mode(&[], Mode::Service, true)
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn privilege_mismatch_messages() {
        let service_yes = RunModes::privilege_mismatch_message(&Mode::Service, true);
        let dump_config_no = RunModes::privilege_mismatch_message(&Mode::DumpConfig, false);
        let initialization_yes = RunModes::privilege_mismatch_message(&Mode::Initialization, true);

        assert_eq!(
            service_yes,
            "MASQNode in Service mode must run with root privilege; try sudo\n"
        );
        assert_eq! (dump_config_no, "MASQNode in DumpConfig mode does not require root privilege; try without sudo next time\n");
        assert_eq!(
            initialization_yes,
            "MASQNode in Initialization mode must run with root privilege; try sudo\n"
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
            "MASQNode.exe in Service mode must run as Administrator.\n"
        );
        assert_eq!(
            dump_config_no,
            "MASQNode.exe in DumpConfig mode does not require Administrator privilege.\n"
        );
        assert_eq!(
            initialization_yes,
            "MASQNode.exe in Initialization mode must run with root privilege; try sudo\n"
        );
    }

    #[test]
    fn go_accepts_requireds_errors_and_renders_them() {
        let mut subject = RunModes::new();
        subject.runner = Box::new(RunnerMock::new().dump_config_result(Err(
            ConfiguratorError::required("parm1", "msg1").another_required("parm2", "msg2"),
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
        assert_eq!(
            daemon_stream_holder.stderr.get_string(),
            RunModes::privilege_mismatch_message(&Mode::Initialization, true)
        );
        assert_eq!(service_mode_exit_code, 1);
        assert_eq!(node_stream_holder.stdout.get_string(), "");
        assert_eq!(
            node_stream_holder.stderr.get_string(),
            RunModes::privilege_mismatch_message(&Mode::Service, true)
        );
        let params = params_arc.lock().unwrap();
        assert_eq!(*params, vec![true, true])
    }

    #[test]
    fn daemon_and_node_modes_do_not_complain_without_privilege_for_help_and_version() {
        let mut subject = RunModes::new();
        let run_params_arc = Arc::new(Mutex::new(vec![]));
        let runner = RunnerMock::new()
            .run_node_params(&run_params_arc)
            .run_node_result(Ok(0))
            .run_node_result(Ok(0))
            .run_daemon_params(&run_params_arc)
            .run_daemon_result(Ok(0))
            .run_daemon_result(Ok(0));
        subject.runner = Box::new(runner);
        let priv_params_arc = Arc::new(Mutex::new(vec![]));
        let privilege_dropper = PrivilegeDropperMock::new()
            .expect_privilege_params(&priv_params_arc)
            .expect_privilege_result(false)
            .expect_privilege_result(false)
            .expect_privilege_result(false)
            .expect_privilege_result(false);
        subject.privilege_dropper = Box::new(privilege_dropper);
        let mut daemon_h_holder = FakeStreamHolder::new();
        let mut daemon_v_holder = FakeStreamHolder::new();
        let mut node_h_holder = FakeStreamHolder::new();
        let mut node_v_holder = FakeStreamHolder::new();

        let daemon_h_exit_code = subject.go(
            &["--initialization".to_string(), "--help".to_string()],
            &mut daemon_h_holder.streams(),
        );
        let daemon_v_exit_code = subject.go(
            &["--initialization".to_string(), "--version".to_string()],
            &mut daemon_v_holder.streams(),
        );
        let node_h_exit_code = subject.go(&["--help".to_string()], &mut node_h_holder.streams());
        let node_v_exit_code = subject.go(&["--version".to_string()], &mut node_v_holder.streams());

        assert_eq!(daemon_h_exit_code, 0);
        assert_eq!(daemon_v_exit_code, 0);
        assert_eq!(daemon_h_holder.stdout.get_string(), "");
        assert_eq!(daemon_h_holder.stderr.get_string(), "");
        assert_eq!(daemon_v_holder.stdout.get_string(), "");
        assert_eq!(daemon_v_holder.stderr.get_string(), "");
        assert_eq!(node_h_exit_code, 0);
        assert_eq!(node_v_exit_code, 0);
        assert_eq!(node_h_holder.stdout.get_string(), "");
        assert_eq!(node_h_holder.stderr.get_string(), "");
        assert_eq!(node_v_holder.stdout.get_string(), "");
        assert_eq!(node_v_holder.stderr.get_string(), "");
        let params = priv_params_arc.lock().unwrap();
        assert_eq!(*params, vec![true, true, true, true]);
        let params = run_params_arc.lock().unwrap();
        assert_eq!(
            *params,
            vec![
                vec!["--initialization".to_string(), "--help".to_string()],
                vec!["--initialization".to_string(), "--version".to_string()],
                vec!["--help".to_string()],
                vec!["--version".to_string()],
            ]
        );
    }

    #[test]
    fn modes_other_than_daemon_and_node_mention_privilege_but_do_not_abort() {
        let mut subject = RunModes::new();
        let runner_params_arc = Arc::new(Mutex::new(vec![]));
        let runner = RunnerMock::new()
            .dump_config_params(&runner_params_arc)
            .dump_config_result(Ok(0));
        subject.runner = Box::new(runner);
        let dropper_params_arc = Arc::new(Mutex::new(vec![]));
        let privilege_dropper = PrivilegeDropperMock::new()
            .expect_privilege_params(&dropper_params_arc)
            .expect_privilege_result(false)
            .expect_privilege_result(false)
            .expect_privilege_result(false);
        subject.privilege_dropper = Box::new(privilege_dropper);
        let mut dump_config_holder = FakeStreamHolder::new();

        let dump_config_exit_code = subject.go(
            &["--dump-config".to_string()],
            &mut dump_config_holder.streams(),
        );

        assert_eq!(dump_config_exit_code, 0);
        assert_eq!(dump_config_holder.stdout.get_string(), "");
        assert_eq!(
            dump_config_holder.stderr.get_string(),
            RunModes::privilege_mismatch_message(&Mode::DumpConfig, false)
        );
        let params = dropper_params_arc.lock().unwrap();
        assert_eq!(*params, vec![false]);
        let params = runner_params_arc.lock().unwrap();
        assert_eq!(*params, vec![vec!["--dump-config"]])
    }

    fn check_mode(args: &[&str], expected_mode: Mode, privilege_required: bool) {
        let mut augmented_args: Vec<&str> = vec!["--unrelated"];
        augmented_args.extend(args);
        augmented_args.push("--unrelated");
        let args = strs_to_strings(augmented_args);
        let subject = RunModes::new();

        let (actual_mode, actual_privilege_required) = subject.determine_mode_and_priv_req(&args);

        assert_eq!(actual_mode, expected_mode, "args: {:?}", args);
        assert_eq!(
            actual_privilege_required, privilege_required,
            "args: {:?}",
            args
        );
    }

    fn strs_to_strings(strs: Vec<&str>) -> Vec<String> {
        strs.into_iter().map(|str| str.to_string()).collect()
    }
}
