// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

use crate::daemon::daemon_initializer::{DaemonInitializer, RecipientsFactoryReal, RerunnerReal};
use crate::daemon::ChannelFactoryReal;
use crate::database::config_dumper;
use crate::node_configurator::node_configurator_generate_wallet::NodeConfiguratorGenerateWallet;
use crate::node_configurator::node_configurator_initialization::NodeConfiguratorInitialization;
use crate::node_configurator::node_configurator_recover_wallet::NodeConfiguratorRecoverWallet;
use crate::node_configurator::{NodeConfigurator, RealDirsWrapper, WalletCreationConfig};
use crate::privilege_drop::{PrivilegeDropper, PrivilegeDropperReal};
use crate::server_initializer::ServerInitializer;
use actix::System;
use futures::future::Future;
use masq_lib::command::{Command, StdStreams};
use masq_lib::shared_schema::ConfiguratorError;

#[derive(Debug, PartialEq)]
enum Mode {
    GenerateWallet,
    RecoverWallet,
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

    pub fn go(&self, args: &Vec<String>, streams: &mut StdStreams<'_>) -> i32 {
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
            Mode::GenerateWallet => self.generate_wallet(args, streams),
            Mode::RecoverWallet => self.recover_wallet(args, streams),
            Mode::DumpConfig => self.runner.dump_config(args, streams),
            Mode::Initialization => self.runner.initialization(args, streams),
            Mode::Service => self.runner.run_service(args, streams),
        } {
            Ok(exit_code) => exit_code,
            Err(e) => {
                writeln!(streams.stderr, "Configuration error").expect("writeln! error");
                e.param_errors.into_iter().for_each(|required| {
                    writeln!(
                        streams.stderr,
                        "{} - {}",
                        required.parameter, required.reason
                    )
                    .expect("writeln! error")
                });
                1
            }
        }
    }

    fn args_contain_help_or_version(args: &Vec<String>) -> bool {
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

    fn determine_mode_and_priv_req(&self, args: &Vec<String>) -> (Mode, bool) {
        if args.contains(&"--dump-config".to_string()) {
            (Mode::DumpConfig, false)
        } else if args.contains(&"--recover-wallet".to_string()) {
            (Mode::RecoverWallet, false)
        } else if args.contains(&"--generate-wallet".to_string()) {
            (Mode::GenerateWallet, false)
        } else if args.contains(&"--initialization".to_string()) {
            (Mode::Initialization, true)
        } else {
            (Mode::Service, true)
        }
    }

    fn generate_wallet(
        &self,
        args: &Vec<String>,
        streams: &mut StdStreams<'_>,
    ) -> Result<i32, ConfiguratorError> {
        let configurator = NodeConfiguratorGenerateWallet::new();
        self.runner.configuration_run(
            args,
            streams,
            &configurator,
            self.privilege_dropper.as_ref(),
        )
    }

    fn recover_wallet(
        &self,
        args: &Vec<String>,
        streams: &mut StdStreams<'_>,
    ) -> Result<i32, ConfiguratorError> {
        let configurator = NodeConfiguratorRecoverWallet::new();
        self.runner.configuration_run(
            args,
            streams,
            &configurator,
            self.privilege_dropper.as_ref(),
        )
    }
}

trait Runner {
    fn run_service(
        &self,
        args: &Vec<String>,
        streams: &mut StdStreams<'_>,
    ) -> Result<i32, ConfiguratorError>;
    fn dump_config(
        &self,
        args: &Vec<String>,
        streams: &mut StdStreams<'_>,
    ) -> Result<i32, ConfiguratorError>;
    fn initialization(
        &self,
        args: &Vec<String>,
        streams: &mut StdStreams<'_>,
    ) -> Result<i32, ConfiguratorError>;
    fn configuration_run(
        &self,
        args: &Vec<String>,
        streams: &mut StdStreams<'_>,
        configurator: &dyn NodeConfigurator<WalletCreationConfig>,
        privilege_dropper: &dyn PrivilegeDropper,
    ) -> Result<i32, ConfiguratorError>;
}

struct RunnerReal {}

impl Runner for RunnerReal {
    fn run_service(
        &self,
        args: &Vec<String>,
        streams: &mut StdStreams<'_>,
    ) -> Result<i32, ConfiguratorError> {
        let system = System::new("main");

        let mut server_initializer = ServerInitializer::new();
        server_initializer.go(streams, args);

        actix::spawn(server_initializer.map_err(|_| {
            System::current().stop_with_code(1);
        }));

        Ok(system.run())
    }

    fn dump_config(
        &self,
        args: &Vec<String>,
        streams: &mut StdStreams<'_>,
    ) -> Result<i32, ConfiguratorError> {
        config_dumper::dump_config(args, streams)
    }

    fn initialization(
        &self,
        args: &Vec<String>,
        streams: &mut StdStreams<'_>,
    ) -> Result<i32, ConfiguratorError> {
        let configurator = NodeConfiguratorInitialization {};
        let config = configurator.configure(args, streams)?;
        let mut initializer = DaemonInitializer::new(
            &RealDirsWrapper {},
            config,
            Box::new(ChannelFactoryReal::new()),
            Box::new(RecipientsFactoryReal::new()),
            Box::new(RerunnerReal::new()),
        );
        initializer.go(streams, args);
        Ok(1)
    }

    fn configuration_run(
        &self,
        args: &Vec<String>,
        streams: &mut StdStreams<'_>,
        configurator: &dyn NodeConfigurator<WalletCreationConfig>,
        _privilege_dropper: &dyn PrivilegeDropper,
    ) -> Result<i32, ConfiguratorError> {
        match configurator.configure(args, streams) {
            Ok(_) => Ok(0),
            Err(e) => Err(e),
        }
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
        run_service_params: Arc<Mutex<Vec<Vec<String>>>>,
        run_service_results: RefCell<Vec<Result<i32, ConfiguratorError>>>,
        dump_config_params: Arc<Mutex<Vec<Vec<String>>>>,
        dump_config_results: RefCell<Vec<Result<i32, ConfiguratorError>>>,
        initialization_params: Arc<Mutex<Vec<Vec<String>>>>,
        initialization_results: RefCell<Vec<Result<i32, ConfiguratorError>>>,
        configuration_run_params: Arc<Mutex<Vec<Vec<String>>>>,
        configuration_run_results: RefCell<Vec<Result<i32, ConfiguratorError>>>,
    }

    impl Runner for RunnerMock {
        fn run_service(
            &self,
            args: &Vec<String>,
            _streams: &mut StdStreams<'_>,
        ) -> Result<i32, ConfiguratorError> {
            self.run_service_params.lock().unwrap().push(args.clone());
            self.run_service_results.borrow_mut().remove(0)
        }

        fn dump_config(
            &self,
            args: &Vec<String>,
            _streams: &mut StdStreams<'_>,
        ) -> Result<i32, ConfiguratorError> {
            self.dump_config_params.lock().unwrap().push(args.clone());
            self.dump_config_results.borrow_mut().remove(0)
        }

        fn initialization(
            &self,
            args: &Vec<String>,
            _streams: &mut StdStreams<'_>,
        ) -> Result<i32, ConfiguratorError> {
            self.initialization_params
                .lock()
                .unwrap()
                .push(args.clone());
            self.initialization_results.borrow_mut().remove(0)
        }

        fn configuration_run(
            &self,
            args: &Vec<String>,
            _streams: &mut StdStreams<'_>,
            _configurator: &dyn NodeConfigurator<WalletCreationConfig>,
            _privilege_dropper: &dyn PrivilegeDropper,
        ) -> Result<i32, ConfiguratorError> {
            self.configuration_run_params
                .lock()
                .unwrap()
                .push(args.clone());
            self.configuration_run_results.borrow_mut().remove(0)
        }
    }

    #[allow(dead_code)]
    impl RunnerMock {
        pub fn new() -> Self {
            Self {
                run_service_params: Arc::new(Mutex::new(vec![])),
                run_service_results: RefCell::new(vec![]),
                dump_config_params: Arc::new(Mutex::new(vec![])),
                dump_config_results: RefCell::new(vec![]),
                initialization_params: Arc::new(Mutex::new(vec![])),
                initialization_results: RefCell::new(vec![]),
                configuration_run_params: Arc::new(Mutex::new(vec![])),
                configuration_run_results: RefCell::new(vec![]),
            }
        }

        pub fn run_service_params(mut self, params: &Arc<Mutex<Vec<Vec<String>>>>) -> Self {
            self.run_service_params = params.clone();
            self
        }

        pub fn run_service_result(self, result: Result<i32, ConfiguratorError>) -> Self {
            self.run_service_results.borrow_mut().push(result);
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

        pub fn initialization_params(mut self, params: &Arc<Mutex<Vec<Vec<String>>>>) -> Self {
            self.initialization_params = params.clone();
            self
        }

        pub fn initialization_result(self, result: Result<i32, ConfiguratorError>) -> Self {
            self.initialization_results.borrow_mut().push(result);
            self
        }

        pub fn configuration_run_params(mut self, params: &Arc<Mutex<Vec<Vec<String>>>>) -> Self {
            self.configuration_run_params = params.clone();
            self
        }

        pub fn configuration_run_result(self, result: Result<i32, ConfiguratorError>) -> Self {
            self.configuration_run_results.borrow_mut().push(result);
            self
        }
    }

    #[test]
    fn generate_wallet() {
        [["--generate-wallet"]]
            .iter()
            .for_each(|args| check_mode(args, Mode::GenerateWallet, false));
    }

    #[test]
    fn recover_wallet() {
        [["--recover-wallet"]]
            .iter()
            .for_each(|args| check_mode(args, Mode::RecoverWallet, false));
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
    fn both_generate_and_recover() {
        [
            ["--generate-wallet", "--recover-wallet"],
            ["--recover-wallet", "--generate-wallet"],
        ]
        .iter()
        .for_each(|args| check_mode(args, Mode::RecoverWallet, false));
    }

    #[test]
    fn everything_beats_initialization() {
        check_mode(
            &["--initialization", "--generate-wallet"],
            Mode::GenerateWallet,
            false,
        );
        check_mode(
            &["--initialization", "--recover-wallet"],
            Mode::RecoverWallet,
            false,
        );
        check_mode(
            &["--initialization", "--dump-config"],
            Mode::DumpConfig,
            false,
        );
        check_mode(
            &["--generate-wallet", "--initialization"],
            Mode::GenerateWallet,
            false,
        );
        check_mode(
            &["--recover-wallet", "--initialization"],
            Mode::RecoverWallet,
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
        [
            ["--booga", "--goober", "--generate-wallet", "--dump-config"],
            ["--booga", "--goober", "--recover-wallet", "--dump-config"],
            ["--booga", "--goober", "--initialization", "--dump-config"],
            [
                "--generate-wallet",
                "--recover_wallet",
                "--initialization",
                "--dump-config",
            ],
        ]
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

        assert_eq!(
            service_yes,
            "MASQNode in Service mode must run with root privilege; try sudo\n"
        );
        assert_eq! (dump_config_no, "MASQNode in DumpConfig mode does not require root privilege; try without sudo next time\n");
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn privilege_mismatch_messages() {
        let service_yes = RunModes::privilege_mismatch_message(&Mode::Service, true);
        let dump_config_no = RunModes::privilege_mismatch_message(&Mode::DumpConfig, false);

        assert_eq!(
            service_yes,
            "MASQNode.exe in Service mode must run as Administrator.\n"
        );
        assert_eq!(
            dump_config_no,
            "MASQNode in DumpConfig mode does not require Adminstrator privilege.\n"
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

        let result = subject.go(&vec!["--dump-config".to_string()], &mut holder.streams());

        assert_eq!(result, 1);
        assert_eq!(
            &holder.stderr.get_string(),
            "Configuration error\n\
parm1 - msg1\n\
parm2 - msg2\n"
        )
    }

    #[test]
    fn initialization_and_service_modes_complain_without_privilege() {
        let mut subject = RunModes::new();
        subject.runner = Box::new(RunnerMock::new()); // No prepared results: any calls to this will cause panics
        let params_arc = Arc::new(Mutex::new(vec![]));
        let privilege_dropper = PrivilegeDropperMock::new()
            .expect_privilege_params(&params_arc)
            .expect_privilege_result(false)
            .expect_privilege_result(false);
        subject.privilege_dropper = Box::new(privilege_dropper);
        let mut initialization_holder = FakeStreamHolder::new();
        let mut service_mode_holder = FakeStreamHolder::new();

        let initialization_exit_code = subject.go(
            &vec!["--initialization".to_string()],
            &mut initialization_holder.streams(),
        );
        let service_mode_exit_code = subject.go(&vec![], &mut service_mode_holder.streams());

        assert_eq!(initialization_exit_code, 1);
        assert_eq!(initialization_holder.stdout.get_string(), "");
        assert_eq!(
            initialization_holder.stderr.get_string(),
            RunModes::privilege_mismatch_message(&Mode::Initialization, true)
        );
        assert_eq!(service_mode_exit_code, 1);
        assert_eq!(service_mode_holder.stdout.get_string(), "");
        assert_eq!(
            service_mode_holder.stderr.get_string(),
            RunModes::privilege_mismatch_message(&Mode::Service, true)
        );
        let params = params_arc.lock().unwrap();
        assert_eq!(*params, vec![true, true])
    }

    #[test]
    fn initialization_and_service_modes_do_not_complain_without_privilege_for_help_and_version() {
        let mut subject = RunModes::new();
        let run_params_arc = Arc::new(Mutex::new(vec![]));
        let runner = RunnerMock::new()
            .run_service_params(&run_params_arc)
            .run_service_result(Ok(0))
            .run_service_result(Ok(0))
            .initialization_params(&run_params_arc)
            .initialization_result(Ok(0))
            .initialization_result(Ok(0));
        subject.runner = Box::new(runner);
        let priv_params_arc = Arc::new(Mutex::new(vec![]));
        let privilege_dropper = PrivilegeDropperMock::new()
            .expect_privilege_params(&priv_params_arc)
            .expect_privilege_result(false)
            .expect_privilege_result(false)
            .expect_privilege_result(false)
            .expect_privilege_result(false);
        subject.privilege_dropper = Box::new(privilege_dropper);
        let mut initialization_h_holder = FakeStreamHolder::new();
        let mut initialization_v_holder = FakeStreamHolder::new();
        let mut service_mode_h_holder = FakeStreamHolder::new();
        let mut service_mode_v_holder = FakeStreamHolder::new();

        let initialization_h_exit_code = subject.go(
            &vec!["--initialization".to_string(), "--help".to_string()],
            &mut initialization_h_holder.streams(),
        );
        let initialization_v_exit_code = subject.go(
            &vec!["--initialization".to_string(), "--version".to_string()],
            &mut initialization_v_holder.streams(),
        );
        let service_mode_h_exit_code = subject.go(
            &vec!["--help".to_string()],
            &mut service_mode_h_holder.streams(),
        );
        let service_mode_v_exit_code = subject.go(
            &vec!["--version".to_string()],
            &mut service_mode_v_holder.streams(),
        );

        assert_eq!(initialization_h_exit_code, 0);
        assert_eq!(initialization_v_exit_code, 0);
        assert_eq!(initialization_h_holder.stdout.get_string(), "");
        assert_eq!(
            initialization_h_holder.stderr.get_string(),
            RunModes::privilege_mismatch_message(&Mode::Initialization, true)
        );
        assert_eq!(initialization_v_holder.stdout.get_string(), "");
        assert_eq!(
            initialization_v_holder.stderr.get_string(),
            RunModes::privilege_mismatch_message(&Mode::Initialization, true)
        );
        assert_eq!(service_mode_h_exit_code, 0);
        assert_eq!(service_mode_v_exit_code, 0);
        assert_eq!(service_mode_h_holder.stdout.get_string(), "");
        assert_eq!(
            service_mode_h_holder.stderr.get_string(),
            RunModes::privilege_mismatch_message(&Mode::Service, true)
        );
        assert_eq!(service_mode_v_holder.stdout.get_string(), "");
        assert_eq!(
            service_mode_v_holder.stderr.get_string(),
            RunModes::privilege_mismatch_message(&Mode::Service, true)
        );
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
    fn modes_other_than_initialization_and_service_mention_privilege_but_do_not_abort() {
        let mut subject = RunModes::new();
        let runner_params_arc = Arc::new(Mutex::new(vec![]));
        let runner = RunnerMock::new()
            .dump_config_params(&runner_params_arc)
            .dump_config_result(Ok(0))
            .configuration_run_params(&runner_params_arc)
            .configuration_run_result(Ok(0))
            .configuration_run_result(Ok(0));
        subject.runner = Box::new(runner);
        let dropper_params_arc = Arc::new(Mutex::new(vec![]));
        let privilege_dropper = PrivilegeDropperMock::new()
            .expect_privilege_params(&dropper_params_arc)
            .expect_privilege_result(false)
            .expect_privilege_result(false)
            .expect_privilege_result(false);
        subject.privilege_dropper = Box::new(privilege_dropper);
        let mut generate_wallet_holder = FakeStreamHolder::new();
        let mut recover_wallet_holder = FakeStreamHolder::new();
        let mut dump_config_holder = FakeStreamHolder::new();

        let generate_wallet_exit_code = subject.go(
            &vec!["--generate-wallet".to_string()],
            &mut generate_wallet_holder.streams(),
        );
        let recover_wallet_exit_code = subject.go(
            &vec!["--recover-wallet".to_string()],
            &mut recover_wallet_holder.streams(),
        );
        let dump_config_exit_code = subject.go(
            &vec!["--dump-config".to_string()],
            &mut dump_config_holder.streams(),
        );

        assert_eq!(generate_wallet_exit_code, 0);
        assert_eq!(generate_wallet_holder.stdout.get_string(), "");
        assert_eq!(
            generate_wallet_holder.stderr.get_string(),
            RunModes::privilege_mismatch_message(&Mode::GenerateWallet, false)
        );
        assert_eq!(recover_wallet_exit_code, 0);
        assert_eq!(recover_wallet_holder.stdout.get_string(), "");
        assert_eq!(
            recover_wallet_holder.stderr.get_string(),
            RunModes::privilege_mismatch_message(&Mode::RecoverWallet, false)
        );
        assert_eq!(dump_config_exit_code, 0);
        assert_eq!(dump_config_holder.stdout.get_string(), "");
        assert_eq!(
            dump_config_holder.stderr.get_string(),
            RunModes::privilege_mismatch_message(&Mode::DumpConfig, false)
        );
        let params = dropper_params_arc.lock().unwrap();
        assert_eq!(*params, vec![false, false, false]);
        let params = runner_params_arc.lock().unwrap();
        assert_eq!(
            *params,
            vec![
                vec!["--generate-wallet"],
                vec!["--recover-wallet"],
                vec!["--dump-config"]
            ]
        )
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
