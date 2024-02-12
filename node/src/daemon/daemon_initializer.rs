// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::bootstrapper::RealUser;
use crate::daemon::launcher::LauncherReal;
use crate::daemon::{
    ChannelFactory, ChannelFactoryReal, Daemon, DaemonBindMessage, Launcher, Recipients,
};
use crate::node_configurator::node_configurator_initialization::InitializationConfig;
use crate::node_configurator::port_is_busy;
use crate::run_modes_factories::{DIClusteredParams, DaemonInitializer, RunModeResult};
use crate::sub_lib::main_tools::main_with_args;
use crate::sub_lib::ui_gateway::UiGatewayConfig;
#[cfg(target_os = "windows")]
use crate::sub_lib::utils::wsa_startup_init;
use crate::ui_gateway::UiGateway;
use actix::{Actor, System, SystemRunner};
use crossbeam_channel::{unbounded, Receiver, Sender};
use flexi_logger::LevelFilter;
use itertools::Itertools;
use masq_lib::command::StdStreams;
use masq_lib::shared_schema::ConfiguratorError;
use std::collections::HashMap;

use masq_lib::utils::ExpectValue;
use std::path::PathBuf;
use std::str::FromStr;

pub trait RecipientsFactory {
    fn make(&self, launcher: Box<dyn Launcher>, ui_port: u16) -> Recipients;
}

#[derive(Default)]
pub struct RecipientsFactoryReal {}

impl RecipientsFactory for RecipientsFactoryReal {
    fn make(&self, launcher: Box<dyn Launcher>, ui_port: u16) -> Recipients {
        let ui_gateway_addr = UiGateway::new(&UiGatewayConfig { ui_port }, false).start();
        let daemon_addr = Daemon::new(launcher).start();
        Recipients {
            ui_gateway_from_sub: ui_gateway_addr.clone().recipient(),
            ui_gateway_to_sub: ui_gateway_addr.clone().recipient(),
            from_ui_subs: vec![daemon_addr.clone().recipient()],
            crash_notification_sub: daemon_addr.clone().recipient(),
            bind_message_subs: vec![daemon_addr.recipient(), ui_gateway_addr.recipient()],
        }
    }
}

impl RecipientsFactoryReal {
    pub fn new() -> Self {
        Self::default()
    }
}

#[allow(clippy::type_complexity)]
impl ChannelFactory for ChannelFactoryReal {
    fn make(
        &self,
    ) -> (
        Sender<HashMap<String, String>>,
        Receiver<HashMap<String, String>>,
    ) {
        unbounded()
    }
}

pub struct DaemonInitializerReal {
    config: InitializationConfig,
    channel_factory: Box<dyn ChannelFactory>,
    recipients_factory: Box<dyn RecipientsFactory>,
    rerunner: Box<dyn Rerunner>,
}

impl DaemonInitializer for DaemonInitializerReal {
    fn go(&mut self, _streams: &mut StdStreams<'_>, _args: &[String]) -> RunModeResult {
        #[cfg(target_os = "windows")]
        unsafe {
            wsa_startup_init();
        }
        if port_is_busy(self.config.ui_port) {
            let message = format!("There appears to be a process already listening on port {}; are you sure there's not a Daemon already running?", self.config.ui_port);
            return Err(ConfiguratorError::required("ui-port", message.as_str()));
        }
        let system = System::new("daemon");
        let (sender, receiver) = self.channel_factory.make();

        self.bind(sender);

        self.split(system, receiver);
        Ok(())
    }
    as_any_in_trait_impl!();
}

pub trait Rerunner {
    fn rerun(&self, args: Vec<String>);
}

#[derive(Default)]
pub struct RerunnerReal {}

impl Rerunner for RerunnerReal {
    fn rerun(&self, args: Vec<String>) {
        let mut prefixed_args = vec![String::new()];
        prefixed_args.extend(args);
        eprintln!("------\nRerunning with args: {:?}\n------", prefixed_args);
        main_with_args(&prefixed_args);
    }
}

impl RerunnerReal {
    pub fn new() -> RerunnerReal {
        RerunnerReal {}
    }
}

impl DaemonInitializerReal {
    pub fn new(
        config: InitializationConfig,
        mut params: DIClusteredParams,
    ) -> DaemonInitializerReal {
        let real_user = RealUser::new(None, None, None).populate(params.dirs_wrapper.as_ref());
        let dirs_home_dir_opt = params.dirs_wrapper.home_dir();
        let dirs_home_dir = dirs_home_dir_opt
            .as_ref()
            .expectv("home directory")
            .to_str()
            .expectv("path string");
        let dirs_data_dir_opt = params.dirs_wrapper.data_dir();
        let dirs_data_dir = dirs_data_dir_opt
            .as_ref()
            .expect("data directory")
            .to_str()
            .expectv("path string");
        let real_home_dir = real_user
            .home_dir_opt
            .as_ref()
            .expectv("home directory")
            .to_str()
            .expectv("path string");
        let relative_data_dir = &dirs_data_dir[(dirs_home_dir.len() + 1)..];
        let real_data_dir = PathBuf::from_str(real_home_dir)
            .expectv("path string")
            .join(relative_data_dir);
        params.logger_initializer_wrapper.init(
            real_data_dir.join("MASQ"),
            &real_user,
            LevelFilter::Trace,
            Some("daemon"),
        );
        DaemonInitializerReal {
            config,
            channel_factory: params.channel_factory,
            recipients_factory: params.recipients_factory,
            rerunner: params.rerunner,
        }
    }

    fn bind(&mut self, sender: Sender<HashMap<String, String>>) {
        let launcher = LauncherReal::new(sender);
        let recipients = self
            .recipients_factory
            .make(Box::new(launcher), self.config.ui_port);
        let bind_message = DaemonBindMessage {
            to_ui_message_recipient: recipients.ui_gateway_to_sub,
            from_ui_message_recipient: recipients.ui_gateway_from_sub,
            from_ui_message_recipients: recipients.from_ui_subs,
            crash_notification_recipient: recipients.crash_notification_sub,
        };
        recipients.bind_message_subs.into_iter().for_each(|sub| {
            sub.try_send(bind_message.clone())
                .expect("DaemonBindMessage recipient is dead")
        })
    }

    fn split(&mut self, system: SystemRunner, receiver: Receiver<HashMap<String, String>>) {
        system.run();
        let param_map = receiver.recv().expect("Daemon is dead");
        let param_vec = param_map
            .into_iter()
            .sorted_by_key(|(key, _)| key.to_string())
            .flat_map(|(key, value)| vec![format!("--{}", key), value])
            .collect_vec();
        self.rerunner.rerun(param_vec);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::Recipients;
    use crate::node_configurator::node_configurator_initialization::{
        InitializationConfig, NodeConfiguratorInitializationReal,
    };
    use crate::node_test_utils::DirsWrapperMock;
    use crate::run_modes_factories::mocks::test_clustered_params;
    use crate::run_modes_factories::{DaemonInitializerFactory, DaemonInitializerFactoryReal};
    use crate::server_initializer::test_utils::LoggerInitializerWrapperMock;
    use crate::test_utils::recorder::{make_recorder, Recorder};
    use crate::test_utils::unshared_test_utils::ChannelFactoryMock;
    use actix::System;
    use crossbeam_channel::unbounded;
    use masq_lib::test_utils::environment_guard::EnvironmentGuard;
    use masq_lib::test_utils::fake_stream_holder::FakeStreamHolder;
    use masq_lib::test_utils::utils::ensure_node_home_directory_exists;
    use masq_lib::utils::{find_free_port, localhost, slice_of_strs_to_vec_of_strings};
    use std::cell::RefCell;
    use std::iter::FromIterator;
    use std::net::{SocketAddr, TcpListener};
    use std::path::PathBuf;
    use std::ptr::addr_of;
    use std::str::FromStr;
    use std::sync::{Arc, Mutex};

    struct RecipientsFactoryMock {
        make_params: Arc<Mutex<Vec<(Box<dyn Launcher>, u16)>>>,
        make_results: RefCell<Vec<Recipients>>,
    }

    impl RecipientsFactory for RecipientsFactoryMock {
        fn make(&self, launcher: Box<dyn Launcher>, ui_port: u16) -> Recipients {
            self.make_params.lock().unwrap().push((launcher, ui_port));
            self.make_results.borrow_mut().remove(0)
        }
    }

    impl RecipientsFactoryMock {
        fn new() -> Self {
            Self {
                make_params: Arc::new(Mutex::new(vec![])),
                make_results: RefCell::new(vec![]),
            }
        }

        fn make_result(self, result: Recipients) -> Self {
            self.make_results.borrow_mut().push(result);
            self
        }
    }

    struct RerunnerMock {
        rerun_parameters: Arc<Mutex<Vec<Vec<String>>>>,
    }

    impl Rerunner for RerunnerMock {
        fn rerun(&self, args: Vec<String>) {
            self.rerun_parameters.lock().unwrap().push(args);
        }
    }

    impl RerunnerMock {
        fn new() -> RerunnerMock {
            RerunnerMock {
                rerun_parameters: Arc::new(Mutex::new(vec![])),
            }
        }

        fn rerun_parameters(mut self, params: &Arc<Mutex<Vec<Vec<String>>>>) -> Self {
            self.rerun_parameters = params.clone();
            self
        }
    }

    #[test]
    fn new_handles_standard_home_directory() {
        let _guard = EnvironmentGuard::new();
        new_handles_home_directory(
            "/home/username",
            "standard/data/dir",
            "/home/username/standard/data/dir/MASQ",
        )
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn new_handles_linux_root_home_directory() {
        let _guard = EnvironmentGuard::new();
        std::env::set_var("SUDO_USER", "username");
        new_handles_home_directory(
            "/root",
            "standard/data/dir",
            "/home/username/standard/data/dir/MASQ",
        );
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn new_handles_macos_root_home_directory() {
        let _guard = EnvironmentGuard::new();
        std::env::set_var("SUDO_USER", "username");
        new_handles_home_directory(
            "/var/root",
            "standard/data/dir",
            "/Users/username/standard/data/dir/MASQ",
        );
    }

    fn new_handles_home_directory(dirs_home_dir: &str, relative_data_dir: &str, expected: &str) {
        let dirs_wrapper = DirsWrapperMock::new()
            .home_dir_result(Some(PathBuf::from_str(dirs_home_dir).unwrap()))
            .data_dir_result(Some(
                PathBuf::from_str(dirs_home_dir)
                    .unwrap()
                    .join(PathBuf::from_str(relative_data_dir).unwrap()),
            ));
        let config = InitializationConfig::default();
        let mut clustered_params = DIClusteredParams::default();
        let init_params_arc = Arc::new(Mutex::new(vec![]));
        let logger_initializer_wrapper =
            LoggerInitializerWrapperMock::new().init_parameters(&init_params_arc);
        clustered_params.logger_initializer_wrapper = Box::new(logger_initializer_wrapper);
        clustered_params.dirs_wrapper = Box::new(dirs_wrapper);

        let _ = DaemonInitializerReal::new(config, clustered_params);

        let init_params = init_params_arc.lock().unwrap();
        let element = &((*init_params)[0]);
        let log_dir = &element.0;
        assert_eq!(log_dir, &PathBuf::from_str(expected).unwrap());
    }

    #[test]
    fn bind_binds_everything_together() {
        let home_dir = ensure_node_home_directory_exists(
            "daemon_initializer",
            "bind_binds_everything_together",
        );
        let (ui_gateway, _, ui_gateway_recording_arc) = make_recorder();
        let (daemon, _, daemon_recording_arc) = make_recorder();
        let system = System::new("bind_binds_everything_together");
        let recipients = make_recipients(ui_gateway, daemon);
        let dirs_wrapper = DirsWrapperMock::new()
            .home_dir_result(Some(home_dir.clone()))
            .data_dir_result(Some(home_dir.join("data")));
        let logger_initializer_wrapper = LoggerInitializerWrapperMock::new();
        let port = find_free_port();
        let config = InitializationConfig { ui_port: port };
        let channel_factory = ChannelFactoryMock::new();
        let addr_factory = RecipientsFactoryMock::new().make_result(recipients);
        let rerunner = RerunnerMock::new();
        let clustered_params = DIClusteredParams {
            dirs_wrapper: Box::new(dirs_wrapper),
            logger_initializer_wrapper: Box::new(logger_initializer_wrapper),
            channel_factory: Box::new(channel_factory),
            recipients_factory: Box::new(addr_factory),
            rerunner: Box::new(rerunner),
        };
        let mut subject = DaemonInitializerReal::new(config, clustered_params);

        subject.bind(unbounded().0);

        System::current().stop();
        system.run();
        let ui_gateway_recording = ui_gateway_recording_arc.lock().unwrap();
        let daemon_recording = daemon_recording_arc.lock().unwrap();
        let _ = ui_gateway_recording.get_record::<DaemonBindMessage>(0);
        let _ = daemon_recording.get_record::<DaemonBindMessage>(0);
        assert_eq!(ui_gateway_recording.len(), 1);
        assert_eq!(daemon_recording.len(), 1);
    }

    #[test]
    fn split_accepts_parameters_upon_system_shutdown_and_calls_main_with_args() {
        let home_dir = ensure_node_home_directory_exists(
            "daemon_initializer",
            "split_accepts_parameters_upon_system_shutdown_and_calls_main_with_args",
        );
        let system =
            System::new("split_accepts_parameters_upon_system_shutdown_and_calls_main_with_args");
        let dirs_wrapper = DirsWrapperMock::new()
            .home_dir_result(Some(home_dir.clone()))
            .data_dir_result(Some(home_dir.join("data")));
        let logger_initializer_wrapper = LoggerInitializerWrapperMock::new();
        let port = find_free_port();
        let config = InitializationConfig { ui_port: port };
        let (sender, receiver) = unbounded();
        let channel_factory = ChannelFactoryMock::new();
        let addr_factory = RecipientsFactoryMock::new();
        let rerun_parameters_arc = Arc::new(Mutex::new(vec![]));
        let rerunner = RerunnerMock::new().rerun_parameters(&rerun_parameters_arc);
        let clustered_params = DIClusteredParams {
            dirs_wrapper: Box::new(dirs_wrapper),
            logger_initializer_wrapper: Box::new(logger_initializer_wrapper),
            channel_factory: Box::new(channel_factory),
            recipients_factory: Box::new(addr_factory),
            rerunner: Box::new(rerunner),
        };
        let mut subject = DaemonInitializerReal::new(config, clustered_params);
        let msg = HashMap::from_iter(
            vec![("address", "123 Main St."), ("name", "Billy")]
                .into_iter()
                .map(|(n, v)| (n.to_string(), v.to_string())),
        );
        sender.send(msg).unwrap();
        System::current().stop();

        subject.split(system, receiver);

        let mut rerun_parameters = rerun_parameters_arc.lock().unwrap();
        assert_eq!(
            rerun_parameters.remove(0),
            vec![
                "--address".to_string(),
                "123 Main St.".to_string(),
                "--name".to_string(),
                "Billy".to_string(),
            ]
        );
    }

    #[test]
    fn go_detects_already_running_daemon() {
        let home_dir = ensure_node_home_directory_exists(
            "daemon_initializer",
            "go_detects_already_running_daemon",
        );
        let dirs_wrapper = DirsWrapperMock::new()
            .home_dir_result(Some(home_dir.clone()))
            .data_dir_result(Some(home_dir.join("data")));
        let logger_initializer_wrapper = LoggerInitializerWrapperMock::new();
        let port = find_free_port();
        let _listener = TcpListener::bind(SocketAddr::new(localhost(), port)).unwrap();
        let clustered_params = DIClusteredParams {
            dirs_wrapper: Box::new(dirs_wrapper),
            logger_initializer_wrapper: Box::new(logger_initializer_wrapper),
            channel_factory: Box::new(ChannelFactoryMock::new()),
            recipients_factory: Box::new(RecipientsFactoryMock::new()),
            rerunner: Box::new(RerunnerMock::new()),
        };
        let mut subject =
            DaemonInitializerReal::new(InitializationConfig { ui_port: port }, clustered_params);
        let mut holder = FakeStreamHolder::new();

        let result = subject.go(&mut holder.streams(), &[]);

        assert_eq!(result,Err(ConfiguratorError::required("ui-port",&format!("There \
         appears to be a process already listening on port {}; are you sure there's not a Daemon already running?", port))));
        assert!(holder.stderr.get_string().is_empty());
    }

    fn make_recipients(ui_gateway: Recorder, daemon: Recorder) -> Recipients {
        let ui_gateway_addr = ui_gateway.start();
        let daemon_addr = daemon.start();
        Recipients {
            ui_gateway_from_sub: ui_gateway_addr.clone().recipient(),
            ui_gateway_to_sub: ui_gateway_addr.clone().recipient(),
            from_ui_subs: vec![
                daemon_addr.clone().recipient(),
                ui_gateway_addr.clone().recipient(),
            ],
            crash_notification_sub: daemon_addr.clone().recipient(),
            bind_message_subs: vec![daemon_addr.recipient(), ui_gateway_addr.recipient()],
        }
    }

    #[test]
    fn make_for_daemon_initializer_factory_labours_hard_and_produces_a_proper_object() {
        let daemon_clustered_params = test_clustered_params();
        let init_pointer_of_recipients_factory =
            addr_of!(*daemon_clustered_params.recipients_factory);
        let init_pointer_of_channel_factory = addr_of!(*daemon_clustered_params.channel_factory);
        let init_pointer_of_rerunner = addr_of!(*daemon_clustered_params.rerunner);
        let subject = DaemonInitializerFactoryReal::new(
            Box::new(NodeConfiguratorInitializationReal),
            daemon_clustered_params,
        );
        let args = &slice_of_strs_to_vec_of_strings(&[
            "program",
            "--initialization",
            "--ui-port",
            1234.to_string().as_str(),
        ]);

        let result = subject.make(&args).unwrap();

        let factory_product = result
            .as_any()
            .downcast_ref::<DaemonInitializerReal>()
            .unwrap();
        assert_eq!(factory_product.config.ui_port, 1234);
        let final_pointer_of_recipients_factory = addr_of!(*factory_product.recipients_factory);
        assert_eq!(
            init_pointer_of_recipients_factory,
            final_pointer_of_recipients_factory
        );
        let final_pointer_of_channel_factory = addr_of!(*factory_product.channel_factory);
        assert_eq!(
            init_pointer_of_channel_factory,
            final_pointer_of_channel_factory
        );
        let final_pointer_of_rerunner = addr_of!(*factory_product.rerunner);
        assert_eq!(init_pointer_of_rerunner, final_pointer_of_rerunner);
    }
}
