// Copyright (c) 2019-2021, MASQ (https://masq.ai). All rights reserved.

use crate::bootstrapper::RealUser;
use crate::daemon::launcher::LauncherReal;
use crate::daemon::{
    ChannelFactory, ChannelFactoryReal, Daemon, DaemonBindMessage, Launcher, Recipients,
};
use crate::node_configurator::node_configurator_initialization::InitializationConfig;
use crate::node_configurator::{port_is_busy, DirsWrapper};
use crate::server_initializer::LoggerInitializerWrapper;
use crate::sub_lib::main_tools::main_with_args;
use crate::sub_lib::ui_gateway::UiGatewayConfig;
use crate::ui_gateway::UiGateway;
use actix::{Actor, System, SystemRunner};
use crossbeam_channel::{unbounded, Receiver, Sender};
use flexi_logger::LevelFilter;
use itertools::Itertools;
use masq_lib::command::{Command, StdStreams};
use std::collections::HashMap;

pub trait RecipientsFactory {
    fn make(&self, launcher: Box<dyn Launcher>, ui_port: u16) -> Recipients;
}

#[derive(Default)]
pub struct RecipientsFactoryReal {}

impl RecipientsFactory for RecipientsFactoryReal {
    fn make(&self, launcher: Box<dyn Launcher>, ui_port: u16) -> Recipients {
        let ui_gateway_addr = UiGateway::new(&UiGatewayConfig {
            ui_port,
            node_descriptor: "".to_string(), // irrelevant; field should be removed
        })
        .start();
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

pub struct DaemonInitializer {
    config: InitializationConfig,
    channel_factory: Box<dyn ChannelFactory>,
    recipients_factory: Box<dyn RecipientsFactory>,
    rerunner: Box<dyn Rerunner>,
}

impl Command for DaemonInitializer {
    fn go(&mut self, streams: &mut StdStreams<'_>, _args: &[String]) -> u8 {
        if port_is_busy(self.config.ui_port) {
            short_writeln! (streams.stderr, "There appears to be a process already listening on port {}; are you sure there's not a Daemon already running?", self.config.ui_port);
            return 1;
        }
        let system = System::new("daemon");
        let (sender, receiver) = self.channel_factory.make();

        self.bind(sender);

        self.split(system, receiver);
        0
    }
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

impl DaemonInitializer {
    pub fn new(
        dirs_wrapper: &dyn DirsWrapper,
        mut logger_initializer_wrapper: Box<dyn LoggerInitializerWrapper>,
        config: InitializationConfig,
        channel_factory: Box<dyn ChannelFactory>,
        recipients_factory: Box<dyn RecipientsFactory>,
        rerunner: Box<dyn Rerunner>,
    ) -> DaemonInitializer {
        logger_initializer_wrapper.init(
            dirs_wrapper
                .data_dir()
                .expect("No data directory")
                .join("MASQ"),
            &RealUser::new(None, None, None).populate(dirs_wrapper),
            LevelFilter::Trace,
            Some("daemon"),
        );
        DaemonInitializer {
            config,
            channel_factory,
            recipients_factory,
            rerunner,
        }
    }

    fn bind(&mut self, sender: Sender<HashMap<String, String>>) -> u8 {
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
        });
        0
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
    use crate::daemon::{ChannelFactory, Recipients};
    use crate::node_configurator::node_configurator_initialization::InitializationConfig;
    use crate::node_test_utils::MockDirsWrapper;
    use crate::server_initializer::test_utils::LoggerInitializerWrapperMock;
    use crate::test_utils::recorder::{make_recorder, Recorder};
    use actix::System;
    use crossbeam_channel::unbounded;
    use masq_lib::test_utils::fake_stream_holder::FakeStreamHolder;
    use masq_lib::test_utils::utils::ensure_node_home_directory_exists;
    use masq_lib::utils::{find_free_port, localhost};
    use std::cell::RefCell;
    use std::iter::FromIterator;
    use std::net::{SocketAddr, TcpListener};
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

    struct ChannelFactoryMock {
        make_results: RefCell<
            Vec<(
                Sender<HashMap<String, String>>,
                Receiver<HashMap<String, String>>,
            )>,
        >,
    }

    impl ChannelFactory for ChannelFactoryMock {
        fn make(
            &self,
        ) -> (
            Sender<HashMap<String, String>>,
            Receiver<HashMap<String, String>>,
        ) {
            self.make_results.borrow_mut().remove(0)
        }
    }

    impl ChannelFactoryMock {
        pub fn new() -> ChannelFactoryMock {
            ChannelFactoryMock {
                make_results: RefCell::new(vec![]),
            }
        }

        pub fn _make_result(
            self,
            sender: Sender<HashMap<String, String>>,
            receiver: Receiver<HashMap<String, String>>,
        ) -> Self {
            self.make_results.borrow_mut().push((sender, receiver));
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
    fn bind_binds_everything_together() {
        let data_dir = ensure_node_home_directory_exists(
            "daemon_initializer",
            "bind_binds_everything_together",
        );
        let (ui_gateway, _, ui_gateway_recording_arc) = make_recorder();
        let (daemon, _, daemon_recording_arc) = make_recorder();
        let system = System::new("bind_binds_everything_together");
        let recipients = make_recipients(ui_gateway, daemon);
        let dirs_wrapper = MockDirsWrapper::new()
            .home_dir_result(Some(data_dir.clone()))
            .data_dir_result(Some(data_dir));
        let logger_initializer_wrapper = LoggerInitializerWrapperMock::new();
        let port = find_free_port();
        let config = InitializationConfig { ui_port: port };
        let channel_factory = ChannelFactoryMock::new();
        let addr_factory = RecipientsFactoryMock::new().make_result(recipients);
        let rerunner = RerunnerMock::new();
        let mut subject = DaemonInitializer::new(
            &dirs_wrapper,
            Box::new(logger_initializer_wrapper),
            config,
            Box::new(channel_factory),
            Box::new(addr_factory),
            Box::new(rerunner),
        );

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
        let data_dir = ensure_node_home_directory_exists(
            "daemon_initializer",
            "split_accepts_parameters_upon_system_shutdown_and_calls_main_with_args",
        );
        let system =
            System::new("split_accepts_parameters_upon_system_shutdown_and_calls_main_with_args");
        let dirs_wrapper = MockDirsWrapper::new()
            .home_dir_result(Some(data_dir.clone()))
            .data_dir_result(Some(data_dir));
        let logger_initializer_wrapper = LoggerInitializerWrapperMock::new();
        let port = find_free_port();
        let config = InitializationConfig { ui_port: port };
        let (sender, receiver) = unbounded();
        let channel_factory = ChannelFactoryMock::new();
        let addr_factory = RecipientsFactoryMock::new();
        let rerun_parameters_arc = Arc::new(Mutex::new(vec![]));
        let rerunner = RerunnerMock::new().rerun_parameters(&rerun_parameters_arc);
        let mut subject = DaemonInitializer::new(
            &dirs_wrapper,
            Box::new(logger_initializer_wrapper),
            config,
            Box::new(channel_factory),
            Box::new(addr_factory),
            Box::new(rerunner),
        );
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
        let data_dir = ensure_node_home_directory_exists(
            "daemon_initializer",
            "go_detects_already_running_daemon",
        );
        let dirs_wrapper = MockDirsWrapper::new()
            .home_dir_result(Some(data_dir.clone()))
            .data_dir_result(Some(data_dir));
        let logger_initializer_wrapper = LoggerInitializerWrapperMock::new();
        let port = find_free_port();
        let _listener = TcpListener::bind(SocketAddr::new(localhost(), port)).unwrap();
        let mut subject = DaemonInitializer::new(
            &dirs_wrapper,
            Box::new(logger_initializer_wrapper),
            InitializationConfig { ui_port: port },
            Box::new(ChannelFactoryMock::new()),
            Box::new(RecipientsFactoryMock::new()),
            Box::new(RerunnerMock::new()),
        );
        let mut holder = FakeStreamHolder::new();

        let result = subject.go(&mut holder.streams(), &[]);

        assert_eq!(result, 1);
        assert_eq! (holder.stderr.get_string(), format!("There appears to be a process already listening on port {}; are you sure there's not a Daemon already running?\n", port));
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
}
