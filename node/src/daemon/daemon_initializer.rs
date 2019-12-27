// Copyright (c) 2019, MASQ (https://masq.ai). All rights reserved.

#[cfg(not(target_os = "windows"))]
use crate::daemon::launcher_not_windows::LauncherReal;
#[cfg(target_os = "windows")]
use crate::daemon::launcher_windows::LauncherReal;
use crate::daemon::{
    ChannelFactory, ChannelFactoryReal, Daemon, DaemonBindMessage, Recipients, RecipientsFactory,
    RecipientsFactoryReal,
};
use crate::node_configurator::node_configurator_initialization::InitializationConfig;
use crate::sub_lib::main_tools::{main_with_args, Command, StdStreams};
use crate::sub_lib::ui_gateway::{NodeFromUiMessage, NodeToUiMessage, UiGatewayConfig};
use crate::ui_gateway::UiGateway;
use actix::{Actor, System, SystemRunner};
use itertools::Itertools;
use std::collections::HashMap;
use std::sync::mpsc::{Receiver, Sender};

impl RecipientsFactory for RecipientsFactoryReal {
    fn make(&self, args_sender: Sender<HashMap<String, String>>, ui_port: u16) -> Recipients {
        let ui_gateway_addr = UiGateway::new(&UiGatewayConfig {
            ui_port,
            node_descriptor: "".to_string(), // irrelevant; field should be removed
        })
        .start();
        let launcher = LauncherReal::new(args_sender);
        let daemon_addr = Daemon::new(Box::new(launcher)).start();
        Recipients {
            ui_gateway_from_sub: ui_gateway_addr.clone().recipient::<NodeFromUiMessage>(),
            ui_gateway_to_sub: ui_gateway_addr.clone().recipient::<NodeToUiMessage>(),
            from_ui_subs: vec![daemon_addr.clone().recipient::<NodeFromUiMessage>()],
            bind_message_subs: vec![
                daemon_addr.recipient::<DaemonBindMessage>(),
                ui_gateway_addr.recipient::<DaemonBindMessage>(),
            ],
        }
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
        std::sync::mpsc::channel()
    }
}

pub struct DaemonInitializer {
    config: InitializationConfig,
    channel_factory: Box<dyn ChannelFactory>,
    recipients_factory: Box<dyn RecipientsFactory>,
    rerunner: Box<dyn Rerunner>,
}

impl Command for DaemonInitializer {
    fn go(&mut self, _streams: &mut StdStreams<'_>, _args: &Vec<String>) -> u8 {
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
        config: InitializationConfig,
        channel_factory: Box<dyn ChannelFactory>,
        recipients_factory: Box<dyn RecipientsFactory>,
        rerunner: Box<dyn Rerunner>,
    ) -> DaemonInitializer {
        DaemonInitializer {
            config,
            channel_factory,
            recipients_factory,
            rerunner,
        }
    }

    fn bind(&mut self, sender: Sender<HashMap<String, String>>) {
        let recipients = self.recipients_factory.make(sender, self.config.ui_port);
        let bind_message = DaemonBindMessage {
            to_ui_message_recipient: recipients.ui_gateway_to_sub,
            from_ui_message_recipient: recipients.ui_gateway_from_sub,
            from_ui_message_recipients: recipients.from_ui_subs,
        };
        recipients.bind_message_subs.into_iter().for_each(|sub| {
            sub.try_send(bind_message.clone())
                .expect("DaemonBindMessage recipient is dead")
        });
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
    use crate::daemon::{ChannelFactory, Recipients, RecipientsFactory};
    use crate::node_configurator::node_configurator_initialization::InitializationConfig;
    use crate::node_configurator::{DirsWrapper, RealDirsWrapper};
    use crate::test_utils::recorder::{make_recorder, Recorder};
    use actix::System;
    use itertools::Itertools;
    use std::cell::RefCell;
    use std::iter::FromIterator;
    use std::sync::{Arc, Mutex};

    struct RecipientsFactoryMock {
        ui_gateway: RefCell<Option<Recorder>>,
        actors: RefCell<Option<Vec<Recorder>>>,
        sender: RefCell<Option<Sender<HashMap<String, String>>>>,
        ui_port: RefCell<Option<u16>>,
    }

    impl RecipientsFactory for RecipientsFactoryMock {
        fn make(&self, sender: Sender<HashMap<String, String>>, ui_port: u16) -> Recipients {
            let _ = self.sender.borrow_mut().replace(sender);
            let _ = self.ui_port.borrow_mut().replace(ui_port);

            let ui_gateway = self.ui_gateway.borrow_mut().take().unwrap();
            let ui_gateway_addr = ui_gateway.start();
            let ui_gateway_from_sub = ui_gateway_addr.clone().recipient::<NodeFromUiMessage>();
            let ui_gateway_to_sub = ui_gateway_addr.clone().recipient::<NodeToUiMessage>();

            let actors = self.actors.borrow_mut().take().unwrap();
            let actor_addrs = actors.into_iter().map(|actor| actor.start()).collect_vec();
            let from_ui_subs = actor_addrs
                .iter()
                .map(|addr| addr.clone().recipient::<NodeFromUiMessage>())
                .collect_vec();
            let mut bind_message_subs = actor_addrs
                .into_iter()
                .map(|addr| addr.recipient::<DaemonBindMessage>())
                .collect_vec();
            bind_message_subs.push(ui_gateway_addr.recipient::<DaemonBindMessage>());
            Recipients {
                ui_gateway_from_sub,
                ui_gateway_to_sub,
                from_ui_subs,
                bind_message_subs,
            }
        }
    }

    impl RecipientsFactoryMock {
        pub fn new(ui_gateway: Recorder, actors: Vec<Recorder>) -> RecipientsFactoryMock {
            RecipientsFactoryMock {
                ui_gateway: RefCell::new(Some(ui_gateway)),
                actors: RefCell::new(Some(actors)),
                sender: RefCell::new(None),
                ui_port: RefCell::new(None),
            }
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
        let (ui_gateway, _, ui_gateway_recording_arc) = make_recorder();
        let (one_actor, _, one_actor_recording_arc) = make_recorder();
        let (another_actor, _, another_actor_recording_arc) = make_recorder();
        let system = System::new("test");
        let config = InitializationConfig {
            chain_id: 0,                     // irrelevant
            config_file: Default::default(), // irrelevant
            data_directory: RealDirsWrapper {}.data_dir().unwrap(),
            db_password_opt: None, // irrelevant
            real_user: Default::default(),
            ui_port: 1234,
        };
        let channel_factory = ChannelFactoryMock::new();
        let recipients_factory =
            RecipientsFactoryMock::new(ui_gateway, vec![one_actor, another_actor]);
        let rerunner = RerunnerMock::new();
        let mut subject = DaemonInitializer::new(
            config,
            Box::new(channel_factory),
            Box::new(recipients_factory),
            Box::new(rerunner),
        );

        subject.bind(std::sync::mpsc::channel().0);

        System::current().stop();
        system.run();
        assert_eq!(ui_gateway_recording_arc.lock().unwrap().len(), 1);
        assert_eq!(one_actor_recording_arc.lock().unwrap().len(), 1);
        assert_eq!(another_actor_recording_arc.lock().unwrap().len(), 1);
    }

    #[test]
    fn split_accepts_parameters_upon_system_shutdown_and_calls_main_with_args() {
        let (ui_gateway, _, _) = make_recorder();
        let system = System::new("test");
        let config = InitializationConfig {
            chain_id: 0,                     // irrelevant
            config_file: Default::default(), // irrelevant
            data_directory: RealDirsWrapper {}.data_dir().unwrap(),
            db_password_opt: None, // irrelevant
            real_user: Default::default(),
            ui_port: 1234,
        };
        let (sender, receiver) = std::sync::mpsc::channel::<HashMap<String, String>>();
        let channel_factory = ChannelFactoryMock::new();
        let recipients_factory = RecipientsFactoryMock::new(ui_gateway, vec![]);
        let rerun_parameters_arc = Arc::new(Mutex::new(vec![]));
        let rerunner = RerunnerMock::new().rerun_parameters(&rerun_parameters_arc);
        let mut subject = DaemonInitializer::new(
            config,
            Box::new(channel_factory),
            Box::new(recipients_factory),
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
}
