// Copyright (c) 2019, MASQ (https://masq.ai). All rights reserved.

use crate::daemon::{Daemon, DaemonBindMessage};
use crate::node_configurator::node_configurator_initialization::InitializationConfig;
use crate::sub_lib::main_tools::{Command, StdStreams};
use crate::sub_lib::ui_gateway::{NodeFromUiMessage, NodeToUiMessage, UiGatewayConfig};
use crate::ui_gateway::UiGateway;
use actix::{Actor, Recipient};

pub struct Recipients {
    ui_gateway_from_sub: Recipient<NodeFromUiMessage>,
    ui_gateway_to_sub: Recipient<NodeToUiMessage>,
    from_ui_subs: Vec<Recipient<NodeFromUiMessage>>,
    bind_message_subs: Vec<Recipient<DaemonBindMessage>>,
}

pub trait RecipientsFactory {
    fn make(&self, ui_port: u16) -> Recipients;
}

pub struct RecipientsFactoryReal {}

impl RecipientsFactory for RecipientsFactoryReal {
    fn make(&self, ui_port: u16) -> Recipients {
        let ui_gateway_addr = UiGateway::new(&UiGatewayConfig {
            ui_port,
            node_descriptor: "".to_string(), // irrelevant; field should be removed
        })
        .start();
        let daemon_addr = Daemon::new().start();
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

impl RecipientsFactoryReal {
    pub fn new() -> Self {
        RecipientsFactoryReal {}
    }
}

pub struct DaemonInitializer {
    config: InitializationConfig,
    recipients_factory: Box<dyn RecipientsFactory>,
}

impl Command for DaemonInitializer {
    fn go(&mut self, _streams: &mut StdStreams<'_>, _args: &Vec<String>) -> u8 {
        let recipients = self.recipients_factory.make(self.config.ui_port);
        let bind_message = DaemonBindMessage {
            to_ui_message_recipient: recipients.ui_gateway_to_sub,
            from_ui_message_recipient: recipients.ui_gateway_from_sub,
            from_ui_message_recipients: recipients.from_ui_subs,
        };
        recipients.bind_message_subs.into_iter().for_each(|sub| {
            sub.try_send(bind_message.clone())
                .expect("DaemonBindMessage recipient is dead")
        });
        0
    }
}

impl DaemonInitializer {
    pub fn new(
        config: InitializationConfig,
        recipients_factory: Box<dyn RecipientsFactory>,
    ) -> DaemonInitializer {
        DaemonInitializer {
            config,
            recipients_factory,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node_configurator::node_configurator_initialization::InitializationConfig;
    use crate::node_configurator::{DirsWrapper, RealDirsWrapper};
    use crate::sub_lib::main_tools::Command;
    use crate::test_utils::recorder::{make_recorder, Recorder};
    use crate::test_utils::FakeStreamHolder;
    use actix::System;
    use itertools::Itertools;
    use std::cell::RefCell;

    struct RecipientsFactoryMock {
        ui_gateway: RefCell<Option<Recorder>>,
        actors: RefCell<Option<Vec<Recorder>>>,
        ui_port: RefCell<Option<u16>>,
    }

    impl RecipientsFactory for RecipientsFactoryMock {
        fn make(&self, ui_port: u16) -> Recipients {
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
                ui_port: RefCell::new(None),
            }
        }
    }

    #[test]
    fn go_binds_everything_together() {
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
        let recipients_factory =
            RecipientsFactoryMock::new(ui_gateway, vec![one_actor, another_actor]);
        let mut subject = DaemonInitializer::new(config, Box::new(recipients_factory));

        let result = subject.go(&mut FakeStreamHolder::new().streams(), &vec![]);

        System::current().stop();
        system.run();
        assert_eq!(result, 0);
        assert_eq!(ui_gateway_recording_arc.lock().unwrap().len(), 1);
        assert_eq!(one_actor_recording_arc.lock().unwrap().len(), 1);
        assert_eq!(another_actor_recording_arc.lock().unwrap().len(), 1);
    }
}
