// Copyright (c) 2019, MASQ (https://masq.ai). All rights reserved.

pub mod daemon_initializer;
#[cfg(target_os = "windows")]
mod launcher_windows;
#[cfg(not(target_os = "windows"))]
mod launcher_not_windows;

use crate::sub_lib::logger::Logger;
use crate::sub_lib::ui_gateway::MessageTarget::ClientId;
use crate::sub_lib::ui_gateway::{NodeFromUiMessage, NodeToUiMessage, MessageBody};
use crate::ui_gateway::messages::UiMessageError::BadOpcode;
use crate::ui_gateway::messages::{FromMessageBody, ToMessageBody, UiMessageError, UiSetup, UiSetupValue, UiStartOrder, UiStartResponse, NODE_LAUNCH_ERROR};
use actix::Recipient;
use actix::{Actor, Context, Handler, Message};
use std::collections::HashMap;
use std::iter::FromIterator;
use std::sync::mpsc::{Sender, Receiver};
use crate::sub_lib::ui_gateway::MessagePath::TwoWay;

pub struct Recipients {
    ui_gateway_from_sub: Recipient<NodeFromUiMessage>,
    ui_gateway_to_sub: Recipient<NodeToUiMessage>,
    from_ui_subs: Vec<Recipient<NodeFromUiMessage>>,
    bind_message_subs: Vec<Recipient<DaemonBindMessage>>,
}

pub trait RecipientsFactory {
    fn make(&self, args_sender: Sender<HashMap<String, String>>, ui_port: u16) -> Recipients;
}

pub struct RecipientsFactoryReal {}

impl RecipientsFactoryReal {
    pub fn new() -> Self {
        RecipientsFactoryReal {}
    }
}

pub trait ChannelFactory {
    fn make(&self) -> (Sender<HashMap<String, String>>, Receiver<HashMap<String, String>>);
}

pub struct ChannelFactoryReal {}

impl ChannelFactoryReal {
    pub fn new() -> ChannelFactoryReal {
        ChannelFactoryReal{}
    }
}

#[derive(PartialEq, Debug)]
pub struct LaunchSuccess {
    pub new_process_id: i32,
    pub redirect_ui_port: u16,
}

pub trait Launcher {
    fn launch(&self, params: HashMap<String, String>) -> Result<LaunchSuccess, String>;
}

#[derive(Message, PartialEq, Clone)]
pub struct DaemonBindMessage {
    pub to_ui_message_recipient: Recipient<NodeToUiMessage>, // for everybody to send UI-bound messages to
    pub from_ui_message_recipient: Recipient<NodeFromUiMessage>, // for the WebsocketSupervisor to send inbound UI messages to the UiGateway
    pub from_ui_message_recipients: Vec<Recipient<NodeFromUiMessage>>, // for the UiGateway to relay inbound UI messages to everybody
}

pub struct Daemon {
    launcher: Box<dyn Launcher>,
    params: HashMap<String, String>,
    ui_gateway_sub: Option<Recipient<NodeToUiMessage>>,
    logger: Logger,
}

impl Actor for Daemon {
    type Context = Context<Daemon>;
}

impl Handler<DaemonBindMessage> for Daemon {
    type Result = ();

    fn handle(&mut self, msg: DaemonBindMessage, _ctx: &mut Self::Context) -> Self::Result {
        self.ui_gateway_sub = Some(msg.to_ui_message_recipient);
    }
}

impl Handler<NodeFromUiMessage> for Daemon {
    type Result = ();

    fn handle(&mut self, msg: NodeFromUiMessage, _ctx: &mut Self::Context) -> Self::Result {
        let client_id = msg.client_id;
        let opcode = msg.body.opcode.clone();
        // TODO: Gotta be a better way to arrange this code
        let result: Result<(UiSetup, u64), UiMessageError> = UiSetup::fmb(msg.body.clone());
        match result {
            Ok((payload, context_id)) => self.handle_setup(client_id, context_id, payload),
            Err(BadOpcode) => {
                let result: Result<(UiStartOrder, u64), UiMessageError> =
                    UiStartOrder::fmb(msg.body);
                match result {
                    Ok((_, context_id)) => self.handle_start_order(client_id, context_id),
                    Err(e) => error!(
                        &self.logger,
                        "Bad {} request from client {}: {:?}", opcode, client_id, e
                    ),
                }
            }
            Err(e) => error!(
                &self.logger,
                "Bad {} request from client {}: {:?}", opcode, client_id, e
            ),
        }
    }
}

impl Daemon {
    pub fn new(launcher: Box<dyn Launcher>) -> Daemon {
        let mut params = HashMap::new();
        params.insert("dns-servers".to_string(), "1.1.1.1".to_string()); // TODO: This should default to the system DNS value before subversion.
        Daemon {
            launcher,
            params,
            ui_gateway_sub: None,
            logger: Logger::new("Daemon"),
        }
    }

    fn get_default_params() -> HashMap<String, String> {
        let schema = crate::node_configurator::node_configurator_standard::app();
        schema
            .p
            .opts
            .iter()
            .flat_map(|opt| {
                let name = opt.b.name.to_string();
                match opt.v.default_val {
                    Some(os_str) => Some((name, os_str.to_str().unwrap().to_string())),
                    None => None,
                }
            })
            .collect()
    }

    fn handle_setup(&mut self, client_id: u64, context_id: u64, payload: UiSetup) {
        let mut report = Self::get_default_params();
        let params: HashMap<String, String> =
            HashMap::from_iter(payload.values.into_iter().map(|usv| (usv.name, usv.value)));
        self.params.extend(params.clone().into_iter());
        report.extend(self.params.clone().into_iter());
        let msg = NodeToUiMessage {
            target: ClientId(client_id),
            body: UiSetup {
                values: report
                    .into_iter()
                    .map(|(name, value)| UiSetupValue { name, value })
                    .collect(),
            }
            .tmb(context_id),
        };
        self.ui_gateway_sub
            .as_ref()
            .expect("UiGateway is unbound")
            .try_send(msg)
            .expect("UiGateway is dead");
    }

    fn handle_start_order(&mut self, client_id: u64, context_id: u64) {
        match self.launcher.launch(self.params.drain().collect()) {
            Ok(success) => self
                .respond_to_ui (client_id, UiStartResponse {
                    new_process_id: success.new_process_id,
                    redirect_ui_port: success.redirect_ui_port,
                }
                .tmb(context_id)),
            Err(s) => self
                .respond_to_ui (client_id, MessageBody {
                    opcode: "start".to_string(),
                    path: TwoWay(context_id),
                    payload: Err((
                        NODE_LAUNCH_ERROR,
                        format!("Could not launch Node: {}", s),
                    ))
                }),
        }
    }

    fn respond_to_ui(&self, client_id: u64, body: MessageBody) {
        self
            .ui_gateway_sub
            .as_ref()
            .expect("UiGateway is unbound")
            .try_send(NodeToUiMessage {
                target: ClientId(client_id),
                body,
            })
            .expect("UiGateway is dead")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sub_lib::ui_gateway::MessageTarget::ClientId;
    use crate::test_utils::recorder::{make_recorder, Recorder};
    use crate::ui_gateway::messages::{UiSetup, UiStartOrder, UiStartResponse, NODE_LAUNCH_ERROR};
    use actix::System;
    use std::collections::HashSet;
    use std::sync::{Arc, Mutex};
    use std::cell::RefCell;
    use crate::daemon::{LaunchSuccess};

    struct LauncherMock {
        launch_params: Arc<Mutex<Vec<HashMap<String, String>>>>,
        launch_results: RefCell<Vec<Result<LaunchSuccess, String>>>,
    }

    impl Launcher for LauncherMock {
        fn launch(&self, params: HashMap<String, String>) -> Result<LaunchSuccess, String> {
            self.launch_params.lock().unwrap().push(params);
            self.launch_results.borrow_mut().remove(0)
        }
    }

    impl LauncherMock {
        fn new() -> LauncherMock {
            LauncherMock {
                launch_params: Arc::new(Mutex::new(vec![])),
                launch_results: RefCell::new(vec![]),
            }
        }

        fn launch_params(mut self, params: &Arc<Mutex<Vec<HashMap<String, String>>>>) -> Self {
            self.launch_params = params.clone();
            self
        }

        fn launch_result(self, result: Result<LaunchSuccess, String>) -> Self {
            self.launch_results.borrow_mut().push(result);
            self
        }
    }

    fn make_bind_message(ui_gateway: Recorder) -> DaemonBindMessage {
        let (stub, _, _) = make_recorder();
        let stub_sub = stub.start().recipient::<NodeFromUiMessage>();
        let ui_gateway_sub = ui_gateway.start().recipient::<NodeToUiMessage>();
        DaemonBindMessage {
            to_ui_message_recipient: ui_gateway_sub,
            from_ui_message_recipient: stub_sub,
            from_ui_message_recipients: vec![],
        }
    }

    #[test]
    fn accepts_empty_setup_and_returns_defaults() {
        let (ui_gateway, _, ui_gateway_recording_arc) = make_recorder();
        let system = System::new("test");
        let subject = Daemon::new(Box::new(LauncherMock::new()));
        let subject_addr = subject.start();
        subject_addr
            .try_send(make_bind_message(ui_gateway))
            .unwrap();

        subject_addr
            .try_send(NodeFromUiMessage {
                client_id: 1234,
                body: UiSetup { values: vec![] }.tmb(4321),
            })
            .unwrap();

        System::current().stop();
        system.run();
        let ui_gateway_recording = ui_gateway_recording_arc.lock().unwrap();
        let record = ui_gateway_recording
            .get_record::<NodeToUiMessage>(0)
            .clone();
        assert_eq!(record.target, ClientId(1234));
        let (payload, context_id): (UiSetup, u64) = UiSetup::fmb(record.body).unwrap();
        assert_eq!(context_id, 4321);
        let actual_pairs: HashSet<(String, String)> = payload
            .values
            .into_iter()
            .map(|value| (value.name, value.value))
            .collect();
        let schema = crate::node_configurator::node_configurator_standard::app();
        let mut expected_pairs: HashSet<(String, String)> = schema
            .p
            .opts
            .iter()
            .flat_map(|opt| {
                let name = opt.b.name.to_string();
                match opt.v.default_val {
                    Some(os_str) => Some((name, os_str.to_str().unwrap().to_string())),
                    None => None,
                }
            })
            .collect();
        expected_pairs.insert(("dns-servers".to_string(), "1.1.1.1".to_string()));

        assert_eq!(actual_pairs, expected_pairs);
    }

    #[test]
    fn accepts_full_setup_and_returns_settings_then_remembers_them() {
        let (ui_gateway, _, ui_gateway_recording_arc) = make_recorder();
        let system = System::new("test");
        let subject = Daemon::new(Box::new(LauncherMock::new()));
        let subject_addr = subject.start();
        subject_addr
            .try_send(make_bind_message(ui_gateway))
            .unwrap();

        subject_addr
            .try_send(NodeFromUiMessage {
                client_id: 1234,
                body: UiSetup {
                    values: vec![
                        UiSetupValue::new("chain", "ropsten"),
                        UiSetupValue::new("config-file", "biggles.txt"),
                        UiSetupValue::new("db-password", "goober"),
                        UiSetupValue::new("real-user", "1234:4321:hormel"),
                    ],
                }
                .tmb(4321),
            })
            .unwrap();
        subject_addr
            .try_send(NodeFromUiMessage {
                client_id: 1234,
                body: UiSetup { values: vec![] }.tmb(4321),
            })
            .unwrap();

        System::current().stop();
        system.run();
        let ui_gateway_recording = ui_gateway_recording_arc.lock().unwrap();
        let record = ui_gateway_recording
            .get_record::<NodeToUiMessage>(0)
            .clone();
        assert_eq!(record.target, ClientId(1234));
        let (payload, context_id): (UiSetup, u64) = UiSetup::fmb(record.body).unwrap();
        assert_eq!(context_id, 4321);
        let actual_pairs: HashMap<String, String> = payload
            .values
            .into_iter()
            .map(|value| (value.name, value.value))
            .collect();
        let schema = crate::node_configurator::node_configurator_standard::app();
        let mut expected_pairs: HashMap<String, String> = schema
            .p
            .opts
            .iter()
            .flat_map(|opt| {
                let name = opt.b.name.to_string();
                match opt.v.default_val {
                    Some(os_str) => Some((name, os_str.to_str().unwrap().to_string())),
                    None => None,
                }
            })
            .collect();
        expected_pairs.insert("dns-servers".to_string(), "1.1.1.1".to_string());
        expected_pairs.insert("chain".to_string(), "ropsten".to_string());
        expected_pairs.insert("config-file".to_string(), "biggles.txt".to_string());
        expected_pairs.insert("db-password".to_string(), "goober".to_string());
        expected_pairs.insert("real-user".to_string(), "1234:4321:hormel".to_string());

        assert_eq!(actual_pairs, expected_pairs);

        let record = ui_gateway_recording
            .get_record::<NodeToUiMessage>(1)
            .clone();
        assert_eq!(record.target, ClientId(1234));
        let (payload, context_id): (UiSetup, u64) = UiSetup::fmb(record.body).unwrap();
        assert_eq!(context_id, 4321);
        let actual_pairs: HashMap<String, String> = payload
            .values
            .into_iter()
            .map(|value| (value.name, value.value))
            .collect();

        assert_eq!(actual_pairs, expected_pairs);
    }

    #[test]
    fn overrides_defaults() {
        let (ui_gateway, _, ui_gateway_recording_arc) = make_recorder();
        let system = System::new("test");
        let subject = Daemon::new(Box::new(LauncherMock::new()));
        let subject_addr = subject.start();
        subject_addr
            .try_send(make_bind_message(ui_gateway))
            .unwrap();

        subject_addr
            .try_send(NodeFromUiMessage {
                client_id: 1234,
                body: UiSetup {
                    values: vec![
                        UiSetupValue::new("dns-servers", "192.168.0.1"),
                    ],
                }
                .tmb(4321),
            })
            .unwrap();

        System::current().stop();
        system.run();
        let ui_gateway_recording = ui_gateway_recording_arc.lock().unwrap();
        let record = ui_gateway_recording
            .get_record::<NodeToUiMessage>(0)
            .clone();
        assert_eq!(record.target, ClientId(1234));
        let (payload, context_id): (UiSetup, u64) = UiSetup::fmb(record.body).unwrap();
        assert_eq!(context_id, 4321);
        let actual_pairs: HashMap<String, String> = payload
            .values
            .into_iter()
            .map(|value| (value.name, value.value))
            .collect();
        let schema = crate::node_configurator::node_configurator_standard::app();
        let mut expected_pairs: HashMap<String, String> = schema
            .p
            .opts
            .iter()
            .flat_map(|opt| {
                let name = opt.b.name.to_string();
                match opt.v.default_val {
                    Some(os_str) => Some((name, os_str.to_str().unwrap().to_string())),
                    None => None,
                }
            })
            .collect();
        expected_pairs.insert("dns-servers".to_string(), "192.168.0.1".to_string());

        assert_eq!(actual_pairs, expected_pairs);
    }

    #[test]
    fn accepts_start_order_launches_and_replies_success() {
        let (ui_gateway, _, ui_gateway_recording_arc) = make_recorder();
        let launch_params_arc = Arc::new(Mutex::new(vec![]));
        let launcher = LauncherMock::new()
            .launch_params(&launch_params_arc)
            .launch_result(Ok(LaunchSuccess{
                new_process_id: 2345,
                redirect_ui_port: 5432
            }));
        let system = System::new("test");
        let mut subject = Daemon::new(Box::new(launcher));
        subject
            .params
            .insert("db-password".to_string(), "goober".to_string());
        let subject_addr = subject.start();
        subject_addr
            .try_send(make_bind_message(ui_gateway))
            .unwrap();

        subject_addr
            .try_send(NodeFromUiMessage {
                client_id: 1234,
                body: UiStartOrder {}.tmb(4321),
            })
            .unwrap();

        System::current().stop();
        system.run();
        let launch_params = launch_params_arc.lock().unwrap();
        assert_eq!(*launch_params, vec![HashMap::from_iter(vec![
            ("db-password", "goober"),
            ("dns-servers", "1.1.1.1"),
        ].into_iter().map(|(n, v)| (n.to_string(), v.to_string())))]);
        let ui_gateway_recording = ui_gateway_recording_arc.lock().unwrap();
        let record = ui_gateway_recording
            .get_record::<NodeToUiMessage>(0)
            .clone();
        assert_eq!(record.target, ClientId(1234));
        let (payload, context_id): (UiStartResponse, u64) =
            UiStartResponse::fmb(record.body).unwrap();
        assert_eq!(context_id, 4321);
        assert_eq!(
            payload,
            UiStartResponse {
                new_process_id: 2345,
                redirect_ui_port: 5432
            }
        );
    }

    #[test]
    fn accepts_start_order_launches_and_replies_failure() {
        let (ui_gateway, _, ui_gateway_recording_arc) = make_recorder();
        let launcher = LauncherMock::new()
            .launch_result(Err("booga".to_string()));
        let system = System::new("test");
        let mut subject = Daemon::new(Box::new(launcher));
        subject
            .params
            .insert("db-password".to_string(), "goober".to_string());
        let subject_addr = subject.start();
        subject_addr
            .try_send(make_bind_message(ui_gateway))
            .unwrap();

        subject_addr
            .try_send(NodeFromUiMessage {
                client_id: 1234,
                body: UiStartOrder {}.tmb(4321),
            })
            .unwrap();

        System::current().stop();
        system.run();
        let ui_gateway_recording = ui_gateway_recording_arc.lock().unwrap();
        let record = ui_gateway_recording
            .get_record::<NodeToUiMessage>(0)
            .clone();
        assert_eq!(record.target, ClientId(1234));
        let (code, message) = record.body.payload.err().unwrap();
        assert_eq! (code, NODE_LAUNCH_ERROR);
        assert_eq! (message, "Could not launch Node: booga".to_string());
    }
}
