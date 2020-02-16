// Copyright (c) 2019-2020, MASQ (https://masq.ai). All rights reserved.

pub mod daemon_initializer;
pub mod launch_verifier;
mod launch_verifier_mock;
mod launcher;

use crate::sub_lib::logger::Logger;
use crate::sub_lib::utils::NODE_MAILBOX_CAPACITY;
use actix::Recipient;
use actix::{Actor, Context, Handler, Message};
use masq_lib::messages::UiMessageError::UnexpectedMessage;
use masq_lib::messages::{
    FromMessageBody, ToMessageBody, UiMessageError, UiRedirect, UiSetup, UiSetupValue,
    UiStartOrder, UiStartResponse, NODE_LAUNCH_ERROR, NODE_NOT_RUNNING_ERROR,
};
use masq_lib::ui_gateway::MessagePath::{OneWay, TwoWay};
use masq_lib::ui_gateway::MessageTarget::ClientId;
use masq_lib::ui_gateway::{MessageBody, NodeFromUiMessage, NodeToUiMessage};
use std::collections::HashMap;
use std::iter::FromIterator;
use std::sync::mpsc::{Receiver, Sender};

pub struct Recipients {
    ui_gateway_from_sub: Recipient<NodeFromUiMessage>,
    ui_gateway_to_sub: Recipient<NodeToUiMessage>,
    from_ui_subs: Vec<Recipient<NodeFromUiMessage>>,
    bind_message_subs: Vec<Recipient<DaemonBindMessage>>,
}

#[allow(clippy::type_complexity)]
pub trait ChannelFactory {
    fn make(
        &self,
    ) -> (
        Sender<HashMap<String, String>>,
        Receiver<HashMap<String, String>>,
    );
}

#[derive(Default)]
pub struct ChannelFactoryReal {}

impl ChannelFactoryReal {
    pub fn new() -> ChannelFactoryReal {
        ChannelFactoryReal {}
    }
}

#[derive(PartialEq, Debug)]
pub struct LaunchSuccess {
    pub new_process_id: u32,
    pub redirect_ui_port: u16,
}

pub trait Launcher {
    fn launch(&self, params: HashMap<String, String>) -> Result<Option<LaunchSuccess>, String>;
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
    node_process_id: Option<u32>,
    node_ui_port: Option<u16>,
    logger: Logger,
}

impl Actor for Daemon {
    type Context = Context<Daemon>;
}

impl Handler<DaemonBindMessage> for Daemon {
    type Result = ();

    fn handle(&mut self, msg: DaemonBindMessage, ctx: &mut Self::Context) -> Self::Result {
        debug!(&self.logger, "Handling DaemonBindMessage");
        ctx.set_mailbox_capacity(NODE_MAILBOX_CAPACITY);
        self.ui_gateway_sub = Some(msg.to_ui_message_recipient);
        debug!(&self.logger, "DaemonBindMessage handled");
    }
}

impl Handler<NodeFromUiMessage> for Daemon {
    type Result = ();

    fn handle(&mut self, msg: NodeFromUiMessage, _ctx: &mut Self::Context) -> Self::Result {
        debug!(
            &self.logger,
            "Handing NodeFromUiMessage from client {}: {}", msg.client_id, msg.body.opcode
        );
        let client_id = msg.client_id;
        let opcode = msg.body.opcode.clone();
        // TODO: Gotta be a better way to arrange this code; but I'll wait until there are more than 2 choices
        let result: Result<(UiSetup, u64), UiMessageError> = UiSetup::fmb(msg.body.clone());
        match result {
            Ok((payload, context_id)) => self.handle_setup(client_id, context_id, payload),
            Err(UnexpectedMessage(_, _)) => {
                let result: Result<(UiStartOrder, u64), UiMessageError> =
                    UiStartOrder::fmb(msg.body.clone());
                match result {
                    Ok((_, context_id)) => self.handle_start_order(client_id, context_id),
                    Err(UnexpectedMessage(_, _)) => {
                        self.handle_unexpected_message(msg.client_id, msg.body);
                    }
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
        debug!(&self.logger, "NodeFromUiMessage handled");
    }
}

impl Daemon {
    pub fn new(seed_params: &HashMap<String, String>, launcher: Box<dyn Launcher>) -> Daemon {
        let mut params = HashMap::new();
        params.insert("dns-servers".to_string(), "1.1.1.1".to_string()); // TODO: This should default to the system DNS value before subversion.
        #[cfg(not(target_os = "windows"))]
        let transferred_keys = vec![
            "chain",
            "config-file",
            "data-directory",
            "db-password",
            "real-user",
        ];
        #[cfg(target_os = "windows")]
        let transferred_keys = vec!["chain", "config-file", "data-directory", "db-password"];
        transferred_keys.into_iter().for_each(|key| {
            if let Some(value) = seed_params.get(key) {
                params.insert(key.to_string(), value.clone());
            }
        });
        Daemon {
            launcher,
            params,
            ui_gateway_sub: None,
            node_process_id: None,
            node_ui_port: None,
            logger: Logger::new("Daemon"),
        }
    }

    pub fn get_default_params() -> HashMap<String, String> {
        let schema = crate::node_configurator::node_configurator_initialization::app();
        schema
            .p
            .opts
            .iter()
            .flat_map(|opt| {
                let name = opt.b.name.to_string();
                #[cfg(target_os = "windows")]
                {
                    if &name == "real-user" {
                        return None;
                    }
                }
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
        self.params.extend(params.into_iter());
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
            Ok(Some(success)) => {
                self.node_process_id = Some(success.new_process_id);
                self.node_ui_port = Some(success.redirect_ui_port);
                self.respond_to_ui(
                    client_id,
                    UiStartResponse {
                        new_process_id: success.new_process_id,
                        redirect_ui_port: success.redirect_ui_port,
                    }
                    .tmb(context_id),
                )
            }
            Ok(None) => (),
            Err(s) => self.respond_to_ui(
                client_id,
                MessageBody {
                    opcode: "start".to_string(),
                    path: TwoWay(context_id),
                    payload: Err((NODE_LAUNCH_ERROR, format!("Could not launch Node: {}", s))),
                },
            ),
        }
    }

    fn handle_unexpected_message(&mut self, client_id: u64, body: MessageBody) {
        match self.node_ui_port {
            Some(port) => {
                info!(
                    &self.logger,
                    "Daemon is redirecting {} message from UI {} Node at port {}",
                    body.opcode,
                    client_id,
                    port
                );
                self.ui_gateway_sub
                    .as_ref()
                    .expect("UiGateway is unbound")
                    .try_send(NodeToUiMessage {
                        target: ClientId(client_id),
                        body: UiRedirect {
                            port,
                            opcode: body.opcode,
                            context_id: match body.path {
                                OneWay => None,
                                TwoWay(context_id) => Some(context_id),
                            },
                            payload: match body.payload {
                                Ok(json) => json,
                                Err((_code, _message)) => unimplemented!(),
                            },
                        }
                        .tmb(0),
                    })
                    .expect("UiGateway is dead")
            }
            None => {
                error!(
                    &self.logger,
                    "Daemon is sending redirect error for {} message to UI {}: Node is not running",
                    body.opcode,
                    client_id
                );
                self.ui_gateway_sub
                    .as_ref()
                    .expect("UiGateway is unbound")
                    .try_send(NodeToUiMessage {
                        target: ClientId(client_id),
                        body: MessageBody {
                            opcode: "redirect".to_string(),
                            path: OneWay,
                            payload: Err((
                                NODE_NOT_RUNNING_ERROR,
                                format!(
                                    "Cannot handle {} request: Node is not running",
                                    body.opcode
                                ),
                            )),
                        },
                    })
                    .expect("UiGateway is dead")
            }
        }
    }

    fn respond_to_ui(&self, client_id: u64, body: MessageBody) {
        self.ui_gateway_sub
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
    use crate::daemon::LaunchSuccess;
    use crate::test_utils::recorder::{make_recorder, Recorder};
    use actix::System;
    use masq_lib::messages::{
        UiFinancialsRequest, UiRedirect, UiSetup, UiSetupValue, UiShutdownRequest, UiStartOrder,
        UiStartResponse, NODE_LAUNCH_ERROR, NODE_NOT_RUNNING_ERROR,
    };
    use std::cell::RefCell;
    use std::collections::HashSet;
    use std::sync::{Arc, Mutex};

    struct LauncherMock {
        launch_params: Arc<Mutex<Vec<HashMap<String, String>>>>,
        launch_results: RefCell<Vec<Result<Option<LaunchSuccess>, String>>>,
    }

    impl Launcher for LauncherMock {
        fn launch(&self, params: HashMap<String, String>) -> Result<Option<LaunchSuccess>, String> {
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

        fn launch_result(self, result: Result<Option<LaunchSuccess>, String>) -> Self {
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
    fn accepts_filled_out_config_and_initializes_setup() {
        let mut seed_params = HashMap::new();
        seed_params.insert("chain".to_string(), "ropsten".to_string());
        seed_params.insert("config-file".to_string(), "non_default.toml".to_string());
        seed_params.insert("data-directory".to_string(), "non_default_data".to_string());
        seed_params.insert("db-password".to_string(), "booga".to_string());
        seed_params.insert(
            "real-user".to_string(),
            "123:456:non_default_home".to_string(),
        );
        seed_params.insert("ui-port".to_string(), "4444".to_string()); // this should be ignored

        let subject = Daemon::new(&seed_params, Box::new(LauncherMock::new()));

        assert_eq!(subject.params.get("chain").unwrap(), "ropsten");
        assert_eq!(
            subject.params.get("config-file").unwrap(),
            "non_default.toml"
        );
        assert_eq!(
            subject.params.get("data-directory").unwrap(),
            "non_default_data"
        );
        assert_eq!(subject.params.get("db-password").unwrap(), "booga");
        #[cfg(not(target_os = "windows"))]
        assert_eq!(
            subject.params.get("real-user").unwrap(),
            "123:456:non_default_home"
        );
        #[cfg(target_os = "windows")]
        assert_eq!(subject.params.get("real-user"), None,);
        assert_eq!(subject.params.get("ui-port"), None);
        assert_eq!(subject.params.get("crash-point"), None);
    }

    #[test]
    fn accepts_empty_setup_and_returns_defaults() {
        let (ui_gateway, _, ui_gateway_recording_arc) = make_recorder();
        let system = System::new("test");
        let subject = Daemon::new(&HashMap::new(), Box::new(LauncherMock::new()));
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
        let mut expected_pairs: HashSet<(String, String)> =
            Daemon::get_default_params().into_iter().collect();
        expected_pairs.insert(("dns-servers".to_string(), "1.1.1.1".to_string()));

        assert_eq!(actual_pairs, expected_pairs);
    }

    #[test]
    fn accepts_full_setup_and_returns_settings_then_remembers_them() {
        let (ui_gateway, _, ui_gateway_recording_arc) = make_recorder();
        let system = System::new("test");
        let subject = Daemon::new(&HashMap::new(), Box::new(LauncherMock::new()));
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
        let mut expected_pairs = Daemon::get_default_params();
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
        let subject = Daemon::new(&HashMap::new(), Box::new(LauncherMock::new()));
        let subject_addr = subject.start();
        subject_addr
            .try_send(make_bind_message(ui_gateway))
            .unwrap();

        subject_addr
            .try_send(NodeFromUiMessage {
                client_id: 1234,
                body: UiSetup {
                    values: vec![UiSetupValue::new("dns-servers", "192.168.0.1")],
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
        let mut expected_pairs = Daemon::get_default_params();
        expected_pairs.insert("dns-servers".to_string(), "192.168.0.1".to_string());

        assert_eq!(actual_pairs, expected_pairs);
    }

    #[test]
    fn accepts_start_order_launches_and_replies_parent_success() {
        let (ui_gateway, _, ui_gateway_recording_arc) = make_recorder();
        let launch_params_arc = Arc::new(Mutex::new(vec![]));
        let launcher = LauncherMock::new()
            .launch_params(&launch_params_arc)
            .launch_result(Ok(Some(LaunchSuccess {
                new_process_id: 2345,
                redirect_ui_port: 5432,
            })));
        let system = System::new("test");
        let mut subject = Daemon::new(&HashMap::new(), Box::new(launcher));
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
        assert_eq!(
            *launch_params,
            vec![HashMap::from_iter(
                vec![("db-password", "goober"), ("dns-servers", "1.1.1.1"),]
                    .into_iter()
                    .map(|(n, v)| (n.to_string(), v.to_string()))
            )]
        );
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
    fn accepts_start_order_launches_and_replies_child_success() {
        let (ui_gateway, _, ui_gateway_recording_arc) = make_recorder();
        let launcher = LauncherMock::new().launch_result(Ok(None));
        let system = System::new("test");
        let mut subject = Daemon::new(&HashMap::new(), Box::new(launcher));
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
        assert_eq!(ui_gateway_recording.len(), 0);
    }

    #[test]
    fn accepts_start_order_launches_and_replies_failure() {
        let (ui_gateway, _, ui_gateway_recording_arc) = make_recorder();
        let launcher = LauncherMock::new().launch_result(Err("booga".to_string()));
        let system = System::new("test");
        let mut subject = Daemon::new(&HashMap::new(), Box::new(launcher));
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
        assert_eq!(code, NODE_LAUNCH_ERROR);
        assert_eq!(message, "Could not launch Node: booga".to_string());
    }

    #[test]
    fn sets_process_id_and_node_ui_port_upon_node_launch_success() {
        let (ui_gateway, _, _) = make_recorder();
        let launcher = LauncherMock::new().launch_result(Ok(Some(LaunchSuccess {
            new_process_id: 54321,
            redirect_ui_port: 7777,
        })));
        let mut subject = Daemon::new(&HashMap::new(), Box::new(launcher));
        subject.ui_gateway_sub = Some(ui_gateway.start().recipient());

        subject.handle_start_order(1234, 2345);

        assert_eq!(subject.node_process_id, Some(54321));
        assert_eq!(subject.node_ui_port, Some(7777));
    }

    #[test]
    fn accepts_financials_request_after_start_and_returns_redirect() {
        let (ui_gateway, _, ui_gateway_recording_arc) = make_recorder();
        let system = System::new("test");
        let mut subject = Daemon::new(&HashMap::new(), Box::new(LauncherMock::new()));
        subject.node_ui_port = Some(7777);
        let subject_addr = subject.start();
        subject_addr
            .try_send(make_bind_message(ui_gateway))
            .unwrap();
        let body: MessageBody = UiFinancialsRequest {
            payable_minimum_amount: 0,
            payable_maximum_age: 0,
            receivable_minimum_amount: 0,
            receivable_maximum_age: 0,
        }
        .tmb(4321);

        subject_addr
            .try_send(NodeFromUiMessage {
                client_id: 1234,
                body: body.clone(),
            })
            .unwrap();

        System::current().stop();
        system.run();
        let ui_gateway_recording = ui_gateway_recording_arc.lock().unwrap();
        let record = ui_gateway_recording
            .get_record::<NodeToUiMessage>(0)
            .clone();
        assert_eq!(record.target, ClientId(1234));
        assert_eq!(record.body.path, OneWay);
        let (payload, context_id): (UiRedirect, u64) = UiRedirect::fmb(record.body).unwrap();
        assert_eq!(context_id, 0);
        assert_eq!(
            payload,
            UiRedirect {
                port: 7777,
                opcode: body.opcode,
                context_id: Some(4321),
                payload: body.payload.unwrap(),
            }
        );
    }

    #[test]
    fn accepts_shutdown_order_after_start_and_returns_redirect() {
        let (ui_gateway, _, ui_gateway_recording_arc) = make_recorder();
        let system = System::new("test");
        let mut subject = Daemon::new(&HashMap::new(), Box::new(LauncherMock::new()));
        subject.node_ui_port = Some(7777);
        let subject_addr = subject.start();
        subject_addr
            .try_send(make_bind_message(ui_gateway))
            .unwrap();
        let body: MessageBody = UiShutdownRequest {}.tmb(4321); // Context ID is irrelevant

        subject_addr
            .try_send(NodeFromUiMessage {
                client_id: 1234,
                body: body.clone(),
            })
            .unwrap();

        System::current().stop();
        system.run();
        let ui_gateway_recording = ui_gateway_recording_arc.lock().unwrap();
        let record = ui_gateway_recording
            .get_record::<NodeToUiMessage>(0)
            .clone();
        assert_eq!(record.target, ClientId(1234));
        assert_eq!(record.body.path, OneWay);
        let (payload, context_id): (UiRedirect, u64) = UiRedirect::fmb(record.body).unwrap();
        assert_eq!(context_id, 0);
        assert_eq!(
            payload,
            UiRedirect {
                port: 7777,
                opcode: body.opcode,
                context_id: None,
                payload: body.payload.unwrap(),
            }
        );
    }

    #[test]
    fn accepts_financials_request_before_start_and_returns_error() {
        let (ui_gateway, _, ui_gateway_recording_arc) = make_recorder();
        let system = System::new("test");
        let mut subject = Daemon::new(&HashMap::new(), Box::new(LauncherMock::new()));
        subject.node_ui_port = None;
        let subject_addr = subject.start();
        subject_addr
            .try_send(make_bind_message(ui_gateway))
            .unwrap();
        let body: MessageBody = UiFinancialsRequest {
            payable_minimum_amount: 0,
            payable_maximum_age: 0,
            receivable_minimum_amount: 0,
            receivable_maximum_age: 0,
        }
        .tmb(4321);

        subject_addr
            .try_send(NodeFromUiMessage {
                client_id: 1234,
                body: body.clone(),
            })
            .unwrap();

        System::current().stop();
        system.run();
        let ui_gateway_recording = ui_gateway_recording_arc.lock().unwrap();
        let record = ui_gateway_recording
            .get_record::<NodeToUiMessage>(0)
            .clone();
        assert_eq!(record.target, ClientId(1234));
        assert_eq!(
            record.body.payload,
            Err((
                NODE_NOT_RUNNING_ERROR,
                "Cannot handle financials request: Node is not running".to_string()
            ))
        );
    }
}
