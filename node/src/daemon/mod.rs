// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

pub mod crash_notification;
pub mod daemon_initializer;
pub mod dns_inspector;
pub mod launch_verifier;
mod launcher;
mod setup_reporter;

#[cfg(test)]
mod mocks;

use crate::daemon::crash_notification::CrashNotification;
use crate::daemon::launch_verifier::{VerifierTools, VerifierToolsReal};
use crate::daemon::setup_reporter::{SetupCluster, SetupReporter, SetupReporterReal};
use crate::node_configurator::DirsWrapperReal;
use crate::sub_lib::utils::NODE_MAILBOX_CAPACITY;
use actix::Recipient;
use actix::{Actor, Context, Handler, Message};
use crossbeam_channel::{Receiver, Sender};
use itertools::Itertools;
use lazy_static::lazy_static;
use masq_lib::constants::{NODE_ALREADY_RUNNING_ERROR, NODE_LAUNCH_ERROR, NODE_NOT_RUNNING_ERROR};
use masq_lib::logger::Logger;
use masq_lib::messages::UiSetupResponseValueStatus::{Configured, Set};
use masq_lib::messages::{
    FromMessageBody, ToMessageBody, UiNodeCrashedBroadcast, UiRedirect, UiSetupBroadcast,
    UiSetupRequest, UiSetupResponse, UiSetupResponseValue, UiStartOrder, UiStartResponse,
    UiUndeliveredFireAndForget,
};
use masq_lib::shared_schema::ConfiguratorError;
use masq_lib::ui_gateway::MessagePath::{Conversation, FireAndForget};
use masq_lib::ui_gateway::MessageTarget::ClientId;
use masq_lib::ui_gateway::{
    MessageBody, MessagePath, MessageTarget, NodeFromUiMessage, NodeToUiMessage,
};
use std::collections::{HashMap, HashSet};

pub struct Recipients {
    ui_gateway_from_sub: Recipient<NodeFromUiMessage>,
    ui_gateway_to_sub: Recipient<NodeToUiMessage>,
    from_ui_subs: Vec<Recipient<NodeFromUiMessage>>,
    crash_notification_sub: Recipient<CrashNotification>,
    bind_message_subs: Vec<Recipient<DaemonBindMessage>>,
}

lazy_static! {
    static ref CENSORABLES: HashMap<String, usize> = {
        vec![
            ("db-password".to_string(), 16),
            ("consuming-private-key".to_string(), 64),
        ]
        .into_iter()
        .collect()
    };
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

#[derive(PartialEq, Eq, Debug)]
pub struct LaunchSuccess {
    pub new_process_id: u32,
    pub redirect_ui_port: u16,
}

pub trait Launcher {
    fn launch(
        &self,
        params: HashMap<String, String>,
        crashed_recipient: Recipient<CrashNotification>,
    ) -> Result<Option<LaunchSuccess>, String>;
}

#[derive(Message, PartialEq, Eq, Clone)]
pub struct DaemonBindMessage {
    pub to_ui_message_recipient: Recipient<NodeToUiMessage>, // for everybody to send UI-bound messages to
    pub from_ui_message_recipient: Recipient<NodeFromUiMessage>, // for the WebsocketSupervisor to send inbound UI messages to the UiGateway
    pub from_ui_message_recipients: Vec<Recipient<NodeFromUiMessage>>, // for the UiGateway to relay inbound UI messages to everybody
    pub crash_notification_recipient: Recipient<CrashNotification>, // the Daemon itself, for crash notifications
}

pub struct Daemon {
    launcher: Box<dyn Launcher>,
    params: SetupCluster,
    ui_gateway_sub: Option<Recipient<NodeToUiMessage>>,
    crash_notification_sub: Option<Recipient<CrashNotification>>,
    node_process_id: Option<u32>,
    node_ui_port: Option<u16>,
    verifier_tools: Box<dyn VerifierTools>,
    setup_reporter: Box<dyn SetupReporter>,
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
        self.crash_notification_sub = Some(msg.crash_notification_recipient);
        debug!(&self.logger, "DaemonBindMessage handled");
    }
}

impl Handler<NodeFromUiMessage> for Daemon {
    type Result = ();

    fn handle(&mut self, msg: NodeFromUiMessage, _ctx: &mut Self::Context) -> Self::Result {
        debug!(&self.logger, "Handing NodeFromUiMessage:\n  {:?}", msg);
        let client_id = msg.client_id;
        if let Ok((setup_request, context_id)) = UiSetupRequest::fmb(msg.body.clone()) {
            self.handle_setup(client_id, context_id, setup_request);
        } else if let Ok((_, context_id)) = UiStartOrder::fmb(msg.body.clone()) {
            self.handle_start_order(client_id, context_id);
        } else {
            self.handle_unexpected_message(client_id, msg.body);
        }
        debug!(&self.logger, "NodeFromUiMessage handled");
    }
}

impl Handler<CrashNotification> for Daemon {
    type Result = ();

    fn handle(&mut self, msg: CrashNotification, _ctx: &mut Self::Context) -> Self::Result {
        debug!(&self.logger, "Handling CrashNotification");
        self.handle_crash_notification(msg);
        debug!(&self.logger, "CrashNotification handled");
    }
}

impl Daemon {
    pub fn new(launcher: Box<dyn Launcher>) -> Daemon {
        Daemon {
            launcher,
            params: HashMap::new(),
            ui_gateway_sub: None,
            crash_notification_sub: None,
            node_process_id: None,
            node_ui_port: None,
            verifier_tools: Box::new(VerifierToolsReal::new()),
            setup_reporter: Box::new(SetupReporterReal::new(Box::new(DirsWrapperReal::default()))),
            logger: Logger::new("Daemon"),
        }
    }

    fn handle_setup(&mut self, client_id: u64, context_id: u64, payload: UiSetupRequest) {
        if self.port_if_node_is_running().is_some() {
            let body =
                UiSetupResponse::new(true, self.censored_params(), ConfiguratorError::new(vec![]))
                    .tmb(context_id);
            let target = MessageTarget::ClientId(client_id);
            self.send_ui_message(body, target);
        } else {
            let incoming_setup = payload.values;
            let existing_setup = self.params.clone();
            match self
                .setup_reporter
                .get_modified_setup(existing_setup, incoming_setup)
            {
                Ok(setup) => self.change_setup_and_notify(
                    setup,
                    ConfiguratorError::new(vec![]),
                    client_id,
                    context_id,
                ),
                Err((lame_cluster, errors)) => {
                    self.change_setup_and_notify(lame_cluster, errors, client_id, context_id)
                }
            }
        };
    }

    fn handle_start_order(&mut self, client_id: u64, context_id: u64) {
        match self.port_if_node_is_running() {
            Some(_) => self.respond_to_ui(
                client_id,
                MessageBody {
                    opcode: "start".to_string(),
                    path: Conversation(context_id),
                    payload: Err((
                        NODE_ALREADY_RUNNING_ERROR,
                        "Could not launch Node: already running".to_string(),
                    )),
                },
            ),
            None => match self.launcher.launch(
                self.params
                    .iter()
                    .filter(|(_, v)| v.status == Set || v.status == Configured)
                    .map(|(k, v)| (k.to_string(), v.value.to_string()))
                    .collect(),
                self.crash_notification_sub.clone().expect("Daemon unbound"),
            ) {
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
                        path: Conversation(context_id),
                        payload: Err((NODE_LAUNCH_ERROR, format!("Could not launch Node: {}", s))),
                    },
                ),
            },
        }
    }

    fn handle_unexpected_message(&mut self, client_id: u64, body: MessageBody) {
        match self.port_if_node_is_running() {
            Some(port) => {
                info!(
                    &self.logger,
                    "Daemon is redirecting {} message from UI {} Node at port {}",
                    body.opcode,
                    client_id,
                    port
                );
                self.send_ui_message(
                    UiRedirect {
                        port,
                        opcode: body.opcode,
                        context_id: match body.path {
                            FireAndForget => None,
                            Conversation(context_id) => Some(context_id),
                        },
                        payload: match body.payload {
                            Ok(json) => json,
                            Err((_code, _message)) => unimplemented!(),
                        },
                    }
                    .tmb(0),
                    ClientId(client_id),
                );
            }
            None => self.send_node_is_not_running_error(client_id, body.opcode, body.path),
        }
    }

    fn handle_crash_notification(&mut self, msg: CrashNotification) {
        if self.node_ui_port.is_some() || self.node_process_id.is_some() {
            self.node_process_id = None;
            self.node_ui_port = None;
            self.send_ui_message(
                UiNodeCrashedBroadcast {
                    process_id: msg.process_id,
                    crash_reason: msg.analyze(),
                }
                .tmb(0),
                MessageTarget::AllClients,
            );
        }
    }

    fn port_if_node_is_running(&mut self) -> Option<u16> {
        if let Some(process_id) = self.node_process_id {
            if self.verifier_tools.process_is_running(process_id) {
                Some(
                    self.node_ui_port
                        .expect("Internal error: node_process_id is set but node_ui_port is not"),
                )
            } else {
                self.node_process_id = None;
                self.node_ui_port = None;
                None
            }
        } else {
            None
        }
    }

    fn send_node_is_not_running_error(&self, client_id: u64, opcode: String, path: MessagePath) {
        error!(
            &self.logger,
            "Daemon is sending redirect error for {} message to UI {}: Node is not running",
            &opcode,
            client_id
        );
        let body = match path {
            Conversation(_) => MessageBody {
                opcode: opcode.clone(),
                path,
                payload: Err((
                    NODE_NOT_RUNNING_ERROR,
                    format!("Cannot handle {} request: Node is not running", opcode),
                )),
            },

            FireAndForget => UiUndeliveredFireAndForget { opcode }.tmb(0),
        };
        let target = ClientId(client_id);
        self.send_ui_message(body, target);
    }

    fn respond_to_ui(&self, client_id: u64, body: MessageBody) {
        self.send_ui_message(body, ClientId(client_id));
    }

    fn change_setup_and_notify(
        &mut self,
        new_setup: SetupCluster,
        errors: ConfiguratorError,
        client_id: u64,
        context_id: u64,
    ) {
        let body_target_pairs = match Self::compare_setup_clusters(&self.params, &new_setup) {
            Err(_) => {
                let originally_empty = self.params.is_empty();
                self.params = new_setup;
                let mut pairs = vec![(
                    UiSetupResponse::new(false, self.censored_params(), errors.clone())
                        .tmb(context_id),
                    MessageTarget::ClientId(client_id),
                )];
                if !originally_empty {
                    pairs.push((
                        UiSetupBroadcast::new(false, self.censored_params(), errors).tmb(0),
                        MessageTarget::AllExcept(client_id),
                    ));
                };
                pairs
            }
            Ok(_) => vec![(
                UiSetupResponse::new(false, self.censored_params(), errors).tmb(context_id),
                MessageTarget::ClientId(client_id),
            )],
        };
        body_target_pairs
            .into_iter()
            .for_each(|(body, target)| self.send_ui_message(body, target));
    }

    fn censored_params(&self) -> SetupCluster {
        self.params
            .clone()
            .into_iter()
            .map(|(name, uisrv)| match CENSORABLES.get(&name) {
                Some(length) => (
                    name,
                    UiSetupResponseValue::new(&uisrv.name, &"*".repeat(*length), uisrv.status),
                ),
                None => (name, uisrv),
            })
            .collect()
    }

    fn send_ui_message(&self, body: MessageBody, target: MessageTarget) {
        self.ui_gateway_sub
            .as_ref()
            .expect("UiGateway is unbound")
            .try_send(NodeToUiMessage { target, body })
            .expect("UiGateway is dead")
    }

    fn compare_setup_clusters(left: &SetupCluster, right: &SetupCluster) -> Result<(), String> {
        let mut left_not_right = HashSet::new();
        let mut unequal = HashSet::new();
        let mut right_not_left: HashSet<String> = right.keys().cloned().collect();
        left.iter().for_each(|(k, v_left)| match right.get(k) {
            Some(v_right) => {
                let _ = right_not_left.remove(k);
                if v_right.value != v_left.value {
                    unequal.insert(k);
                }
            }
            None => {
                left_not_right.insert(k);
            }
        });
        if left_not_right.is_empty() && unequal.is_empty() && right_not_left.is_empty() {
            Ok(())
        } else {
            let msg_parts = vec![
                if left_not_right.is_empty() {
                    None
                } else {
                    Some(format!("Keys in left but not right: {:?}", left_not_right))
                },
                if unequal.is_empty() {
                    None
                } else {
                    Some(format!("Keys with unequal values: {:?}", unequal))
                },
                if right_not_left.is_empty() {
                    None
                } else {
                    Some(format!("Keys in right but not left: {:?}", right_not_left))
                },
            ];
            let msg = msg_parts.into_iter().flatten().join("; ");
            Err(msg)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::crash_notification::CrashNotification;
    use crate::daemon::mocks::VerifierToolsMock;
    use crate::daemon::setup_reporter::{setup_cluster_from, SetupCluster};
    use crate::daemon::LaunchSuccess;
    use crate::test_utils::recorder::make_recorder;
    use crate::test_utils::unshared_test_utils::make_daemon_bind_message;
    use actix::System;
    use masq_lib::constants::{
        NODE_ALREADY_RUNNING_ERROR, NODE_LAUNCH_ERROR, NODE_NOT_RUNNING_ERROR,
    };
    use masq_lib::messages::UiSetupResponseValueStatus::{Blank, Required, Set};
    use masq_lib::messages::{
        CrashReason, UiFinancialsRequest, UiNodeCrashedBroadcast, UiRedirect, UiSetupBroadcast,
        UiSetupRequest, UiSetupRequestValue, UiSetupResponse, UiSetupResponseValue,
        UiSetupResponseValueStatus, UiShutdownRequest, UiStartOrder, UiStartResponse,
    };
    use masq_lib::shared_schema::ConfiguratorError;
    use masq_lib::test_utils::environment_guard::{ClapGuard, EnvironmentGuard};
    use masq_lib::test_utils::utils::{ensure_node_home_directory_exists, TEST_DEFAULT_CHAIN};
    use masq_lib::ui_gateway::MessageTarget::AllExcept;
    use masq_lib::ui_gateway::{MessagePath, MessageTarget};
    use std::cell::RefCell;
    use std::collections::HashSet;
    use std::iter::FromIterator;
    use std::sync::{Arc, Mutex};

    #[test]
    fn constants_have_correct_values() {
        let censorables_expected: HashMap<String, usize> = {
            vec![
                ("db-password".to_string(), 16),
                ("consuming-private-key".to_string(), 64),
            ]
            .into_iter()
            .collect()
        };

        assert_eq!(*CENSORABLES, censorables_expected);
    }

    struct LauncherMock {
        launch_params: Arc<Mutex<Vec<(HashMap<String, String>, Recipient<CrashNotification>)>>>,
        launch_results: RefCell<Vec<Result<Option<LaunchSuccess>, String>>>,
    }

    impl Launcher for LauncherMock {
        fn launch(
            &self,
            params: HashMap<String, String>,
            crashed_recipient: Recipient<CrashNotification>,
        ) -> Result<Option<LaunchSuccess>, String> {
            self.launch_params
                .lock()
                .unwrap()
                .push((params, crashed_recipient));
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

        fn launch_params(
            mut self,
            params: &Arc<Mutex<Vec<(HashMap<String, String>, Recipient<CrashNotification>)>>>,
        ) -> Self {
            self.launch_params = params.clone();
            self
        }

        fn launch_result(self, result: Result<Option<LaunchSuccess>, String>) -> Self {
            self.launch_results.borrow_mut().push(result);
            self
        }
    }

    struct SetupReporterMock {
        get_modified_setup_params: Arc<Mutex<Vec<(SetupCluster, Vec<UiSetupRequestValue>)>>>,
        get_modified_setup_results:
            RefCell<Vec<Result<SetupCluster, (SetupCluster, ConfiguratorError)>>>,
    }

    impl SetupReporter for SetupReporterMock {
        fn get_modified_setup(
            &self,
            existing_setup: SetupCluster,
            incoming_setup: Vec<UiSetupRequestValue>,
        ) -> Result<SetupCluster, (SetupCluster, ConfiguratorError)> {
            self.get_modified_setup_params
                .lock()
                .unwrap()
                .push((existing_setup, incoming_setup));
            self.get_modified_setup_results.borrow_mut().remove(0)
        }
    }

    impl SetupReporterMock {
        fn new() -> Self {
            Self {
                get_modified_setup_params: Arc::new(Mutex::new(vec![])),
                get_modified_setup_results: RefCell::new(vec![]),
            }
        }

        fn _get_modified_setup_params(
            mut self,
            params: &Arc<Mutex<Vec<(SetupCluster, Vec<UiSetupRequestValue>)>>>,
        ) -> Self {
            self.get_modified_setup_params = params.clone();
            self
        }

        fn get_modified_setup_result(
            self,
            result: Result<SetupCluster, (SetupCluster, ConfiguratorError)>,
        ) -> Self {
            self.get_modified_setup_results.borrow_mut().push(result);
            self
        }
    }

    fn make_setup_cluster(items: Vec<(&str, &str, UiSetupResponseValueStatus)>) -> SetupCluster {
        items
            .into_iter()
            .map(|(name, value, status)| {
                (
                    name.to_string(),
                    UiSetupResponseValue::new(name, value, status),
                )
            })
            .collect()
    }

    #[test]
    fn censorship_works() {
        let mut subject = Daemon::new(Box::new(LauncherMock::new()));
        subject.params = make_setup_cluster(vec![
            ("one-non-censorable", "one value", Set),
            ("db-password", "super-secret value", Configured),
            ("consuming-private-key", "another super-secret value", Blank),
            ("another-non-censorable", "another value", Required),
        ]);

        let result = subject.censored_params();

        assert_eq!(
            result,
            make_setup_cluster(vec![
                ("one-non-censorable", "one value", Set),
                ("db-password", "****************", Configured),
                (
                    "consuming-private-key",
                    "****************************************************************",
                    Blank
                ),
                ("another-non-censorable", "another value", Required),
            ])
        );
    }

    #[test]
    fn accepts_setup_when_node_is_running_and_returns_existing_setup() {
        let (ui_gateway, _, ui_gateway_recording_arc) = make_recorder();
        let verifier_tools = VerifierToolsMock::new().process_is_running_result(true);
        let setup_reporter = SetupReporterMock::new(); // will panic if called
        let system = System::new("test");
        let mut subject = Daemon::new(Box::new(LauncherMock::new()));
        subject.verifier_tools = Box::new(verifier_tools);
        subject.setup_reporter = Box::new(setup_reporter);
        subject.params = make_setup_cluster(vec![
            ("neighborhood-mode", "zero-hop", Set),
            ("consuming-private-key", "secret value", Set),
            ("db-password", "secret value", Set),
        ]);
        subject.node_process_id = Some(12345);
        subject.node_ui_port = Some(54321);
        let subject_addr = subject.start();
        subject_addr
            .try_send(make_daemon_bind_message(ui_gateway))
            .unwrap();

        subject_addr
            .try_send(NodeFromUiMessage {
                client_id: 1234,
                body: UiSetupRequest {
                    values: vec![UiSetupRequestValue::new("log-level", "trace")],
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
        let (payload, context_id): (UiSetupResponse, u64) =
            UiSetupResponse::fmb(record.body).unwrap();
        assert_eq!(context_id, 4321);
        assert_eq!(
            payload,
            UiSetupResponse {
                running: true,
                values: vec![
                    UiSetupResponseValue::new(
                        "consuming-private-key",
                        "****************************************************************",
                        Set
                    ),
                    UiSetupResponseValue::new("db-password", "****************", Set),
                    UiSetupResponseValue::new("neighborhood-mode", "zero-hop", Set),
                ],
                errors: vec![],
            }
        );
    }

    #[test]
    fn accepts_setup_when_node_is_not_running_and_returns_combined_setup() {
        let (ui_gateway, _, ui_gateway_recording_arc) = make_recorder();
        let verifier_tools = VerifierToolsMock::new().process_is_running_result(false);
        let combined_setup = make_setup_cluster(vec![
            ("neighborhood-mode", "zero-hop", Set),
            ("db-password", "secret value", Set),
            ("log-level", "trace", Set),
            ("consuming-private-key", "secret value", Set),
        ]);
        let setup_reporter = SetupReporterMock::new().get_modified_setup_result(Ok(combined_setup));
        let system = System::new("test");
        let mut subject = Daemon::new(Box::new(LauncherMock::new()));
        subject.verifier_tools = Box::new(verifier_tools);
        subject.setup_reporter = Box::new(setup_reporter);
        subject.params = make_setup_cluster(vec![
            ("neighborhood-mode", "zero-hop", Set),
            ("db-password", "secret value", Set),
        ]);
        subject.node_process_id = None;
        subject.node_ui_port = None;
        let subject_addr = subject.start();
        subject_addr
            .try_send(make_daemon_bind_message(ui_gateway))
            .unwrap();

        subject_addr
            .try_send(NodeFromUiMessage {
                client_id: 1234,
                body: UiSetupRequest {
                    values: vec![
                        UiSetupRequestValue::new("log-level", "trace"),
                        UiSetupRequestValue::new("consuming-private-key", "secret value"),
                    ],
                }
                .tmb(4321),
            })
            .unwrap();

        System::current().stop();
        system.run();
        let expected_combined_setup = vec![
            UiSetupResponseValue::new(
                "consuming-private-key",
                "****************************************************************",
                Set,
            ),
            UiSetupResponseValue::new("db-password", "****************", Set),
            UiSetupResponseValue::new("log-level", "trace", Set),
            UiSetupResponseValue::new("neighborhood-mode", "zero-hop", Set),
        ];
        let ui_gateway_recording = ui_gateway_recording_arc.lock().unwrap();
        let record = ui_gateway_recording
            .get_record::<NodeToUiMessage>(0)
            .clone();
        assert_eq!(record.target, ClientId(1234));
        let (payload, context_id): (UiSetupResponse, u64) =
            UiSetupResponse::fmb(record.body).unwrap();
        assert_eq!(context_id, 4321);
        assert_eq!(payload.running, false);
        assert_eq!(&payload.values, &expected_combined_setup,);
        let record = ui_gateway_recording
            .get_record::<NodeToUiMessage>(1)
            .clone();
        assert_eq!(record.target, AllExcept(1234));
        let (payload, context_id): (UiSetupBroadcast, u64) =
            UiSetupBroadcast::fmb(record.body).unwrap();
        assert_eq!(context_id, 0);
        assert_eq!(payload.running, false);
        assert_eq!(&payload.values, &expected_combined_setup);
    }

    #[test]
    fn setup_judges_node_not_running_when_port_and_pid_are_none_without_checking_os() {
        let home_dir = ensure_node_home_directory_exists(
            "daemon",
            "setup_judges_node_not_running_when_port_and_pid_are_none_without_checking_os",
        );
        let (ui_gateway, _, ui_gateway_recording_arc) = make_recorder();
        let system = System::new("test");
        let verifier_tools = VerifierToolsMock::new();
        let mut subject = Daemon::new(Box::new(LauncherMock::new()));
        subject.node_ui_port = None;
        subject.node_process_id = None;
        subject.verifier_tools = Box::new(verifier_tools);
        let subject_addr = subject.start();
        subject_addr
            .try_send(make_daemon_bind_message(ui_gateway))
            .unwrap();

        subject_addr
            .try_send(NodeFromUiMessage {
                client_id: 1234,
                body: UiSetupRequest {
                    values: vec![
                        UiSetupRequestValue::new("ip", "1.2.3.4"),
                        UiSetupRequestValue::new(
                            "data-directory",
                            format!("{:?}", home_dir).as_str(),
                        ),
                        UiSetupRequestValue::new(
                            "chain",
                            TEST_DEFAULT_CHAIN.rec().literal_identifier,
                        ),
                        UiSetupRequestValue::new("neighborhood-mode", "zero-hop"),
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
        let (payload, context_id): (UiSetupResponse, u64) =
            UiSetupResponse::fmb(record.body).unwrap();
        assert_eq!(context_id, 4321);
        assert_eq!(payload.running, false);
        let actual_pairs: Vec<(String, UiSetupResponseValue)> = payload
            .values
            .into_iter()
            .map(|value| (value.name.clone(), value))
            .collect();
        assert_eq!(
            actual_pairs.contains(&(
                "chain".to_string(),
                UiSetupResponseValue::new(
                    "chain",
                    TEST_DEFAULT_CHAIN.rec().literal_identifier,
                    Set
                )
            )),
            true
        );
    }

    #[test]
    fn setup_judges_node_not_running_when_port_and_pid_are_set_but_os_says_different() {
        let _clap_guard = ClapGuard::new();
        let data_dir = ensure_node_home_directory_exists(
            "daemon",
            "setup_judges_node_not_running_when_port_and_pid_are_set_but_os_says_different",
        );
        let (ui_gateway, _, ui_gateway_recording_arc) = make_recorder();
        let system = System::new("test");
        let verifier_tools = VerifierToolsMock::new().process_is_running_result(false); // only consulted once; second time, we already know
        let mut subject = Daemon::new(Box::new(LauncherMock::new()));
        subject.node_ui_port = Some(1234);
        subject.node_process_id = Some(4321);
        subject.verifier_tools = Box::new(verifier_tools);
        let subject_addr = subject.start();
        subject_addr
            .try_send(make_daemon_bind_message(ui_gateway))
            .unwrap();
        let msg = NodeFromUiMessage {
            client_id: 1234,
            body: UiSetupRequest {
                values: vec![
                    UiSetupRequestValue::new("blockchain-service-url", "https://booga.com"),
                    UiSetupRequestValue::new("data-directory", data_dir.to_str().unwrap()),
                    UiSetupRequestValue::new("chain", TEST_DEFAULT_CHAIN.rec().literal_identifier),
                    UiSetupRequestValue::new("neighborhood-mode", "zero-hop"),
                ],
            }
            .tmb(4321),
        };

        subject_addr.try_send(msg.clone()).unwrap(); // accepted because Node, thought to be up, turns out to be down
        subject_addr.try_send(msg.clone()).unwrap(); // accepted without asking because we already know Node is down

        System::current().stop();
        system.run();
        let ui_gateway_recording = ui_gateway_recording_arc.lock().unwrap();
        let get_record = |idx: usize| {
            ui_gateway_recording
                .get_record::<NodeToUiMessage>(idx)
                .clone()
        };
        let check_payload =
            |running: bool, values: Vec<UiSetupResponseValue>, errors: Vec<(String, String)>| {
                assert_eq!(running, false);
                let actual_pairs: HashSet<(String, String)> = values
                    .into_iter()
                    .map(|value| (value.name, value.value))
                    .collect();
                assert_eq!(
                    actual_pairs.contains(&(
                        "chain".to_string(),
                        TEST_DEFAULT_CHAIN.rec().literal_identifier.to_string()
                    )),
                    true
                );
                assert_eq!(errors, vec![]);
            };
        let record = get_record(0);
        assert_eq!(record.target, ClientId(1234));
        let (payload, context_id): (UiSetupResponse, u64) =
            UiSetupResponse::fmb(record.body).unwrap();
        assert_eq!(context_id, 4321);
        check_payload(payload.running, payload.values, payload.errors);
        let record = get_record(1);
        assert_eq!(record.target, ClientId(1234));
        let (payload, context_id): (UiSetupResponse, u64) =
            UiSetupResponse::fmb(record.body).unwrap();
        assert_eq!(context_id, 4321);
        check_payload(payload.running, payload.values, payload.errors);
    }

    #[test]
    fn handle_setup_handles_configuration_error() {
        let (ui_gateway, _, ui_gateway_recording_arc) = make_recorder();
        let lame_setup = vec![(
            "name".to_string(),
            UiSetupResponseValue::new("name", "value", Configured),
        )]
        .into_iter()
        .collect::<SetupCluster>();
        let mut subject = Daemon::new(Box::new(LauncherMock::new()));
        subject.setup_reporter =
            Box::new(SetupReporterMock::new().get_modified_setup_result(Err((
                lame_setup,
                ConfiguratorError::required("parameter", "message"),
            ))));
        let system = System::new("test");
        subject.ui_gateway_sub = Some(ui_gateway.start().recipient());

        subject.handle_setup(47, 74, UiSetupRequest::new(vec![]));

        System::current().stop();
        system.run();
        let ui_gateway_recording = ui_gateway_recording_arc.lock().unwrap();
        let message: &NodeToUiMessage = ui_gateway_recording.get_record(0);
        assert_eq!(
            *message,
            NodeToUiMessage {
                target: MessageTarget::ClientId(47),
                body: UiSetupResponse {
                    running: false,
                    values: vec![UiSetupResponseValue::new("name", "value", Configured)],
                    errors: vec![("parameter".to_string(), "message".to_string())]
                }
                .tmb(74),
            }
        );
    }

    #[test]
    fn handle_setup_responds_but_does_not_broadcast_if_setup_changes_from_nothing() {
        let (ui_gateway, _, ui_gateway_recording_arc) = make_recorder();
        let mut subject = Daemon::new(Box::new(LauncherMock::new()));
        subject.params.clear(); // nothing
        let existing_setup = subject.params.clone();
        let modified_setup = {
            let mut modified_setup = existing_setup.clone();
            modified_setup.insert(
                "additional-item".to_string(),
                UiSetupResponseValue::new("additional-item", "booga", Set),
            );
            modified_setup
        };
        subject.setup_reporter = Box::new(
            SetupReporterMock::new().get_modified_setup_result(Ok(modified_setup.clone())),
        );
        let system = System::new("test");
        subject.ui_gateway_sub = Some(ui_gateway.start().recipient());

        subject.handle_setup(47, 74, UiSetupRequest::new(vec![]));

        System::current().stop();
        system.run();
        let ui_gateway_recording = ui_gateway_recording_arc.lock().unwrap();
        let message: &NodeToUiMessage = ui_gateway_recording.get_record(0);
        assert_eq!(
            *message,
            NodeToUiMessage {
                target: MessageTarget::ClientId(47),
                body: UiSetupResponse {
                    running: false,
                    values: modified_setup
                        .iter()
                        .map(|(_, v)| v)
                        .map(|v| v.clone())
                        .collect(),
                    errors: vec![]
                }
                .tmb(74),
            }
        );
        assert_eq!(ui_gateway_recording.len(), 1);
    }

    #[test]
    fn handle_setup_responds_but_does_not_broadcast_if_setup_is_not_changed() {
        let (ui_gateway, _, ui_gateway_recording_arc) = make_recorder();
        let mut subject = Daemon::new(Box::new(LauncherMock::new()));
        subject.params.insert(
            "db-password".to_string(),
            UiSetupResponseValue::new("db-password", "secret value", Configured),
        ); // not nothing
           // Same value, different status
        let incoming_setup = vec![(
            "db-password".to_string(),
            UiSetupResponseValue::new("db-password", "secret value", Set),
        )]
        .into_iter()
        .collect();
        subject.setup_reporter =
            Box::new(SetupReporterMock::new().get_modified_setup_result(Ok(incoming_setup)));
        let system = System::new("test");
        subject.ui_gateway_sub = Some(ui_gateway.start().recipient());

        subject.handle_setup(47, 74, UiSetupRequest::new(vec![]));

        System::current().stop();
        system.run();
        let ui_gateway_recording = ui_gateway_recording_arc.lock().unwrap();
        let message: &NodeToUiMessage = ui_gateway_recording.get_record(0);
        assert_eq!(
            *message,
            NodeToUiMessage {
                target: MessageTarget::ClientId(47),
                body: UiSetupResponse {
                    running: false,
                    values: vec![UiSetupResponseValue::new(
                        "db-password",
                        "****************",
                        Configured
                    ),]
                    .into_iter()
                    .collect(),
                    errors: vec![]
                }
                .tmb(74),
            }
        );
        assert_eq!(ui_gateway_recording.len(), 1);
    }

    #[test]
    fn handle_setup_responds_and_broadcasts_if_setup_is_changed() {
        let (ui_gateway, _, ui_gateway_recording_arc) = make_recorder();
        let mut subject = Daemon::new(Box::new(LauncherMock::new()));
        subject.params.insert(
            "booga".to_string(),
            UiSetupResponseValue::new("booga", "agoob", Configured),
        ); // not nothing
        let existing_setup = subject.params.clone();
        let modified_setup = {
            let mut modified_setup = existing_setup.clone();
            modified_setup.insert(
                "additional-item".to_string(),
                UiSetupResponseValue::new("additional-item", "booga", Set),
            );
            modified_setup
        };
        subject.setup_reporter = Box::new(
            SetupReporterMock::new().get_modified_setup_result(Ok(modified_setup.clone())),
        );
        let system = System::new("test");
        subject.ui_gateway_sub = Some(ui_gateway.start().recipient());

        subject.handle_setup(47, 74, UiSetupRequest::new(vec![]));

        System::current().stop();
        system.run();
        let ui_gateway_recording = ui_gateway_recording_arc.lock().unwrap();
        let message: &NodeToUiMessage = ui_gateway_recording.get_record(0);
        assert_eq!(
            *message,
            NodeToUiMessage {
                target: MessageTarget::ClientId(47),
                body: UiSetupResponse {
                    running: false,
                    values: modified_setup
                        .iter()
                        .map(|(_, v)| v.clone())
                        .sorted_by(|a, b| Ord::cmp(&a.name, &b.name))
                        .collect(),
                    errors: vec![]
                }
                .tmb(74),
            }
        );
        let message: &NodeToUiMessage = ui_gateway_recording.get_record(1);
        assert_eq!(
            *message,
            NodeToUiMessage {
                target: MessageTarget::AllExcept(47),
                body: UiSetupBroadcast {
                    running: false,
                    values: modified_setup
                        .into_iter()
                        .map(|(_, v)| v)
                        .sorted_by(|a, b| Ord::cmp(&a.name, &b.name))
                        .collect(),
                    errors: vec![]
                }
                .tmb(0),
            }
        );
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
        let verifier_tools = VerifierToolsMock::new();
        let system = System::new("test");
        let mut subject = Daemon::new(Box::new(launcher));
        subject.params.insert(
            "db-password".to_string(),
            UiSetupResponseValue::new("db-password", "goober", Set),
        );
        subject.verifier_tools = Box::new(verifier_tools);
        let subject_addr = subject.start();
        subject_addr
            .try_send(make_daemon_bind_message(ui_gateway))
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
            (*launch_params)
                .iter()
                .map(|x| &x.0)
                .collect::<Vec<&HashMap<String, String>>>(),
            vec![&HashMap::from_iter(
                vec![("db-password", "goober")]
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
        let verifier_tools = VerifierToolsMock::new();
        let system = System::new("test");
        let mut subject = Daemon::new(Box::new(launcher));
        subject.params.insert(
            "db-password".to_string(),
            UiSetupResponseValue::new("db-password", "goober", Set),
        );
        subject.verifier_tools = Box::new(verifier_tools);
        let subject_addr = subject.start();
        subject_addr
            .try_send(make_daemon_bind_message(ui_gateway))
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
    fn maintains_setup_through_start_order() {
        let _environment_guard = EnvironmentGuard::new();
        let _clap_guard = ClapGuard::new();
        let data_dir =
            ensure_node_home_directory_exists("daemon", "maintains_setup_through_start_order");
        let (ui_gateway, _, ui_gateway_recording_arc) = make_recorder();
        let launcher = LauncherMock::new().launch_result(Ok(Some(LaunchSuccess {
            new_process_id: 2345,
            redirect_ui_port: 5432,
        })));
        let verifier_tools = VerifierToolsMock::new()
            .process_is_running_result(false)
            .process_is_running_result(false)
            .process_is_running_result(false);
        let system = System::new("test");
        let mut subject = Daemon::new(Box::new(launcher));
        subject.params.insert(
            "ip".to_string(),
            UiSetupResponseValue::new("ip", "1.2.3.4", Set),
        );
        subject.params.insert(
            "db-password".to_string(),
            UiSetupResponseValue::new("db-password", "goober", Set),
        );
        subject.params.insert(
            "neighborhood-mode".to_string(),
            UiSetupResponseValue::new("neighborhood-mode", "zero-hop", Set),
        );
        subject.params.insert(
            "data-directory".to_string(),
            UiSetupResponseValue::new(
                "data-directory",
                data_dir.to_string_lossy().to_string().as_str(),
                Set,
            ),
        );
        subject.verifier_tools = Box::new(verifier_tools);
        let subject_addr = subject.start();
        subject_addr
            .try_send(make_daemon_bind_message(ui_gateway))
            .unwrap();

        subject_addr
            .try_send(NodeFromUiMessage {
                client_id: 1234,
                body: UiSetupRequest { values: vec![] }.tmb(4321),
            })
            .unwrap();
        subject_addr
            .try_send(NodeFromUiMessage {
                client_id: 1234,
                body: UiStartOrder {}.tmb(4321),
            })
            .unwrap();
        subject_addr
            .try_send(NodeFromUiMessage {
                client_id: 1234,
                body: UiSetupRequest { values: vec![] }.tmb(4321),
            })
            .unwrap();

        System::current().stop();
        system.run();
        let ui_gateway_recording = ui_gateway_recording_arc.lock().unwrap();
        // ------
        let record = ui_gateway_recording
            .get_record::<NodeToUiMessage>(0)
            .clone();
        assert_eq!(record.target, ClientId(1234));
        let (setup_response_before, _) = UiSetupResponse::fmb(record.body).unwrap();
        let record = ui_gateway_recording
            .get_record::<NodeToUiMessage>(1)
            .clone();
        assert_eq!(record.target, AllExcept(1234));
        let (setup_broadcast_before, _) = UiSetupBroadcast::fmb(record.body).unwrap();
        // skip start record (2)
        let record = ui_gateway_recording
            .get_record::<NodeToUiMessage>(3)
            .clone();
        let (setup_after, _) = UiSetupResponse::fmb(record.body).unwrap();
        // ------
        assert_eq!(setup_after.values, setup_response_before.values);
        assert_eq!(setup_after.values, setup_broadcast_before.values);
    }

    #[test]
    fn accepts_start_order_launches_and_replies_failure() {
        let (ui_gateway, _, ui_gateway_recording_arc) = make_recorder();
        let launcher = LauncherMock::new().launch_result(Err("booga".to_string()));
        let verifier_tools = VerifierToolsMock::new();
        let system = System::new("test");
        let mut subject = Daemon::new(Box::new(launcher));
        subject.params.insert(
            "db-password".to_string(),
            UiSetupResponseValue::new("db-password", "goober", Set),
        );
        subject.verifier_tools = Box::new(verifier_tools);
        let subject_addr = subject.start();
        subject_addr
            .try_send(make_daemon_bind_message(ui_gateway))
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
    fn rejects_start_order_when_node_is_already_running() {
        let (ui_gateway, _, ui_gateway_recording_arc) = make_recorder();
        let launcher = LauncherMock::new().launch_result(Err("booga".to_string()));
        let verifier_tools = VerifierToolsMock::new().process_is_running_result(true);
        let system = System::new("test");
        let mut subject = Daemon::new(Box::new(launcher));
        subject.params.insert(
            "db-password".to_string(),
            UiSetupResponseValue::new("db-password", "goober", Set),
        );
        subject.node_ui_port = Some(1234);
        subject.node_process_id = Some(3421);
        subject.verifier_tools = Box::new(verifier_tools);
        let subject_addr = subject.start();
        subject_addr
            .try_send(make_daemon_bind_message(ui_gateway))
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
        assert_eq!(&record.body.opcode, "start");
        let (code, message) = record.body.payload.err().unwrap();
        assert_eq!(code, NODE_ALREADY_RUNNING_ERROR);
        assert_eq!(
            message,
            "Could not launch Node: already running".to_string()
        );
    }

    #[test]
    fn sets_process_id_and_node_ui_port_upon_node_launch_success() {
        let (ui_gateway, _, gateway_recording_arc) = make_recorder();
        let (daemon, _, daemon_recording_arc) = make_recorder();
        let gateway_recipient = ui_gateway.start().recipient();
        let crash_notification_recipient = daemon.start().recipient();
        let launch_params_arc = Arc::new(Mutex::new(vec![]));
        let launcher = LauncherMock::new()
            .launch_params(&launch_params_arc)
            .launch_result(Ok(Some(LaunchSuccess {
                new_process_id: 54321,
                redirect_ui_port: 7777,
            })));
        let verifier_tools = VerifierToolsMock::new();
        let mut subject = Daemon::new(Box::new(launcher));
        subject.ui_gateway_sub = Some(gateway_recipient.clone());
        subject.crash_notification_sub = Some(crash_notification_recipient);
        subject.verifier_tools = Box::new(verifier_tools);
        subject.params = setup_cluster_from(vec![("data-directory", "bigglesworth", Set)]);

        subject.handle_start_order(1234, 2345);

        assert_eq!(subject.node_process_id, Some(54321));
        assert_eq!(subject.node_ui_port, Some(7777));
        let launch_params = launch_params_arc.lock().unwrap();
        assert_eq!(
            launch_params
                .iter()
                .map(|x| &x.0)
                .collect::<Vec<&HashMap<String, String>>>(),
            vec![
                (&vec![("data-directory".to_string(), "bigglesworth".to_string())]
                    .into_iter()
                    .collect::<HashMap<String, String>>())
            ]
        );
        let crashed_msg_to_daemon = CrashNotification {
            process_id: 54321,
            exit_code: None,
            stderr: None,
        };
        let system = System::new("test");
        launch_params[0]
            .1
            .try_send(crashed_msg_to_daemon.clone())
            .unwrap();
        System::current().stop();
        system.run();
        let gateway_recording = gateway_recording_arc.lock().unwrap();
        let start_msg = NodeToUiMessage {
            target: MessageTarget::ClientId(1234),
            body: UiStartResponse {
                new_process_id: 54321,
                redirect_ui_port: 7777,
            }
            .tmb(2345),
        };
        let actual_msg = gateway_recording.get_record::<NodeToUiMessage>(0);
        assert_eq!(actual_msg, &start_msg);
        let daemon_recording = daemon_recording_arc.lock().unwrap();
        let actual_msg = daemon_recording.get_record::<CrashNotification>(0);
        assert_eq!(actual_msg, &crashed_msg_to_daemon);
    }

    #[test]
    fn accepts_shutdown_order_after_start_and_returns_redirect() {
        let (ui_gateway, _, ui_gateway_recording_arc) = make_recorder();
        let system = System::new("test");
        let process_is_running_params_arc = Arc::new(Mutex::new(vec![]));
        let verifier_tools = VerifierToolsMock::new()
            .process_is_running_params(&process_is_running_params_arc)
            .process_is_running_result(true);
        let mut subject = Daemon::new(Box::new(LauncherMock::new()));
        subject.node_ui_port = Some(7777);
        subject.node_process_id = Some(8888);
        subject.verifier_tools = Box::new(verifier_tools);
        let subject_addr = subject.start();
        subject_addr
            .try_send(make_daemon_bind_message(ui_gateway))
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
        assert_eq!(record.body.path, FireAndForget);
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
        let process_is_running_params = process_is_running_params_arc.lock().unwrap();
        assert_eq!(*process_is_running_params, vec![8888])
    }

    #[test]
    fn remembers_unexpected_node_crash() {
        let verifier_tools = VerifierToolsMock::new().process_is_running_result(false);
        let mut subject = Daemon::new(Box::new(LauncherMock::new()));
        subject.node_ui_port = Some(7777);
        subject.node_process_id = Some(8888);
        subject.verifier_tools = Box::new(verifier_tools);

        let result = subject.port_if_node_is_running();

        assert_eq!(result, None);
        assert_eq!(subject.node_ui_port, None);
        assert_eq!(subject.node_process_id, None)
    }

    #[test]
    fn accepts_unexpected_message_discovers_non_running_node_and_returns_conversational_answer_of_error(
    ) {
        let (ui_gateway, _, ui_gateway_recording_arc) = make_recorder();
        let system = System::new("test");
        let verifier_tools = VerifierToolsMock::new().process_is_running_result(false); // only consulted once; second time, we already know
        let mut subject = Daemon::new(Box::new(LauncherMock::new()));
        subject.node_ui_port = Some(7777);
        subject.node_process_id = Some(8888);
        subject.verifier_tools = Box::new(verifier_tools);
        let subject_addr = subject.start();
        subject_addr
            .try_send(make_daemon_bind_message(ui_gateway))
            .unwrap();
        let shutdown_body: MessageBody = UiShutdownRequest {}.tmb(4321);

        subject_addr
            .try_send(NodeFromUiMessage {
                client_id: 1234,
                body: shutdown_body.clone(),
            })
            .unwrap();

        System::current().stop();
        system.run();
        let ui_gateway_recording = ui_gateway_recording_arc.lock().unwrap();
        let record = ui_gateway_recording
            .get_record::<NodeToUiMessage>(0)
            .clone();
        assert_eq!(record.target, ClientId(1234));
        assert_eq!(record.body.path, Conversation(4321));
        assert_eq!(
            record.body.payload,
            Err((
                NODE_NOT_RUNNING_ERROR,
                "Cannot handle shutdown request: Node is not running".to_string()
            ))
        );
    }

    #[test]
    fn unexpected_ff_message_undeliverable_to_inactive_node_is_announced_with_another_ff_message() {
        //fire and forget message that could be sent from UI to Node does not exist so far,
        //this is a touch of the future
        let (ui_gateway, _, ui_gateway_recording_arc) = make_recorder();
        let system = System::new("test");
        let verifier_tools = VerifierToolsMock::new().process_is_running_result(false);
        let mut subject = Daemon::new(Box::new(LauncherMock::new()));
        subject.node_ui_port = Some(7777);
        subject.node_process_id = Some(8888);
        subject.verifier_tools = Box::new(verifier_tools);
        let subject_addr = subject.start();
        subject_addr
            .try_send(make_daemon_bind_message(ui_gateway))
            .unwrap();
        let body = MessageBody {
            opcode: "uninventedMessage".to_string(),
            path: MessagePath::FireAndForget,
            payload: Ok("Something very important".to_string()),
        };
        subject_addr
            .try_send(NodeFromUiMessage {
                client_id: 1234,
                body,
            })
            .unwrap();

        System::current().stop();
        system.run();
        let ui_gateway_recording = ui_gateway_recording_arc.lock().unwrap();
        let record = ui_gateway_recording
            .get_record::<NodeToUiMessage>(0)
            .clone();
        assert_eq!(record.target, ClientId(1234));
        assert_eq!(record.body.opcode, "undelivered");
        assert_eq!(record.body.path, FireAndForget);
        assert_eq!(
            UiUndeliveredFireAndForget::fmb(record.body).unwrap(),
            (
                UiUndeliveredFireAndForget {
                    opcode: "uninventedMessage".to_string()
                },
                0
            )
        );
    }

    #[test]
    fn accepts_financials_request_before_start_and_returns_error() {
        let (ui_gateway, _, ui_gateway_recording_arc) = make_recorder();
        let system = System::new("test");
        let verifier_tools = VerifierToolsMock::new();
        let mut subject = Daemon::new(Box::new(LauncherMock::new()));
        subject.node_ui_port = None;
        subject.node_process_id = None;
        subject.verifier_tools = Box::new(verifier_tools);
        let subject_addr = subject.start();
        subject_addr
            .try_send(make_daemon_bind_message(ui_gateway))
            .unwrap();
        let body: MessageBody = UiFinancialsRequest {
            stats_required: true,
            top_records_opt: None,
            custom_queries_opt: None,
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

    #[test]
    fn accepts_crash_notification_when_not_in_setup_mode_and_sends_ui_notification() {
        let (ui_gateway, _, ui_gateway_recording_arc) = make_recorder();
        let system = System::new("test");
        let verifier_tools = VerifierToolsMock::new();
        let mut subject = Daemon::new(Box::new(LauncherMock::new()));
        subject.node_ui_port = Some(1234);
        subject.node_process_id = Some(12345);
        subject.verifier_tools = Box::new(verifier_tools);
        let subject_addr = subject.start();
        subject_addr
            .try_send(make_daemon_bind_message(ui_gateway))
            .unwrap();
        let message = CrashNotification {
            process_id: 54321,
            exit_code: Some(123),
            stderr: Some("Standard error".to_string()),
        };

        subject_addr.try_send(message).unwrap();

        subject_addr
            .try_send(NodeFromUiMessage {
                client_id: 7777,
                body: UiShutdownRequest {}.tmb(777),
            })
            .unwrap();
        System::current().stop();
        system.run();
        let ui_gateway_recording = ui_gateway_recording_arc.lock().unwrap();
        let record = ui_gateway_recording.get_record::<NodeToUiMessage>(0);
        assert_eq!(record.target, MessageTarget::AllClients);
        assert_eq!(
            &record.body,
            &UiNodeCrashedBroadcast {
                process_id: 54321,
                crash_reason: CrashReason::Unrecognized("Standard error".to_string()),
            }
            .tmb(0)
        );
        let record = ui_gateway_recording
            .get_record::<NodeToUiMessage>(1)
            .clone();
        assert_eq!(record.target, ClientId(7777));
        assert_eq!(
            &record.body,
            &MessageBody {
                opcode: "shutdown".to_string(),
                path: Conversation(777),
                payload: Err((
                    NODE_NOT_RUNNING_ERROR,
                    format!(
                        "Cannot handle {} request: Node is not running",
                        UiShutdownRequest {}.opcode()
                    ),
                )),
            }
        );
    }

    #[test]
    fn accepts_crash_notification_in_setup_mode_and_swallows() {
        let (ui_gateway, _, ui_gateway_recording_arc) = make_recorder();
        let system = System::new("test");
        let ui_gateway_sub = ui_gateway.start().recipient();
        let verifier_tools = VerifierToolsMock::new();
        let mut subject = Daemon::new(Box::new(LauncherMock::new()));
        subject.ui_gateway_sub = Some(ui_gateway_sub);
        subject.verifier_tools = Box::new(verifier_tools);
        subject.node_ui_port = None;
        subject.node_process_id = None;

        subject.handle_crash_notification(CrashNotification {
            process_id: 54321,
            exit_code: Some(123),
            stderr: Some("Standard Error".to_string()),
        });

        System::current().stop();
        system.run();
        let ui_gateway_recording = ui_gateway_recording_arc.lock().unwrap();
        assert_eq!(ui_gateway_recording.len(), 0);
    }
}
