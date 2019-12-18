// Copyright (c) 2019, MASQ (https://masq.ai). All rights reserved.

use actix::{Actor, Context, Handler, Message};
use actix::Recipient;
use crate::sub_lib::ui_gateway::{NodeFromUiMessage, NodeToUiMessage};
use crate::ui_gateway::messages::{UiSetup, UiMessageError, FromMessageBody, ToMessageBody, NULL_MESSAGE_BODY};
use crate::sub_lib::ui_gateway::MessageTarget::ClientId;
use crate::sub_lib::logger::Logger;

#[derive(Message, PartialEq, Clone)]
pub struct DaemonBindMessage {
    pub to_ui_message_recipient: Recipient<NodeToUiMessage>, // for everybody to send UI-bound messages to
    pub from_ui_message_recipient: Recipient<NodeFromUiMessage>, // for the WebsocketSupervisor to send inbound UI messages to the UiGateway
    pub from_ui_message_recipients: Vec<Recipient<NodeFromUiMessage>>, // for the UiGateway to relay inbound UI messages to everybody
}

trait Launcher {
    fn launch(self, params: Vec<String>) -> String;
}

struct LauncherReal {}

impl Launcher for LauncherReal {
    fn launch(self, _params: Vec<String>) -> String {
        unimplemented!()
    }
}

impl LauncherReal {
    fn new () -> Self {
        Self {}
    }
}

pub struct Daemon {
    _launcher: Box<dyn Launcher>,
    ui_gateway_sub: Option<Recipient<NodeToUiMessage>>,
    logger: Logger,
}

impl Actor for Daemon {
    type Context = Context<Daemon>;
}

impl Handler<DaemonBindMessage> for Daemon {
    type Result = ();

    fn handle(&mut self, msg: DaemonBindMessage, _ctx: &mut Self::Context) -> Self::Result {
        self.ui_gateway_sub = Some (msg.to_ui_message_recipient);
    }
}

impl Handler<NodeFromUiMessage> for Daemon {
    type Result = ();

    fn handle(&mut self, msg: NodeFromUiMessage, _ctx: &mut Self::Context) -> Self::Result {
        let client_id = msg.client_id;
        let opcode = msg.body.opcode.clone();
        let result: Result<(UiSetup, u64), UiMessageError> = msg.body.fmb();
        match result {
            Ok ((payload, context_id)) => self.handle_setup(client_id, context_id, payload),
            Err(e) => error! (&self.logger, "Bad {} request from client {}: {:?}", opcode, client_id, e),
        }
    }
}

impl Daemon {
    pub fn new() -> Daemon {
        Daemon {
            _launcher: Box::new(LauncherReal::new()),
            ui_gateway_sub: None,
            logger: Logger::new("Daemon"),
        }
    }

    fn handle_setup(&mut self, client_id: u64, context_id: u64, _payload: UiSetup) {
        let msg = NodeToUiMessage {
            target: ClientId(client_id),
            body: NULL_MESSAGE_BODY.tmb(UiSetup {
                values: vec![]
            }, context_id),
        };
        self.ui_gateway_sub.as_ref().expect("UiGateway is unbound").try_send(msg).expect("UiGateway is dead");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, Arc};
    use std::cell::RefCell;
    use crate::test_utils::recorder::{make_recorder, Recorder};
    use actix::System;
    use crate::sub_lib::ui_gateway::MessageTarget::ClientId;
    use crate::ui_gateway::messages::{UiSetup, NULL_MESSAGE_BODY};
    use std::collections::HashSet;

    struct LauncherMock {
        launch_params: Arc<Mutex<Vec<Vec<String>>>>,
        launch_results: RefCell<Vec<String>>,
    }

    impl Launcher for LauncherMock {
        fn launch(self, params: Vec<String>) -> String {
            self.launch_params.lock().unwrap().push (params);
            self.launch_results.borrow_mut().remove(0)
        }
    }

    impl LauncherMock {
        fn _new() -> LauncherMock {
            LauncherMock {
                launch_params: Arc::new(Mutex::new(vec![])),
                launch_results: RefCell::new(vec![]),
            }
        }

        fn _launch_params(mut self, params: &Arc<Mutex<Vec<Vec<String>>>>) -> Self {
            self.launch_params = params.clone();
            self
        }

        fn _launch_result(self, result: &str) -> Self {
            self.launch_results.borrow_mut().push (result.to_string());
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
        let subject = Daemon::new();
        let subject_addr = subject.start();
        subject_addr.try_send(make_bind_message(ui_gateway)).unwrap();

        subject_addr.try_send(NodeFromUiMessage {
            client_id: 1234,
            body: NULL_MESSAGE_BODY.tmb(UiSetup{values: vec![]}, 4321),
        }).unwrap();

        System::current().stop();
        system.run();
        let ui_gateway_recording = ui_gateway_recording_arc.lock().unwrap();
        let record = ui_gateway_recording.get_record::<NodeToUiMessage>(0).clone();
        assert_eq! (record.target, ClientId(1234));
        let (payload, context_id): (UiSetup, u64) = record.body.fmb().unwrap();
        assert_eq! (context_id, 4321);
        let actual_pairs: HashSet<(String, String)> = payload.values.into_iter()
            .map(|value| (value.name, value.value))
            .collect();
        let schema = crate::node_configurator::node_configurator_standard::app();
        let expected_pairs: HashSet<(String, String)> = schema.p.opts
            .iter()
            .map(|opt| {
                let name = opt.b.name.to_string();
                let value = match opt.v.default_val {
                    Some(os_str) => os_str.to_str().unwrap().to_string(),
                    None => "booga".to_string(),
                };
                (name, value)
            })
            .collect();
        assert_eq! (actual_pairs, expected_pairs);
    }
}