// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

mod websocket_supervisor;

#[cfg(test)]
pub mod websocket_supervisor_mock;

use crate::daemon::DaemonBindMessage;
use crate::sub_lib::logger::Logger;
use crate::sub_lib::peer_actors::BindMessage;
use crate::sub_lib::ui_gateway::UiGatewayConfig;
use crate::sub_lib::ui_gateway::UiGatewaySubs;
use crate::sub_lib::utils::{NODE_MAILBOX_CAPACITY};
use crate::ui_gateway::websocket_supervisor::WebSocketSupervisor;
use crate::ui_gateway::websocket_supervisor::WebSocketSupervisorReal;
use actix::Actor;
use actix::Addr;
use actix::Context;
use actix::Handler;
use actix::Recipient;
use masq_lib::messages::{UiCrashRequest, UiMessageError};
use masq_lib::ui_gateway::{MessageBody, NodeFromUiMessage, NodeToUiMessage};

pub const CRASH_KEY: &str = "UIGATEWAY";

pub struct UiGateway {
    port: u16,
    websocket_supervisor: Option<Box<dyn WebSocketSupervisor>>,
    incoming_message_recipients: Vec<Recipient<NodeFromUiMessage>>,
    crashable: bool,
    logger: Logger,
}

impl UiGateway {
    pub fn new(config: &UiGatewayConfig, crashable: bool) -> UiGateway {
        UiGateway {
            port: config.ui_port,
            websocket_supervisor: None,
            incoming_message_recipients: vec![],
            crashable,

            logger: Logger::new("UiGateway"),
        }
    }

    pub fn make_subs_from(addr: &Addr<UiGateway>) -> UiGatewaySubs {
        UiGatewaySubs {
            bind: recipient!(addr, BindMessage),
            node_from_ui_message_sub: recipient!(addr, NodeFromUiMessage),
            node_to_ui_message_sub: recipient!(addr, NodeToUiMessage),
        }
    }

    //TODO: this function will probably be transformed into more appropriate one with GH-472
    fn deserialization_check_with_potential_crash_request_handling(
        &self,
        message_body: MessageBody,
    ) -> Option<UiMessageError> {
        match message_body.payload {
            Ok(payload) => match serde_json::from_str::<UiCrashRequest>(&payload) {
                Ok(crash_request) => match (self.crashable, crash_request.actor == CRASH_KEY) {
                    (true, true) => panic!("{}", crash_request.panic_message),
                    _ => None,
                },
                Err(e) if e.is_syntax() => Some(UiMessageError::DeserializationError(e.to_string())),
                Err(_) => None
            }
                Err(_) => None,
            }
        }
}

impl Actor for UiGateway {
    type Context = Context<Self>;
}

impl Handler<BindMessage> for UiGateway {
    type Result = ();

    fn handle(&mut self, msg: BindMessage, _ctx: &mut Self::Context) -> Self::Result {
        self.incoming_message_recipients = vec![
            msg.peer_actors.accountant.ui_message_sub.clone(),
            msg.peer_actors.neighborhood.from_ui_message_sub.clone(),
            msg.peer_actors.blockchain_bridge.ui_sub.clone(),
            msg.peer_actors.dispatcher.ui_sub.clone(),
            msg.peer_actors.configurator.node_from_ui_sub.clone(),
        ];
        self.websocket_supervisor = match WebSocketSupervisorReal::new(
            self.port,
            msg.peer_actors.ui_gateway.node_from_ui_message_sub,
        ) {
            Ok(wss) => Some(Box::new(wss)),
            Err(e) => panic!("Couldn't start WebSocketSupervisor: {:?}", e),
        };
        debug!(self.logger, "UIGateway bound");
    }
}

impl Handler<DaemonBindMessage> for UiGateway {
    type Result = ();

    fn handle(&mut self, msg: DaemonBindMessage, ctx: &mut Self::Context) -> Self::Result {
        ctx.set_mailbox_capacity(NODE_MAILBOX_CAPACITY);
        self.incoming_message_recipients = msg.from_ui_message_recipients;
        self.websocket_supervisor =
            match WebSocketSupervisorReal::new(self.port, msg.from_ui_message_recipient) {
                Ok(wss) => Some(Box::new(wss)),
                Err(e) => panic!("Couldn't start WebSocketSupervisor: {:?}", e),
            };
        debug!(self.logger, "UIGateway bound");
    }
}

impl Handler<NodeToUiMessage> for UiGateway {
    type Result = ();

    fn handle(&mut self, msg: NodeToUiMessage, _ctx: &mut Self::Context) -> Self::Result {
        self.websocket_supervisor
            .as_ref()
            .expect("WebsocketSupervisor is unbound")
            .send_msg(msg)
    }
}

impl Handler<NodeFromUiMessage> for UiGateway {
    type Result = ();

    fn handle(&mut self, msg: NodeFromUiMessage, _ctx: &mut Self::Context) -> Self::Result {
        if let Some(UiMessageError::DeserializationError(error)) =
            self.deserialization_check_with_potential_crash_request_handling(msg.body.clone())
        {
            warning!(self.logger, "Deserialization error: {}", error);
            return;
        };
        let len = self.incoming_message_recipients.len();
        (0..len).for_each(|idx| {
            let recipient = &self.incoming_message_recipients[idx];
            recipient.try_send(msg.clone()).unwrap_or_else(|_| {
                panic!("UiGateway's NodeFromUiMessage recipient #{} has died.", idx)
            });
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dispatcher;
    use crate::test_utils::logging::{init_test_logging, TestLogHandler};
    use crate::test_utils::recorder::peer_actors_builder;
    use crate::test_utils::recorder::{make_recorder, Recording};
    use crate::ui_gateway::websocket_supervisor_mock::WebSocketSupervisorMock;
    use actix::System;
    use masq_lib::messages::{ToMessageBody, UiChangePasswordRequest};
    use masq_lib::ui_gateway::MessagePath::FireAndForget;
    use masq_lib::ui_gateway::{MessageBody, MessagePath, MessageTarget};
    use masq_lib::utils::find_free_port;
    use std::sync::Arc;
    use std::sync::Mutex;

    #[test]
    fn inbound_ui_message_is_disseminated_properly() {
        // These actors should receive NodeFromUiMessages
        let (accountant, _, accountant_recording_arc) = make_recorder();
        let (neighborhood, _, neighborhood_recording_arc) = make_recorder();
        let (blockchain, _, blockchain_recording_arc) = make_recorder();
        let (dispatcher, _, dispatcher_recording_arc) = make_recorder();
        let (configurator, _, configurator_recording_arc) = make_recorder();
        // These actors should not receive NodeFromUiMessages
        let (ui_gateway, _, ui_gateway_recording_arc) = make_recorder();
        let (proxy_client, _, proxy_client_recording_arc) = make_recorder();
        let (proxy_server, _, proxy_server_recording_arc) = make_recorder();
        let (hopper, _, hopper_recording_arc) = make_recorder();
        let subject = UiGateway::new(
            &UiGatewayConfig {
                ui_port: find_free_port(),
            },
            false,
        );
        let system = System::new("test");
        let subject_addr: Addr<UiGateway> = subject.start();
        let peer_actors = peer_actors_builder()
            .accountant(accountant)
            .neighborhood(neighborhood)
            .blockchain_bridge(blockchain)
            .dispatcher(dispatcher)
            .configurator(configurator)
            .ui_gateway(ui_gateway)
            .proxy_server(proxy_server)
            .proxy_client(proxy_client)
            .hopper(hopper)
            .build();
        subject_addr.try_send(BindMessage { peer_actors }).unwrap();
        let msg = NodeFromUiMessage {
            client_id: 1234,
            body: MessageBody {
                opcode: "booga".to_string(),
                path: FireAndForget,
                payload: Ok("{\n
                }".to_string()),
            },
        };

        subject_addr.try_send(msg.clone()).unwrap();

        System::current().stop();
        system.run();
        let did_receive = |recording_arc: Arc<Mutex<Recording>>| {
            let recording = recording_arc.lock().unwrap();
            assert_eq!(recording.get_record::<NodeFromUiMessage>(0), &msg);
        };
        let did_not_receive = |recording_arc: Arc<Mutex<Recording>>| {
            let recording = recording_arc.lock().unwrap();
            assert_eq!(recording.len(), 0);
        };
        did_receive(accountant_recording_arc);
        did_receive(neighborhood_recording_arc);
        did_receive(blockchain_recording_arc);
        did_receive(dispatcher_recording_arc);
        did_receive(configurator_recording_arc);
        did_not_receive(ui_gateway_recording_arc);
        did_not_receive(proxy_client_recording_arc);
        did_not_receive(proxy_server_recording_arc);
        did_not_receive(hopper_recording_arc);
    }

    #[test]
    fn outbound_ui_message_goes_only_to_websocket_supervisor() {
        let (accountant, _, accountant_recording_arc) = make_recorder();
        let send_msg_params_arc = Arc::new(Mutex::new(vec![]));
        let websocket_supervisor =
            WebSocketSupervisorMock::new().send_msg_params(&send_msg_params_arc);
        let mut subject = UiGateway::new(
            &UiGatewayConfig {
                ui_port: find_free_port(),
            },
            false,
        );
        let system = System::new("test");
        subject.websocket_supervisor = Some(Box::new(websocket_supervisor));
        //TODO this doesn't work; but with the bind message it would
        subject.incoming_message_recipients =
            vec![accountant.start().recipient::<NodeFromUiMessage>()];
        let subject_addr: Addr<UiGateway> = subject.start();
        let msg = NodeToUiMessage {
            target: MessageTarget::ClientId(1234),
            body: MessageBody {
                opcode: "booga".to_string(),
                path: FireAndForget,
                payload: Ok("{}".to_string()),
            },
        };

        subject_addr.try_send(msg.clone()).unwrap();

        System::current().stop();
        system.run();
        let accountant_recording = accountant_recording_arc.lock().unwrap();
        assert_eq!(accountant_recording.len(), 0);
        let send_parameters = send_msg_params_arc.lock().unwrap();
        assert_eq!(send_parameters[0], msg);
    }

    #[test]
    fn a_syntactically_bad_json_is_caught() {
        init_test_logging();
        let (accountant, _, accountant_recording_arc) = make_recorder();
        let subject = UiGateway::new(
            &UiGatewayConfig {
                ui_port: find_free_port(),
            },
            false,
        );
        let system = System::new("test");
        let subject_addr: Addr<UiGateway> = subject.start();
        let peer_actors = peer_actors_builder().accountant(accountant).build();
        subject_addr.try_send(BindMessage { peer_actors }).unwrap();
        let msg = NodeFromUiMessage {
            client_id: 0,
            body: MessageBody {
                opcode: "booga".to_string(),
                path: FireAndForget,
                payload: Ok("some bad bite for a jason processor".to_string()),
            },
        };

        subject_addr.try_send(msg.clone()).unwrap();

        System::current().stop();
        system.run();
        let random_actor_recording = accountant_recording_arc.lock().unwrap();
        assert_eq!(random_actor_recording.len(), 0);
        TestLogHandler::new().exists_log_containing(
            "WARN: UiGateway: Deserialization error: expected value at line 1 column 1",
        );
    }

    #[test]
    fn other_than_syntactical_errors_are_ignored() {
        //we deserialize against the crash request so deviating from its syntax causes also a deserialization error
        let msg_body = UiChangePasswordRequest{ old_password_opt: None, new_password: "bubbles".to_string() }.tmb(12);
        let subject = UiGateway::new(&UiGatewayConfig { ui_port: 123 }, false);

        let result = subject.deserialization_check_with_potential_crash_request_handling(msg_body);

        assert_eq!(result, None)
    }

    #[test]
    fn deserialization_checker_does_not_care_about_errors_like_payload_errors() {
        let msg_body = MessageBody {
            opcode: "blah".to_string(),
            path: MessagePath::Conversation(45),
            payload: Err((1234, "We did it wrong".to_string())),
        };
        let subject = UiGateway::new(&UiGatewayConfig { ui_port: 123 }, false);

        let result = subject.deserialization_check_with_potential_crash_request_handling(msg_body);

        assert_eq!(result, None)
    }

    #[test]
    fn deserialization_checker_does_not_panic_on_a_crash_request_if_the_actor_is_not_crashable() {
        let crash_request = UiCrashRequest {
            actor: CRASH_KEY.to_string(),
            panic_message: "Testing crashing".to_string(),
        }
        .tmb(0);
        let crashable = false;
        let subject = UiGateway::new(&UiGatewayConfig { ui_port: 123 }, crashable);

        let result =
            subject.deserialization_check_with_potential_crash_request_handling(crash_request);

        assert_eq!(result, None)
    }

    #[test]
    fn deserialization_checker_does_not_panic_if_the_crash_request_belongs_to_another_actor() {
        let crash_request = UiCrashRequest {
            actor: dispatcher::CRASH_KEY.to_string(),
            panic_message: "Testing crashing".to_string(),
        }
        .tmb(0);
        let crashable = true;
        let subject = UiGateway::new(&UiGatewayConfig { ui_port: 123 }, crashable);

        let result =
            subject.deserialization_check_with_potential_crash_request_handling(crash_request);

        assert_eq!(result, None)
    }
}
