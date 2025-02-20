// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

mod websocket_supervisor;

#[cfg(test)]
pub mod websocket_supervisor_mocks;

use crate::daemon::DaemonBindMessage;
use crate::sub_lib::peer_actors::BindMessage;
use crate::sub_lib::ui_gateway::UiGatewayConfig;
use crate::sub_lib::ui_gateway::UiGatewaySubs;
use crate::sub_lib::utils::{supervisor_restarting, NODE_MAILBOX_CAPACITY};
use crate::ui_gateway::websocket_supervisor::{
    WebSocketSupervisor, WebSocketSupervisorFactory, WebsocketSupervisorFactoryReal,
};
use actix::Addr;
use actix::Context;
use actix::Handler;
use actix::Recipient;
use actix::{Actor, Supervised, System};
use itertools::Either;
use masq_lib::logger::Logger;
use masq_lib::messages::UiCrashRequest;
use masq_lib::ui_gateway::{MessageBody, NodeFromUiMessage, NodeToUiMessage};
use masq_lib::utils::ExpectValue;
use std::sync::{Arc, Mutex};
use std::thread::panicking;

pub const CRASH_KEY: &str = "UIGATEWAY";

pub struct UiGateway {
    port: u16,
    websocket_supervisor_or_factory:
        Either<Box<dyn WebSocketSupervisorFactory>, Box<dyn WebSocketSupervisor>>,
    incoming_message_recipients: Vec<Recipient<NodeFromUiMessage>>,
    crashable: bool,
    logger: Logger,
}

impl UiGateway {
    pub fn new(config: &UiGatewayConfig, crashable: bool) -> UiGateway {
        UiGateway {
            port: config.ui_port,
            websocket_supervisor_or_factory: Either::Left(Box::new(WebsocketSupervisorFactoryReal)),
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
    fn deserialization_validator_with_crash_request_handler(
        &self,
        message_body: MessageBody,
    ) -> Option<(String, String)> {
        match &message_body.payload {
            Ok(payload) => match serde_json::from_str::<UiCrashRequest>(payload) {
                Ok(crash_request) => match (self.crashable, crash_request.actor == CRASH_KEY) {
                    (true, true) => panic!("{}", crash_request.panic_message),
                    _ => {
                        trace!(self.logger,"Crash request not to be addressed by this actor; correct addressee: {}; is this actor being crashable: {}",crash_request.actor,self.crashable);
                        None
                    }
                },
                Err(e) if e.is_syntax() => {
                    let mut example = payload.clone();
                    example.truncate(100);
                    Some((e.to_string(), example))
                }
                //we don't care when messages just look different from the crash request
                //in 99% we're here and getting an err for legit messages; thus not a true error
                Err(e) if e.is_data() => None,
                //untested, don't know how to trigger this
                Err(e) => {
                    error!(self.logger, "An IO or EoF error: {}", e);
                    None
                }
            },
            Err((_, e)) => {
                error!(
                    self.logger,
                    "Received a message of '{}' opcode with an error in its payload: '{}'",
                    message_body.opcode,
                    e
                );
                None
            }
        }
    }

    fn initiate_websocket_supervisor(&mut self, recipient: Recipient<NodeFromUiMessage>) {
        let ws = match self
            .websocket_supervisor_or_factory
            .as_ref()
            .left()
            .as_ref()
            .expectv("WebSocket factory")
            .make(self.port, recipient)
        {
            Ok(wss) => Either::Right(wss),
            Err(e) => panic!("Couldn't start WebSocketSupervisor: {:?}", e),
        };
        self.websocket_supervisor_or_factory = ws;
        // let _ = replace(&mut self.websocket_supervisor_arc_or_factory, ws); Delete this if the line above works
    }
}

impl Actor for UiGateway {
    type Context = Context<Self>;
}

impl Supervised for UiGateway {
    fn restarting(&mut self, _ctx: &mut Self::Context) {
        supervisor_restarting();
    }
}

impl Drop for UiGateway {
    fn drop(&mut self) {
        if panicking() {
            System::current().stop_with_code(1);
        }
    }
}

impl Handler<BindMessage> for UiGateway {
    type Result = ();

    fn handle(&mut self, msg: BindMessage, ctx: &mut Self::Context) -> Self::Result {
        ctx.set_mailbox_capacity(NODE_MAILBOX_CAPACITY);
        self.incoming_message_recipients = vec![
            msg.peer_actors.accountant.ui_message_sub.clone(),
            msg.peer_actors.neighborhood.from_ui_message_sub.clone(),
            msg.peer_actors.blockchain_bridge.ui_sub.clone(),
            msg.peer_actors.dispatcher.ui_sub.clone(),
            msg.peer_actors.configurator.node_from_ui_sub.clone(),
        ];
        self.initiate_websocket_supervisor(msg.peer_actors.ui_gateway.node_from_ui_message_sub);
        debug!(self.logger, "UIGateway bound");
    }
}

impl Handler<DaemonBindMessage> for UiGateway {
    type Result = ();

    fn handle(&mut self, msg: DaemonBindMessage, ctx: &mut Self::Context) -> Self::Result {
        ctx.set_mailbox_capacity(NODE_MAILBOX_CAPACITY);
        self.incoming_message_recipients = msg.from_ui_message_recipients;
        self.initiate_websocket_supervisor(msg.from_ui_message_recipient);
        debug!(self.logger, "UIGateway bound");
    }
}

impl Handler<NodeToUiMessage> for UiGateway {
    type Result = ();

    fn handle(&mut self, msg: NodeToUiMessage, _ctx: &mut Self::Context) -> Self::Result {
        self.websocket_supervisor_or_factory
            .as_ref()
            .right()
            .as_ref()
            .expect("WebSocketSupervisor is uninitialized")
            .send_msg(msg);
    }
}

impl Handler<NodeFromUiMessage> for UiGateway {
    type Result = ();

    fn handle(&mut self, msg: NodeFromUiMessage, _ctx: &mut Self::Context) -> Self::Result {
        debug!(
            self.logger,
            "Received NodeFromUiMessage with opcode: '{}'", msg.body.opcode
        );
        if let Some((error, original)) =
            self.deserialization_validator_with_crash_request_handler(msg.body.clone())
        {
            warning!(
                self.logger,
                "Deserialization error: {}; original message (maximally 100 characters): {}",
                error,
                original
            );
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
    use crate::test_utils::recorder::peer_actors_builder;
    use crate::test_utils::recorder::{make_recorder, Recording};
    use crate::test_utils::unshared_test_utils::make_daemon_bind_message;
    use crate::ui_gateway::websocket_supervisor::WebSocketSupervisorFactory;
    use crate::ui_gateway::websocket_supervisor_mocks::{
        WebSocketSupervisorMock, WebsocketSupervisorFactoryMock,
    };
    use actix::dev::AsyncContextParts;
    use actix::Message;
    use actix::System;
    use crossbeam_channel::{unbounded, Sender};
    use masq_lib::messages::{ToMessageBody, UiChangePasswordRequest};
    use masq_lib::test_utils::logging::{init_test_logging, TestLogHandler};
    use masq_lib::ui_gateway::MessagePath::FireAndForget;
    use masq_lib::ui_gateway::{MessageBody, MessagePath, MessageTarget};
    use masq_lib::utils::find_free_port;
    use std::sync::{Arc, Mutex};

    #[test]
    fn constants_have_correct_values() {
        assert_eq!(CRASH_KEY, "UIGATEWAY");
    }

    #[derive(Debug, Message, Clone)]
    #[rtype(result = "()")]
    struct MailboxCapacityCheck {
        tx: Sender<usize>,
    }

    impl Handler<MailboxCapacityCheck> for UiGateway {
        type Result = ();

        fn handle(&mut self, msg: MailboxCapacityCheck, ctx: &mut Self::Context) -> Self::Result {
            let capacity = ctx.parts().capacity();
            msg.tx.send(capacity).unwrap();
        }
    }

    #[test]
    fn bind_message_removes_mailbox_size_limit() {
        let system = System::new();
        let subject = UiGateway::new(
            &UiGatewayConfig {
                ui_port: find_free_port(),
            },
            false,
        );
        let peer_actors = peer_actors_builder().build();
        let subject_addr = subject.start();
        subject_addr.try_send(BindMessage { peer_actors }).unwrap();
        let (tx, rx) = unbounded();
        let check = MailboxCapacityCheck { tx };

        subject_addr.try_send(check).unwrap();

        System::current().stop();
        system.run();
        let capacity = rx.recv().unwrap();
        assert_eq!(capacity, 0);
    }

    #[test]
    fn daemon_bind_message_removes_mailbox_size_limit() {
        let system = System::new();
        let subject = UiGateway::new(
            &UiGatewayConfig {
                ui_port: find_free_port(),
            },
            false,
        );
        let (ui_gateway, _, _) = make_recorder();
        let daemon_bind_message = make_daemon_bind_message(ui_gateway);
        let subject_addr = subject.start();
        subject_addr.try_send(daemon_bind_message).unwrap();
        let (tx, rx) = unbounded();
        let check = MailboxCapacityCheck { tx };

        subject_addr.try_send(check).unwrap();

        System::current().stop();
        system.run();
        let capacity = rx.recv().unwrap();
        assert_eq!(capacity, 0);
    }

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
        let system = System::new();
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
                }"
                .to_string()),
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
        let websocket_supervisor_factory =
            WebsocketSupervisorFactoryMock::default().make_result(Ok(websocket_supervisor));
        let port = find_free_port();
        let mut subject = UiGateway::new(&UiGatewayConfig { ui_port: port }, false);
        subject.websocket_supervisor_or_factory = Either::Left(Box::new(
            websocket_supervisor_factory,
        )
            as Box<dyn WebSocketSupervisorFactory>);
        let system = System::new();
        let subject_addr: Addr<UiGateway> = subject.start();
        let peer_actors = peer_actors_builder().accountant(accountant).build();
        subject_addr.try_send(BindMessage { peer_actors }).unwrap();
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
    fn syntactically_bad_json_is_caught_and_a_truncated_example_is_provided() {
        init_test_logging();
        let (accountant, _, accountant_recording_arc) = make_recorder();
        let subject = UiGateway::new(
            &UiGatewayConfig {
                ui_port: find_free_port(),
            },
            false,
        );
        let system = System::new();
        let subject_addr: Addr<UiGateway> = subject.start();
        let peer_actors = peer_actors_builder().accountant(accountant).build();
        subject_addr.try_send(BindMessage { peer_actors }).unwrap();
        let mut payload = "some bad bite for a jason processor; abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcde".to_string();
        let payload_length_before_truncation = payload.len();
        let msg = NodeFromUiMessage {
            client_id: 0,
            body: MessageBody {
                opcode: "booga".to_string(),
                path: FireAndForget,
                payload: Ok(payload.clone()),
            },
        };

        subject_addr.try_send(msg.clone()).unwrap();

        System::current().stop();
        system.run();
        let random_actor_recording = accountant_recording_arc.lock().unwrap();
        assert_eq!(random_actor_recording.len(), 0);
        payload.truncate(100);
        let expected_msg_example = payload;
        let len_expected = expected_msg_example.len();
        assert_eq!(payload_length_before_truncation, len_expected + 20);
        let log_handler = TestLogHandler::new();
        let expected_log = format!("WARN: UiGateway: Deserialization error: expected value at line 1 column 1; original message (maximally 100 characters): {}",expected_msg_example);
        log_handler.exists_log_containing(&expected_log);
        let log_unexpected_because_longer = &format!("{}f", expected_log);
        log_handler.exists_no_log_containing(log_unexpected_because_longer)
    }

    #[test]
    fn semantics_errors_are_ignored() {
        //we deserialize against the crash request so deviating from its syntax causes also a deserialization error
        let msg_body = UiChangePasswordRequest {
            old_password_opt: None,
            new_password: "bubbles".to_string(),
        }
        .tmb(12);
        let subject = UiGateway::new(&UiGatewayConfig { ui_port: 123 }, false);

        let result = subject.deserialization_validator_with_crash_request_handler(msg_body);

        assert_eq!(result, None)
    }

    #[test]
    fn deserialization_validator_logs_payload_errors() {
        init_test_logging();
        let msg_body = MessageBody {
            opcode: "whatever".to_string(),
            path: MessagePath::Conversation(45),
            payload: Err((1234, "We did it wrong".to_string())),
        };
        let subject = UiGateway::new(&UiGatewayConfig { ui_port: 123 }, false);

        let result = subject.deserialization_validator_with_crash_request_handler(msg_body);

        assert_eq!(result, None);
        TestLogHandler::new().exists_log_containing("ERROR: UiGateway: Received a message of 'whatever' opcode with an error in its payload: 'We did it wrong'");
    }

    #[test]
    fn deserialization_validator_does_not_panic_on_a_crash_request_if_the_actor_is_not_crashable() {
        let crash_request = UiCrashRequest {
            actor: CRASH_KEY.to_string(),
            panic_message: "Testing crashing".to_string(),
        }
        .tmb(0);
        let crashable = false;
        let subject = UiGateway::new(&UiGatewayConfig { ui_port: 123 }, crashable);

        let result = subject.deserialization_validator_with_crash_request_handler(crash_request);

        assert_eq!(result, None)
    }

    #[test]
    fn deserialization_validator_does_not_panic_if_the_crash_request_belongs_to_another_actor() {
        let crash_request = UiCrashRequest {
            actor: dispatcher::CRASH_KEY.to_string(),
            panic_message: "Testing crashing".to_string(),
        }
        .tmb(0);
        let crashable = true;
        let subject = UiGateway::new(&UiGatewayConfig { ui_port: 123 }, crashable);

        let result = subject.deserialization_validator_with_crash_request_handler(crash_request);

        assert_eq!(result, None)
    }
}
