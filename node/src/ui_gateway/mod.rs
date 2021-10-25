// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

mod websocket_supervisor;

#[cfg(test)]
pub mod websocket_supervisor_mock;

use crate::daemon::DaemonBindMessage;
use crate::sub_lib::logger::Logger;
use crate::sub_lib::peer_actors::BindMessage;
use crate::sub_lib::ui_gateway::UiGatewayConfig;
use crate::sub_lib::ui_gateway::UiGatewaySubs;
use crate::sub_lib::utils::NODE_MAILBOX_CAPACITY;
use crate::ui_gateway::websocket_supervisor::WebSocketSupervisor;
use crate::ui_gateway::websocket_supervisor::WebSocketSupervisorReal;
use actix::Actor;
use actix::Addr;
use actix::Context;
use actix::Handler;
use actix::Recipient;
use masq_lib::ui_gateway::{NodeFromUiMessage, NodeToUiMessage};

pub const CRASH_KEY: &str = "UIGATEWAY";

pub struct UiGateway {
    port: u16,
    websocket_supervisor: Option<Box<dyn WebSocketSupervisor>>,
    incoming_message_recipients: Vec<Recipient<NodeFromUiMessage>>,
    logger: Logger,
}

impl UiGateway {
    pub fn new(config: &UiGatewayConfig) -> UiGateway {
        UiGateway {
            port: config.ui_port,
            websocket_supervisor: None,
            incoming_message_recipients: vec![],
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
        let len = self.incoming_message_recipients.len();
        (0..len).for_each(|idx| {
            let recipient = &self.incoming_message_recipients[idx];
            recipient.try_send(msg.clone()).unwrap_or_else(|_| {
                panic!("UiGateway's NodeFromUiMessage recipient #{} has died.", idx)
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::recorder::peer_actors_builder;
    use crate::test_utils::recorder::{make_recorder, Recording};
    use crate::ui_gateway::websocket_supervisor_mock::WebSocketSupervisorMock;
    use actix::System;
    use masq_lib::ui_gateway::MessagePath::FireAndForget;
    use masq_lib::ui_gateway::{MessageBody, MessageTarget};
    use masq_lib::utils::find_free_port;
    use std::sync::{Arc, Mutex};

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
        let subject = UiGateway::new(&UiGatewayConfig {
            ui_port: find_free_port(),
        });
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
                payload: Ok("{}".to_string()),
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
        let send_msg_parameters_arc = Arc::new(Mutex::new(vec![]));
        let websocket_supervisor =
            WebSocketSupervisorMock::new().send_msg_parameters(&send_msg_parameters_arc);
        let mut subject = UiGateway::new(&UiGatewayConfig {
            ui_port: find_free_port(),
        });
        let system = System::new("test");
        subject.websocket_supervisor = Some(Box::new(websocket_supervisor));
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
        let send_parameters = send_msg_parameters_arc.lock().unwrap();
        assert_eq!(send_parameters[0], msg);
    }
}
