// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use crate::stream_messages::{PoolBindMessage, RemovedStreamType};
use crate::sub_lib::dispatcher::InboundClientData;
use crate::sub_lib::dispatcher::{DispatcherSubs, StreamShutdownMsg};
use crate::sub_lib::logger::Logger;
use crate::sub_lib::peer_actors::BindMessage;
use crate::sub_lib::stream_handler_pool::TransmitDataMsg;
use crate::sub_lib::utils::{handle_ui_crash_request, NODE_MAILBOX_CAPACITY};
use actix::Actor;
use actix::Addr;
use actix::Context;
use actix::Handler;
use actix::Recipient;
use masq_lib::crash_point::CrashPoint;
use masq_lib::messages::{
    FromMessageBody, ToMessageBody, UiCrashRequest, UiDescriptorRequest, UiDescriptorResponse,
};
use masq_lib::ui_gateway::{MessageTarget, NodeFromUiMessage, NodeToUiMessage};

pub const CRASH_KEY: &str = "DISPATCHER";

struct DispatcherOutSubs {
    to_proxy_server: Recipient<InboundClientData>,
    to_hopper: Recipient<InboundClientData>,
    proxy_server_stream_shutdown_sub: Recipient<StreamShutdownMsg>,
    neighborhood_stream_shutdown_sub: Recipient<StreamShutdownMsg>,
    ui_gateway_sub: Recipient<NodeToUiMessage>,
}

pub struct Dispatcher {
    subs: Option<DispatcherOutSubs>,
    crashable: bool,
    node_descriptor: String,
    to_stream: Option<Recipient<TransmitDataMsg>>,
    logger: Logger,
}

impl Actor for Dispatcher {
    type Context = Context<Self>;
}

impl Handler<BindMessage> for Dispatcher {
    type Result = ();

    fn handle(&mut self, msg: BindMessage, ctx: &mut Self::Context) {
        ctx.set_mailbox_capacity(NODE_MAILBOX_CAPACITY);
        let subs = DispatcherOutSubs {
            to_proxy_server: msg.peer_actors.proxy_server.from_dispatcher,
            to_hopper: msg.peer_actors.hopper.from_dispatcher,
            proxy_server_stream_shutdown_sub: msg.peer_actors.proxy_server.stream_shutdown_sub,
            neighborhood_stream_shutdown_sub: msg.peer_actors.neighborhood.stream_shutdown_sub,
            ui_gateway_sub: msg.peer_actors.ui_gateway.node_to_ui_message_sub,
        };
        self.subs = Some(subs);
    }
}

impl Handler<PoolBindMessage> for Dispatcher {
    type Result = ();

    fn handle(&mut self, msg: PoolBindMessage, _ctx: &mut Self::Context) {
        self.to_stream = Some(msg.stream_handler_pool_subs.transmit_sub);
    }
}

impl Handler<InboundClientData> for Dispatcher {
    type Result = ();

    fn handle(&mut self, msg: InboundClientData, _ctx: &mut Self::Context) {
        if msg.is_clandestine {
            self.subs
                .as_ref()
                .expect("Hopper unbound in Dispatcher")
                .to_hopper
                .try_send(msg)
                .expect("Hopper is dead");
        } else {
            self.subs
                .as_ref()
                .expect("ProxyServer unbound in Dispatcher")
                .to_proxy_server
                .try_send(msg)
                .expect("ProxyServer is dead");
        }
    }
}

impl Handler<TransmitDataMsg> for Dispatcher {
    type Result = ();

    fn handle(&mut self, msg: TransmitDataMsg, _ctx: &mut Self::Context) {
        debug!(
            self.logger,
            "Relaying {} bytes to StreamHandlerPool for {:?}",
            msg.data.len(),
            msg.endpoint
        );
        self.to_stream
            .as_ref()
            .expect("StreamHandlerPool unbound in Dispatcher")
            .try_send(msg)
            .expect("StreamHandlerPool is dead");
    }
}

impl Handler<StreamShutdownMsg> for Dispatcher {
    type Result = ();

    fn handle(&mut self, msg: StreamShutdownMsg, _ctx: &mut Self::Context) -> Self::Result {
        self.handle_stream_shutdown_msg(msg)
    }
}

impl Handler<NodeFromUiMessage> for Dispatcher {
    type Result = ();

    fn handle(&mut self, msg: NodeFromUiMessage, _ctx: &mut Self::Context) -> Self::Result {
        if let Ok((crash_request, _)) = UiCrashRequest::fmb(msg.body.clone()) {
            handle_ui_crash_request(crash_request, &self.logger, self.crashable, CRASH_KEY);
        } else if let Ok((_, context_id)) = UiDescriptorRequest::fmb(msg.body) {
            self.handle_descriptor_request(msg.client_id, context_id);
        }
    }
}

impl Dispatcher {
    pub fn new(crash_point: CrashPoint, node_descriptor: String) -> Dispatcher {
        Dispatcher {
            subs: None,
            crashable: crash_point == CrashPoint::Message,
            node_descriptor,
            to_stream: None,
            logger: Logger::new("Dispatcher"),
        }
    }

    pub fn make_subs_from(addr: &Addr<Dispatcher>) -> DispatcherSubs {
        DispatcherSubs {
            ibcd_sub: addr.clone().recipient::<InboundClientData>(),
            bind: addr.clone().recipient::<BindMessage>(),
            from_dispatcher_client: addr.clone().recipient::<TransmitDataMsg>(),
            stream_shutdown_sub: addr.clone().recipient::<StreamShutdownMsg>(),
            ui_sub: addr.clone().recipient::<NodeFromUiMessage>(),
        }
    }

    fn handle_stream_shutdown_msg(&mut self, msg: StreamShutdownMsg) {
        let subs = self.subs.as_ref().expect("Dispatcher is unbound");
        match msg.stream_type {
            RemovedStreamType::Clandestine => subs
                .neighborhood_stream_shutdown_sub
                .try_send(msg)
                .expect("Neighborhood is dead"),
            RemovedStreamType::NonClandestine(_) => subs
                .proxy_server_stream_shutdown_sub
                .try_send(msg)
                .expect("ProxyServer is dead"),
        }
    }

    fn handle_descriptor_request(&mut self, client_id: u64, context_id: u64) {
        let response_inner = UiDescriptorResponse {
            node_descriptor: self.node_descriptor.clone(),
        };
        let response_msg = NodeToUiMessage {
            target: MessageTarget::ClientId(client_id),
            body: response_inner.tmb(context_id),
        };
        let subs = self.subs.as_ref().expect("Dispatcher is unbound");
        subs.ui_gateway_sub
            .try_send(response_msg)
            .expect("UiGateway is dead");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node_test_utils::make_stream_handler_pool_subs_from;
    use crate::stream_messages::NonClandestineAttributes;
    use crate::sub_lib::dispatcher::Endpoint;
    use crate::test_utils::recorder::Recorder;
    use crate::test_utils::recorder::{make_recorder, peer_actors_builder};
    use actix::Addr;
    use actix::System;
    use masq_lib::constants::HTTP_PORT;
    use masq_lib::messages::{ToMessageBody, UiDescriptorResponse};
    use masq_lib::ui_gateway::MessageTarget;
    use std::net::SocketAddr;
    use std::str::FromStr;

    #[test]
    fn sends_inbound_data_for_proxy_server_to_proxy_server() {
        let system = System::new("test");
        let subject = Dispatcher::new(CrashPoint::None, "descriptor".to_string());
        let subject_addr: Addr<Dispatcher> = subject.start();
        let subject_ibcd = subject_addr.clone().recipient::<InboundClientData>();
        let proxy_server = Recorder::new();
        let recording_arc = proxy_server.get_recording();
        let awaiter = proxy_server.get_awaiter();
        let peer_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let reception_port = Some(8080);
        let data: Vec<u8> = vec![9, 10, 11];
        let ibcd_in = InboundClientData {
            peer_addr,
            reception_port,
            sequence_number: Some(0),
            last_data: false,
            is_clandestine: false,
            data: data.clone(),
        };
        let mut peer_actors = peer_actors_builder().proxy_server(proxy_server).build();
        peer_actors.dispatcher = Dispatcher::make_subs_from(&subject_addr);
        subject_addr.try_send(BindMessage { peer_actors }).unwrap();

        subject_ibcd.try_send(ibcd_in).unwrap();

        System::current().stop_with_code(0);
        system.run();

        awaiter.await_message_count(1);
        let recording = recording_arc.lock().unwrap();

        let message = recording.get_record::<InboundClientData>(0);
        let actual_socket_addr = message.peer_addr.clone();
        let actual_data = message.data.clone();

        assert_eq!(actual_socket_addr, peer_addr);
        assert_eq!(actual_data, data);
        assert_eq!(recording.len(), 1);
    }

    #[test]
    fn sends_inbound_data_for_hopper_to_hopper() {
        let system = System::new("test");
        let subject = Dispatcher::new(CrashPoint::None, "descriptor".to_string());
        let subject_addr: Addr<Dispatcher> = subject.start();
        let (hopper, hopper_awaiter, hopper_recording_arc) = make_recorder();
        let peer_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let reception_port = Some(8080);
        let data: Vec<u8> = vec![9, 10, 11];
        let ibcd_in = InboundClientData {
            peer_addr,
            reception_port,
            last_data: false,
            is_clandestine: true,
            sequence_number: None,
            data: data.clone(),
        };
        let mut peer_actors = peer_actors_builder().hopper(hopper).build();
        peer_actors.dispatcher = Dispatcher::make_subs_from(&subject_addr);
        subject_addr.try_send(BindMessage { peer_actors }).unwrap();

        subject_addr.try_send(ibcd_in).unwrap();

        System::current().stop_with_code(0);
        system.run();

        hopper_awaiter.await_message_count(1);
        let hopper_recording = hopper_recording_arc.lock().unwrap();

        let message = hopper_recording.get_record::<InboundClientData>(0);
        let actual_socket_addr = message.peer_addr.clone();
        let actual_data = message.data.clone();

        assert_eq!(actual_socket_addr, peer_addr);
        assert_eq!(actual_data, data);
        assert_eq!(hopper_recording.len(), 1);
    }

    #[test]
    #[should_panic(expected = "ProxyServer unbound in Dispatcher")]
    fn inbound_client_data_handler_panics_when_proxy_server_is_unbound() {
        let system = System::new("test");
        let subject = Dispatcher::new(CrashPoint::None, "descriptor".to_string());
        let subject_addr: Addr<Dispatcher> = subject.start();
        let subject_ibcd = subject_addr.recipient::<InboundClientData>();
        let peer_addr = SocketAddr::from_str("1.2.3.4:8765").unwrap();
        let reception_port = Some(1234);
        let data: Vec<u8> = vec![9, 10, 11];
        let ibcd_in = InboundClientData {
            peer_addr,
            reception_port,
            last_data: false,
            is_clandestine: false,
            sequence_number: Some(0),
            data: data.clone(),
        };

        subject_ibcd.try_send(ibcd_in).unwrap();

        System::current().stop_with_code(0);
        system.run();
    }

    #[test]
    #[should_panic(expected = "Hopper unbound in Dispatcher")]
    fn inbound_client_data_handler_panics_when_hopper_is_unbound() {
        let system = System::new("test");
        let subject = Dispatcher::new(CrashPoint::None, "descriptor".to_string());
        let subject_addr: Addr<Dispatcher> = subject.start();
        let subject_ibcd = subject_addr.recipient::<InboundClientData>();
        let peer_addr = SocketAddr::from_str("1.2.3.4:8765").unwrap();
        let reception_port = Some(1234);
        let data: Vec<u8> = vec![9, 10, 11];
        let ibcd_in = InboundClientData {
            peer_addr,
            reception_port,
            last_data: false,
            is_clandestine: true,
            sequence_number: None,
            data: data.clone(),
        };

        subject_ibcd.try_send(ibcd_in).unwrap();

        System::current().stop_with_code(0);
        system.run();
    }

    #[test]
    #[should_panic(expected = "StreamHandlerPool unbound in Dispatcher")]
    fn panics_when_stream_handler_pool_is_unbound() {
        let system = System::new("test");
        let subject = Dispatcher::new(CrashPoint::None, "descriptor".to_string());
        let subject_addr: Addr<Dispatcher> = subject.start();
        let subject_obcd = subject_addr.recipient::<TransmitDataMsg>();
        let socket_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let data: Vec<u8> = vec![9, 10, 11];
        let obcd = TransmitDataMsg {
            endpoint: Endpoint::Socket(socket_addr),
            last_data: false,
            sequence_number: Some(0),
            data: data.clone(),
        };

        subject_obcd.try_send(obcd).unwrap();

        System::current().stop_with_code(0);
        system.run();
    }

    #[test]
    fn forwards_outbound_data_to_stream_handler_pool() {
        let system = System::new("test");
        let subject = Dispatcher::new(CrashPoint::None, "descriptor".to_string());
        let subject_addr: Addr<Dispatcher> = subject.start();
        let subject_obcd = subject_addr.clone().recipient::<TransmitDataMsg>();
        let stream_handler_pool = Recorder::new();
        let recording_arc = stream_handler_pool.get_recording();
        let awaiter = stream_handler_pool.get_awaiter();
        let socket_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let data: Vec<u8> = vec![9, 10, 11];
        let obcd = TransmitDataMsg {
            endpoint: Endpoint::Socket(socket_addr),
            last_data: false,
            sequence_number: None,
            data: data.clone(),
        };
        let mut peer_actors = peer_actors_builder().build();
        peer_actors.dispatcher = Dispatcher::make_subs_from(&subject_addr);
        let stream_handler_pool_subs =
            make_stream_handler_pool_subs_from(Some(stream_handler_pool));
        subject_addr
            .try_send(PoolBindMessage {
                dispatcher_subs: peer_actors.dispatcher.clone(),
                stream_handler_pool_subs,
                neighborhood_subs: peer_actors.neighborhood.clone(),
            })
            .unwrap();
        subject_addr.try_send(BindMessage { peer_actors }).unwrap();

        subject_obcd.try_send(obcd).unwrap();

        System::current().stop_with_code(0);
        system.run();

        awaiter.await_message_count(1);
        let recording = recording_arc.lock().unwrap();

        let message = recording.get_record::<TransmitDataMsg>(0);
        let actual_endpoint = message.endpoint.clone();
        let actual_data = message.data.clone();

        assert_eq!(actual_endpoint, Endpoint::Socket(socket_addr));
        assert_eq!(actual_data, data);
        assert_eq!(recording.len(), 1);
    }

    #[test]
    fn handle_stream_shutdown_msg_routes_non_clandestine_to_proxy_server() {
        let system = System::new("test");
        let subject = Dispatcher::new(CrashPoint::None, "descriptor".to_string());
        let addr = subject.start();
        let (proxy_server, _, proxy_server_recording_arc) = make_recorder();
        let (neighborhood, _, neighborhood_recording_arc) = make_recorder();
        let peer_actors = peer_actors_builder()
            .proxy_server(proxy_server)
            .neighborhood(neighborhood)
            .build();
        addr.try_send(BindMessage { peer_actors }).unwrap();
        let msg = StreamShutdownMsg {
            peer_addr: SocketAddr::from_str("7.8.9.0:6543").unwrap(),
            stream_type: RemovedStreamType::NonClandestine(NonClandestineAttributes {
                reception_port: HTTP_PORT,
                sequence_number: 1234,
            }),
            report_to_counterpart: true,
        };

        addr.try_send(msg.clone()).unwrap();

        System::current().stop_with_code(0);
        system.run();
        let proxy_server_recording = proxy_server_recording_arc.lock().unwrap();
        assert_eq!(
            proxy_server_recording.get_record::<StreamShutdownMsg>(0),
            &msg
        );
        let neighborhood_recording = neighborhood_recording_arc.lock().unwrap();
        assert_eq!(neighborhood_recording.len(), 0);
    }

    #[test]
    fn handle_stream_shutdown_msg_routes_clandestine_to_neighborhood() {
        let system = System::new("test");
        let subject = Dispatcher::new(CrashPoint::None, "descriptor".to_string());
        let addr = subject.start();
        let (proxy_server, _, proxy_server_recording_arc) = make_recorder();
        let (neighborhood, _, neighborhood_recording_arc) = make_recorder();
        let peer_actors = peer_actors_builder()
            .proxy_server(proxy_server)
            .neighborhood(neighborhood)
            .build();
        addr.try_send(BindMessage { peer_actors }).unwrap();
        let msg = StreamShutdownMsg {
            peer_addr: SocketAddr::from_str("7.8.9.0:6543").unwrap(),
            stream_type: RemovedStreamType::Clandestine,
            report_to_counterpart: false,
        };

        addr.try_send(msg.clone()).unwrap();

        System::current().stop_with_code(0);
        system.run();
        let proxy_server_recording = proxy_server_recording_arc.lock().unwrap();
        assert_eq!(proxy_server_recording.len(), 0);
        let neighborhood_recording = neighborhood_recording_arc.lock().unwrap();
        assert_eq!(
            neighborhood_recording.get_record::<StreamShutdownMsg>(0),
            &msg
        );
    }

    #[test]
    fn descriptor_request_results_in_descriptor_response() {
        let system = System::new("test");
        let subject = Dispatcher::new(CrashPoint::None, "Node descriptor".to_string());
        let addr = subject.start();
        let (ui_gateway_recorder, _, ui_gateway_recording_arc) = make_recorder();
        let peer_actors = peer_actors_builder()
            .ui_gateway(ui_gateway_recorder)
            .build();
        addr.try_send(BindMessage { peer_actors }).unwrap();
        let msg = NodeFromUiMessage {
            client_id: 1234,
            body: UiDescriptorRequest {}.tmb(4321),
        };

        addr.try_send(msg).unwrap();

        System::current().stop_with_code(0);
        system.run();
        let ui_gateway_recording = ui_gateway_recording_arc.lock().unwrap();
        assert_eq!(
            ui_gateway_recording.get_record::<NodeToUiMessage>(0),
            &NodeToUiMessage {
                target: MessageTarget::ClientId(1234),
                body: UiDescriptorResponse {
                    node_descriptor: "Node descriptor".to_string()
                }
                .tmb(4321)
            }
        );
    }
}
