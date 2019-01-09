// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use actix::Actor;
use actix::Addr;
use actix::Context;
use actix::Handler;
use actix::Recipient;
use actix::Syn;
use stream_messages::PoolBindMessage;
use sub_lib::dispatcher::DispatcherSubs;
use sub_lib::dispatcher::InboundClientData;
use sub_lib::logger::Logger;
use sub_lib::peer_actors::BindMessage;
use sub_lib::stream_handler_pool::TransmitDataMsg;
use sub_lib::utils::NODE_MAILBOX_CAPACITY;

pub struct Dispatcher {
    to_proxy_server: Option<Recipient<Syn, InboundClientData>>,
    to_hopper: Option<Recipient<Syn, InboundClientData>>,
    to_stream: Option<Recipient<Syn, TransmitDataMsg>>,
    logger: Logger,
}

impl Actor for Dispatcher {
    type Context = Context<Self>;
}

impl Handler<BindMessage> for Dispatcher {
    type Result = ();

    fn handle(&mut self, msg: BindMessage, ctx: &mut Self::Context) {
        ctx.set_mailbox_capacity(NODE_MAILBOX_CAPACITY);
        self.to_proxy_server = Some(msg.peer_actors.proxy_server.from_dispatcher);
        self.to_hopper = Some(msg.peer_actors.hopper.from_dispatcher);
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
            self.to_hopper
                .as_ref()
                .expect("Hopper unbound in Dispatcher")
                .try_send(msg)
                .expect("Hopper is dead");
        } else {
            self.to_proxy_server
                .as_ref()
                .expect("ProxyServer unbound in Dispatcher")
                .try_send(msg)
                .expect("ProxyServer is dead");
        }
    }
}

impl Handler<TransmitDataMsg> for Dispatcher {
    type Result = ();

    fn handle(&mut self, msg: TransmitDataMsg, _ctx: &mut Self::Context) {
        self.logger.debug(format!(
            "Relaying {} bytes to StreamHandlerPool for {:?}",
            msg.data.len(),
            msg.endpoint
        ));
        self.to_stream
            .as_ref()
            .expect("StreamHandlerPool unbound in Dispatcher")
            .try_send(msg)
            .expect("StreamHandlerPool is dead");
    }
}

impl Dispatcher {
    pub fn new() -> Dispatcher {
        Dispatcher {
            to_proxy_server: None,
            to_stream: None,
            to_hopper: None,
            logger: Logger::new("Dispatcher"),
        }
    }

    pub fn make_subs_from(addr: &Addr<Syn, Dispatcher>) -> DispatcherSubs {
        DispatcherSubs {
            ibcd_sub: addr.clone().recipient::<InboundClientData>(),
            bind: addr.clone().recipient::<BindMessage>(),
            from_dispatcher_client: addr.clone().recipient::<TransmitDataMsg>(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix::msgs;
    use actix::Addr;
    use actix::Arbiter;
    use actix::System;
    use node_test_utils::make_stream_handler_pool_subs_from;
    use std::net::SocketAddr;
    use std::str::FromStr;
    use sub_lib::dispatcher::Endpoint;
    use test_utils::recorder::make_peer_actors_from;
    use test_utils::recorder::Recorder;

    #[test]
    fn sends_inbound_data_for_proxy_server_to_proxy_server() {
        let system = System::new("test");
        let subject = Dispatcher::new();
        let subject_addr: Addr<Syn, Dispatcher> = subject.start();
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
        let mut peer_actors = make_peer_actors_from(Some(proxy_server), None, None, None, None);
        peer_actors.dispatcher = Dispatcher::make_subs_from(&subject_addr);
        subject_addr.try_send(BindMessage { peer_actors }).unwrap();

        subject_ibcd.try_send(ibcd_in).unwrap();

        Arbiter::system().try_send(msgs::SystemExit(0)).unwrap();
        system.run();

        awaiter.await_message_count(1);
        let recording = recording_arc.lock().unwrap();

        let message = &recording.get_record::<InboundClientData>(0) as *const _;
        let (actual_socket_addr, actual_data) = unsafe {
            let tptr = message as *const Box<InboundClientData>;
            let message = &*tptr;
            (message.peer_addr, message.data.clone())
        };

        assert_eq!(actual_socket_addr, peer_addr);
        assert_eq!(actual_data, data);
        assert_eq!(recording.len(), 1);
    }

    #[test]
    fn sends_inbound_data_for_hopper_to_hopper() {
        let system = System::new("test");
        let subject = Dispatcher::new();
        let subject_addr: Addr<Syn, Dispatcher> = subject.start();
        let subject_ibcd = subject_addr.clone().recipient::<InboundClientData>();
        let hopper = Recorder::new();
        let recording_arc = hopper.get_recording();
        let awaiter = hopper.get_awaiter();
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
        let mut peer_actors = make_peer_actors_from(None, None, Some(hopper), None, None);
        peer_actors.dispatcher = Dispatcher::make_subs_from(&subject_addr);
        subject_addr.try_send(BindMessage { peer_actors }).unwrap();

        subject_ibcd.try_send(ibcd_in).unwrap();

        Arbiter::system().try_send(msgs::SystemExit(0)).unwrap();
        system.run();

        awaiter.await_message_count(1);
        let recording = recording_arc.lock().unwrap();

        let message = &recording.get_record::<InboundClientData>(0) as *const _;
        let (actual_socket_addr, actual_data) = unsafe {
            let tptr = message as *const Box<InboundClientData>;
            let message = &*tptr;
            (message.peer_addr, message.data.clone())
        };

        assert_eq!(actual_socket_addr, peer_addr);
        assert_eq!(actual_data, data);
        assert_eq!(recording.len(), 1);
    }

    #[test]
    #[should_panic(expected = "ProxyServer unbound in Dispatcher")]
    fn inbound_client_data_handler_panics_when_proxy_server_is_unbound() {
        let system = System::new("test");
        let subject = Dispatcher::new();
        let subject_addr: Addr<Syn, Dispatcher> = subject.start();
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

        Arbiter::system().try_send(msgs::SystemExit(0)).unwrap();
        system.run();
    }

    #[test]
    #[should_panic(expected = "Hopper unbound in Dispatcher")]
    fn inbound_client_data_handler_panics_when_hopper_is_unbound() {
        let system = System::new("test");
        let subject = Dispatcher::new();
        let subject_addr: Addr<Syn, Dispatcher> = subject.start();
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

        Arbiter::system().try_send(msgs::SystemExit(0)).unwrap();
        system.run();
    }

    #[test]
    #[should_panic(expected = "StreamHandlerPool unbound in Dispatcher")]
    fn panics_when_stream_handler_pool_is_unbound() {
        let system = System::new("test");
        let subject = Dispatcher::new();
        let subject_addr: Addr<Syn, Dispatcher> = subject.start();
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

        Arbiter::system().try_send(msgs::SystemExit(0)).unwrap();
        system.run();
    }

    #[test]
    fn forwards_outbound_data_to_stream_handler_pool() {
        let system = System::new("test");
        let subject = Dispatcher::new();
        let subject_addr: Addr<Syn, Dispatcher> = subject.start();
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
        let mut peer_actors = make_peer_actors_from(None, None, None, None, None);
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

        Arbiter::system().try_send(msgs::SystemExit(0)).unwrap();
        system.run();

        awaiter.await_message_count(1);
        let recording = recording_arc.lock().unwrap();

        let message = &recording.get_record::<TransmitDataMsg>(0) as *const _;
        let (actual_endpoint, actual_data) = unsafe {
            let tptr = message as *const Box<TransmitDataMsg>;
            let message = &*tptr;
            (message.endpoint.clone(), message.data.clone())
        };

        assert_eq!(actual_endpoint, Endpoint::Socket(socket_addr));
        assert_eq!(actual_data, data);
        assert_eq!(recording.len(), 1);
    }
}
